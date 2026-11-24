"""WebAuthn 无密码登录安全回归测试。

共 15 个测试。前 10 个分别对应题面中的 10 个缺陷，后 5 个是正向路径和关键不变量。
所有测试只通过 ``webauthn`` 顶层门面调用 8 个公开函数；初始状态下每个测试都会在
第一次调用桩时因 ``NotImplementedError`` 失败。测试不使用随机数、系统时间、网络或
外部依赖，所有挑战、时间、密钥都由被测函数或固定夹具生成。
"""

import hashlib
import hmac
import json
import struct

import webauthn

RP_ID = "login.example.com"
ORIGIN = "https://login.example.com"
USER = "alice"
NOW = 1_700_000_000
TTL = 300

KEY_A = b"sec-webauthn-key-a-0123456789"
KEY_B = b"sec-webauthn-key-b-0123456789"


def _store():
    return {"challenges": {}}


def _credential(
    credential_id,
    *,
    rp_id=RP_ID,
    key=KEY_A,
    assertion_sign_count=5,
    registration_sign_count=99,
):
    """构造一份同时带有注册状态和断言状态的凭证。"""
    return {
        "credential_id": credential_id,
        "rp_id": rp_id,
        "public_key": key,
        "user_handle": USER.encode("utf-8"),
        "registration": {
            "sign_count": registration_sign_count,
            "user_present": True,
        },
        "assertion": {"sign_count": assertion_sign_count},
    }


def _client_data(challenge, origin=ORIGIN):
    return {
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
    }


def _json_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _auth_data(rp_id=RP_ID, sign_count=6, flags=0x01):
    return (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([flags])
        + struct.pack(">I", sign_count)
    )


def _sign(key, client_data_hash, authenticator_data):
    return hmac.new(
        key,
        client_data_hash + authenticator_data,
        hashlib.sha256,
    ).digest()


def _raw_assertion(
    credential,
    challenge,
    *,
    origin=ORIGIN,
    sign_count=6,
    flags=0x01,
    authenticator_data=None,
    client_data=None,
):
    client_data = client_data or _client_data(challenge, origin)
    client_data_json = _json_bytes(client_data)
    client_data_hash = hashlib.sha256(client_data_json).digest()
    if authenticator_data is None:
        authenticator_data = _auth_data(
            credential["rp_id"],
            sign_count,
            flags,
        )
    signature = _sign(
        credential["public_key"],
        client_data_hash,
        authenticator_data,
    )
    return {
        "credential_id": credential["credential_id"],
        "client_data": client_data,
        "authenticator_data": authenticator_data,
        "signature": signature,
    }


def _policy(store):
    return {
        "store": store,
        "expected_origin": ORIGIN,
        "expected_rp_id": RP_ID,
    }


def _request(request_id, credential, raw):
    return {
        "id": request_id,
        "credential": credential,
        "raw": raw,
    }


def _scenario():
    """构造一组顺序无关的批量校验请求，供独立批次和单条校验对照。"""
    store = _store()
    policy = _policy(store)
    requests = []

    valid = _credential(
        b"cred-scenario-valid",
        key=KEY_A,
        assertion_sign_count=5,
    )
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    requests.append(
        _request(
            "valid",
            valid,
            _raw_assertion(valid, challenge, sign_count=6),
        )
    )

    bad_origin = _credential(
        b"cred-scenario-origin",
        key=KEY_B,
        assertion_sign_count=5,
    )
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    requests.append(
        _request(
            "bad-origin",
            bad_origin,
            _raw_assertion(
                bad_origin,
                challenge,
                origin="https://evil.login.example.com",
                sign_count=6,
            ),
        )
    )

    bad_counter = _credential(
        b"cred-scenario-counter",
        key=KEY_A,
        assertion_sign_count=5,
    )
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    requests.append(
        _request(
            "bad-counter",
            bad_counter,
            _raw_assertion(bad_counter, challenge, sign_count=5),
        )
    )

    expired = _credential(
        b"cred-scenario-expired",
        key=KEY_B,
        assertion_sign_count=5,
    )
    challenge = webauthn.issue_challenge(
        store,
        USER,
        NOW - 1000,
        10,
    )["challenge"]
    requests.append(
        _request(
            "expired",
            expired,
            _raw_assertion(expired, challenge, sign_count=6),
        )
    )

    zero = _credential(
        b"cred-scenario-zero",
        key=KEY_A,
        assertion_sign_count=0,
    )
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    requests.append(
        _request(
            "zero",
            zero,
            _raw_assertion(zero, challenge, sign_count=0),
        )
    )

    return store, policy, requests


def _batch_oks(store, policy, requests, now):
    result = webauthn.assertion_batch(requests, policy, now)
    return [item["ok"] for item in result["results"]]


def _individual_oks(store, policy, requests, now):
    """按与批量校验相同的公开步骤逐条校验，作为独立对照。"""
    outcomes = []
    for request in requests:
        credential = request["credential"]
        try:
            parsed = webauthn.parse_assertion(request["raw"])
            ok = (
                parsed["credential_id"] == credential["credential_id"]
                and webauthn.check_challenge(
                    store,
                    parsed["challenge"],
                    now,
                )
                and webauthn.check_origin(
                    parsed["client_data"],
                    policy["expected_origin"],
                )
                and webauthn.check_rp_id(
                    credential["rp_id"],
                    policy["expected_rp_id"],
                )
                and webauthn.verify_signature(
                    credential,
                    parsed["client_data_hash"],
                    parsed["authenticator_data"],
                    parsed["signature"],
                )
                and webauthn.check_counter(
                    credential,
                    parsed["sign_count"],
                )
            )
        except (KeyError, TypeError, ValueError):
            ok = False
        if ok:
            credential["assertion"]["sign_count"] = parsed["sign_count"]
        outcomes.append(ok)
    return outcomes


# ---------------------------------------------------------------------------
# 10 个缺陷：每条测试对应一个必须修复的协议状态缺陷。
# ---------------------------------------------------------------------------


def test_challenge_is_one_time_and_invalidated_after_use():
    """缺陷 1：挑战校验通过后不作废时，同一断言可以反复重放。"""
    store = _store()
    record = webauthn.issue_challenge(store, USER, NOW, TTL)
    challenge = record["challenge"]

    assert challenge
    assert record["expires_at"] == NOW + TTL
    assert record["used"] is False
    assert webauthn.check_challenge(store, challenge, NOW) is True
    assert webauthn.check_challenge(store, challenge, NOW) is False


def test_expired_challenge_is_rejected():
    """缺陷 2：挑战不校验过期时间时，签发后长期有效。"""
    store = _store()
    boundary = webauthn.issue_challenge(store, USER, NOW, 10)
    expired = webauthn.issue_challenge(store, USER, NOW, 10)

    assert webauthn.check_challenge(
        store,
        boundary["challenge"],
        NOW + 10,
    ) is True
    assert webauthn.check_challenge(
        store,
        expired["challenge"],
        NOW + 11,
    ) is False


def test_origin_subdomain_and_suffix_are_rejected():
    """缺陷 3：来源匹配用后缀比较时，攻击者子域会被放行。"""
    assert webauthn.check_origin(
        _client_data("c", "https://evil.login.example.com"),
        ORIGIN,
    ) is False
    assert webauthn.check_origin(
        _client_data("c", "https://login.example.com.evil.test"),
        ORIGIN,
    ) is False
    assert webauthn.check_origin(
        _client_data("c", ORIGIN),
        ORIGIN,
    ) is True


def test_origin_scheme_must_match_exactly():
    """缺陷 4：来源匹配忽略协议差异时，明文来源会与安全来源等同。"""
    assert webauthn.check_origin(
        _client_data("c", "http://login.example.com"),
        ORIGIN,
    ) is False
    assert webauthn.check_origin(
        _client_data("c", ORIGIN),
        ORIGIN,
    ) is True


def test_rp_id_cannot_cross_registrable_suffix():
    """缺陷 5：依赖方标识接受任意子域且不做注册后缀检查，跨 RP 凭证可用。"""
    assert webauthn.check_rp_id("login.example.com", RP_ID) is True
    assert webauthn.check_rp_id("example.com", RP_ID) is True
    assert webauthn.check_rp_id("com", RP_ID) is False
    assert webauthn.check_rp_id("notexample.com", RP_ID) is False
    assert webauthn.check_rp_id("evil.login.example.com", RP_ID) is False
    assert webauthn.check_rp_id("evil.com", RP_ID) is False

    store = _store()
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    evil = _credential(
        b"cred-evil-rp",
        rp_id="evil.com",
        key=KEY_B,
        assertion_sign_count=5,
    )
    raw = _raw_assertion(evil, challenge, sign_count=6)
    parsed = webauthn.parse_assertion(raw)

    assert webauthn.verify_signature(
        evil,
        parsed["client_data_hash"],
        raw["authenticator_data"],
        raw["signature"],
    ) is True
    assert webauthn.verify_signature(
        evil,
        parsed["client_data_hash"],
        _auth_data(RP_ID, 6),
        raw["signature"],
    ) is False

    result = webauthn.assertion_batch(
        [_request("cross-rp", evil, raw)],
        _policy(store),
        NOW,
    )
    assert result["results"][0]["ok"] is False
    assert result["results"][0]["reason"] == "rp_id"


def test_counter_must_strictly_increase():
    """缺陷 6：签名计数只校验非负而不要求严格递增时，旧计数可重放。"""
    credential = _credential(
        b"cred-counter",
        assertion_sign_count=5,
    )

    assert webauthn.check_counter(credential, 6) is True
    assert webauthn.check_counter(credential, 5) is False
    assert webauthn.check_counter(credential, 4) is False
    assert webauthn.check_counter(credential, -1) is False


def test_zero_counter_reset_is_rejected():
    """缺陷 7：计数为零时按递增放行，计数器被清零后仍可使用。"""
    zero = _credential(
        b"cred-zero",
        assertion_sign_count=0,
    )
    used = _credential(
        b"cred-used",
        assertion_sign_count=5,
    )

    assert webauthn.check_counter(zero, 0) is True
    assert webauthn.check_counter(zero, 1) is True
    assert webauthn.check_counter(used, 0) is False


def test_signature_covers_client_data_hash_and_user_presence():
    """缺陷 8：验签漏掉客户端数据摘要或用户在场标志时，断言可被换绑。"""
    credential = _credential(
        b"cred-signature",
        assertion_sign_count=5,
    )
    client_data = _client_data("challenge-signature")
    client_data_hash = hashlib.sha256(_json_bytes(client_data)).digest()
    authenticator_data = _auth_data(RP_ID, 6, flags=0x01)
    good_signature = _sign(
        credential["public_key"],
        client_data_hash,
        authenticator_data,
    )

    assert webauthn.verify_signature(
        credential,
        client_data_hash,
        authenticator_data,
        good_signature,
    ) is True

    other_hash = hashlib.sha256(
        _json_bytes(_client_data("challenge-other"))
    ).digest()
    assert webauthn.verify_signature(
        credential,
        other_hash,
        authenticator_data,
        good_signature,
    ) is False

    auth_only_signature = hmac.new(
        credential["public_key"],
        authenticator_data,
        hashlib.sha256,
    ).digest()
    assert webauthn.verify_signature(
        credential,
        client_data_hash,
        authenticator_data,
        auth_only_signature,
    ) is False

    no_up_authenticator_data = _auth_data(RP_ID, 6, flags=0x00)
    no_up_signature = _sign(
        credential["public_key"],
        client_data_hash,
        no_up_authenticator_data,
    )
    assert webauthn.verify_signature(
        credential,
        client_data_hash,
        no_up_authenticator_data,
        no_up_signature,
    ) is False


def test_registration_counter_does_not_pollute_assertion():
    """缺陷 9：注册与断言共用计数时，注册阶段的高计数会污染断言。"""
    credential = _credential(
        b"cred-separate-state",
        assertion_sign_count=2,
        registration_sign_count=99,
    )

    assert webauthn.check_counter(credential, 3) is True
    assert webauthn.check_counter(credential, 2) is False
    assert credential["registration"]["sign_count"] == 99
    assert credential["assertion"]["sign_count"] == 2


def test_batch_does_not_share_challenge_between_requests():
    """缺陷 10：批量校验复用挑战状态时，第二个请求命中第一个请求的挑战。"""
    store = _store()
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    first = _credential(
        b"cred-batch-first",
        key=KEY_A,
        assertion_sign_count=5,
    )
    second = _credential(
        b"cred-batch-second",
        key=KEY_B,
        assertion_sign_count=5,
    )

    result = webauthn.assertion_batch(
        [
            _request(
                "first",
                first,
                _raw_assertion(first, challenge, sign_count=6),
            ),
            _request(
                "second",
                second,
                _raw_assertion(second, challenge, sign_count=6),
            ),
        ],
        _policy(store),
        NOW,
    )

    assert result["ok"] is False
    assert [item["ok"] for item in result["results"]] == [True, False]
    assert result["results"][1]["reason"] == "challenge"
    assert result["accepted"] == ["first"]
    assert result["rejected"] == ["second"]


# ---------------------------------------------------------------------------
# 另外 5 条：合法路径、重放、来源、计数和批量一致性。
# ---------------------------------------------------------------------------


def test_valid_assertion_passes():
    """合法断言应同时通过解析、来源、RP、验签、计数和批量校验。"""
    store = _store()
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    credential = _credential(
        b"cred-valid",
        assertion_sign_count=5,
    )
    raw = _raw_assertion(credential, challenge, sign_count=7)
    parsed = webauthn.parse_assertion(raw)

    assert parsed["credential_id"] == credential["credential_id"]
    assert parsed["challenge"] == challenge
    assert parsed["origin"] == ORIGIN
    assert parsed["sign_count"] == 7
    assert parsed["user_present"] is True
    assert parsed["client_data_hash"] == hashlib.sha256(
        _json_bytes(_client_data(challenge))
    ).digest()
    assert webauthn.check_origin(raw["client_data"], ORIGIN) is True
    assert webauthn.check_rp_id(credential["rp_id"], RP_ID) is True
    assert webauthn.verify_signature(
        credential,
        parsed["client_data_hash"],
        raw["authenticator_data"],
        raw["signature"],
    ) is True
    assert webauthn.check_counter(credential, 7) is True
    assert webauthn.check_challenge(store, challenge, NOW) is True

    batch_store = _store()
    batch_challenge = webauthn.issue_challenge(
        batch_store,
        USER,
        NOW,
        TTL,
    )["challenge"]
    batch_raw = _raw_assertion(
        credential,
        batch_challenge,
        sign_count=7,
    )
    result = webauthn.assertion_batch(
        [_request("valid", credential, batch_raw)],
        _policy(batch_store),
        NOW,
    )

    assert result["ok"] is True
    assert result["results"][0]["ok"] is True
    assert credential["assertion"]["sign_count"] == 7


def test_same_challenge_cannot_be_used_twice():
    """同一个挑战在第一次完整批量校验后必须立即失效。"""
    store = _store()
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    credential = _credential(
        b"cred-replay",
        assertion_sign_count=5,
    )
    raw = _raw_assertion(credential, challenge, sign_count=6)
    request = _request("replay", credential, raw)
    policy = _policy(store)

    first = webauthn.assertion_batch([request], policy, NOW)
    second = webauthn.assertion_batch([request], policy, NOW)

    assert first["results"][0]["ok"] is True
    assert second["results"][0]["ok"] is False
    assert second["results"][0]["reason"] == "challenge"


def test_origin_mismatch_is_rejected():
    """来源不匹配的断言必须被拒绝，并在尝试后消耗挑战。"""
    store = _store()
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    credential = _credential(
        b"cred-origin",
        assertion_sign_count=5,
    )
    raw = _raw_assertion(
        credential,
        challenge,
        origin="https://evil.login.example.com",
        sign_count=6,
    )

    assert webauthn.check_origin(raw["client_data"], ORIGIN) is False
    result = webauthn.assertion_batch(
        [_request("bad-origin", credential, raw)],
        _policy(store),
        NOW,
    )

    assert result["results"][0]["ok"] is False
    assert result["results"][0]["reason"] == "origin"
    assert webauthn.check_challenge(store, challenge, NOW) is False


def test_counter_non_increase_is_rejected():
    """签名计数等于已接受计数时，批量校验必须拒绝。"""
    store = _store()
    challenge = webauthn.issue_challenge(store, USER, NOW, TTL)["challenge"]
    credential = _credential(
        b"cred-counter-batch",
        assertion_sign_count=5,
    )
    raw = _raw_assertion(credential, challenge, sign_count=5)

    assert webauthn.check_counter(credential, 5) is False
    result = webauthn.assertion_batch(
        [_request("bad-counter", credential, raw)],
        _policy(store),
        NOW,
    )

    assert result["results"][0]["ok"] is False
    assert result["results"][0]["reason"] == "counter"


def test_two_independent_batches_match_individual_checks():
    """两个独立批次与逐条公开函数校验必须得到相同的布尔结果。"""
    store_a, policy_a, requests_a = _scenario()
    store_b, policy_b, requests_b = _scenario()
    store_c, policy_c, requests_c = _scenario()

    batch_a = _batch_oks(store_a, policy_a, requests_a, NOW)
    batch_b = _batch_oks(store_b, policy_b, requests_b, NOW)
    individual = _individual_oks(store_c, policy_c, requests_c, NOW)

    expected = [True, False, False, False, True]
    assert batch_a == expected
    assert batch_b == expected
    assert individual == expected
    assert batch_a == batch_b == individual
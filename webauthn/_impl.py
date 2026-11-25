"""WebAuthn 无密码登录题目的唯一实现文件。

本模块刻意只保留 8 个公开桩，全部直接抛出 ``NotImplementedError``。测试只通过
``webauthn`` 顶层包调用这些函数；实现时只替换函数体，不改变签名，不增加可供测试
绕过的旁路。

题目模拟的协议数据（测试也按此构造）：

* ``store`` 是可变映射，至少包含 ``{"challenges": {}}``；实现可以按需创建该键。
* 挑战记录包含 ``challenge``、``user``、``issued_at``、``expires_at``、``used``、
  ``used_at`` 字段。``expires_at = now + ttl``，边界时刻仍有效。
* 凭证是可变映射::

      {
          "credential_id": bytes,
          "rp_id": str,
          "public_key": bytes,       # 本题用 HMAC-SHA256 模拟公钥验签的共享密钥
          "user_handle": bytes,
          "registration": {"sign_count": int, "user_present": bool},
          "assertion": {"sign_count": int},
      }

  注册状态与断言状态必须分开保存。断言校验只能读取并推进
  ``credential["assertion"]["sign_count"]``，绝不能被 ``registration`` 中的计数污染。
* 客户端数据是 JSON 对象，规范化为
  ``json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))``
  的 UTF-8 字节；客户端数据摘要为这段字节的 SHA-256。
* 认证器数据固定为 37 字节：前 32 字节是 ``sha256(rp_id.encode("utf-8"))``，第 33
  字节是标志位，最后 4 字节是大端无符号签名计数。标志位 bit 0（0x01）表示用户在场。
* 签名是 ``HMAC-SHA256(credential["public_key"], client_data_hash + authenticator_data)``。
  这是刻意简化的可复现模型，用于把协议状态缺陷与真实密码学实现解耦。
* 批量结果固定为::

      {
          "ok": bool,
          "accepted": [request_id, ...],
          "rejected": [request_id, ...],
          "results": [
              {"id": request_id, "ok": bool, "reason": str | None},
              ...
          ],
      }

  其中 ``reason`` 只取 ``parse_error``、``credential_mismatch``、``challenge``、
  ``origin``、``rp_id``、``signature``、``counter`` 之一。
"""

import hashlib
import hmac
import json
import secrets
import struct


# 题目固定的公共后缀集合（见 check_rp_id 契约）。
PUBLIC_SUFFIXES = frozenset(
    {
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "io",
        "co",
        "uk",
        "co.uk",
        "org.uk",
        "com.au",
        "net.au",
        "co.jp",
        "com.br",
        "co.nz",
    }
)


def _is_real_int(value) -> bool:
    """bool 不算 int 的整数判断。"""
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical_client_data_json(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_valid_domain(value) -> bool:
    """小写 ASCII 域名：标签非空、至少两个标签、无协议/端口/路径/通配符。"""
    if not isinstance(value, str) or not value:
        return False
    if value.startswith(".") or value.endswith("."):
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or label.startswith("-") or label.endswith("-"):
            return False
        for char in label:
            if not (
                "a" <= char <= "z" or "0" <= char <= "9" or char == "-"
            ):
                return False
    return True


def _registrable_suffix(domain: str) -> str:
    """注册后缀：默认最后两个标签；命中公共后缀集合时取最后三个标签。"""
    labels = domain.split(".")
    last_two = ".".join(labels[-2:])
    if last_two in PUBLIC_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def issue_challenge(store: dict, user: str, now: int, ttl: int) -> dict:
    """签发一个一次性、带过期时间的挑战并写入 ``store``。

    实现要求：

    * ``store`` 是可变映射；缺少 ``challenges`` 时创建 ``store["challenges"] = {}``。
    * ``ttl`` 必须是正整数（``bool`` 不算 int），否则抛 ``ValueError``；``now`` 必须是
      非负 int（``bool`` 不算 int）。
    * 生成不可预测的新挑战字符串，不得使用固定值或只依赖 ``user`` 与 ``now`` 的
      可预测值；同一用户在同一时刻连续签发也必须得到不同挑战。
    * 记录并返回写入 ``store["challenges"][challenge]`` 的那个映射，字段为
      ``challenge``、``user``、``issued_at``、``expires_at``、``used``、``used_at``。
      ``expires_at`` 必须等于 ``now + ttl``；``used`` 初始为 ``False``，``used_at``
      初始为 ``None``。
    * 挑战的有效区间是 ``now <= t <= expires_at``，边界时刻仍然有效。

    返回值必须是存储中的记录本身（而不是丢失 ``used`` 变化的副本），以便调用方和
    :func:`check_challenge` 观察到同一份状态。
    """
    if not _is_real_int(now) or now < 0:
        raise ValueError("now must be a non-negative int")
    if not _is_real_int(ttl) or ttl <= 0:
        raise ValueError("ttl must be a positive int")

    challenges = store.get("challenges")
    if not isinstance(challenges, dict):
        challenges = {}
        store["challenges"] = challenges

    # secrets.token_urlsafe 提供不可预测性；循环保证同用户同时刻连续签发也不重复。
    challenge = secrets.token_urlsafe(32)
    while challenge in challenges:
        challenge = secrets.token_urlsafe(32)

    record = {
        "challenge": challenge,
        "user": user,
        "issued_at": now,
        "expires_at": now + ttl,
        "used": False,
        "used_at": None,
    }
    challenges[challenge] = record
    return record


def parse_assertion(raw: dict) -> dict:
    """解析断言，返回后续校验所需的规范化字段。

    ``raw`` 是映射，至少包含::

        {
            "credential_id": bytes,
            "client_data": dict | bytes | str,
            "authenticator_data": bytes,
            "signature": bytes,
        }

    ``client_data`` 为映射时，按模块说明中的规范 JSON 序列化为
    ``client_data_json``；为 bytes 或 str 时先解析 JSON，并保留原始字节用于摘要。
    返回的字典至少包含：

    * ``credential_id``：原样保留的字节串；
    * ``client_data``：解析后的 JSON 对象；
    * ``client_data_json``：参与摘要的 UTF-8 字节；
    * ``client_data_hash``：``sha256(client_data_json).digest()``，32 字节；
    * ``challenge``、``origin``、``type``：从客户端数据中取出；
    * ``authenticator_data``、``signature``：原样保留的字节串；
    * ``rp_id_hash``：认证器数据前 32 字节；
    * ``flags``：第 33 字节的整数；
    * ``sign_count``：最后 4 字节的大端无符号整数；
    * ``user_present``：``flags & 0x01 != 0`` 的布尔值。

    认证器数据长度必须恰好为 37 字节；客户端数据、类型、挑战、来源、字段类型任一
    不合法时抛 ``ValueError``。本函数只解析，不校验来源、RP ID、计数或签名。
    """
    if not isinstance(raw, dict):
        raise ValueError("raw assertion must be a mapping")

    credential_id = raw.get("credential_id")
    if not isinstance(credential_id, bytes):
        raise ValueError("credential_id must be bytes")

    authenticator_data = raw.get("authenticator_data")
    if not isinstance(authenticator_data, bytes) or len(authenticator_data) != 37:
        raise ValueError("authenticator_data must be exactly 37 bytes")

    signature = raw.get("signature")
    if not isinstance(signature, bytes):
        raise ValueError("signature must be bytes")

    client_data_input = raw.get("client_data")
    if isinstance(client_data_input, dict):
        client_data = client_data_input
        client_data_json = _canonical_client_data_json(client_data)
    elif isinstance(client_data_input, bytes):
        client_data_json = client_data_input
        client_data = json.loads(client_data_json.decode("utf-8"))
        if not isinstance(client_data, dict):
            raise ValueError("client_data JSON must encode an object")
    elif isinstance(client_data_input, str):
        client_data_json = client_data_input.encode("utf-8")
        client_data = json.loads(client_data_input)
        if not isinstance(client_data, dict):
            raise ValueError("client_data JSON must encode an object")
    else:
        raise ValueError("client_data must be a dict, bytes or str")

    if not isinstance(client_data_json, bytes) or not client_data_json:
        raise ValueError("client_data_json must be non-empty bytes")

    challenge = client_data.get("challenge")
    if not isinstance(challenge, str) or not challenge:
        raise ValueError("client_data.challenge must be a non-empty string")

    origin = client_data.get("origin")
    if not isinstance(origin, str) or not origin:
        raise ValueError("client_data.origin must be a non-empty string")

    assertion_type = client_data.get("type")
    if not isinstance(assertion_type, str) or not assertion_type:
        raise ValueError("client_data.type must be a non-empty string")

    client_data_hash = hashlib.sha256(client_data_json).digest()
    rp_id_hash = authenticator_data[:32]
    flags = authenticator_data[32]
    sign_count = struct.unpack(">I", authenticator_data[33:37])[0]

    return {
        "credential_id": credential_id,
        "client_data": client_data,
        "client_data_json": client_data_json,
        "client_data_hash": client_data_hash,
        "challenge": challenge,
        "origin": origin,
        "type": assertion_type,
        "authenticator_data": authenticator_data,
        "signature": signature,
        "rp_id_hash": rp_id_hash,
        "flags": flags,
        "sign_count": sign_count,
        "user_present": bool(flags & 0x01),
    }


def check_challenge(store: dict, challenge: str, now: int) -> bool:
    """校验挑战是否存在、未使用、未过期，并在成功时立即作废。

    返回 ``True`` 当且仅当以下条件全部成立：

    * ``store["challenges"]`` 中存在键完全等于 ``challenge`` 的记录；
    * 记录的 ``used`` 为 ``False``；
    * ``now`` 不早于 ``issued_at``，且不晚于 ``expires_at``；
    * ``challenge`` 是非空字符串，``now`` 是非负 int（``bool`` 不算 int）。

    校验成功时必须在返回前把记录的 ``used`` 置为 ``True``、``used_at`` 置为
    ``now``，实现“校验后立即作废”。即使调用方随后因来源、RP ID、签名或计数失败，
    该挑战也不得再次通过。不存在、已使用、已过期或未来签发的挑战返回 ``False``，
    且不得修改其 ``used`` 状态。畸形输入返回 ``False``，不抛异常。
    """
    try:
        if not isinstance(challenge, str) or not challenge:
            return False
        if not _is_real_int(now) or now < 0:
            return False

        record = store["challenges"].get(challenge)
        if not isinstance(record, dict):
            return False
        if record.get("used") is not False:
            return False

        issued_at = record.get("issued_at")
        expires_at = record.get("expires_at")
        if not _is_real_int(issued_at) or not _is_real_int(expires_at):
            return False
        # 有效区间 issued_at <= now <= expires_at，边界时刻仍然有效；
        # 同时拒绝未来签发（now < issued_at）与已过期（now > expires_at）。
        if now < issued_at or now > expires_at:
            return False

        # 仅在所有条件通过后才作废，失败路径不得改动 used 状态。
        record["used"] = True
        record["used_at"] = now
        return True
    except (KeyError, TypeError, AttributeError):
        return False


def check_origin(client_data: dict | bytes | str, expected_origin: str) -> bool:
    """要求客户端数据的来源与 ``expected_origin`` 精确相等。

    规则：

    * 来源比较是完整字符串相等，不做后缀、子域、路径或大小写归一化；
    * 不得忽略协议差异：``http://`` 与 ``https://`` 必须视为不同来源；
    * 不得把 ``https://evil.example.com`` 当成 ``https://example.com``，也不得把
      ``https://example.com.evil.test`` 当成 ``https://example.com``；
    * ``client_data`` 可以是映射，也可以是 JSON bytes/str；解析失败、缺少
      ``origin``、类型错误或 ``expected_origin`` 不是字符串时返回 ``False``。

    这是“精确来源匹配”契约：没有末尾斜杠归一化，也不接受默认端口补全。调用方传入
    什么字符串，就与什么字符串比较。
    """
    try:
        if not isinstance(expected_origin, str):
            return False
        if isinstance(client_data, dict):
            origin = client_data.get("origin")
        elif isinstance(client_data, bytes):
            parsed = json.loads(client_data.decode("utf-8"))
            if not isinstance(parsed, dict):
                return False
            origin = parsed.get("origin")
        elif isinstance(client_data, str):
            parsed = json.loads(client_data)
            if not isinstance(parsed, dict):
                return False
            origin = parsed.get("origin")
        else:
            return False

        if not isinstance(origin, str):
            return False
        # 完整字符串相等：天然区分协议（http/https）、拒绝子域后缀与任何归一化。
        return origin == expected_origin
    except (ValueError, TypeError, UnicodeDecodeError):
        return False


def check_rp_id(rp_id: str, expected_rp: str) -> bool:
    """校验依赖方标识，只允许期望值本身或它的父域，且不得跨注册后缀。

    通过条件（全部满足）：

    * ``rp_id`` 与 ``expected_rp`` 都是小写 ASCII 域名，标签非空、无前导或尾随点，
      且至少有两个标签；不得包含协议、端口、路径或通配符；
    * ``rp_id == expected_rp``，或 ``expected_rp`` 以 ``"." + rp_id`` 结尾；因此
      ``example.com`` 可以作为 ``login.example.com`` 的父域，但
      ``evil.login.example.com`` 不是父域，必须拒绝；
    * ``rp_id`` 不是公共后缀；
    * ``rp_id`` 与 ``expected_rp`` 的注册后缀（registrable suffix）相同。

    为避免引入外部公共后缀库，本题使用固定公共后缀集合：
    ``com``、``org``、``net``、``edu``、``gov``、``io``、``co``、``uk``、
    ``co.uk``、``org.uk``、``com.au``、``net.au``、``co.jp``、``com.br``、
    ``co.nz``。注册后缀取最后两个标签；若最后两个标签命中上述集合，则取最后三个
    标签。例如 ``login.example.com`` 与 ``example.com`` 的注册后缀都是
    ``example.com``；``co.uk`` 是公共后缀，不能作为 ``rp_id``。

    该规则同时阻断三类错误：把 ``com`` 当父域、把任意子域当 ``rp_id``、以及用
    ``"notexample.com"`` 之类的字符串做无边界的后缀比较。
    """
    if not _is_valid_domain(rp_id) or not _is_valid_domain(expected_rp):
        return False

    # rp_id 本身不能是公共后缀（如 com、co.uk）。
    if rp_id in PUBLIC_SUFFIXES:
        return False

    # 只允许期望值本身，或 expected_rp 的父域（带边界的 "." + rp_id 后缀比较）。
    if rp_id != expected_rp and not expected_rp.endswith("." + rp_id):
        return False

    # 注册后缀必须相同，阻断跨注册域的凭证（evil.com vs login.example.com）。
    if _registrable_suffix(rp_id) != _registrable_suffix(expected_rp):
        return False

    return True


def check_counter(credential: dict, sign_count: int) -> bool:
    """检查签名计数是否严格递增；计数器为零时按专门规则处理。

    只读取 ``credential["assertion"]["sign_count"]`` 作为已接受计数，绝不能读取
    ``credential["registration"]["sign_count"]``。注册阶段写入的计数不得污染断言
    计数。

    * ``sign_count`` 必须是 int（``bool`` 不算 int）且非负；
    * 已接受计数也必须是合法非负 int，否则返回 ``False``；
    * 若已接受计数大于 0，则仅当 ``sign_count > 已接受计数`` 时返回 ``True``；等于或
      小于都返回 ``False``，因此计数器被清零后不能继续使用；
    * 若已接受计数等于 0，则 ``sign_count == 0`` 与 ``sign_count > 0`` 都返回
      ``True``，以兼容不支持计数器的认证器；负数仍然拒绝。

    本函数只判断，不修改凭证状态；只有 :func:`assertion_batch` 在整条断言成功后
    才推进 ``credential["assertion"]["sign_count"]``。
    """
    try:
        if not _is_real_int(sign_count) or sign_count < 0:
            return False

        # 只读取断言状态；注册阶段的计数绝不参与判断，避免污染。
        accepted = credential["assertion"]["sign_count"]
        if not _is_real_int(accepted) or accepted < 0:
            return False

        if accepted > 0:
            # 已接受计数大于 0：必须严格递增，等于（重放）或清零都拒绝。
            return sign_count > accepted
        # 已接受计数为 0：兼容不支持计数器的认证器，0 与正数都接受，负数已在上面拒绝。
        return sign_count >= 0
    except (KeyError, TypeError):
        return False


def verify_signature(
    credential: dict,
    client_data_hash: bytes,
    authenticator_data: bytes,
    signature: bytes,
) -> bool:
    """验证签名、RP 绑定与用户在场标志，并使用恒定时间比较。

    通过条件（全部满足）：

    * ``client_data_hash`` 是 32 字节，``authenticator_data`` 是 37 字节，
      ``signature`` 是 32 字节；``credential["public_key"]`` 是非空 bytes；
    * ``authenticator_data[:32]`` 等于
      ``sha256(credential["rp_id"].encode("utf-8")).digest()``，把凭证绑定到 RP；
    * ``authenticator_data[32] & 0x01`` 非零，即用户在场标志必须置位；
    * 期望签名是
      ``HMAC-SHA256(public_key, client_data_hash + authenticator_data)``，并且只用
      ``hmac.compare_digest`` 与传入签名比较。

    签名输入必须同时覆盖客户端数据摘要和认证器数据。若缺少客户端数据摘要，签名就
    会与挑战脱钩，同一认证器数据可被换到另一个挑战上。任何类型、长度或内容不匹配
    都返回 ``False``，不抛异常。本函数不校验挑战一次性、来源、RP ID 策略或计数。
    """
    try:
        if not isinstance(client_data_hash, bytes) or len(client_data_hash) != 32:
            return False
        if not isinstance(authenticator_data, bytes) or len(authenticator_data) != 37:
            return False
        if not isinstance(signature, bytes) or len(signature) != 32:
            return False

        public_key = credential["public_key"]
        if not isinstance(public_key, bytes) or not public_key:
            return False
        rp_id = credential["rp_id"]
        if not isinstance(rp_id, str):
            return False

        # RP 绑定：认证器数据前 32 字节必须是凭证所属 rp_id 的哈希。
        expected_rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        if not hmac.compare_digest(authenticator_data[:32], expected_rp_id_hash):
            return False

        # 用户在场标志（bit 0）必须置位。
        if authenticator_data[32] & 0x01 == 0:
            return False

        # 签名输入同时覆盖客户端数据摘要与认证器数据，使签名与挑战绑定。
        expected_signature = hmac.new(
            public_key,
            client_data_hash + authenticator_data,
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(signature, expected_signature)
    except (KeyError, TypeError):
        return False


def assertion_batch(requests: list[dict], policy: dict, now: int) -> dict:
    """批量校验断言，每个请求独立解析、独立消费挑战，返回固定结构的结果。

    ``policy`` 形如::

        {
            "store": {"challenges": {}},
            "expected_origin": "https://login.example.com",
            "expected_rp_id": "login.example.com",
        }

    每个请求形如::

        {"id": "r1", "credential": {...}, "raw": {...}}

    处理顺序必须是：解析 ``raw``；比较 ``raw`` 的凭证标识与
    ``request["credential"]["credential_id"]``；调用
    :func:`check_challenge`；调用 :func:`check_origin`；调用
    :func:`check_rp_id(credential["rp_id"], policy["expected_rp_id"])`；调用
    :func:`verify_signature`；调用 :func:`check_counter`。挑战一旦通过校验就立即
    作废，即使后续来源、RP ID、签名或计数失败也不得回滚。

    每个请求都必须重新解析自己的 ``raw``、重新读取自己的挑战与凭证，不得缓存上一个
    请求的解析结果、挑战状态或校验结果。两个请求携带同一个挑战时，第一个成功后第二
    个必须因 ``challenge`` 失败；不得先在副本上批量预检再统一提交。

    全部检查通过时，把 ``credential["assertion"]["sign_count"]`` 推进为该请求的
    ``sign_count``；失败时不得修改凭证计数。结果按输入顺序返回：

    * ``results``：每项 ``{"id": ..., "ok": bool, "reason": str | None}``；
    * ``accepted``：成功请求的 id 列表，保持输入顺序；
    * ``rejected``：失败请求的 id 列表，保持输入顺序；
    * ``ok``：所有请求都成功时为 ``True``。

    失败原因按上面检查顺序取第一个失败项：``parse_error``、``credential_mismatch``、
    ``challenge``、``origin``、``rp_id``、``signature``、``counter``。请求缺字段、
    类型错误或 ``raw`` 无法解析时该请求失败并归入 ``parse_error``，不得让整批抛异常；
    重复 id 合法，结果仍按位置返回。
    """
    store = policy["store"]
    expected_origin = policy["expected_origin"]
    expected_rp_id = policy["expected_rp_id"]

    results = []
    accepted = []
    rejected = []

    for request in requests:
        request_id = request.get("id") if isinstance(request, dict) else None
        result = {"id": request_id, "ok": False, "reason": None}
        results.append(result)

        try:
            # 每个请求独立解析自己的 raw，绝不复用上一个请求的任何状态。
            if not isinstance(request, dict):
                raise ValueError("request must be a mapping")
            credential = request["credential"]
            raw = request["raw"]
            if not isinstance(credential, dict):
                raise ValueError("credential must be a mapping")

            parsed = parse_assertion(raw)
        except (KeyError, TypeError, ValueError):
            result["reason"] = "parse_error"
            rejected.append(request_id)
            continue

        # 凭证标识必须与请求携带的凭证一致。
        if parsed["credential_id"] != credential.get("credential_id"):
            result["reason"] = "credential_mismatch"
            rejected.append(request_id)
            continue

        # 挑战：成功即作废，即使后续检查失败也不回滚；第二个同挑战请求在此失败。
        if not check_challenge(store, parsed["challenge"], now):
            result["reason"] = "challenge"
            rejected.append(request_id)
            continue

        if not check_origin(parsed["client_data"], expected_origin):
            result["reason"] = "origin"
            rejected.append(request_id)
            continue

        if not check_rp_id(credential["rp_id"], expected_rp_id):
            result["reason"] = "rp_id"
            rejected.append(request_id)
            continue

        if not verify_signature(
            credential,
            parsed["client_data_hash"],
            parsed["authenticator_data"],
            parsed["signature"],
        ):
            result["reason"] = "signature"
            rejected.append(request_id)
            continue

        if not check_counter(credential, parsed["sign_count"]):
            result["reason"] = "counter"
            rejected.append(request_id)
            continue

        # 全部检查通过后才推进断言计数；失败路径不会修改凭证状态。
        credential["assertion"]["sign_count"] = parsed["sign_count"]
        result["ok"] = True
        result["reason"] = None
        accepted.append(request_id)

    return {
        "ok": len(rejected) == 0,
        "accepted": accepted,
        "rejected": rejected,
        "results": results,
    }
"""WebAuthn 无密码登录题目门面包。

只从 :mod:`webauthn.api` 导出 8 个公开函数；实现在 :mod:`webauthn._impl`。
"""

from .api import (
    assertion_batch,
    check_challenge,
    check_counter,
    check_origin,
    check_rp_id,
    issue_challenge,
    parse_assertion,
    verify_signature,
)

__all__ = [
    "issue_challenge",
    "parse_assertion",
    "check_challenge",
    "check_origin",
    "check_rp_id",
    "check_counter",
    "verify_signature",
    "assertion_batch",
]
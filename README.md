换成无密码登录之后，同一个断言重放两次都能登录，签名计数也从来不变：挑战校验通过后不作废，同一断言可反复重放；挑战不校验过期时间，签发后长期有效；来源匹配用后缀比较，攻击者子域被放行；来源匹配忽略协议差异，明文来源与安全来源等同；依赖方标识接受任意子域且不做注册后缀检查，跨依赖方凭证可用；签名计数只校验非负，不要求严格递增；计数为零时按递增放行，计数器被清零后仍可使用；验签只覆盖认证器数据而缺少客户端数据摘要，也不核验用户在场标志，签名与挑战脱钩且凭证绑定失效；注册与断言共用凭证状态，注册阶段计数污染断言；批量校验复用挑战状态，第二个请求命中第一个请求的挑战。webauthn/_impl.py 是核心，tests/test_assertion.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行，不需要安装、联网或启动服务：

```powershell
cd D:\gsb-20261119\sec-webauthn
python -m pytest tests -q
```

初始状态必须恰好有 **15 failed**，且没有 collection error、import error 或 syntax error；每个失败都必须是 `NotImplementedError`。输出末行形如：

```text
15 failed in 0.02s
```

`webauthn/_impl.py` 中恰好有 8 个函数，全部直接 `raise NotImplementedError`。实现时只替换这 8 个函数体，不要修改函数签名，不要把测试改成跳过、参数化或通过。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 协议契约

### 挑战

`issue_challenge(store, user, now, ttl)` 返回并写入 `store["challenges"][challenge]` 的记录：

```text
challenge   不可预测的新字符串
user        发起用户
issued_at   签发时刻
expires_at  now + ttl
used        初始 False
used_at     初始 None
```

有效区间是 `issued_at <= now <= expires_at`，边界时刻有效。`check_challenge` 必须同时检查存在、未使用、未过期和不是未来签发；成功时在返回前把 `used` 置为 `True`、`used_at` 置为当前时刻。即使后续来源、RP ID、验签或计数失败，挑战也不得恢复。

### 客户端数据

客户端数据是 JSON 对象：

```json
{"type": "webauthn.get", "challenge": "...", "origin": "https://login.example.com"}
```

映射输入按 `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))` 的 UTF-8 字节规范化。`client_data_hash` 是这串字节的 SHA-256。

### 认证器数据与签名

认证器数据固定 37 字节：

```text
bytes 0..31   sha256(rp_id.encode("utf-8")).digest()
byte 32       标志位，bit 0（0x01）表示用户在场
bytes 33..36  大端无符号签名计数
```

本题用 HMAC-SHA256 模拟公钥签名，`credential["public_key"]` 是共享密钥：

```text
signature = HMAC-SHA256(public_key, client_data_hash + authenticator_data)
```

必须使用 `hmac.compare_digest` 比较签名。`verify_signature` 还要校验 `authenticator_data[:32]` 与凭证的 `rp_id` 一致，并要求用户在场标志置位。

### 凭证状态

```text
credential:
  credential_id              bytes
  rp_id                      str
  public_key                 bytes
  user_handle                bytes
  registration.sign_count    注册阶段计数
  assertion.sign_count       已接受的断言计数
```

注册状态和断言状态必须分开保存。`check_counter` 只能读取 `assertion.sign_count`，不能读取注册计数。计数大于 0 时必须严格递增；已接受计数为 0 时，0 和正数都可以接受；已接受计数大于 0 时，新的 0 必须拒绝。

### RP ID

`check_rp_id(rp_id, expected_rp)` 只允许：

- `rp_id == expected_rp`；
- 或 `rp_id` 是 `expected_rp` 的父域，即 `expected_rp.endswith("." + rp_id)`；
- 且 `rp_id` 不是公共后缀；
- 且二者注册后缀相同。

固定公共后缀集合为 `com`、`org`、`net`、`edu`、`gov`、`io`、`co`、`uk`、`co.uk`、`org.uk`、`com.au`、`net.au`、`co.jp`、`com.br`、`co.nz`。注册后缀取最后两段；若最后两段命中集合，则取最后三段。

### 批量校验

`assertion_batch(requests, policy, now)` 的 `policy` 包含：

```text
store            挑战存储
expected_origin  精确来源
expected_rp_id   期望 RP ID
```

每个请求是 `{"id", "credential", "raw"}`。必须逐请求重新解析、重新消费挑战，禁止复用上一个请求的挑战或解析结果。同一条挑战出现在两个请求中时，第二个必须失败。结果固定为：

```text
{
  "ok": bool,
  "accepted": [id, ...],
  "rejected": [id, ...],
  "results": [{"id": id, "ok": bool, "reason": str | None}, ...]
}
```

失败原因只取 `parse_error`、`credential_mismatch`、`challenge`、`origin`、`rp_id`、`signature`、`counter`。成功时推进 `credential["assertion"]["sign_count"]`；失败时不推进。

## 门面布局

```text
sec-webauthn/
├── README.md
├── conftest.py
├── webauthn/
│   ├── __init__.py
│   ├── _impl.py
│   └── api.py
└── tests/
    └── test_assertion.py
```

- `webauthn/__init__.py` 只从 `webauthn.api` 导出 8 个公开函数。
- `webauthn/api.py` 只做再导出，不含任何校验或状态逻辑。
- `webauthn/_impl.py` 是唯一实现文件，恰好 8 个桩，全部 `raise NotImplementedError`。
- 测试只通过 `import webauthn` 调用顶层 API，不直接导入 `_impl`，避免绕过门面。

## tests 不可修改

`tests/test_assertion.py` 是验收标准，不可修改、删除、跳过、参数化替换或放宽。不要改动测试中的固定密钥、挑战、时间、计数和断言；只能实现 `webauthn/_impl.py` 中的 8 个函数体。
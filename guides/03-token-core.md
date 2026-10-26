# 03 · token 核与旋转

token 核是纯函数面:签发、校验、带门校验、换发,时间与熵全参数注入
(核心零时钟零随机——测试不睡不 mock,生产用真钟 + CSPRNG)。

## 线形

```
base64url(定序 JSON 载荷) "." base64url(mac)
载荷字段(定序):sub / iss / aud / iat / exp / typ / jti
```

- 线形对消费方是**黑盒字符串**——只该由 `issue` 产出、`verify` 消费,
  不要自己拼解。
- 校验序(mac 核 → 定型 → iss/aud → 时间窗)是框架私产,任何一段拒
  即短路;mac 校验**先于**载荷解析,不可信字节不碰。

## 三式

```moonbit
// 签发:exp = now + (typ 对应的 ttl);jti 由你注入(CSPRNG)
let issued = @moongrd.issue(config, signer, now, "alice", @moongrd.TokenType::Access, "jti-1")

// 校验(任一 typ)
let r = @moongrd.verify(config, signer, now, issued.token)

// 带门校验(业务门只收 access;refresh 门只收 refresh)
let r2 = @moongrd.verify_for(config, signer, now, token, @moongrd.TokenType::Access)
```

## 时间窗与 drift

有效判定:`iat - now ≤ drift` 且 `now ≤ exp + drift`。默认
`allowed_drift = 5000ms`;时钟不同步的集群可放大:

```moonbit
let loose : @moongrd.GuardConfig = {
  issuer: "demo-iss", audience: "demo-app",
  allowed_drift_ms: 60000L,
  access_ttl_ms: 60000L, refresh_ttl_ms: 600000L,
}
```

## 换发与旋转(会话续命)

access 短命、refresh 长命。access 过期后拿 refresh 换发,**旧 refresh
立即作废**,新 refresh 入同族:

```moonbit
match @moongrd.refresh(config, signer, store, now, refresh_token, next_jti) {
  Ok(r) => {
    // r.refresh:新 refresh 票(记得 store.put 入账由 refresh 内部完成)
    // access 用 issue(config, signer, now, r.sub, Access, 新 jti) 另发
  }
  Err(@moongrd.RefreshErr::Verify(Expired(_))) => // refresh 也过期了:回握手重登录
  Err(e) => // 其他拒
}
```

## 重放检测与撤全族

已 used 的 refresh 再次出现 = **被盗信号**,框架自动 `revoke_family`——
该族所有 refresh(含最新那张)一并作废:

```moonbit
match @moongrd.refresh(config, signer, store, now, old_token, "jti-new") {
  Err(@moongrd.RefreshErr::Replayed(family)) => println("族 \{family} 已全撤")
  ...
}
```

登出/紧急下线同理:`store.revoke_family(family_id)` 一行走人。

## 错误面(token 核)

| 错误 | 含义 | 处置建议 |
|---|---|---|
| `Malformed(_)` | 线形/编码/定型败 | 不是本框架签的票,直接拒 |
| `BadMac` | 签名不符(篡改/异钥) | 安全事件,记审计 |
| `Expired(claims)` | 过期(带 claims 供审计) | access → 引导刷新;refresh → 回登录 |
| `NotYetValid(claims)` | 生效未到(未来票) | 查两端时钟 |
| `WrongIssuer / WrongAudience` | iss/aud 不配 | 多系统混用票,配置错了 |
| `WrongType(claims)` | access/refresh 走错门 | 用 `verify_for` 钉死每扇门的 typ |

## 下一步

- 想把这套票装进四段门:[04 · 四段管线与 Guard 全形](04-guard-pipeline.md)
- 想换签名算法(HMAC → Ed25519 等):[05 · 五换挡位](05-swap-points.md)

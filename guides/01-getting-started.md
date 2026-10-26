# 01 · 五分钟上一门

目标:从安装到"发出一张票、过一道门",不碰任何泛型标注。

## 1. 安装

```bash
moon add thy1016/moongard
moon add thy1016/moongard/adapter/mooncry   # 真加密面(HMAC-SHA256)
moon add thy1016/moongard/memstore          # 内存账本(族谱/吊销表)
moon add thy1016/moongard/style/handler     # 回调方言
```

消费包 `moon.pkg` 的 import 块加上对应路径,前缀分别为
`@moongard` / `@mooncry` / `@memstore` / `@handler`。

## 2. 配置与签名者

```moonbit
let config = @moongard.GuardConfig::make(
  issuer="demo-iss",
  audience="demo-app",
  access_ttl_ms=60000L,      // access 票 60 秒
  refresh_ttl_ms=600000L,    // refresh 票 10 分钟
)
// 真实部署:key 来自启动期口令/PSK 拉伸(见 05 篇慢哈希律)
let signer : &@moongard.Signer = @mooncry.HmacSha256Signer::new(
  Bytes::make(32, b'\x11'),
)
```

## 3. 发一张 access 票

```moonbit
// 时间与 jti 由你注入(核心零时钟零随机;生产用真钟 + CSPRNG)
let token = @moongard.issue(
  config,
  signer,
  now_ms(),
  "alice",
  @moongard.TokenType::Access,
  "jti-0001",
)
// token.token 即线形字符串,随请求带给服务端
```

## 4. 一键起门(预设形)

```moonbit
let handler = @handler.FlexDoor::demo(allow=["alice"], prefix="[door] ")
let door = @handler.mount(
  config=config,
  signer=signer,
  revocations=@memstore.MemRevocationStore::new(),
  handler,
)
```

## 5. 进门

```moonbit
match door.run(now_ms(), token.token, Json::string("读空间 doc1")) {
  Ok(resp) => println("放行 → \{resp.stringify()}")
  Err(e) => println("拒 → \{e.to_repr()}")
}
```

## 6. 读拒因

| 拒因(短) | 含义 | 常见原因 |
|---|---|---|
| `Unresolved(sub)` | 陌生人 | admit 回 false:名单没这个人 |
| `Verify(Expired)` | 票过期 | 用 access 过了 TTL+drift;去换发(见 03 篇) |
| `Verify(BadMac)` | 签名不符 | 票被改过,或签发/验签不是同一 signer |
| `Verify(WrongType)` | 型不符 | 拿 refresh 票走 access 门(反之亦然) |
| `Revoked` | 已吊销 | 登出或紧急停门后 |

## 7. 下一步

- 想自己写三个回调(而不是用预设):[02 · 门房回调](02-handler-callbacks.md)
- 想懂票为什么过期、refresh 怎么续命:[03 · token 核与旋转](03-token-core.md)

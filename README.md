# MoonGard

Guardian 式认证管道框架(MoonBit):access/refresh 双 token 旋转与四段
分发管线(verify → revocation → resolve → dispatch,段段审计)。设计
借鉴 Elixir Guardian:双 token 旋转、时钟漂移容忍、段间纯值管线。

核心包零依赖:不内置传输、存储与密码学实现。算法藏在 `Signer` /
`Cipher` trait 后(参考实现绑定 mooncry);安全信道属 TLS 层职责,不在
本框架范围,token 由既有信道承载。

## 包结构

| 包 | 内容 |
|---|---|
| `thy1016/moongard` | token 核与四段门 |
| `thy1016/moongard/memstore` | 内存账本(测试与单机用) |
| `thy1016/moongard/style/handler` | 回调方言(具名回调,免写 async) |
| `thy1016/moongard/adapter/mooncry` | 真加密面(HMAC-SHA256 / AES-GCM) |

**状态**:0.1.2。0.x 实验期,API 仍可能随反馈调整;未经独立安全审计。
设计决策表(D-G1~G20)见 [spec.md](spec.md)。

## 特性

- **token 核**:双 token 签发/校验/带门校验,定序 JSON + base64url
  线形,HMAC 签名;时间与熵全参数注入(核心零时钟零随机)。
- **旋转语义**:refresh 一次性作废;已用票再现判定为重放,自动撤销
  全族。
- **四段门**:段段审计、拒绝短路带拒因;回调方言 / 标签钩子 / 泛型
  钩子三种接入方式。
- **五个 trait 换挡位**:Signer、Cipher、AuthProtocol、
  RefreshStore、RevocationStore——新实现即新 impl,框架不改。
- **预制回调与运行时换装**:名单准入、回声派工、审计三形现成;
  FlexDoor `swap_*` 运行时替换,即时生效。

## 安装

```bash
moon add thy1016/moongard
```

消费包 `moon.pkg` 按需添加 import:`thy1016/moongard`(`@moongard`),
及子包 `style/handler`(`@handler`)、`adapter/mooncry`(`@mooncry`)、
`memstore`(`@memstore`)。

## 快速上手

分步文档见 `guides/`:入门[五分钟上一门](guides/01-getting-started.md)、[门房回调](guides/02-handler-callbacks.md);进阶[token 核与旋转](guides/03-token-core.md)、[四段管线](guides/04-guard-pipeline.md)、[换挡位与 adapter](guides/05-swap-points.md)。

### 签发与校验(token 核)

```moonbit
let config = @moongard.GuardConfig::make(
  issuer="demo-iss",
  audience="demo-app",
  access_ttl_ms=60000L,
  refresh_ttl_ms=600000L,
)
let signer : &@moongard.Signer = @mooncry.HmacSha256Signer::new(session_key)
// 签发:时间与熵(jti)由调用方注入
let access = @moongard.issue(config, signer, now, "alice", @moongard.TokenType::Access, jti_a)
let refresh = @moongard.issue(config, signer, now, "alice", @moongard.TokenType::Refresh, jti_r)
// 业务门:typ 不对即拒
match @moongard.verify_for(config, signer, now, access.token, @moongard.TokenType::Access) {
  Ok(claims) => // claims.sub 即主体
  Err(e) => // 拒因:过期/签名不符/型不符……
}
```

### 四段门(三种接入方式)

方式一,回调方言:实现三个具名回调,`mount` 即得一门;主体即 sub,
req/resp 走 Json,全程不写 async:

```moonbit
pub impl DoorHandler for MyDoor with admit(self : MyDoor, sub : String) -> Bool { ... }
pub impl DoorHandler for MyDoor with dispatch(self : MyDoor, sub : String, req : Json) -> Json { ... }
pub impl DoorHandler for MyDoor with audit(self : MyDoor, e : @moongard.AuditEvent) -> Unit { ... }

let door = @handler.mount(config=config, signer=signer,
                          revocations=revocations, handler=my_door)
let resp = door.run(now, access_token, req)
```

方式二,标签钩子:audit 可省(省略即吞流):

```moonbit
let door = @moongard.Guard::new(
  config=config, signer=signer, revocations=revocations,
  resolve=async fn(sub : String) -> User? { ... },        // sub → 主体
  dispatch=async fn(u : User, req : Req) -> Resp { ... }, // 业务到达
)
```

方式三,挂审计与协议换挡:每段落一行审计事件;`protocol=` 可换认证
协议(缺省 bearer token):

```moonbit
let door = @moongard.Guard::new(
  config=config, signer=signer, revocations=revocations,
  resolve=..., dispatch=...,
  audit=async fn(e : @moongard.AuditEvent) -> Unit { ... },
  protocol=my_protocol,
)
```

### 换发与旋转

```moonbit
match @moongard.refresh(config, signer, store, now, refresh_token, next_jti) {
  Ok(r) => // 新 refresh 到手;access 用 issue() 另发
  Err(@moongard.RefreshErr::Replayed(family)) => // 重放:全族已自动作废
  Err(@moongard.RefreshErr::Verify(Expired(_))) => // 转登录,重新认证
  ...
}
```

### 预制回调与运行时换装

```moonbit
let handler = @handler.FlexDoor::demo(allow=["alice"], prefix="[admin] ")
// 运行时替换,已挂门即时生效:
handler.swap_admit(admit=@handler.admit_none())   // 紧急停门
handler.swap_admit(admit=@handler.admit_allowlist(allow=["alice", "carol"]))
handler.swap_audit(audit=@handler.audit_collector(log=lines))
```

`@handler` 提供七个预制工厂:`admit_allowlist` / `admit_all` /
`admit_none` / `dispatch_echo` / `audit_println` / `audit_silent` /
`audit_collector`。

### 示例

四个可运行示例:

```bash
moon run examples/walkthrough          # 全链六幕:登录/门/旋转/重放撤族/篡改拒
moon run examples/session_lifecycle    # 会话一生五幕:登录→过期→换发→登出
moon run examples/handler_demo         # 回调方言三幕
moon run examples/signer_swap          # 换 verify 算法三幕(HMAC-SHA512/CMAC/Ed25519)
```

## API 总览

| 入口(`@moongard`) | 作用 |
|---|---|
| `GuardConfig::make(issuer~, audience~, access_ttl_ms~, refresh_ttl_ms~)` | 配置(drift 默认 5000ms) |
| `issue(config, signer, now, sub, typ, jti)` | 签发(纯函数) |
| `verify(config, signer, now, token)` | 校验(任一 typ) |
| `verify_for(config, signer, now, token, typ)` | 带门校验 |
| `refresh(config, signer, store, now, token, next_jti)` | 换发(旋转 + 重放撤全族) |
| `Guard::new(config~, signer~, revocations~, resolve~, dispatch~, audit?, protocol?)` | 四段门单构造点 |
| `Guard::run(now, token, req)` | 过门 |
| trait 五位 | `Signer` `Cipher` `RefreshStore` `RevocationStore` `AuthProtocol` |

| 入口(`@handler`) | 作用 |
|---|---|
| `DoorHandler`(admit/dispatch/audit)+ `mount(...)` | 回调方言接线 |
| `admit_allowlist` / `admit_all` / `admit_none` | 预制准入 |
| `dispatch_echo` | 预制派工 |
| `audit_println` / `audit_silent` / `audit_collector` | 预制审计 |
| `FlexDoor::new / demo` + `swap_admit / swap_dispatch / swap_audit` | 运行时换装 |

| 入口(`@mooncry` / `@memstore`) | 作用 |
|---|---|
| `HmacSha256Signer::new(key)` | 签名面(RFC 4231 KAT 过 trait) |
| `AesGcmCipher::new(key)` | AEAD 密封面 |
| `MemRefreshStore::new / sweep`、`MemRevocationStore::new` | 内存账本 |

## 错误面

```
VerifyErr   Malformed(线形/编码/定型败) · BadMac(签名不符/篡改)
            · Expired(claims) · NotYetValid(claims) · WrongIssuer(claims)
            · WrongAudience(claims) · WrongType(claims)
RefreshErr  Verify(内含 VerifyErr;Expired = 重新认证信号)
            · UnknownToken(mac 过但账本无记录) · Replayed(family)(已撤族)
            · Revoked(claims)
GuardErr    Verify(内含) · Revoked · Unresolved(sub)
```

语义三条:核心面全 `Result`/`Option` 化,无 abort 无 trap;mac 校验前
的错误不携带载荷,mac 后的错误携带 claims 供审计;拒绝一律无 oracle。

## 设计边界

回调收在**数据面**(数据从哪来、结果到哪去),不收在**控制面**(校验
序、短路逻辑)——verify 段是框架私产,不开放回调;换算法(Signer)≠
关校验。

| 扩展点 | 形 |
|---|---|
| `Signer` / `Cipher` / `AuthProtocol`(有状态算法/协议面) | trait |
| `RefreshStore` / `RevocationStore`(多式共享状态) | trait |
| `resolve` / `dispatch` / `audit`(单钩子) | 闭包 |
| TTL / drift / issuer / audience | 字段配置 |
| 校验序、线形格式、Claims 形状、旋转策略 | **钉死**(安全语义) |

已知边界(0.x):记录层钉 AES-GCM(ChaCha20 换挡 = trait 位,需求触发);
rekey 留接口未实现;Ed25519 Signer 备位未落;未经独立安全审计——公网
部署请配合信道层 PFS 并自行评审。

## 测试与验证

```bash
moon test --target native        # 38 项测试
```

覆盖 token 核线形边界、旋转与账本、四段管线、回调方言与换装;含
RFC 4231 HMAC 已知答案向量。四个示例即文档,可直接运行
(`moon run examples/<名称> --target native`)。

## 许可证

Apache-2.0。

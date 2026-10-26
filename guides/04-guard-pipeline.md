# 04 · 四段管线与 Guard 全形

Guard 是认证门的单构造点:三个钩子由你注入,协议与算法可换挡,四段
语义框架私产。本篇讲全形与高级用法。

## 四段语义

```
verify      票真不真:mac → 定型 → iss/aud → 时间窗(±allowed_drift)
revocation  票被吊销没:查 RevocationStore(登出/紧急下线的即时面)
resolve     主体装载:sub → 你的领域对象(查库/查缓存,你说了算)
dispatch    业务到达:已认证主体处理请求,应答原路折回
audit       全程每段一行 AuditEvent,拒绝短路带拒因
```

段间纯值;任何一段拒即短路,后续段不执行;审计事件照发(拒因携带,
供定罪)。

## Guard 全形(进阶)

```moonbit
let door = @moongrd.Guard::new(
  config=config,
  signer=signer,
  revocations=revocations,
  resolve=async fn(sub : String) -> User? { ... },      // None = 陌生人拒
  dispatch=async fn(u : User, req : Req) -> Resp { ... },
  audit=async fn(e : @moongrd.AuditEvent) -> Unit { ... }, // 可省,省略 = 吞流
  protocol=my_protocol,                                   // 可省,省略 = bearer token
)
let resp = door.run(now_ms(), access_token, req)  // 泛型 TReq/TResp 任意
```

- 主体型 `TSubj` 泛型:你的 User/Session 结构直接用,框架不假设任何
  用户库(类型从 `resolve` 钩子推断,免 turbofish)。
- `audit` 不可失败:返回 `Unit`,写败是 sink 自己的事,管线不被拖死。
- 业务错误**不走** `GuardErr`——dispatch 的失败语义由你的 `Resp` 自己
  表达(如 `Result` 内嵌),框架只管认证拒。

## GuardErr 三形

| 错误 | 段 | 含义 |
|---|---|---|
| `Verify(VerifyErr)` | verify | 票不合法(过期/篡改/型错……内含细节) |
| `Revoked` | revocation | 票在吊销表(登出/紧急下线) |
| `Unresolved(sub)` | resolve | 主体装载失败(查无此人) |

## 协议换挡(AuthProtocol)

缺省协议 = bearer token(核心 `TokenProtocol`)。换认证协议 = 实现
trait,构造时挂上;**校验序与短路逻辑不变**:

```moonbit
pub(open) trait AuthProtocol {
  async fn verify_access(
    self : Self,
    config~ : GuardConfig,
    signer~ : &Signer,
    now~ : Int64,
    token~ : String,
  ) -> Result[Claims, VerifyErr]
}

// 例:内网工具的固定口令协议(测试/演示形;生产请走 TokenProtocol + 强钥)
pub impl AuthProtocol for SharedSecretProtocol with verify_access(...) {
  // 你的校验逻辑;返回定型 Claims 即视为认证通过
}
```

注意:协议在**构造期钉死**,不做运行时协商(降级攻击面);refresh
旋转属 bearer token 协议的续命面,换协议时续命策略由你的协议自带。

## 与回调方言的关系

`style/handler` 的 `DoorHandler` + `mount` 是本全形的**具象特例**
(主体 = sub 字符串,req/resp = Json,三回调即三钩子)。初级走方言,
需要泛型主体/自定义凭据型时下到本全形——语义完全同一。

## 测试建议

- 每段拒绝一罐(verify 拒/revoked/unresolved),断言 audit 行数与行序。
- 协议换挡一罐:自定义协议下合法凭据过、非法凭据拒。
- 参考实作:`memstore/guard_test.mbt`(全链/短路/换挡齐全)。

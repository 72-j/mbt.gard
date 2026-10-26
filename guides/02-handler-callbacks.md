# 02 · 门房回调(DoorHandler 三回调)

回调方言是初级主门:实现三个具名回调,`mount` 一句接线。三回调各有
明确职责,写的时候只需要回答三个问题——**认不认、怎么干、怎么记**。

## 三回调各职

| 回调 | 对应段 | 你回答的问题 | 签名 |
|---|---|---|---|
| `admit` | resolve | 这个人认不认?(false = 陌生人拒) | `(sub : String) -> Bool` |
| `dispatch` | dispatch | 认证过了,活儿怎么干? | `(sub : String, req : Json) -> Json` |
| `audit` | 全程 | 流水账怎么记?(不可失败,不想记写空体) | `(e : AuditEvent) -> Unit` |

主体就是 `sub` 字符串;请求/应答走 `Json`——零泛型、零 async 标注
(asyncness 从 trait 继承,你一个字母都不用写)。

## 实现一份门房

```moonbit
///|
struct MyDoor {
  allow : String
}

///|
pub impl @moongrd.DoorHandler for MyDoor with admit(
  self : MyDoor,
  sub : String,
) -> Bool {
  sub == self.allow
}

///|
pub impl @moongrd.DoorHandler for MyDoor with dispatch(
  self : MyDoor,
  sub : String,
  req : Json,
) -> Json {
  Json::string("已为 \{sub} 处理 \{req.stringify()}")
}

///|
pub impl @moongrd.DoorHandler for MyDoor with audit(
  self : MyDoor,
  e : @moongrd.AuditEvent,
) -> Unit {
  println("[audit] \{e.stage} ok=\{e.ok} \{e.detail}")
}
```

## 挂载与过门

```moonbit
let door = @handler.mount(
  config=config,
  signer=signer,
  revocations=@memstore.MemRevocationStore::new(),
  handler=MyDoor::{ allow: "alice" },
)
let resp = door.run(now_ms(), access_token, Json::string("读空间 doc1"))
```

`run` 内部走四段:verify(票真不真)→ revocation(吊销没)→
resolve(你的 `admit`)→ dispatch(你的 `dispatch`);每段落一行
`AuditEvent` 交给你的 `audit`。任何一段拒即短路,后续段不执行。

## 嫌自己写麻烦?stock 预制库

`style/handler` 内置七个工厂,常见形一行取用:

```moonbit
@handler.admit_allowlist(allow=["alice", "bob"])  // 名单准入
@handler.admit_all()                              // 全放(演示)
@handler.admit_none()                             // 全拒(紧急停门)
@handler.dispatch_echo(prefix="[door] ")          // 回声派工
@handler.audit_println()                          // 审计上屏
@handler.audit_silent()                           // 审计吞流
@handler.audit_collector(log=lines)               // 审计收集进数组
```

`FlexDoor` 把三个函数位做成**可热换**的——已挂的门运行时一键换装:

```moonbit
let handler = @handler.FlexDoor::demo(allow=["alice"], prefix="[door] ")
let door = @handler.mount(config=config, signer=signer,
                          revocations=revocations, handler)

// 紧急停门:一行,已挂门即时生效
handler.swap_admit(admit=@handler.admit_none())
// 复活:
handler.swap_admit(admit=@handler.admit_allowlist(allow=["alice"]))
// 换派工:
handler.swap_dispatch(
  dispatch=fn(sub : String, _req : Json) -> Json {
    Json::string("维护中,请稍后再试")
  },
)
```

## 测试建议

- 全链绿一罐:合法票 `run` 得应答,audit 收到四行
  (verify/revocation/resolve/dispatch 各一)。
- 陌生人一罐:`admit` false → `Err(Unresolved(sub))`,且 dispatch 不曾
  到场(audit 只有三行)。
- 参考实作:`style/handler/handler_test.mbt` 与 `stock_test.mbt`。

## 下一步

- 想知道票本身怎么防伪、为什么过期:[03 · token 核与旋转](03-token-core.md)
- 想换签名算法或整个认证协议:[05 · 五换挡位](05-swap-points.md)

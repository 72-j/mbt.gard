// main.mbt — 回调方言演示:实现三回调 + 一句 mount = 一道四段门
// 运行:cd moongrd && moon run examples/handler_demo
// 对照:examples/walkthrough 是进阶形(泛型钩子);本演示是初级形——
// 用户的全部工作量 = 下面 Reception 的三个 impl,其余框架代劳。

///|
/// 你的门房:实现三个具名回调,这就是初级用户的全部工作量。
struct Reception {
  allow : String
}

///|
/// 认不认:resolve 段(false = 陌生人拒)
pub impl @handler.DoorHandler for Reception with admit(
  self : Reception,
  sub : String,
) -> Bool {
  sub == self.allow
}

///|
/// 怎么干:dispatch 段(req/resp 走 Json)
pub impl @handler.DoorHandler for Reception with dispatch(
  self : Reception,
  sub : String,
  req : Json,
) -> Json {
  Json::string("[\{self.allow} 的门房] 已为 \{sub} 处理 \{req.stringify()}")
}

///|
/// 怎么记:audit 段(不可失败;不想记就写空体)
pub impl @handler.DoorHandler for Reception with audit(
  self : Reception,
  e : @moongrd.AuditEvent,
) -> Unit {
  let _ = self
  println("  流水[\{e.stage}] ok=\{e.ok} \{e.detail}")
}

///|
async fn main {
  let config = @moongrd.GuardConfig::make(
    issuer="demo-iss",
    audience="demo-aud",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
  let signer : &@moongrd.Signer = @mooncry.HmacSha256Signer::new(
    Bytes::make(32, b'\x33'),
  )
  let door = @handler.mount(
    config=config,
    signer=signer,
    revocations=@memstore.MemRevocationStore::new(),
    handler=Reception::{ allow: "alice" },
  )
  println("== 回调方言:实现三回调 + 一句 mount ==")
  println("")
  println("── 访客 alice:全链放行 ──")
  let alice = @moongrd.issue(
    config,
    signer,
    1000L,
    "alice",
    @moongrd.TokenType::Access,
    "jti-x1",
  )
  match door.run(1000L, alice.token, Json::string("读空间 doc1")) {
    Ok(resp) => println("  门放行 → \{resp.stringify()}")
    Err(e) => println("  拒 → \{e.to_repr()}")
  }
  println("")
  println("── 访客 bob:陌生人,resolve 段拒 ──")
  let bob = @moongrd.issue(
    config,
    signer,
    1000L,
    "bob",
    @moongrd.TokenType::Access,
    "jti-x2",
  )
  match door.run(1000L, bob.token, Json::string("删库")) {
    Ok(_) => println("  ?!删库竟成")
    Err(e) => println("  拒 → \{e.to_repr()}")
  }
  println("")
  println("── 伪造票:verify 段拒 ──")
  let n = alice.token.length()
  match door.run(1000L, "f" + alice.token[1:n].to_owned(), Json::string("越权")) {
    Ok(_) => println("  ?!伪造竟过")
    Err(e) => println("  拒 → \{e.to_repr()}")
  }
}

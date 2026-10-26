// handler_test.mbt — 回调方言罐:初级用户视角——实现三回调 → mount →
// 四段门全链 / 陌生人拒 / 坏票拒;审计行全落 handler 自己的账本。

///|
/// 初级用户的门房:实现三回调即可,全程不写 async 三字母。
struct AdminDoor {
  allow : String
  prefix : String
  lines : Array[String]
}

///|
pub impl @handler.DoorHandler for AdminDoor with fn admit(
  self : AdminDoor,
  sub : String,
) -> Bool {
  sub == self.allow
}

///|
pub impl @handler.DoorHandler for AdminDoor with fn dispatch(
  self : AdminDoor,
  sub : String,
  req : Json,
) -> Json {
  Json::string("\{self.prefix}\{sub} 执行了 \{req.stringify()}")
}

///|
pub impl @handler.DoorHandler for AdminDoor with fn audit(
  self : AdminDoor,
  e : @moongard.AuditEvent,
) -> Unit {
  self.lines.push("\{e.stage}:\{e.ok}")
}

///|
fn hd_config() -> @moongard.GuardConfig {
  @moongard.GuardConfig::make(
    issuer="iss1",
    audience="aud1",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
}

///|
fn hd_signer() -> &@moongard.Signer {
  @mooncry.HmacSha256Signer::new(Bytes::make(32, b'\x21'))
}

///|
async test "handler 方言:三回调 mount,全链绿+审计四行" {
  let door_log : Array[String] = []
  let handler = AdminDoor::{
    allow: "alice",
    prefix: "[admin] ",
    lines: door_log,
  }
  let door = @handler.mount(
    config=hd_config(),
    signer=hd_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    handler~,
  )
  let token = @moongard.issue(
    hd_config(),
    hd_signer(),
    1000000L,
    "alice",
    @moongard.TokenType::Access,
    "jti-h1",
  )
  let out = door.run(1000000L, token.token, Json::string("清理缓存"))
  match out {
    Ok(resp) =>
      assert_eq(resp, Json::string("[admin] alice 执行了 \"清理缓存\""))
    Err(_) => abort("挂载门应绿")
  }
  assert_eq(door_log.length(), 4)
  assert_eq(door_log[0], "verify:true")
  assert_eq(door_log[3], "dispatch:true")
}

///|
async test "handler 方言:陌生人 resolve 拒,审计三行带拒因" {
  let door_log : Array[String] = []
  let handler = AdminDoor::{
    allow: "alice",
    prefix: "[admin] ",
    lines: door_log,
  }
  let door = @handler.mount(
    config=hd_config(),
    signer=hd_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    handler~,
  )
  let bob = @moongard.issue(
    hd_config(),
    hd_signer(),
    1000000L,
    "bob",
    @moongard.TokenType::Access,
    "jti-h2",
  )
  let out = door.run(1000000L, bob.token, Json::string("清理缓存"))
  assert_true(out is Err(@moongard.GuardErr::Unresolved("bob")))
  // verify ok + revocation ok + resolve fail = 三行
  assert_eq(door_log.length(), 3)
  assert_eq(door_log[2], "resolve:false")
}

///|
async test "handler 方言:坏票 verify 拒,单行拒因 malformed" {
  let door_log : Array[String] = []
  let handler = AdminDoor::{
    allow: "alice",
    prefix: "[admin] ",
    lines: door_log,
  }
  let door = @handler.mount(
    config=hd_config(),
    signer=hd_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    handler~,
  )
  let out = door.run(1000000L, "nodot", Json::string("清理缓存"))
  assert_true(out is Err(@moongard.GuardErr::Verify(_)))
  assert_eq(door_log.length(), 1)
  assert_eq(door_log[0], "verify:false")
}

///|
async test "handler 方言:demo 预设一键起门(名单+回声+上屏)" {
  let handler = @handler.FlexDoor::demo(allow=["alice"], prefix="[p] ")
  let door = @handler.mount(
    config=hd_config(),
    signer=hd_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    handler~,
  )
  let alice = @moongard.issue(
    hd_config(),
    hd_signer(),
    1000000L,
    "alice",
    @moongard.TokenType::Access,
    "jti-hd1",
  )
  assert_true(door.run(1000000L, alice.token, Json::string("x")) is Ok(_))
  let bob = @moongard.issue(
    hd_config(),
    hd_signer(),
    1000000L,
    "bob",
    @moongard.TokenType::Access,
    "jti-hd2",
  )
  let out = door.run(1000000L, bob.token, Json::string("x"))
  assert_true(out is Err(@moongard.GuardErr::Unresolved("bob")))
}

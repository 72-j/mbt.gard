// guard_test.mbt — G2 罐(async test;四段 runner:全链绿/坏票短路/吊销拒/
// 陌生人拒)。audit 沉淀 = 顶层 mut 态 + 命名 async fn(避匿名 async 闭包
// 语法险,ctx §一.6);guard 每罐新建,吊销表新鲜不串味。

///|
struct AuditLog {
  events : Array[@moongrd.AuditEvent]
}

///|
let g2_log : AuditLog = { events: [], }

///|
async fn g2_audit(e : @moongrd.AuditEvent) -> Unit {
  g2_log.events.push(e)
}

///|
struct DUser {
  name : String
}

///|
async fn g2_resolve(name : String) -> DUser? {
  if name == "alice" {
    Some({ name, })
  } else {
    None
  }
}

///|
async fn g2_dispatch(u : DUser, req : String) -> String {
  "\{u.name}:\{req}"
}

///|
fn g2_guard(
  revocations : &@moongrd.RevocationStore,
) -> @moongrd.Guard[DUser, String, String] {
  @moongrd.Guard::new(
    config=g1_config(),
    signer=g1_signer(),
    revocations~,
    resolve=g2_resolve,
    dispatch=g2_dispatch,
    audit=g2_audit,
  )
}

///|
fn g2_login(jti : String) -> @moongrd.Issued {
  @moongrd.issue(
    g1_config(),
    g1_signer(),
    1000000L,
    "alice",
    @moongrd.TokenType::Access,
    jti,
  )
}

///|
async test "G2 全链绿:四段依序四行全 ok" {
  g2_log.events.clear()
  let door = g2_guard(@memstore.MemRevocationStore::new())
  let token = g2_login("jti-a1")
  let out = door.run(1000000L, token.token, "hi")
  match out {
    Ok(resp) => assert_eq(resp, "alice:hi")
    Err(_) => abort("全链应绿")
  }
  assert_eq(g2_log.events.length(), 4)
  assert_eq(g2_log.events[0].stage, "verify")
  assert_eq(g2_log.events[1].stage, "revocation")
  assert_eq(g2_log.events[2].stage, "resolve")
  assert_eq(g2_log.events[3].stage, "dispatch")
  let mut all_ok = true
  for e in g2_log.events {
    if e.ok == false {
      all_ok = false
    }
  }
  assert_true(all_ok)
}

///|
async test "G2 坏票:verify 拒短路,dispatch 不曾到场" {
  g2_log.events.clear()
  let door = g2_guard(@memstore.MemRevocationStore::new())
  let out = door.run(1000000L, "nodot", "hi")
  assert_true(out is Err(@moongrd.GuardErr::Verify(_)))
  assert_eq(g2_log.events.length(), 1)
  assert_eq(g2_log.events[0].stage, "verify")
  assert_true(g2_log.events[0].ok == false)
  assert_eq(g2_log.events[0].detail, "malformed")
}

///|
async test "G2 吊销票:revocation 段拒,拒因落审计" {
  g2_log.events.clear()
  let revocations = @memstore.MemRevocationStore::new()
  let door = g2_guard(revocations)
  let token = g2_login("jti-a3")
  revocations.revoke("jti-a3")
  let out = door.run(1000000L, token.token, "hi")
  assert_true(out is Err(@moongrd.GuardErr::Revoked))
  // 两行:verify ok + revocation fail
  assert_eq(g2_log.events.length(), 2)
  assert_true(g2_log.events[0].ok)
  assert_true(g2_log.events[1].ok == false)
  assert_eq(g2_log.events[1].detail, "revoked")
}

///|
async test "G2 陌生人:resolve None → Unresolved,sub 随审计" {
  g2_log.events.clear()
  let door = g2_guard(@memstore.MemRevocationStore::new())
  let token = @moongrd.issue(
    g1_config(),
    g1_signer(),
    1000000L,
    "bob",
    @moongrd.TokenType::Access,
    "jti-a4",
  )
  let out = door.run(1000000L, token.token, "hi")
  match out {
    Err(@moongrd.GuardErr::Unresolved(sub)) => assert_eq(sub, "bob")
    _ => abort("应报 Unresolved")
  }
  // 三行:verify ok + revocation ok + resolve fail
  assert_eq(g2_log.events.length(), 3)
  assert_eq(g2_log.events[2].stage, "resolve")
  assert_eq(g2_log.events[2].detail, "unresolved")
}

///|
async test "G2 匿名 async 钩子字面量:语法探针转正罐" {
  g2_log.events.clear()
  let door = @moongrd.Guard::new(
    config=g1_config(),
    signer=g1_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    resolve=async fn(name : String) -> DUser? { Some({ name, }) },
    dispatch=async fn(u : DUser, _req : String) -> String { "\{u.name}!" },
    audit=async fn(e : @moongrd.AuditEvent) -> Unit { g2_log.events.push(e) },
  )
  let token = g2_login("jti-a5")
  let out = door.run(1000000L, token.token, "yo")
  match out {
    Ok(resp) => assert_eq(resp, "alice!")
    Err(_) => abort("字面量钩子全链应绿")
  }
  assert_eq(g2_log.events.length(), 4)
}

///|
async test "G2 初级方言:audit 可省(吞流 no-op),五参起步" {
  g2_log.events.clear()
  let door = @moongrd.Guard::new(
    config=g1_config(),
    signer=g1_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    resolve=async fn(name : String) -> DUser? { Some({ name, }) },
    dispatch=async fn(u : DUser, _req : String) -> String { "\{u.name}:ok" },
  )
  let token = g2_login("jti-a6")
  let out = door.run(1000000L, token.token, "hi")
  match out {
    Ok(resp) => assert_eq(resp, "alice:ok")
    Err(_) => abort("初级形应全链绿")
  }
  // 吞流审计:缺省 no-op,事件不进账
  assert_eq(g2_log.events.length(), 0)
}

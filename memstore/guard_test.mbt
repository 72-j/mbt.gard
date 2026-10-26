// guard_test.mbt — G2 罐(async test;四段 runner:全链绿/坏票短路/吊销拒/
// 陌生人拒)。audit 沉淀 = 顶层 mut 态 + 命名 async fn(避匿名 async 闭包
// 语法险,ctx §一.6);guard 每罐新建,吊销表新鲜不串味。

///|
struct AuditLog {
  events : Array[@moongard.AuditEvent]
}

///|
let g2_log : AuditLog = { events: [], }

///|
async fn g2_audit(e : @moongard.AuditEvent) -> Unit {
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
  revocations : &@moongard.RevocationStore,
) -> @moongard.Guard[DUser, String, String] {
  @moongard.Guard::new(
    config=g1_config(),
    signer=g1_signer(),
    revocations~,
    resolve=g2_resolve,
    dispatch=g2_dispatch,
    audit=g2_audit,
  )
}

///|
fn g2_login(jti : String) -> @moongard.Issued {
  @moongard.issue(
    g1_config(),
    g1_signer(),
    1000000L,
    "alice",
    @moongard.TokenType::Access,
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
  assert_true(out is Err(@moongard.GuardErr::Verify(_)))
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
  assert_true(out is Err(@moongard.GuardErr::Revoked))
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
  let token = @moongard.issue(
    g1_config(),
    g1_signer(),
    1000000L,
    "bob",
    @moongard.TokenType::Access,
    "jti-a4",
  )
  let out = door.run(1000000L, token.token, "hi")
  match out {
    Err(@moongard.GuardErr::Unresolved(sub)) => assert_eq(sub, "bob")
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
  let door = @moongard.Guard::new(
    config=g1_config(),
    signer=g1_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    resolve=async fn(name : String) -> DUser? { Some({ name, }) },
    dispatch=async fn(u : DUser, _req : String) -> String { "\{u.name}!" },
    audit=async fn(e : @moongard.AuditEvent) -> Unit { g2_log.events.push(e) },
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
  let door = @moongard.Guard::new(
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

///|
/// 自定义协议:万能票(演示协议位换挡——测试/内网工具形;真协议照
/// TokenProtocol 形实作校验)。
struct MasterProtocol {}

///|
pub impl @moongard.AuthProtocol for MasterProtocol with fn verify_access(
  self : MasterProtocol,
  config~ : @moongard.GuardConfig,
  signer~ : &@moongard.Signer,
  now~ : Int64,
  token~ : String,
) -> Result[@moongard.Claims, @moongard.VerifyErr] {
  let _ = (self, config, signer, now, token)
  Ok({
    sub: "master",
    iss: "master",
    aud: "master",
    iat: 0L,
    exp: 9223372036854775807L,
    typ: @moongard.TokenType::Access,
    jti: "jti-master",
  })
}

///|
async test "G2 协议换挡:自定义 AuthProtocol 万能票进门,管线四行照走" {
  g2_log.events.clear()
  let door = @moongard.Guard::new(
    config=g1_config(),
    signer=g1_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    resolve=async fn(name : String) -> DUser? { Some({ name, }) },
    dispatch=async fn(u : DUser, _req : String) -> String { "\{u.name}:ok" },
    audit=g2_audit,
    protocol=MasterProtocol::{ },
  )
  let out = door.run(1000000L, "any-credential-string", "hi")
  match out {
    Ok(resp) => assert_eq(resp, "master:ok")
    Err(_) => abort("换挡协议应放行")
  }
  // 协议位只换 verify 算法,管线序不换:四行审计照走
  assert_eq(g2_log.events.length(), 4)
}

///|
async test "G2 drift 自定义:漂移窗随配置移动" {
  let signer = g1_signer()
  let strict : @moongard.GuardConfig = @moongard.GuardConfig::make(
    issuer="iss1",
    audience="aud1",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
  let issued = @moongard.issue(
    strict,
    signer,
    1000000L,
    "alice",
    @moongard.TokenType::Access,
    "jti-d1",
  )
  // 默认 drift 5000:exp=1060000,1065001 起拒
  assert_true(
    @moongard.verify(strict, signer, 1065001L, issued.token) is Err(Expired(_)),
  )
  // 自定义 drift 60000:同一票 1119999 仍收,1120001 拒
  let loose : @moongard.GuardConfig = {
    issuer: "iss1",
    audience: "aud1",
    allowed_drift_ms: 60000L,
    access_ttl_ms: 60000L,
    refresh_ttl_ms: 600000L,
  }
  assert_true(@moongard.verify(loose, signer, 1119999L, issued.token) is Ok(_))
  assert_true(
    @moongard.verify(loose, signer, 1120001L, issued.token) is Err(Expired(_)),
  )
}

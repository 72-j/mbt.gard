// stock_test.mbt — 一键换装罐:stock 工厂形/FlexDoor mount 全链/运行时
// swap 换装(紧急停门与复活)/审计换装。

///|
fn stock_config() -> @moongard.GuardConfig {
  @moongard.GuardConfig::make(
    issuer="iss1",
    audience="aud1",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
}

///|
fn stock_signer() -> &@moongard.Signer {
  @mooncry.HmacSha256Signer::new(Bytes::make(32, b'\x71'))
}

///|
fn stock_token(sub : String, jti : String) -> String {
  @moongard.issue(
    stock_config(),
    stock_signer(),
    1000000L,
    sub,
    @moongard.TokenType::Access,
    jti,
  ).token
}

///|
test "stock 工厂形:名单准入/全放/全拒/回声" {
  let allow = @handler.admit_allowlist(allow=["alice", "bob"])
  assert_true(allow("alice"))
  assert_true(allow("bob"))
  assert_true(allow("carol") == false)
  assert_true(@handler.admit_all()("anyone"))
  assert_true(@handler.admit_none()("alice") == false)
  let echo = @handler.dispatch_echo(prefix="[demo] ")
  match echo("alice", Json::string("ping")) {
    Json::String(s) => assert_true(s.contains("[demo] alice"))
    _ => abort("回声应出 Json::string")
  }
}

///|
async test "FlexDoor mount 全链:名单内放行,审计收集" {
  let log : Array[String] = []
  let door_log = @handler.audit_collector(log~)
  let handler = @handler.FlexDoor::new(
    admit_fn=@handler.admit_allowlist(allow=["alice"]),
    dispatch_fn=@handler.dispatch_echo(prefix="[flex] "),
    audit_fn=door_log,
  )
  let door = @handler.mount(
    config=stock_config(),
    signer=stock_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    handler~,
  )
  let out = door.run(
    1000000L,
    stock_token("alice", "jti-f1"),
    Json::string("task"),
  )
  match out {
    Ok(resp) => assert_true(Json::string("[flex] alice → \"task\"") == resp)
    Err(_) => abort("FlexDoor 全链应绿")
  }
  assert_eq(log.length(), 4)
}

///|
async test "一键换装:紧急停门与复活,已挂门即时生效" {
  let handler = @handler.FlexDoor::demo(allow=["alice"], prefix="[flex] ")
  let door = @handler.mount(
    config=stock_config(),
    signer=stock_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    handler~,
  )
  let alice = stock_token("alice", "jti-f2")
  // 换装前:放行
  assert_true(door.run(1000000L, alice, Json::string("x")) is Ok(_))
  // 一键紧急停门:admit 换全拒 → alice 立刻拒(Unresolved,dispatch 不曾到场)
  handler.swap_admit(admit=@handler.admit_none())
  let out = door.run(1000000L, alice, Json::string("x"))
  assert_true(out is Err(@moongard.GuardErr::Unresolved("alice")))
  // 一键复活:换回名单准入 → 放行
  handler.swap_admit(admit=@handler.admit_allowlist(allow=["alice"]))
  assert_true(door.run(1000000L, alice, Json::string("x")) is Ok(_))
}

///|
async test "审计换装:吞流换收集,行数开始进账" {
  let log : Array[String] = []
  let handler = @handler.FlexDoor::new(
    admit_fn=@handler.admit_all(),
    dispatch_fn=@handler.dispatch_echo(prefix=""),
    audit_fn=@handler.audit_silent(),
  )
  let door = @handler.mount(
    config=stock_config(),
    signer=stock_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    handler~,
  )
  let _ = door.run(1000000L, stock_token("alice", "jti-f3"), Json::string("x"))
  assert_eq(log.length(), 0)
  // 一键换审计:吞流换收集
  handler.swap_audit(audit=@handler.audit_collector(log~))
  let _ = door.run(1000000L, stock_token("alice", "jti-f4"), Json::string("x"))
  assert_eq(log.length(), 4)
}

///|
async test "stock dispatch 换装:回声换静态应答,已挂门即时生效" {
  let handler = @handler.FlexDoor::new(
    admit_fn=@handler.admit_allowlist(allow=["alice"]),
    dispatch_fn=@handler.dispatch_echo(prefix="[flex] "),
    audit_fn=@handler.audit_silent(),
  )
  let door = @handler.mount(
    config=stock_config(),
    signer=stock_signer(),
    revocations=@memstore.MemRevocationStore::new(),
    handler~,
  )
  let token = stock_token("alice", "jti-s1")
  match door.run(1000000L, token, Json::string("q")) {
    Ok(resp) => assert_true(resp.stringify().contains("[flex]"))
    Err(_) => abort("回声形应绿")
  }
  // 一键换装:回声换维护应答
  handler.swap_dispatch(dispatch=fn(_sub : String, _req : Json) -> Json {
    Json::string("maintenance")
  })
  match door.run(1000000L, token, Json::string("q")) {
    Ok(resp) => assert_eq(resp, Json::string("maintenance"))
    Err(_) => abort("换装后应绿")
  }
}

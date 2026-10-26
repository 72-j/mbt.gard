// refresh_test.mbt — G1 罐(黑盒:核+账本合演;罐单:换新/重放报
// Replayed/族谱尽戮/过期回握/伪造/无记录/显式吊销/账本基操)
// 语义基准:refresh 只管 refresh 串;过期 Verify(Expired) = 回握手信号。

///|
/// 玩具签名者(与 G0 同款 deterministic 滚动,只验逻辑不验强度)。
struct ToySigner {
  salt : Int32
}

///|
fn toy_digest(salt : Int32, payload : Bytes) -> Bytes {
  let mut acc = 5381 + salt
  let n = payload.length()
  let mut i = 0
  while i < n {
    acc = (acc * 33 + payload[i].to_int()) & 0x7FFFFFFF
    i += 1
  }
  @utf8.encode("toy:\{acc}")
}

///|
impl @moongrd.Signer for ToySigner with fn sign(self, payload) -> Bytes {
  toy_digest(self.salt, payload)
}

///|
impl @moongrd.Signer for ToySigner with fn verify(self, payload, mac) -> Bool {
  toy_digest(self.salt, payload) == mac
}

///|
fn g1_config() -> @moongrd.GuardConfig {
  @moongrd.GuardConfig::make("iss1", "aud1", 60000L, 600000L)
}

///|
fn g1_signer() -> &@moongrd.Signer {
  let toy : ToySigner = { salt: 11, }
  toy
}

///|
/// 登录造族:发 refresh 票并入账(family/jti 由测方注入)。
fn login(
  store : &@moongrd.RefreshStore,
  family : String,
  jti : String,
) -> @moongrd.Issued {
  let issued = @moongrd.issue(
    g1_config(),
    g1_signer(),
    1000000L,
    "alice",
    @moongrd.TokenType::Refresh,
    jti,
  )
  let record : @moongrd.RefreshRecord = {
    family_id: family,
    sub: "alice",
    issued_at: 1000000L,
    expires_at: 1600000L,
    used: false,
    revoked: false,
  }
  store.put(jti, record)
  issued
}

///|
test "G1 旋转换新:旧票作废,新票同族有效" {
  let store : &@moongrd.RefreshStore = @memstore.MemRefreshStore::new()
  let first = login(store, "fam1", "jti-1")
  let rotated = match
    @moongrd.refresh(
      g1_config(),
      g1_signer(),
      store,
      1000001L,
      first.token,
      "jti-2",
    ) {
    Ok(r) => r
    Err(_) => abort("换新应成")
  }
  // 旧票已 used
  let old = match store.get("jti-1") {
    Some(r) => r
    None => abort("旧票不应消失")
  }
  assert_true(old.used)
  assert_false(old.revoked)
  // 新票同族、未用、可再验
  assert_eq(rotated.family_id, "fam1")
  assert_eq(rotated.refresh.claims.jti, "jti-2")
  assert_eq(rotated.refresh.claims.sub, "alice")
  let again = @moongrd.verify_for(
    g1_config(),
    g1_signer(),
    1000001L,
    rotated.refresh.token,
    @moongrd.TokenType::Refresh,
  )
  assert_true(again is Ok(_))
  let new_record = match store.get("jti-2") {
    Some(r) => r
    None => abort("新票应已入账")
  }
  assert_false(new_record.used)
  assert_eq(new_record.family_id, "fam1")
}

///|
test "G1 重放检测:已用票再现报 Replayed 并撤全族" {
  let store : &@moongrd.RefreshStore = @memstore.MemRefreshStore::new()
  let first = login(store, "fam1", "jti-1")
  let _ = @moongrd.refresh(
    g1_config(),
    g1_signer(),
    store,
    1000001L,
    first.token,
    "jti-2",
  )
  // 已用旧票再现 = 重放
  match
    @moongrd.refresh(
      g1_config(),
      g1_signer(),
      store,
      1000002L,
      first.token,
      "jti-3",
    ) {
    Err(@moongrd.RefreshErr::Replayed(family)) => assert_eq(family, "fam1")
    _ => abort("应报 Replayed")
  }
  // 撤族生效:账面 revoked 位翻真
  let old = match store.get("jti-1") {
    Some(r) => r
    None => abort("旧票不应消失")
  }
  assert_true(old.revoked)
}

///|
test "G1 族谱尽戮:撤族后连新票也拒" {
  let store : &@moongrd.RefreshStore = @memstore.MemRefreshStore::new()
  let first = login(store, "fam1", "jti-1")
  let rotated = match
    @moongrd.refresh(
      g1_config(),
      g1_signer(),
      store,
      1000001L,
      first.token,
      "jti-2",
    ) {
    Ok(r) => r
    Err(_) => abort("换新应成")
  }
  let _ = @moongrd.refresh(
    g1_config(),
    g1_signer(),
    store,
    1000002L,
    first.token,
    "jti-3",
  )
  // 新票(未用过)也因族被撤而拒,错误携带 claims 供审计
  match
    @moongrd.refresh(
      g1_config(),
      g1_signer(),
      store,
      1000003L,
      rotated.refresh.token,
      "jti-4",
    ) {
    Err(@moongrd.RefreshErr::Revoked(c)) => assert_eq(c.jti, "jti-2")
    _ => abort("新票应因族被撤而拒")
  }
}

///|
test "G1 过期 refresh:Verify(Expired) 即回握手信号" {
  let store : &@moongrd.RefreshStore = @memstore.MemRefreshStore::new()
  let first = login(store, "fam1", "jti-1")
  // token exp = 1000000 + refresh_ttl 600000 = 1600000;+drift 5000 → 界内 1605000 收
  assert_true(
    @moongrd.verify(g1_config(), g1_signer(), 1605000L, first.token) is Ok(_),
  )
  // 1605001 起拒:Verify(Expired) 即回握手信号
  match
    @moongrd.refresh(
      g1_config(),
      g1_signer(),
      store,
      1605001L,
      first.token,
      "jti-2",
    ) {
    Err(@moongrd.RefreshErr::Verify(@moongrd.VerifyErr::Expired(_))) => ()
    _ => abort("应报 Verify(Expired)")
  }
}

///|
test "G1 伪造票:线形坏 → Verify 包裹上抛" {
  let store : &@moongrd.RefreshStore = @memstore.MemRefreshStore::new()
  match
    @moongrd.refresh(
      g1_config(),
      g1_signer(),
      store,
      1000000L,
      "nodot",
      "jti-1",
    ) {
    Err(@moongrd.RefreshErr::Verify(@moongrd.VerifyErr::Malformed(_))) => ()
    _ => abort("应报 Verify(Malformed)")
  }
}

///|
test "G1 账本无记录:mac 过也拒 UnknownToken" {
  let store : &@moongrd.RefreshStore = @memstore.MemRefreshStore::new()
  // 签发但故意不入账(模拟别处签发/账本丢)
  let ghost = @moongrd.issue(
    g1_config(),
    g1_signer(),
    1000000L,
    "alice",
    @moongrd.TokenType::Refresh,
    "ghost-1",
  )
  match
    @moongrd.refresh(
      g1_config(),
      g1_signer(),
      store,
      1000000L,
      ghost.token,
      "jti-1",
    ) {
    Err(@moongrd.RefreshErr::UnknownToken) => ()
    _ => abort("应报 UnknownToken")
  }
}

///|
test "G1 显式吊销:revoked 位直拒" {
  let store : &@moongrd.RefreshStore = @memstore.MemRefreshStore::new()
  let issued = @moongrd.issue(
    g1_config(),
    g1_signer(),
    1000000L,
    "alice",
    @moongrd.TokenType::Refresh,
    "jti-1",
  )
  let record : @moongrd.RefreshRecord = {
    family_id: "fam1",
    sub: "alice",
    issued_at: 1000000L,
    expires_at: 1060000L,
    used: false,
    revoked: true,
  }
  store.put("jti-1", record)
  match
    @moongrd.refresh(
      g1_config(),
      g1_signer(),
      store,
      1000000L,
      issued.token,
      "jti-2",
    ) {
    Err(@moongrd.RefreshErr::Revoked(c)) => assert_eq(c.jti, "jti-1")
    _ => abort("应报 Revoked")
  }
}

///|
test "G1 账本基操:mark_used/revoke_family/sweep" {
  let mem = @memstore.MemRefreshStore::new()
  let store : &@moongrd.RefreshStore = mem
  let _ = login(store, "fam1", "jti-1")
  let _ = login(store, "fam1", "jti-2")
  let _ = login(store, "fam2", "jti-3")
  // 定点 mark_used 不伤同族
  store.mark_used("jti-1")
  let r1 = match store.get("jti-1") {
    Some(r) => r
    None => abort("jti-1 应在")
  }
  assert_true(r1.used)
  let r2 = match store.get("jti-2") {
    Some(r) => r
    None => abort("jti-2 应在")
  }
  assert_false(r2.used)
  // revoke_family 只翻本族
  store.revoke_family("fam1")
  let r1b = match store.get("jti-1") {
    Some(r) => r
    None => abort("jti-1 应在")
  }
  assert_true(r1b.revoked)
  let r3 = match store.get("jti-3") {
    Some(r) => r
    None => abort("jti-3 应在")
  }
  assert_false(r3.revoked)
  // sweep 清过期:三记录全在 1600000 过期
  assert_eq(mem.sweep(1600000L), 0)
  assert_eq(mem.sweep(1600001L), 3)
  assert_true(store.get("jti-1") is None)
}

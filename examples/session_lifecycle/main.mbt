// main.mbt — 会话全生命周期演示:登录 → 进门 → 过期 → 换发续命 → 登出吊销
// 运行:cd moongard && moon run examples/session_lifecycle --target native
// access_ttl 故意给 30s 短档,时间全常量跳进(D-G2:核心零时钟零随机;
// 生产 = 真钟 + CSPRNG)。展示三层语义:令牌有效期 / 旋转换发 / 登出吊销。

///|
/// 校验拒的短因(审计友好,不倾倒载荷)。
fn reason(e : @moongard.VerifyErr) -> String {
  match e {
    @moongard.VerifyErr::Expired(_) => "令牌过期"
    @moongard.VerifyErr::BadMac => "签名不符"
    @moongard.VerifyErr::Malformed(_) => "线形畸形"
    @moongard.VerifyErr::WrongType(_) => "型不符"
    @moongard.VerifyErr::WrongIssuer(_) => "签发方不符"
    @moongard.VerifyErr::WrongAudience(_) => "受众不符"
    @moongard.VerifyErr::NotYetValid(_) => "生效未到"
  }
}

///|
fn main {
  let config = @moongard.GuardConfig::make(
    issuer="demo-iss",
    audience="demo-app",
    access_ttl_ms=30000L,
    refresh_ttl_ms=600000L,
  )
  let signer : &@moongard.Signer = @mooncry.HmacSha256Signer::new(
    Bytes::make(32, b'\x44'),
  )
  let family = @memstore.MemRefreshStore::new()
  let store : &@moongard.RefreshStore = family
  let revocations = @memstore.MemRevocationStore::new()
  let rev : &@moongard.RevocationStore = revocations
  // 真实门禁两查:先吊销表,后令牌校验。
  let door_check = fn(now : Int64, jti : String, token : String) -> String {
    if rev.revoked(jti) {
      return "拒(已吊销——登出生效)"
    }
    match
      @moongard.verify_for(
        config,
        signer,
        now,
        token,
        @moongard.TokenType::Access,
      ) {
      Ok(_) => "放行"
      Err(e) => "拒(\{reason(e)})"
    }
  }
  println("== 幕 1 登录:双 token 入手 ==")
  let mut now = 1000000L
  let access = @moongard.issue(
    config,
    signer,
    now,
    "alice",
    @moongard.TokenType::Access,
    "jti-a1",
  )
  let refresh = @moongard.issue(
    config,
    signer,
    now,
    "alice",
    @moongard.TokenType::Refresh,
    "jti-r1",
  )
  let record : @moongard.RefreshRecord = {
    family_id: "fam-1",
    sub: "alice",
    issued_at: now,
    expires_at: refresh.claims.exp,
    used: false,
    revoked: false,
  }
  store.put("jti-r1", record)
  println(
    "access 有效至 \{access.claims.exp};refresh 有效至 \{refresh.claims.exp}",
  )
  println("")
  println("== 幕 2 十秒后进门:放行 ==")
  now = 1010000L
  let verdict = door_check(now, "jti-a1", access.token)
  println("  now=\{now} → \{verdict}")
  println("")
  println("== 幕 3 四十秒后:access 过期,refresh 换发续命 ==")
  now = 1040000L
  let verdict = door_check(now, "jti-a1", access.token)
  println("  now=\{now} → \{verdict}")
  let mut live_access = access.token
  let mut live_jti = "jti-a1"
  let mut live_refresh = refresh.token
  match @moongard.refresh(config, signer, store, now, refresh.token, "jti-r2") {
    Ok(r) => {
      let access2 = @moongard.issue(
        config,
        signer,
        now,
        r.sub,
        @moongard.TokenType::Access,
        "jti-a2",
      )
      live_access = access2.token
      live_jti = "jti-a2"
      live_refresh = r.refresh.token
      println(
        "  换发成功:新 refresh 入族 \{r.family_id},新 access 已发",
      )
    }
    Err(_) => println("  换发败(意外)")
  }
  println("")
  println("== 幕 4 新 access 进门:会话无感续命 ==")
  now = 1045000L
  let verdict = door_check(now, live_jti, live_access)
  println("  now=\{now} → \{verdict}")
  println("")
  println("== 幕 5 登出:吊销 access + 撤 refresh 全族 ==")
  rev.revoke(live_jti)
  store.revoke_family("fam-1")
  println("  now=\{now} → 门禁:\{door_check(now, live_jti, live_access)}")
  match @moongard.refresh(config, signer, store, now, live_refresh, "jti-r3") {
    Err(@moongard.RefreshErr::Revoked(_)) =>
      println("  refresh 也回不去 → 全族已撤,回握手重登录")
    Err(e) => println("  refresh 意外拒 → \{e.to_repr()}")
    Ok(_) => println("  ?!已登出还能换发")
  }
  println("")
  println("== 幕终:会话作废,要再进来请重新登录 ==")
}

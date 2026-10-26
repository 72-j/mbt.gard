// main.mbt — moongrd 全链演示:登录 → 四段门 → 换发旋转 → 重放撤族 →
// 族谱尽戮 → 篡改拒。运行:cd moongrd && moon run examples/walkthrough
// 时间与熵全是常量注入(D-G2:核心零时钟零随机;生产换真钟 + CSPRNG,
// 见 README §4:慢哈希拉伸口令、CSPRNG 供 nonce/jti)。

///|
async fn main {
  let config = @moongrd.GuardConfig::make(
    issuer="demo-iss",
    audience="demo-aud",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
  let signer : &@moongrd.Signer = @mooncry.HmacSha256Signer::new(
    Bytes::make(32, b'\x11'),
  )
  let family_store = @memstore.MemRefreshStore::new()
  let store : &@moongrd.RefreshStore = family_store
  let revocations : &@moongrd.RevocationStore = @memstore.MemRevocationStore::new()
  println("== 1 登录:双 token 签发 ==")
  let access = @moongrd.issue(
    config,
    signer,
    1000L,
    "alice",
    @moongrd.TokenType::Access,
    "jti-a",
  )
  let refresh = @moongrd.issue(
    config,
    signer,
    1000L,
    "alice",
    @moongrd.TokenType::Refresh,
    "jti-r1",
  )
  let record : @moongrd.RefreshRecord = {
    family_id: "fam-1",
    sub: "alice",
    issued_at: 1000L,
    expires_at: refresh.claims.exp,
    used: false,
    revoked: false,
  }
  store.put("jti-r1", record)
  println("access  = \{access.token}")
  println("refresh = \{refresh.token}")
  println("")
  println("== 2 四段门:verify → revocation → resolve → dispatch ==")
  let door : @moongrd.Guard[String, String, String] = @moongrd.Guard::new(
    config,
    signer,
    revocations,
    async fn(sub : String) -> String? {
      if sub == "alice" {
        Some(sub)
      } else {
        None
      }
    },
    async fn(u : String, req : String) -> String { "已为 \{u} 处理:\{req}" },
    async fn(e : @moongrd.AuditEvent) -> Unit {
      println("  audit[\{e.stage}] ok=\{e.ok} \{e.detail}")
    },
  )
  match door.run(2000L, access.token, "读空间 doc1") {
    Ok(resp) => println("门放行 → \{resp}")
    Err(e) => println("门拒绝 → \{e.to_repr()}")
  }
  println("")
  println("== 3 换发:旧票作废,新票入族 ==")
  let mut latest = refresh.token
  match
    @moongrd.refresh(config, signer, store, 3000L, refresh.token, "jti-r2") {
    Ok(r) => {
      latest = r.refresh.token
      println("新 refresh 入族 \{r.family_id}(旧票 jti-r1 已标 used)")
    }
    Err(e) => println("换发失败 → \{e.to_repr()}")
  }
  println("")
  println("== 4 重放:已用旧票再现 → 撤全族 ==")
  match
    @moongrd.refresh(config, signer, store, 4000L, refresh.token, "jti-r3") {
    Err(@moongrd.RefreshErr::Replayed(family)) =>
      println("重放戳穿!族 \{family} 已全族作废")
    Err(e) => println("意外 → \{e.to_repr()}")
    Ok(_) => println("?!重放竟成功")
  }
  println("")
  println("== 5 族谱尽戮:换发来的新票也活不成 ==")
  match @moongrd.refresh(config, signer, store, 5000L, latest, "jti-r4") {
    Err(@moongrd.RefreshErr::Revoked(c)) =>
      println("新票 \{c.jti} 随族殉葬 → 回握手重登录")
    Err(e) => println("意外 → \{e.to_repr()}")
    Ok(_) => println("?!族撤了新票还活着")
  }
  println("")
  println("== 6 篡改:载荷首码元翻转 → BadMac ==")
  let n = access.token.length()
  let tampered = "f" + access.token[1:n].to_owned()
  match @moongrd.verify(config, signer, 2000L, tampered) {
    Err(@moongrd.VerifyErr::BadMac) =>
      println("BadMac 戳穿,拒绝不带载荷")
    Err(e) => println("意外 → \{e.to_repr()}")
    Ok(_) => println("?!篡改竟通过")
  }
}

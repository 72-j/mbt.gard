// main.mbt — 换 verify 算法演示:同一管线,Signer 位三换三绿
// 运行:cd moongard && moon run examples/signer_swap --target native
// D-G6 复利现场:算法住 adapter 墙后,框架与管线零改。交叉核验全拒
// 则演示安全面:签发与验签必须同算法同钥,算法间不换算。

///|
/// HMAC-SHA512 签名者(key ≥ 32B 建议)。
struct HmacSha512Signer {
  key : Bytes
}

///|
impl @moongard.Signer for HmacSha512Signer with fn sign(self, payload) -> Bytes {
  @lib.hmac_sha512(self.key, payload)
}

///|
impl @moongard.Signer for HmacSha512Signer with fn verify(self, payload, mac) -> Bool {
  @lib.bytes_equal(@lib.hmac_sha512(self.key, payload), mac)
}

///|
/// AES-CMAC 签名者(分组密码派生 MAC,tag 16B)。
struct CmacAesSigner {
  key : Bytes
}

///|
impl @moongard.Signer for CmacAesSigner with fn sign(self, payload) -> Bytes {
  @lib.cmac_aes(payload, self.key)
}

///|
impl @moongard.Signer for CmacAesSigner with fn verify(self, payload, mac) -> Bool {
  @lib.bytes_equal(@lib.cmac_aes(payload, self.key), mac)
}

///|
/// Ed25519 签名者(非对称:seed 签、public 验,签名 64B)。
struct Ed25519Signer {
  seed : Bytes
  public : Bytes
}

///|
impl @moongard.Signer for Ed25519Signer with fn sign(self, payload) -> Bytes {
  @lib.ed25519_sign(self.seed, payload)
}

///|
impl @moongard.Signer for Ed25519Signer with fn verify(self, payload, mac) -> Bool {
  @lib.ed25519_verify(self.public, payload, mac)
}

///|
fn hd_config() -> @moongard.GuardConfig {
  @moongard.GuardConfig::make(
    issuer="demo-iss",
    audience="demo-app",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
}

///|
/// 幕 1 助手:单签名者签发→验签往返。
fn roundtrip(tag : String, signer : &@moongard.Signer) -> Unit {
  let issued = @moongard.issue(
    hd_config(),
    signer,
    1000L,
    "alice",
    @moongard.TokenType::Access,
    "jti-\{tag}",
  )
  match
    @moongard.verify_for(
      hd_config(),
      signer,
      1000L,
      issued.token,
      @moongard.TokenType::Access,
    ) {
    Ok(_) => println("  [\{tag}] 签发 → 验签 放行")
    Err(_) => println("  [\{tag}] 往返应绿")
  }
}

///|
/// 幕 3 助手:同一道 Guard,只换 signer 构造参数。
async fn guard_scene(
  tag : String,
  signer : &@moongard.Signer,
  revocations : &@moongard.RevocationStore,
) -> Unit {
  let door = @moongard.Guard::new(
    config=hd_config(),
    signer~,
    revocations~,
    resolve=async fn(sub : String) -> String? { Some(sub) },
    dispatch=async fn(sub : String, _req : String) -> String {
      "为 \{sub} 服务"
    },
  )
  let issued = @moongard.issue(
    hd_config(),
    signer,
    1000L,
    "alice",
    @moongard.TokenType::Access,
    "jti-\{tag}",
  )
  match door.run(1000L, issued.token, "读空间 doc1") {
    Ok(resp) => println("  [\{tag}] 门放行 → \{resp}")
    Err(_) => println("  [\{tag}] 换挡应绿")
  }
}

///|
async fn main {
  let config = hd_config()
  let sha512 : &@moongard.Signer = HmacSha512Signer::{
    key: Bytes::make(32, b'\x51'),
  }
  let cmac : &@moongard.Signer = CmacAesSigner::{
    key: Bytes::make(32, b'\x52'),
  }
  let seed = Bytes::make(32, b'\x53')
  let ed : &@moongard.Signer = Ed25519Signer::{
    seed,
    public: @lib.ed25519_public_key(seed),
  }
  println("== 幕 1 三位签名者:各签各验 ==")
  roundtrip("hmac-sha512", sha512)
  roundtrip("aes-cmac", cmac)
  roundtrip("ed25519", ed)
  println("  (ed25519 非对称形:验签方可只持公钥)")
  println("")
  println("== 幕 2 交叉核验:算法不换算,全拒 ==")
  let cross = @moongard.issue(
    config,
    sha512,
    1000L,
    "alice",
    @moongard.TokenType::Access,
    "jti-cross",
  )
  for pair in [("aes-cmac", cmac), ("ed25519", ed)] {
    let (tag, verifier) = pair
    match
      @moongard.verify_for(
        config,
        verifier,
        1000L,
        cross.token,
        @moongard.TokenType::Access,
      ) {
      Ok(_) => println("  [\{tag} 验 sha512 票] ?!竟通过")
      Err(_) => println("  [\{tag} 验 sha512 票] 拒(BadMac)")
    }
  }
  println("")
  println("== 幕 3 Guard 换挡:只换 signer 参数,管线零改 ==")
  let revocations = @memstore.MemRevocationStore::new()
  guard_scene("hmac-sha512", sha512, revocations)
  guard_scene("aes-cmac", cmac, revocations)
  guard_scene("ed25519", ed, revocations)
}

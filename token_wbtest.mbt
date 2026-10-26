// token_wbtest.mbt — G0 罐(白盒:构造器/私件直用;黑盒冒烟面由 .mbti 审代偿)
// 罐单(茗篇 §五 G0):签发回环/过期漂移界/iat 未来/篡改拒/iss·aud 错拒/typ 错拒/畸形拒

///|
/// 玩具签名者:deterministic 滚动多项式——测试专用,只验核心逻辑,
/// 不验密码强度(真面 G3 落 mooncry)。
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
impl Signer for ToySigner with fn sign(self, payload) -> Bytes {
  toy_digest(self.salt, payload)
}

///|
impl Signer for ToySigner with fn verify(self, payload, mac) -> Bool {
  toy_digest(self.salt, payload) == mac
}

///|
fn g0_config() -> GuardConfig {
  GuardConfig::make(
    issuer="iss1",
    audience="aud1",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
}

///|
fn g0_signer() -> &Signer {
  let toy : ToySigner = { salt: 7, }
  toy
}

///|
test "G0 签发回环:线形两段,claims 逐字段对上" {
  let config = g0_config()
  let signer = g0_signer()
  let issued = issue(
    config,
    signer,
    1000000L,
    "alice",
    TokenType::Access,
    "jti-1",
  )
  assert_eq(issued.claims.sub, "alice")
  assert_eq(issued.claims.iss, "iss1")
  assert_eq(issued.claims.aud, "aud1")
  assert_eq(issued.claims.iat, 1000000L)
  assert_eq(issued.claims.exp, 1060000L)
  assert_eq(issued.claims.typ, TokenType::Access)
  assert_eq(issued.claims.jti, "jti-1")
  assert_true(issued.token.contains("."))
  match verify(config, signer, 1000000L, issued.token) {
    Ok(c) => assert_eq(c, issued.claims)
    Err(_) => abort("回环失败")
  }
}

///|
test "G0 过期与漂移界:exp+drift 收,再一毫秒拒且带 claims" {
  let config = g0_config()
  let signer = g0_signer()
  let issued = issue(
    config,
    signer,
    1000000L,
    "alice",
    TokenType::Access,
    "jti-2",
  )
  // exp = 1060000,drift 5000 → 界内 1065000 收
  assert_true(verify(config, signer, 1065000L, issued.token) is Ok(_))
  // 1065001 拒,错误携带 claims(审计定罪面)
  match verify(config, signer, 1065001L, issued.token) {
    Err(Expired(c)) => assert_eq(c.sub, "alice")
    _ => abort("应过期,实得非 Expired")
  }
}

///|
test "G0 iat 未来:漂移界内收,界外 NotYetValid" {
  let config = g0_config()
  let signer = g0_signer()
  let issued = issue(
    config,
    signer,
    1000000L,
    "alice",
    TokenType::Access,
    "jti-3",
  )
  // now = 995000 → iat(1000000) ≤ now+5000 收
  assert_true(verify(config, signer, 995000L, issued.token) is Ok(_))
  // now = 994999 → iat > now+5000 拒
  assert_true(
    verify(config, signer, 994999L, issued.token) is Err(NotYetValid(_)),
  )
}

///|
/// 载荷段首码元 'e'↔'f'(JSON "{" 的 b64 首码元必为 'e',翻转运参与
/// 首字节,不触尾部对齐,保 decode 仍过、只破 mac)。
fn flip_payload_head(token : String) -> String {
  let n = token.length()
  let mut dot = -1
  let mut i = 0
  while i < n {
    if token[i].to_int() == 46 {
      dot = i
      i = n
    } else {
      i += 1
    }
  }
  let head = token[0:1].to_owned()
  let flipped = match head {
    "e" => "f"
    "f" => "e"
    _ => head
  }
  let sb = StringBuilder()
  sb.write(flipped)
  sb.write(token[1:dot].to_owned())
  sb.write(token[dot:n].to_owned())
  sb.to_string()
}

///|
test "G0 篡改拒:载荷首字符翻转 mac 即破" {
  let config = g0_config()
  let signer = g0_signer()
  let issued = issue(
    config,
    signer,
    1000000L,
    "alice",
    TokenType::Access,
    "jti-4",
  )
  let tampered = flip_payload_head(issued.token)
  match verify(config, signer, 1000000L, tampered) {
    Err(BadMac) => ()
    _ => abort("应 BadMac,实得非 BadMac")
  }
}

///|
test "G0 iss/aud 错拒" {
  let signer = g0_signer()
  let issued = issue(
    g0_config(),
    signer,
    1000000L,
    "alice",
    TokenType::Access,
    "jti-5",
  )
  let wrong_iss = GuardConfig::make(
    issuer="other",
    audience="aud1",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
  assert_true(
    verify(wrong_iss, signer, 1000000L, issued.token) is Err(WrongIssuer(_)),
  )
  let wrong_aud = GuardConfig::make(
    issuer="iss1",
    audience="other",
    access_ttl_ms=60000L,
    refresh_ttl_ms=600000L,
  )
  assert_true(
    verify(wrong_aud, signer, 1000000L, issued.token) is Err(WrongAudience(_)),
  )
}

///|
test "G0 typ 错拒:access 门不收 refresh,refresh 门收" {
  let config = g0_config()
  let signer = g0_signer()
  let issued = issue(
    config,
    signer,
    1000000L,
    "alice",
    TokenType::Refresh,
    "jti-6",
  )
  assert_true(
    verify_for(config, signer, 1000000L, issued.token, TokenType::Access)
    is Err(WrongType(_)),
  )
  assert_true(
    verify_for(config, signer, 1000000L, issued.token, TokenType::Refresh)
    is Ok(_),
  )
}

///|
test "G0 畸形拒:无点/坏字母表/坏载荷形" {
  let config = g0_config()
  let signer = g0_signer()
  assert_true(verify(config, signer, 1000000L, "nodot") is Err(Malformed(_)))
  assert_true(verify(config, signer, 1000000L, "a.b") is Err(Malformed(_)))
  assert_true(verify(config, signer, 1000000L, "eyJ.A@") is Err(Malformed(_)))
}

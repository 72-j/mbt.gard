// signer_test.mbt — G3 罐:真加密面(RFC 4231 KAT 过 trait / issue-verify
// 回环+篡改拒 / AES-GCM 回环+撕尾+篡改拒)。黑盒:@moongrd/@mooncry 双前缀。

///|
let g3_key : Bytes = Bytes::make(32, b'\x2b')

///|
test "G3 HMAC-SHA256 RFC 4231 KAT 过 Signer trait" {
  let signer : &@moongrd.Signer = @mooncry.HmacSha256Signer::new(
    Bytes::make(20, b'\x0b'),
  )
  let mac = signer.sign(@utf8.encode("Hi There"))
  assert_eq(
    @lib.bytes_to_hex(mac),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  assert_true(signer.verify(@utf8.encode("Hi There"), mac))
  assert_false(signer.verify(@utf8.encode("Hi There2"), mac))
}

///|
test "G3 真签发回环:issue→verify,篡改即 BadMac" {
  let config = @moongrd.GuardConfig::make("iss1", "aud1", 60000L, 600000L)
  let signer : &@moongrd.Signer = @mooncry.HmacSha256Signer::new(g3_key)
  let issued = @moongrd.issue(
    config,
    signer,
    1000000L,
    "alice",
    @moongrd.TokenType::Access,
    "jti-real-1",
  )
  match @moongrd.verify_for(config, signer, 1000000L, issued.token, @moongrd.TokenType::Access) {
    Ok(c) => assert_eq(c.sub, "alice")
    Err(_) => abort("真签回环应绿")
  }
  // 载荷翻一字(mac 必破;真哈希下必然)
  // 首码元翻转:JSON "{" 的 b64 首字符必为 'e',翻 'f' 保解码必破 mac
  let n = issued.token.length()
  let tampered = "f" + issued.token[1:n].to_owned()
  assert_true(
    @moongrd.verify(config, signer, 1000000L, tampered) is Err(
      @moongrd.VerifyErr::BadMac,
    ),
  )
}

///|
test "G3 AES-GCM 过 Cipher trait:回环/撕尾拒/篡改拒" {
  let cipher : &@moongrd.Cipher = @mooncry.AesGcmCipher::new(g3_key)
  let nonce = Bytes::make(12, b'\x07')
  let aad = @utf8.encode("door:admin")
  let envelope = cipher.seal(@utf8.encode("open sesame"), nonce, aad)
  match cipher.open(envelope, nonce, aad) {
    Some(pt) => assert_eq(@lib.bytes_to_hex(pt), @lib.bytes_to_hex(@utf8.encode("open sesame")))
    None => abort("GCM 回环应绿")
  }
  // 撕尾(tag 不足 16B)→ None
  assert_true(cipher.open(envelope[0:envelope.length() - 1].to_owned(), nonce, aad) is None)
  // 篡改 ct 首字节 → None(认证失败统一 None,无 oracle)
  let broken = Bytes::makei(envelope.length(), fn(i) {
    if i == 0 {
      let flipped = envelope[i].to_int() ^ 1
      flipped.to_byte()
    } else {
      envelope[i]
    }
  })
  assert_true(cipher.open(broken, nonce, aad) is None)
}

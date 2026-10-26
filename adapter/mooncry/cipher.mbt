// cipher.mbt — Cipher 的 mooncry 实现:AES-GCM(nonce 12B / tag 16B;
// 线形 = ct ‖ tag,解端按尾 16B 撕)。key 16/24/32 字节,nonce 必须
// 每 (key, message) 唯一——复用即灾难(mooncry 同款警告,此处一样)。

///|
/// AES-256-GCM 密封者(key 32 字节;16/24 亦可,取长即定档)。
pub struct AesGcmCipher {
  key : Bytes
}

///|
pub fn AesGcmCipher::new(key : Bytes) -> AesGcmCipher {
  { key, }
}

///|
pub impl @moongrd.Cipher for AesGcmCipher with fn seal(
  self,
  plaintext : Bytes,
  nonce : Bytes,
  aad : Bytes,
) -> Bytes {
  let tagged = @lib.aes_gcm_encrypt(plaintext, self.key, nonce, aad)
  tagged.ct + tagged.tag
}

///|
pub impl @moongrd.Cipher for AesGcmCipher with fn open(
  self,
  ciphertext : Bytes,
  nonce : Bytes,
  aad : Bytes,
) -> Bytes? {
  if ciphertext.length() < 16 {
    return None
  }
  let split = ciphertext.length() - 16
  let ct = Bytes::makei(split, fn(i) { ciphertext[i] })
  let tag = Bytes::makei(16, fn(i) { ciphertext[split + i] })
  match @lib.aes_gcm_decrypt(ct, self.key, nonce, aad, tag) {
    Ok(pt) => Some(pt)
    Err(_) => None
  }
}

///|
/// trait 方法显式晋升([0079] 标准动作)。
pub extend AesGcmCipher with @moongrd.Cipher::{seal, open}

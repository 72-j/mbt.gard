// signer.mbt — Signer 的 mooncry 实现:HMAC-SHA256(D-G6;换算法 = 换本包,
// 核心与消费方零改)。key 为会话密钥/PSK 派生物,建议 ≥32 字节。

///|
/// HMAC-SHA256 签名者(对称:签验同 key,守护进程自签自验的形)。
pub struct HmacSha256Signer {
  key : Bytes
}

///|
pub fn HmacSha256Signer::new(key : Bytes) -> HmacSha256Signer {
  { key: key, }
}

///|
pub impl @moongrd.Signer for HmacSha256Signer with sign(
  self,
  payload : Bytes,
) -> Bytes {
  @lib.hmac_sha256(self.key, payload)
}

///|
pub impl @moongrd.Signer for HmacSha256Signer with verify(
  self,
  payload : Bytes,
  mac : Bytes,
) -> Bool {
  @lib.bytes_equal(@lib.hmac_sha256(self.key, payload), mac)
}

///|
/// trait 方法显式晋升([0079] 标准动作)。
pub extend HmacSha256Signer with @moongrd.Signer::{sign, verify}

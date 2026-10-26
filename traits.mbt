// traits.mbt — 扩展面 trait(D-G10:多式有状态面走 trait;单钩子闭包归 Guard,G2 落)

///|
/// 签名面:mac 签发/核验。核心只定义,实现在 adapter/mooncry(G3);
/// 换算法 ≠ 关校验——verify 段调用序是框架私产,不开放回调(D-G10)。
pub(open) trait Signer {
  fn sign(Self, payload : Bytes) -> Bytes
  fn verify(Self, payload : Bytes, mac : Bytes) -> Bool
}

///|
/// AEAD 面(可选腿):封/启。G0 仅定义,G3 落 mooncry 实现(D-G6)。
pub(open) trait Cipher {
  fn seal(Self, plaintext : Bytes, nonce : Bytes, aad : Bytes) -> Bytes
  fn open(Self, ciphertext : Bytes, nonce : Bytes, aad : Bytes) -> Bytes?
}

///|
/// refresh 族谱记录:同 family_id = 同一会话的历次 refresh 串
/// (重放检测撤全族的底座,D-G3)。used = 已消费(再现即重放);
/// revoked = 族被撤(盗用或登出)。
pub(all) struct RefreshRecord {
  family_id : String
  sub : String
  issued_at : Int64
  expires_at : Int64
  used : Bool
  revoked : Bool
} derive(Eq, Debug)

///|
/// refresh 存储面:旋转/重放检测的底座。G0 同步色(memstore G1 即用);
/// async 色待 D-G12 探针定谳,分叉只影响消费方底座,不破本 trait 语义。
pub(open) trait RefreshStore {
  fn put(Self, jti : String, record : RefreshRecord) -> Unit
  fn get(Self, jti : String) -> RefreshRecord?
  fn mark_used(Self, jti : String) -> Unit
  fn revoke_family(Self, family_id : String) -> Unit
}

///|
/// 吊销表:access 即时吊销面(登出/被盗)。
pub(open) trait RevocationStore {
  fn revoked(Self, jti : String) -> Bool
  fn revoke(Self, jti : String) -> Unit
}

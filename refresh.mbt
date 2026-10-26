// refresh.mbt — G1 旋转核:refresh 换发 + 重放检测撤全族(D-G3)
//
// 账本语义:store.get(jti) 无记录 = mac 合法但不出自本账本(伪造);
// used 再现 = 重放,立即 revoke_family;revoked = 族已死,新老皆拒。
// 换发只管 refresh 串;access 续发是纯函数 issue(),消费方随手调。

///|
/// 换发错误。Verify(Expired) 即"回握手"信号(A0 语义,由消费方解释)。
pub(all) enum RefreshErr {
  Verify(VerifyErr)
  UnknownToken
  Replayed(String)
  Revoked(Claims)
} derive(Eq, Debug)

///|
/// 换发产物:新 refresh 票 + 族号 + 主体。
pub(all) struct Refreshed {
  refresh : Issued
  family_id : String
  sub : String
} derive(Eq, Debug)

///|
/// 换发:verify_for(refresh) → 账本核 → 旧票 mark_used → 新票入族。
/// 纯函数 + 账本参数:时间与熵(next_jti)全由消费方注入(D-G2),
/// 核心零时钟零随机。
pub fn refresh(
  config : GuardConfig,
  signer : &Signer,
  store : &RefreshStore,
  now : Int64,
  token : String,
  next_jti : String,
) -> Result[Refreshed, RefreshErr] {
  let old = match verify_for(config, signer, now, token, TokenType::Refresh) {
    Ok(c) => c
    Err(e) => return Err(RefreshErr::Verify(e))
  }
  let record = match store.get(old.jti) {
    Some(r) => r
    None => return Err(RefreshErr::UnknownToken)
  }
  if record.revoked {
    return Err(RefreshErr::Revoked(old))
  }
  if record.used {
    store.revoke_family(record.family_id)
    return Err(RefreshErr::Replayed(record.family_id))
  }
  store.mark_used(old.jti)
  let issued = issue(config, signer, now, old.sub, TokenType::Refresh, next_jti)
  store.put(next_jti, {
    family_id: record.family_id,
    sub: old.sub,
    issued_at: now,
    expires_at: issued.claims.exp,
    used: false,
    revoked: false,
  })
  Ok({ refresh: issued, family_id: record.family_id, sub: old.sub, })
}

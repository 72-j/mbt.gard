// guard.mbt — G2 管线:四段 runner(verify→revocation→resolve→dispatch)
// D-G4/D-G13:段间纯值,Guard 单构造点收拢;hooks 全 async 型、核心零依赖
// (D-G12 案A);audit 不可失败(D-G11);业务错归 TResp,本面只管认证拒。

///|
/// 守护拒错(认证面)。
pub(all) enum GuardErr {
  Verify(VerifyErr)
  Revoked
  Unresolved(String)
} derive(Eq, Debug)

///|
/// 审计事件:每段落一行;早期拒绝 sub/jti 可为空串(detail 带拒因)。
pub(all) struct AuditEvent {
  stage : String
  sub : String
  jti : String
  ok : Bool
  detail : String
} derive(Eq, Debug)

///|
/// 单构造点(D-G13):三钩子由消费方注入;主体型 TSubj 泛型——框架
/// 不假设任何用户库(Resolver 消费方实现,茗篇 §2.6)。
pub(all) struct Guard[TSubj, TReq, TResp] {
  config : GuardConfig
  signer : &Signer
  revocations : &RevocationStore
  resolve : async (String) -> TSubj?
  dispatch : async (TSubj, TReq) -> TResp
  audit : async (AuditEvent) -> Unit
}

///|
pub fn[TSubj, TReq, TResp] Guard::new(
  config : GuardConfig,
  signer : &Signer,
  revocations : &RevocationStore,
  resolve : async (String) -> TSubj?,
  dispatch : async (TSubj, TReq) -> TResp,
  audit : async (AuditEvent) -> Unit,
) -> Guard[TSubj, TReq, TResp] {
  { config, signer, revocations, resolve, dispatch, audit, }
}

///|
/// 校验错误的审计短码(不携带载荷,防敏感物进审计)。
fn verify_detail(e : VerifyErr) -> String {
  match e {
    VerifyErr::Malformed(_) => "malformed"
    VerifyErr::BadMac => "bad_mac"
    VerifyErr::Expired(_) => "expired"
    VerifyErr::NotYetValid(_) => "not_yet_valid"
    VerifyErr::WrongIssuer(_) => "wrong_issuer"
    VerifyErr::WrongAudience(_) => "wrong_audience"
    VerifyErr::WrongType(_) => "wrong_type"
  }
}

///|
/// access 门 runner:verify → 吊销核 → resolve → dispatch,段段审计
/// (fail 即短路,拒因落审计;成功路四行全 ok)。
pub async fn[TSubj, TReq, TResp] Guard::run(
  self : Guard[TSubj, TReq, TResp],
  now : Int64,
  token : String,
  req : TReq,
) -> Result[TResp, GuardErr] {
  let claims = match
    verify_for(self.config, self.signer, now, token, TokenType::Access) {
    Ok(c) => c
    Err(e) => {
      let _ = (self.audit)({
        stage: "verify",
        sub: "",
        jti: "",
        ok: false,
        detail: verify_detail(e),
      })
      return Err(GuardErr::Verify(e))
    }
  }
  (self.audit)({
    stage: "verify",
    sub: claims.sub,
    jti: claims.jti,
    ok: true,
    detail: "",
  })
  if self.revocations.revoked(claims.jti) {
    (self.audit)({
      stage: "revocation",
      sub: claims.sub,
      jti: claims.jti,
      ok: false,
      detail: "revoked",
    })
    return Err(GuardErr::Revoked)
  }
  (self.audit)({
    stage: "revocation",
    sub: claims.sub,
    jti: claims.jti,
    ok: true,
    detail: "",
  })
  let subject = match (self.resolve)(claims.sub) {
    Some(s) => s
    None => {
      (self.audit)({
        stage: "resolve",
        sub: claims.sub,
        jti: claims.jti,
        ok: false,
        detail: "unresolved",
      })
      return Err(GuardErr::Unresolved(claims.sub))
    }
  }
  (self.audit)({
    stage: "resolve",
    sub: claims.sub,
    jti: claims.jti,
    ok: true,
    detail: "",
  })
  let resp = (self.dispatch)(subject, req)
  (self.audit)({
    stage: "dispatch",
    sub: claims.sub,
    jti: claims.jti,
    ok: true,
    detail: "",
  })
  Ok(resp)
}

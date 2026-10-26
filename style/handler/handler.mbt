// handler.mbt — 回调方言(初级面):具名回调 trait + mount 挂载
//
// 型(进阶正门)= Guard::new 泛型钩子(核心包);本包 = 方言面:
// 实现三个具名回调(admit/dispatch/audit,sub:String + Json 进出,
// 零泛型、零 turbofish、用户全程不写 async 三字母),一个 mount
// 接线成四段门。impl 侧 self 注实现类型(moonrdb 役3 律),trait
// 方法 pub impl 跨包可见(G1 语言律三针)。

///|
/// 初级回调面:认证门三回调。主体即 sub(String);req/resp 走 Json。
pub(open) trait DoorHandler {
  /// 这人认不认(resolve 段;false = 陌生人拒)
  async fn admit(self : Self, sub : String) -> Bool
  /// 认证过了,活儿怎么干(dispatch 段)
  async fn dispatch(self : Self, sub : String, req : Json) -> Json
  /// 流水账怎么记(audit 段;不可失败,不想记就写空体)
  async fn audit(self : Self, e : @moongrd.AuditEvent) -> Unit
}

///|
/// 挂载:回调 trait → 四段门(框架代接线,audit 直通 handler.audit)。
pub fn mount(
  config~ : @moongrd.GuardConfig,
  signer~ : &@moongrd.Signer,
  revocations~ : &@moongrd.RevocationStore,
  handler~ : &DoorHandler,
) -> @moongrd.Guard[String, Json, Json] {
  @moongrd.Guard::new(
    config~,
    signer~,
    revocations~,
    resolve=async fn(sub : String) -> String? {
      match handler.admit(sub) {
        true => Some(sub)
        false => None
      }
    },
    dispatch=async fn(sub : String, req : Json) -> Json {
      handler.dispatch(sub, req)
    },
    audit=async fn(e : @moongrd.AuditEvent) -> Unit { handler.audit(e) },
  )
}

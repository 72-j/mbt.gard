// stock.mbt — 预制回调库 + 可换装门房(一键换装面)
//
// 工厂函数给常见形(名单准入/回声派工/上屏·吞流·收集审计),返回
// 普通回调值;FlexDoor 三回调皆函数位,swap_* 运行时一键换装——
// 已挂的门即时生效(紧急停门 = swap 进 admit_none(),一行)。

///|
/// 名单准入:仅名单内 sub 放行。
pub fn admit_allowlist(allow~ : Array[String]) -> (String) -> Bool {
  fn(sub : String) -> Bool {
    let mut hit = false
    for name in allow {
      if name == sub {
        hit = true
      }
    }
    hit
  }
}

///|
/// 全放(演示/内测形)。
pub fn admit_all() -> (String) -> Bool {
  fn(_sub : String) -> Bool { true }
}

///|
/// 全拒(紧急停门形)。
pub fn admit_none() -> (String) -> Bool {
  fn(_sub : String) -> Bool { false }
}

///|
/// 回声派工:prefix 装饰,req 原文随应答折回。
pub fn dispatch_echo(prefix~ : String) -> (String, Json) -> Json {
  fn(sub : String, req : Json) -> Json {
    Json::string("\{prefix}\{sub} → \{req.stringify()}")
  }
}

///|
/// 审计上屏(控制台)。
pub fn audit_println() -> (@moongrd.AuditEvent) -> Unit {
  fn(e : @moongrd.AuditEvent) -> Unit {
    println("[audit] \{e.stage} ok=\{e.ok} \{e.detail}")
  }
}

///|
/// 审计吞流(D-G11 沉没形)。
pub fn audit_silent() -> (@moongrd.AuditEvent) -> Unit {
  fn(_e : @moongrd.AuditEvent) -> Unit { () }
}

///|
/// 审计收集:捕获行数组引用,消费方随时可读。
pub fn audit_collector(log~ : Array[String]) -> (@moongrd.AuditEvent) -> Unit {
  fn(e : @moongrd.AuditEvent) -> Unit { log.push("\{e.stage}:\{e.ok}") }
}

///|
/// 可换装门房:三回调皆函数位,swap_* 运行时一键换装。
pub(all) struct FlexDoor {
  mut admit_fn : (String) -> Bool
  mut dispatch_fn : (String, Json) -> Json
  mut audit_fn : (@moongrd.AuditEvent) -> Unit
}

///|
pub fn FlexDoor::new(
  admit_fn~ : (String) -> Bool,
  dispatch_fn~ : (String, Json) -> Json,
  audit_fn~ : (@moongrd.AuditEvent) -> Unit,
) -> FlexDoor {
  { admit_fn, dispatch_fn, audit_fn, }
}

///|
/// 预设门房:名单准入 + 回声派工 + 上屏审计(演示/开发一键起)。
pub fn FlexDoor::demo(allow~ : Array[String], prefix~ : String) -> FlexDoor {
  FlexDoor::new(
    admit_fn=admit_allowlist(allow~),
    dispatch_fn=dispatch_echo(prefix~),
    audit_fn=audit_println(),
  )
}

///|
/// 一键换装:准入策略(紧急停门 = swap 进 admit_none())。
pub fn FlexDoor::swap_admit(self : FlexDoor, admit~ : (String) -> Bool) -> Unit {
  self.admit_fn = admit
}

///|
/// 一键换装:派工策略。
pub fn FlexDoor::swap_dispatch(
  self : FlexDoor,
  dispatch~ : (String, Json) -> Json,
) -> Unit {
  self.dispatch_fn = dispatch
}

///|
/// 一键换装:审计策略。
pub fn FlexDoor::swap_audit(
  self : FlexDoor,
  audit~ : (@moongrd.AuditEvent) -> Unit,
) -> Unit {
  self.audit_fn = audit
}

///|
pub impl DoorHandler for FlexDoor with fn admit(self : FlexDoor, sub : String) -> Bool {
  (self.admit_fn)(sub)
}

///|
pub impl DoorHandler for FlexDoor with fn dispatch(
  self : FlexDoor,
  sub : String,
  req : Json,
) -> Json {
  (self.dispatch_fn)(sub, req)
}

///|
pub impl DoorHandler for FlexDoor with fn audit(
  self : FlexDoor,
  e : @moongrd.AuditEvent,
) -> Unit {
  (self.audit_fn)(e)
}

///|
/// trait 方法显式晋升([0079] 标准动作)。
pub extend FlexDoor with DoorHandler::{admit, audit, dispatch}

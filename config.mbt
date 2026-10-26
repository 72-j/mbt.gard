// config.mbt — 框架配置:构造期注入,无全局无环境变量(D-G5)

///|
/// 框架配置。allowed_drift 界内算有效(时钟漂移容忍);TTL 单位毫秒。
pub(all) struct GuardConfig {
  issuer : String
  audience : String
  allowed_drift_ms : Int64
  access_ttl_ms : Int64
  refresh_ttl_ms : Int64
} derive(Eq, Debug)

///|
/// 默认形:allowed_drift 5000ms(D-AUTH8/D-G5);TTL 由消费方给。
pub fn GuardConfig::make(
  issuer : String,
  audience : String,
  access_ttl_ms : Int64,
  refresh_ttl_ms : Int64,
) -> GuardConfig {
  { issuer, audience, allowed_drift_ms: 5000L, access_ttl_ms, refresh_ttl_ms, }
}

// claims.mbt — token 型与声明集(定型载荷)

///|
/// token 型:access(业务门)/ refresh(换发门)。
pub(all) enum TokenType {
  Access
  Refresh
} derive(Eq, Debug)

///|
/// 线形名(JSON typ 字段取值)。
pub fn TokenType::wire(self : TokenType) -> String {
  match self {
    TokenType::Access => "access"
    TokenType::Refresh => "refresh"
  }
}

///|
/// 线形名反解(未知值 None)。
pub fn TokenType::of_wire(w : String) -> TokenType? {
  if w == "access" {
    Some(TokenType::Access)
  } else if w == "refresh" {
    Some(TokenType::Refresh)
  } else {
    None
  }
}

///|
/// 声明集:token 载荷定型字段。iat/exp 单位毫秒;时间全参数注入,
/// 核心零时钟读(D-G2)。
pub(all) struct Claims {
  sub : String
  iss : String
  aud : String
  iat : Int64
  exp : Int64
  typ : TokenType
  jti : String
} derive(Eq, Debug)

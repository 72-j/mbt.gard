// token.mbt — token 核:签发/校验(定序 JSON 载荷 + base64url 两段 + mac)

///|
/// 签发产物:线形 token(payload.mac 两段)+ 定型 claims。
pub(all) struct Issued {
  token : String
  claims : Claims
} derive(Eq, Debug)

///|
/// 校验错误:mac 之后的错携带 claims(签名已过,载荷可信,供审计定罪);
/// mac 之前的错不携带(不可信物不外传)。
pub(all) enum VerifyErr {
  Malformed(String)
  BadMac
  Expired(Claims)
  NotYetValid(Claims)
  WrongIssuer(Claims)
  WrongAudience(Claims)
  WrongType(Claims)
} derive(Eq, Debug)

///|
/// 签发:claims 定型 → 定序载荷 JSON → mac → base64url 两段线形。
/// 纯函数:时间(now)与熵(jti)全由参数注入,核心零时钟零随机(D-G2)。
pub fn issue(
  config : GuardConfig,
  signer : &Signer,
  now : Int64,
  sub : String,
  typ : TokenType,
  jti : String,
) -> Issued {
  let ttl = match typ {
    TokenType::Access => config.access_ttl_ms
    TokenType::Refresh => config.refresh_ttl_ms
  }
  let claims : Claims = {
    sub,
    iss: config.issuer,
    aud: config.audience,
    iat: now,
    exp: now + ttl,
    typ,
    jti,
  }
  let payload = claims_wire(claims)
  let mac = signer.sign(payload)
  { token: b64url_encode(payload) + "." + b64url_encode(mac), claims, }
}

///|
/// 校验:分段 → 解码 → mac 核(先于解析,不碰未信物)→ 定型 →
/// iss/aud → 时间窗(漂移界)。管线 verify 段的核(四段 runner G2 组)。
pub fn verify(
  config : GuardConfig,
  signer : &Signer,
  now : Int64,
  token : String,
) -> Result[Claims, VerifyErr] {
  let (payload_seg, mac_seg) = match split_dot(token) {
    Some(pair) => pair
    None =>
      return Err(VerifyErr::Malformed("需两段 base64url 以 '.' 分隔"))
  }
  let payload = match b64url_decode(payload_seg) {
    Some(b) => b
    None => return Err(VerifyErr::Malformed("载荷段非 base64url"))
  }
  let mac = match b64url_decode(mac_seg) {
    Some(b) => b
    None => return Err(VerifyErr::Malformed("mac 段非 base64url"))
  }
  if signer.verify(payload, mac) == false {
    return Err(VerifyErr::BadMac)
  }
  let claims = match claims_of_wire(payload) {
    Some(c) => c
    None => return Err(VerifyErr::Malformed("载荷非定型 claims"))
  }
  if claims.iss != config.issuer {
    return Err(VerifyErr::WrongIssuer(claims))
  }
  if claims.aud != config.audience {
    return Err(VerifyErr::WrongAudience(claims))
  }
  if now > claims.exp + config.allowed_drift_ms {
    return Err(VerifyErr::Expired(claims))
  }
  if claims.iat > now + config.allowed_drift_ms {
    return Err(VerifyErr::NotYetValid(claims))
  }
  Ok(claims)
}

///|
/// 带门校验:typ 不对即 WrongType(门面用——access 门不收 refresh)。
pub fn verify_for(
  config : GuardConfig,
  signer : &Signer,
  now : Int64,
  token : String,
  typ : TokenType,
) -> Result[Claims, VerifyErr] {
  let claims = match verify(config, signer, now, token) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  if claims.typ != typ {
    return Err(VerifyErr::WrongType(claims))
  }
  Ok(claims)
}

///|
/// 首点分段;余点交给 b64url 字符集校验兜底('.' 不在字母表 → Malformed)。
fn split_dot(token : String) -> (String, String)? {
  let n = token.length()
  let mut dot = -1
  let mut i = 0
  while i < n {
    if token[i].to_int() == 46 {
      dot = i
      i = n
    } else {
      i += 1
    }
  }
  if dot < 0 {
    return None
  }
  Some((token[0:dot].to_owned(), token[dot + 1:n].to_owned()))
}

///|
/// 载荷定序 JSON(手写:字段序稳定,线形可读可核)。
fn claims_wire(c : Claims) -> Bytes {
  let sb = StringBuilder()
  sb.write("{\"sub\":")
  sb.write(jstr(c.sub))
  sb.write(",\"iss\":")
  sb.write(jstr(c.iss))
  sb.write(",\"aud\":")
  sb.write(jstr(c.aud))
  sb.write(",\"iat\":")
  sb.write("\{c.iat}")
  sb.write(",\"exp\":")
  sb.write("\{c.exp}")
  sb.write(",\"typ\":\"")
  sb.write(c.typ.wire())
  sb.write("\",\"jti\":")
  sb.write(jstr(c.jti))
  sb.write("}")
  @utf8.encode(sb.to_string())
}

///|
/// JSON 字符串值转义:引号/反斜杠/控制字符(\uXXXX);非 BMP 成对码元
/// 直通,孤立码元替损不致崩。
fn jstr(s : String) -> String {
  let sb = StringBuilder()
  sb.write("\"")
  let n = s.length()
  let mut i = 0
  while i < n {
    let code = s[i].to_int()
    if code == 34 {
      sb.write("\\\"")
      i += 1
    } else if code == 92 {
      sb.write("\\\\")
      i += 1
    } else if code < 32 {
      sb.write("\\u")
      sb.write(hex4(code))
      i += 1
    } else if code >= 0xD800 &&
      code < 0xDC00 &&
      i + 1 < n &&
      s[i + 1].to_int() >= 0xDC00 {
      sb.write(s[i:i + 2].to_owned())
      i += 2
    } else {
      sb.write(s[i:i + 1].to_owned())
      i += 1
    }
  }
  sb.write("\"")
  sb.to_string()
}

///|
let hex_digits : Array[String] = [
  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
]

///|
fn hex4(v : Int32) -> String {
  let sb = StringBuilder()
  sb.write(hex_digits[(v >> 12) & 15])
  sb.write(hex_digits[(v >> 8) & 15])
  sb.write(hex_digits[(v >> 4) & 15])
  sb.write(hex_digits[v & 15])
  sb.to_string()
}

///|
/// 定型反解:七字段全齐才认;多余字段无视(前向兼容)。
fn claims_of_wire(payload : Bytes) -> Claims? {
  let parsed = @json.parse(@utf8.decode_lossy(payload)) catch {
    _ => return None
  }
  let map = match parsed {
    Object(m) => m
    _ => return None
  }
  let sub = match jstr_field(map, "sub") {
    Some(v) => v
    None => return None
  }
  let iss = match jstr_field(map, "iss") {
    Some(v) => v
    None => return None
  }
  let aud = match jstr_field(map, "aud") {
    Some(v) => v
    None => return None
  }
  let iat = match ji64_field(map, "iat") {
    Some(v) => v
    None => return None
  }
  let exp = match ji64_field(map, "exp") {
    Some(v) => v
    None => return None
  }
  let typ = match jstr_field(map, "typ") {
    Some(w) =>
      match TokenType::of_wire(w) {
        Some(t) => t
        None => return None
      }
    None => return None
  }
  let jti = match jstr_field(map, "jti") {
    Some(v) => v
    None => return None
  }
  Some({ sub, iss, aud, iat, exp, typ, jti, })
}

///|
fn jstr_field(map : Map[String, Json], key : String) -> String? {
  match map.get(key) {
    Some(Json::String(s)) => Some(s)
    _ => None
  }
}

///|
fn ji64_field(map : Map[String, Json], key : String) -> Int64? {
  match map.get(key) {
    Some(Json::Number(d, ..)) => Some(d.to_int64())
    _ => None
  }
}

///|
/// base64url 无垫编码(JWT 式;'-'/'_' 直落,不出 '=')。
fn b64url_encode(bytes : Bytes) -> String {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  let sb = StringBuilder()
  let n = bytes.length()
  let mut i = 0
  while i < n {
    let b0 = bytes[i].to_int()
    if i + 1 >= n {
      sb.write(slice1(alphabet, (b0 >> 2) & 63))
      sb.write(slice1(alphabet, (b0 << 4) & 63))
    } else if i + 2 >= n {
      let b1 = bytes[i + 1].to_int()
      sb.write(slice1(alphabet, (b0 >> 2) & 63))
      sb.write(slice1(alphabet, ((b0 << 4) & 63) | (b1 >> 4)))
      sb.write(slice1(alphabet, (b1 << 2) & 63))
    } else {
      let b1 = bytes[i + 1].to_int()
      let b2 = bytes[i + 2].to_int()
      sb.write(slice1(alphabet, (b0 >> 2) & 63))
      sb.write(slice1(alphabet, ((b0 << 4) & 63) | (b1 >> 4)))
      sb.write(slice1(alphabet, ((b1 << 2) & 63) | (b2 >> 6)))
      sb.write(slice1(alphabet, b2 & 63))
    }
    i += 3
  }
  sb.to_string()
}

///|
/// base64url 无垫解码(严格:字母表外拒;尾残留非零拒;'=' 不收)。
fn b64url_decode(s : String) -> Bytes? {
  let n = s.length()
  if n % 4 == 1 {
    return None
  }
  let out_len = n * 6 / 8
  if out_len == 0 {
    return Some(@utf8.encode(""))
  }
  let out : Array[Byte] = Array::make(out_len, b'\x00')
  let mut acc = 0
  let mut bits = 0
  let mut written = 0
  let mut i = 0
  while i < n {
    let v = match b64url_value(s[i].to_int()) {
      Some(v) => v
      None => return None
    }
    acc = ((acc << 6) | v) & 0xFFFF
    bits += 6
    if bits >= 8 {
      bits -= 8
      out[written] = ((acc >> bits) & 255).to_byte()
      written += 1
    }
    i += 1
  }
  if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
    return None
  }
  Some(Bytes::from_array(out))
}

///|
/// ASCII 串单码元切片(调用点保证界内)。
fn slice1(s : String, i : Int32) -> String {
  s[i:i + 1].to_owned()
}

///|
fn b64url_value(code : Int32) -> Int32? {
  if code >= 65 && code <= 90 {
    Some(code - 65)
  } else if code >= 97 && code <= 122 {
    Some(code - 97 + 26)
  } else if code >= 48 && code <= 57 {
    Some(code - 48 + 52)
  } else if code == 45 {
    Some(62)
  } else if code == 95 {
    Some(63)
  } else {
    None
  }
}

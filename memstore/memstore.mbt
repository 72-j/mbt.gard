// memstore.mbt — 内存账本:refresh 族谱 + 吊销表(G1;测试与单机用,
// 生产存储按 trait 自带 CouchDB/redis 实现)

///|
/// refresh 族谱内存实现:jti → 记录。进程内单点用,无并发保证。
pub(all) struct MemRefreshStore {
  mut table : Map[String, @moongrd.RefreshRecord]
}

///|
pub fn MemRefreshStore::new() -> MemRefreshStore {
  { table: Map([]), }
}

///|
pub impl @moongrd.RefreshStore for MemRefreshStore with fn put(
  self,
  jti : String,
  record : @moongrd.RefreshRecord,
) -> Unit {
  self.table[jti] = record
}

///|
pub impl @moongrd.RefreshStore for MemRefreshStore with fn get(
  self,
  jti : String,
) -> @moongrd.RefreshRecord? {
  self.table.get(jti)
}

///|
pub impl @moongrd.RefreshStore for MemRefreshStore with fn mark_used(
  self,
  jti : String,
) -> Unit {
  let updated : @moongrd.RefreshRecord? = match self.table.get(jti) {
    Some(r) =>
      Some({
        family_id: r.family_id,
        sub: r.sub,
        issued_at: r.issued_at,
        expires_at: r.expires_at,
        used: true,
        revoked: r.revoked,
      })
    None => None
  }
  match updated {
    Some(r) => self.table[jti] = r
    None => ()
  }
}

///|
pub impl @moongrd.RefreshStore for MemRefreshStore with fn revoke_family(
  self,
  family_id : String,
) -> Unit {
  let hits : Array[(String, @moongrd.RefreshRecord)] = []
  for jti, r in self.table {
    if r.family_id == family_id {
      hits.push((jti, r))
    }
  }
  for pair in hits {
    let (jti, r) = pair
    self.table[jti] = {
      family_id: r.family_id,
      sub: r.sub,
      issued_at: r.issued_at,
      expires_at: r.expires_at,
      used: r.used,
      revoked: true,
    }
  }
}

///|
/// 清扫过期记录(返回清除数)——守护进程周期调,防账本无限长。
pub fn MemRefreshStore::sweep(self : MemRefreshStore, now : Int64) -> Int32 {
  let dead : Array[String] = []
  for jti, r in self.table {
    if now > r.expires_at {
      dead.push(jti)
    }
  }
  for jti in dead {
    let _ = self.table.remove(jti)
  }
  dead.length()
}

///|
/// access 吊销表内存实现:jti → 墓碑。
pub(all) struct MemRevocationStore {
  mut tomb : Map[String, Bool]
}

///|
pub fn MemRevocationStore::new() -> MemRevocationStore {
  { tomb: Map([]), }
}

///|
pub impl @moongrd.RevocationStore for MemRevocationStore with fn revoke(
  self,
  jti : String,
) -> Unit {
  self.tomb[jti] = true
}

///|
pub impl @moongrd.RevocationStore for MemRevocationStore with fn revoked(
  self,
  jti : String,
) -> Bool {
  match self.tomb.get(jti) {
    Some(_) => true
    None => false
  }
}

///|
/// trait 方法显式晋升([0079] 标准动作)。
pub extend MemRefreshStore with @moongrd.RefreshStore::{
  revoke_family,
  put,
  get,
  mark_used,
}

///|
pub extend MemRevocationStore with @moongrd.RevocationStore::{revoked, revoke}

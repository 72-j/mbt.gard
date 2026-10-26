# 05 · 五换挡位与 adapter 编写

moongrd 有五个 trait 换挡位。判据一条:**部署期换算法/实现 → trait;
运行期换行为 → 回调;调数值 → 字段;安全语义 → 钉死**(柔性规程
D-G20)。

| 位 | trait | 缺省/参考实现 |
|---|---|---|
| 算法 | `Signer`(sign/verify) | adapter/mooncry `HmacSha256Signer` |
| AEAD | `Cipher`(seal/open) | adapter/mooncry `AesGcmCipher` |
| refresh 存储 | `RefreshStore`(put/get/mark_used/revoke_family) | memstore |
| 吊销存储 | `RevocationStore`(revoked/revoke) | memstore |
| 认证协议 | `AuthProtocol`(verify_access) | 核心 `TokenProtocol` |

## 编写一个 Signer(以 Ed25519 为例)

```moonbit
///|
struct Ed25519Signer {
  seed : Bytes     // 签名私钥(32B seed)
  public : Bytes   // 验签公钥
}

///|
impl @moongrd.Signer for Ed25519Signer with sign(self, payload) -> Bytes {
  @lib.ed25519_sign(self.seed, payload)
}

///|
impl @moongrd.Signer for Ed25519Signer with verify(self, payload, mac) -> Bool {
  @lib.ed25519_verify(self.public, payload, mac)
}
```

要点:

- `pub impl`(**带 pub**)——裸 impl 包私有,跨包不可见([4018] 教训)。
- verify 用常量时比较(`@lib.bytes_equal`),别用 `==` 直比大数组。
- 非对称形注意:`Signer` trait 是"自签自验"的对称形;纯验签方
  (只持公钥)直接调 `ed25519_verify`,不走本 trait。

## 编写一个 Cipher

```moonbit
///|
struct ChaChaCipher {
  key : Bytes
}

///|
impl @moongrd.Cipher for ChaChaCipher with seal(
  self, plaintext : Bytes, nonce : Bytes, aad : Bytes,
) -> Bytes {
  // ct ‖ tag 线形自定,open 对称撕开
  ...
}

///|
impl @moongrd.Cipher for ChaChaCipher with open(
  self, ciphertext : Bytes, nonce : Bytes, aad : Bytes,
) -> Bytes? {
  ... // 验签失败返回 None,不抛不 abort
}
```

## 编写一个存储(如 CouchDB 族谱)

```moonbit
///|
pub impl @moongrd.RefreshStore for CouchStore with put(
  self, jti : String, record : @moongrd.RefreshRecord,
) -> Unit {
  // 异步库:内部写队列,daemon 泵消费(存储位保持同步色)
  ...
}
```

同步色约定:存储 trait 为同步——异步库在实现里走内部队列/写穿透,
由消费方的泵驱动,trait 面不引 async。

## 信道位(外置)

第五位 `Handshake` 住 moonkcp `secchan`(PSK-CR 已通,Noise IKpsk2
备位)。会话密钥以 `SessionKeys{key_c2s, key_s2c}` 为唯一交换物——
任何握手产出这对钥即可与记录层对接。选型参考 secchan 设计卷 §七
(PSK-CR / Noise IKpsk2 / NK·KK·XX / 签名挑战 / mTLS / ML-KEM 对照表)。

## 慢哈希边界(D-G16)

PBKDF2/Argon2 是口令拉伸器,**永不进 token 校验路**(校验高频,快是
特性)。合法落点:启动期 PSK 伸展(信道层)、口令存储(存储侧)、
静态加密(消费方)——全框架外,mooncry 直调。

## 换挡即换构造参数

所有换挡位都是 `Guard` / `mount` 的构造参数:

```moonbit
let door = @moongrd.Guard::new(
  config=config,
  signer=my_ed25519_signer,     // 换算法
  revocations=my_couch_store,   // 换存储
  protocol=my_protocol,         // 换协议(可省)
  resolve=..., dispatch=..., audit=...,
)
```

新实现 = 新 impl + 换一个构造参数,框架与管线零改。

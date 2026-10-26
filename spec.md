# MoonGrd spec —— 协议形态与演进锚

Guardian 式认证管道框架。本卷 = 协议形态定谳 + 升级演进锚:每个可换维度
钉一条**不变式**,升级换内脏不破消费方。

## 一、两层切分(D-G7)

| 层 | 职责 | 住处 |
|---|---|---|
| token 面 | 谁能干什么到什么时候:签发/校验/刷新/旋转 | **本仓** |
| 信道面 | 字节怎么保密过网:PSK-CR 握手 + HKDF + AEAD seq-IV + 滑窗 | moonkcp secchan,**永不进本仓** |

不变式:token 走信道传,信道不知道 token 里是什么;两层各自独立可换。

## 二、token 面协议形态(G0 已落)

- bearer 双 token:access(业务门)/ refresh(换发门);refresh 旋转一次性
  作废,已用再现 = 重放,撤全族(D-G3)。
- 线形 = 定序 JSON 载荷 + mac,两段 base64url 无垫。
- 校验序:分段 → 解码 → mac → 定型 → iss/aud → 时间窗(漂移界),拒绝
  短路带原因;**校验序是框架私产,不开放回调**(D-G10)。

不变式:线形格式可整体替换(JWT/COSE/二进制),`Issued.token : String`
黑盒进黑盒出,消费方不解析线形。

## 三、签名算法(G3 定谳)

`Signer` trait 后面落 **HMAC-SHA256**(对称,共享密钥)或 **Ed25519**
(非对称,可分发验签),实现住 adapter/mooncry(D-G6)。

不变式:换算法 = 换 adapter 包,核心与消费方零改;换算法 ≠ 关校验。

## 四、慢哈希律(D-G16)

**PBKDF2 / Argon2 是口令拉伸器,永不进 token 校验路**——校验是每请求
高频路径,慢哈希放那里 = 每请求白交税 + 自我 DoS。校验路只有
mac + 时间窗 + iss/aud,快是特性。

合法落点三个,全在框架外:

| 口子 | 用法 | 归属 |
|---|---|---|
| PSK 伸展 | 管理员口令 → Argon2/PBKDF2 → 信道 PSK 种子(启动期一次性) | moonkcp secchan / A0,mooncry 直调 |
| 口令存储 | Argon2id 落库 | 存储侧;现状 CouchDB `_users` 自带 PBKDF2,不做 |
| 静态加密 | refresh 族谱落盘加密(若将来需要) | 消费方 |

依赖账:mooncry 全有(PBKDF2/scrypt/Argon2),零新增依赖。真到要进框架
那天,唯一路径 = 照 `Signer` 模式立 `PasswordHasher` trait + argon2
adapter(D-G6 同构)——YAGNI,不预铺。

## 五、信道认证的取舍(在位/备位;详表 = moonkcp `.mingspace/secchan_ming.md` §七)

| 位 | 方式 | 取舍 |
|---|---|---|
| **在位** | PSK-CR(三消息挑战应答,双向互认) | 无 PFS——内网/白名单/PSK 可控分发够用;先通不卡工期 |
| **备位·主** | Noise IKpsk2(X25519 临时 DH + psk2 互认 + 服务端静态公钥钉死) | 有 PFS + 免 MITM——公网运维必选;A2 触发时评审上座 |
| **备位·族** | Noise NK/KK/XX、Ed25519 签名挑战、TLS 1.3/mTLS、ML-KEM 混合 | 按需触发:客户端匿名走 NK;身份不预分发走 XX;已有 PKI 走 TLS;抗量子远期 |

取舍三问:**在哪**(内网 A 够/公网 PFS 必选)、**能预置什么**(PSK 可安全
分发走 A,只能发公钥走 IK/NK,都不能走 XX)、**PFS 要不要**(内容价值期
长于 PSK 泄露窗口则必须)。两条红线:协议构造期钉死禁在线协商(降级面);
白名单场景双向互认是底线。

不变式:握手可插拔——`SessionKeys` 是唯一交换物,换挡 = 换 Handshake
实现,记录层与上层零改(D-S1)。

## 六、演进锚点总表

| 维度 | 现状 | 升级形 | 不变式 |
|---|---|---|---|
| 线形格式 | 定序 JSON + base64url | JWT / COSE / 二进制 | token 对消费方是黑盒 String |
| 签名算法 | **G3 已落:HMAC-SHA256**(adapter/mooncry,RFC 4231 KAT 过 trait)+ AES-GCM Cipher | Ed25519(非对称验签分发形)↔ 后量子 | `Signer` trait 签名即接口 |
| 存储 | G1 memstore 已落(族谱+吊销表+sweep) | CouchDB / redis 按 trait 自带 | `RefreshStore`/`RevocationStore` trait |
| **管线** | **G2 runner 已落**(Guard[TSubj,TReq,TResp] 四段:verify→revocation→resolve→dispatch,段段审计;钩子匿名 async fn 字面量可内联) | 段增删/审计分流 | 段间纯值;校验序框架私产;拒绝短路带原因 |
| 信道 | **在位 PSK-CR(已通);备位 Noise IKpsk2(A2 评审上座)** | NK/KK/XX/签名挑战/TLS/ML-KEM 按需 | 信道永不在本仓;SessionKeys 唯一交换物 |
| 口令拉伸 | 框架外 | `PasswordHasher` trait(触发才立) | 慢哈希不进校验路 |
| hooks 异步色 | async fn 型零 import;async trait 声明语法已证(D-G12 案 A) | async impl 实练(G2 runner 已用 async 字面量钩子) | 核心零依赖 |
| 会话认证协议 | **AuthProtocol trait 已落**(TokenProtocol 缺省;`protocol?` 可选举参) | bearer 外新协议 = 新 impl | 校验序/短路框架私产 |

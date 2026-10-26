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

## 五、演进锚点总表

| 维度 | 现状 | 升级形 | 不变式 |
|---|---|---|---|
| 线形格式 | 定序 JSON + base64url | JWT / COSE / 二进制 | token 对消费方是黑盒 String |
| 签名算法 | 未定(G3) | HMAC ↔ Ed25519 ↔ 后量子 | `Signer` trait 签名即接口 |
| 存储 | G1 memstore 已落(族谱+吊销表+sweep) | CouchDB / redis 按 trait 自带 | `RefreshStore`/`RevocationStore` trait |
| **管线** | **G2 runner 已落**(Guard[TSubj,TReq,TResp] 四段:verify→revocation→resolve→dispatch,段段审计;钩子匿名 async fn 字面量可内联) | 段增删/审计分流 | 段间纯值;校验序框架私产;拒绝短路带原因 |
| 信道 | 外置 | moonkcp secchan(PSK-CR+HKDF+AEAD) | 信道永不在本仓 |
| 口令拉伸 | 框架外 | `PasswordHasher` trait(触发才立) | 慢哈希不进校验路 |
| hooks 异步色 | async fn 型零 import;async trait 声明语法已证(D-G12 案 A) | async impl 实练(G2 runner 已用 async 字面量钩子) | 核心零依赖 |

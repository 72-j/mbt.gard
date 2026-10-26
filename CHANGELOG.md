# Changelog

本文件记录 MoonGrd 的显著变更。格式参照 Keep a Changelog;
版本遵循语义化版本(0.x 为实验期,API 仍可能随反馈调整)。

## 0.1.1（2026-10-26）

### Changed

- **audit 槽 Option 化**:`Guard.audit` 型由 `async (AuditEvent) ->
  Unit` 改 `(async (AuditEvent) -> Unit)?`——省略 audit 即 `None`
  吞流(D-G11 合法沉没改缺席表示),不再构造空 async 函数;
  `Guard::new` 签名不变,经构造点消费的面无感。

## 0.1.0（2026-10-26）

首个公开版本:Guardian 式认证管道框架,token 核 / 旋转 / 四段管线 /
真加密绑定全线走完。

### Added

- **token 核**:access/refresh 双 token 签发、校验、带门校验;定序 JSON
  + base64url 无垫线形;HMAC 签名;时间与熵全参数注入(核心零时钟零随机)。
- **旋转语义**:refresh 一次性作废;已用票再现 = 重放检测,自动撤全族。
- **memstore**:refresh 族谱 + 吊销表的内存实现(含过期清扫),测试与
  单机用;生产存储按 trait 自带。
- **四段管线**:verify → revocation → resolve → dispatch,段段审计、
  拒绝短路带拒因;Guard 单构造点,钩子全 async、主体泛型。
- **四个换挡位(全 trait)**:算法 Signer、AEAD Cipher、存储
  RefreshStore/RevocationStore、认证协议 AuthProtocol(TokenProtocol
  缺省)——新实现 = 新 impl,框架零改。
- **回调方言(style/handler)**:DoorHandler 三具名回调 + mount 接线;
  stock 预制回调库(名单准入/全放全拒/回声派工/审计三形)+ FlexDoor
  运行时一键换装(紧急停门一行)。
- **adapter/mooncry**:HMAC-SHA256 Signer(RFC 4231 已知答案向量过
  trait)+ AES-GCM Cipher。
- **示例 ×4**:`walkthrough`(全链六幕)/ `session_lifecycle`(会话
  生命周期五幕)/ `handler_demo`(回调方言三幕)/ `signer_swap`(换
  verify 算法三幕)。
- **spec.md**:协议形态、两层切分、慢哈希律、演进锚点总表、设计决策表
  (D-G1~G20 公开版)。

### Security

- 认证失败统一错误形,无认证 oracle;mac 校验前的错误不携带载荷。
- 常量时间 mac 比较(adapter 侧)。
- 慢哈希(PBKDF2/Argon2)不进 token 校验路(慢哈希律,D-G16)。
- **未经独立安全审计**——0.x 实验期;公网部署请配合信道层 PFS(见
  moonkcp secchan)并自行评审。

### Notes

- 核心包零外部依赖;`moonbitlang/async` 为 test-only 依赖;
  `cc06b/mooncry` 仅 adapter 包消费。
- 安全信道(PSK-CR / Noise)不在本框架——token 走信道传,信道不知道
  token 里是什么。

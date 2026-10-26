# MoonGrd

Guardian 式认证管道框架(MoonBit)。access/refresh 双 token 旋转 + 四段分发
管线(verify → resolve → dispatch → audit,段间纯值);transport-free、
storage-free、crypto-impl-free——核心包零依赖,密码学藏 `Signer`/`Cipher`
trait 后面(参考实现绑 mooncry,与 Guardian 委托 Joken 同构)。

> 安全信道(PSK-CR 握手 / HKDF / AEAD seq-IV / 滑窗防重放)不属于本框架——
> 那是 TLS 层的活,住传输侧(moonkcp `secchan`,另役)。本框架的 token 走信道传。

**状态**:G0 骨架在工(token 核 + 扩展面 trait;绿门待复跑)。
路线:G0 骨架(token 核)→ G1 旋转 + 重放检测 → G2 四段管线 → G3 mooncry 绑定 + 教程。

## 设计渊源

三针采自 Elixir Guardian(moonkcp admin plane A0 v2 回灌,裁定 D-AUTH7/8/9):

- access/refresh 双 token,refresh 旋转一次性作废;
- `allowed_drift` 时钟漂移容忍配置化(默认 5000ms);
- 四段分发管线,段间纯值(采 Plug 组合)。

## 扩展面分寸(D-G10)

回调收在**数据面**(数据从哪来、结果到哪去),不收在**控制面**(校验序、
短路逻辑)——verify 段是框架私产,不开放回调;换算法(Signer)≠ 关校验。

| 扩展点 | 形 |
|---|---|
| `Signer`(sign/verify,有状态成对操作) | trait |
| `RefreshStore` / `RevocationStore`(多式共享状态) | trait |
| `resolve` / `dispatch` / `audit`(单钩子) | 闭包 |
| `audit` 特例 | 不可失败(返回 `Unit`,写败是 sink 自己的事) |

全部钩子在一个 `Guard` 构造点收拢,消费方一处组装。

## 许可证

Apache-2.0。

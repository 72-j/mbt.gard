# MoonGrd Guides

按手感选路:初级两篇走回调方言,半小时上一门;高级三篇下到 token 核与
五换挡位。所有代码均取自仓内可跑实况(测试与 `examples/`),命令皆可
复制执行。

## 初级(回调方言,零泛型零 async)

| Guide | 内容 |
|---|---|
| [01 · 五分钟上一门](01-getting-started.md) | 安装、发票、起门、进门、读拒因 |
| [02 · 门房回调](02-handler-callbacks.md) | DoorHandler 三回调各职、mount 接线、测试建议 |

## 高级(token 核与换挡位)

| Guide | 内容 |
|---|---|
| [03 · token 核与旋转](03-token-core.md) | 线形、issue/verify/verify_for、refresh 旋转与重放撤族、drift |
| [04 · 四段管线与 Guard 全形](04-guard-pipeline.md) | 段语义、审计事件流、AuthProtocol 协议换挡、泛型主体 |
| [05 · 五换挡位与 adapter](05-swap-points.md) | Signer/Cipher/双 Store/Handshake 的 trait 设计与 adapter 编写 |

## 示例廊对照(一键可跑)

```bash
moon run examples/walkthrough          # 全链六幕(进阶形)
moon run examples/session_lifecycle    # 会话一生五幕(token 核)
moon run examples/handler_demo         # 回调方言三幕(初级)
moon run examples/signer_swap          # 换 verify 算法三幕(换挡位)
```

遇到拒不知道为什么?先看 [03 · token 核](03-token-core.md) 的错误面表;
要改行为,先看 [05 · 换挡位](05-swap-points.md) 对四分法。

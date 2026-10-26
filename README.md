# MoonGrd

Guardian 式认证管道框架(MoonBit)。access/refresh 双 token 旋转 + 四段分发
管线(verify → resolve → dispatch → audit,段间纯值);transport-free、
storage-free、crypto-impl-free——核心包零依赖,密码学藏 `Signer`/`Cipher`
trait 后面(参考实现绑 mooncry,与 Guardian 委托 Joken 同构)。

> 安全信道(PSK-CR 握手 / HKDF / AEAD seq-IV / 滑窗防重放)不属于本框架——
> 那是 TLS 层的活,住传输侧(moonkcp `secchan`,另役)。本框架的 token 走信道传。

**状态**:G0 骨架在工(token 核 + 扩展面 trait;绿门待复跑)。
路线:G0 骨架(token 核)→ G1 旋转 + 重放检测 → G2 四段管线 → G3 mooncry 绑定 + 教程。

## 五分钟上手(D-G8 教程律:示例内嵌可跑形,真源 = 各 _test.mbt)

**一键全链演示**:`cd moongrd && moon run examples/walkthrough`——登录
双 token → 四段门审计 → 换发旋转 → 重放撤族 → 族谱尽戮 → 篡改拒,六幕
连映(真 HMAC 签名,时间/熵常量注入)。

**会话全生命周期**:`moon run examples/session_lifecycle`——登录 → 进门 →
access 过期 → refresh 换发续命 → 登出吊销,五幕讲完一个会话的一生。

**回调方言**:`moon run examples/handler_demo`——实现三个具名回调 +
一句 mount,初级用户视角的三幕剧(放行/陌生人拒/伪造拒)。

**换 verify 算法**:`moon run examples/signer_swap`——同一管线,HMAC-SHA512 /
AES-CMAC / Ed25519 三位签名者三换三绿;交叉核验全拒演示"算法不换算"。

### 1 签发与校验(纯函数;时间/熵全参数注入)

```moonbit
let config = @moongrd.GuardConfig::make("iss1", "aud1", 60000L, 600000L)
let signer : &@moongrd.Signer = @mooncry.HmacSha256Signer::new(session_key)
let access = @moongrd.issue(config, signer, now, "alice", @moongrd.TokenType::Access, jti_a)
let refresh = @moongrd.issue(config, signer, now, "alice", @moongrd.TokenType::Refresh, jti_r)
store.put(jti_r, { family_id: "fam-1", sub: "alice", issued_at: now,
                   expires_at: refresh.claims.exp, used: false, revoked: false })
// 业务门:typ 不对即拒
let claims = @moongrd.verify_for(config, signer, now, access.token, @moongrd.TokenType::Access)
```

### 2 换发(旋转一次性 + 重放撤全族)

```moonbit
match @moongrd.refresh(config, signer, store, now, refresh_token, next_jti) {
  Ok(r) => // 新 refresh 到手;access 用 issue() 另发
  Err(@moongrd.RefreshErr::Replayed(fam)) => // 盗用!全族已自动作废
  Err(@moongrd.RefreshErr::Verify(Expired(_))) => // 回握手
  ...
}
```

### 3 四段门(三种姿势,按手感选)

**最简形(回调方言,`style/handler`)**——实现三个具名回调,mount 即得
一门;主体即 sub,req/resp 走 Json,全程不写 async:

```moonbit
pub impl DoorHandler for MyDoor with admit(self : MyDoor, sub : String) -> Bool { ... }
pub impl DoorHandler for MyDoor with dispatch(self : MyDoor, sub : String, req : Json) -> Json { ... }
pub impl DoorHandler for MyDoor with audit(self : MyDoor, e : @moongrd.AuditEvent) -> Unit { ... }

let door = @handler.mount(config=config, signer=signer,
                          revocations=revocations, handler=my_door)
let resp = door.run(now, access_token, req)
```

**中级形(标签钩子)**——audit 可省(省略 = 吞流,进阶再挂):

```moonbit
let door = @moongrd.Guard::new(
  config=config, signer=signer, revocations=revocations,
  resolve=async fn(sub : String) -> User? { ... },        // sub → 主体
  dispatch=async fn(u : User, req : Req) -> Resp { ... }, // 业务到达
)
```

**进阶形(挂审计)**——每段落一行事件,fail 短路带拒因;泛型全权
(任意主体/进出型)同门加 `audit=` 即得。四段语义三者同一:
verify → revocation → resolve → dispatch。

### 4 真加密面(adapter/mooncry)

HMAC-SHA256 签名 + AES-256-GCM 密封。key 来源:启动期口令/PSK 经
Argon2/PBKDF2 拉伸(mooncry 直调——慢哈希不进校验路,D-G16);运行期
nonce/jti 由你的 CSPRNG 注入(核心零随机,D-G2;mooncry 无随机面,
推荐 experimental_crypto/getrandom)。

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

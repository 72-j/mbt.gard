name = "thy1016/moongard"

version = "0.1.2"

readme = "README.md"

repository = "https://gitlink.org.cn/thy7/mbt.gard"

license = "Apache-2.0"

keywords = [
  "auth",
  "authentication",
  "token",
  "pipeline",
  "guardian",
  "moonbit",
]

description = "MoonGard — Guardian 式认证管道框架(access/refresh 双 token 旋转 + 四段分发管线;transport/storage/crypto-free,核心零依赖)"

// test-only:async test 基建(核心包 import 面仍零依赖,D-G1)
// adapter:mooncry 绑定仅 adapter/mooncry 包消费(核心包不 import,D-G6)
import {
  "moonbitlang/async@0.22.4",
  "cc06b/mooncry@0.95.0",
  // test-only:quicktest 守恒律机(qcs 0.0.1 在册;quickcheck 统一 0.15.1——
  // 0.14.0 注册表 tarball 是旧格式 moon.mod.json,新工具链拒装,家法同款)
  "moonbit-community/quickcheck_statemachine@0.0.1",
  "moonbitlang/quickcheck@0.15.1",
}

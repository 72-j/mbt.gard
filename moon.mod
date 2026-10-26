name = "thy1016/moongrd"

version = "0.1.0"

readme = "README.md"

repository = "https://gitlink.org.cn/thy7/mbt.grd"

license = "Apache-2.0"

keywords = [
  "auth",
  "authentication",
  "token",
  "pipeline",
  "guardian",
  "moonbit",
]

description = "MoonGrd — Guardian 式认证管道框架(access/refresh 双 token 旋转 + 四段分发管线;transport/storage/crypto-free,核心零依赖)"

// test-only:async test 基建(核心包 import 面仍零依赖,D-G1)
// adapter:mooncry 绑定仅 adapter/mooncry 包消费(核心包不 import,D-G6)
import {
  "moonbitlang/async@0.22.4",
  "cc06b/mooncry@0.95.0",
}

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
import {
  "moonbitlang/async@0.22.4",
}

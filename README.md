# eudi_lib_statium

Cangjie (HarmonyOS) port of [eudi-lib-ios-statium-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-statium-swift) —
an implementation of the IETF **OAuth Token Status List** specification, used by the EUDI Wallet to
resolve the revocation/validity status of issued credentials.

Cangjie 包名: `ohos_app_cangjie_eudi_cjstatium`(模块目录 `eudi_cjstatium`)。

## 能力
- Status List Token 解析:JWT(`parseJwtStatusListClaims`)与 CWT/COSE(`decodeCwtStatusListToken`)两种格式
- 位串解压:DEFLATE(`decompressDeflate` / `decompressDeflateOrThrow`,基于 `stdx.compress.zlib`)
- 状态读取:`ReadStatus` 支持 1/2/4/8-bit per status;`GetStatus` 打通 解码→解压→按 index 读状态 全链
- 凭据状态枚举:`CredentialStatus`(Valid/Invalid/Suspended/ApplicationSpecific/Reserved)
- Token claims 校验:`StatusListTokenClaims.ensureValid`(exp/iat/sub)

## 复用(非自造密码学/压缩)
- 签名/Base64Url → `eudi_lib_core_crypto`(`Jws.verifyEs256` / `Base64Url`)
- CBOR(CWT)→ `eudi_lib_cbor`
- DEFLATE 解压 → `stdx.compress.zlib`
- HTTP 拉取 → `stdx.net.http`

## 依赖消费(external_repo_module)
clone 本仓到 `third_party/eudi_lib_statium`,并把 `eudi_lib_core_crypto` / `eudi_lib_cbor` 置于同级 `third_party/`(参见 project_blueprint 的 `integration_modes.external_repo_module`);消费方
`cjpm.toml [dependencies]` 加 `ohos_app_cangjie_eudi_cjstatium = { path = "../third_party/eudi_lib_statium/eudi_cjstatium" }`。

## 测试
entry 内含 27 个 `@Test` 类(OpenHarmonyTestRunner),覆盖全部公开接口,含 DEFLATE 真往返、CWT/JWT 解码、端到端 getStatus 链;模拟器 `aa test` 全过(ResultCode 0)。

> 逐函数对照 iOS 源迁移;iOS app target 通过 wallet-kit 间接消费本库。

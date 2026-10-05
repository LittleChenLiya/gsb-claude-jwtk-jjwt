# 显式 Key Locator 契约（Explicit Key Locator Contract）

`io.jsonwebtoken.impl.security.ExplicitKeyLocator` 实现了显式密钥定位契约：

- **kid 只用于候选定位**：`kid` 头参数只能用来“找到”候选密钥，本身不授权任何密钥或算法。
- **最终选择要求 key 类型与允许算法共同匹配**：候选唯一后，JWS `alg` 必须在该候选的显式
  允许列表中，且密钥类型类别必须与 `alg` 算法族一致。Header 无法指定任意降级算法。
- **同 kid 多候选歧义拒绝**：同一 `kid` 注册多个候选（例如两个不同类型密钥）时直接拒绝，
  不做任何猜测。
- **验签失败不猜其它算法**：定位器只返回唯一密钥、只对应 Header 中的 `alg`；验签失败后
  不会回退或重试其它（更弱）算法。
- **解析不读取磁盘密钥文件**：候选只接受内存中的 `java.security.Key` 实例，没有
  File/Path/InputStream/URL 等 API。
- **回执仅含选择类别**：`KeySelection` 只暴露选择类别（HMAC/RSA/EC/EDWARDS），不含密钥材料、
  kid 或 token 内容；异常信息也不包含 JWT compact 字符串。
- **默认单 key 接口保留**：`ExplicitKeyLocator.of(key, algs...)` 与解析器既有的
  `verifyWith(key)` 均不受影响。

## 选择表（Selection Table）

| # | kid 头 | 匹配候选数 | alg 在允许列表 | key 类型匹配 alg 族 | 结果 |
|---|--------|-----------|----------------|----------------------|------|
| 1 | 存在且唯一 | 1 | 是 | 是 | 选中该 key，回执记录类别 |
| 2 | 存在 | 0 | — | — | 拒绝：`No key candidate found` |
| 3 | 存在 | ≥2（含同 kid 不同类型） | — | — | 拒绝：`Ambiguous key location` |
| 4 | 缺失 | 1（唯一候选） | 是 | 是 | 选中该 key（默认单 key 场景） |
| 5 | 缺失 | ≥2 | — | — | 拒绝：`Ambiguous key location` |
| 6 | 唯一候选 | 1 | 否（禁用算法） | — | 拒绝：`not permitted`，不进入验签 |
| 7 | 唯一候选 | 1 | 是 | 否 | 拒绝：`does not match` |
| 8 | alg 缺失 / `none` / 未知族 | — | — | — | 拒绝：不进入验签 |
| 9 | 验签失败（签名被篡改） | — | — | — | `SignatureException`，仅定位 1 次，不回退弱算法 |

算法族映射：`HS*`→HMAC（SecretKey），`RS*`/`PS*`→RSA（RSAPublicKey），
`ES*`→EC（ECPublicKey），`EdDSA`→EDWARDS（Ed25519/Ed448/EdDSA 公钥）。
私钥一律拒绝注册为验签密钥。

## JUnit 命令

在本仓库根目录执行（仅需构建 api 与 impl 两个模块，只运行该契约的测试）：

```bash
mvn -pl impl -am test -Dtest=ExplicitKeyLocatorTest -Dsurefire.failIfNoSpecifiedTests=false
```

如需把本地仓库与临时目录定向到 D 盘（避免写 C 盘，本任务实际验证所用命令）：

```bash
export TEMP='D:\Codex\tmp-1007-051' TMP='D:\Codex\tmp-1007-051'
export MAVEN_OPTS='-Djava.io.tmpdir=D:/Codex/tmp-1007-051'
mvn -Dmaven.repo.local=D:/Codex/m2repo \
    -pl impl -am test -Dtest=ExplicitKeyLocatorTest \
    -Dsurefire.failIfNoSpecifiedTests=false \
    -Dlicense.skip=true -Dclover.skip=true -Dmaven.javadoc.skip=true \
    -Dgpg.skip=true -Djapicmp.skip=true
```

已验证结果：`Tests run: 10, Failures: 0, Errors: 0, Skipped: 0`。

测试类：`impl/src/test/groovy/io/jsonwebtoken/impl/security/ExplicitKeyLocatorTest.groovy`
（JUnit 4，覆盖上表全部 9 行场景及“token 不打印”“无磁盘密钥 API”约束）。

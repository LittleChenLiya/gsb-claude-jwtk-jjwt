# ExplicitKeyLocator：显式 Key Locator 契约

`io.jsonwebtoken.impl.security.ExplicitKeyLocator` 是一个失败即关闭（fail-closed）的 JWS 验签密钥定位器，实现以下显式契约：

1. **`kid` 只用于候选定位**：JWT Header 中的 `kid` 仅用于查找候选密钥（`KeyCandidate`），绝不影响算法选择。
2. **key 类型与允许算法必须共同匹配**：Header 的 `alg` 必须同时满足
   (a) 命中候选的显式允许算法集合，且 (b) 候选密钥的 `KeyCategory` 与该算法要求的类别一致。
   Header 不能为密钥指定任意（降级）算法；注册时类型与算法族不匹配的候选会被直接拒绝。
3. **同 `kid` 多候选歧义拒绝**：同一 `kid` 命中多于一个候选（即使是不同类型）时立即抛出
   `SecurityException`，不做任意取舍。
4. **验签失败不猜其它算法**：每个 Header 至多返回一个候选；验签失败后 locator 与 parser 均不会
   换用其它算法或密钥重试（`getLocateCount()` 每个 JWS 恰好 +1）。
5. **解析不读取磁盘密钥文件**：所有候选都是内存中的 `java.security.Key` 实例，locator 不进行任何
   文件系统、网络或 keystore I/O。
6. **回执仅含选择类别**：`getLastSelection()` 返回的 `KeySelection` 只暴露所选密钥的类别
   （`KeyCategory`），不包含密钥、密钥材料或 JWT 本身，可安全记录日志。
7. **默认单 key 接口保留**：`Jwts.parser().verifyWith(key)` 等既有单密钥接口行为不变；
   本 locator 是可选的增强，单 key 便捷构造为 `ExplicitKeyLocator.of(key, "HS256")`。

## 选择表（Selection Table）

| JWS `alg` 族 | 要求的 `KeyCategory` | 示例算法 | 合法密钥类型 |
|---|---|---|---|
| `HS*` | `OCT` | HS256 / HS384 / HS512 | `javax.crypto.SecretKey` |
| `RS*` | `RSA` | RS256 / RS384 / RS512 | `java.security.interfaces.RSAKey` |
| `PS*` | `RSA` | PS256 / PS384 / PS512 | `java.security.interfaces.RSAKey` |
| `ES*` | `EC` | ES256 / ES384 / ES512 | `java.security.interfaces.ECKey` |
| `EdDSA` | `OKP` | EdDSA（Ed25519 / Ed448） | Edwards 曲线密钥 |
| 其它/缺失 | —（拒绝） | `none`、空、未知 | 抛出异常，绝不猜测算法族 |

## 判定结果表

| 场景 | 行为 |
|---|---|
| `kid` 命中 0 个候选 | 返回 `null`，parser 抛出标准 `UnsupportedJwtException`（unable to locate） |
| `kid` 命中 ≥2 个候选（歧义） | 抛出 `SecurityException`（Ambiguous），不产生回执 |
| `alg` 不在候选允许集合（禁用算法） | 抛出 `SecurityException`（not permitted），**不进入验签** |
| 密钥类别与算法族不匹配 | 注册时抛 `IllegalArgumentException`；定位时兜底抛 `InvalidKeyException` |
| 类别与算法均匹配 | 返回唯一密钥，记录仅含类别的 `KeySelection` 回执 |
| 验签失败 | 抛出 `SignatureException`，**不回退**到其它（弱）算法，locate 次数恒为 1 |
| Header 缺少 `alg` | 抛出 `MalformedJwtException` |

所有异常信息与回执均不包含 token 内容或密钥材料。

## 用法示例

```java
SecretKey key = Jwts.SIG.HS256.key().build(); // 内存密钥
ExplicitKeyLocator locator = ExplicitKeyLocator.builder()
        .add("k1", key, "HS256")                 // kid 仅用于定位；仅允许 HS256
        .build();

Jws<Claims> jws = Jwts.parser()
        .keyLocator(locator)
        .build()
        .parseSignedClaims(token);

KeySelection receipt = locator.getLastSelection(); // 仅含类别，如 KeySelection{category=OCT}
```

## 验收测试（JUnit）

测试类：`impl/src/test/groovy/io/jsonwebtoken/impl/security/ExplicitKeyLocatorTest.groovy`
（JUnit 4，覆盖：同 kid 双候选拒绝、禁用算法不进入验签、内存密钥验签通过、token 不打印、
失败不回退弱算法、默认单 key 接口保留、类别映射）。

运行命令（在仓库根目录）：

```bash
mvn -pl impl -am test -Dtest=ExplicitKeyLocatorTest -Dsurefire.failIfNoSpecifiedTests=false
```

离线/本地缓存环境可追加：

```bash
mvn -o -Dmaven.repo.local=<本地仓库路径> -pl impl -am test \
    -Dtest=ExplicitKeyLocatorTest -Dsurefire.failIfNoSpecifiedTests=false
```

预期输出：`Tests run: 12, Failures: 0, Errors: 0, Skipped: 0`。

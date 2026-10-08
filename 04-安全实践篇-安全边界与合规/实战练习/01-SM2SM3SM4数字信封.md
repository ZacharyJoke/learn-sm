# 练习 01 SM2+SM3+SM4 数字信封

> 亲手实现「SM4 加密正文、SM2 包裹 DEK、SM3 摘要校验」的标准信封，并通过三处篡改观察系统在哪个点拒绝。

## 目标

- 定义统一的信封 JSON：`version / recipientKeyId / iv / encryptedKey / ciphertext / tag / digest`。
- 用 BouncyCastle（BC）轻量 API 完成封包（seal）与拆包（open）。
- 分别篡改 `ciphertext`、`encryptedKey`、`digest` 各一次，观察并记录拒绝点。
- 验收：正常往返明文一致；三类篡改全部被拒绝。

## 前置

- JDK 17、Maven 3.8+；无需任何外部服务。
- 密钥对在程序启动时用安全随机源动态生成（**不写入任何固定密钥**）；DEK 一次一密。
- 新建 Maven 工程 `gm-envelope-lab`，`pom.xml` 关键依赖（版本可替换为更新的稳定版）：

```xml
<properties>
  <maven.compiler.source>17</maven.compiler.source>
  <maven.compiler.target>17</maven.compiler.target>
  <bouncycastle.version>1.78</bouncycastle.version>
  <jackson.version>2.17.2</jackson.version>
</properties>

<dependencies>
  <dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>${bouncycastle.version}</version>
  </dependency>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>${jackson.version}</version>
  </dependency>
</dependencies>
```

## 路径

```text
gm-envelope-lab/
├── pom.xml
└── src/main/java/com/example/envelope/
    ├── EnvelopeData.java        # 信封 JSON 结构
    ├── DigitalEnvelope.java     # seal / open 核心逻辑
    └── EnvelopeDemo.java        # main：正常往返 + 三次篡改实验
```

## 步骤

### 1. 注册 BC 并定义信封结构

`EnvelopeData.java`：

```java
package com.example.envelope;

public final class EnvelopeData {
    public String version;
    public String recipientKeyId;
    public String iv;
    public String encryptedKey;
    public String ciphertext;
    public String tag;
    public String digest;

    public EnvelopeData() {
    }
}
```

### 2. 实现封包与拆包

`DigitalEnvelope.java`：

```java
package com.example.envelope;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public final class DigitalEnvelope {

    private static final int DEK_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private final SecureRandom random = new SecureRandom();

    public EnvelopeData seal(byte[] plaintext,
                             String recipientKeyId,
                             ECPublicKeyParameters recipientPublicKey) {
        byte[] dek = new byte[DEK_LENGTH];
        random.nextBytes(dek);
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);

        GCMBlockCipher encryptor = new GCMBlockCipher(new SM4Engine());
        encryptor.init(true, new AEADParameters(new KeyParameter(dek), TAG_BITS, iv, null));
        byte[] ciphertext = new byte[encryptor.getOutputSize(plaintext.length)];
        int length = encryptor.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
        try {
            length += encryptor.doFinal(ciphertext, length);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("SM4-GCM encryption failed", e);
        }
        byte[] tag = encryptor.getMac();

        SM2Engine sm2 = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2.init(true, new ParametersWithRandom(recipientPublicKey, random));
        byte[] encryptedKey;
        try {
            encryptedKey = sm2.processBlock(dek, 0, dek.length);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("SM2 key wrap failed", e);
        }

        EnvelopeData envelope = new EnvelopeData();
        envelope.version = "1.0";
        envelope.recipientKeyId = recipientKeyId;
        envelope.iv = Base64.getEncoder().encodeToString(iv);
        envelope.encryptedKey = Base64.getEncoder().encodeToString(encryptedKey);
        envelope.ciphertext = Base64.getEncoder()
                .encodeToString(java.util.Arrays.copyOf(ciphertext, length));
        envelope.tag = Base64.getEncoder().encodeToString(tag);
        envelope.digest = Hex.encode(sm3(plaintext));
        return envelope;
    }

    public byte[] open(EnvelopeData envelope, ECPrivateKeyParameters recipientPrivateKey) {
        byte[] encryptedKey = Base64.getDecoder().decode(envelope.encryptedKey);
        SM2Engine sm2 = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2.init(false, recipientPrivateKey);
        byte[] dek;
        try {
            dek = sm2.processBlock(encryptedKey, 0, encryptedKey.length);
        } catch (InvalidCipherTextException e) {
            throw new EnvelopeException("UNWRAP_DEK",
                    "SM2 解密 DEK 失败：encryptedKey 被篡改或私钥不匹配", e);
        }

        byte[] iv = Base64.getDecoder().decode(envelope.iv);
        byte[] ciphertext = Base64.getDecoder().decode(envelope.ciphertext);

        GCMBlockCipher decryptor = new GCMBlockCipher(new SM4Engine());
        decryptor.init(false, new AEADParameters(new KeyParameter(dek), TAG_BITS, iv, null));
        byte[] plaintext = new byte[decryptor.getOutputSize(ciphertext.length)];
        int length = decryptor.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
        try {
            length += decryptor.doFinal(plaintext, length);
        } catch (InvalidCipherTextException e) {
            throw new EnvelopeException("VERIFY_TAG",
                    "SM4-GCM 校验失败：ciphertext 或 tag 被篡改", e);
        }

        byte[] actual = sm3(plaintext);
        if (!Hex.encode(actual).equals(envelope.digest)) {
            throw new EnvelopeException("VERIFY_DIGEST",
                    "SM3 摘要不一致：digest 字段被篡改或数据损坏");
        }

        byte[] result = new byte[length];
        System.arraycopy(plaintext, 0, result, 0, length);
        return result;
    }

    private static byte[] sm3(byte[] input) {
        SM3Digest digest = new SM3Digest();
        digest.update(input, 0, input.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    public static final class EnvelopeException extends RuntimeException {
        private final String stage;

        public EnvelopeException(String stage, String message, Throwable cause) {
            super(message, cause);
            this.stage = stage;
        }

        public EnvelopeException(String stage, String message) {
            super(message);
            this.stage = stage;
        }

        public String stage() {
            return stage;
        }
    }
}
```

### 3. 小工具：Hex 编码

`Hex.java`（同包）：

```java
package com.example.envelope;

public final class Hex {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[i * 2] = HEX[(bytes[i] >> 4) & 0x0F];
            out[i * 2 + 1] = HEX[bytes[i] & 0x0F];
        }
        return new String(out);
    }
}
```

### 4. 演示：正常往返 + 三次篡改

`EnvelopeDemo.java`：

```java
package com.example.envelope;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Consumer;

public class EnvelopeDemo {

    public static void main(String[] args) throws Exception {
        ECDomainParameters sm2Domain = sm2Domain();
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(sm2Domain, new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECPublicKeyParameters recipientPublic = (ECPublicKeyParameters) keyPair.getPublic();
        ECPrivateKeyParameters recipientPrivate = (ECPrivateKeyParameters) keyPair.getPrivate();

        DigitalEnvelope envelopeService = new DigitalEnvelope();
        ObjectMapper mapper = new ObjectMapper();
        byte[] message = "转账：from=A，to=B，amount=100.00".getBytes(StandardCharsets.UTF_8);

        EnvelopeData sealed = envelopeService.seal(message, "sm2-key-2026-01", recipientPublic);
        System.out.println("=== 信封 JSON ===");
        System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(sealed));

        byte[] opened = envelopeService.open(sealed, recipientPrivate);
        System.out.println("=== 正常拆包 ===");
        System.out.println(new String(opened, StandardCharsets.UTF_8));
        System.out.println("往返一致：" + java.util.Arrays.equals(message, opened));

        tamper("ciphertext", sealed, mapper, envelopeService, recipientPrivate, env -> {
            byte[] raw = Base64.getDecoder().decode(env.ciphertext);
            raw[0] ^= 0x01;
            env.ciphertext = Base64.getEncoder().encodeToString(raw);
        });

        tamper("encryptedKey", sealed, mapper, envelopeService, recipientPrivate, env -> {
            byte[] raw = Base64.getDecoder().decode(env.encryptedKey);
            raw[raw.length - 1] ^= 0x01;
            env.encryptedKey = Base64.getEncoder().encodeToString(raw);
        });

        tamper("digest", sealed, mapper, envelopeService, recipientPrivate, env -> {
            char first = env.digest.charAt(0);
            char replaced = first == '0' ? '1' : '0';
            env.digest = replaced + env.digest.substring(1);
        });
    }

    private static void tamper(String field,
                               EnvelopeData original,
                               ObjectMapper mapper,
                               DigitalEnvelope service,
                               ECPrivateKeyParameters privateKey,
                               Consumer<EnvelopeData> mutation) throws Exception {
        EnvelopeData copy = mapper.readValue(mapper.writeValueAsString(original), EnvelopeData.class);
        mutation.accept(copy);
        System.out.println("=== 篡改 " + field + " ===");
        try {
            service.open(copy, privateKey);
            System.out.println("危险：篡改未被发现！");
        } catch (DigitalEnvelope.EnvelopeException e) {
            System.out.println("已拒绝，拒绝点：" + e.stage() + "，原因：" + e.getMessage());
        }
    }

    private static ECDomainParameters sm2Domain() {
        var parameters = CustomNamedCurves.getByName("sm2p256v1");
        return new ECDomainParameters(parameters.getCurve(), parameters.getG(),
                parameters.getN(), parameters.getH());
    }
}
```

说明：`tamper` 方法先深拷贝信封、对**复制件**做篡改，保证三次实验互不影响；曲线参数类使用 `org.bouncycastle.crypto.ec.CustomNamedCurves`。若希望直接用 `mvn exec:java` 运行，可在 `pom.xml` 增加插件：

```xml
<build>
  <plugins>
    <plugin>
      <groupId>org.codehaus.mojo</groupId>
      <artifactId>exec-maven-plugin</artifactId>
      <version>3.2.0</version>
    </plugin>
  </plugins>
</build>
```

## 执行命令

```bash
mvn -q compile exec:java -Dexec.mainClass=com.example.envelope.EnvelopeDemo
```

## 预期输出

```text
=== 信封 JSON ===
{ "version" : "1.0", "recipientKeyId" : "sm2-key-2026-01", "iv" : "...", ... }
=== 正常拆包 ===
转账：from=A，to=B，amount=100.00
往返一致：true
=== 篡改 ciphertext ===
已拒绝，拒绝点：VERIFY_TAG，原因：SM4-GCM 校验失败：ciphertext 或 tag 被篡改
=== 篡改 encryptedKey ===
已拒绝，拒绝点：UNWRAP_DEK，原因：SM2 解密 DEK 失败：encryptedKey 被篡改或私钥不匹配
=== 篡改 digest ===
已拒绝，拒绝点：VERIFY_DIGEST，原因：SM3 摘要不一致：digest 字段被篡改或数据损坏
```

## 验收标准

- 正常封包 / 拆包后明文与原文逐字节一致，输出 `往返一致：true`。
- 篡改 `ciphertext` → 在 `VERIFY_TAG` 被拒绝。
- 篡改 `encryptedKey` → 在 `UNWRAP_DEK` 被拒绝。
- 篡改 `digest` → 在 `VERIFY_DIGEST` 被拒绝。
- 代码与配置中无任何固定密钥 / 固定 IV；DEK、IV 均由 `SecureRandom` 生成；SM2 密文为 C1C3C2。

## 扩展思考

- 当前 `digest` 只是明文摘要，若信封被中间人整体替换，攻击者可连 `digest` 一起伪造。生产环境应增加 `signature` 字段：发送方用自己的 SM2 私钥对 `SM3(密文或明文)` 签名，接收方按发送方证书验签。
- `recipientKeyId` 现在只是展示字段；接入 KMS 后应用它路由到对应版本的私钥，支持密钥轮换（见练习 04）。
- 若改 SM2 用户 ID（默认 `1234567812345678`），需双方显式约定；本练习信封的 SM2 加密不依赖用户 ID，签名才依赖。
- 大文件场景应流式处理：SM3 流式摘要、SM4-GCM 分块更新，避免全文驻留内存。

## 失败排查

| 现象 | 可能原因 | 处理 |
|------|---------|------|
| `NoSuchAlgorithmException: SM4/GCM/NoPadding` | BC 未注册或版本不含国密 | 确认 `bcprov-jdk18on` 已引入；本练习用轻量 API 不依赖静态注册，但建议 `Security.addProvider(new BouncyCastleProvider())` |
| 解密抛 InvalidCipherTextException | C1C2C3 / C1C3C2 不匹配 | 双方统一 `SM2Engine.Mode.C1C3C2` |
| tag 校验总失败 | IV 或 tag Base64 解码错误 | 打印各字段长度：IV 12 字节、tag 16 字节 |
| `CustomNamedCurves` 找不到 | import 写错或 BC 版本过老 | 用 `org.bouncycastle.crypto.ec.CustomNamedCurves`，升级 BC |
| 编译报 cannot find symbol | import 拼写错误 | 按编译器提示核对包名，BC 类以实际版本 API 为准 |

## 完成检查

- [ ] 能解释信封中每个字段由谁产生、在拆包哪一步使用。
- [ ] 三次篡改实验全部按预期拒绝点失败。
- [ ] 向同事讲清：为什么 DEK 用一次就扔、SM2 为什么只包密钥。
- [ ] 已记录一个生产化改造点：增加发送方签名字段。

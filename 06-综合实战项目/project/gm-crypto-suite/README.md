# gm-crypto-suite

基于 Spring Boot 3 + BouncyCastle 的国密（SM2/SM3/SM4）能力组件工程，作为团队 `crypto-common`/SDK 的参考起点。

## 能力

- SM2：密钥对生成、SM3withSM2 签名验签（含用户 ID 绑定）、C1C3C2 加解密、PEM 读写
- SM3：字节/流式摘要、HMAC-SM3
- SM4：GCM（默认，AEAD）与 CBC 模式，IV/Nonce 随机
- 数字信封：SM4 加密正文、SM2 包裹 DEK、SM3 校验摘要
- 接口签名验签：`X-App-Id/X-Timestamp/X-Nonce/X-Signature`，防篡改、防重放
- 静态审计：ECB、弱随机数、硬编码十六进制、内嵌私钥等规则

## 环境

- JDK 17+（JDK 21 实测）
- Maven 3.8+
- BouncyCastle `bcprov-jdk18on`（版本见 `pom.xml`）

## 构建与测试

```bash
mvn test
```

测试包含 SM3/SM4 国家标准向量、信封三类篡改拒绝、签名拦截器负向用例。

## 启动

```bash
mvn spring-boot:run
```

信封演示：

```bash
curl -s -X POST http://localhost:8080/api/demo/envelope \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"hello"}'
```

## 安全说明

示例密钥均由 `SecureRandom` 运行期生成；生产环境请将密钥材料替换为 KMS/HSM 注入，禁止把真实密钥写入配置或代码。

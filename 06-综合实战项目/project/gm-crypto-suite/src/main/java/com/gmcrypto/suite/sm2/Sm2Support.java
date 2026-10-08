package com.gmcrypto.suite.sm2;

import com.gmcrypto.suite.codec.Codec;
import com.gmcrypto.suite.common.ErrorCode;
import com.gmcrypto.suite.common.GmCryptoException;
import com.gmcrypto.suite.random.RandomUtils;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class Sm2Support {

    public static final String CURVE_NAME = "sm2p256v1";
    public static final byte[] DEFAULT_USER_ID = "1234567812345678".getBytes(StandardCharsets.UTF_8);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private Sm2Support() {
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            generator.initialize(new org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec(CURVE_NAME), RandomUtils.secureRandom());
            return generator.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.ALGORITHM_UNAVAILABLE, "SM2 密钥对生成失败", e);
        }
    }

    public static byte[] sign(PrivateKey privateKey, byte[] message) {
        return sign(privateKey, message, DEFAULT_USER_ID);
    }

    public static byte[] sign(PrivateKey privateKey, byte[] message, byte[] userId) {
        try {
            Signature signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
            signature.setParameter(new SM2ParameterSpec(userId));
            signature.initSign(privateKey);
            signature.update(message == null ? new byte[0] : message);
            return signature.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.SIGNATURE_INVALID, "SM2 签名失败", e);
        }
    }

    public static boolean verify(PublicKey publicKey, byte[] message, byte[] signatureValue) {
        return verify(publicKey, message, signatureValue, DEFAULT_USER_ID);
    }

    public static boolean verify(PublicKey publicKey, byte[] message, byte[] signatureValue, byte[] userId) {
        try {
            Signature signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
            signature.setParameter(new SM2ParameterSpec(userId));
            signature.initVerify(publicKey);
            signature.update(message == null ? new byte[0] : message);
            return signature.verify(signatureValue);
        } catch (java.security.GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.SIGNATURE_INVALID, "SM2 验签失败", e);
        }
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("SM2", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, RandomUtils.secureRandom());
            return cipher.doFinal(plaintext);
        } catch (java.security.GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.ENCRYPTION_FAILED, "SM2 加密失败", e);
        }
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("SM2", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(ciphertext);
        } catch (java.security.GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.DECRYPTION_FAILED, "SM2 解密失败", e);
        }
    }

    public static PublicKey loadPublicKey(byte[] der) {
        try {
            return KeyFactory.getInstance("EC", new BouncyCastleProvider())
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (java.security.GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.INVALID_KEY, "SM2 公钥加载失败", e);
        }
    }

    public static PrivateKey loadPrivateKey(byte[] der) {
        try {
            return KeyFactory.getInstance("EC", new BouncyCastleProvider())
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (java.security.GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.INVALID_KEY, "SM2 私钥加载失败", e);
        }
    }

    public static String publicKeyToPem(PublicKey publicKey) {
        return toPem("PUBLIC KEY", publicKey.getEncoded());
    }

    public static String privateKeyToPem(PrivateKey privateKey) {
        return toPem("PRIVATE KEY", privateKey.getEncoded());
    }

    public static PublicKey pemToPublicKey(String pem) {
        return loadPublicKey(fromPem(pem));
    }

    public static PrivateKey pemToPrivateKey(String pem) {
        return loadPrivateKey(fromPem(pem));
    }

    private static String toPem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    private static byte[] fromPem(String pem) {
        String body = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s", "");
        return Codec.fromBase64(body);
    }
}

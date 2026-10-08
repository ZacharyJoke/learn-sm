package com.gmcrypto.suite.sm4;

import com.gmcrypto.suite.common.ErrorCode;
import com.gmcrypto.suite.common.GmCryptoException;
import com.gmcrypto.suite.random.RandomUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public final class Sm4Support {

    public static final String ALGORITHM = "SM4";
    public static final int KEY_SIZE_BYTES = 16;
    public static final int GCM_NONCE_BYTES = 12;
    public static final int GCM_TAG_BITS = 128;
    public static final int CBC_IV_BYTES = 16;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private Sm4Support() {
    }

    public static byte[] generateKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM, new BouncyCastleProvider());
            generator.init(128);
            return generator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new GmCryptoException(ErrorCode.ALGORITHM_UNAVAILABLE, "SM4 密钥生成器不可用", e);
        }
    }

    public static Sm4Payload gcmEncrypt(byte[] key, byte[] plaintext, byte[] aad) {
        validateKey(key);
        byte[] nonce = RandomUtils.randomBytes(GCM_NONCE_BYTES);
        try {
            Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, toKey(key), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            byte[] ciphertextWithTag = cipher.doFinal(plaintext);
            int tagBytes = GCM_TAG_BITS / 8;
            int ciphertextLength = ciphertextWithTag.length - tagBytes;
            byte[] ciphertext = new byte[ciphertextLength];
            byte[] tag = new byte[tagBytes];
            System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
            System.arraycopy(ciphertextWithTag, ciphertextLength, tag, 0, tagBytes);
            return new Sm4Payload(nonce, ciphertext, tag);
        } catch (GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.ENCRYPTION_FAILED, "SM4-GCM 加密失败", e);
        }
    }

    public static byte[] gcmDecrypt(byte[] key, Sm4Payload payload, byte[] aad) {
        validateKey(key);
        try {
            Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, toKey(key), new GCMParameterSpec(GCM_TAG_BITS, payload.iv()));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            byte[] ciphertextWithTag = new byte[payload.ciphertext().length + payload.tag().length];
            System.arraycopy(payload.ciphertext(), 0, ciphertextWithTag, 0, payload.ciphertext().length);
            System.arraycopy(payload.tag(), 0, ciphertextWithTag, payload.ciphertext().length, payload.tag().length);
            return cipher.doFinal(ciphertextWithTag);
        } catch (GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.DECRYPTION_FAILED, "SM4-GCM 解密或完整性校验失败", e);
        }
    }

    public static Sm4Payload cbcEncrypt(byte[] key, byte[] plaintext) {
        validateKey(key);
        byte[] iv = RandomUtils.randomBytes(CBC_IV_BYTES);
        try {
            Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, toKey(key), new IvParameterSpec(iv));
            return new Sm4Payload(iv, cipher.doFinal(plaintext), null);
        } catch (GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.ENCRYPTION_FAILED, "SM4-CBC 加密失败", e);
        }
    }

    public static byte[] cbcDecrypt(byte[] key, Sm4Payload payload) {
        validateKey(key);
        try {
            Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, toKey(key), new IvParameterSpec(payload.iv()));
            return cipher.doFinal(payload.ciphertext());
        } catch (GeneralSecurityException e) {
            throw new GmCryptoException(ErrorCode.DECRYPTION_FAILED, "SM4-CBC 解密失败", e);
        }
    }

    private static Key toKey(byte[] key) {
        return new SecretKeySpec(key, ALGORITHM);
    }

    private static void validateKey(byte[] key) {
        if (key == null || key.length != KEY_SIZE_BYTES) {
            throw new GmCryptoException(ErrorCode.INVALID_KEY, "SM4 密钥必须为 16 字节");
        }
    }
}

package com.gmcrypto.suite.sm3;

import com.gmcrypto.suite.common.ErrorCode;
import com.gmcrypto.suite.common.GmCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public final class Sm3Support {

    private static final String ALGORITHM = "SM3";
    private static final int BUFFER_SIZE = 8192;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private Sm3Support() {
    }

    public static byte[] digest(byte[] message) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM, new BouncyCastleProvider());
            return digest.digest(message);
        } catch (NoSuchAlgorithmException e) {
            throw new GmCryptoException(ErrorCode.ALGORITHM_UNAVAILABLE, "SM3 不可用", e);
        }
    }

    public static byte[] digest(InputStream inputStream) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM, new BouncyCastleProvider());
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new GmCryptoException(ErrorCode.ALGORITHM_UNAVAILABLE, "SM3 流式摘要失败", e);
        }
    }

    public static byte[] hmac(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HMAC-SM3", new BouncyCastleProvider());
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HMAC-SM3"));
            return mac.doFinal(message);
        } catch (NoSuchAlgorithmException e) {
            throw new GmCryptoException(ErrorCode.ALGORITHM_UNAVAILABLE, "HMAC-SM3 不可用", e);
        } catch (java.security.InvalidKeyException e) {
            throw new GmCryptoException(ErrorCode.INVALID_KEY, "HMAC-SM3 密钥无效", e);
        }
    }
}

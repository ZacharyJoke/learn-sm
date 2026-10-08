package com.gmcrypto.suite.sm4;

import com.gmcrypto.suite.codec.Codec;
import com.gmcrypto.suite.common.GmCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Sm4SupportTest {

    private static final String VECTOR_HEX = "0123456789abcdeffedcba9876543210";
    private static final String VECTOR_CIPHERTEXT = "681edf34d206965e86b3e94f536e4246";

    @Test
    void ecbStandardVector() throws Exception {
        byte[] key = Codec.fromHex(VECTOR_HEX);
        byte[] plaintext = Codec.fromHex(VECTOR_HEX);
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"));
        assertArrayEquals(Codec.fromHex(VECTOR_CIPHERTEXT), cipher.doFinal(plaintext));
    }

    @Test
    void gcmRoundTrip() {
        byte[] key = Sm4Support.generateKey();
        byte[] plaintext = Codec.utf8("国密 SM4-GCM 测试数据");
        byte[] aad = Codec.utf8("key-v1");
        Sm4Payload payload = Sm4Support.gcmEncrypt(key, plaintext, aad);
        assertArrayEquals(plaintext, Sm4Support.gcmDecrypt(key, payload, aad));
    }

    @Test
    void gcmTamperDetected() {
        byte[] key = Sm4Support.generateKey();
        Sm4Payload payload = Sm4Support.gcmEncrypt(key, Codec.utf8("secret"), null);
        payload.ciphertext()[0] ^= 1;
        assertThrows(GmCryptoException.class, () -> Sm4Support.gcmDecrypt(key, payload, null));
    }

    @Test
    void cbcRoundTrip() {
        byte[] key = Sm4Support.generateKey();
        byte[] plaintext = new byte[100];
        Arrays.fill(plaintext, (byte) 7);
        Sm4Payload payload = Sm4Support.cbcEncrypt(key, plaintext);
        assertArrayEquals(plaintext, Sm4Support.cbcDecrypt(key, payload));
    }
}

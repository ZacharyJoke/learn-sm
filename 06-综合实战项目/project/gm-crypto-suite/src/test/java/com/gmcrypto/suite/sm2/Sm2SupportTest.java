package com.gmcrypto.suite.sm2;

import com.gmcrypto.suite.codec.Codec;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Sm2SupportTest {

    @Test
    void signAndVerify() {
        KeyPair keyPair = Sm2Support.generateKeyPair();
        byte[] message = Codec.utf8("hello sm2");
        byte[] signatureValue = Sm2Support.sign(keyPair.getPrivate(), message);
        assertTrue(Sm2Support.verify(keyPair.getPublic(), message, signatureValue));
    }

    @Test
    void tamperedMessageRejected() {
        KeyPair keyPair = Sm2Support.generateKeyPair();
        byte[] signatureValue = Sm2Support.sign(keyPair.getPrivate(), Codec.utf8("original"));
        assertFalse(Sm2Support.verify(keyPair.getPublic(), Codec.utf8("tampered"), signatureValue));
    }

    @Test
    void mismatchedUserIdRejected() {
        KeyPair keyPair = Sm2Support.generateKeyPair();
        byte[] message = Codec.utf8("user binding");
        byte[] signatureValue = Sm2Support.sign(keyPair.getPrivate(), message, Sm2Support.DEFAULT_USER_ID);
        assertFalse(Sm2Support.verify(keyPair.getPublic(), message, signatureValue,
                "8765432187654321".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void encryptAndDecrypt() {
        KeyPair keyPair = Sm2Support.generateKeyPair();
        byte[] plaintext = Codec.utf8("数字信封中的短数据");
        byte[] ciphertext = Sm2Support.encrypt(keyPair.getPublic(), plaintext);
        assertArrayEquals(plaintext, Sm2Support.decrypt(keyPair.getPrivate(), ciphertext));
    }

    @Test
    void pemRoundTrip() {
        KeyPair keyPair = Sm2Support.generateKeyPair();
        String publicPem = Sm2Support.publicKeyToPem(keyPair.getPublic());
        String privatePem = Sm2Support.privateKeyToPem(keyPair.getPrivate());
        byte[] message = Codec.utf8("pem");
        byte[] signatureValue = Sm2Support.sign(Sm2Support.pemToPrivateKey(privatePem), message);
        assertTrue(Sm2Support.verify(Sm2Support.pemToPublicKey(publicPem), message, signatureValue));
    }
}

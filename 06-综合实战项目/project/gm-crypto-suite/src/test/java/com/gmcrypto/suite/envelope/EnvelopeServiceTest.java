package com.gmcrypto.suite.envelope;

import com.gmcrypto.suite.codec.Codec;
import com.gmcrypto.suite.common.ErrorCode;
import com.gmcrypto.suite.common.GmCryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EnvelopeServiceTest {

    private EnvelopeService envelopeService;
    private KeyPair recipient;

    @BeforeEach
    void setUp() {
        envelopeService = new EnvelopeService();
        recipient = com.gmcrypto.suite.sm2.Sm2Support.generateKeyPair();
    }

    @Test
    void sealAndOpen() {
        byte[] plaintext = Codec.utf8("信封正文 confidential");
        EnvelopeData envelope = envelopeService.seal(recipient.getPublic(), "rk-1", "s-1", plaintext);
        assertEquals(new String(plaintext), new String(envelopeService.open(recipient.getPrivate(), envelope)));
    }

    @Test
    void tamperedCiphertextRejected() {
        EnvelopeData envelope = envelopeService.seal(recipient.getPublic(), "rk-1", "s-1", Codec.utf8("data"));
        byte[] ciphertext = Codec.fromBase64(envelope.ciphertext());
        ciphertext[0] ^= 1;
        EnvelopeData modified = new EnvelopeData(envelope.version(), envelope.recipientKeyId(),
                envelope.senderKeyId(), envelope.iv(), envelope.encryptedKey(),
                Codec.toBase64(ciphertext), envelope.tag(), envelope.digest());
        assertThrows(GmCryptoException.class,
                () -> envelopeService.open(recipient.getPrivate(), modified));
    }

    @Test
    void tamperedEncryptedKeyRejected() {
        EnvelopeData envelope = envelopeService.seal(recipient.getPublic(), "rk-1", "s-1", Codec.utf8("data"));
        byte[] encryptedKey = Codec.fromBase64(envelope.encryptedKey());
        encryptedKey[1] ^= 1;
        EnvelopeData modified = new EnvelopeData(envelope.version(), envelope.recipientKeyId(),
                envelope.senderKeyId(), envelope.iv(), Codec.toBase64(encryptedKey),
                envelope.ciphertext(), envelope.tag(), envelope.digest());
        assertThrows(GmCryptoException.class,
                () -> envelopeService.open(recipient.getPrivate(), modified));
    }

    @Test
    void tamperedDigestRejected() {
        EnvelopeData envelope = envelopeService.seal(recipient.getPublic(), "rk-1", "s-1", Codec.utf8("data"));
        EnvelopeData modified = new EnvelopeData(envelope.version(), envelope.recipientKeyId(),
                envelope.senderKeyId(), envelope.iv(), envelope.encryptedKey(),
                envelope.ciphertext(), envelope.tag(), "0".repeat(64));
        GmCryptoException exception = assertThrows(GmCryptoException.class,
                () -> envelopeService.open(recipient.getPrivate(), modified));
        assertEquals(ErrorCode.INTEGRITY_CHECK_FAILED, exception.getErrorCode());
    }
}

package com.gmcrypto.suite.envelope;

import com.gmcrypto.suite.codec.Codec;
import com.gmcrypto.suite.common.ErrorCode;
import com.gmcrypto.suite.common.GmCryptoException;
import com.gmcrypto.suite.sm3.Sm3Support;
import com.gmcrypto.suite.sm4.Sm4Payload;
import com.gmcrypto.suite.sm4.Sm4Support;
import com.gmcrypto.suite.sm2.Sm2Support;

import java.security.PrivateKey;
import java.security.PublicKey;

public class EnvelopeService {

    private static final int VERSION = 1;

    public EnvelopeData seal(PublicKey recipientKey, String recipientKeyId, String senderKeyId, byte[] plaintext) {
        byte[] dek = Sm4Support.generateKey();
        byte[] aad = Codec.utf8(recipientKeyId);
        Sm4Payload payload = Sm4Support.gcmEncrypt(dek, plaintext, aad);
        byte[] encryptedDek = Sm2Support.encrypt(recipientKey, dek);
        String digest = Codec.toHex(Sm3Support.digest(plaintext));
        return new EnvelopeData(
                VERSION,
                recipientKeyId,
                senderKeyId,
                Codec.toBase64(payload.iv()),
                Codec.toBase64(encryptedDek),
                Codec.toBase64(payload.ciphertext()),
                Codec.toBase64(payload.tag()),
                digest
        );
    }

    public byte[] open(PrivateKey recipientKey, EnvelopeData envelope) {
        byte[] dek = Sm2Support.decrypt(recipientKey, Codec.fromBase64(envelope.encryptedKey()));
        Sm4Payload payload = new Sm4Payload(
                Codec.fromBase64(envelope.iv()),
                Codec.fromBase64(envelope.ciphertext()),
                Codec.fromBase64(envelope.tag())
        );
        byte[] plaintext = Sm4Support.gcmDecrypt(dek, payload, Codec.utf8(envelope.recipientKeyId()));
        String actualDigest = Codec.toHex(Sm3Support.digest(plaintext));
        if (!actualDigest.equals(envelope.digest())) {
            throw new GmCryptoException(ErrorCode.INTEGRITY_CHECK_FAILED, "信封摘要不一致");
        }
        return plaintext;
    }
}

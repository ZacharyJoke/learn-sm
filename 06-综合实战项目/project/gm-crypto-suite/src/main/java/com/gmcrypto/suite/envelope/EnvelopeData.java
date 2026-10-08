package com.gmcrypto.suite.envelope;

public record EnvelopeData(
        int version,
        String recipientKeyId,
        String senderKeyId,
        String iv,
        String encryptedKey,
        String ciphertext,
        String tag,
        String digest
) {
}

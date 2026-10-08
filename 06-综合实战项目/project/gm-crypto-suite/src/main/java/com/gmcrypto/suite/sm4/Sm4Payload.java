package com.gmcrypto.suite.sm4;

public record Sm4Payload(byte[] iv, byte[] ciphertext, byte[] tag) {

    public boolean isGcm() {
        return tag != null;
    }
}

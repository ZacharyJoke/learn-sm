package com.gmcrypto.suite.web;

import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AppKeyResolver {

    private final Map<String, PublicKey> directory = new ConcurrentHashMap<>();

    public void register(String appId, PublicKey publicKey) {
        directory.put(appId, publicKey);
    }

    public PublicKey resolve(String appId) {
        PublicKey publicKey = directory.get(appId);
        if (publicKey == null) {
            throw new com.gmcrypto.suite.common.GmCryptoException(
                    com.gmcrypto.suite.common.ErrorCode.INVALID_PARAMETER, "未知 appId: " + appId);
        }
        return publicKey;
    }
}

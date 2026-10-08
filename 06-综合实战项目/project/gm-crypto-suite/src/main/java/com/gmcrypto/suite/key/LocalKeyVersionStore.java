package com.gmcrypto.suite.key;

import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class LocalKeyVersionStore implements KeyVersionStore {

    private final Map<String, ManagedKey> keys = new ConcurrentHashMap<>();

    @Override
    public ManagedKey register(String algorithm) {
        String id = UUID.randomUUID().toString();
        KeyPair keyPair = switch (algorithm) {
            case "SM2" -> com.gmcrypto.suite.sm2.Sm2Support.generateKeyPair();
            default -> throw new IllegalArgumentException("不支持的算法: " + algorithm);
        };
        ManagedKey managedKey = new ManagedKey(new KeyVersion(id, algorithm, KeyStatus.ACTIVE, Instant.now()), keyPair);
        keys.put(id, managedKey);
        return managedKey;
    }

    @Override
    public ManagedKey get(String id) {
        ManagedKey managedKey = keys.get(id);
        if (managedKey == null) {
            throw new com.gmcrypto.suite.common.GmCryptoException(
                    com.gmcrypto.suite.common.ErrorCode.KEY_NOT_FOUND, "密钥不存在: " + id);
        }
        return managedKey;
    }

    @Override
    public List<ManagedKey> list() {
        return List.copyOf(keys.values());
    }

    @Override
    public void markStatus(String id, KeyStatus status) {
        keys.computeIfPresent(id, (keyId, managedKey) -> new ManagedKey(
                new KeyVersion(managedKey.version().id(), managedKey.version().algorithm(), status,
                        managedKey.version().createdAt()),
                managedKey.keyPair()));
    }
}

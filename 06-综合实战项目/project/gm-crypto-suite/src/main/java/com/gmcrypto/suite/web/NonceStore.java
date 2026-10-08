package com.gmcrypto.suite.web;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class NonceStore {

    private final Map<String, Instant> expiresAt = new ConcurrentHashMap<>();

    public boolean registerIfAbsent(String nonce, Duration ttl) {
        prune();
        Instant now = Instant.now();
        return expiresAt.putIfAbsent(nonce, now.plus(ttl)) == null;
    }

    private void prune() {
        Instant now = Instant.now();
        expiresAt.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }
}

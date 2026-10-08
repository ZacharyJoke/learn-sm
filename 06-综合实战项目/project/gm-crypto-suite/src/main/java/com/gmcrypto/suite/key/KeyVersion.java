package com.gmcrypto.suite.key;

import java.time.Instant;

public record KeyVersion(String id, String algorithm, KeyStatus status, Instant createdAt) {
}

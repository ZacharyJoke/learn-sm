package com.gmcrypto.suite.key;

import java.security.KeyPair;

public record ManagedKey(KeyVersion version, KeyPair keyPair) {
}

package com.gmcrypto.suite.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class RandomUtils {

    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private RandomUtils() {
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static SecureRandom secureRandom() {
        return SECURE_RANDOM;
    }
}

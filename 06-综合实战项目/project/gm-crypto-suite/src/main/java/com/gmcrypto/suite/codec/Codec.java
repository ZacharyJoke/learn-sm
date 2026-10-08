package com.gmcrypto.suite.codec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

public final class Codec {

    private static final HexFormat HEX = HexFormat.of();

    private Codec() {
    }

    public static String toHex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    public static byte[] fromHex(String hex) {
        return HEX.parseHex(hex);
    }

    public static String toBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    public static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    public static String utf8(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}

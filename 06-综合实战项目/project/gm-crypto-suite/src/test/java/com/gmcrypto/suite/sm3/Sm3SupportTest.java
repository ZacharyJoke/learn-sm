package com.gmcrypto.suite.sm3;

import com.gmcrypto.suite.codec.Codec;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class Sm3SupportTest {

    @Test
    void emptyVector() {
        assertEquals("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
                Codec.toHex(Sm3Support.digest(new byte[0])));
    }

    @Test
    void abcVector() {
        assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                Codec.toHex(Sm3Support.digest(Codec.utf8("abc"))));
    }

    @Test
    void hmacChangesWithKey() {
        byte[] valueA = Sm3Support.hmac(Codec.utf8("key-a"), Codec.utf8("message"));
        byte[] valueB = Sm3Support.hmac(Codec.utf8("key-b"), Codec.utf8("message"));
        assertFalse(java.util.Arrays.equals(valueA, valueB));
    }
}

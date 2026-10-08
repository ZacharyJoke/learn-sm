package com.gmcrypto.suite.key;

import com.gmcrypto.suite.common.GmCryptoException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyVersionStoreTest {

    @Test
    void registerGetAndRotate() {
        KeyVersionStore store = new LocalKeyVersionStore();
        ManagedKey managedKey = store.register("SM2");
        assertEquals(KeyStatus.ACTIVE, store.get(managedKey.version().id()).version().status());
        store.markStatus(managedKey.version().id(), KeyStatus.ROTATED);
        assertEquals(KeyStatus.ROTATED, store.get(managedKey.version().id()).version().status());
    }

    @Test
    void missingKeyThrows() {
        assertThrows(GmCryptoException.class, () -> new LocalKeyVersionStore().get("missing"));
    }
}

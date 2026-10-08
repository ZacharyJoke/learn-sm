package com.gmcrypto.suite.key;

import java.util.List;

public interface KeyVersionStore {

    ManagedKey register(String algorithm);

    ManagedKey get(String id);

    List<ManagedKey> list();

    void markStatus(String id, KeyStatus status);
}

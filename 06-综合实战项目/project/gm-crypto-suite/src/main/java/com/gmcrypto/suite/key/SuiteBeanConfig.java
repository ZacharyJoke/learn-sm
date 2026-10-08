package com.gmcrypto.suite.key;

import com.gmcrypto.suite.envelope.EnvelopeService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SuiteBeanConfig {

    @Bean
    KeyVersionStore keyVersionStore() {
        return new LocalKeyVersionStore();
    }

    @Bean
    DemoRecipient demoRecipient(KeyVersionStore keyVersionStore) {
        return new DemoRecipient(keyVersionStore.register("SM2"));
    }

    @Bean
    EnvelopeService envelopeService() {
        return new EnvelopeService();
    }
}

package com.gmcrypto.suite.web;

import com.gmcrypto.suite.codec.Codec;
import com.gmcrypto.suite.sm2.Sm2Support;
import com.gmcrypto.suite.sm3.Sm3Support;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.security.KeyPair;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SignVerifyInterceptorTest {

    private static final String PATH = "/api/signed/echo";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppKeyResolver appKeyResolver;

    private KeyPair appKeyPair;

    @BeforeEach
    void setUp() {
        appKeyPair = Sm2Support.generateKeyPair();
        appKeyResolver.register("demo-app", appKeyPair.getPublic());
    }

    @Test
    void validSignatureAccepted() throws Exception {
        mockMvc.perform(signedRequest(System.currentTimeMillis(), UUID.randomUUID().toString(), "{}"))
                .andExpect(status().isOk());
    }

    @Test
    void expiredTimestampRejected() throws Exception {
        mockMvc.perform(signedRequest(System.currentTimeMillis() - 3600_000, UUID.randomUUID().toString(), "{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void replayRejected() throws Exception {
        String nonce = UUID.randomUUID().toString();
        mockMvc.perform(signedRequest(System.currentTimeMillis(), nonce, "{}")).andExpect(status().isOk());
        mockMvc.perform(signedRequest(System.currentTimeMillis(), nonce, "{}")).andExpect(status().isConflict());
    }

    @Test
    void wrongSignatureRejected() throws Exception {
        mockMvc.perform(signedRequest(System.currentTimeMillis(), UUID.randomUUID().toString(), "{}",
                        "00".repeat(64)))
                .andExpect(status().isUnauthorized());
    }

    private MockHttpServletRequestBuilder signedRequest(long timestamp, String nonce, String body) {
        return signedRequest(timestamp, nonce, body, null);
    }

    private MockHttpServletRequestBuilder signedRequest(long timestamp, String nonce, String body,
                                                        String signatureOverride) {
        String bodyDigest = Codec.toHex(Sm3Support.digest(Codec.utf8(body)));
        String signingContent = String.join("\n", "demo-app", String.valueOf(timestamp), nonce, "POST", PATH,
                bodyDigest);
        String signature = signatureOverride != null
                ? signatureOverride
                : Codec.toHex(Sm2Support.sign(appKeyPair.getPrivate(), Codec.utf8(signingContent)));
        return post(PATH).contentType(MediaType.APPLICATION_JSON).content(body)
                .header(SignHeaders.APP_ID, "demo-app")
                .header(SignHeaders.TIMESTAMP, timestamp)
                .header(SignHeaders.NONCE, nonce)
                .header(SignHeaders.SIGNATURE, signature);
    }
}

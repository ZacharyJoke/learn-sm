package com.gmcrypto.suite.api;

import com.gmcrypto.suite.envelope.EnvelopeData;
import com.gmcrypto.suite.envelope.EnvelopeService;
import com.gmcrypto.suite.key.DemoRecipient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    private final EnvelopeService envelopeService;
    private final DemoRecipient demoRecipient;

    public DemoController(EnvelopeService envelopeService, DemoRecipient demoRecipient) {
        this.envelopeService = envelopeService;
        this.demoRecipient = demoRecipient;
    }

    @PostMapping("/signed/echo")
    public Map<String, Object> signedEcho(@RequestBody String body) {
        return Map.of("received", true, "body", body);
    }

    @PostMapping("/demo/envelope")
    public Map<String, String> envelopeDemo(@RequestBody Map<String, String> request) {
        String plaintext = request.getOrDefault("plaintext", "");
        String recipientKeyId = demoRecipient.managedKey().version().id();
        EnvelopeData envelope = envelopeService.seal(
                demoRecipient.managedKey().keyPair().getPublic(),
                recipientKeyId,
                "demo-sender",
                plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] opened = envelopeService.open(demoRecipient.managedKey().keyPair().getPrivate(), envelope);
        return Map.of("recipientKeyId", recipientKeyId,
                "digest", envelope.digest(),
                "opened", new String(opened, java.nio.charset.StandardCharsets.UTF_8));
    }
}

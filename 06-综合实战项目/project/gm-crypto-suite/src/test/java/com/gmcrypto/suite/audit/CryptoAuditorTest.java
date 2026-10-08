package com.gmcrypto.suite.audit;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoAuditorTest {

    @Test
    void detectsRules() throws Exception {
        Path file = Files.createTempFile("audit", ".java");
        Files.writeString(file, String.join("\n",
                "Cipher.getInstance(\"SM4/ECB/NoPadding\");",
                "new Random();",
                "String k = \"0123456789abcdef0123456789abcdef\";"));
        List<AuditFinding> findings = new CryptoAuditor().scanPath(file);
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("GM-ECB")));
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("GM-WEAK-RANDOM")));
        assertTrue(findings.size() >= 3);
    }
}

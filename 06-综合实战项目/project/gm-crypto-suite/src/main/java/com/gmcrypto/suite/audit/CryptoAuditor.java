package com.gmcrypto.suite.audit;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class CryptoAuditor {

    private record Rule(String id, String severity, Pattern pattern, String message) {
    }

    private static final List<Rule> RULES = List.of(
            new Rule("GM-ECB", "HIGH", Pattern.compile("/ECB/"), "使用 ECB 工作模式，会泄露明文模式"),
            new Rule("GM-WEAK-RANDOM", "HIGH", Pattern.compile("new\\s+Random\\s*\\("), "使用非安全随机源"),
            new Rule("GM-HARDCODED-HEX", "MEDIUM", Pattern.compile("\"[0-9a-fA-F]{32,}\""), "疑似硬编码十六进制密钥"),
            new Rule("GM-EMBEDDED-PRIVATE-KEY", "HIGH", Pattern.compile("BEGIN [A-Z ]*PRIVATE KEY"), "源码内嵌私钥"),
            new Rule("GM-ZERO-IV", "MEDIUM", Pattern.compile("IvParameterSpec\\(\\s*new\\s+byte"), "疑似固定/全零 IV")
    );

    public List<AuditFinding> scanPath(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        List<AuditFinding> findings = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            for (Rule rule : RULES) {
                if (rule.pattern().matcher(line).find()) {
                    findings.add(new AuditFinding(rule.id(), rule.severity(), path.toString(), i + 1, rule.message()));
                }
            }
        }
        return findings;
    }
}

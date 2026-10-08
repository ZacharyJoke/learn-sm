package com.gmcrypto.suite.audit;

public record AuditFinding(String ruleId, String severity, String path, int line, String message) {
}

package com.gmcrypto.suite.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.nio.file.Paths;
import java.util.List;

@Component
public class AuditCliRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AuditCliRunner.class);

    @Override
    public void run(ApplicationArguments args) throws Exception {
        List<String> targets = args.getOptionValues("audit");
        if (targets == null) {
            return;
        }
        CryptoAuditor auditor = new CryptoAuditor();
        for (String target : targets) {
            auditor.scanPath(Paths.get(target)).forEach(finding -> log.warn("{} {}:{} {}",
                    finding.ruleId(), finding.path(), finding.line(), finding.message()));
        }
    }
}

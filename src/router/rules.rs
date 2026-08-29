use std::sync::Arc;

use crate::router::migration::{CompositeDetector, Detector, KeywordDetector, RegexDetector};

pub fn build_detector() -> Arc<dyn Detector> {
    Arc::new(CompositeDetector {
        detectors: vec![
            Arc::new(RegexDetector::new(
                r"(?i)(/dev/tcp/|bash\s+-i|sh\s+-i|/bin/(?:bash|sh)\s+-i|0>&1|1>&2)",
                "beelzebub",
            )),
            Arc::new(RegexDetector::new(
                r"(?i)(\bnc\b[^|;&]*(?:-e|-c)\b|\bncat\b[^|;&]*(?:-e|-c)\b|\bsocat\b[^|;&]*exec:|\bmkfifo\b[^|;&]*\|\s*/bin/(?:ba)?sh)",
                "beelzebub",
            )),
            Arc::new(RegexDetector::new(
                r"(?i)(\b(curl|wget|fetch|python(?:3)?|perl|ruby|php|node|powershell|pwsh)\b[^|;&]*(?:\|\s*(?:ba)?sh\b|(?:-o|-O|--output|-OutFile)\b|(?:base64\s+-d|base64\s+--decode|certutil\b|\bInvoke-WebRequest\b|\bStart-BitsTransfer\b)))",
                "beelzebub",
            )),
            Arc::new(RegexDetector::new(
                r"(?i)(\bsudo\s+-l\b|\bpkexec\b|\bchmod\s+[ugo+=-]*s\b|\bsetcap\b|\bcrontab\b|\bsystemctl\s+(?:enable|start)\b|/etc/(?:cron|sudoers|shadow)|\.ssh/id_rsa|\.aws/credentials|\.kube/config)",
                "beelzebub",
            )),
            Arc::new(RegexDetector::new(
                r"(?i)(\bsshpass\b|\bscp\b|\bsftp\b|\bplink\b|\brdesktop\b|\bxfreerdp\b|\bwmic\b|\bpsexec\b|\bwinrs\b|\breg\s+save\b|\brunas\b|\bmimikatz\b|\bsecretsdump\b)",
                "beelzebub",
            )),
            Arc::new(KeywordDetector::new(
                &[
                    "tar -x",
                    "base64 -d",
                    "openssl enc",
                    "nohup",
                    ">/dev/tcp/",
                    "python -c",
                    "python3 -c",
                    "perl -e",
                    "ruby -e",
                    "php -r",
                    "node -e",
                    "powershell -enc",
                    "curl ",
                    "wget ",
                ],
                "beelzebub",
            )),
        ],
    })
}

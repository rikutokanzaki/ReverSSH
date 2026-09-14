use anyhow::{Context, Result};
use regex::Regex;
use std::sync::Arc;

use crate::config::RoutingRuleConfig;
use crate::terminal::state::CmdInfo;

pub trait Detector: Send + Sync {
    fn detect(&self, cmd: &CmdInfo, username: &str, password: &str) -> Option<String>;
}

pub struct KeywordDetector {
    pub keywords: Vec<String>,
    pub target: String,
}

impl KeywordDetector {
    pub fn new(keywords: &[&str], target: &str) -> Self {
        Self {
            keywords: keywords.iter().map(|s| s.to_string()).collect(),
            target: target.to_string(),
        }
    }
}

pub struct RegexDetector {
    pub re: Regex,
    pub target: String,
}

impl RegexDetector {
    pub fn new(pattern: &str, target: &str) -> Result<Self> {
        Ok(Self {
            re: Regex::new(pattern).with_context(|| format!("invalid routing regex: {pattern}"))?,
            target: target.to_string(),
        })
    }
}

pub struct AuthDetector {
    rules: Vec<AuthRule>,
    target: String,
}

struct AuthRule {
    username: GlobPattern,
    password: GlobPattern,
}

struct GlobPattern {
    regex: Regex,
}

impl GlobPattern {
    fn new(pattern: &str) -> Result<Self> {
        let expression = format!(
            "^{}$",
            pattern
                .split('*')
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join(".*")
        );

        Ok(Self {
            regex: Regex::new(&expression)
                .with_context(|| format!("invalid auth wildcard: {pattern}"))?,
        })
    }

    fn is_match(&self, value: &str) -> bool {
        self.regex.is_match(value)
    }
}

impl AuthDetector {
    pub fn new(patterns: &[String], target: &str) -> Result<Self> {
        let mut rules = Vec::with_capacity(patterns.len());

        for pattern in patterns {
            let (username, password) = pattern
                .split_once(':')
                .with_context(|| format!("auth rule must be in user:password form: {pattern}"))?;

            rules.push(AuthRule {
                username: GlobPattern::new(username)?,
                password: GlobPattern::new(password)?,
            });
        }

        Ok(Self {
            rules,
            target: target.to_string(),
        })
    }
}

pub fn build_rule_detectors(rule: &RoutingRuleConfig) -> Result<Vec<Arc<dyn Detector>>> {
    let mut detectors: Vec<Arc<dyn Detector>> = Vec::new();

    for pattern in &rule.regex {
        detectors.push(Arc::new(RegexDetector::new(pattern, &rule.backend)?));
    }

    if !rule.keywords.is_empty() {
        detectors.push(Arc::new(KeywordDetector {
            keywords: rule.keywords.clone(),
            target: rule.backend.clone(),
        }));
    }

    if !rule.auth.is_empty() {
        detectors.push(Arc::new(AuthDetector::new(&rule.auth, &rule.backend)?));
    }

    Ok(detectors)
}

pub struct CompositeDetector {
    pub detectors: Vec<Arc<dyn Detector>>,
}

impl Detector for KeywordDetector {
    fn detect(&self, cmd_info: &CmdInfo, _username: &str, _password: &str) -> Option<String> {
        if self
            .keywords
            .iter()
            .any(|kw| cmd_info.cmd.contains(kw.as_str()))
        {
            Some(self.target.clone())
        } else {
            None
        }
    }
}

impl Detector for RegexDetector {
    fn detect(&self, cmd_info: &CmdInfo, _username: &str, _password: &str) -> Option<String> {
        if self.re.is_match(&cmd_info.cmd) {
            Some(self.target.clone())
        } else {
            None
        }
    }
}

impl Detector for AuthDetector {
    fn detect(&self, _cmd_info: &CmdInfo, username: &str, password: &str) -> Option<String> {
        self.rules
            .iter()
            .any(|rule| rule.username.is_match(username) && rule.password.is_match(password))
            .then(|| self.target.clone())
    }
}

impl Detector for CompositeDetector {
    fn detect(&self, cmd_info: &CmdInfo, username: &str, password: &str) -> Option<String> {
        for detector in &self.detectors {
            if let Some(target) = detector.detect(cmd_info, username, password) {
                return Some(target);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(value: &str) -> CmdInfo {
        CmdInfo::new_with_generated_id("guest", value)
    }

    #[test]
    fn auth_rules_support_wildcards_and_multiple_patterns() {
        let detector = AuthDetector::new(
            &[
                "root:*".to_string(),
                "admin:admin*".to_string(),
                "*:service-*".to_string(),
            ],
            "cowrie2",
        )
        .expect("auth rules should compile");

        assert_eq!(
            detector.detect(&command("true"), "root", "any-password"),
            Some("cowrie2".to_string())
        );
        assert_eq!(
            detector.detect(&command("true"), "admin", "admin123"),
            Some("cowrie2".to_string())
        );
        assert_eq!(
            detector.detect(&command("true"), "guest", "service-account"),
            Some("cowrie2".to_string())
        );
        assert_eq!(detector.detect(&command("true"), "guest", "password"), None);
    }

    #[test]
    fn rule_can_contain_regex_keywords_and_auth_together() {
        let rule = RoutingRuleConfig {
            name: "combined".to_string(),
            backend: "cowrie1".to_string(),
            regex: vec!["danger".to_string()],
            keywords: vec!["download".to_string()],
            auth: vec!["root:*".to_string()],
        };
        let detectors = build_rule_detectors(&rule).expect("rule should compile");
        let detector = CompositeDetector { detectors };

        assert_eq!(
            detector.detect(&command("danger"), "guest", "password"),
            Some("cowrie1".to_string())
        );
        assert_eq!(
            detector.detect(&command("download file"), "guest", "password"),
            Some("cowrie1".to_string())
        );
        assert_eq!(
            detector.detect(&command("true"), "root", "password"),
            Some("cowrie1".to_string())
        );
    }
}

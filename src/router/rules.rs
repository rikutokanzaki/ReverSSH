use anyhow::{Context, Result, bail};
use std::sync::Arc;

use crate::config::{RoutingConfig, RoutingRuleConfig};
use crate::router::migration::{CompositeDetector, Detector, build_rule_detectors};

pub(crate) fn build_detector(config: &RoutingConfig) -> Result<Arc<dyn Detector>> {
    let mut detectors = Vec::new();

    for rule in &config.rules {
        if rule.regex.is_empty() && rule.keywords.is_empty() && rule.auth.is_empty() {
            bail!("routing rule '{}' has no conditions", rule.name);
        }

        let rule_detectors = build_rule_detectors(rule)
            .with_context(|| format!("invalid routing rule '{}'", rule.name))?;
        detectors.extend(rule_detectors);
    }

    for rule in &config.command {
        let rule = RoutingRuleConfig {
            name: rule.name.clone(),
            backend: rule.backend.clone(),
            regex: rule.regex.clone(),
            keywords: rule.keywords.clone(),
            auth: Vec::new(),
        };

        if rule.regex.is_empty() && rule.keywords.is_empty() {
            bail!("command rule '{}' has no conditions", rule.name);
        }

        let rule_detectors = build_rule_detectors(&rule)
            .with_context(|| format!("invalid command rule '{}'", rule.name))?;
        detectors.extend(rule_detectors);
    }

    Ok(Arc::new(CompositeDetector { detectors }))
}

#[cfg(test)]
mod tests {
    use super::build_detector;
    use crate::config::{RoutingConfig, RoutingRuleConfig};
    use crate::router::migration::{Detector, build_rule_detectors};
    use crate::terminal::state::CmdInfo;
    use anyhow::Result;
    use std::sync::Arc;

    const SAMPLE: &str = include_str!("../../config/routing.toml.sample");

    fn command(value: &str) -> CmdInfo {
        CmdInfo::new_with_generated_id("user", value)
    }

    fn wildcard_value(pattern: &str, fallback: &str) -> String {
        if pattern == "*" {
            fallback.to_string()
        } else {
            pattern.replace('*', fallback)
        }
    }

    fn regex_example(pattern: &str) -> &'static str {
        match pattern {
            "(?i)^id$" => "id",
            "(?i)^uname(?:\\s+-[a-z]+)?$" => "uname -a",
            "^cowrie$" => "cowrie",
            "^beelzebub$" => "beelzebub",
            _ => panic!("add a representative command for sample regex {pattern:?}"),
        }
    }

    fn assert_rule_conditions(rule: &RoutingRuleConfig, detectors: &[Arc<dyn Detector>]) {
        for regex in &rule.regex {
            let cmd = command(regex_example(regex));
            assert!(
                detectors
                    .iter()
                    .any(|detector| detector.detect(&cmd, "not-user", "not-password")
                        == Some(rule.backend.clone())),
                "regex condition {regex:?} in rule {} did not route to {}",
                rule.name,
                rule.backend
            );
        }

        for keyword in &rule.keywords {
            let cmd = command(&format!("prefix-{keyword}-suffix"));
            assert!(
                detectors
                    .iter()
                    .any(|detector| detector.detect(&cmd, "not-user", "not-password")
                        == Some(rule.backend.clone())),
                "keyword condition {keyword:?} in rule {} did not route to {}",
                rule.name,
                rule.backend
            );
        }

        for auth in &rule.auth {
            let (username, password) = auth
                .split_once(':')
                .expect("sample auth condition must have user:password form");
            let cmd = command("unmatched-command");
            assert!(
                detectors.iter().any(|detector| {
                    detector.detect(
                        &cmd,
                        &wildcard_value(username, "user"),
                        &wildcard_value(password, "password"),
                    ) == Some(rule.backend.clone())
                }),
                "auth condition {auth:?} in rule {} did not route to {}",
                rule.name,
                rule.backend
            );
        }
    }

    #[test]
    fn routing_sample_covers_every_condition() -> Result<()> {
        let routing: RoutingConfig = toml::from_str(SAMPLE)?;
        let detector = build_detector(&routing)?;

        for rule in &routing.rules {
            let detectors = build_rule_detectors(rule)?;
            assert_rule_conditions(rule, &detectors);
        }

        for rule in &routing.command {
            let rule_as_routing = RoutingRuleConfig {
                name: rule.name.clone(),
                backend: rule.backend.clone(),
                regex: rule.regex.clone(),
                keywords: rule.keywords.clone(),
                auth: Vec::new(),
            };
            let detectors = build_rule_detectors(&rule_as_routing)?;
            assert_rule_conditions(&rule_as_routing, &detectors);
        }

        for rule in &routing.authentication {
            let rule_as_routing = RoutingRuleConfig {
                name: rule.name.clone(),
                backend: rule.backend.clone(),
                regex: Vec::new(),
                keywords: Vec::new(),
                auth: rule.auth.clone(),
            };
            let detectors = build_rule_detectors(&rule_as_routing)?;
            assert_rule_conditions(&rule_as_routing, &detectors);
        }

        assert!(
            detector
                .detect(&command("uname -a"), "not-user", "not-password")
                .is_some()
        );
        Ok(())
    }
}

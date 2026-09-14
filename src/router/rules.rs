use anyhow::{Context, Result, bail};
use std::sync::Arc;

use crate::config::{RoutingConfig, RoutingRuleConfig};
use crate::router::migration::{CompositeDetector, Detector, build_rule_detectors};

pub fn build_detector(config: &RoutingConfig) -> Result<Arc<dyn Detector>> {
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

    for rule in &config.authentication {
        let rule = RoutingRuleConfig {
            name: rule.name.clone(),
            backend: rule.backend.clone(),
            regex: Vec::new(),
            keywords: Vec::new(),
            auth: rule.auth.clone(),
        };

        if rule.auth.is_empty() {
            bail!(
                "authentication rule '{}' has no authentication conditions",
                rule.name
            );
        }

        let rule_detectors = build_rule_detectors(&rule)
            .with_context(|| format!("invalid authentication rule '{}'", rule.name))?;
        detectors.extend(rule_detectors);
    }

    Ok(Arc::new(CompositeDetector { detectors }))
}

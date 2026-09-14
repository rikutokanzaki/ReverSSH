use anyhow::{Context, Result, bail};
use std::sync::Arc;

use crate::config::RoutingConfig;
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

    Ok(Arc::new(CompositeDetector { detectors }))
}

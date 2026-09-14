use anyhow::{Result, bail};
use std::collections::HashSet;

use crate::config::AppConfig;

pub fn validate_config(config: &AppConfig) -> Result<()> {
    let defaults = config.backends.iter().filter(|b| b.default).count();

    if defaults > 1 {
        bail!("multiple default backends defined")
    }

    let backend_names: HashSet<&str> = config.backends.iter().map(|b| b.name.as_str()).collect();
    let default_backend_names: HashSet<&str> = config
        .backends
        .iter()
        .filter(|backend| backend.default)
        .map(|backend| backend.name.as_str())
        .collect();

    for rule in &config.routing.rules {
        if !backend_names.contains(rule.backend.as_str()) {
            bail!(
                "routing rule '{}' targets unknown backend '{}'",
                rule.name,
                rule.backend
            )
        }

        if default_backend_names.contains(rule.backend.as_str()) {
            bail!(
                "routing rule '{}' targets default backend '{}'; routing targets must be non-default backends",
                rule.name,
                rule.backend
            )
        }

        if rule.regex.is_empty() && rule.keywords.is_empty() && rule.auth.is_empty() {
            bail!("routing rule '{}' has no conditions", rule.name)
        }

        for auth in &rule.auth {
            if !auth.contains(':') {
                bail!(
                    "routing rule '{}' has invalid auth rule '{}'; expected user:password",
                    rule.name,
                    auth
                )
            }
        }
    }

    for (from, to) in &config.migration {
        if !backend_names.contains(to.as_str()) {
            bail!("migration maps '{}' to unknown backend '{}'", from, to)
        }
    }

    Ok(())
}

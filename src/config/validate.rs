use anyhow::{Result, bail};
use std::collections::HashSet;

use crate::config::{AppConfig, AuthType, BackendType};

pub fn validate_config(config: &AppConfig) -> Result<()> {
    let interaction_defaults = config
        .backends
        .iter()
        .filter(|backend| backend.default && backend.backend_type == BackendType::Interaction)
        .count();
    let credential_defaults = config
        .backends
        .iter()
        .filter(|backend| backend.default && backend.backend_type == BackendType::Credential)
        .count();

    if interaction_defaults > 1 {
        bail!("multiple default interaction backends defined")
    }
    if credential_defaults > 1 {
        bail!("multiple default credential backends defined")
    }

    let backend_names: HashSet<&str> = config.backends.iter().map(|b| b.name.as_str()).collect();
    let default_backend_names: HashSet<&str> = config
        .backends
        .iter()
        .filter(|backend| backend.default && backend.backend_type == BackendType::Interaction)
        .map(|backend| backend.name.as_str())
        .collect();

    for rule in &config.routing.rules {
        validate_routing_target(
            &backend_names,
            &default_backend_names,
            &config.backends,
            &rule.name,
            &rule.backend,
            false,
            false,
        )?;
        validate_rule_conditions(&rule.name, &rule.regex, &rule.keywords, &rule.auth)?;
    }

    for rule in &config.routing.command {
        validate_routing_target(
            &backend_names,
            &default_backend_names,
            &config.backends,
            &rule.name,
            &rule.backend,
            true,
            false,
        )?;
        validate_rule_conditions(&rule.name, &rule.regex, &rule.keywords, &[])?;
    }

    for rule in &config.routing.authentication {
        validate_routing_target(
            &backend_names,
            &default_backend_names,
            &config.backends,
            &rule.name,
            &rule.backend,
            false,
            true,
        )?;
        validate_rule_conditions(&rule.name, &[], &[], &rule.auth)?;
    }

    for backend in &config.backends {
        if backend.backend_type == BackendType::Credential {
            if backend.auth_type != AuthType::Password {
                bail!(
                    "credential backend '{}' must use password authentication",
                    backend.name
                )
            }

            if backend.username.is_some() != backend.password.is_some() {
                bail!(
                    "credential backend '{}' must define both username and password",
                    backend.name
                )
            }
        }
    }

    for (from, to) in &config.migration {
        if !backend_names.contains(to.as_str()) {
            bail!("migration maps '{}' to unknown backend '{}'", from, to)
        }

        if config
            .backends
            .iter()
            .find(|backend| backend.name == *to)
            .is_some_and(|backend| backend.backend_type == BackendType::Credential)
        {
            bail!(
                "migration maps '{}' to credential backend '{}'; credential backends only observe failed authentication",
                from,
                to
            )
        }
    }

    Ok(())
}

fn validate_routing_target(
    backend_names: &HashSet<&str>,
    default_backend_names: &HashSet<&str>,
    backends: &[crate::config::BackendConfig],
    rule_name: &str,
    backend_name: &str,
    command_rule: bool,
    authentication_rule: bool,
) -> Result<()> {
    if !backend_names.contains(backend_name) {
        bail!(
            "routing rule '{}' targets unknown backend '{}'",
            rule_name,
            backend_name
        )
    }

    if default_backend_names.contains(backend_name) {
        bail!(
            "routing rule '{}' targets default backend '{}'; routing targets must be non-default backends",
            rule_name,
            backend_name
        )
    }

    if backends
        .iter()
        .find(|backend| backend.name == backend_name)
        .is_some_and(|backend| backend.backend_type == BackendType::Credential)
    {
        if command_rule {
            bail!(
                "command rule '{}' targets credential backend '{}'; command routing requires an interaction backend",
                rule_name,
                backend_name
            )
        }

        if authentication_rule {
            return Ok(());
        }

        bail!(
            "routing rule '{}' targets credential backend '{}'; credential backends only observe failed authentication",
            rule_name,
            backend_name
        )
    }

    Ok(())
}

fn validate_rule_conditions(
    rule_name: &str,
    regex: &[String],
    keywords: &[String],
    auth: &[String],
) -> Result<()> {
    if regex.is_empty() && keywords.is_empty() && auth.is_empty() {
        bail!("routing rule '{}' has no conditions", rule_name)
    }

    for auth_rule in auth {
        if !auth_rule.contains(':') {
            bail!(
                "routing rule '{}' has invalid auth rule '{}'; expected user:password",
                rule_name,
                auth_rule
            )
        }
    }

    Ok(())
}

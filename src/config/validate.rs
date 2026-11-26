use anyhow::{Context, Result, bail};
use std::collections::HashSet;

use crate::config::{AppConfig, AuthType, BackendType};

pub fn validate_config(config: &AppConfig) -> Result<()> {
    validate_profiles(config)?;

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

fn validate_profiles(config: &AppConfig) -> Result<()> {
    let backend_names: HashSet<&str> = config.backends.iter().map(|b| b.name.as_str()).collect();
    let profile_names: HashSet<&str> = config
        .routing
        .profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();

    if profile_names.len() != config.routing.profiles.len() {
        bail!("duplicate routing profile name defined");
    }

    for profile in &config.routing.profiles {
        let backend = config
            .backends
            .iter()
            .find(|backend| backend.name == profile.default_backend)
            .with_context(|| {
                format!(
                    "routing profile '{}' targets unknown default backend '{}'",
                    profile.name, profile.default_backend
                )
            })?;
        if backend.backend_type != BackendType::Interaction {
            bail!(
                "routing profile '{}' default backend '{}' must be an interaction backend",
                profile.name,
                profile.default_backend
            );
        }

        if !backend_names.contains(profile.credential_backend.as_str()) {
            bail!(
                "routing profile '{}' targets unknown credential backend '{}'",
                profile.name,
                profile.credential_backend
            );
        }

        for rule in &profile.command {
            if !backend_names.contains(rule.backend.as_str()) {
                bail!(
                    "profile command rule '{}' targets unknown backend '{}'",
                    rule.name,
                    rule.backend
                );
            }
            if config
                .backends
                .iter()
                .find(|backend| backend.name == rule.backend)
                .is_some_and(|backend| backend.backend_type == BackendType::Credential)
            {
                bail!(
                    "profile command rule '{}' targets credential backend '{}'",
                    rule.name,
                    rule.backend
                );
            }
            validate_rule_conditions(&rule.name, &rule.regex, &rule.keywords, &[])?;
        }
    }

    if let Some(schedule) = &config.routing.schedule {
        if schedule.interval_seconds == 0 {
            bail!("schedule interval_seconds must be greater than zero");
        }
        if schedule.sequence.is_empty() {
            bail!("schedule sequence must not be empty");
        }
        if !matches!(schedule.timezone.as_str(), "UTC" | "Asia/Tokyo") {
            bail!("unsupported schedule timezone '{}'", schedule.timezone);
        }
        for profile in &schedule.sequence {
            if !profile_names.contains(profile.as_str()) {
                bail!("schedule references unknown profile '{profile}'");
            }
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

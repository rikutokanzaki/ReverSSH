use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::backend::handler::BackendConnection;
use crate::config::{AuthenticationRuleConfig, BackendConfig, BackendType};

#[derive(Clone)]
struct AuthenticationRoute {
    backend: String,
    credentials: Vec<String>,
}

pub struct BackendPool {
    backends: Arc<RwLock<HashMap<String, BackendConfig>>>,
    default_interaction_backend: Option<String>,
    default_credential_backend: Option<String>,
    authentication_routes: Vec<AuthenticationRoute>,
}

impl BackendPool {
    pub fn new(
        configs: Vec<BackendConfig>,
        authentication_rules: &[AuthenticationRuleConfig],
    ) -> Self {
        let mut backends = HashMap::new();
        let mut default_interaction_backend = None;
        let mut default_credential_backend = None;

        for config in configs {
            if config.default {
                match config.backend_type {
                    BackendType::Interaction => {
                        default_interaction_backend = Some(config.name.clone())
                    }
                    BackendType::Credential => {
                        default_credential_backend = Some(config.name.clone())
                    }
                }
            }
            backends.insert(config.name.clone(), config);
        }

        Self {
            backends: Arc::new(RwLock::new(backends)),
            default_interaction_backend,
            default_credential_backend,
            authentication_routes: authentication_rules
                .iter()
                .map(|rule| AuthenticationRoute {
                    backend: rule.backend.clone(),
                    credentials: rule.auth.clone(),
                })
                .collect(),
        }
    }

    pub async fn create_connection(
        &self,
        backend_name: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(Arc<BackendConnection>, Option<String>)> {
        let backends = self.backends.read().await;

        let name = backend_name
            .or(self.default_interaction_backend.as_deref())
            .context("No backend specified and no default")?;

        let config = backends.get(name).context("Backend not found")?.clone();

        let config_username = config.username.as_deref().unwrap_or("unknown").to_string();
        let config_password = config.password.as_deref().unwrap_or("unknown").to_string();
        let effective_username = username.unwrap_or(&config_username);
        let effective_password = password.unwrap_or(&config_password);

        let connection =
            BackendConnection::connect(config, effective_username, effective_password).await?;
        let initial_cwd = connection.open_channel().await?;

        Ok((Arc::new(connection), initial_cwd))
    }

    pub async fn observe_failed_auth(&self, username: &str, password: &str) -> Result<()> {
        let config = {
            let backends = self.backends.read().await;
            let routed_backend = self.authentication_routes.iter().find(|route| {
                route
                    .credentials
                    .iter()
                    .any(|credential| matches_credential(credential, username, password))
            });

            routed_backend
                .and_then(|route| backends.get(&route.backend))
                .or_else(|| {
                    backends.values().find(|backend| {
                        backend.backend_type == BackendType::Credential
                            && backend.username.as_deref() == Some(username)
                            && backend.password.as_deref() == Some(password)
                    })
                })
                .or_else(|| {
                    self.default_credential_backend
                        .as_deref()
                        .and_then(|name| backends.get(name))
                })
                .cloned()
        };

        let Some(config) = config else {
            return Ok(());
        };

        let connection = BackendConnection::connect(config, username, password).await?;
        connection.close().await
    }

    pub async fn interaction_backend_for_auth(
        &self,
        username: &str,
        password: &str,
    ) -> Option<String> {
        let backends = self.backends.read().await;

        self.authentication_routes
            .iter()
            .find(|route| {
                route
                    .credentials
                    .iter()
                    .any(|credential| matches_credential(credential, username, password))
            })
            .and_then(|route| backends.get(&route.backend))
            .filter(|backend| backend.backend_type == BackendType::Interaction)
            .map(|backend| backend.name.clone())
    }

    pub async fn get_backend_config(&self, name: &str) -> Option<BackendConfig> {
        let backends = self.backends.read().await;
        backends.get(name).cloned()
    }
}

fn matches_credential(pattern: &str, username: &str, password: &str) -> bool {
    let Some((username_pattern, password_pattern)) = pattern.split_once(':') else {
        return false;
    };

    matches_glob(username_pattern, username) && matches_glob(password_pattern, password)
}

fn matches_glob(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }

    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }

    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let mut offset = 0;

    for (index, part) in parts.iter().enumerate() {
        let Some(relative_index) = value[offset..].find(part) else {
            return false;
        };
        let match_index = offset + relative_index;

        if index == 0 && !starts_with_wildcard && match_index != 0 {
            return false;
        }

        offset = match_index + part.len();
    }

    ends_with_wildcard || offset == value.len()
}

#[cfg(test)]
mod tests {
    use super::{matches_credential, matches_glob};

    #[test]
    fn credential_patterns_match_expected_wildcards() {
        assert!(matches_credential("root:*", "root", "any-password"));
        assert!(matches_credential("*:admin*", "operator", "admin123"));
        assert!(!matches_credential("root:admin*", "operator", "admin123"));
        assert!(!matches_credential("root:admin*", "root", "user"));
    }

    #[test]
    fn glob_patterns_are_anchored_without_wildcards() {
        assert!(matches_glob("admin*", "admin123"));
        assert!(matches_glob("*admin", "superadmin"));
        assert!(matches_glob("*min*", "administrator"));
        assert!(!matches_glob("admin", "superadmin"));
    }
}

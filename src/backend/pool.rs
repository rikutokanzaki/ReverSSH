use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::backend::handler::BackendConnection;
use crate::config::BackendConfig;

pub struct BackendPool {
    backends: Arc<RwLock<HashMap<String, BackendConfig>>>,
    default_backend: Option<String>,
}

impl BackendPool {
    pub fn new(configs: Vec<BackendConfig>) -> Self {
        let mut backends = HashMap::new();
        let mut default_backend = None;

        for config in configs {
            if config.default {
                default_backend = Some(config.name.clone());
            }
            backends.insert(config.name.clone(), config);
        }

        Self {
            backends: Arc::new(RwLock::new(backends)),
            default_backend,
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
            .or(self.default_backend.as_deref())
            .context("No backend specified and no default")?;

        let config = backends.get(name).context("Backend not found")?.clone();

        let config_username = config.username.as_deref().unwrap_or("unknown").to_string();
        let config_password = config.password.as_deref().unwrap_or("unknown").to_string();
        let effective_username = username.unwrap_or(&config_username);
        let effective_password = password.unwrap_or(&config_password);

        let conn =
            BackendConnection::connect(config, effective_username, effective_password).await?;
        let initial_cwd = conn.open_channel().await?;

        Ok((Arc::new(conn), initial_cwd))
    }

    pub async fn get_backend_config(&self, name: &str) -> Option<BackendConfig> {
        let backends = self.backends.read().await;
        backends.get(name).cloned()
    }
}

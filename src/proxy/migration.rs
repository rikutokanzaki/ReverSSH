use std::path::PathBuf;
use std::sync::Arc;

use log::{info, warn};

use crate::client::handler::Client;
use crate::proxy::server::ProxyServer;

impl ProxyServer {
    pub(super) async fn perform_migration(
        &mut self,
        session_id: &str,
        target_backend: &str,
    ) -> anyhow::Result<()> {
        let current_cwd = self.session_cwd(session_id).await?;
        let old_backend = self.backend_for_migration(session_id).await?;
        let new_backend = self.connect_to_backend(target_backend).await?;

        self.context
            .session_manager
            .set_backend(session_id, new_backend.clone())
            .await?;

        self.close_migrated_backend(session_id, old_backend).await;
        self.restore_working_directory(session_id, &new_backend, current_cwd)
            .await;

        Ok(())
    }

    pub(super) async fn initialize_session_cwd(
        &self,
        session_id: &str,
        initial_cwd: Option<String>,
    ) {
        let Some(initial_cwd) = initial_cwd else {
            return;
        };

        if let Err(error) = self.update_session_cwd(session_id, &initial_cwd).await {
            warn!(
                "Failed to update initial CWD for session {}: {:?}",
                session_id, error
            );
        }
    }

    async fn backend_for_migration(&mut self, session_id: &str) -> anyhow::Result<Arc<Client>> {
        match self.context.session_manager.get_backend(session_id).await {
            Ok(backend) => Ok(backend),
            Err(_) => self.ensure_backend_connected(session_id).await,
        }
    }

    async fn connect_to_backend(&self, backend_name: &str) -> anyhow::Result<Arc<Client>> {
        let (backend, _) = self
            .context
            .client_pool
            .create_connection(
                Some(backend_name),
                self.username.as_deref(),
                self.password.as_deref(),
            )
            .await?;
        Ok(backend)
    }

    async fn close_migrated_backend(&self, session_id: &str, old_backend: Arc<Client>) {
        if let Err(error) = old_backend.close().await {
            warn!(
                "Failed to close old backend while migrating session {}: {:?}",
                session_id, error
            );
        }
    }

    async fn restore_working_directory(
        &self,
        session_id: &str,
        backend: &Client,
        cwd: Option<PathBuf>,
    ) {
        let Some(cwd) = cwd else {
            return;
        };

        let cd_cmd = format!("cd {}", cwd.display());
        match backend.execute_command(&cd_cmd).await {
            Ok(result) => {
                if let Some(verified_cwd) = result.cwd
                    && let Err(error) = self.update_session_cwd(session_id, &verified_cwd).await
                {
                    warn!(
                        "Failed to update migrated CWD for session {}: {:?}",
                        session_id, error
                    );
                }
                info!("Reproduced CWD: {}", cwd.display());
            }
            Err(error) => {
                warn!(
                    "Failed to reproduce CWD for session {} ({}): {:?}",
                    session_id,
                    cwd.display(),
                    error
                );
            }
        }
    }
}

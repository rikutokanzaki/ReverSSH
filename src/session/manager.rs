use anyhow::{Context, Result};
use log::{debug, info, warn};
use russh::ChannelId;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::backend::handler::BackendConnection;
use crate::session::logger::SharedLogger;
use crate::terminal::state::{CmdInfo, TerminalState, WindowSize};

pub type SessionId = String;

pub struct SessionData {
    pub session_id: SessionId,
    pub username: String,
    pub password: String,
    pub client_channel: ChannelId,
    pub backend: Option<Arc<BackendConnection>>,
    pub terminal_state: TerminalState,
    pub logger: SharedLogger,
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<SessionId, Arc<RwLock<SessionData>>>>>,
    logger: SharedLogger,
}

impl SessionManager {
    pub fn new(log_path: String) -> Self {
        use crate::session::logger::create_logger;
        let logger = create_logger(&log_path);
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            logger,
        }
    }

    pub async fn create_session(
        &self,
        username: String,
        password: String,
        client_channel: ChannelId,
    ) -> Result<SessionId> {
        let session_id = Uuid::new_v4().to_string();

        let session_data = SessionData {
            session_id: session_id.clone(),
            username: username.clone(),
            password,
            client_channel,
            backend: None,
            terminal_state: TerminalState::new(),
            logger: self.logger.clone(),
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), Arc::new(RwLock::new(session_data)));

        info!(
            "Created session {} for user {} on channel {:?}",
            session_id, username, client_channel
        );

        Ok(session_id)
    }

    pub async fn get_session(&self, session_id: &str) -> Option<Arc<RwLock<SessionData>>> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn set_backend(
        &self,
        session_id: &str,
        backend: Arc<BackendConnection>,
    ) -> Result<()> {
        let session_lock = self
            .get_session(session_id)
            .await
            .context("Session not found")?;

        let mut session = session_lock.write().await;
        session.backend = Some(backend);
        Ok(())
    }

    pub async fn get_backend(&self, session_id: &str) -> Result<Arc<BackendConnection>> {
        let session_lock = self
            .get_session(session_id)
            .await
            .context("Session not found")?;

        let session = session_lock.read().await;
        session
            .backend
            .clone()
            .context("No backend connection established")
    }

    pub fn get_logger(&self) -> SharedLogger {
        self.logger.clone()
    }

    pub async fn update_cwd(&self, session_id: &str, new_cwd: PathBuf) -> Result<()> {
        let session_lock = self
            .get_session(session_id)
            .await
            .context("Session not found")?;

        let mut session = session_lock.write().await;
        session.terminal_state.cwd = Some(new_cwd.clone());
        debug!("Updated CWD for session {} to {:?}", session_id, new_cwd);
        Ok(())
    }

    pub async fn update_window_size(&self, session_id: &str, cols: u16, rows: u16) -> Result<()> {
        let session_lock = self
            .get_session(session_id)
            .await
            .context("Session not found")?;

        let mut session = session_lock.write().await;
        session.terminal_state.window_size = Some(WindowSize::new(cols, rows));

        debug!(
            "Updated window size for session {}: {}x{}",
            session_id, cols, rows
        );
        Ok(())
    }

    pub async fn push_command(&self, session_id: &str, cmd: String) -> Result<()> {
        let session_lock = self
            .get_session(session_id)
            .await
            .context("Session not found")?;

        let mut session = session_lock.write().await;
        let cmd_info = CmdInfo::new(session.username.clone(), cmd);
        session.terminal_state.push_cmd(cmd_info);

        Ok(())
    }

    pub async fn remove_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        if let Some(session_lock) = sessions.remove(session_id) {
            let session = session_lock.read().await;
            info!(
                "Removed session {} (user: {}, channel: {:?})",
                session_id, session.username, session.client_channel
            );
        } else {
            warn!("Attempted to remove non-existent session: {}", session_id);
        }

        Ok(())
    }

    pub async fn list_sessions(&self) -> Vec<SessionId> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }

    pub async fn count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }
}

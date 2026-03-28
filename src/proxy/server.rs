use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use log::{error, info, warn};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, MethodSet};

use crate::backend::pool::BackendPool;
use crate::config::AppConfig;
use crate::proxy::authenticator::load_allowed_usernames;
use crate::proxy::motd::return_motd;
use crate::router::migration::Detector;
use crate::session::manager::{SessionId, SessionManager};
use crate::terminal::reader::{InputEvent, LineReader};
use crate::terminal::renderer::Renderer;

pub struct ProxyServer {
    config: Arc<AppConfig>,
    session_manager: Arc<SessionManager>,
    backend_pool: Arc<BackendPool>,
    detector: Arc<dyn Detector>,

    accept_any: bool,
    allowed_users: Arc<HashSet<String>>,
    motd: String,

    session_id: Option<SessionId>,
    username: Option<String>,
    password: Option<String>,
    shell_active: bool,
    exec_mode: bool,
    reader: LineReader,
    renderer: Renderer,
}

impl ProxyServer {
    pub fn new(
        config: Arc<AppConfig>,
        session_manager: Arc<SessionManager>,
        backend_pool: Arc<BackendPool>,
        detector: Arc<dyn Detector>,
        accept_any: bool,
        allowed_users: Arc<HashSet<String>>,
        motd: String,
    ) -> Self {
        let renderer = Renderer::new();

        Self {
            config: config.clone(),
            session_manager,
            backend_pool,
            detector,
            accept_any,
            allowed_users,
            motd,
            session_id: None,
            username: None,
            password: None,
            shell_active: false,
            exec_mode: false,
            reader: LineReader::new(config.server.history_size),
            renderer,
        }
    }
}

#[async_trait]
impl server::Handler for ProxyServer {
    type Error = anyhow::Error;

    async fn auth_none(self, _user: &str) -> Result<(Self, Auth), Self::Error> {
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: Some(MethodSet::PASSWORD),
            },
        ))
    }

    async fn auth_publickey_offered(
        self,
        _user: &str,
        _public_key: &russh_keys::key::PublicKey,
    ) -> Result<(Self, Auth), Self::Error> {
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: Some(MethodSet::PASSWORD),
            },
        ))
    }

    async fn auth_publickey(
        self,
        _user: &str,
        _public_key: &russh_keys::key::PublicKey,
    ) -> Result<(Self, Auth), Self::Error> {
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: Some(MethodSet::PASSWORD),
            },
        ))
    }

    async fn auth_password(
        mut self,
        user: &str,
        password: &str,
    ) -> Result<(Self, Auth), Self::Error> {
        let is_allowed = self.accept_any || self.allowed_users.contains(user);

        if is_allowed {
            self.username = Some(user.to_string());
            self.password = Some(password.to_string());

            let logger = self.session_manager.get_logger();
            let logger_guard = logger.lock().await;
            logger_guard.log_auth_event("0.0.0.0", 0, "127.0.0.1", 22, user, password, true);
            drop(logger_guard);

            return Ok((self, Auth::Accept));
        }

        let logger = self.session_manager.get_logger();
        let logger_guard = logger.lock().await;
        logger_guard.log_auth_event("0.0.0.0", 0, "127.0.0.1", 22, user, password, false);
        drop(logger_guard);

        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: Some(MethodSet::PASSWORD),
            },
        ))
    }

    async fn channel_open_session(
        self,
        _channel: Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        Ok((self, true, session))
    }

    async fn pty_request(
        self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        session.channel_success(channel);
        Ok((self, session))
    }

    async fn shell_request(
        mut self,
        channel: ChannelId,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        self.shell_active = true;

        if let (Some(username), Some(password)) = (self.username.as_ref(), self.password.as_ref()) {
            match self
                .session_manager
                .create_session(username.clone(), password.clone(), channel)
                .await
            {
                Ok(session_id) => {
                    self.session_id = Some(session_id.clone());
                    info!("Session {} created for user {}", session_id, username);
                }
                Err(e) => {
                    error!("Failed to create session for user {}: {:?}", username, e);
                }
            }
        }

        session.channel_success(channel);

        self.renderer.send_newline(channel, &mut session);

        self.renderer
            .send_data(channel, &mut session, self.motd.as_bytes());

        self.send_prompt_with_cwd(channel, &mut session).await;

        Ok((self, session))
    }

    async fn exec_request(
        mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        self.exec_mode = true;

        let command = String::from_utf8_lossy(data).to_string();
        info!("Exec request: {}", command);

        let (username, password) = match (&self.username, &self.password) {
            (Some(u), Some(p)) => (u.clone(), p.clone()),
            _ => {
                error!("No credentials available for exec request");
                let error_msg = "Authentication required\r\n";
                self.renderer
                    .send_data(channel, &mut session, error_msg.as_bytes());
                session.exit_status_request(channel, 1);
                session.eof(channel);
                session.close(channel);
                return Ok((self, session));
            }
        };

        let session_id = match self
            .session_manager
            .create_session(username.clone(), password.clone(), channel)
            .await
        {
            Ok(session_id) => {
                info!("Exec session {} created for user {}", session_id, username);
                session_id
            }
            Err(e) => {
                error!(
                    "Failed to create exec session for user {}: {:?}",
                    username, e
                );
                let error_msg = "Failed to create session\r\n";
                self.renderer
                    .send_data(channel, &mut session, error_msg.as_bytes());
                session.exit_status_request(channel, 1);
                session.eof(channel);
                session.close(channel);

                return Ok((self, session));
            }
        };

        self.session_id = Some(session_id.clone());

        if let Err(e) = self
            .session_manager
            .push_command(&session_id, command.clone())
            .await
        {
            warn!("Failed to record command: {:?}", e);
        }

        self.run_argument_command(channel, &mut session, &session_id, &command)
            .await;

        Ok((self, session))
    }

    async fn window_change_request(
        self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(ref session_id) = self.session_id {
            if let Err(e) = self
                .session_manager
                .update_window_size(session_id, col_width as u16, row_height as u16)
                .await
            {
                warn!(
                    "Failed to update window size for session {}: {:?}",
                    session_id, e
                );
            }
        }

        session.channel_success(channel);
        Ok((self, session))
    }

    async fn data(
        mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if !self.shell_active {
            return Ok((self, session));
        }

        let events = self.reader.feed_bytes(data);

        for event in events {
            if matches!(event, InputEvent::Tab) {
                if let Some(session_id) = self.session_id.clone() {
                    self.handle_tab_completion(channel, &mut session, &session_id)
                        .await;
                }
                continue;
            }

            if let Some(line) = self.reader.apply(event) {
                self.renderer.send_newline(channel, &mut session);

                let trimmed = line.trim();

                if let Some(ref session_id) = self.session_id {
                    if let Err(e) = self
                        .session_manager
                        .push_command(session_id, trimmed.to_string())
                        .await
                    {
                        warn!("Failed to record command: {:?}", e);
                    }
                }

                if trimmed.is_empty() {
                    self.handle_empty_line(channel, &mut session).await;
                    continue;
                }

                if trimmed == "exit" || trimmed == "logout" {
                    if self.handle_exit_command(channel, &mut session).await {
                        return Ok((self, session));
                    }
                    continue;
                }

                if let Some(session_id) = self.session_id.clone() {
                    self.execute_and_handle_command(channel, &mut session, &session_id, trimmed)
                        .await;
                }
            } else {
                let username = self.get_username();

                let cwd = if let Some(ref session_id) = self.session_id {
                    self.get_session_cwd(session_id).await
                } else {
                    None
                };

                let buf = self.reader.buffer();
                let cursor = self.reader.cursor();
                self.renderer.redraw_line(
                    channel,
                    &mut session,
                    username,
                    &self.config.server.name,
                    cwd.as_deref(),
                    buf,
                    cursor,
                );
            }
        }

        Ok((self, session))
    }

    async fn channel_close(
        mut self,
        _channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(ref session_id) = self.session_id {
            if let Some(session_lock) = self.session_manager.get_session(session_id).await {
                let session_data = session_lock.read().await;
                let username = session_data.username.clone();
                drop(session_data);

                let logger = self.session_manager.get_logger();
                let logger_guard = logger.lock().await;
                logger_guard.log_session_close("0.0.0.0", 0, &username, 0.0, "Channel closed");
                drop(logger_guard);
            }

            if let Err(e) = self.session_manager.remove_session(session_id).await {
                error!(
                    "Failed to remove session {} on channel close: {:?}",
                    session_id, e
                );
            }
            self.session_id = None;
        }

        Ok((self, session))
    }
}

impl ProxyServer {
    fn get_username(&self) -> &str {
        self.username.as_deref().unwrap_or("unknown")
    }

    async fn send_prompt_with_cwd(&mut self, channel: ChannelId, session: &mut Session) {
        let cwd = if let Some(ref session_id) = self.session_id {
            self.get_session_cwd(session_id).await
        } else {
            None
        };

        self.renderer.send_prompt(
            channel,
            session,
            self.get_username(),
            &self.config.server.name,
            cwd.as_deref(),
        );
    }

    async fn get_session_cwd(&self, session_id: &str) -> Option<String> {
        if let Some(session_lock) = self.session_manager.get_session(session_id).await {
            let session_data = session_lock.read().await;

            return session_data
                .terminal_state
                .cwd
                .as_ref()
                .map(|p| p.to_string_lossy().to_string());
        }
        None
    }

    async fn update_session_cwd(&self, session_id: &str, cwd: &str) -> anyhow::Result<()> {
        let path = PathBuf::from(cwd);
        self.session_manager.update_cwd(session_id, path).await
    }

    fn send_error_and_prompt(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        error_msg: &str,
    ) {
        self.renderer
            .send_data(channel, session, error_msg.as_bytes());
        self.renderer.send_prompt(
            channel,
            session,
            self.get_username(),
            &self.config.server.name,
            None,
        );
    }

    async fn ensure_backend_connected(
        &mut self,
        session_id: &str,
    ) -> anyhow::Result<Arc<crate::backend::handler::BackendConnection>> {
        if let Ok(backend) = self.session_manager.get_backend(session_id).await {
            return Ok(backend);
        }

        let (backend, initial_cwd) = self
            .backend_pool
            .create_connection(None, self.username.as_deref(), self.password.as_deref())
            .await?;

        self.session_manager
            .set_backend(session_id, backend.clone())
            .await?;

        if let Some(cwd) = initial_cwd {
            let _ = self.update_session_cwd(session_id, &cwd).await;
        }

        info!("Backend connection established for session {}", session_id);
        Ok(backend)
    }

    async fn handle_empty_line(&mut self, channel: ChannelId, session: &mut Session) {
        self.send_prompt_with_cwd(channel, session).await;
    }

    async fn handle_exit_command(&mut self, channel: ChannelId, session: &mut Session) -> bool {
        if let Some(ref session_id) = self.session_id {
            if let Ok(backend) = self.session_manager.get_backend(session_id).await {
                let _ = backend.close().await;
            }

            if let Err(e) = self.session_manager.remove_session(session_id).await {
                error!("Failed to remove session {}: {:?}", session_id, e);
            }
            self.session_id = None;
        }

        self.renderer.clean_and_close(channel, session, None);
        true
    }

    async fn handle_post_execution(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
        _command: &str,
    ) {
        if let Some(session_lock) = self.session_manager.get_session(session_id).await {
            let session_data = session_lock.read().await;

            if let Some(ref cmd_info) = session_data.terminal_state.last_cmd {
                if let Some(target_backend) = self.detector.detect(cmd_info) {
                    drop(session_data);
                    info!("Detected attack pattern, migrating to: {}", target_backend);

                    if let Err(e) = self
                        .perform_migration(session_id, &target_backend, channel, session)
                        .await
                    {
                        error!("Migration failed: {:?}", e);
                    }
                }
            }
        }

        self.send_prompt_with_cwd(channel, session).await;
    }

    async fn execute_and_handle_command(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
        command: &str,
    ) {
        let backend = match self.ensure_backend_connected(session_id).await {
            Ok(backend) => backend,
            Err(e) => {
                error!("Failed to establish backend connection: {:?}", e);
                self.send_error_and_prompt(channel, session, "Failed to connect to backend\r\n");

                return;
            }
        };

        match backend.execute_command(command).await {
            Ok((output, cwd)) => {
                self.renderer.send_data(channel, session, &output);

                if let Some(new_cwd) = cwd {
                    if let Err(e) = self.update_session_cwd(session_id, &new_cwd).await {
                        warn!("Failed to update CWD: {:?}", e);
                    }
                }

                self.handle_post_execution(channel, session, session_id, command)
                    .await;
            }
            Err(e) => {
                error!("Command execution failed: {:?}", e);
                self.send_error_and_prompt(channel, session, "Command execution failed\r\n");
            }
        }
    }

    async fn perform_migration(
        &self,
        session_id: &str,
        target_backend: &str,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> anyhow::Result<()> {
        use anyhow::Context;

        let session_lock = self
            .session_manager
            .get_session(session_id)
            .await
            .context("Session not found")?;

        let current_cwd = {
            let session_data = session_lock.read().await;
            session_data.terminal_state.cwd.clone()
        };

        if let Ok(old_backend) = self.session_manager.get_backend(session_id).await {
            let _ = old_backend.close().await;
        }

        let (new_backend, _initial_cwd) = self
            .backend_pool
            .create_connection(
                Some(target_backend),
                self.username.as_deref(),
                self.password.as_deref(),
            )
            .await?;

        self.session_manager
            .set_backend(session_id, new_backend.clone())
            .await?;

        if let Some(cwd) = current_cwd {
            let cd_cmd = format!("cd {}", cwd.display());

            if let Ok((_, new_cwd)) = new_backend.execute_command(&cd_cmd).await {
                if let Some(verified_cwd) = new_cwd {
                    let _ = self.update_session_cwd(session_id, &verified_cwd).await;
                }
            }
            info!("Reproduced CWD: {}", cwd.display());
        }

        Ok(())
    }

    async fn handle_tab_completion(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
    ) {
        let current_buffer = self.reader.get_buffer_clone();

        let backend = match self.session_manager.get_backend(session_id).await {
            Ok(backend) => backend,
            Err(_) => {
                warn!("No backend available for tab completion");
                return;
            }
        };

        match backend.send_tab_completion(&current_buffer).await {
            Ok(output) => {
                if let Some(completed_line) =
                    crate::backend::handler::BackendConnection::extract_completed_line(&output)
                {
                    self.reader.replace_buffer(completed_line);
                } else {
                    warn!("Tab completion: no change detected");
                }

                let text = String::from_utf8_lossy(&output);
                let lines: Vec<&str> = text.lines().collect();

                if lines.len() > 1 {
                    self.renderer.send_newline(channel, session);

                    for line in &lines[..lines.len().saturating_sub(1)] {
                        let formatted = format!("{}\r\n", line);
                        self.renderer
                            .send_data(channel, session, formatted.as_bytes());
                    }
                }

                let username = self.get_username();
                let cwd = self.get_session_cwd(session_id).await;
                let buf = self.reader.buffer();
                let cursor = self.reader.cursor();

                self.renderer.redraw_line(
                    channel,
                    session,
                    username,
                    &self.config.server.name,
                    cwd.as_deref(),
                    buf,
                    cursor,
                );
            }
            Err(e) => {
                warn!("Tab completion failed: {:?}", e);
            }
        }
    }

    async fn run_argument_command(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
        command: &str,
    ) {
        let backend = match self.ensure_backend_connected(session_id).await {
            Ok(backend) => backend,
            Err(e) => {
                error!("Failed to establish backend connection: {:?}", e);
                let error_msg = "Failed to connect to backend\r\n";
                self.renderer
                    .send_data(channel, session, error_msg.as_bytes());
                session.exit_status_request(channel, 1);
                session.eof(channel);
                session.close(channel);

                return;
            }
        };

        match backend.execute_command(command).await {
            Ok((output, cwd)) => {
                self.renderer.send_data(channel, session, &output);

                let cwd_str = cwd
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "/".to_string());

                if let Some(session_lock) = self.session_manager.get_session(session_id).await {
                    let session_data = session_lock.read().await;
                    let username = session_data.username.clone();
                    drop(session_data);

                    let logger = self.session_manager.get_logger();
                    let logger_guard = logger.lock().await;
                    logger_guard.log_command_event("0.0.0.0", 0, &username, command, &cwd_str);
                    drop(logger_guard);
                }

                if let Some(new_cwd) = cwd {
                    if let Err(e) = self.update_session_cwd(session_id, &new_cwd).await {
                        warn!("Failed to update CWD: {:?}", e);
                    }
                }

                if let Some(session_lock) = self.session_manager.get_session(session_id).await {
                    let session_data = session_lock.read().await;

                    if let Some(ref cmd_info) = session_data.terminal_state.last_cmd {
                        if let Some(target_backend) = self.detector.detect(cmd_info) {
                            drop(session_data);
                            info!(
                                "Detected attack pattern in exec mode, migrating to: {}",
                                target_backend
                            );

                            if let Err(e) = self
                                .perform_migration(session_id, &target_backend, channel, session)
                                .await
                            {
                                error!("Migration failed: {:?}", e);
                            }
                        }
                    }
                }

                session.exit_status_request(channel, 0);
                session.eof(channel);
                session.close(channel);
            }
            Err(e) => {
                error!("Command execution failed: {:?}", e);
                let error_msg = "Command execution failed\r\n";
                self.renderer
                    .send_data(channel, session, error_msg.as_bytes());
                session.exit_status_request(channel, 1);
                session.eof(channel);
                session.close(channel);
            }
        }
    }
}

pub struct ProxyServerFactory {
    config: Arc<AppConfig>,
    session_manager: Arc<SessionManager>,
    backend_pool: Arc<BackendPool>,
    detector: Arc<dyn Detector>,
    accept_any: bool,
    allowed_users: Arc<HashSet<String>>,
    motd: String,
}

impl ProxyServerFactory {
    pub fn new(
        config: Arc<AppConfig>,
        session_manager: Arc<SessionManager>,
        backend_pool: Arc<BackendPool>,
        detector: Arc<dyn Detector>,
    ) -> Self {
        let accept_any = config.auth.accept_any;

        let mut allowed_users = HashSet::new();
        let primary = config.auth.user_db_path.clone();

        match load_allowed_usernames(&primary) {
            Ok(set) => allowed_users = set,
            Err(err) => {
                let fallback = std::path::PathBuf::from("config/user.txt");

                match load_allowed_usernames(&fallback) {
                    Ok(set) => allowed_users = set,
                    Err(err2) => {
                        warn!(
                            "Failed to load user db: {} ({}) and fallback {} ({})",
                            primary.display(),
                            err,
                            fallback.display(),
                            err2
                        );
                    }
                }
            }
        }

        let motd = return_motd("/config/motd.txt");

        Self {
            config,
            session_manager,
            backend_pool,
            detector,
            accept_any,
            allowed_users: Arc::new(allowed_users),
            motd,
        }
    }
}

impl server::Server for ProxyServerFactory {
    type Handler = ProxyServer;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        ProxyServer::new(
            self.config.clone(),
            self.session_manager.clone(),
            self.backend_pool.clone(),
            self.detector.clone(),
            self.accept_any,
            self.allowed_users.clone(),
            self.motd.clone(),
        )
    }
}

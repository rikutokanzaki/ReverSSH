use chrono::Utc;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use log::{error, info, warn};
use russh::MethodKind;
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, MethodSet};
use uuid::Uuid;

use crate::backend::handler::CommandEndReason;
use crate::backend::pool::BackendPool;
use crate::config::AppConfig;
use crate::proxy::authenticator::{Authentication, FileBasedAuthenticator};
use crate::proxy::motd::return_motd;
use crate::router::migration::Detector;
use crate::session::logger::CommandLogEvent;
use crate::session::manager::{SessionId, SessionManager};
use crate::terminal::reader::{InputEvent, LineReader};
use crate::terminal::renderer::Renderer;

pub struct ProxyServer {
    config: Arc<AppConfig>,
    session_manager: Arc<SessionManager>,
    backend_pool: Arc<BackendPool>,
    detector: Arc<dyn Detector>,
    peer_addr: Option<SocketAddr>,

    accept_any: bool,
    authenticator: Option<Arc<FileBasedAuthenticator>>,
    motd: String,

    session_id: Option<SessionId>,
    session_created: bool,
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
        peer_addr: Option<SocketAddr>,
        accept_any: bool,
        authenticator: Option<Arc<FileBasedAuthenticator>>,
        motd: String,
    ) -> Self {
        let renderer = Renderer::new();

        Self {
            config: config.clone(),
            session_manager,
            backend_pool,
            detector,
            peer_addr,
            accept_any,
            authenticator,
            motd,
            session_id: Some(Uuid::new_v4().to_string()),
            session_created: false,
            username: None,
            password: None,
            shell_active: false,
            exec_mode: false,
            reader: LineReader::new(config.server.history_size),
            renderer,
        }
    }
}

impl server::Handler for ProxyServer {
    type Error = anyhow::Error;

    fn auth_none(&mut self, _user: &str) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
                partial_success: false,
            })
        }
    }

    fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
                partial_success: false,
            })
        }
    }

    fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
                partial_success: false,
            })
        }
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let is_allowed = if self.accept_any {
            true
        } else if let Some(authenticator) = &self.authenticator {
            authenticator.auth(user, password).is_some()
        } else {
            false
        };

        let session_id = self.session_id.as_deref().unwrap_or("unknown");
        let (src_ip, src_port) = self.client_address();
        let (dest_ip, dest_port) = self.server_address();

        if is_allowed {
            self.username = Some(user.to_string());
            self.password = Some(password.to_string());

            let logger = self.session_manager.get_logger();
            let logger_guard = logger.lock().await;
            logger_guard.log_auth_event(
                session_id, &src_ip, src_port, &dest_ip, dest_port, user, password, true,
            );
            drop(logger_guard);

            info!("[AUTH SUCCESS] user={} password={}", user, password);
            return Ok(Auth::Accept);
        }

        let logger = self.session_manager.get_logger();
        let logger_guard = logger.lock().await;
        logger_guard.log_auth_event(
            session_id, &src_ip, src_port, &dest_ip, dest_port, user, password, false,
        );
        drop(logger_guard);

        info!("[AUTH REJECTED] user={} password={}", user, password);
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shell_active = true;

        if let (Some(username), Some(password)) = (self.username.as_ref(), self.password.as_ref()) {
            let session_id = self
                .session_id
                .clone()
                .expect("session id must exist for accepted connections");

            match self
                .session_manager
                .create_session(
                    session_id.clone(),
                    username.clone(),
                    password.clone(),
                    channel,
                )
                .await
            {
                Ok(session_id) => {
                    self.session_id = Some(session_id.clone());
                    self.session_created = true;
                    info!("Session {} created for user {}", session_id, username);
                    info!(
                        "[SESSION START - SHELL] session_id={} user={}",
                        session_id, username
                    );
                }
                Err(e) => {
                    error!("Failed to create session for user {}: {:?}", username, e);
                }
            }
        }

        let _ = session.channel_success(channel);

        self.renderer.send_newline(channel, session);

        self.renderer
            .send_data(channel, session, self.motd.as_bytes());

        self.send_prompt_with_cwd(channel, session).await;

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.exec_mode = true;

        let command = String::from_utf8_lossy(data).to_string();
        info!("Exec request: {}", command);

        let (username, password) = match (&self.username, &self.password) {
            (Some(u), Some(p)) => (u.clone(), p.clone()),
            _ => {
                error!("No credentials available for exec request");
                let error_msg = "Authentication required\r\n";
                self.renderer
                    .send_data(channel, session, error_msg.as_bytes());

                let _ = session.exit_status_request(channel, 1);
                let _ = session.eof(channel);
                let _ = session.close(channel);

                return Ok(());
            }
        };

        let session_id = match self
            .session_manager
            .create_session(
                self.session_id
                    .clone()
                    .expect("session id must exist for accepted connections"),
                username.clone(),
                password.clone(),
                channel,
            )
            .await
        {
            Ok(session_id) => {
                info!("Exec session {} created for user {}", session_id, username);
                self.session_created = true;
                info!(
                    "[SESSION START - EXEC] session_id={} user={} command={}",
                    session_id, username, command
                );
                session_id
            }
            Err(e) => {
                error!(
                    "Failed to create exec session for user {}: {:?}",
                    username, e
                );
                let error_msg = "Failed to create session\r\n";
                self.renderer
                    .send_data(channel, session, error_msg.as_bytes());
                let _ = session.exit_status_request(channel, 1);
                let _ = session.eof(channel);
                let _ = session.close(channel);

                return Ok(());
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

        self.run_argument_command(channel, session, &session_id, &command)
            .await;

        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
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

        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.shell_active {
            return Ok(());
        }

        let events = self.reader.feed_bytes(data);

        for event in events {
            if matches!(event, InputEvent::Tab) {
                if let Some(session_id) = self.session_id.clone() {
                    self.handle_tab_completion(channel, session, &session_id)
                        .await;
                }
                continue;
            }

            if let Some(line) = self.reader.apply(event) {
                self.renderer.send_newline(channel, session);

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
                    self.handle_empty_line(channel, session).await;
                    continue;
                }

                if trimmed == "exit" || trimmed == "logout" {
                    if self.handle_exit_command(channel, session).await {
                        return Ok(());
                    }
                    continue;
                }

                if let Some(session_id) = self.session_id.clone() {
                    self.execute_and_handle_command(channel, session, &session_id, trimmed)
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
                    session,
                    username,
                    &self.config.server.name,
                    cwd.as_deref(),
                    buf,
                    cursor,
                );
            }
        }

        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.session_created {
            if let Some(ref session_id) = self.session_id {
                self.log_session_close(session_id, "Channel closed", "channel_close")
                    .await;

                if let Err(e) = self.session_manager.remove_session(session_id).await {
                    error!(
                        "Failed to remove session {} on channel close: {:?}",
                        session_id, e
                    );
                }
            }

            self.session_created = false;
            self.session_id = None;
        }

        Ok(())
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
        if self.session_created {
            if let Some(ref session_id) = self.session_id {
                self.log_session_close(session_id, "Client requested exit", "exit_command")
                    .await;

                if let Ok(backend) = self.session_manager.get_backend(session_id).await {
                    let _ = backend.close().await;
                }

                if let Err(e) = self.session_manager.remove_session(session_id).await {
                    error!("Failed to remove session {}: {:?}", session_id, e);
                }
            }

            self.session_created = false;
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
                    let resolved_backend = self
                        .config
                        .migration
                        .get(target_backend.as_str())
                        .map(|s| s.as_str())
                        .unwrap_or(target_backend.as_str());

                    if resolved_backend != target_backend.as_str() {
                        info!(
                            "Detected attack pattern, migrating to: {} (mapped from {})",
                            resolved_backend, target_backend
                        );
                    } else {
                        info!(
                            "Detected attack pattern, migrating to: {}",
                            resolved_backend
                        );
                    }

                    if let Err(e) = self
                        .perform_migration(session_id, resolved_backend, channel, session)
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
                let error_message = e.to_string();
                error!("Failed to establish backend connection: {:?}", e);

                self.send_error_and_prompt(channel, session, "Failed to connect to backend\r\n");

                self.log_command_execution(
                    session_id,
                    command,
                    None,
                    None,
                    Some(error_message.as_str()),
                    None,
                    Utc::now(),
                    0,
                    false,
                    &CommandEndReason::ExitStatus,
                )
                .await;

                return;
            }
        };

        match backend.execute_command(command).await {
            Ok(result) => {
                self.renderer
                    .send_data(channel, session, &result.displayed_output);
                let response_cwd = result.cwd.clone();

                self.log_command_execution(
                    session_id,
                    command,
                    Some(&result.raw_output),
                    Some(&result.displayed_output),
                    None,
                    response_cwd.as_deref(),
                    result.first_response_timestamp,
                    result.first_response_latency_ms,
                    result.prompt_returned,
                    &result.end_reason,
                )
                .await;

                if let Some(new_cwd) = response_cwd {
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
                let error_message = e.to_string();
                self.log_command_execution(
                    session_id,
                    command,
                    None,
                    None,
                    Some(error_message.as_str()),
                    None,
                    Utc::now(),
                    0,
                    false,
                    &CommandEndReason::ExitStatus,
                )
                .await;
            }
        }
    }

    async fn perform_migration(
        &self,
        session_id: &str,
        target_backend: &str,
        _channel: ChannelId,
        mut _session: &mut Session,
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

            if let Ok(result) = new_backend.execute_command(&cd_cmd).await {
                if let Some(verified_cwd) = result.cwd {
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
                let error_message = e.to_string();
                error!("Failed to establish backend connection: {:?}", e);
                let error_msg = "Failed to connect to backend\r\n";
                self.renderer
                    .send_data(channel, session, error_msg.as_bytes());
                self.log_command_execution(
                    session_id,
                    command,
                    None,
                    None,
                    Some(error_message.as_str()),
                    None,
                    Utc::now(),
                    0,
                    false,
                    &CommandEndReason::ExitStatus,
                )
                .await;
                let _ = session.exit_status_request(channel, 1);
                let _ = session.eof(channel);
                let _ = session.close(channel);

                return;
            }
        };

        match backend.execute_command(command).await {
            Ok(result) => {
                self.renderer
                    .send_data(channel, session, &result.displayed_output);
                let response_cwd = result.cwd.clone();

                self.log_command_execution(
                    session_id,
                    command,
                    Some(&result.raw_output),
                    Some(&result.displayed_output),
                    None,
                    response_cwd.as_deref(),
                    result.first_response_timestamp,
                    result.first_response_latency_ms,
                    result.prompt_returned,
                    &result.end_reason,
                )
                .await;

                let cwd_str = response_cwd.clone().unwrap_or_else(|| "/".to_string());

                if let Some(session_lock) = self.session_manager.get_session(session_id).await {
                    let session_data = session_lock.read().await;
                    let username = session_data.username.clone();
                    drop(session_data);

                    info!(
                        "[COMMAND EXECUTED] session_id={} user={} cmd={} cwd={}",
                        session_id, username, command, cwd_str
                    );
                }

                if let Some(new_cwd) = response_cwd {
                    if let Err(e) = self.update_session_cwd(session_id, &new_cwd).await {
                        warn!("Failed to update CWD: {:?}", e);
                    }
                }

                if let Some(session_lock) = self.session_manager.get_session(session_id).await {
                    let session_data = session_lock.read().await;

                    if let Some(ref cmd_info) = session_data.terminal_state.last_cmd {
                        if let Some(target_backend) = self.detector.detect(cmd_info) {
                            drop(session_data);
                            let resolved_backend = self
                                .config
                                .migration
                                .get(target_backend.as_str())
                                .map(|s| s.as_str())
                                .unwrap_or(target_backend.as_str());

                            info!(
                                "Detected attack pattern in exec mode, migrating to: {}{}",
                                resolved_backend,
                                if resolved_backend != target_backend.as_str() {
                                    " (mapped)"
                                } else {
                                    ""
                                }
                            );

                            if let Err(e) = self
                                .perform_migration(session_id, resolved_backend, channel, session)
                                .await
                            {
                                error!("Migration failed: {:?}", e);
                            }
                        }
                    }
                }

                let _ = session.exit_status_request(channel, 0);
                let _ = session.eof(channel);
                info!(
                    "[SESSION EXIT] session_id={} exit_point=exec_success",
                    session_id
                );
                let _ = session.close(channel);
            }
            Err(e) => {
                error!("Command execution failed: {:?}", e);
                let error_msg = "Command execution failed\r\n";
                self.renderer
                    .send_data(channel, session, error_msg.as_bytes());
                let error_message = e.to_string();
                self.log_command_execution(
                    session_id,
                    command,
                    None,
                    None,
                    Some(error_message.as_str()),
                    None,
                    Utc::now(),
                    0,
                    false,
                    &CommandEndReason::ExitStatus,
                )
                .await;
                let _ = session.exit_status_request(channel, 1);
                let _ = session.eof(channel);
                info!(
                    "[SESSION EXIT] session_id={} exit_point=exec_error error={:?}",
                    session_id, e
                );
                let _ = session.close(channel);
            }
        }
    }

    async fn log_command_execution(
        &self,
        session_id: &str,
        command: &str,
        backend_response_raw: Option<&[u8]>,
        backend_response_displayed: Option<&[u8]>,
        backend_response_error: Option<&str>,
        cwd_override: Option<&str>,
        response_timestamp: chrono::DateTime<Utc>,
        response_latency_ms: i64,
        prompt_returned: bool,
        end_reason: &CommandEndReason,
    ) {
        let session_lock = match self.session_manager.get_session(session_id).await {
            Some(session_lock) => session_lock,
            None => return,
        };

        let session_data = session_lock.read().await;
        let username = session_data.username.clone();
        let cwd = cwd_override
            .map(|path| path.to_string())
            .or_else(|| {
                session_data
                    .terminal_state
                    .cwd
                    .as_ref()
                    .map(|path| path.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| "/".to_string());
        let input_timestamp = session_data
            .terminal_state
            .last_cmd
            .as_ref()
            .map(|cmd_info| cmd_info.ts)
            .unwrap_or(response_timestamp);
        let command_id = session_data
            .terminal_state
            .last_cmd
            .as_ref()
            .map(|cmd_info| cmd_info.command_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        drop(session_data);

        let raw_response =
            backend_response_raw.map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        let displayed_response =
            backend_response_displayed.map(|bytes| String::from_utf8_lossy(bytes).into_owned());

        let logger = self.session_manager.get_logger();
        let logger_guard = logger.lock().await;
        let (src_ip, src_port) = self.client_address();

        logger_guard.log_command_event(&CommandLogEvent {
            session_id,
            command_id: &command_id,
            src_ip: &src_ip,
            src_port,
            username: &username,
            command,
            cwd: &cwd,
            input_timestamp,
            response_timestamp,
            response_latency_ms,
            prompt_returned,
            end_reason: match end_reason {
                CommandEndReason::Prompt => "prompt",
                CommandEndReason::ExitStatus => "exit_status",
                CommandEndReason::Eof => "eof",
                CommandEndReason::Timeout => "timeout",
            },
            backend_response_raw: raw_response.as_deref(),
            backend_response_displayed: displayed_response.as_deref(),
            backend_response_error,
            success: backend_response_error.is_none(),
        });
    }

    async fn log_session_close(&self, session_id: &str, message: &str, exit_point: &str) {
        if !self.session_created {
            return;
        }

        let session_lock = match self.session_manager.get_session(session_id).await {
            Some(session_lock) => session_lock,
            None => return,
        };

        let session_data = session_lock.read().await;
        let username = session_data.username.clone();
        let started_at = session_data.started_at;
        drop(session_data);

        let duration_secs = Utc::now()
            .signed_duration_since(started_at)
            .num_milliseconds() as f64
            / 1000.0;

        let logger = self.session_manager.get_logger();
        let logger_guard = logger.lock().await;
        let (src_ip, src_port) = self.client_address();
        logger_guard.log_session_close(
            session_id,
            &src_ip,
            src_port,
            &username,
            duration_secs,
            message,
        );
        drop(logger_guard);

        info!(
            "[SESSION EXIT] session_id={} user={} exit_point={}",
            session_id, username, exit_point
        );
    }

    fn client_address(&self) -> (String, u16) {
        self.peer_addr
            .map(|addr| (addr.ip().to_string(), addr.port()))
            .unwrap_or_else(|| ("unknown".to_string(), 0))
    }

    fn server_address(&self) -> (String, u16) {
        (
            self.config.server.listen_addr.ip().to_string(),
            self.config.server.listen_addr.port(),
        )
    }
}

pub struct ProxyServerFactory {
    config: Arc<AppConfig>,
    session_manager: Arc<SessionManager>,
    backend_pool: Arc<BackendPool>,
    detector: Arc<dyn Detector>,
    accept_any: bool,
    authenticator: Option<Arc<FileBasedAuthenticator>>,
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

        let mut authenticator: Option<Arc<FileBasedAuthenticator>> = None;
        let primary = config.auth.user_db_path.clone();

        match FileBasedAuthenticator::new(primary.to_string_lossy().as_ref()) {
            Ok(auth) => authenticator = Some(Arc::new(auth)),
            Err(err) => {
                let fallback = std::path::PathBuf::from("config/user.txt");

                match FileBasedAuthenticator::new(fallback.to_string_lossy().as_ref()) {
                    Ok(auth) => authenticator = Some(Arc::new(auth)),
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
            authenticator,
            motd,
        }
    }
}

impl server::Server for ProxyServerFactory {
    type Handler = ProxyServer;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        ProxyServer::new(
            self.config.clone(),
            self.session_manager.clone(),
            self.backend_pool.clone(),
            self.detector.clone(),
            peer_addr,
            self.accept_any,
            self.authenticator.clone(),
            self.motd.clone(),
        )
    }
}

use anyhow::Context;
use chrono::Utc;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use log::{error, info, warn};
use russh::MethodKind;
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, MethodSet};
use uuid::Uuid;

use crate::client::handler::{Client, CommandEndReason, CommandExecutionResult};
use crate::proxy::authenticator::{Authentication, FileBasedAuthenticator};
use crate::proxy::context::ProxyContext;
use crate::session::manager::SessionId;
use crate::terminal::parser::TerminalOutputParser;
use crate::terminal::reader::{InputEvent, LineReader};
use crate::terminal::renderer::Renderer;
use crate::terminal::state::CmdInfo;

pub struct ProxyServer {
    pub(super) context: Arc<ProxyContext>,
    pub(super) peer_addr: Option<SocketAddr>,

    pub(super) accept_any: bool,
    pub(super) authenticator: Option<Arc<FileBasedAuthenticator>>,
    pub(super) motd: String,

    pub(super) session_id: Option<SessionId>,
    pub(super) session_created: bool,
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    pub(super) authenticated_backend: Option<String>,
    pub(super) shell_active: bool,
    pub(super) exec_mode: bool,
    pub(super) reader: LineReader,
    pub(super) renderer: Renderer,
}

#[derive(Copy, Clone)]
pub(super) enum CommandExecutionMode {
    Shell,
    Exec,
}

impl ProxyServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: Arc<ProxyContext>,
        peer_addr: Option<SocketAddr>,
        accept_any: bool,
        authenticator: Option<Arc<FileBasedAuthenticator>>,
        motd: String,
    ) -> Self {
        let renderer = Renderer::new();

        Self {
            context: context.clone(),
            peer_addr,
            accept_any,
            authenticator,
            motd,
            session_id: Some(Uuid::new_v4().to_string()),
            session_created: false,
            username: None,
            password: None,
            authenticated_backend: None,
            shell_active: false,
            exec_mode: false,
            reader: LineReader::new(context.config.server.history_size),
            renderer,
        }
    }
}

impl server::Handler for ProxyServer {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
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

        if is_allowed {
            self.username = Some(user.to_string());
            self.password = Some(password.to_string());
            let authenticated_backend = self
                .context
                .client_pool
                .interaction_backend_for_auth(user, password)
                .await;
            self.authenticated_backend = authenticated_backend.clone();

            let destination = match authenticated_backend.as_deref() {
                Some(name) => self.context.client_pool.get_backend_config(name).await,
                None => None,
            };

            let logger = self.context.session_manager.get_logger();
            let logger_guard = logger.lock().await;
            logger_guard.log_auth_event(
                session_id,
                &src_ip,
                src_port,
                authenticated_backend.as_deref(),
                destination.as_ref().map(|config| config.hostname.as_str()),
                destination.as_ref().map(|config| config.port),
                user,
                password,
                true,
            );
            drop(logger_guard);

            info!("[AUTH SUCCESS] user={} password={}", user, password);
            return Ok(Auth::Accept);
        }

        let destination = self
            .context
            .client_pool
            .credential_backend_for_auth(user, password)
            .await;
        let logger = self.context.session_manager.get_logger();
        let logger_guard = logger.lock().await;
        logger_guard.log_auth_event(
            session_id,
            &src_ip,
            src_port,
            destination.as_ref().map(|config| config.name.as_str()),
            destination.as_ref().map(|config| config.hostname.as_str()),
            destination.as_ref().map(|config| config.port),
            user,
            password,
            false,
        );
        drop(logger_guard);

        if let Err(error) = self
            .context
            .client_pool
            .observe_failed_auth(user, password)
            .await
        {
            warn!(
                "Failed to observe rejected authentication for user {}: {:?}",
                user, error
            );
        }

        info!("[AUTH REJECTED] user={} password={}", user, password);
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
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
        self.confirm_channel(channel, session, "pty_request");
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shell_active = true;

        if self.username.is_some()
            && self.password.is_some()
            && let Err(e) = self
                .create_session_for_channel(channel, CommandExecutionMode::Shell, None)
                .await
        {
            error!("Failed to create shell session: {:?}", e);
        }

        self.confirm_channel(channel, session, "shell_request");

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

        if self.username.is_none() || self.password.is_none() {
            error!("No credentials available for exec request");
            let error_msg = "Authentication required\r\n";
            self.renderer
                .send_data(channel, session, error_msg.as_bytes());

            self.terminate_channel(channel, session, 1, "exec_auth_required")
                .await;

            return Ok(());
        }

        let session_id = match self
            .create_session_for_channel(channel, CommandExecutionMode::Exec, Some(&command))
            .await
        {
            Ok(session_id) => session_id,
            Err(error) => {
                error!("Failed to create exec session: {:?}", error);
                let error_msg = "Failed to create session\r\n";
                self.renderer
                    .send_data(channel, session, error_msg.as_bytes());

                self.terminate_channel(channel, session, 1, "exec_session_create_failed")
                    .await;

                return Ok(());
            }
        };

        if let Err(e) = self
            .context
            .session_manager
            .push_command(&session_id, command.clone())
            .await
        {
            warn!("Failed to record command: {:?}", e);
        }

        self.handle_exec_request(channel, session, &session_id, &command)
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
        if let Some(ref session_id) = self.session_id
            && let Err(e) = self
                .context
                .session_manager
                .update_window_size(session_id, col_width as u16, row_height as u16)
                .await
        {
            warn!(
                "Failed to update window size for session {}: {:?}",
                session_id, e
            );
        }

        self.confirm_channel(channel, session, "window_change_request");
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

                if let Some(ref session_id) = self.session_id
                    && let Err(e) = self
                        .context
                        .session_manager
                        .push_command(session_id, trimmed.to_string())
                        .await
                {
                    warn!("Failed to record command: {:?}", e);
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
                    self.handle_shell_command(channel, session, &session_id, trimmed)
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
                    &self.context.config.server.name,
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

                if let Err(e) = self
                    .context
                    .session_manager
                    .remove_session(session_id)
                    .await
                {
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
            &self.context.config.server.name,
            cwd.as_deref(),
        );
    }

    async fn get_session_cwd(&self, session_id: &str) -> Option<String> {
        if let Some(session_lock) = self.context.session_manager.get_session(session_id).await {
            let session_data = session_lock.read().await;

            return session_data
                .terminal_state
                .cwd
                .as_ref()
                .map(|p| p.to_string_lossy().to_string());
        }
        None
    }

    pub(super) async fn update_session_cwd(
        &self,
        session_id: &str,
        cwd: &str,
    ) -> anyhow::Result<()> {
        let path = PathBuf::from(cwd);
        self.context
            .session_manager
            .update_cwd(session_id, path)
            .await
    }

    fn confirm_channel(&self, channel: ChannelId, session: &mut Session, context: &str) {
        if let Err(e) = session.channel_success(channel) {
            warn!("Failed to confirm channel in {}: {:?}", context, e);
        }
    }

    async fn terminate_channel(
        &self,
        channel: ChannelId,
        session: &mut Session,
        exit_status: u32,
        context: &str,
    ) {
        if let Err(e) = session.exit_status_request(channel, exit_status) {
            warn!(
                "Failed to send exit status for {} ({}): {:?}",
                context, exit_status, e
            );
        }
        if let Err(e) = session.eof(channel) {
            warn!("Failed to send EOF for {}: {:?}", context, e);
        }
        if let Err(e) = session.close(channel) {
            warn!("Failed to close channel for {}: {:?}", context, e);
        }
    }

    async fn send_command_error(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        mode: CommandExecutionMode,
        error_msg: &str,
    ) {
        self.renderer
            .send_data(channel, session, error_msg.as_bytes());

        if matches!(mode, CommandExecutionMode::Shell) {
            self.send_prompt_with_cwd(channel, session).await;
        }
    }

    pub(super) async fn ensure_backend_connected(
        &mut self,
        session_id: &str,
    ) -> anyhow::Result<Arc<Client>> {
        if let Ok(backend) = self.context.session_manager.get_backend(session_id).await {
            return Ok(backend);
        }

        let preferred_backend = self.authenticated_backend.take();
        let (backend, initial_cwd) = self
            .context
            .client_pool
            .create_connection(
                preferred_backend.as_deref(),
                self.username.as_deref(),
                self.password.as_deref(),
            )
            .await?;

        self.context
            .session_manager
            .set_backend(session_id, backend.clone())
            .await?;

        self.initialize_session_cwd(session_id, initial_cwd).await;

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

                if let Ok(backend) = self.context.session_manager.get_backend(session_id).await
                    && let Err(e) = backend.close().await
                {
                    warn!(
                        "Failed to close backend for session {} on exit: {:?}",
                        session_id, e
                    );
                }

                if let Err(e) = self
                    .context
                    .session_manager
                    .remove_session(session_id)
                    .await
                {
                    error!("Failed to remove session {}: {:?}", session_id, e);
                }
            }

            self.session_created = false;
            self.session_id = None;
        }

        self.renderer.clean_and_close(channel, session, None);
        true
    }

    async fn handle_command_execution(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
        command: &str,
        mode: CommandExecutionMode,
    ) {
        let command_info = CmdInfo::new_with_generated_id(self.get_username(), command);
        if let Some(target_backend) = self.resolve_migration_target(&command_info)
            && self.should_migrate(session_id, &target_backend).await
            && let Err(error) = self.perform_migration(session_id, &target_backend).await
        {
            error!(
                "Failed to route command '{}' to backend '{}': {:?}",
                command, target_backend, error
            );
        }

        let backend = match self.ensure_backend_connected(session_id).await {
            Ok(backend) => backend,
            Err(e) => {
                let error_message = e.to_string();
                error!("Failed to establish backend connection: {:?}", e);

                self.send_command_error(channel, session, mode, "Failed to connect to backend\r\n")
                    .await;

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

                if matches!(mode, CommandExecutionMode::Exec) {
                    self.terminate_channel(channel, session, 1, "exec_backend_error")
                        .await;
                    info!(
                        "[SESSION EXIT] session_id={} exit_point=exec_backend_error",
                        session_id
                    );
                }

                return;
            }
        };

        match backend.execute_command(command).await {
            Ok(result) => {
                self.handle_command_success(channel, session, session_id, command, mode, result)
                    .await;
            }
            Err(e) => {
                error!("Command execution failed: {:?}", e);
                let error_message = e.to_string();

                self.send_command_error(channel, session, mode, "Command execution failed\r\n")
                    .await;

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

                if matches!(mode, CommandExecutionMode::Exec) {
                    self.terminate_channel(channel, session, 1, "exec_error")
                        .await;
                    info!(
                        "[SESSION EXIT] session_id={} exit_point=exec_error error={:?}",
                        session_id, e
                    );
                }
            }
        }
    }

    fn resolve_migration_target(&self, command_info: &CmdInfo) -> Option<String> {
        let detected_backend = self.context.detector.detect(
            command_info,
            self.get_username(),
            self.password.as_deref().unwrap_or(""),
        )?;

        Some(
            self.context
                .config
                .migration
                .get(detected_backend.as_str())
                .cloned()
                .unwrap_or(detected_backend),
        )
    }

    async fn should_migrate(&self, session_id: &str, target_backend: &str) -> bool {
        self.context
            .session_manager
            .get_backend(session_id)
            .await
            .map(|backend| backend.name != target_backend)
            .unwrap_or(true)
    }

    async fn handle_command_success(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
        command: &str,
        mode: CommandExecutionMode,
        result: CommandExecutionResult,
    ) {
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

        let cwd_str = response_cwd.as_deref().unwrap_or("/");

        if let Some(session_lock) = self.context.session_manager.get_session(session_id).await {
            let session_data = session_lock.read().await;
            let username = session_data.username.clone();
            drop(session_data);

            info!(
                "[COMMAND EXECUTED] session_id={} user={} cmd={} cwd={}",
                session_id, username, command, cwd_str
            );
        }

        if let Some(new_cwd) = response_cwd
            && let Err(e) = self.update_session_cwd(session_id, &new_cwd).await
        {
            warn!("Failed to update CWD: {:?}", e);
        }

        self.handle_detection_and_migration(channel, session, session_id, mode)
            .await;
    }

    async fn create_session_for_channel(
        &mut self,
        channel: ChannelId,
        mode: CommandExecutionMode,
        command: Option<&str>,
    ) -> anyhow::Result<SessionId> {
        let username = self.username.clone().context("username is not available")?;
        let password = self.password.clone().context("password is not available")?;
        let session_id = self
            .context
            .session_manager
            .create_session(
                self.session_id
                    .clone()
                    .context("session id must exist for accepted connections")?,
                username.clone(),
                password,
                channel,
            )
            .await?;

        self.session_id = Some(session_id.clone());
        self.session_created = true;

        match mode {
            CommandExecutionMode::Shell => {
                info!("Session {} created for user {}", session_id, username);
                info!(
                    "[SESSION START - SHELL] session_id={} user={}",
                    session_id, username
                );
            }
            CommandExecutionMode::Exec => {
                info!("Exec session {} created for user {}", session_id, username);
                info!(
                    "[SESSION START - EXEC] session_id={} user={} command={}",
                    session_id,
                    username,
                    command.unwrap_or_default()
                );
            }
        }

        Ok(session_id)
    }

    async fn handle_detection_and_migration(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        _session_id: &str,
        mode: CommandExecutionMode,
    ) {
        match mode {
            CommandExecutionMode::Shell => {
                self.send_prompt_with_cwd(channel, session).await;
            }
            CommandExecutionMode::Exec => {
                self.terminate_channel(channel, session, 0, "exec_success")
                    .await;
            }
        }
    }

    pub(super) async fn session_cwd(&self, session_id: &str) -> anyhow::Result<Option<PathBuf>> {
        let session_lock = self
            .context
            .session_manager
            .get_session(session_id)
            .await
            .context("Session not found")?;

        let session_data = session_lock.read().await;
        Ok(session_data.terminal_state.cwd.clone())
    }

    async fn handle_tab_completion(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
    ) {
        let current_buffer = self.reader.get_buffer_clone();

        let backend = match self.context.session_manager.get_backend(session_id).await {
            Ok(backend) => backend,
            Err(_) => {
                warn!("No backend available for tab completion");
                return;
            }
        };

        match backend.send_tab_completion(&current_buffer).await {
            Ok(output) => {
                if let Some(completed_line) = TerminalOutputParser::extract_completed_line(&output)
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
                    &self.context.config.server.name,
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

    async fn handle_shell_command(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
        command: &str,
    ) {
        self.handle_command_execution(
            channel,
            session,
            session_id,
            command,
            CommandExecutionMode::Shell,
        )
        .await;
    }

    async fn handle_exec_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        session_id: &str,
        command: &str,
    ) {
        self.handle_command_execution(
            channel,
            session,
            session_id,
            command,
            CommandExecutionMode::Exec,
        )
        .await;
    }

    pub(super) fn client_address(&self) -> (String, u16) {
        self.peer_addr
            .map(|addr| (addr.ip().to_string(), addr.port()))
            .unwrap_or_else(|| ("unknown".to_string(), 0))
    }
}

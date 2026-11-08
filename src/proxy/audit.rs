use chrono::Utc;

use crate::client::handler::CommandEndReason;
use crate::proxy::server::ProxyServer;
use crate::session::logger::CommandLogEvent;

pub(super) struct CommandExecutionAudit<'a> {
    pub(super) session_id: &'a str,
    pub(super) command: &'a str,
    pub(super) backend_response_raw: Option<&'a [u8]>,
    pub(super) backend_response_displayed: Option<&'a [u8]>,
    pub(super) backend_response_error: Option<&'a str>,
    pub(super) cwd_override: Option<&'a str>,
    pub(super) response_timestamp: chrono::DateTime<Utc>,
    pub(super) response_latency_ms: i64,
    pub(super) prompt_returned: bool,
    pub(super) end_reason: &'a CommandEndReason,
}

impl ProxyServer {
    pub(super) async fn log_command_execution(&self, audit: CommandExecutionAudit<'_>) {
        let Some(session_lock) = self
            .context
            .session_manager
            .get_session(audit.session_id)
            .await
        else {
            return;
        };
        let session_data = session_lock.read().await;
        let username = session_data.username.clone();
        let cwd = audit
            .cwd_override
            .map(str::to_string)
            .or_else(|| {
                session_data
                    .terminal_state
                    .cwd
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "/".to_string());
        let input_timestamp = session_data
            .terminal_state
            .last_cmd
            .as_ref()
            .map(|cmd| cmd.ts)
            .unwrap_or(audit.response_timestamp);
        let command_id = session_data
            .terminal_state
            .last_cmd
            .as_ref()
            .map(|cmd| cmd.command_id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        drop(session_data);

        let destination = self
            .context
            .session_manager
            .get_backend(audit.session_id)
            .await
            .ok();
        let destination_name = destination.as_ref().map(|backend| backend.name.clone());
        let destination_config = match destination_name.as_deref() {
            Some(name) => self.context.client_pool.get_backend_config(name).await,
            None => None,
        };
        let raw_response = audit
            .backend_response_raw
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        let displayed_response = audit
            .backend_response_displayed
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        let (src_ip, src_port) = self.client_address();
        let logger = self.context.session_manager.get_logger();
        let logger_guard = logger.lock().await;

        logger_guard.log_command_event(&CommandLogEvent {
            session_id: audit.session_id,
            command_id: &command_id,
            src_ip: &src_ip,
            src_port,
            username: &username,
            command: audit.command,
            cwd: &cwd,
            input_timestamp,
            response_timestamp: audit.response_timestamp,
            response_latency_ms: audit.response_latency_ms,
            prompt_returned: audit.prompt_returned,
            end_reason: match audit.end_reason {
                CommandEndReason::Prompt => "prompt",
                CommandEndReason::ExitStatus => "exit_status",
                CommandEndReason::Eof => "eof",
                CommandEndReason::Timeout => "timeout",
            },
            backend_response_raw: raw_response.as_deref(),
            backend_response_displayed: displayed_response.as_deref(),
            backend_response_error: audit.backend_response_error,
            success: audit.backend_response_error.is_none(),
            dest_backend: destination_name.as_deref(),
            dest_ip: destination_config
                .as_ref()
                .map(|config| config.hostname.as_str()),
            dest_port: destination_config.as_ref().map(|config| config.port),
        });
    }

    pub(super) async fn log_session_close(
        &self,
        session_id: &str,
        message: &str,
        exit_point: &str,
    ) {
        if !self.session_created {
            return;
        }

        let Some(session_lock) = self.context.session_manager.get_session(session_id).await else {
            return;
        };
        let session_data = session_lock.read().await;
        let username = session_data.username.clone();
        let duration_secs = Utc::now()
            .signed_duration_since(session_data.started_at)
            .num_milliseconds() as f64
            / 1000.0;

        drop(session_data);

        let (src_ip, src_port) = self.client_address();
        let logger = self.context.session_manager.get_logger();
        let logger_guard = logger.lock().await;
        logger_guard.log_session_close(
            session_id,
            &src_ip,
            src_port,
            &username,
            duration_secs,
            message,
        );

        drop(logger_guard);

        log::info!(
            "[SESSION EXIT] session_id={} user={} exit_point={}",
            session_id,
            username,
            exit_point
        );
    }
}

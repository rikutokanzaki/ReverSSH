use chrono::{DateTime, Utc};
use log::warn;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) struct CommandLogEvent<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) command_id: &'a str,
    pub(crate) src_ip: &'a str,
    pub(crate) src_port: u16,
    pub(crate) username: &'a str,
    pub(crate) command: &'a str,
    pub(crate) cwd: &'a str,
    pub(crate) input_timestamp: DateTime<Utc>,
    pub(crate) response_timestamp: DateTime<Utc>,
    pub(crate) response_latency_ms: i64,
    pub(crate) prompt_returned: bool,
    pub(crate) end_reason: &'a str,
    pub(crate) backend_response_raw: Option<&'a str>,
    pub(crate) backend_response_displayed: Option<&'a str>,
    pub(crate) backend_response_error: Option<&'a str>,
    pub(crate) success: bool,
    pub(crate) dest_backend: Option<&'a str>,
    pub(crate) dest_ip: Option<&'a str>,
    pub(crate) dest_port: Option<u16>,
}

#[derive(Serialize)]
struct AuthLogEntry<'a> {
    timestamp: String,
    #[serde(rename = "type")]
    event_type: &'a str,
    eventid: &'a str,
    session_id: &'a str,
    src_ip: &'a str,
    src_port: u16,
    dest_backend: Option<&'a str>,
    dest_ip: Option<&'a str>,
    dest_port: Option<u16>,
    username: &'a str,
    password: &'a str,
    protocol: &'a str,
    success: bool,
}

#[derive(Serialize)]
struct CommandLogEntry<'a> {
    timestamp: String,
    #[serde(rename = "type")]
    event_type: &'a str,
    eventid: &'a str,
    session_id: &'a str,
    command_id: &'a str,
    src_ip: &'a str,
    src_port: u16,
    username: &'a str,
    command: &'a str,
    cwd: &'a str,
    input_timestamp: String,
    response_timestamp: String,
    response_latency_ms: i64,
    prompt_returned: bool,
    end_reason: &'a str,
    backend_response_raw: Option<&'a str>,
    backend_response_displayed: Option<&'a str>,
    backend_response_error: Option<&'a str>,
    success: bool,
    protocol: &'a str,
    dest_backend: Option<&'a str>,
    dest_ip: Option<&'a str>,
    dest_port: Option<u16>,
}

#[derive(Serialize)]
struct SessionCloseLogEntry<'a> {
    timestamp: String,
    #[serde(rename = "type")]
    event_type: &'a str,
    eventid: &'a str,
    session_id: &'a str,
    src_ip: &'a str,
    src_port: u16,
    username: &'a str,
    duration: String,
    message: &'a str,
    protocol: &'a str,
}

pub(crate) struct SessionLogger {
    log_path: String,
}

impl SessionLogger {
    fn new(log_path: &str) -> Self {
        if let Some(parent) = Path::new(log_path).parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            warn!("Failed to create log directory {}: {}", parent.display(), e);
        }
        Self {
            log_path: log_path.to_string(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn log_auth_event(
        &self,
        session_id: &str,
        src_ip: &str,
        src_port: u16,
        dest_backend: Option<&str>,
        dest_ip: Option<&str>,
        dest_port: Option<u16>,
        username: &str,
        password: &str,
        success: bool,
    ) {
        let log_entry = AuthLogEntry {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event_type: "ReverSSH",
            eventid: "reverssh.login.attempt",
            session_id,
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            dest_backend,
            username,
            password,
            protocol: "ssh",
            success,
        };

        if let Err(e) = self.write_log(&log_entry) {
            warn!("Failed to write auth log: {}", e);
        }
    }

    pub(crate) fn log_command_event(&self, event: &CommandLogEvent<'_>) {
        let log_entry = CommandLogEntry {
            timestamp: event
                .input_timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event_type: "ReverSSH",
            eventid: "reverssh.command.input",
            session_id: event.session_id,
            command_id: event.command_id,
            src_ip: event.src_ip,
            src_port: event.src_port,
            username: event.username,
            command: event.command,
            cwd: event.cwd,
            input_timestamp: event
                .input_timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            response_timestamp: event
                .response_timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            response_latency_ms: event.response_latency_ms,
            prompt_returned: event.prompt_returned,
            end_reason: event.end_reason,
            backend_response_raw: event.backend_response_raw,
            backend_response_displayed: event.backend_response_displayed,
            backend_response_error: event.backend_response_error,
            success: event.success,
            protocol: "ssh",
            dest_backend: event.dest_backend,
            dest_ip: event.dest_ip,
            dest_port: event.dest_port,
        };

        if let Err(e) = self.write_log(&log_entry) {
            warn!("Failed to write command log: {}", e);
        }
    }

    pub(crate) fn log_session_close(
        &self,
        session_id: &str,
        src_ip: &str,
        src_port: u16,
        username: &str,
        duration_secs: f64,
        message: &str,
    ) {
        let log_entry = SessionCloseLogEntry {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event_type: "ReverSSH",
            eventid: "reverssh.session.close",
            session_id,
            src_ip,
            src_port,
            username,
            duration: format!("{:.2}s", duration_secs),
            message,
            protocol: "ssh",
        };

        if let Err(e) = self.write_log(&log_entry) {
            warn!("Failed to write session close log: {}", e);
        }
    }

    fn write_log<T: Serialize>(&self, entry: &T) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }
}

pub(crate) type SharedLogger = Arc<Mutex<SessionLogger>>;

pub(crate) fn create_logger(log_path: &str) -> SharedLogger {
    Arc::new(Mutex::new(SessionLogger::new(log_path)))
}

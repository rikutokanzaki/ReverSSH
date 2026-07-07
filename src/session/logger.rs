use chrono::{DateTime, Utc};
use log::warn;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct CommandLogEvent<'a> {
    pub src_ip: &'a str,
    pub src_port: u16,
    pub username: &'a str,
    pub command: &'a str,
    pub cwd: &'a str,
    pub input_timestamp: DateTime<Utc>,
    pub response_timestamp: DateTime<Utc>,
    pub response_latency_ms: i64,
    pub backend_response_raw: Option<&'a str>,
    pub backend_response_displayed: Option<&'a str>,
    pub backend_response_error: Option<&'a str>,
    pub success: bool,
}

#[derive(Serialize)]
struct AuthLogEntry<'a> {
    timestamp: String,
    #[serde(rename = "type")]
    event_type: &'a str,
    eventid: &'a str,
    src_ip: &'a str,
    src_port: u16,
    dest_ip: &'a str,
    dest_port: u16,
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
    src_ip: &'a str,
    src_port: u16,
    username: &'a str,
    command: &'a str,
    cwd: &'a str,
    input_timestamp: String,
    response_timestamp: String,
    response_latency_ms: i64,
    backend_response_raw: Option<&'a str>,
    backend_response_displayed: Option<&'a str>,
    backend_response_error: Option<&'a str>,
    success: bool,
    protocol: &'a str,
}

#[derive(Serialize)]
struct SessionCloseLogEntry<'a> {
    timestamp: String,
    #[serde(rename = "type")]
    event_type: &'a str,
    eventid: &'a str,
    src_ip: &'a str,
    src_port: u16,
    username: &'a str,
    duration: String,
    message: &'a str,
    protocol: &'a str,
}

pub struct SessionLogger {
    log_path: String,
}

impl SessionLogger {
    pub fn new(log_path: &str) -> Self {
        if let Some(parent) = Path::new(log_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self {
            log_path: log_path.to_string(),
        }
    }

    pub fn log_auth_event(
        &self,
        src_ip: &str,
        src_port: u16,
        dest_ip: &str,
        dest_port: u16,
        username: &str,
        password: &str,
        success: bool,
    ) {
        let log_entry = AuthLogEntry {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event_type: "ReverSSH",
            eventid: "reverssh.login.attempt",
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            username,
            password,
            protocol: "ssh",
            success,
        };

        if let Err(e) = self.write_log(&log_entry) {
            warn!("Failed to write auth log: {}", e);
        }
    }

    pub fn log_command_event(&self, event: &CommandLogEvent<'_>) {
        let log_entry = CommandLogEntry {
            timestamp: event
                .input_timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event_type: "ReverSSH",
            eventid: "reverssh.command.input",
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
            backend_response_raw: event.backend_response_raw,
            backend_response_displayed: event.backend_response_displayed,
            backend_response_error: event.backend_response_error,
            success: event.success,
            protocol: "ssh",
        };

        if let Err(e) = self.write_log(&log_entry) {
            warn!("Failed to write command log: {}", e);
        }
    }

    pub fn log_session_close(
        &self,
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

        let line = serde_json::to_string(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        writeln!(file, "{}", line)?;
        Ok(())
    }
}

pub type SharedLogger = Arc<Mutex<SessionLogger>>;

pub fn create_logger(log_path: &str) -> SharedLogger {
    Arc::new(Mutex::new(SessionLogger::new(log_path)))
}

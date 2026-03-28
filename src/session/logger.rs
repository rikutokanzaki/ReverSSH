use chrono::Utc;
use log::warn;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

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
        let log_entry = json!({
            "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "type": "ReverSSH",
            "eventid": "reverssh.login.attempt",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "username": username,
            "password": password,
            "protocol": "ssh",
            "success": success,
        });

        if let Err(e) = self.write_log(&log_entry) {
            warn!("Failed to write auth log: {}", e);
        }
    }

    pub fn log_command_event(
        &self,
        src_ip: &str,
        src_port: u16,
        username: &str,
        command: &str,
        cwd: &str,
    ) {
        let log_entry = json!({
            "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "type": "ReverSSH",
            "eventid": "reverssh.command.input",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": username,
            "command": command,
            "cwd": cwd,
            "protocol": "ssh",
        });

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
        let log_entry = json!({
            "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "type": "ReverSSH",
            "eventid": "reverssh.session.close",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": username,
            "duration": format!("{:.2}s", duration_secs),
            "message": message,
            "protocol": "ssh",
        });

        if let Err(e) = self.write_log(&log_entry) {
            warn!("Failed to write session close log: {}", e);
        }
    }

    fn write_log(&self, entry: &serde_json::Value) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        writeln!(file, "{}", entry.to_string())?;
        Ok(())
    }
}

pub type SharedLogger = Arc<Mutex<SessionLogger>>;

pub fn create_logger(log_path: &str) -> SharedLogger {
    Arc::new(Mutex::new(SessionLogger::new(log_path)))
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowSize {
    pub cols: u16,
    pub rows: u16,
}

impl WindowSize {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self { cols, rows }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmdInfo {
    pub command_id: String,
    pub window_size_at_exec: Option<WindowSize>,
    pub username: String,
    pub cwd: Option<PathBuf>,
    pub cmd: String,
    pub ts: DateTime<Utc>,
}

pub struct TerminalState {
    pub window_size: Option<WindowSize>,
    pub cwd: Option<PathBuf>,
    pub last_cmd: Option<CmdInfo>,
    pub history: Vec<CmdInfo>,
}

impl CmdInfo {
    pub fn new<S: Into<String>>(command_id: String, username: S, cmd: S) -> Self {
        Self {
            command_id,
            window_size_at_exec: None,
            username: username.into(),
            cmd: cmd.into(),
            cwd: None,
            ts: Utc::now(),
        }
    }

    pub fn new_with_generated_id<S: Into<String>>(username: S, cmd: S) -> Self {
        Self::new(Uuid::new_v4().to_string(), username, cmd)
    }
}

impl TerminalState {
    pub fn new() -> Self {
        Self {
            window_size: None,
            cwd: None,
            last_cmd: None,
            history: Vec::new(),
        }
    }

    pub fn push_cmd(&mut self, mut info: CmdInfo) {
        if let Some(ref ws) = self.window_size {
            info.window_size_at_exec = Some(ws.clone());
        }
        self.last_cmd = Some(info.clone());
        self.history.push(info);
    }

    pub fn refresh_window_size(&mut self) -> Option<WindowSize> {
        None
    }
}

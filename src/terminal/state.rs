use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct WindowSize {
    pub(crate) cols: u16,
    pub(crate) rows: u16,
}

impl WindowSize {
    pub(crate) fn new(cols: u16, rows: u16) -> Self {
        Self { cols, rows }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct CmdInfo {
    pub(crate) command_id: String,
    pub(crate) window_size_at_exec: Option<WindowSize>,
    pub(crate) username: String,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) cmd: String,
    pub(crate) ts: DateTime<Utc>,
}

pub(crate) struct TerminalState {
    pub(crate) window_size: Option<WindowSize>,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) last_cmd: Option<CmdInfo>,
    pub(crate) history: Vec<CmdInfo>,
}

impl CmdInfo {
    pub(crate) fn new<S: Into<String>>(command_id: String, username: S, cmd: S) -> Self {
        Self {
            command_id,
            window_size_at_exec: None,
            username: username.into(),
            cmd: cmd.into(),
            cwd: None,
            ts: Utc::now(),
        }
    }

    pub(crate) fn new_with_generated_id<S: Into<String>>(username: S, cmd: S) -> Self {
        Self::new(Uuid::new_v4().to_string(), username, cmd)
    }
}

impl Default for TerminalState {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalState {
    pub(crate) fn new() -> Self {
        Self {
            window_size: None,
            cwd: None,
            last_cmd: None,
            history: Vec::new(),
        }
    }

    pub(crate) fn push_cmd(&mut self, mut info: CmdInfo) {
        if let Some(ref ws) = self.window_size {
            info.window_size_at_exec = Some(ws.clone());
        }
        self.last_cmd = Some(info.clone());
        self.history.push(info);
    }
}

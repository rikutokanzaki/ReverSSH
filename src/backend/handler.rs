use anyhow::{Context, Result};
use lazy_static::lazy_static;
use log::{info, warn};
use regex::Regex;
use russh::client::{self, Handle, Msg as ClientMsg};
use russh::{Channel, ChannelMsg};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

use crate::client::connection::Client;
use crate::config::app::{AuthType, BackendConfig};

lazy_static! {
    static ref ANSI_ESCAPE_RE: Regex =
        Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("Invalid regex pattern");
    static ref PROMPT_CWD_RE: Regex =
        Regex::new(r"[\w-]+@[\w-]+:(.*?)[\$#]\s*$").expect("Invalid prompt regex");
}

pub struct BackendConnection {
    pub name: String,
    pub handle: Arc<Mutex<Handle<Client>>>,
    pub channel: Arc<Mutex<Option<Channel<ClientMsg>>>>,
}

impl BackendConnection {
    pub async fn connect(config: BackendConfig, username: &str, password: &str) -> Result<Self> {
        let client_config = client::Config::default();
        let client = Client;

        let mut session = client::connect(
            Arc::new(client_config),
            (config.hostname.as_str(), config.port),
            client,
        )
        .await
        .context("Failed to connect to backend")?;

        let auth_result = match config.auth_type {
            AuthType::Password => session
                .authenticate_password(username, password)
                .await
                .context("Password authentication failed")?,
            AuthType::Key => {
                if let Some(ref key_path) = config.key_pair {
                    let key = russh_keys::load_secret_key(key_path, None)
                        .context("Failed to load SSH key")?;
                    session
                        .authenticate_publickey(username, Arc::new(key))
                        .await
                        .context("Key authentication failed")?
                } else {
                    return Err(anyhow::anyhow!("Key auth requires key_pair path"));
                }
            }
        };

        if !auth_result {
            return Err(anyhow::anyhow!("Backend authentication failed"));
        }

        info!("Successfully connected to backend: {}", config.name);

        Ok(Self {
            name: config.name.clone(),
            handle: Arc::new(Mutex::new(session)),
            channel: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn open_channel(&self) -> Result<Option<String>> {
        let handle = self.handle.lock().await;
        let mut channel = handle
            .channel_open_session()
            .await
            .context("Failed to open channel")?;

        channel
            .request_pty(false, "xterm", 80, 24, 0, 0, &[])
            .await
            .context("Failed to request PTY")?;

        channel
            .request_shell(false)
            .await
            .context("Failed to request shell")?;

        drop(handle);

        let initial_cwd = self.wait_for_initial_prompt(&mut channel).await?;

        let mut channel_lock = self.channel.lock().await;
        *channel_lock = Some(channel);

        Ok(initial_cwd)
    }

    async fn wait_for_initial_prompt(
        &self,
        channel: &mut Channel<ClientMsg>,
    ) -> Result<Option<String>> {
        let mut buffer = Vec::new();
        let timeout_duration = Duration::from_secs(10);

        loop {
            match timeout(timeout_duration, channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    ChannelMsg::Data { ref data } => {
                        buffer.extend_from_slice(data);

                        if Self::has_prompt(&buffer) {
                            info!("Initial prompt received from backend: {}", self.name);
                            let cwd = Self::extract_cwd_from_output(&buffer);
                            return Ok(cwd);
                        }
                    }
                    ChannelMsg::Eof => {
                        return Err(anyhow::anyhow!(
                            "Channel closed while waiting for initial prompt"
                        ));
                    }
                    _ => {}
                },
                Ok(None) => {
                    return Err(anyhow::anyhow!(
                        "Channel closed while waiting for initial prompt"
                    ));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!("Timeout waiting for initial prompt"));
                }
            }
        }
    }

    pub async fn execute_command(&self, cmd: &str) -> Result<(Vec<u8>, Option<String>)> {
        let mut channel_lock = self.channel.lock().await;
        let channel = channel_lock.as_mut().context("Channel not opened")?;

        let cmd_with_newline = format!("{}\n", cmd.trim_end());
        channel
            .data(cmd_with_newline.as_bytes())
            .await
            .context("Failed to send command")?;

        let mut output = Vec::new();
        let read_timeout = Duration::from_secs(5);

        loop {
            match timeout(read_timeout, channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    ChannelMsg::Data { ref data } => {
                        output.extend_from_slice(data);

                        if Self::has_prompt(&output) {
                            break;
                        }
                    }
                    ChannelMsg::Eof => {
                        warn!("Channel EOF while reading command output");
                        break;
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        warn!("Channel exit status: {}", exit_status);
                        break;
                    }
                    _ => {}
                },
                Ok(None) => {
                    break;
                }
                Err(_) => {
                    warn!("Timeout reading command output");
                    break;
                }
            }
        }

        drop(channel_lock);

        let cwd = Self::extract_cwd_from_output(&output);

        let command_output = Self::clean_output(&output, cmd);
        Ok((command_output, cwd))
    }

    fn has_prompt(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            let ansi_stripped = ANSI_ESCAPE_RE.replace_all(&text, "");
            let lines: Vec<&str> = ansi_stripped.lines().collect();

            if let Some(last_line) = lines.last() {
                return last_line.ends_with("$ ") || last_line.ends_with("# ");
            }
        }
        false
    }

    fn extract_cwd_from_output(data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);

        let ansi_stripped = ANSI_ESCAPE_RE.replace_all(&text, "");
        let lines: Vec<&str> = ansi_stripped.lines().collect();

        if let Some(last_line) = lines.last() {
            if let Some(captures) = PROMPT_CWD_RE.captures(last_line) {
                if let Some(cwd_match) = captures.get(1) {
                    let cwd = cwd_match.as_str();
                    return Some(cwd.to_string());
                }
            }
        }
        None
    }

    fn clean_output(data: &[u8], cmd: &str) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);

        let ansi_stripped = ANSI_ESCAPE_RE.replace_all(&text, "");

        let mut lines: Vec<&str> = ansi_stripped.lines().collect();

        if !lines.is_empty() && lines[0].trim().ends_with(cmd) {
            lines.remove(0);
        }

        if !lines.is_empty() {
            let last = lines.last().unwrap();

            if last.ends_with("$ ") || last.ends_with("# ") {
                lines.pop();
            }
        }

        let result = lines.join("\r\n");
        if !result.is_empty() {
            format!("{}\r\n", result).into_bytes()
        } else {
            Vec::new()
        }
    }

    pub async fn close(&self) -> Result<()> {
        if let Some(channel) = self.channel.lock().await.take() {
            let _ = channel.eof().await;
        }

        let handle = self.handle.lock().await;
        handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await?;

        Ok(())
    }

    pub async fn send_tab_completion(&self, current_buffer: &str) -> Result<Vec<u8>> {
        let mut channel_lock = self.channel.lock().await;
        let channel = channel_lock.as_mut().context("Channel not opened")?;

        let clear_line = format!("\x15{}\t", current_buffer);
        channel
            .data(clear_line.as_bytes())
            .await
            .context("Failed to send buffer and tab")?;

        let mut output = Vec::new();
        let read_timeout = Duration::from_millis(500);

        loop {
            match timeout(read_timeout, channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    ChannelMsg::Data { ref data } => {
                        output.extend_from_slice(data);

                        if Self::has_prompt(&output) {
                            break;
                        }
                    }
                    ChannelMsg::Eof => {
                        warn!("Channel EOF during tab completion");
                        break;
                    }
                    _ => {}
                },
                Ok(None) => break,
                Err(_) => {
                    break;
                }
            }
        }

        channel
            .data(&b"\x15"[..])
            .await
            .context("Failed to clear line after completion")?;

        let clear_timeout = Duration::from_millis(100);
        match timeout(clear_timeout, channel.wait()).await {
            Ok(Some(ChannelMsg::Data { .. })) => {}
            _ => {}
        }

        drop(channel_lock);
        Ok(output)
    }

    pub fn extract_completed_line(data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);

        let ansi_stripped = ANSI_ESCAPE_RE.replace_all(&text, "");

        if ansi_stripped.trim().is_empty() {
            return None;
        }

        let lines: Vec<&str> = ansi_stripped
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();

        if let Some(last_line) = lines.last() {
            if let Some(prompt_end) = last_line.find(|c| c == '$' || c == '#') {
                let command_part = last_line[prompt_end + 1..].trim_start();
                return Some(command_part.to_string());
            }

            let trimmed = last_line.trim();

            let words: Vec<&str> = trimmed.split_whitespace().collect();

            if words.is_empty() {
                return None;
            }

            if words.len() == 1 {
                return Some(words[0].to_string());
            }

            let cmd = words[0];
            let last_arg = words[words.len() - 1];

            let result = format!("{} {}", cmd, last_arg);

            return Some(result);
        }

        None
    }
}

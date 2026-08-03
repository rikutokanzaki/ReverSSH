use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::{info, warn};
use russh::client::{self, AuthResult, Handle, Msg as ClientMsg};
use russh::keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg};
use std::borrow::Cow;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

use crate::client::connection::Client;
use crate::config::app::{AuthType, BackendConfig};
use crate::terminal::parser::TerminalOutputParser;

#[derive(Debug, Clone)]
pub enum CommandEndReason {
    Prompt,
    ExitStatus,
    Eof,
    Timeout,
}

pub struct CommandExecutionResult {
    pub raw_output: Vec<u8>,
    pub displayed_output: Vec<u8>,
    pub cwd: Option<String>,
    pub first_response_timestamp: chrono::DateTime<Utc>,
    pub first_response_latency_ms: i64,
    pub end_reason: CommandEndReason,
    pub prompt_returned: bool,
}

pub struct BackendConnection {
    pub name: String,
    pub handle: Arc<Mutex<Handle<Client>>>,
    pub channel: Arc<Mutex<Option<Channel<ClientMsg>>>>,
}

impl BackendConnection {
    pub async fn connect(config: BackendConfig, username: &str, password: &str) -> Result<Self> {
        let mut client_config = client::Config::default();
        client_config.preferred.key = Cow::Owned(vec![
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa { hash: None },
        ]);

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
                    let private_key = russh::keys::load_secret_key(key_path, None)
                        .context("Failed to load private key")?;
                    let key =
                        PrivateKeyWithHashAlg::new(Arc::new(private_key), Some(HashAlg::Sha256));
                    session
                        .authenticate_publickey(username, key)
                        .await
                        .context("Key authentication failed")?
                } else {
                    return Err(anyhow::anyhow!("Key auth requires key_pair path"));
                }
            }
        };

        if !matches!(auth_result, AuthResult::Success) {
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

                        if TerminalOutputParser::is_prompt(&buffer) {
                            info!("Initial prompt received from backend: {}", self.name);
                            let cwd = TerminalOutputParser::extract_cwd_from_output(&buffer);
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

    pub async fn execute_command(&self, cmd: &str) -> Result<CommandExecutionResult> {
        let mut channel_lock = self.channel.lock().await;
        let channel = channel_lock.as_mut().context("Channel not opened")?;

        let cmd_with_newline = format!("{}\n", cmd.trim_end());

        let start = std::time::Instant::now();

        channel
            .data(cmd_with_newline.as_bytes())
            .await
            .context("Failed to send command")?;

        let mut output = Vec::new();
        let read_timeout = Duration::from_secs(300);

        let mut first_response_latency: Option<i64> = None;
        let mut first_response_timestamp: Option<DateTime<Utc>> = None;

        let mut end_reason = CommandEndReason::Timeout;

        loop {
            match timeout(read_timeout, channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    ChannelMsg::Data { ref data } => {
                        output.extend_from_slice(data);

                        if first_response_latency.is_none() {
                            let displayed = TerminalOutputParser::clean_output(&output, cmd);

                            if !displayed.is_empty() {
                                first_response_latency = Some(start.elapsed().as_millis() as i64);
                                first_response_timestamp = Some(Utc::now());
                            }
                        }

                        if TerminalOutputParser::is_prompt(&output) {
                            end_reason = CommandEndReason::Prompt;
                            break;
                        }
                    }
                    ChannelMsg::Eof => {
                        end_reason = CommandEndReason::Eof;
                        break;
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        warn!("Exit status: {}", exit_status);
                        end_reason = CommandEndReason::ExitStatus;
                        break;
                    }
                    _ => {}
                },
                Ok(None) => {
                    break;
                }
                Err(_) => {
                    warn!("Timeout");
                    end_reason = CommandEndReason::Timeout;
                    break;
                }
            }
        }

        drop(channel_lock);

        let cwd = TerminalOutputParser::extract_cwd_from_output(&output);
        let raw_output = output;
        let displayed_output = TerminalOutputParser::clean_output(&raw_output, cmd);

        Ok(CommandExecutionResult {
            raw_output,
            displayed_output,
            cwd,
            first_response_timestamp: first_response_timestamp.unwrap_or(Utc::now()),
            first_response_latency_ms: first_response_latency
                .unwrap_or(start.elapsed().as_millis() as i64),
            prompt_returned: matches!(end_reason, CommandEndReason::Prompt),
            end_reason,
        })
    }

    pub async fn close(&self) -> Result<()> {
        if let Some(channel) = self.channel.lock().await.take() {
            if let Err(e) = channel.eof().await {
                warn!("Failed to send EOF to backend channel: {:?}", e);
            }
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
        let read_timeout = Duration::from_secs(300);

        loop {
            match timeout(read_timeout, channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    ChannelMsg::Data { ref data } => {
                        output.extend_from_slice(data);

                        if TerminalOutputParser::is_prompt(&output) {
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
}

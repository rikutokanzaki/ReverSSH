use anyhow::{Context, Result, bail};
use russh::client::{self, AuthResult, Handle, Msg as ClientMsg};
use russh::{Channel, ChannelMsg};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

struct TestClient;

impl client::Handler for TestClient {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct TestSession {
    handle: Handle<TestClient>,
    channel: Channel<ClientMsg>,
}

impl TestSession {
    async fn connect(host: &str, port: u16, user: &str, password: &str) -> Result<Self> {
        let config = Arc::new(client::Config::default());
        let mut handle = timeout(
            Duration::from_secs(10),
            client::connect(config, (host, port), TestClient),
        )
        .await
        .context("timed out connecting to reverssh")??;

        let auth = handle
            .authenticate_password(user, password)
            .await
            .context("password authentication failed")?;
        if !matches!(auth, AuthResult::Success) {
            bail!("password authentication was rejected");
        }

        let channel = handle
            .channel_open_session()
            .await
            .context("failed to open SSH session")?;
        channel
            .request_pty(false, "xterm", 80, 24, 0, 0, &[])
            .await
            .context("failed to request PTY")?;
        channel
            .request_shell(false)
            .await
            .context("failed to request shell")?;

        let mut session = Self { handle, channel };
        session.read_until_prompt(None).await?;
        Ok(session)
    }

    async fn assert_password_rejected(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
    ) -> Result<()> {
        let config = Arc::new(client::Config::default());
        let mut handle = timeout(
            Duration::from_secs(10),
            client::connect(config, (host, port), TestClient),
        )
        .await
        .context("timed out connecting to reverssh")??;

        let auth = handle
            .authenticate_password(user, password)
            .await
            .context("password authentication request failed")?;
        if matches!(auth, AuthResult::Success) {
            bail!("password authentication unexpectedly succeeded");
        }

        handle
            .disconnect(russh::Disconnect::ByApplication, "expected rejection", "")
            .await
            .context("failed to disconnect rejected SSH client")?;
        Ok(())
    }

    async fn send(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.channel
            .data(input)
            .await
            .context("failed to send SSH input")?;

        let raw = String::from_utf8_lossy(input);
        let command = raw
            .rsplit_once("\x1b[")
            .and_then(|(_, sequence)| sequence.get(1..))
            .unwrap_or(&raw)
            .trim_matches('\r');
        let mut output = Vec::new();
        let mut command_seen = false;

        loop {
            let message = timeout(Duration::from_secs(10), self.channel.wait())
                .await
                .context("timed out waiting for SSH output")?
                .context("SSH channel closed before prompt")?;

            match message {
                ChannelMsg::Data { ref data } => {
                    output.extend_from_slice(data);
                    if !command_seen && String::from_utf8_lossy(&output).contains(command) {
                        command_seen = true;
                    }
                    if command_seen && prompt_cwd(&output).is_some() {
                        return Ok(output);
                    }
                }
                ChannelMsg::Eof => bail!("SSH channel reached EOF before prompt"),
                _ => {}
            }
        }
    }

    async fn read_until_prompt(&mut self, expected_cwd: Option<&str>) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        loop {
            let message = timeout(Duration::from_secs(10), self.channel.wait())
                .await
                .context("timed out waiting for SSH output")?
                .context("SSH channel closed before prompt")?;

            match message {
                ChannelMsg::Data { ref data } => {
                    output.extend_from_slice(data);
                    if let Some(expected) = expected_cwd {
                        if prompt_cwd(&output) == Some(expected) {
                            return Ok(output);
                        }
                    } else if prompt_cwd(&output).is_some() {
                        return Ok(output);
                    }
                }
                ChannelMsg::Eof => bail!("SSH channel reached EOF before prompt"),
                _ => {}
            }
        }
    }

    async fn read_until_quiet(&mut self) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        loop {
            match timeout(Duration::from_millis(300), self.channel.wait()).await {
                Ok(Some(ChannelMsg::Data { ref data })) => output.extend_from_slice(data),
                Ok(Some(ChannelMsg::Eof)) => bail!("SSH channel reached EOF during completion"),
                Ok(Some(_)) => {}
                Ok(None) => bail!("SSH channel closed during completion"),
                Err(_) => return Ok(output),
            }
        }
    }

    async fn close(self) -> Result<()> {
        let _ = self.channel.data(&b"exit\r"[..]).await;
        let _ = self.channel.eof().await;
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .context("failed to disconnect test SSH client")?;
        Ok(())
    }
}

fn prompt_cwd(data: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(data).ok()?;
    let line = text.rsplit('\n').next()?.trim_matches(['\r', ' ']);
    let prompt_start = line.rfind("root@")?;
    let prompt = line[prompt_start..].trim_end();
    let prompt_end = prompt.find(['#', '$'])?;
    if !prompt[prompt_end + 1..].trim().is_empty() {
        return None;
    }
    let prompt = &prompt[..prompt_end];
    let cwd = prompt.split_once(':')?.1;
    (!cwd.is_empty()).then_some(cwd)
}

async fn run_tests(host: &str, port: u16, user: &str, password: &str) -> Result<()> {
    let mut session = TestSession::connect(host, port, user, password).await?;

    session
        .channel
        .data(&b"cd /tmp/reverssh-replay\r"[..])
        .await?;
    session
        .read_until_prompt(Some("/tmp/reverssh-replay"))
        .await?;

    session
        .channel
        .data(&b"cd /tmp/reverssh-tab-ta\t"[..])
        .await?;
    let completion = session.read_until_quiet().await?;
    assert_output(&completion, "reverssh-tab-target")?;
    session
        .channel
        .data(&b"\r"[..])
        .await
        .context("failed to submit completed path")?;
    session
        .read_until_prompt(Some("/tmp/reverssh-tab-target"))
        .await?;

    let output = session.send(b"echo abc\r").await?;
    assert_output(&output, "abc")?;

    session.send(b"\x1b[A\x1b[D\x1b[C\x1b[Becho down\r").await?;

    let output = session.send(b"echo cowrie-ok\r").await?;
    assert_output(&output, "cowrie-ok")?;

    let output = session.send(b"echo beelzebub-ok\r").await?;
    assert_output(&output, "beelzebub-ok")?;

    session.close().await
}

fn assert_output(output: &[u8], expected: &str) -> Result<()> {
    let text = String::from_utf8_lossy(output);
    if !text.contains(expected) {
        bail!("expected {expected:?} in SSH output: {text:?}");
    }
    Ok(())
}

#[tokio::test]
async fn ssh_e2e() -> Result<()> {
    let host = std::env::var("SSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("SSH_PORT")
        .unwrap_or_else(|_| "2222".to_string())
        .parse::<u16>()?;
    let user = std::env::var("SSH_USER").unwrap_or_else(|_| "root".to_string());
    let password = std::env::var("SSH_PASSWORD").unwrap_or_else(|_| "test-password".to_string());

    TestSession::assert_password_rejected(&host, port, &user, "rejected-password").await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match run_tests(&host, port, &user, &password).await {
            Ok(()) => {
                return Ok(());
            }
            Err(error) if tokio::time::Instant::now() < deadline => {
                eprintln!("E2E startup retry: {error:#}");
                sleep(Duration::from_secs(1)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

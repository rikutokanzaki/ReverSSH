use russh::server::Session;
use russh::{ChannelId, CryptoVec};
use unicode_width::UnicodeWidthChar;

pub struct Renderer;

impl Renderer {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_prompt(&self, username: &str, server_name: &str, cwd: Option<&str>) -> String {
        let symbol = if username == "root" { "#" } else { "$" };
        let display_cwd = cwd.unwrap_or("~");
        format!("{username}@{server_name}:{display_cwd}{symbol} ")
    }

    pub fn send_prompt(
        &self,
        channel: ChannelId,
        session: &mut Session,
        username: &str,
        server_name: &str,
        cwd: Option<&str>,
    ) {
        let prompt = self.generate_prompt(username, server_name, cwd);
        self.send_data(channel, session, prompt.as_bytes());
    }

    pub fn redraw_line(
        &self,
        channel: ChannelId,
        session: &mut Session,
        username: &str,
        server_name: &str,
        cwd: Option<&str>,
        buffer: &str,
        cursor: usize,
    ) {
        let prompt = self.generate_prompt(username, server_name, cwd);

        let mut out = String::new();
        out.push('\r');
        out.push_str("\x1b[2K");
        out.push_str(&prompt);
        out.push_str(buffer);

        let tail_cols: usize = buffer[cursor..]
            .chars()
            .map(|c| c.width().unwrap_or(1))
            .sum();
        if tail_cols > 0 {
            out.push_str(&format!("\x1b[{}D", tail_cols));
        }

        self.send_data(channel, session, out.as_bytes());
    }

    pub fn send_data(&self, channel: ChannelId, session: &mut Session, data: &[u8]) {
        session.data(channel, CryptoVec::from(data.to_vec()));
    }

    pub fn send_newline(&self, channel: ChannelId, session: &mut Session) {
        self.send_data(channel, session, b"\r\n");
    }

    pub fn clean_and_close(
        &self,
        channel: ChannelId,
        session: &mut Session,
        final_message: Option<&str>,
    ) {
        let mut out = Vec::new();
        out.extend_from_slice(b"\x1b[0m");
        if let Some(msg) = final_message {
            out.extend_from_slice(msg.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        self.send_data(channel, session, &out);
        session.close(channel);
    }
}

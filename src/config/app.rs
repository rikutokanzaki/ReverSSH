use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,

    #[serde(default)]
    pub backends: Vec<BackendConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub host_key_path: PathBuf,

    #[serde(default = "default_server_name")]
    pub name: String,

    #[serde(default = "default_host_key_mode")]
    pub host_key_mode: HostKeyMode,

    #[serde(default = "default_host_key_type")]
    pub host_key_type: HostKeyType,

    #[serde(default = "default_history_size")]
    pub history_size: usize,

    #[serde(default)]
    pub ssh_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostKeyMode {
    Auto,
    Require,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostKeyType {
    Ed25519,
    Rsa,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    #[default]
    Key,
    Password,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BackendConfig {
    pub name: String,
    pub hostname: String,
    pub port: u16,

    #[serde(default)]
    pub username: Option<String>,

    #[serde(alias = "key_path")]
    pub key_pair: Option<PathBuf>,

    #[serde(default)]
    pub password: Option<String>,

    #[serde(default)]
    pub auth_type: AuthType,

    #[serde(default)]
    pub default: bool,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub authorized_keys_dir: PathBuf,

    #[serde(default)]
    pub accept_any: bool,

    #[serde(default = "default_user_db_path")]
    pub user_db_path: PathBuf,
}

fn default_host_key_mode() -> HostKeyMode {
    HostKeyMode::Auto
}

fn default_host_key_type() -> HostKeyType {
    HostKeyType::Ed25519
}

fn default_server_name() -> String {
    "svr04".to_string()
}

fn default_history_size() -> usize {
    1000
}

fn default_user_db_path() -> PathBuf {
    PathBuf::from("/config/user.txt")
}

pub struct LineReader {
    history_size: usize,
    buffer: Vec<String>,
}

impl LineReader {
    pub fn new(history_size: usize) -> Self {
        LineReader {
            history_size,
            buffer: Vec::new(),
        }
    }

    pub fn read(&mut self, line: &str) -> bool {
        self.buffer.push(line.to_string());
        self.buffer.len() <= self.history_size
    }
}

use anyhow::{Result, bail};
use russh_keys::{key, load_secret_key};
use std::fs;

use crate::config::{HostKeyMode, HostKeyType, ServerConfig};

pub fn load_or_generate_host_key(config: &ServerConfig) -> Result<key::KeyPair> {
    if config.host_key_path.exists() {
        return Ok(load_secret_key(&config.host_key_path, None)?);
    }

    match config.host_key_mode {
        HostKeyMode::Require => {
            bail!("host key not found: {:?}", config.host_key_path);
        }

        HostKeyMode::Auto => {
            let key = match config.host_key_type {
                HostKeyType::Ed25519 => key::KeyPair::generate_ed25519()
                    .ok_or_else(|| anyhow::anyhow!("Failed to generate Ed25519 key"))?,
                HostKeyType::Rsa => {
                    bail!("RSA key generation is not supported in this version");
                }
            };

            if let Some(parent) = config.host_key_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut pem_data = Vec::new();
            russh_keys::encode_pkcs8_pem(&key, &mut pem_data)?;
            fs::write(&config.host_key_path, pem_data)?;
            Ok(key)
        }
    }
}

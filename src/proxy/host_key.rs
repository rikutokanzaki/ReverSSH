use anyhow::{bail, Result};
use rand::{rngs::StdRng, SeedableRng};
use russh::keys::{load_secret_key, Algorithm, PrivateKey};
use std::fs;

use crate::config::{HostKeyMode, ServerConfig};

pub fn load_or_generate_host_key(config: &ServerConfig) -> Result<PrivateKey> {
    if config.host_key_path.exists() {
        return Ok(load_secret_key(&config.host_key_path, None)?);
    }

    match config.host_key_mode {
        HostKeyMode::Require => {
            bail!("host key not found: {:?}", config.host_key_path);
        }

        HostKeyMode::Auto => {
            let mut rng = StdRng::from_rng(&mut rand::rng());
            let key = PrivateKey::random(&mut rng, Algorithm::Ed25519)?;

            if let Some(parent) = config.host_key_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut pem_data = Vec::new();
            russh::keys::encode_pkcs8_pem(&key, &mut pem_data)?;
            Ok(key)
        }
    }
}

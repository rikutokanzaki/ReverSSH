use std::fs;
use std::io::ErrorKind;

use anyhow::{Context, Result};

use crate::config::app::AppConfig;

pub fn load_config(path: &str) -> Result<AppConfig> {
    let toml_str = read_config_with_fallback(path)?;
    let config: AppConfig = toml::from_str(&toml_str)?;

    Ok(config)
}

fn read_config_with_fallback(path: &str) -> Result<String> {
    let fallback_path = format!("{path}.sample");

    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(err) if err.kind() == ErrorKind::NotFound => fs::read_to_string(&fallback_path)
            .with_context(|| {
                format!(
                    "failed to read config files: primary='{}', fallback='{}'",
                    path, fallback_path
                )
            }),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read primary config file '{path}'"))
        }
    }
}

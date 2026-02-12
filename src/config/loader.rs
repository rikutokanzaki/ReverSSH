use anyhow::Result;
use std::fs;

use crate::config::app::AppConfig;

pub fn load_config(path: &str) -> Result<AppConfig> {
    let toml_str = fs::read_to_string(path)?;
    let config: AppConfig = toml::from_str(&toml_str)?;

    Ok(config)
}

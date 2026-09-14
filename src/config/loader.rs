use std::fs;
use std::io::ErrorKind;

use anyhow::{Context, Result};
use log::warn;

use crate::config::app::{AppConfig, RoutingConfig};

const DEFAULT_CONFIG_PATH: &str = "/config/default.toml";
const ROUTING_CONFIG_PATH: &str = "/config/routing.toml";

pub fn load_config() -> Result<AppConfig> {
    let toml_str = read_config_with_fallback(DEFAULT_CONFIG_PATH)?;
    let mut config: AppConfig = toml::from_str(&toml_str)?;
    let routing_toml = read_config_with_fallback(ROUTING_CONFIG_PATH).with_context(|| {
        format!(
            "failed to read required routing files: primary='{}', fallback='{}.sample'",
            ROUTING_CONFIG_PATH, ROUTING_CONFIG_PATH
        )
    })?;
    config.routing = toml::from_str::<RoutingConfig>(&routing_toml)
        .with_context(|| format!("failed to parse routing file '{}'", ROUTING_CONFIG_PATH))?;

    Ok(config)
}

fn read_config_with_fallback(path: &str) -> Result<String> {
    let fallback_path = format!("{path}.sample");

    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let content = fs::read_to_string(&fallback_path).with_context(|| {
                format!(
                    "failed to read config files: primary='{}', fallback='{}'",
                    path, fallback_path
                )
            })?;
            warn!(
                "Using fallback configuration file '{}' because '{}' was not found",
                fallback_path, path
            );
            Ok(content)
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to read primary config file '{path}'"))
        }
    }
}

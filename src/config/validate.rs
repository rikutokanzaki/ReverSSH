use anyhow::{Result, bail};

use crate::config::AppConfig;

pub fn validate_config(config: &AppConfig) -> Result<()> {
    let defaults = config.backends.iter().filter(|b| b.default).count();

    if defaults > 1 {
        bail!("multiple default backends defined")
    }

    Ok(())
}

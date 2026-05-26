use anyhow::{Result, bail};
use std::collections::HashSet;

use crate::config::AppConfig;

pub fn validate_config(config: &AppConfig) -> Result<()> {
    let defaults = config.backends.iter().filter(|b| b.default).count();

    if defaults > 1 {
        bail!("multiple default backends defined")
    }

    let backend_names: HashSet<&str> = config.backends.iter().map(|b| b.name.as_str()).collect();
    for (from, to) in &config.migration {
        if !backend_names.contains(to.as_str()) {
            bail!(
                "migration maps '{}' to unknown backend '{}'",
                from,
                to
            )
        }
    }

    Ok(())
}

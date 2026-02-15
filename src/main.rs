use anyhow::Result;
use russh::SshId;
use russh::server::Config as SshConfig;
use std::sync::Arc;
use std::time::Duration;

use reverssh::backend::pool::BackendPool;
use reverssh::config::{load_config, validate_config};
use reverssh::proxy::host_key::load_or_generate_host_key;
use reverssh::proxy::server::ProxyServerFactory;
use reverssh::router::migration::{CompositeDetector, KeywordDetector};
use reverssh::session::manager::SessionManager;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = load_config("/config/default.toml")?;
    validate_config(&config)?;

    let host_key = load_or_generate_host_key(&config.server)?;
    let session_manager = Arc::new(SessionManager::new());

    let backend_pool = Arc::new(BackendPool::new(config.backends.clone()));

    let detector = Arc::new(CompositeDetector {
        detectors: vec![
            Arc::new(KeywordDetector {
                keyword: "wget".to_string(),
                target: "cowrie2".to_string(),
            }),
            Arc::new(KeywordDetector {
                keyword: "curl".to_string(),
                target: "cowrie2".to_string(),
            }),
        ],
    });

    let mut ssh_config = SshConfig {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keys: vec![host_key],
        ..Default::default()
    };

    if let Some(ref version) = config.server.ssh_version {
        ssh_config.server_id = SshId::Standard(version.clone());
    }

    let config_arc = Arc::new(config);
    let listen_addr = config_arc.server.listen_addr;

    let server_factory = ProxyServerFactory::new(
        config_arc.clone(),
        session_manager.clone(),
        backend_pool,
        detector,
    );

    russh::server::run(Arc::new(ssh_config), listen_addr, server_factory).await?;

    Ok(())
}

use anyhow::Result;
use russh::SshId;
use russh::server::Config as SshConfig;
use russh::server::Server;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use reverssh::backend::pool::BackendPool;
use reverssh::config::{load_config, validate_config};
use reverssh::proxy::host_key::load_or_generate_host_key;
use reverssh::proxy::server::ProxyServerFactory;
use reverssh::router::rules::build_detector;
use reverssh::session::manager::SessionManager;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = load_config("/config/default.toml")?;
    validate_config(&config)?;

    let host_key = load_or_generate_host_key(&config.server)?;
    let log_path = "/var/log/reverssh/reverssh.log".to_string();
    let session_manager = Arc::new(SessionManager::new(log_path));

    let backend_pool = Arc::new(BackendPool::new(config.backends.clone()));

    let detector = build_detector();

    let mut ssh_config = SshConfig {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keys: vec![host_key],
        ..Default::default()
    };

    if let Some(ref version) = config.server.ssh_version {
        ssh_config.server_id = SshId::Standard(version.clone().into());
    }

    let config_arc = Arc::new(config);
    let listen_addr = config_arc.server.listen_addr;

    let mut server_factory = ProxyServerFactory::new(
        config_arc.clone(),
        session_manager.clone(),
        backend_pool,
        detector,
    );

    let ssh_config = Arc::new(ssh_config);

    log::info!("Listening on {}", listen_addr);
    let listener = TcpListener::bind(listen_addr).await?;

    while let Ok((stream, client_addr)) = listener.accept().await {
        let config = Arc::clone(&ssh_config);

        let handler = server_factory.new_client(Some(client_addr));

        tokio::spawn(async move {
            if let Err(e) = russh::server::run_stream(config, stream, handler).await {
                log::error!("SSH session error for {}: {:?}", client_addr, e);
            }
        });
    }

    Ok(())
}

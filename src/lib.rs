use anyhow::Result;
use russh::SshId;
use russh::server::Config as SshConfig;
use russh::server::Server;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

mod backend;
mod client;
pub mod config;
mod proxy;
mod router;
mod session;
mod terminal;

use backend::pool::BackendPool;
use config::{AppConfig, load_config, validate_config};
use proxy::host_key::load_or_generate_host_key;
use proxy::server::ProxyServerFactory;
use router::rules::build_detector;
use session::manager::SessionManager;

pub async fn run() -> Result<()> {
    let config = load_config()?;
    validate_config(&config)?;
    run_with_config(config).await
}

pub async fn run_with_config(config: AppConfig) -> Result<()> {
    let host_key = load_or_generate_host_key(&config.server)?;
    let log_path = "/var/log/reverssh/reverssh.log".to_string();
    let session_manager = Arc::new(SessionManager::new(log_path));

    let backend_pool = Arc::new(BackendPool::new(
        config.backends.clone(),
        &config.routing.authentication,
    ));

    let detector = build_detector(&config.routing)?;

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

use std::net::SocketAddr;
use std::sync::Arc;

use log::warn;
use russh::server;

use crate::client::pool::ClientPool;
use crate::config::AppConfig;
use crate::proxy::authenticator::FileBasedAuthenticator;
use crate::proxy::context::ProxyContext;
use crate::proxy::motd::return_motd;
use crate::proxy::server::ProxyServer;
use crate::router::migration::Detector;
use crate::session::manager::SessionManager;

/// Builds one per-connection [`ProxyServer`] handler from shared services.
pub struct ProxyServerFactory {
    context: Arc<ProxyContext>,
    accept_any: bool,
    authenticator: Option<Arc<FileBasedAuthenticator>>,
    motd: String,
}

impl ProxyServerFactory {
    pub fn new(
        config: Arc<AppConfig>,
        session_manager: Arc<SessionManager>,
        client_pool: Arc<ClientPool>,
        detector: Arc<dyn Detector>,
    ) -> Self {
        let accept_any = config.auth.accept_any;
        let primary = config.auth.user_db_path.clone();
        let authenticator = match FileBasedAuthenticator::new(primary.to_string_lossy().as_ref()) {
            Ok(auth) => Some(Arc::new(auth)),
            Err(err) => {
                let fallback = std::path::PathBuf::from("config/user.txt");

                match FileBasedAuthenticator::new(fallback.to_string_lossy().as_ref()) {
                    Ok(auth) => Some(Arc::new(auth)),
                    Err(err2) => {
                        warn!(
                            "Failed to load user db: {} ({}) and fallback {} ({})",
                            primary.display(),
                            err,
                            fallback.display(),
                            err2
                        );
                        None
                    }
                }
            }
        };

        Self {
            context: Arc::new(ProxyContext::new(
                config,
                session_manager,
                client_pool,
                detector,
            )),
            accept_any,
            authenticator,
            motd: return_motd("/config/motd.txt"),
        }
    }
}

impl server::Server for ProxyServerFactory {
    type Handler = ProxyServer;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        ProxyServer::new(
            self.context.clone(),
            peer_addr,
            self.accept_any,
            self.authenticator.clone(),
            self.motd.clone(),
        )
    }
}

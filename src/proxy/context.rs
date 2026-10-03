use std::sync::Arc;

use crate::client::pool::ClientPool;
use crate::config::AppConfig;
use crate::router::migration::Detector;
use crate::session::manager::SessionManager;

pub struct ProxyContext {
    pub(crate) config: Arc<AppConfig>,
    pub(crate) session_manager: Arc<SessionManager>,
    pub(crate) client_pool: Arc<ClientPool>,
    pub(crate) detector: Arc<dyn Detector>,
}

impl ProxyContext {
    pub fn new(
        config: Arc<AppConfig>,
        session_manager: Arc<SessionManager>,
        client_pool: Arc<ClientPool>,
        detector: Arc<dyn Detector>,
    ) -> Self {
        Self {
            config,
            session_manager,
            client_pool,
            detector,
        }
    }
}

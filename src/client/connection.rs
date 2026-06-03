use russh::client;
use std::future::Future;

pub struct Client;

impl client::Handler for Client {
    type Error = anyhow::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async move {
            Ok(true)
        }
    }
}

use russh::client;
use russh::keys::PublicKeyOrCertificate;

pub struct Client;

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

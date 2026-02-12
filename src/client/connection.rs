use async_trait::async_trait;
use russh::client;
use russh_keys::key::PublicKey;

pub struct Client;

#[async_trait]
impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(
        self,
        _server_public_key: &PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        Ok((self, true))
    }
}

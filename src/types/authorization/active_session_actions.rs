use crate::Client;
use crate::errors::Result;
use crate::types::ActiveSession;

impl ActiveSession {
    /// Ends this session; `true` when Telegram did.
    pub async fn reset(&self, client: &Client) -> Result<bool> {
        client.terminate_session(self.id).await
    }
}

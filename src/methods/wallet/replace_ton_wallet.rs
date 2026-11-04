use crate::Client;
use crate::errors::Result;
use crate::raw::{base, functions};
use crate::types::{TonWalletOwnershipProof, TonWalletState};
use crate::utils::compute_password_check;

/// The cloud password check, fetched only when a password was given.
pub(super) async fn password_check(
    client: &Client,
    password: Option<&str>,
) -> Result<Option<base::InputCheckPasswordSRP>> {
    let Some(password) = password else { return Ok(None) };
    let base::account::Password::Password(p) = client.invoke(&functions::account::GetPassword {}).await?;
    Ok(Some(compute_password_check(&p, password)?))
}

#[must_use = "a request does nothing until it is awaited"]
pub struct ReplaceTonWallet<'a> {
    client: &'a Client,
    proof: TonWalletOwnershipProof,
    password: Option<String>,
    anchor_public_key: Option<Vec<u8>>,
}

impl Client {
    /// Swaps the account's wallet for one you hold the key to. Irreversible: the old wallet is detached.
    pub fn replace_ton_wallet(&self, proof: TonWalletOwnershipProof) -> ReplaceTonWallet<'_> {
        ReplaceTonWallet { client: self, proof, password: None, anchor_public_key: None }
    }
}

impl ReplaceTonWallet<'_> {
    /// The cloud password, for accounts that have one.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn anchor_public_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.anchor_public_key = Some(key.into());
        self
    }

    fn request(self, password: Option<base::InputCheckPasswordSRP>) -> functions::wallet::ReplaceWallet {
        let imported = crate::raw::types::InputWalletImported {
            public_key: self.proof.public_key.clone(),
            anchor_public_key: self.anchor_public_key,
            proof: self.proof.to_raw(),
        };
        functions::wallet::ReplaceWallet {
            wallet: base::InputWalletReplacement::InputWalletImported(Box::new(imported)),
            password,
        }
    }

    async fn send(self) -> Result<TonWalletState> {
        let password = password_check(self.client, self.password.as_deref()).await?;
        let client = self.client;
        let state = client.invoke(&self.request(password)).await?;
        Ok(TonWalletState::parse(client, &state))
    }
}

into_future!(ReplaceTonWallet, TonWalletState);

#[cfg(test)]
mod tests {
    use crate::Client;
    use crate::errors::{Error, RpcError};
    use crate::raw::functions::wallet::ReplaceWallet;
    use crate::raw::{Serializable, base, types};
    use crate::types::TonWalletOwnershipProof;

    fn proof() -> TonWalletOwnershipProof {
        TonWalletOwnershipProof { public_key: vec![1, 2], timestamp: 10, signature: vec![3] }
    }

    #[tokio::test]
    async fn replace_sends_imported_wallet_with_proof() {
        let reply = base::WalletState::WalletStateEmpty(types::WalletStateEmpty { creating: true }).to_bytes();
        let (client, mut rx) = Client::scripted(vec![Ok(reply)]);
        let state = client.replace_ton_wallet(proof()).anchor_public_key(vec![9]).await.unwrap();
        assert!(state.is_being_created);
        let imported = types::InputWalletImported {
            public_key: vec![1, 2],
            anchor_public_key: Some(vec![9]),
            proof: base::WalletOwnershipProof::WalletOwnershipProof(Box::new(types::WalletOwnershipProof {
                timestamp: 10,
                signature: vec![3],
            })),
        };
        let expected = ReplaceWallet {
            wallet: base::InputWalletReplacement::InputWalletImported(Box::new(imported)),
            password: None,
        };
        assert_eq!(rx.try_recv().unwrap(), expected.to_bytes());
        // Without a password nothing else is sent.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn password_is_checked_first() {
        let (client, mut rx) = Client::scripted(vec![Err(Error::Rpc(RpcError::new(400, "PASSWORD_HASH_INVALID")))]);
        let result = client.replace_ton_wallet(proof()).password("hunter2").await;
        assert!(matches!(&result, Err(e) if e.is("PASSWORD_HASH_INVALID")), "{result:?}");
        rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());
    }
}

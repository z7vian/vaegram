use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url};
use serde_json::{Value, json};

use super::engine::{PeerRecord, Storage, StorageFuture, StoredState};
use super::{MemoryStorage, SessionData, session_string};

const FORMAT: u64 = 1;
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPLY: usize = 1 << 20;

const NEWER: &str = "this Vault secret needs a newer vaegram";
const FOREIGN: &str = "not a vaegram secret; it was left as it is";
const MALFORMED: &str = "this Vault secret is malformed";
const CHANGED: &str = "the Vault secret changed since it was read (is another client using it?); it was left as it is";

/// Keeps the login in a HashiCorp Vault KV version 2 secret, and everything else (update state and peers) in
/// another engine, [`MemoryStorage`] unless [`data`](Self::data) says otherwise.
///
/// The secret holds two fields: `vaegram` (the format, 1) and `session` (a session string). Every write names the
/// version it read, so a secret that changed since, or one vaegram didn't write, is refused and left as it is.
/// Logging out deletes every version of the secret.
///
/// The token is sent only to the given address and never in a redirect. Plain `http://` is accepted only for a
/// loopback address, so the token can't cross a network in the clear.
pub struct VaultStorage {
    client: Client,
    data_url: Url,
    metadata_url: Url,
    secret: String,
    token: HeaderValue,
    data: Box<dyn Storage>,
    // The secret's version as last read or written; None until it has been read.
    version: Mutex<Option<u64>>,
}

impl VaultStorage {
    /// `addr` is the server (`https://vault.example.com:8200`), `mount` the KV v2 mount (`secret`) and `path` the
    /// secret's path under it. Nothing connects until the storage is opened.
    pub fn new(addr: &str, token: &str, mount: &str, path: &str) -> io::Result<VaultStorage> {
        let invalid = |why: &str| io::Error::new(io::ErrorKind::InvalidInput, why.to_owned());
        let base = Url::parse(addr).map_err(|_| invalid("not a Vault address"))?;
        if !base.username().is_empty() || base.password().is_some() {
            return Err(invalid("the Vault address must not hold credentials"));
        }
        let host = base.host_str().unwrap_or("");
        let ip = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>();
        let loopback = host.eq_ignore_ascii_case("localhost") || ip.is_ok_and(|ip| ip.is_loopback());
        match base.scheme() {
            "https" => {}
            "http" if loopback => {}
            "http" => return Err(invalid("the Vault address must use https unless it is on this machine")),
            _ => return Err(invalid("not a Vault address")),
        }
        let segments = |s: &str| {
            let parts: Vec<String> = s.split('/').filter(|p| !p.is_empty()).map(str::to_owned).collect();
            let bad = parts.is_empty() || parts.iter().any(|p| p == "." || p == "..");
            if bad { Err(invalid("not a Vault mount or path")) } else { Ok(parts) }
        };
        let (mount, path) = (segments(mount)?, segments(path)?);
        let url = |kind: &str| -> io::Result<Url> {
            let mut url = base.clone();
            url.path_segments_mut()
                .map_err(|()| invalid("not a Vault address"))?
                .pop_if_empty()
                .push("v1")
                .extend(&mount)
                .push(kind)
                .extend(&path);
            Ok(url)
        };
        let mut token = HeaderValue::from_str(token).map_err(|_| invalid("not a Vault token"))?;
        token.set_sensitive(true);
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::other(format!("vault: {e}")))?
            .with_root_certificates(rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()))
            .with_no_client_auth();
        let client = Client::builder()
            .tls_backend_preconfigured(tls)
            .redirect(Policy::none())
            .connect_timeout(TIMEOUT)
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| io::Error::other(format!("vault: {}", e.without_url())))?;
        Ok(VaultStorage {
            client,
            data_url: url("data")?,
            metadata_url: url("metadata")?,
            secret: format!("{}/{}", mount.join("/"), path.join("/")),
            token,
            data: Box::new(MemoryStorage::new()),
            version: Mutex::new(None),
        })
    }

    /// Keeps the update state and peers in `engine` instead of in memory.
    pub fn data(mut self, engine: impl Storage) -> VaultStorage {
        self.data = Box::new(engine);
        self
    }

    fn named(&self, e: io::Error) -> io::Error {
        io::Error::new(e.kind(), format!("vault secret {}: {e}", self.secret))
    }

    fn set_version(&self, version: Option<u64>) {
        *self.version.lock().unwrap_or_else(PoisonError::into_inner) = version;
    }

    async fn send(&self, request: RequestBuilder) -> io::Result<(StatusCode, Value)> {
        let mut reply = request.header("X-Vault-Token", self.token.clone()).send().await.map_err(network)?;
        let status = reply.status();
        let body = read_reply(&mut reply).await?;
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok((status, Value::Null));
        }
        let json = serde_json::from_slice(&body).map_err(|_| io::Error::other("vault: the reply isn't JSON"))?;
        Ok((status, json))
    }

    /// Reads the login and notes the secret's version. A secret vaegram didn't write is an error.
    async fn read(&self) -> io::Result<Option<SessionData>> {
        let (status, json) = self.send(self.client.get(self.data_url.clone())).await?;
        let version = json["data"]["metadata"]["version"].as_u64();
        if status == StatusCode::NOT_FOUND {
            // A deleted latest version keeps its number: the next write has to name it.
            self.set_version(Some(version.unwrap_or(0)));
            return Ok(None);
        }
        if !status.is_success() {
            return Err(failed(status, &json));
        }
        let fields = &json["data"]["data"];
        let invalid = |why: &str| io::Error::new(io::ErrorKind::InvalidData, why.to_owned());
        match fields["vaegram"].as_u64() {
            Some(FORMAT) => {}
            Some(_) => return Err(invalid(NEWER)),
            None => return Err(invalid(FOREIGN)),
        }
        let session = fields["session"].as_str().ok_or_else(|| invalid(MALFORMED))?;
        let session = session_string::parse(session)
            .map_err(|why| invalid(if why == session_string::NEWER_VAEGRAM { NEWER } else { MALFORMED }))?;
        self.set_version(Some(version.ok_or_else(|| invalid(MALFORMED))?));
        Ok(Some(session))
    }

    async fn write(&self, session: &SessionData) -> io::Result<()> {
        let known = *self.version.lock().unwrap_or_else(PoisonError::into_inner);
        let cas = match known {
            Some(version) => version,
            None => {
                self.read().await?;
                self.version.lock().unwrap_or_else(PoisonError::into_inner).unwrap_or(0)
            }
        };
        let body = json!({
            "options": { "cas": cas },
            "data": { "vaegram": FORMAT, "session": session_string::export(session) },
        });
        let request = self.client.post(self.data_url.clone()).header(CONTENT_TYPE, "application/json");
        let (status, json) = self.send(request.body(body.to_string())).await?;
        if !status.is_success() {
            // Whatever happened, the version is no longer known: the next write reads it again.
            self.set_version(None);
            if status == StatusCode::BAD_REQUEST && first_error(&json).contains("check-and-set") {
                return Err(io::Error::new(io::ErrorKind::InvalidData, CHANGED));
            }
            return Err(failed(status, &json));
        }
        self.set_version(json["data"]["version"].as_u64());
        Ok(())
    }

    async fn remove(&self) -> io::Result<()> {
        let (status, json) = self.send(self.client.delete(self.metadata_url.clone())).await?;
        if !status.is_success() && status != StatusCode::NOT_FOUND {
            return Err(failed(status, &json));
        }
        self.set_version(Some(0));
        Ok(())
    }
}

async fn read_reply(reply: &mut Response) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = reply.chunk().await.map_err(network)? {
        if body.len() + chunk.len() > MAX_REPLY {
            return Err(io::Error::other("vault: the reply is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn network(e: reqwest::Error) -> io::Error {
    let kind = if e.is_timeout() {
        io::ErrorKind::TimedOut
    } else if e.is_connect() {
        io::ErrorKind::ConnectionRefused
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, format!("vault: {}", e.without_url()))
}

fn first_error(json: &Value) -> &str {
    json["errors"][0].as_str().unwrap_or("")
}

fn failed(status: StatusCode, json: &Value) -> io::Error {
    let kind = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => io::ErrorKind::PermissionDenied,
        StatusCode::NOT_FOUND => io::ErrorKind::NotFound,
        _ => io::ErrorKind::Other,
    };
    let why: String = first_error(json).chars().take(200).collect();
    io::Error::new(kind, format!("vault: {status} {why}").trim_end().to_owned())
}

impl fmt::Debug for VaultStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = self.data_url.host_str().unwrap_or("");
        f.debug_struct("VaultStorage").field("host", &host).field("secret", &self.secret).finish_non_exhaustive()
    }
}

impl Storage for VaultStorage {
    fn open(&self) -> StorageFuture<'_, ()> {
        Box::pin(async move {
            self.read().await.map_err(|e| self.named(e))?;
            self.data.open().await
        })
    }

    fn close(&self) -> StorageFuture<'_, ()> {
        Box::pin(async move {
            self.set_version(None);
            self.data.close().await
        })
    }

    fn delete(&self) -> StorageFuture<'_, ()> {
        Box::pin(async move {
            self.remove().await.map_err(|e| self.named(e))?;
            self.data.delete().await
        })
    }

    fn load_session(&self) -> StorageFuture<'_, Option<SessionData>> {
        Box::pin(async move { self.read().await.map_err(|e| self.named(e)) })
    }

    fn save_session<'a>(&'a self, session: &'a SessionData) -> StorageFuture<'a, ()> {
        Box::pin(async move { self.write(session).await.map_err(|e| self.named(e)) })
    }

    fn load_state(&self) -> StorageFuture<'_, Option<StoredState>> {
        self.data.load_state()
    }

    fn save_state<'a>(&'a self, state: &'a StoredState) -> StorageFuture<'a, ()> {
        self.data.save_state(state)
    }

    fn update_peers<'a>(&'a self, peers: &'a [PeerRecord]) -> StorageFuture<'a, ()> {
        self.data.update_peers(peers)
    }

    fn get_peer_by_id(&self, id: i64) -> StorageFuture<'_, Option<PeerRecord>> {
        self.data.get_peer_by_id(id)
    }

    fn get_peer_by_username<'a>(&'a self, username: &'a str) -> StorageFuture<'a, Option<PeerRecord>> {
        self.data.get_peer_by_username(username)
    }

    fn get_peer_by_phone_number<'a>(&'a self, phone_number: &'a str) -> StorageFuture<'a, Option<PeerRecord>> {
        self.data.get_peer_by_phone_number(phone_number)
    }

    fn export_peers(&self, limit: Option<usize>) -> StorageFuture<'_, Vec<PeerRecord>> {
        self.data.export_peers(limit)
    }

    fn clear_peers(&self) -> StorageFuture<'_, ()> {
        self.data.clear_peers()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::VaultStorage;
    use crate::session::Salt;
    use crate::storage::{MemoryStorage, PeerRecord, SessionData, Storage, StoredState, conformance};

    const TOKEN: &str = "hvs.hunter2";

    #[derive(Default)]
    struct Kv {
        // path -> (version, data of the latest version, None once deleted)
        secrets: HashMap<String, (u64, Option<Value>)>,
        fail_writes: bool,
        tokens: Vec<String>,
    }

    /// Just enough of Vault's KV v2 API for the requests the storage sends, one request per connection.
    struct MiniVault {
        addr: SocketAddr,
        kv: Arc<Mutex<Kv>>,
    }

    impl MiniVault {
        async fn start() -> MiniVault {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let kv = Arc::new(Mutex::new(Kv::default()));
            let shared = kv.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, shared.clone()));
                }
            });
            MiniVault { addr, kv }
        }

        fn url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn storage(&self) -> VaultStorage {
            VaultStorage::new(&self.url(), TOKEN, "secret", "bots/bot").unwrap()
        }

        fn secret(&self) -> Option<(u64, Option<Value>)> {
            self.kv.lock().unwrap().secrets.get("bots/bot").cloned()
        }

        fn put(&self, data: Value) {
            let mut kv = self.kv.lock().unwrap();
            let entry = kv.secrets.entry("bots/bot".into()).or_insert((0, None));
            *entry = (entry.0 + 1, Some(data));
        }
    }

    async fn serve(mut stream: TcpStream, kv: Arc<Mutex<Kv>>) {
        let mut buf = Vec::new();
        let mut chunk = [0; 4096];
        let head_end = loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut request = lines.next().unwrap_or("").split(' ');
        let (method, target) = (request.next().unwrap_or("").to_owned(), request.next().unwrap_or("").to_owned());
        let mut headers = HashMap::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
            }
        }
        let length: usize = headers.get("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
        while buf.len() < head_end + length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body: Value = serde_json::from_slice(&buf[head_end..head_end + length]).unwrap_or(Value::Null);
        let token = headers.get("x-vault-token").cloned().unwrap_or_default();
        let (status, reply) = handle(&mut kv.lock().unwrap(), &method, &target, &token, body);
        let reply = if reply.is_null() { String::new() } else { reply.to_string() };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    }

    fn handle(kv: &mut Kv, method: &str, target: &str, token: &str, body: Value) -> (&'static str, Value) {
        kv.tokens.push(token.to_owned());
        if token != TOKEN {
            return ("403 Forbidden", json!({ "errors": ["permission denied"] }));
        }
        let (kind, path) = match target.strip_prefix("/v1/secret/").and_then(|rest| rest.split_once('/')) {
            Some(found) => found,
            None => return ("404 Not Found", json!({ "errors": [] })),
        };
        let secret = kv.secrets.get(path).cloned();
        match (method, kind) {
            ("GET", "data") => match secret {
                Some((version, Some(data))) => {
                    ("200 OK", json!({ "data": { "data": data, "metadata": { "version": version } } }))
                }
                Some((version, None)) => {
                    ("404 Not Found", json!({ "data": { "data": null, "metadata": { "version": version } } }))
                }
                None => ("404 Not Found", json!({ "errors": [] })),
            },
            ("POST", "data") => {
                let current = secret.map_or(0, |(version, _)| version);
                if body["options"]["cas"].as_u64() != Some(current) {
                    let why = "check-and-set parameter did not match the current version";
                    return ("400 Bad Request", json!({ "errors": [why] }));
                }
                if kv.fail_writes {
                    return ("500 Internal Server Error", json!({ "errors": ["storage failed"] }));
                }
                kv.secrets.insert(path.to_owned(), (current + 1, Some(body["data"].clone())));
                ("200 OK", json!({ "data": { "version": current + 1 } }))
            }
            ("DELETE", "metadata") => {
                kv.secrets.remove(path);
                ("204 No Content", Value::Null)
            }
            _ => ("405 Method Not Allowed", json!({ "errors": [] })),
        }
    }

    fn session(user_id: i64) -> SessionData {
        let mut s = SessionData::new(4, [9; 256]);
        s.user_id = user_id;
        s
    }

    #[tokio::test]
    async fn conformance_against_a_mini_vault() {
        let vault = MiniVault::start().await;
        conformance::check(&vault.storage()).await;
        assert_eq!(vault.secret(), None, "delete removes every version");
        let tokens = vault.kv.lock().unwrap().tokens.clone();
        assert!(!tokens.is_empty() && tokens.iter().all(|t| t == TOKEN));
    }

    #[tokio::test]
    async fn non_session_data_goes_to_the_data_engine() {
        let vault = MiniVault::start().await;
        let data = Arc::new(MemoryStorage::new());
        let storage = vault.storage().data(data.clone());
        storage.open().await.unwrap();
        storage.save_session(&session(7)).await.unwrap();
        let state = StoredState::new(7, Salt { value: 1, time_offset: 0 }, None);
        storage.save_state(&state).await.unwrap();
        storage.update_peers(&[PeerRecord::new(5, 6)]).await.unwrap();

        let (version, fields) = vault.secret().unwrap();
        let fields = fields.unwrap();
        let mut names: Vec<&str> = fields.as_object().unwrap().keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!((version, names), (1, vec!["session", "vaegram"]));
        assert_eq!(fields["vaegram"], 1);
        assert!(fields["session"].as_str().unwrap().starts_with("VAE_"));
        assert_eq!(data.load_state().await.unwrap(), Some(state));
        assert_eq!(data.get_peer_by_id(5).await.unwrap(), Some(PeerRecord::new(5, 6)));
        assert!(data.load_session().await.unwrap().is_none(), "the login stays in Vault");
    }

    #[tokio::test]
    async fn token_never_in_debug_or_errors() {
        let vault = MiniVault::start().await;
        let storage = VaultStorage::new(&vault.url(), "hvs.wrong-secret", "secret", "bots/bot").unwrap();
        let debug = format!("{storage:?}");
        let error = storage.open().await.unwrap_err();
        assert_eq!(debug, r#"VaultStorage { host: "127.0.0.1", secret: "secret/bots/bot", .. }"#);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!error.to_string().contains("wrong-secret"), "{error}");
        assert!(error.to_string().contains("permission denied"), "{error}");

        let unreachable = VaultStorage::new("http://127.0.0.1:1", TOKEN, "secret", "bots/bot").unwrap();
        let error = unreachable.save_session(&session(1)).await.unwrap_err().to_string();
        assert!(!error.contains("hunter2"), "{error}");
    }

    #[tokio::test]
    async fn refuses_secrets_it_did_not_write_untouched() {
        let cases = [
            (json!({ "password": "theirs" }), "not a vaegram secret"),
            (json!({ "vaegram": 2, "session": "VAE_x" }), "newer vaegram"),
        ];
        for (data, why) in cases {
            let vault = MiniVault::start().await;
            vault.put(data.clone());
            let storage = vault.storage();
            let error = storage.open().await.unwrap_err();
            let saved = storage.save_session(&session(1)).await;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains(why), "{error}");
            assert!(saved.is_err());
            assert_eq!(vault.secret(), Some((1, Some(data))), "the secret was left as it is");
        }
    }

    #[tokio::test]
    async fn a_secret_changed_elsewhere_is_not_overwritten() {
        let vault = MiniVault::start().await;
        let storage = vault.storage();
        storage.save_session(&session(1)).await.unwrap();
        vault.put(json!({ "password": "theirs" }));
        let error = storage.save_session(&session(2)).await.unwrap_err();
        assert!(error.to_string().contains("changed since it was read"), "{error}");
        assert_eq!(vault.secret(), Some((2, Some(json!({ "password": "theirs" })))));
        assert!(storage.save_session(&session(2)).await.is_err(), "reading it again finds it foreign");
    }

    #[tokio::test]
    async fn a_failed_write_keeps_the_last_login() {
        let vault = MiniVault::start().await;
        let storage = vault.storage();
        storage.save_session(&session(1)).await.unwrap();
        vault.kv.lock().unwrap().fail_writes = true;
        assert!(storage.save_session(&session(2)).await.is_err());
        assert_eq!(storage.load_session().await.unwrap().map(|s| s.user_id), Some(1));
        vault.kv.lock().unwrap().fail_writes = false;
        storage.save_session(&session(2)).await.unwrap();
        assert_eq!(storage.load_session().await.unwrap().map(|s| s.user_id), Some(2));
        assert_eq!(vault.secret().map(|(version, _)| version), Some(2));
    }

    #[tokio::test]
    async fn a_deleted_latest_version_is_a_missing_login() {
        let vault = MiniVault::start().await;
        let storage = vault.storage();
        storage.save_session(&session(1)).await.unwrap();
        vault.kv.lock().unwrap().secrets.get_mut("bots/bot").unwrap().1 = None;
        assert!(storage.load_session().await.unwrap().is_none());
        storage.save_session(&session(3)).await.unwrap();
        assert_eq!(vault.secret().map(|(version, _)| version), Some(2));
    }

    #[tokio::test]
    async fn addresses_and_paths_are_checked() {
        let new = |addr: &str, mount: &str, path: &str| VaultStorage::new(addr, TOKEN, mount, path).map(drop);
        assert!(new("https://vault.example.com:8200", "secret", "bots/bot").is_ok());
        assert!(new("http://localhost:8200", "kv", "bot").is_ok());
        assert!(new("http://[::1]:8200", "kv", "bot").is_ok());
        let refused = new("http://vault.example.com:8200", "secret", "bot").unwrap_err();
        assert!(refused.to_string().contains("https"), "{refused}");
        assert!(new("https://user:pass@vault.example.com", "secret", "bot").is_err());
        assert!(new("https://vault.example.com", "secret", "../sys").is_err());
        assert!(new("https://vault.example.com", "", "bot").is_err());
        assert!(new("not a url", "secret", "bot").is_err());
        assert!(VaultStorage::new("https://vault.example.com", "bad\ntoken", "secret", "bot").is_err());

        let storage = VaultStorage::new("https://vault.example.com/prefix/", TOKEN, "/kv/", "bots//echo").unwrap();
        assert_eq!(storage.data_url.as_str(), "https://vault.example.com/prefix/v1/kv/data/bots/echo");
        assert_eq!(storage.metadata_url.as_str(), "https://vault.example.com/prefix/v1/kv/metadata/bots/echo");
    }

    #[tokio::test]
    #[ignore = "needs VAEGRAM_VAULT_ADDR and VAEGRAM_VAULT_TOKEN for a KV v2 mount `secret` it may write to"]
    async fn conformance_on_a_live_server() {
        let (Ok(addr), Ok(token)) = (std::env::var("VAEGRAM_VAULT_ADDR"), std::env::var("VAEGRAM_VAULT_TOKEN")) else {
            return;
        };
        let path = format!("vaegram-live-{}", std::process::id());
        conformance::check(&VaultStorage::new(&addr, &token, "secret", &path).unwrap()).await;
    }
}

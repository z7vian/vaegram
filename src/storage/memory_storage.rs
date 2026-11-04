use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::SessionData;
use super::engine::{PeerRecord, Storage, StorageFuture, StoredState};

/// Everything an engine keeps, with the username and phone indexes. File engines replay into it.
#[derive(Default)]
pub(crate) struct Tables {
    pub(crate) session: Option<SessionData>,
    pub(crate) state: Option<StoredState>,
    peers: HashMap<i64, PeerRecord>,
    usernames: HashMap<String, i64>,
    phones: HashMap<String, i64>,
}

impl Tables {
    pub(crate) fn upsert(&mut self, record: PeerRecord) {
        if let Some(old) = self.peers.remove(&record.id) {
            self.unindex(&old);
        }
        for username in &record.usernames {
            self.usernames.insert(username.clone(), record.id);
        }
        if let Some(phone) = &record.phone_number {
            self.phones.insert(phone.clone(), record.id);
        }
        self.peers.insert(record.id, record);
    }

    // A username or number another peer took since stays with that peer.
    fn unindex(&mut self, old: &PeerRecord) {
        for username in &old.usernames {
            if self.usernames.get(username) == Some(&old.id) {
                self.usernames.remove(username);
            }
        }
        if let Some(phone) = &old.phone_number {
            if self.phones.get(phone) == Some(&old.id) {
                self.phones.remove(phone);
            }
        }
    }

    pub(crate) fn clear_peers(&mut self) {
        self.peers.clear();
        self.usernames.clear();
        self.phones.clear();
    }

    pub(crate) fn peers(&self) -> impl Iterator<Item = &PeerRecord> {
        self.peers.values()
    }

    pub(crate) fn by_id(&self, id: i64) -> Option<PeerRecord> {
        self.peers.get(&id).cloned()
    }

    pub(crate) fn by_username(&self, username: &str) -> Option<PeerRecord> {
        self.usernames.get(username).and_then(|id| self.by_id(*id))
    }

    pub(crate) fn by_phone_number(&self, phone_number: &str) -> Option<PeerRecord> {
        self.phones.get(phone_number).and_then(|id| self.by_id(*id))
    }

    pub(crate) fn export(&self, limit: Option<usize>) -> Vec<PeerRecord> {
        let mut newest: Vec<&PeerRecord> = self.peers.values().collect();
        newest.sort_unstable_by(|a, b| b.updated.cmp(&a.updated).then(a.id.cmp(&b.id)));
        newest.into_iter().take(limit.unwrap_or(usize::MAX)).cloned().collect()
    }
}

/// Keeps everything in memory: nothing outlives the client unless the login is exported.
#[derive(Default)]
pub struct MemoryStorage(Mutex<Tables>);

impl MemoryStorage {
    pub fn new() -> MemoryStorage {
        MemoryStorage::default()
    }

    fn tables(&self) -> MutexGuard<'_, Tables> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryStorage").field("peers", &self.tables().peers.len()).finish_non_exhaustive()
    }
}

impl Storage for MemoryStorage {
    fn delete(&self) -> StorageFuture<'_, ()> {
        Box::pin(async move {
            *self.tables() = Tables::default();
            Ok(())
        })
    }

    fn load_session(&self) -> StorageFuture<'_, Option<SessionData>> {
        Box::pin(async move { Ok(self.tables().session.clone()) })
    }

    fn save_session<'a>(&'a self, session: &'a SessionData) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            self.tables().session = Some(session.clone());
            Ok(())
        })
    }

    fn load_state(&self) -> StorageFuture<'_, Option<StoredState>> {
        Box::pin(async move { Ok(self.tables().state.clone()) })
    }

    fn save_state<'a>(&'a self, state: &'a StoredState) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            self.tables().state = Some(state.clone());
            Ok(())
        })
    }

    fn update_peers<'a>(&'a self, peers: &'a [PeerRecord]) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            let mut tables = self.tables();
            for peer in peers {
                tables.upsert(peer.clone());
            }
            Ok(())
        })
    }

    fn get_peer_by_id(&self, id: i64) -> StorageFuture<'_, Option<PeerRecord>> {
        Box::pin(async move { Ok(self.tables().by_id(id)) })
    }

    fn get_peer_by_username<'a>(&'a self, username: &'a str) -> StorageFuture<'a, Option<PeerRecord>> {
        Box::pin(async move { Ok(self.tables().by_username(username)) })
    }

    fn get_peer_by_phone_number<'a>(&'a self, phone_number: &'a str) -> StorageFuture<'a, Option<PeerRecord>> {
        Box::pin(async move { Ok(self.tables().by_phone_number(phone_number)) })
    }

    fn export_peers(&self, limit: Option<usize>) -> StorageFuture<'_, Vec<PeerRecord>> {
        Box::pin(async move { Ok(self.tables().export(limit)) })
    }

    fn clear_peers(&self) -> StorageFuture<'_, ()> {
        Box::pin(async move {
            self.tables().clear_peers();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryStorage;

    #[tokio::test]
    async fn conformance() {
        super::super::conformance::check(&MemoryStorage::new()).await;
    }
}

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, mpsc as std_mpsc};
use std::time::Duration;

use tokio::sync::{Notify, mpsc, oneshot};

use super::{PeerRecord, SessionData, Storage, StoredState, UpdateState};
use crate::session::Salt;

const FLUSH_EVERY: Duration = Duration::from_secs(5);
const FLUSH_AT: usize = 512;
const DROP_WAIT: Duration = Duration::from_secs(10);
/// The newest peers loaded into memory at startup; older ones come from the engine when asked for.
pub(crate) const WARM_PEERS: usize = 4096;

type Job = Box<dyn FnOnce(Arc<dyn Storage>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

enum Message {
    Run(Job),
    Flush(oneshot::Sender<()>),
    Finish(std_mpsc::Sender<()>),
}

/// Writes waiting for the next flush: peers coalesced by id and the newest state.
#[derive(Default)]
struct Queued {
    peers: HashMap<i64, PeerRecord>,
    state: Option<StoredState>,
    // Set by log_out: nothing queued or still to come may write the old account back.
    dead: bool,
}

#[derive(Default)]
struct Pending {
    queued: Mutex<Queued>,
    full: Notify,
}

impl Pending {
    fn lock(&self) -> MutexGuard<'_, Queued> {
        self.queued.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A client's storage engine, run on a thread of its own with its own runtime, so engines may block or await as
/// they like, the caller's runtime is never blocked on, and dropping the client can still save on any runtime.
pub(crate) struct Store {
    engine: Arc<dyn Storage>,
    pending: Arc<Pending>,
    worker: OnceLock<io::Result<mpsc::UnboundedSender<Message>>>,
}

impl Store {
    pub(crate) fn new(engine: Arc<dyn Storage>) -> Store {
        Store { engine, pending: Arc::default(), worker: OnceLock::new() }
    }

    fn worker(&self) -> io::Result<&mpsc::UnboundedSender<Message>> {
        let worker = self.worker.get_or_init(|| {
            let (tx, rx) = mpsc::unbounded_channel();
            let (engine, pending) = (self.engine.clone(), self.pending.clone());
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            std::thread::Builder::new()
                .name("vaegram-store".into())
                .spawn(move || runtime.block_on(work(engine, pending, rx)))?;
            Ok(tx)
        });
        worker.as_ref().map_err(|e| io::Error::new(e.kind(), format!("couldn't start the store thread: {e}")))
    }

    fn started(&self) -> bool {
        self.worker.get().is_some()
    }

    #[cfg(test)]
    pub(crate) fn pending_is_empty(&self) -> bool {
        let queued = self.pending.lock();
        queued.peers.is_empty() && queued.state.is_none()
    }

    /// Runs `f` on the store thread and returns what it gives.
    pub(crate) async fn call<T, F>(&self, f: impl FnOnce(Arc<dyn Storage>) -> F + Send + 'static) -> io::Result<T>
    where
        T: Send + 'static,
        F: Future<Output = io::Result<T>> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let job: Job = Box::new(move |engine| {
            Box::pin(async move {
                let _ = tx.send(f(engine).await);
            })
        });
        self.worker()?.send(Message::Run(job)).map_err(|_| stopped())?;
        rx.await.map_err(|_| stopped())?
    }

    pub(crate) async fn open(&self) -> io::Result<()> {
        self.call(|e| async move { e.open().await }).await
    }

    pub(crate) async fn load_session(&self) -> io::Result<Option<SessionData>> {
        self.call(|e| async move { e.load_session().await }).await
    }

    /// The update state and salt saved for `user_id`. Another account's state, and every peer it saved, is
    /// dropped.
    pub(crate) async fn load_state(&self, user_id: i64) -> io::Result<(Option<UpdateState>, Salt)> {
        self.call(move |e| async move {
            match e.load_state().await? {
                Some(s) if s.owner == user_id => Ok((s.update, s.salt)),
                Some(_) => {
                    e.clear_peers().await?;
                    Ok(Default::default())
                }
                None => Ok(Default::default()),
            }
        })
        .await
    }

    pub(crate) async fn warm(&self) -> io::Result<Vec<PeerRecord>> {
        self.call(|e| async move { e.export_peers(Some(WARM_PEERS)).await }).await
    }

    pub(crate) async fn get_peer(&self, id: i64) -> io::Result<Option<PeerRecord>> {
        self.call(move |e| async move { e.get_peer_by_id(id).await }).await
    }

    pub(crate) async fn save_session(&self, session: SessionData) -> io::Result<()> {
        let pending = self.pending.clone();
        self.call(move |e| async move {
            // Checked on the store thread, after every job queued before log_out ran.
            if pending.lock().dead {
                return Ok(());
            }
            e.save_session(&session).await
        })
        .await
    }

    /// Queues peers for the next flush; a peer queued twice is written once, as last queued.
    pub(crate) fn queue_peers(&self, peers: impl IntoIterator<Item = PeerRecord>) {
        let full = {
            let mut queued = self.pending.lock();
            if queued.dead {
                return;
            }
            queued.peers.extend(peers.into_iter().map(|p| (p.id, p)));
            queued.peers.len() >= FLUSH_AT
        };
        self.start_flushing();
        if full {
            self.pending.full.notify_one();
        }
    }

    pub(crate) fn queue_state(&self, state: StoredState) {
        {
            let mut queued = self.pending.lock();
            if queued.dead {
                return;
            }
            queued.state = Some(state);
        }
        self.start_flushing();
    }

    fn start_flushing(&self) {
        if let Err(e) = self.worker() {
            eprintln!("vaegram: {e}; saves wait until it starts");
        }
    }

    /// Returns once everything queued so far is written, or has failed and been queued again.
    pub(crate) async fn flush(&self) {
        if !self.started() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        if self.worker().and_then(|w| w.send(Message::Flush(tx)).map_err(|_| stopped())).is_ok() {
            let _ = rx.await;
        }
    }

    /// Forgets the session, the state and every peer, and stops any write queued or still to come.
    pub(crate) async fn delete(&self) -> io::Result<()> {
        {
            let mut queued = self.pending.lock();
            queued.dead = true;
            queued.peers.clear();
            queued.state = None;
        }
        self.call(|e| async move { e.delete().await }).await
    }

    /// Queues `state`, writes what is queued and closes the engine, waiting at most `DROP_WAIT`. Called when the
    /// client is dropped, from whatever thread drops it.
    pub(crate) fn finish(&self, state: Option<StoredState>) {
        if let Some(state) = state {
            self.queue_state(state);
        }
        let Some(Ok(worker)) = self.worker.get() else { return };
        let (tx, rx) = std_mpsc::channel();
        if worker.send(Message::Finish(tx)).is_ok() && rx.recv_timeout(DROP_WAIT).is_err() {
            eprintln!("vaegram: the storage engine didn't finish saving within {DROP_WAIT:?}; giving up on it");
        }
    }
}

fn stopped() -> io::Error {
    io::Error::other("the store thread stopped")
}

async fn work(engine: Arc<dyn Storage>, pending: Arc<Pending>, mut rx: mpsc::UnboundedReceiver<Message>) {
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            message = rx.recv() => match message {
                Some(Message::Run(job)) => job(engine.clone()).await,
                Some(Message::Flush(done)) => {
                    flush(&*engine, &pending).await;
                    let _ = done.send(());
                }
                Some(Message::Finish(done)) => {
                    finish(&*engine, &pending).await;
                    let _ = done.send(());
                    return;
                }
                None => return finish(&*engine, &pending).await,
            },
            _ = tick.tick() => flush(&*engine, &pending).await,
            _ = pending.full.notified() => flush(&*engine, &pending).await,
        }
    }
}

async fn finish(engine: &dyn Storage, pending: &Pending) {
    flush(engine, pending).await;
    if let Err(e) = engine.close().await {
        eprintln!("vaegram: failed to close the storage engine: {e}");
    }
}

async fn flush(engine: &dyn Storage, pending: &Pending) {
    let peers: Vec<PeerRecord> = std::mem::take(&mut pending.lock().peers).into_values().collect();
    if !peers.is_empty() && !pending.lock().dead {
        if let Err(e) = engine.update_peers(&peers).await {
            eprintln!("vaegram: failed to save {} known chats: {e}", peers.len());
            // Back in the queue, unless a newer record of the same peer arrived meanwhile.
            let mut queued = pending.lock();
            for p in peers {
                queued.peers.entry(p.id).or_insert(p);
            }
        }
    }
    let Some(state) = pending.lock().state.take() else { return };
    if pending.lock().dead {
        return;
    }
    if let Err(e) = engine.save_state(&state).await {
        eprintln!("vaegram: failed to save the update state: {e}");
        pending.lock().state.get_or_insert(state);
    }
}

/// An engine over memory that records every call and can be told to fail them all.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Recording {
    calls: Mutex<Vec<&'static str>>,
    inner: super::MemoryStorage,
    fail: bool,
}

#[cfg(test)]
impl Recording {
    pub(crate) fn failing() -> Recording {
        Recording { fail: true, ..Recording::default() }
    }

    pub(crate) fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn call(&self, name: &'static str) -> io::Result<()> {
        self.calls.lock().unwrap().push(name);
        if self.fail { Err(io::Error::other("store is down")) } else { Ok(()) }
    }
}

#[cfg(test)]
impl Storage for Recording {
    fn open(&self) -> super::StorageFuture<'_, ()> {
        Box::pin(async move { self.call("open") })
    }

    fn close(&self) -> super::StorageFuture<'_, ()> {
        Box::pin(async move { self.call("close") })
    }

    fn delete(&self) -> super::StorageFuture<'_, ()> {
        Box::pin(async move {
            self.call("delete")?;
            self.inner.delete().await
        })
    }

    fn load_session(&self) -> super::StorageFuture<'_, Option<SessionData>> {
        Box::pin(async move {
            self.call("load_session")?;
            self.inner.load_session().await
        })
    }

    fn save_session<'a>(&'a self, session: &'a SessionData) -> super::StorageFuture<'a, ()> {
        Box::pin(async move {
            self.call("save_session")?;
            self.inner.save_session(session).await
        })
    }

    fn load_state(&self) -> super::StorageFuture<'_, Option<StoredState>> {
        Box::pin(async move {
            self.call("load_state")?;
            self.inner.load_state().await
        })
    }

    fn save_state<'a>(&'a self, state: &'a StoredState) -> super::StorageFuture<'a, ()> {
        Box::pin(async move {
            self.call("save_state")?;
            self.inner.save_state(state).await
        })
    }

    fn update_peers<'a>(&'a self, peers: &'a [PeerRecord]) -> super::StorageFuture<'a, ()> {
        Box::pin(async move {
            self.call("update_peers")?;
            self.inner.update_peers(peers).await
        })
    }

    fn get_peer_by_id(&self, id: i64) -> super::StorageFuture<'_, Option<PeerRecord>> {
        Box::pin(async move {
            self.call("get_peer_by_id")?;
            self.inner.get_peer_by_id(id).await
        })
    }

    fn export_peers(&self, limit: Option<usize>) -> super::StorageFuture<'_, Vec<PeerRecord>> {
        Box::pin(async move {
            self.call("export_peers")?;
            self.inner.export_peers(limit).await
        })
    }

    fn clear_peers(&self) -> super::StorageFuture<'_, ()> {
        Box::pin(async move {
            self.call("clear_peers")?;
            self.inner.clear_peers().await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{Recording, Store};
    use crate::session::Salt;
    use crate::storage::{MemoryStorage, PeerRecord, Storage, StorageFuture, StoredState, UpdateState};

    fn state(pts: i32) -> StoredState {
        StoredState::new(7, Salt::default(), Some(UpdateState { pts, date: 1, ..UpdateState::default() }))
    }

    #[tokio::test]
    async fn jobs_run_on_the_store_thread() {
        let store = Store::new(Arc::new(MemoryStorage::new()));
        let name = store.call(|_| async { Ok(std::thread::current().name().map(str::to_owned)) }).await.unwrap();
        assert_eq!(name.as_deref(), Some("vaegram-store"));
        assert_ne!(std::thread::current().name(), Some("vaegram-store"));
    }

    #[tokio::test]
    async fn peers_are_coalesced_by_id() {
        let engine = Arc::new(Recording::default());
        let store = Store::new(engine.clone());
        let mut newer = PeerRecord::new(1, 2);
        newer.updated = 5;
        store.queue_peers([PeerRecord::new(1, 1), PeerRecord::new(2, 1)]);
        store.queue_peers([newer.clone()]);
        store.flush().await;
        assert_eq!(engine.calls(), ["update_peers"], "one write for the batch");
        let saved = engine.export_peers(None).await.unwrap();
        assert_eq!(saved, [newer, PeerRecord::new(2, 1)]);
    }

    #[tokio::test]
    async fn a_failed_flush_keeps_the_writes_queued() {
        let store = Store::new(Arc::new(Recording::failing()));
        store.queue_peers([PeerRecord::new(1, 1)]);
        store.queue_state(state(3));
        store.flush().await;
        let queued = store.pending.lock();
        assert_eq!(
            (queued.peers.len(), queued.state.as_ref().and_then(|s| s.update.as_ref()).map(|u| u.pts)),
            (1, Some(3))
        );
    }

    #[tokio::test]
    async fn drop_flushes_the_last_state() {
        let engine = Arc::new(MemoryStorage::new());
        let store = Store::new(engine.clone());
        store.queue_peers([PeerRecord::new(1, 1)]);
        let saved = tokio::task::spawn_blocking(move || store.finish(Some(state(9)))).await;
        saved.unwrap();
        assert_eq!(engine.load_state().await.unwrap(), Some(state(9)));
        assert_eq!(engine.export_peers(None).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_store_that_never_worked_starts_no_thread_on_drop() {
        let store = Store::new(Arc::new(MemoryStorage::new()));
        store.finish(None);
        assert!(!store.started());
    }

    /// Never finishes a state save.
    struct Stuck(MemoryStorage);

    impl Storage for Stuck {
        fn delete(&self) -> StorageFuture<'_, ()> {
            self.0.delete()
        }
        fn load_session(&self) -> StorageFuture<'_, Option<crate::storage::SessionData>> {
            self.0.load_session()
        }
        fn save_session<'a>(&'a self, s: &'a crate::storage::SessionData) -> StorageFuture<'a, ()> {
            self.0.save_session(s)
        }
        fn load_state(&self) -> StorageFuture<'_, Option<StoredState>> {
            self.0.load_state()
        }
        fn save_state<'a>(&'a self, _: &'a StoredState) -> StorageFuture<'a, ()> {
            Box::pin(std::future::pending())
        }
        fn update_peers<'a>(&'a self, p: &'a [PeerRecord]) -> StorageFuture<'a, ()> {
            self.0.update_peers(p)
        }
        fn get_peer_by_id(&self, id: i64) -> StorageFuture<'_, Option<PeerRecord>> {
            self.0.get_peer_by_id(id)
        }
        fn clear_peers(&self) -> StorageFuture<'_, ()> {
            self.0.clear_peers()
        }
    }

    #[tokio::test]
    async fn drop_gives_up_after_the_timeout() {
        let store = Store::new(Arc::new(Stuck(MemoryStorage::new())));
        store.queue_peers([PeerRecord::new(1, 1)]);
        let started = std::time::Instant::now();
        tokio::task::spawn_blocking(move || store.finish(Some(state(1)))).await.unwrap();
        let waited = started.elapsed();
        assert!(waited >= super::DROP_WAIT && waited < super::DROP_WAIT + Duration::from_secs(5), "{waited:?}");
    }

    #[tokio::test]
    async fn log_out_stops_queued_writes() {
        let engine = Arc::new(Recording::default());
        let store = Store::new(engine.clone());
        store.queue_peers([PeerRecord::new(1, 1)]);
        store.queue_state(state(2));
        store.delete().await.unwrap();
        store.queue_peers([PeerRecord::new(2, 1)]);
        store.queue_state(state(3));
        let mut session = crate::storage::SessionData::new(2, [1; 256]);
        session.user_id = 7;
        store.save_session(session).await.unwrap();
        store.flush().await;
        assert_eq!(engine.calls(), ["delete"]);
    }

    #[tokio::test]
    async fn state_of_another_account_clears_peers() {
        let engine = Arc::new(MemoryStorage::new());
        engine.save_state(&state(4)).await.unwrap();
        engine.update_peers(&[PeerRecord::new(1, 1)]).await.unwrap();
        let store = Store::new(engine.clone());
        let mine = store.load_state(7).await.unwrap();
        let other = store.load_state(8).await.unwrap();
        assert_eq!(mine.0.map(|u| u.pts), Some(4));
        assert_eq!(other, (None, Salt::default()));
        assert!(engine.export_peers(None).await.unwrap().is_empty());
    }
}

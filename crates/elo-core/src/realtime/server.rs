use super::*;
use crate::{replica::ReplicaError, retention_access::Actor, sync::access};
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, Semaphore, mpsc};

const QUEUE: usize = 64;
const MAX_CONNECTIONS: usize = 1024;
const MAX_IDENTITY_CONNECTIONS: usize = 8;
const MAX_DEVICE_CONNECTIONS: usize = 2;
const MAX_QUEUED_BYTES: usize = 256 * 1024;
// Leave room for the complete subscription handshake plus ten publications per
// second. Control frames are counted too, so Ping cannot bypass the frame budget.
const FRAMES_PER_TEN_SECONDS: usize = 200;
const PUBLICATIONS_PER_SECOND: usize = 10;

struct RateBudget {
    started: tokio::time::Instant,
    count: usize,
    limit: usize,
    window: Duration,
}
impl RateBudget {
    fn new(now: tokio::time::Instant, limit: usize, window: Duration) -> Self {
        Self {
            started: now,
            count: 0,
            limit,
            window,
        }
    }
    fn admit(&mut self, now: tokio::time::Instant) -> bool {
        if now.duration_since(self.started) >= self.window {
            self.started = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= self.limit
    }
}

struct Notice {
    id: String,
    slot: Arc<AtomicBool>,
    envelope: Arc<str>,
    actor: Actor,
    companion: bool,
}
struct Listener {
    id: String,
    mailbox: MailboxId,
    identity: IdentityId,
    sender: mpsc::Sender<Notice>,
    changed: Arc<Notify>,
    hint_pending: Arc<AtomicBool>,
    queued_bytes: Arc<AtomicUsize>,
}
#[derive(Default)]
pub(crate) struct Events {
    next: AtomicU64,
    listeners: Mutex<BTreeMap<u64, Listener>>,
}
struct Registration {
    id: u64,
    bus: Arc<Events>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.bus.listeners.lock().unwrap().remove(&self.id);
    }
}
impl Events {
    fn subscribe(self: &Arc<Self>, listener: Listener) -> Registration {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.listeners.lock().unwrap().insert(id, listener);
        Registration {
            id,
            bus: self.clone(),
        }
    }
    pub(crate) fn changed(&self, mailbox: MailboxId) {
        for listener in self.listeners.lock().unwrap().values() {
            if listener.mailbox == mailbox && !listener.hint_pending.swap(true, Ordering::AcqRel) {
                // Durable hints never compete for the ephemeral queue. One bit
                // per live subscription and one wakeup per connection coalesce
                // bursts without losing a hint when a recipient is slow.
                listener.changed.notify_one();
            }
        }
    }
    fn publish(
        &self,
        mailbox: MailboxId,
        actor: Actor,
        companion: bool,
        recipients: &BTreeSet<IdentityId>,
        envelope: &str,
    ) {
        let envelope: Arc<str> = Arc::from(envelope);
        for listener in self.listeners.lock().unwrap().values() {
            if listener.mailbox == mailbox && recipients.contains(&listener.identity) {
                if listener
                    .queued_bytes
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |bytes| {
                        (bytes + envelope.len() <= MAX_QUEUED_BYTES)
                            .then_some(bytes + envelope.len())
                    })
                    .is_err()
                {
                    continue;
                }
                if listener
                    .sender
                    .try_send(Notice {
                        id: listener.id.clone(),
                        slot: listener.hint_pending.clone(),
                        envelope: envelope.clone(),
                        actor,
                        companion,
                    })
                    .is_err()
                {
                    // Dropping transient data must not disconnect its recipient
                    // or retain the byte reservation for an unqueued message.
                    listener
                        .queued_bytes
                        .fetch_sub(envelope.len(), Ordering::AcqRel);
                }
            }
        }
    }
}

struct Subscription {
    request: SubscriptionRequest,
    actor: Actor,
    companion: bool,
    store: ReplicaStore,
    hint_pending: Arc<AtomicBool>,
    _registration: Registration,
}
fn duplicate_subscription(
    subscriptions: &BTreeMap<String, Subscription>,
    store: &ReplicaStore,
    request: &SubscriptionRequest,
    actor: Actor,
) -> bool {
    subscriptions.values().any(|existing| {
        existing.store.key() == store.key()
            && existing.request.mailbox == request.mailbox
            && existing.actor.identity == actor.identity
            && existing.actor.credential == actor.credential
    })
}
#[derive(Default)]
struct Connections {
    identities: BTreeMap<IdentityId, BTreeSet<u64>>,
    devices: BTreeMap<RecordId, BTreeSet<u64>>,
}
impl Connections {
    fn admit(&mut self, connection: u64, actor: Actor) -> bool {
        let identities = self.identities.entry(actor.identity).or_default();
        if !identities.contains(&connection) && identities.len() >= MAX_IDENTITY_CONNECTIONS {
            return false;
        }
        let devices = self.devices.entry(actor.credential).or_default();
        if !devices.contains(&connection) && devices.len() >= MAX_DEVICE_CONNECTIONS {
            return false;
        }
        identities.insert(connection);
        devices.insert(connection);
        true
    }
    fn remove(&mut self, connection: u64) {
        self.identities.retain(|_, ids| {
            ids.remove(&connection);
            !ids.is_empty()
        });
        self.devices.retain(|_, ids| {
            ids.remove(&connection);
            !ids.is_empty()
        });
    }
}
struct ConnectionGuard {
    id: u64,
    server: Arc<Server>,
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.server.connections.lock().unwrap().remove(self.id);
    }
}

pub struct Server {
    origin: String,
    path: String,
    resolver: Arc<dyn Resolver>,
    slots: Arc<Semaphore>,
    verification: Arc<Semaphore>,
    connections: Mutex<Connections>,
    next_connection: AtomicU64,
}
impl Server {
    pub fn new(origin: &str, path: &str, resolver: Arc<dyn Resolver>) -> Arc<Self> {
        Arc::new(Self {
            origin: reqwest::Url::parse(origin)
                .expect("validated realtime origin")
                .origin()
                .ascii_serialization(),
            path: path.into(),
            resolver,
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            verification: Arc::new(Semaphore::new(2)),
            connections: Mutex::new(Connections::default()),
            next_connection: AtomicU64::new(1),
        })
    }
    pub fn router(self: Arc<Self>) -> axum::Router {
        axum::Router::new()
            .route(&self.path.clone(), get(upgrade))
            .with_state(self)
    }
    async fn authorized(&self, subscription: &Subscription) -> Result<(), ReplicaError> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let store = self
                .resolver
                .resolve(&subscription.request.replica)
                .await
                .ok_or(ReplicaError::Unauthorized)?;
            if store.key() != subscription.store.key() {
                return Err(ReplicaError::Unauthorized);
            }
            authorize(
                &store,
                &subscription.request,
                subscription.actor,
                subscription.companion,
            )
            .await
        })
        .await
        .map_err(|_| ReplicaError::Unauthorized)?
    }
    async fn subscribe(
        &self,
        request: &SubscriptionRequest,
        proof: String,
    ) -> Result<(ReplicaStore, Actor, bool), ReplicaError> {
        if request.id.is_empty()
            || request.id.len() > 64
            || !request
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || request.replica.len() > 256
            || request.read_token.len() > 256
        {
            return Err(ReplicaError::Invalid);
        }
        let store = self
            .resolver
            .resolve(&request.replica)
            .await
            .ok_or(ReplicaError::Unauthorized)?;
        // Reject invalid mailbox tokens before doing public-key proof work.
        store
            .authorize(request.mailbox, request.read_token.clone(), false)
            .await?;
        let body = serde_json::to_vec(request).map_err(|_| ReplicaError::Invalid)?;
        let origin = self.origin.clone();
        let path = self.path.clone();
        let key = *store.key();
        let permit = tokio::time::timeout(
            Duration::from_secs(2),
            self.verification.clone().acquire_owned(),
        )
        .await
        .map_err(|_| ReplicaError::Unauthorized)?
        .map_err(|_| ReplicaError::Unauthorized)?;
        let access = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            access::verify(
                &proof,
                &access::RequestContext {
                    origin: &origin,
                    replica: &key,
                    method: "SUBSCRIBE",
                    path: &path,
                    body: &body,
                    transfer: "",
                    retention: "",
                },
            )
            .map_err(|_| ReplicaError::Unauthorized)
        })
        .await
        .map_err(|_| ReplicaError::Unauthorized)??;
        let actor = Actor {
            identity: access.identity,
            credential: access.credential,
        };
        authorize(&store, request, actor, access.companion).await?;
        let companion = access.companion;
        store.consume_access(access).await?;
        Ok((store, actor, companion))
    }
}
async fn authorize(
    store: &ReplicaStore,
    request: &SubscriptionRequest,
    actor: Actor,
    companion: bool,
) -> Result<(), ReplicaError> {
    store.require_active_device(actor.credential)?;
    if companion {
        store.require_admitted_companion(actor.credential)?;
    }
    store
        .authorize(request.mailbox, request.read_token.clone(), false)
        .await?;
    store
        .authorize_identity(request.mailbox, Some(actor.identity))
        .await
}
async fn upgrade(
    State(server): State<Arc<Server>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if headers
        .get("origin")
        .is_some_and(|origin| origin.to_str().ok() != Some(server.origin.as_str()))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(permit) = server.slots.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .write_buffer_size(0)
        .max_write_buffer_size(128 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            connected(server, socket).await;
        })
        .into_response()
}
async fn send(socket: &mut WebSocket, frame: ServerFrame) -> bool {
    let Ok(text) = serde_json::to_string(&frame) else {
        return false;
    };
    matches!(
        tokio::time::timeout(
            Duration::from_secs(3),
            socket.send(Message::Text(text.into()))
        )
        .await,
        Ok(Ok(()))
    )
}
async fn connected(server: Arc<Server>, mut socket: WebSocket) {
    let connection = ConnectionGuard {
        id: server.next_connection.fetch_add(1, Ordering::Relaxed),
        server: server.clone(),
    };
    let (sender, mut receiver) = mpsc::channel::<Notice>(QUEUE);
    let changed = Arc::new(Notify::new());
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let mut subscriptions = BTreeMap::<String, Subscription>::new();
    let authentication = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(authentication);
    let mut tick = tokio::time::interval(Duration::from_secs(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut seen = tokio::time::Instant::now();
    let mut frames = RateBudget::new(seen, FRAMES_PER_TEN_SECONDS, Duration::from_secs(10));
    let mut publications = RateBudget::new(seen, PUBLICATIONS_PER_SECOND, Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = &mut authentication, if subscriptions.is_empty() => break,
            incoming = socket.recv() => {
                seen = tokio::time::Instant::now();
                if !frames.admit(seen) { break; }
                let text = match incoming {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    _ => break,
                };
                let Ok(frame) = serde_json::from_str::<ClientFrame>(&text) else { break; };
                match frame {
                    ClientFrame::Subscribe { request, proof } => {
                        if subscriptions.len() >= MAX_SUBSCRIPTIONS || subscriptions.contains_key(&request.id) { break; }
                        let result = tokio::time::timeout(Duration::from_secs(5), server.subscribe(&request, proof)).await;
                        let Ok(Ok((store, actor, companion))) = result else {
                            let _ = send(&mut socket, ServerFrame::Error { code: "unauthorized".into() }).await; break;
                        };
                        if duplicate_subscription(&subscriptions, &store, &request, actor) {
                            if !send(&mut socket, ServerFrame::Error { code: "duplicate_subscription".into() }).await { break; }
                            continue;
                        }
                        if !server.connections.lock().unwrap().admit(connection.id, actor) { break; }
                        let hint_pending = Arc::new(AtomicBool::new(false));
                        let registration = store.realtime.subscribe(Listener { id: request.id.clone(), mailbox: request.mailbox,
                            identity: actor.identity, sender: sender.clone(), changed: changed.clone(), hint_pending: hint_pending.clone(), queued_bytes: queued_bytes.clone() });
                        let id = request.id.clone();
                        subscriptions.insert(id.clone(), Subscription { request, actor, companion, store, hint_pending, _registration: registration });
                        if !send(&mut socket, ServerFrame::Subscribed { id: id.clone() }).await { break; }
                        // Subscribe-before-snapshot closes the reconnect race; hints contain no trusted data.
                        if !send(&mut socket, ServerFrame::Changed { id }).await { break; }
                    }
                    ClientFrame::Unsubscribe { id } => { subscriptions.remove(&id); }
                    ClientFrame::Publish { request } => {
                        if !publications.admit(seen) { break; }
                        if request.envelope.is_empty() || request.envelope.len() > MAX_ENVELOPE
                            || request.recipients.is_empty() || request.recipients.len() > 256 { break; }
                        let Some(subscription) = subscriptions.get(&request.subscription) else { break; };
                        if server.authorized(subscription).await.is_err() { break; }
                        let recipients = request.recipients.into_iter().collect::<BTreeSet<_>>();
                        subscription.store.realtime.publish(subscription.request.mailbox, subscription.actor, subscription.companion, &recipients, &request.envelope);
                    }
                }
            }
            _ = changed.notified() => {
                let pending = subscriptions.iter()
                    .filter(|(_, subscription)| subscription.hint_pending.swap(false, Ordering::AcqRel))
                    .map(|(id, _)| id.clone()).collect::<Vec<_>>();
                for id in pending {
                    let Some(subscription) = subscriptions.get(&id) else { continue; };
                    let frame = if server.authorized(subscription).await.is_err() {
                        subscriptions.remove(&id);
                        ServerFrame::Revoked { id }
                    } else {
                        ServerFrame::Changed { id }
                    };
                    if !send(&mut socket, frame).await { return; }
                }
            }
            Some(notice) = receiver.recv() => {
                queued_bytes.fetch_sub(notice.envelope.len(), Ordering::AcqRel);
                let Some(subscription) = subscriptions.get(&notice.id) else { continue; };
                if !Arc::ptr_eq(&notice.slot, &subscription.hint_pending) { continue; }
                if server.authorized(subscription).await.is_err() {
                    subscriptions.remove(&notice.id);
                    if !send(&mut socket, ServerFrame::Revoked { id: notice.id }).await { break; }
                    continue;
                }
                // A queued event never extends a revoked sender's access.
                if subscription.store.require_active_device(notice.actor.credential).is_err()
                    || (notice.companion && subscription.store.require_admitted_companion(notice.actor.credential).is_err())
                    || subscription.store.authorize_identity(subscription.request.mailbox, Some(notice.actor.identity)).await.is_err() { continue; }
                let frame = ServerFrame::Ephemeral { id: notice.id, envelope: notice.envelope.to_string(), identity: notice.actor.identity, credential: notice.actor.credential };
                if !send(&mut socket, frame).await { break; }
            }
            _ = tick.tick() => {
                if seen.elapsed() > Duration::from_secs(60) { break; }
                let mut revoked = Vec::new();
                for (id, subscription) in &subscriptions {
                    if server.authorized(subscription).await.is_err() { revoked.push(id.clone()); }
                }
                for id in revoked {
                    subscriptions.remove(&id);
                    if !send(&mut socket, ServerFrame::Revoked { id }).await { return; }
                }
                if !matches!(tokio::time::timeout(Duration::from_secs(3), socket.send(Message::Ping(Vec::new().into()))).await, Ok(Ok(()))) { break; }
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), socket.send(Message::Close(None))).await;
}

#[cfg(test)]
mod tests;

//! Native, unlock-bound live transport. Only verified presentation events enter WebView.
use elo_core::{
    app::{
        AttachmentActivity, ClientApp,
        realtime::{Event, MAX_SCOPES, Payload, Scope, Snapshot, Target, UploadStatus},
    },
    realtime::{ClientFrame, MAX_FRAME, ServerFrame},
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{Emitter, Manager};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Context {
    expected_identity: String,
    expected_space: Option<String>,
    active: bool,
    #[serde(default)]
    scopes: Vec<Scope>,
    typing: Option<Scope>,
    focus: Option<Scope>,
}
#[derive(Clone)]
struct Upload {
    scope: Scope,
    payload: Payload,
    until: u64,
}
#[derive(Clone, Default)]
struct Input {
    snapshot: Option<Arc<Snapshot>>,
    context: Context,
    typing_at: u64,
    uploads: BTreeMap<String, Upload>,
    epoch: u64,
    suspended: bool,
}
pub(crate) struct Live {
    input: watch::Sender<Input>,
}
impl Default for Live {
    fn default() -> Self {
        Self {
            input: watch::channel(Input {
                suspended: true,
                ..Input::default()
            })
            .0,
        }
    }
}
impl Input {
    fn refresh(&mut self, snapshot: Option<Arc<Snapshot>>) {
        if self.suspended && snapshot.is_some() {
            return;
        }
        let changed =
            self.snapshot.as_ref().map(|s| s.identity) != snapshot.as_ref().map(|s| s.identity);
        if changed {
            self.epoch = self.epoch.wrapping_add(1);
            self.context = Context::default();
            self.uploads.clear();
        }
        self.snapshot = snapshot;
    }
    fn suspend(&mut self) {
        self.suspended = true;
        self.epoch = self.epoch.wrapping_add(1);
        self.snapshot = None;
        self.context = Context::default();
        self.uploads.clear();
    }
    fn accepts_prepared(&self, epoch: u64, snapshot: &Arc<Snapshot>) -> bool {
        self.epoch == epoch
            && !self.suspended
            && self
                .snapshot
                .as_ref()
                .is_some_and(|live| Arc::ptr_eq(live, snapshot))
    }
}
pub(crate) fn refresh(app: &tauri::AppHandle, client: Option<&ClientApp>) {
    let snapshot = client.map(ClientApp::realtime_snapshot);
    app.state::<Live>()
        .input
        .send_modify(|input| input.refresh(snapshot));
}
pub(crate) fn activate(app: &tauri::AppHandle, client: &ClientApp) {
    let snapshot = client.realtime_snapshot();
    app.state::<Live>().input.send_modify(|input| {
        input.suspended = false;
        input.refresh(Some(snapshot));
    });
}
pub(crate) fn clear(app: &tauri::AppHandle) {
    app.state::<Live>().input.send_modify(Input::suspend);
}

#[tauri::command]
pub(crate) async fn realtime_context(
    app: tauri::AppHandle,
    context: Context,
) -> Result<(), String> {
    if context.scopes.len() > MAX_SCOPES {
        return Err("Too many live conversations.".into());
    }
    // Mutations and unlock refresh the native snapshot. A typing pulse only
    // changes presentation context; it must not copy profile keys or wait
    // behind an upload. Lock revokes the snapshot independently.
    let live = app.state::<Live>();
    let snapshot = live
        .input
        .borrow()
        .snapshot
        .clone()
        .ok_or("The profile is locked")?;
    if snapshot.identity.to_string() != context.expected_identity
        || snapshot.active_space != context.expected_space
    {
        return Err("The open profile or Space has changed.".into());
    }
    let allowed: Vec<_> = context
        .scopes
        .iter()
        .filter(|scope| snapshot.permits(scope))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let typing = context.typing.filter(|scope| allowed.contains(scope));
    let focus = context.focus.filter(|scope| allowed.contains(scope));
    snapshot.prioritize_membership_focus(focus.as_ref());
    live.input.send_modify(|input| {
        input.typing_at = now();
        input.context = Context {
            scopes: allowed,
            typing,
            focus,
            ..context
        };
    });
    Ok(())
}

pub(crate) fn activity(
    app: &tauri::AppHandle,
    identity: elo_core::ids::IdentityId,
    scope: &Scope,
    event: AttachmentActivity,
) {
    let live = app.state::<Live>();
    live.input.send_modify(|input| {
        if input
            .snapshot
            .as_ref()
            .is_none_or(|s| s.identity != identity || !s.permits(scope))
        {
            return;
        }
        input.uploads.retain(|_, upload| upload.until > now());
        match event {
            AttachmentActivity::Uploading {
                attachment_id,
                name,
                size_bytes,
                ..
            } => {
                if input.uploads.len() >= 16 {
                    return;
                }
                input.uploads.insert(
                    attachment_id.to_string(),
                    Upload {
                        scope: scope.clone(),
                        payload: Payload::Upload {
                            attachment_id,
                            name,
                            size: size_bytes,
                            status: UploadStatus::Uploading,
                            record: None,
                        },
                        until: now() + 600_000,
                    },
                );
            }
            terminal => {
                let (id, status, record) = match terminal {
                    AttachmentActivity::Ready {
                        attachment_id,
                        record,
                    } => (attachment_id, UploadStatus::Ready, Some(record)),
                    AttachmentActivity::Cancelled { attachment_id } => {
                        (attachment_id, UploadStatus::Cancelled, None)
                    }
                    AttachmentActivity::Interrupted { attachment_id } => {
                        (attachment_id, UploadStatus::Interrupted, None)
                    }
                    _ => return,
                };
                if let Some(upload) = input.uploads.get_mut(&id.to_string())
                    && let Payload::Upload {
                        status: old,
                        record: old_record,
                        ..
                    } = &mut upload.payload
                {
                    if *old == UploadStatus::Ready {
                        return;
                    }
                    *old = status;
                    *old_record = record;
                    upload.until = now() + 60_000;
                }
            }
        }
    });
}

#[derive(Clone)]
struct Plan {
    input: Input,
    targets: Vec<Target>,
}
struct Worker {
    source: WorkerSource,
    update: watch::Sender<Plan>,
    task: tokio::task::JoinHandle<()>,
}
#[derive(Clone)]
struct WorkerSource {
    epoch: u64,
    host: String,
    token: Arc<()>,
}
impl WorkerSource {
    fn is_current(&self, epoch: u64, active: Option<&Self>) -> bool {
        // A gracefully closing worker can outlive its replacement on the same host.
        self.epoch == epoch
            && active.is_some_and(|active| {
                active.epoch == self.epoch
                    && active.host == self.host
                    && Arc::ptr_eq(&active.token, &self.token)
            })
    }
}
enum Incoming {
    Connected {
        source: WorkerSource,
        ids: BTreeSet<String>,
    },
    Sync {
        source: WorkerSource,
        space: String,
    },
    Event {
        source: WorkerSource,
        event: Box<Event>,
    },
}

pub(crate) fn setup(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut input = app.state::<Live>().input.subscribe();
        let (send, mut receive) = mpsc::channel(128);
        let crypto = Arc::new(Semaphore::new(2));
        let mut workers = BTreeMap::<String, Worker>::new();
        let mut connections = BTreeMap::<String, BTreeSet<String>>::new();
        let mut events = BTreeMap::<String, Event>::new();
        let mut epoch = input.borrow().epoch;
        let mut target_snapshot: Option<Arc<Snapshot>> = None;
        let mut target_enabled = false;
        let mut cached_targets = Vec::new();
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let mut changed = false;
            let mut plan_changed = false;
            tokio::select! {
                result = input.changed() => { if result.is_err() { break; } changed = true; plan_changed = true; },
                incoming = receive.recv() => match incoming {
                    Some(Incoming::Connected { source, ids }) if source.is_current(input.borrow().epoch, workers.get(&source.host).map(|worker| &worker.source)) => { connections.insert(source.host, ids); changed = true; },
                    Some(Incoming::Sync { source, space }) if source.is_current(input.borrow().epoch, workers.get(&source.host).map(|worker| &worker.source)) => {
                        if let Some(snapshot) = input.borrow().snapshot.as_ref() {
                            let _ = app.emit("realtime-event", json!({"type":"sync", "identity":snapshot.identity, "space_context":space}));
                            #[cfg(desktop)]
                            crate::desktop_activity::realtime_changed(&app, &space);
                        }
                    },
                    Some(Incoming::Event { source, event }) if source.is_current(input.borrow().epoch, workers.get(&source.host).map(|worker| &worker.source)) => {
                        let key = event.key();
                        if event.expires_at_ms > now() && input.borrow().snapshot.as_ref().is_some_and(|s| s.allows_event(&event))
                            && events.get(&key).is_none_or(|old| old.created_at_ms < event.created_at_ms)
                            && (events.len() < 1024 || events.contains_key(&key))
                        {
                            if matches!(&event.payload, Payload::Upload { status: UploadStatus::Ready, .. }) {
                                let _ = app.emit("realtime-event", json!({"type":"sync", "identity":input.borrow().snapshot.as_ref().map(|s| s.identity), "space_context":event.space_context}));
                                #[cfg(desktop)]
                                crate::desktop_activity::realtime_changed(&app, &event.space_context);
                            }
                            events.insert(key, *event); changed = true;
                        }
                    },
                    Some(_) => {}, None => break,
                },
                _ = timer.tick() => {},
            }
            let current = input.borrow().clone();
            if current.epoch != epoch {
                epoch = current.epoch;
                for (_, worker) in std::mem::take(&mut workers) {
                    worker.task.abort();
                }
                connections.clear();
                events.clear();
                changed = true;
            }
            let allowed = !crate::release_policy::required(&app)
                && current.snapshot.is_some()
                && (cfg!(desktop)
                    || current.context.active
                    || current.uploads.values().any(|u| u.until > now()));
            let same_snapshot = match (&target_snapshot, &current.snapshot) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            };
            if target_enabled != allowed || !same_snapshot {
                target_enabled = allowed;
                target_snapshot = current.snapshot.clone();
                cached_targets = if allowed {
                    current
                        .snapshot
                        .as_ref()
                        .map(|s| s.targets())
                        .unwrap_or_default()
                } else {
                    vec![]
                };
            }
            let all_targets = &cached_targets;
            // Excess replicas retain ordinary synchronization instead of repeatedly
            // overflowing the server's per-socket subscription budget.
            let mut targets = all_targets.to_vec();
            let mut host_counts = BTreeMap::<String, usize>::new();
            targets.retain(|target| {
                let count = host_counts.entry(target.url.clone()).or_default();
                *count += 1;
                *count <= elo_core::realtime::MAX_SUBSCRIPTIONS
            });
            let mut by_host = BTreeMap::<String, Vec<Target>>::new();
            for target in &targets {
                by_host
                    .entry(target.url.clone())
                    .or_default()
                    .push(target.clone());
            }
            let removed: Vec<_> = workers
                .keys()
                .filter(|host| !by_host.contains_key(*host))
                .cloned()
                .collect();
            for host in removed {
                if let Some(worker) = workers.remove(&host) {
                    // A bounded graceful close publishes inactive presence when possible.
                    let mut stop = current.clone();
                    stop.context.active = false;
                    stop.context.typing = None;
                    worker.update.send_replace(Plan {
                        input: stop,
                        targets: vec![],
                    });
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        worker.task.abort();
                    });
                }
                connections.remove(&host);
                changed = true;
            }
            for (host, targets) in by_host {
                let plan = Plan {
                    input: current.clone(),
                    targets,
                };
                if let Some(worker) = workers.get(&host) {
                    // Publishing a plan only on real input changes avoids a wakeup feedback loop.
                    if plan_changed {
                        worker.update.send_replace(plan);
                    }
                } else {
                    let (update, rx) = watch::channel(plan);
                    let source = WorkerSource {
                        epoch: current.epoch,
                        host: host.clone(),
                        token: Arc::new(()),
                    };
                    let task = tokio::spawn(connection(
                        source.clone(),
                        rx,
                        send.clone(),
                        input.clone(),
                        crypto.clone(),
                    ));
                    workers.insert(
                        host,
                        Worker {
                            source,
                            update,
                            task,
                        },
                    );
                }
            }
            let time = now();
            let before = events.len();
            events.retain(|_, event| {
                if current
                    .snapshot
                    .as_ref()
                    .is_none_or(|s| !s.allows_event(event))
                {
                    return false;
                }
                if event.expires_at_ms <= time {
                    if let Payload::Upload { status, .. } = &mut event.payload
                        && *status == UploadStatus::Uploading
                    {
                        *status = UploadStatus::Interrupted;
                        event.expires_at_ms = time + 60_000;
                        changed = true;
                        return true;
                    }
                    return false;
                }
                true
            });
            changed |= before != events.len();
            if changed {
                let connected_ids: BTreeSet<_> = connections
                    .values()
                    .flat_map(|ids| ids.iter().cloned())
                    .collect();
                let spaces: BTreeSet<_> = all_targets
                    .iter()
                    .filter(|target| connected_ids.contains(&target.id))
                    .filter(|target| {
                        all_targets
                            .iter()
                            .filter(|t| t.space_context == target.space_context)
                            .all(|t| connected_ids.contains(&t.id))
                    })
                    .map(|target| target.space_context.clone())
                    .collect();
                let identity = current
                    .snapshot
                    .as_ref()
                    .map(|s| s.identity.to_string())
                    .unwrap_or_else(|| current.context.expected_identity.clone());
                let _ = app.emit(
                    "realtime-event",
                    json!({"type":"state", "identity":identity,
                    "connected_spaces":spaces, "events":events.values().collect::<Vec<_>>() }),
                );
            }
        }
        for (_, worker) in workers {
            worker.task.abort();
        }
    });
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
async fn send(socket: &mut Socket, message: Message) -> Result<(), ()> {
    tokio::time::timeout(Duration::from_secs(3), socket.send(message))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}
async fn frame(socket: &mut Socket, value: ClientFrame) -> Result<(), ()> {
    let text = serde_json::to_string(&value).map_err(|_| ())?;
    if text.len() > MAX_FRAME {
        return Err(());
    }
    send(socket, Message::Text(text.into())).await
}
fn fingerprint(targets: &[Target]) -> Vec<(String, String, String)> {
    targets
        .iter()
        .map(|t| (t.id.clone(), t.credential.to_string(), t.signature()))
        .collect()
}
async fn connection(
    source: WorkerSource,
    mut plans: watch::Receiver<Plan>,
    output: mpsc::Sender<Incoming>,
    live: watch::Receiver<Input>,
    crypto: Arc<Semaphore>,
) {
    let mut attempt = 0u32;
    loop {
        let plan = plans.borrow().clone();
        if plan.targets.is_empty() {
            break;
        }
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME))
            .max_frame_size(Some(MAX_FRAME))
            .write_buffer_size(0)
            .max_write_buffer_size(256 * 1024);
        let connected = tokio::time::timeout(
            Duration::from_secs(5),
            connect_async_with_config(&source.host, Some(config), false),
        )
        .await;
        if let Ok(Ok((socket, _))) = connected {
            let started = Instant::now();
            let _ = session(socket, &source, &mut plans, &output, &live, &crypto).await;
            if started.elapsed() > Duration::from_secs(30) {
                attempt = 0;
            }
        }
        if output
            .send(Incoming::Connected {
                source: source.clone(),
                ids: BTreeSet::new(),
            })
            .await
            .is_err()
        {
            break;
        }
        attempt = (attempt + 1).min(6);
        let mut random = [0u8; 2];
        let _ = getrandom::fill(&mut random);
        let delay = Duration::from_millis(
            (1000u64 << (attempt - 1)).min(30_000) + u16::from_le_bytes(random) as u64 % 1000,
        );
        // Changes in foreground drafts must not bypass network failure backoff.
        tokio::time::sleep(delay).await;
        if plans.has_changed().is_err() {
            break;
        }
    }
}

async fn session(
    mut socket: Socket,
    source: &WorkerSource,
    plans: &mut watch::Receiver<Plan>,
    output: &mpsc::Sender<Incoming>,
    live: &watch::Receiver<Input>,
    crypto: &Arc<Semaphore>,
) -> Result<(), ()> {
    let initial = plans.borrow().clone();
    let epoch = source.epoch;
    let original = fingerprint(&initial.targets);
    let targets: BTreeMap<_, _> = initial
        .targets
        .iter()
        .map(|t| (t.id.clone(), t.clone()))
        .collect();
    for target in targets.values() {
        frame(&mut socket, target.subscribe().map_err(|_| ())?).await?;
    }
    let subscribed_at = Instant::now();
    let mut subscribed = BTreeSet::new();
    let mut last_sent = BTreeMap::<String, (Scope, Payload, u64)>::new();
    let mut deferred = BTreeMap::<String, u64>::new();
    let mut tick = tokio::time::interval(Duration::from_millis(125));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut next_send = Instant::now();
    let mut last_rx = Instant::now();
    let mut ping_at = Instant::now();
    let mut input_window = Instant::now();
    let mut input_count = 0u32;
    loop {
        let mut publish = false;
        let mut plan_changed = false;
        tokio::select! {
            message = socket.next() => {
                let message = message.ok_or(())?.map_err(|_| ())?;
                last_rx = Instant::now();
                if input_window.elapsed() >= Duration::from_secs(1) { input_window = Instant::now(); input_count = 0; }
                input_count += 1; if input_count > 256 { return Err(()); }
                match message {
                    Message::Ping(bytes) => send(&mut socket, Message::Pong(bytes)).await?,
                    Message::Pong(_) => {},
                    Message::Text(text) => match serde_json::from_str::<ServerFrame>(&text).map_err(|_| ())? {
                        ServerFrame::Subscribed { id } => {
                            let target = targets.get(&id).ok_or(())?;
                            subscribed.insert(id);
                            output.send(Incoming::Connected { source: source.clone(), ids: subscribed.clone() }).await.map_err(|_| ())?;
                            output.send(Incoming::Sync { source: source.clone(), space: target.space_context.clone() }).await.map_err(|_| ())?;
                        }
                        ServerFrame::Changed { id } => {
                            let target = targets.get(&id).filter(|_| subscribed.contains(&id)).ok_or(())?;
                            output.send(Incoming::Sync { source: source.clone(), space: target.space_context.clone() }).await.map_err(|_| ())?;
                        }
                        ServerFrame::Revoked { id } => {
                            subscribed.remove(&id);
                            output.send(Incoming::Connected { source: source.clone(), ids: subscribed.clone() }).await.map_err(|_| ())?;
                            // Clear stale authority through ordinary authenticated synchronization.
                            if let Some(target) = targets.get(&id) { output.send(Incoming::Sync { source: source.clone(), space: target.space_context.clone() }).await.map_err(|_| ())?; }
                            return Err(());
                        }
                        ServerFrame::Ephemeral { id, envelope, identity, credential } => {
                            let target = targets.get(&id).filter(|_| subscribed.contains(&id)).ok_or(())?;
                            let current = live.borrow().clone();
                            if current.epoch != epoch || current.suspended { return Err(()); }
                            let snapshot = current.snapshot.ok_or(())?;
                            let context = target.space_context.clone();
                            let permit = crypto.clone().acquire_owned().await.map_err(|_| ())?;
                            let event = tokio::task::spawn_blocking(move || { let _permit = permit; snapshot.open(&context, &envelope, identity, credential, now()) }).await.map_err(|_| ())?;
                            if let Ok(event) = event { output.send(Incoming::Event { source: source.clone(), event: Box::new(event) }).await.map_err(|_| ())?; }
                        }
                        ServerFrame::Error { .. } => return Err(()),
                    },
                    _ => return Err(()),
                }
            }
            result = plans.changed() => { result.map_err(|_| ())?; publish = true; plan_changed = true; },
            _ = tick.tick() => { publish = true; },
        }
        let plan = plans.borrow().clone();
        if plan.input.epoch != epoch {
            return Err(());
        }
        let closing = plan.targets.is_empty();
        if !closing && plan_changed && fingerprint(&plan.targets) != original {
            return Err(());
        }
        if last_rx.elapsed() > Duration::from_secs(60) {
            return Err(());
        }
        if subscribed.len() < targets.len() && subscribed_at.elapsed() > Duration::from_secs(10) {
            return Err(());
        }
        if ping_at.elapsed() >= Duration::from_secs(20) {
            send(&mut socket, Message::Ping(vec![].into())).await?;
            ping_at = Instant::now();
        }
        if !publish || Instant::now() < next_send {
            continue;
        }
        let Some(snapshot) = plan.input.snapshot else {
            return Err(());
        };
        let time = now();
        let mut desired = BTreeMap::<String, (Scope, Payload, u64)>::new();
        if plan.input.context.active && !closing {
            for scope in &plan.input.context.scopes {
                if targets
                    .values()
                    .any(|t| t.space_context == scope.space_context)
                    && snapshot.permits(scope)
                {
                    desired.insert(
                        format!(
                            "presence/{}/{}/{}",
                            scope.space_context, scope.space, scope.stream
                        ),
                        (scope.clone(), Payload::Presence { active: true }, 40_000),
                    );
                }
            }
            if time < plan.input.typing_at.saturating_add(8_000)
                && let Some(scope) = &plan.input.context.typing
            {
                desired.insert(
                    format!(
                        "typing/{}/{}/{}",
                        scope.space_context, scope.space, scope.stream
                    ),
                    (scope.clone(), Payload::Typing { active: true }, 3_000),
                );
            }
        }
        if !closing {
            for (id, upload) in &plan.input.uploads {
                if upload.until > time
                    && targets
                        .values()
                        .any(|t| t.space_context == upload.scope.space_context)
                {
                    desired.insert(
                        format!("upload/{id}"),
                        (upload.scope.clone(), upload.payload.clone(), 10_000),
                    );
                }
            }
        }
        for (key, (scope, payload, _)) in &last_sent {
            if !desired.contains_key(key) {
                let inactive = match payload {
                    Payload::Presence { active: true } => Some(Payload::Presence { active: false }),
                    Payload::Typing { active: true } => Some(Payload::Typing { active: false }),
                    _ => None,
                };
                if let Some(payload) = inactive {
                    desired.insert(key.clone(), (scope.clone(), payload, u64::MAX));
                }
            }
        }
        let mut due: Vec<_> = desired
            .iter()
            .filter(|(key, (_, payload, renewal))| {
                if deferred.get(*key).is_some_and(|until| *until > time) {
                    return false;
                }
                last_sent.get(*key).is_none_or(|(_, previous, sent)| {
                    previous != payload || time.saturating_sub(*sent) >= *renewal
                })
            })
            .collect();
        due.sort_by_key(|(key, (scope, payload, _))| {
            (
                matches!(payload, Payload::Presence { .. }),
                plan.input.context.focus.as_ref() != Some(scope),
                last_sent.get(*key).map(|(_, _, sent)| *sent).unwrap_or(0),
            )
        });
        if let Some((key, (scope, payload, _))) = due.first() {
            let target = targets
                .values()
                .find(|t| t.space_context == scope.space_context && subscribed.contains(&t.id));
            if let Some(target) = target {
                let crypto_snapshot = snapshot.clone();
                let target = target.clone();
                let to_scope = scope.clone();
                let to_payload = payload.clone();
                let permit = crypto.clone().acquire_owned().await.map_err(|_| ())?;
                let to_send = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    crypto_snapshot.publication(&target, &to_scope, to_payload, time)
                })
                .await
                .map_err(|_| ())?;
                // Crypto runs off-thread. A lock, block or authority refresh while
                // it ran invalidates the prepared recipients before any send.
                let current = live.borrow().clone();
                if current.epoch != epoch || current.suspended {
                    return Err(());
                }
                if !current.accepts_prepared(epoch, &snapshot) {
                    continue;
                }
                if plans.has_changed().unwrap_or(true) {
                    continue;
                }
                if let Ok(value) = to_send {
                    frame(&mut socket, value).await?;
                    last_sent.insert((*key).clone(), (scope.clone(), payload.clone(), time));
                    deferred.remove(*key);
                } else {
                    // Permission leases can expire between normal status passes.
                    // Wait locally without reporting an optional hint as sent.
                    deferred.insert((*key).clone(), time + 1_000);
                }
                next_send = Instant::now() + Duration::from_millis(125);
            }
        } else if closing {
            let _ = send(&mut socket, Message::Close(None)).await;
            return Ok(());
        }
        deferred.retain(|key, _| desired.contains_key(key));
        last_sent.retain(|key, (_, payload, _)| {
            desired.contains_key(key)
                || matches!(
                    payload,
                    Payload::Presence { active: true } | Payload::Typing { active: true }
                )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replaced_worker_notifications_cannot_clear_a_live_connection() {
        let epoch = 7;
        let previous = WorkerSource {
            epoch,
            host: "wss://example.test/hosting/v1/realtime".into(),
            token: Arc::new(()),
        };
        let active = WorkerSource {
            token: Arc::new(()),
            ..previous.clone()
        };
        let subscribed = BTreeSet::from(["current-subscription".to_owned()]);
        let mut connections = BTreeMap::from([(active.host.clone(), subscribed.clone())]);
        let late_disconnect = Incoming::Connected {
            source: previous.clone(),
            ids: BTreeSet::new(),
        };
        if let Incoming::Connected { source, ids } = late_disconnect
            && source.is_current(epoch, Some(&active))
        {
            connections.insert(source.host, ids);
        }
        assert_eq!(connections.get(&active.host), Some(&subscribed));
        assert!(active.clone().is_current(epoch, Some(&active)));
        assert!(!previous.is_current(epoch, Some(&active)));
        assert!(!active.is_current(epoch, None));
        // Input can advance before the manager consumes its change notification.
        assert!(!active.is_current(epoch + 1, Some(&active)));
        let other_host = WorkerSource {
            host: "wss://other.example.test/hosting/v1/realtime".into(),
            ..active.clone()
        };
        assert!(!active.is_current(epoch, Some(&other_host)));
    }
    #[tokio::test]
    async fn lock_rejects_late_operation_snapshots_and_old_prepared_publications() {
        let directory = tempfile::tempdir().unwrap();
        let client = elo_core::app::ProfileDraft::new()
            .unwrap()
            .save(
                directory.path().join("profile"),
                "synthetic live lifecycle password".into(),
                "Test",
            )
            .await
            .unwrap();
        let snapshot = client.realtime_snapshot();
        let mut input = Live::default().input.borrow().clone();
        input.refresh(Some(snapshot.clone()));
        assert!(input.snapshot.is_none());
        input.suspended = false;
        input.refresh(Some(snapshot.clone()));
        input.context.active = true;
        let epoch = input.epoch;
        assert!(input.accepts_prepared(epoch, &snapshot));
        // A permissions refresh invalidates ciphertext prepared against the old view.
        let refreshed = client.realtime_snapshot();
        input.refresh(Some(refreshed.clone()));
        assert!(!input.accepts_prepared(epoch, &snapshot));
        assert!(input.accepts_prepared(epoch, &refreshed));
        input.suspend();
        input.refresh(Some(refreshed.clone()));
        assert!(input.snapshot.is_none());
        assert!(!input.context.active);
        assert!(!input.accepts_prepared(epoch, &refreshed));
        // A new explicit unlock can resume, but never revive a prior connection epoch.
        input.suspended = false;
        input.refresh(Some(client.realtime_snapshot()));
        assert!(input.snapshot.is_some());
        assert_ne!(input.epoch, epoch);
        client.close().await.unwrap();
    }
}

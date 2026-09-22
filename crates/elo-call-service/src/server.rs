//! Bounded WebSocket transport. A socket is bound to its first verified device;
//! every operation also requires current hosting admission.
use crate::{
    engine::{Engine, MAX_FRAME, Request},
    registry::{CallError, Event, Scope},
};
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use elo_core::ids::{IdentityId, RecordId, SpaceId};
use serde_json::json;
use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Semaphore, broadcast};
use zeroize::Zeroizing;

pub type AdmissionFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, CallError>> + Send + 'a>>;
pub trait Admission: Send + Sync {
    fn allowed(&self, space: SpaceId, identity: IdentityId) -> AdmissionFuture<'_>;
    fn device_allowed(
        &self,
        space: SpaceId,
        identity: IdentityId,
        _device: RecordId,
        _scope: elo_core::calls::CallScope,
        _head: RecordId,
    ) -> AdmissionFuture<'_> {
        self.allowed(space, identity)
    }
}
pub struct HostingAdmission {
    client: reqwest::Client,
    url: String,
    key: Zeroizing<String>,
}
impl HostingAdmission {
    pub fn new(
        url: &str,
        key: Zeroizing<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = reqwest::Url::parse(url)?;
        let local = parsed
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.query().is_some()
            || parsed.path() != "/internal/calls/admission"
        {
            return Err("Use a private HTTPS or loopback hosting admission endpoint.".into());
        }
        if key.len() != 64
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Invalid hosting admission key.".into());
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build()?;
        Ok(Self {
            client,
            url: url.into(),
            key,
        })
    }
}
impl HostingAdmission {
    fn check(
        &self,
        space: SpaceId,
        identity: IdentityId,
        device: Option<(RecordId, elo_core::calls::CallScope, RecordId)>,
    ) -> AdmissionFuture<'_> {
        Box::pin(async move {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Reply {
                allowed: bool,
            }
            let response = self
                .client
                .post(&self.url)
                .bearer_auth(self.key.as_str())
                .json(&json!({"space_id":space,"identity_id":identity,"device":device}))
                .send()
                .await
                .map_err(|_| CallError::Unavailable)?;
            if !response.status().is_success() {
                return Err(CallError::Unavailable);
            }
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| CallError::Unavailable)? {
                if bytes.len() + chunk.len() > 1024 {
                    return Err(CallError::Unavailable);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(serde_json::from_slice::<Reply>(&bytes)
                .map_err(|_| CallError::Unavailable)?
                .allowed)
        })
    }
}

impl Admission for HostingAdmission {
    fn allowed(&self, space: SpaceId, identity: IdentityId) -> AdmissionFuture<'_> {
        self.check(space, identity, None)
    }
    fn device_allowed(
        &self,
        space: SpaceId,
        identity: IdentityId,
        device: RecordId,
        scope: elo_core::calls::CallScope,
        head: RecordId,
    ) -> AdmissionFuture<'_> {
        self.check(space, identity, Some((device, scope, head)))
    }
}

pub struct Service {
    engine: Mutex<Engine>,
    admission: Arc<dyn Admission>,
    media: Option<Arc<crate::media::Provider>>,
    events: broadcast::Sender<Event>,
    wake: Option<Arc<crate::wake::Delivery>>,
    connections: Arc<Semaphore>,
}
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl Service {
    pub fn new(engine: Engine, admission: Arc<dyn Admission>, max_connections: usize) -> Arc<Self> {
        Self::with_media(engine, admission, max_connections, None)
    }
    pub fn with_media(
        engine: Engine,
        admission: Arc<dyn Admission>,
        max_connections: usize,
        media: Option<Arc<crate::media::Provider>>,
    ) -> Arc<Self> {
        let (events, _) = broadcast::channel(256);
        Arc::new(Self {
            engine: Mutex::new(engine),
            admission,
            media,
            events,
            wake: None,
            connections: Arc::new(Semaphore::new(max_connections.clamp(1, 4096))),
        })
    }
    pub fn with_wake(mut self: Arc<Self>, wake: Arc<crate::wake::Delivery>) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("Configure call delivery before sharing the service")
            .wake = Some(wake);
        self
    }
    pub async fn deliver_wakes(&self) {
        if let Some(wake) = &self.wake {
            let declined = wake.declined().await;
            let events = {
                let mut engine = self.engine.lock().await;
                declined
                    .into_iter()
                    .flat_map(|(id, recipient)| engine.background_decline(&id, recipient))
                    .collect()
            };
            let _ = self.publish_media(events).await;
            wake.deliver(self.admission.as_ref(), now()).await;
        }
    }
    async fn queue_wakes(&self, events: &[Event]) {
        use elo_core::calls::{CallKind, InitialMedia, wake::Notice};
        let Some(wake) = &self.wake else {
            return;
        };
        let notices = {
            let engine = self.engine.lock().await;
            events
                .iter()
                .filter_map(|event| match event {
                    Event::Presence { call } if call.kind == CallKind::Direct => {
                        let notice = if call.ringing {
                            Notice::Ring {
                                call_id: call.call_id.clone(),
                                scope: elo_core::calls::wake::scope(
                                    call.scope.hosting_space_id,
                                    call.scope.conversation,
                                ),
                                head: call.config_id,
                                caller: call.started_by,
                                recipients: engine.wake_recipients(call),
                                expires: call.started_at
                                    + engine.registry.limits.ring_timeout.min(60),
                                video: call.initial_media == InitialMedia::Video,
                            }
                        } else {
                            Notice::End {
                                call_id: call.call_id.clone(),
                            }
                        };
                        notice.valid(now()).then_some((call.scope, notice))
                    }
                    Event::Ended { scope, call_id } => Some((
                        *scope,
                        Notice::End {
                            call_id: call_id.clone(),
                        },
                    )),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        for (scope, notice) in notices {
            wake.enqueue(scope, notice, now()).await;
        }
    }
    fn publish(&self, events: Vec<Event>) {
        for event in events {
            let _ = self.events.send(event);
        }
    }
    async fn publish_media(&self, events: Vec<Event>) -> Result<(), CallError> {
        // Notify peers before closing the previous epoch's room. Otherwise a
        // deliberate rekey disconnect could be mistaken for a failed call.
        self.queue_wakes(&events).await;
        self.publish(events.clone());
        if let Some(media) = &self.media {
            media.reconcile(&events, now()).await?;
        }
        Ok(())
    }
    pub async fn maintain(&self) {
        let events = {
            let mut engine = self.engine.lock().await;
            engine
                .maintain(now())
                .unwrap_or_else(|_| engine.registry.tick(u64::MAX))
        };
        if self.publish_media(events).await.is_err() {
            let ended = self.engine.lock().await.registry.tick(u64::MAX);
            self.queue_wakes(&ended).await;
            self.publish(ended);
        }
    }
}
pub fn app(service: Arc<Service>) -> Router {
    Router::new()
        .route("/calls/v1/connect", get(upgrade))
        .route("/calls/v1/health", get(|| async { StatusCode::NO_CONTENT }))
        .with_state(service)
}
async fn upgrade(State(service): State<Arc<Service>>, ws: WebSocketUpgrade) -> impl IntoResponse {
    let Ok(permit) = service.connections.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .max_write_buffer_size(256 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            connected(service, socket).await;
        })
        .into_response()
}
async fn send(socket: &mut WebSocket, value: serde_json::Value) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(3),
            socket.send(Message::Text(value.to_string().into()))
        )
        .await,
        Ok(Ok(()))
    )
}
async fn connected(service: Arc<Service>, mut socket: WebSocket) {
    let mut receiver = service.events.subscribe();
    let mut device: Option<RecordId> = None;
    let mut identity: Option<IdentityId> = None;
    let mut scopes = BTreeSet::<Scope>::new();
    let authentication = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(authentication);
    let mut admission_tick = tokio::time::interval(Duration::from_secs(5));
    admission_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut window = now();
    let mut commands = 0usize;
    loop {
        tokio::select! {
            _ = &mut authentication, if device.is_none() => break,
            message = socket.recv() => {
                let text = match message {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    _ => break,
                };
                let time = now();
                if time.saturating_sub(window) >= 10 { window = time; commands = 0; }
                commands += 1;
                if commands > 120 { break; }
                let request = match serde_json::from_str::<Request>(&text) {
                    Ok(request) => request,
                    Err(_) => { let _ = send(&mut socket, json!({"type":"error","code":CallError::Invalid})).await; break; }
                };
                let prepared = service.engine.lock().await.prepare(request, device, time);
                let prepared = match prepared {
                    Ok(prepared) => prepared,
                    Err(code) => { if !send(&mut socket, json!({"type":"error","code":code})).await { break; } continue; }
                };
                let wants_media=matches!(prepared.command.operation, elo_core::calls::Operation::ConnectMedia { .. });
                let request_id = prepared.request_id;
                let scope = Scope::from(&prepared.command);
                if scopes.len() >= 32 && !scopes.contains(&scope) {
                    if !send(&mut socket, json!({"type":"error","request_id":request_id,"code":CallError::Unavailable})).await { break; }
                    continue;
                }
                let admission = service.admission.device_allowed(scope.hosting_space_id, prepared.identity, prepared.command.credential_id, prepared.command.scope, prepared.command.config_id).await;
                match admission {
                    Ok(true) => {}
                    result => {
                        scopes.remove(&scope);
                        let events = service.engine.lock().await.registry.revoke_member(scope, prepared.identity);
                        let _ = service.publish_media(events).await;
                        let code = result.err().unwrap_or(CallError::Unauthorized);
                        if !send(&mut socket, json!({"type":"error","request_id":request_id,"code":code})).await { break; }
                        continue;
                    }
                }
                let bound_device = prepared.command.credential_id;
                let bound_identity = prepared.identity;
                let mut engine = service.engine.lock().await;
                let applied = engine.execute(prepared, now());
                let authority_events = engine.take_events();
                drop(engine);
                if service.publish_media(authority_events).await.is_err() { break; }
                match applied {
                    Ok(result) => {
                        device = Some(bound_device); identity = Some(bound_identity); scopes.insert(scope);
                        if service.publish_media(result.events).await.is_err() {
                            let ended=service.engine.lock().await.registry.revoke_member(scope,bound_identity);
                            let _ = service.publish_media(ended).await;
                            if !send(&mut socket,json!({"type":"error","request_id":request_id,"code":CallError::Unavailable})).await { break; }
                            continue;
                        }
                        let media=if wants_media {
                            result.call.as_ref().and_then(|call|service.media.as_ref().and_then(|provider|provider.access(call,bound_device,now()).ok()))
                        } else { None };
                        if !send(&mut socket, json!({"type":"result","request_id":result.request_id,"scope":result.scope,
                            "call":result.call,"duplicate":result.duplicate,"media":media})).await { break; }
                    }
                    Err(code) => {
                        if !send(&mut socket, json!({"type":"error","request_id":request_id,"code":code})).await { break; }
                    }
                }
            }
            event = receiver.recv(), if device.is_some() => {
                let Ok(event) = event else { break; }; // A slow consumer reconnects for a fresh snapshot.
                let scope = match &event {
                    Event::Presence { call } => call.scope,
                    Event::Ended { scope, .. } | Event::Signal { scope, .. } => *scope,
                };
                let credential = device.unwrap();
                if !scopes.contains(&scope) || matches!(&event, Event::Signal { to, .. } if *to != credential) { continue; }
                if !service.engine.lock().await.authorized(scope, credential) {
                    scopes.remove(&scope);
                    if !send(&mut socket, json!({"type":"access_revoked","scope":scope})).await { break; }
                    continue;
                }
                if !send(&mut socket, serde_json::to_value(&event).unwrap()).await { break; }
            }
            _ = admission_tick.tick(), if device.is_some() => {
                for scope in scopes.clone() {
                    let head = service.engine.lock().await.authorized_head(scope, device.unwrap(), now());
                    let admitted = if let Some(head) = head {
                        matches!(service.admission.device_allowed(scope.hosting_space_id, identity.unwrap(), device.unwrap(), scope.conversation, head).await, Ok(true))
                    } else { false };
                    if !admitted {
                        scopes.remove(&scope);
                        let events = service.engine.lock().await.registry.revoke_member(scope, identity.unwrap());
                        let _ = service.publish_media(events).await;
                        if !send(&mut socket, json!({"type":"access_revoked","scope":scope})).await { return; }
                    }
                }
            }
        }
    }
    // Keep the short participant lease so a transient socket reconnect can
    // recover the same device session. Heartbeat expiry eventually ends it.
    let _ = tokio::time::timeout(Duration::from_secs(1), socket.send(Message::Close(None))).await;
}

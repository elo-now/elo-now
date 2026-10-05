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
    routing::{get, post},
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
use tokio::sync::{Mutex, Semaphore};
mod events;
mod subscriptions;
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
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            let body = json!({"space_id":space,"identity_id":identity,"device":device});
            let mut response = None;
            for attempt in 0..2 {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(CallError::Unavailable);
                }
                let result = self
                    .client
                    .post(&self.url)
                    .bearer_auth(self.key.as_str())
                    .json(&body)
                    .timeout(remaining)
                    .send()
                    .await;
                match result {
                    Ok(reply) if reply.status().is_success() => {
                        response = Some(reply);
                        break;
                    }
                    Ok(reply) if attempt == 0 && matches!(reply.status().as_u16(), 502..=504) => {}
                    Err(error) if attempt == 0 && (error.is_connect() || error.is_timeout()) => {}
                    _ => return Err(CallError::Unavailable),
                }
                // Only a transient read failure is retried, once, within the same
                // deadline. A membership denial is never retried or cached as allowed.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let response = response.ok_or(CallError::Unavailable)?;
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
    events: Arc<events::Events>,
    connections: Arc<Semaphore>,
    verification: Arc<Semaphore>,
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
        let events = Arc::new(events::Events::default());
        Arc::new(Self {
            engine: Mutex::new(engine),
            admission,
            media,
            events,
            connections: Arc::new(Semaphore::new(max_connections.clamp(1, 4096))),
            verification: Arc::new(Semaphore::new(2)),
        })
    }
    fn publish(&self, events: Vec<Event>) {
        for event in events {
            self.events.send(event);
        }
    }
    async fn publish_media(&self, events: Vec<Event>) -> Result<(), CallError> {
        // Notify peers before closing the previous epoch's room. Otherwise a
        // deliberate rekey disconnect could be mistaken for a failed call.
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
            self.publish(ended);
        }
    }
}
pub fn app(service: Arc<Service>) -> Router {
    Router::new()
        .route("/calls/v1/connect", get(upgrade))
        .route("/calls/v1/state", post(current_state))
        .route("/calls/v1/health", get(|| async { StatusCode::NO_CONTENT }))
        .with_state(service)
}
/// Native notification senders read current presence using the same signed
/// Subscribe operation and hosting admission as a WebSocket. This route cannot
/// start, join, renew or publish media for a participant.
async fn current_state(
    State(service): State<Arc<Service>>,
    request: axum::extract::Request,
) -> Result<axum::Json<serde_json::Value>, StatusCode> {
    let permit = service
        .verification
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let body = tokio::time::timeout(
        Duration::from_secs(5),
        axum::body::to_bytes(request.into_body(), MAX_FRAME),
    )
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
    .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let request: Request = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let job = service
        .engine
        .lock()
        .await
        .preparation(request, None)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let (job, (command, identity), permit) = tokio::task::spawn_blocking(move || {
        let authenticated = job.authenticate(now());
        authenticated.map(|value| (job, value, permit))
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::FORBIDDEN)?;
    if !matches!(command.operation, elo_core::calls::Operation::Subscribe) {
        return Err(StatusCode::FORBIDDEN);
    }
    if !matches!(
        service
            .admission
            .device_allowed(
                command.hosting_space_id,
                identity,
                command.credential_id,
                command.scope,
                command.config_id
            )
            .await,
        Ok(true)
    ) {
        return Err(StatusCode::FORBIDDEN);
    }
    let (prepared, _permit) =
        tokio::task::spawn_blocking(move || job.verify(now()).map(|prepared| (prepared, permit)))
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map_err(|_| StatusCode::FORBIDDEN)?;
    let mut engine = service.engine.lock().await;
    let expired = engine.registry.tick(now());
    let applied = engine.execute(prepared, now());
    let mut events = engine.take_events();
    events.extend(expired);
    drop(engine);
    service
        .publish_media(events)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let applied = applied.map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(axum::Json(json!({"call":applied.call})))
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
    let mut admission_cursor = None;
    let mut grants = subscriptions::Grants::new();
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
                // Bound both deserialization and proof work, including unauthenticated sockets.
                let Ok(Ok(permit)) = tokio::time::timeout(Duration::from_secs(3), service.verification.clone().acquire_owned()).await else {
                    let _ = send(&mut socket, json!({"type":"error","code":CallError::Unavailable})).await;
                    break;
                };
                let request = match serde_json::from_str::<Request>(&text) {
                    Ok(request) => request,
                    Err(_) => { let _ = send(&mut socket, json!({"type":"error","code":CallError::Invalid})).await; break; }
                };
                let job = service.engine.lock().await.preparation(request, device);
                let authenticated = match job {
                    Ok(job) => tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        job.authenticate(time).map(|auth| (job, auth))
                    }).await.unwrap_or(Err(CallError::Unavailable)),
                    Err(error) => Err(error),
                };
                let (job, (command, sender)) = match authenticated {
                    Ok(value) => value,
                    Err(code) => { let _ = send(&mut socket, json!({"type":"error","code":code})).await; break; }
                };
                // Hosting admission precedes verification of attacker-supplied config history.
                if !matches!(service.admission.device_allowed(command.hosting_space_id, sender,
                    command.credential_id, command.scope, command.config_id).await, Ok(true)) {
                    let scope = Scope::from(&command);
                    scopes.remove(&scope);
                    let events = service.engine.lock().await.registry.revoke_member(scope, sender);
                    let _ = service.publish_media(events).await;
                    let _ = send(&mut socket, json!({"type":"error","code":CallError::Unauthorized})).await;
                    break;
                }
                let Ok(Ok(permit)) = tokio::time::timeout(Duration::from_secs(3), service.verification.clone().acquire_owned()).await else { break; };
                let prepared = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    job.verify(time)
                }).await.unwrap_or(Err(CallError::Unavailable));
                let prepared = match prepared {
                    Ok(prepared) => prepared,
                    Err(code) => { let _ = send(&mut socket, json!({"type":"error","code":code})).await; break; }
                };
                let wants_media=matches!(prepared.command.operation, elo_core::calls::Operation::ConnectMedia { .. });
                let request_id = prepared.request_id;
                let scope = Scope::from(&prepared.command);
                if scopes.len() >= 4096 && !scopes.contains(&scope) {
                    if !send(&mut socket, json!({"type":"error","request_id":request_id,"code":CallError::Unavailable})).await { break; }
                    continue;
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
                        receiver.update(bound_device, &scopes);
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
                let Some(event) = event else { break; }; // A slow consumer reconnects for a fresh snapshot.
                let scope = match &event {
                    Event::Presence { call } => call.scope,
                    Event::Ended { scope, .. } | Event::Signal { scope, .. } => *scope,
                };
                let credential = device.unwrap();
                if !scopes.contains(&scope) || matches!(&event, Event::Signal { to, .. } if *to != credential) { continue; }
                // A Leave/Join cycle keeps the session ID but replaces its media
                // generation. Never forward a queued negotiation from the old peer.
                if let Event::Signal { call_id, epoch, from, to, .. } = &event {
                    let engine = service.engine.lock().await;
                    let current = engine.registry.presence(&scope).is_some_and(|call| {
                        call.call_id == *call_id && call.key_epoch == *epoch
                            && call.participants.values().any(|participant| participant.credential_id == *from)
                            && call.participants.values().any(|participant| participant.credential_id == *to)
                    });
                    if !current { continue; }
                }
                if !service.engine.lock().await.authorized(scope, credential) {
                    scopes.remove(&scope);
                    receiver.update(credential, &scopes);
                    if !send(&mut socket, json!({"type":"access_revoked","scope":scope})).await { break; }
                    continue;
                }
                // Idle checks are staggered; never forward fresh presence or
                // media signals on an expired hosting admission. A terminal
                // event still clears an already known call after revocation.
                if !matches!(&event, Event::Ended { .. }) {
                    let head = service.engine.lock().await.authorized_head(scope, credential, now());
                    let allowed = if let Some(head) = head {
                        subscriptions::admitted(&service, &mut grants, scope, identity.unwrap(), credential, head, false).await
                    } else { false };
                    if !allowed {
                        scopes.remove(&scope);
                        grants.remove(&scope);
                        receiver.update(credential, &scopes);
                        let ended = service.engine.lock().await.registry.revoke_member(scope, identity.unwrap());
                        let _ = service.publish_media(ended).await;
                        if !send(&mut socket, json!({"type":"access_revoked","scope":scope})).await { break; }
                        continue;
                    }
                }
                if !send(&mut socket, serde_json::to_value(&event).unwrap()).await { break; }
            }
            _ = admission_tick.tick(), if device.is_some() => {
                let mut urgent = BTreeSet::new();
                {
                    let mut engine = service.engine.lock().await;
                    for scope in &scopes {
                        // Cheap local use keeps a live proof available. Network
                        // admission is bounded separately, rather than per chat.
                        if engine.authorized_head(*scope, device.unwrap(), now()).is_none()
                            || engine.registry.presence(scope).is_some_and(|call| call.participants.values().any(|participant| participant.credential_id == device.unwrap())) {
                            urgent.insert(*scope);
                        }
                    }
                }
                for scope in subscriptions::next_batch(&scopes, &urgent, &mut admission_cursor) {
                    let head = service.engine.lock().await.authorized_head(scope, device.unwrap(), now());
                    let admitted = if let Some(head) = head {
                        subscriptions::admitted(&service, &mut grants, scope, identity.unwrap(), device.unwrap(), head, true).await
                    } else { false };
                    if !admitted {
                        scopes.remove(&scope);
                        grants.remove(&scope);
                        receiver.update(device.unwrap(), &scopes);
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

#[cfg(test)]
mod admission_retry_tests {
    use super::*;
    use axum::response::IntoResponse;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn transient_read_retries_once_but_denial_and_bad_auth_do_not() {
        for initial in [503u16, 403, 200] {
            let count = Arc::new(AtomicUsize::new(0));
            let seen = count.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!(
                "http://{}/internal/calls/admission",
                listener.local_addr().unwrap()
            );
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    axum::Router::new().fallback(move || {
                        let attempt = seen.fetch_add(1, Ordering::SeqCst);
                        async move {
                            if attempt == 0 && initial != 200 {
                                axum::http::StatusCode::from_u16(initial)
                                    .unwrap()
                                    .into_response()
                            } else {
                                axum::Json(json!({"allowed": initial != 200})).into_response()
                            }
                        }
                    }),
                )
                .await
                .unwrap();
            });
            let admission = HostingAdmission::new(&url, Zeroizing::new("11".repeat(32))).unwrap();
            let result = admission
                .allowed(
                    SpaceId::from_bytes([1; 32]),
                    IdentityId::from_bytes([2; 32]),
                )
                .await;
            match initial {
                503 => {
                    assert!(result.unwrap());
                    assert_eq!(count.load(Ordering::SeqCst), 2);
                }
                403 => {
                    assert!(result.is_err());
                    assert_eq!(count.load(Ordering::SeqCst), 1);
                }
                _ => {
                    assert!(!result.unwrap());
                    assert_eq!(count.load(Ordering::SeqCst), 1);
                }
            }
            task.abort();
        }
    }
}

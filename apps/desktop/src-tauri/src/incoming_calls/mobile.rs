use super::transport::{command, socket_url};
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::BTreeSet,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tauri::{Emitter, Manager};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use zeroize::Zeroizing;

struct Offer {
    prepared: Arc<Prepared>,
    target: calls::ring::RingTarget,
    live: AtomicBool,
    answering: AtomicBool,
    ticket: presentation::Ticket,
}
struct Active {
    offer: Arc<Offer>,
    id: String,
    activation: String,
    call: Mutex<Value>,
    connected: AtomicBool,
    live: AtomicBool,
    capture_ready: AtomicBool,
    desired: Mutex<Value>,
    media_updates: tokio::sync::Mutex<()>,
    cleanup: tokio::sync::Mutex<()>,
    media_revision: AtomicU64,
    system_mute_revision: Mutex<Option<u64>>,
    speaker_muted: AtomicBool,
}
#[derive(Default)]
pub(crate) struct Incoming {
    offers: Mutex<BTreeMap<String, Arc<Offer>>>,
    active: Mutex<Option<Arc<Active>>>,
    events: Mutex<BTreeSet<String>>,
    transition: tokio::sync::Mutex<()>,
    prepare: tokio::sync::Mutex<()>,
    enrollment: tokio::sync::Mutex<()>,
    channel: std::sync::OnceLock<tauri::ipc::Channel<Value>>,
    mute_generation: AtomicU64,
    fence: Mutex<presentation::Fence>,
}

async fn plugin(
    app: &tauri::AppHandle,
    method: &'static str,
    payload: Value,
) -> Result<Value, String> {
    let app = app.clone();
    tokio::time::timeout(
        Duration::from_secs(6),
        tauri::async_runtime::spawn_blocking(move || {
            app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
                .call(method, payload)
        }),
    )
    .await
    .map_err(|_| "unavailable".to_string())?
    .map_err(|_| "unavailable".to_string())?
}
async fn native(app: &tauri::AppHandle, payload: Value) -> Result<Value, String> {
    plugin(app, "incomingCall", json!({"payload":payload.to_string()})).await
}
async fn storage(app: &tauri::AppHandle, payload: Value) -> Result<Value, String> {
    plugin(app, "callBindings", json!({"payload":payload.to_string()})).await
}
async fn load_bytes(app: &tauri::AppHandle) -> Result<Zeroizing<Vec<u8>>, String> {
    let result = storage(app, json!({"op":"load"})).await?;
    let Some(encoded) = result["payload"].as_str() else {
        return Ok(Zeroizing::new(Vec::new()));
    };
    if encoded.len() > 3 * 1024 * 1024 {
        return Err("invalid".into());
    }
    let bytes = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| "invalid")?);
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("invalid".into());
    }
    Ok(bytes)
}
async fn load(app: &tauri::AppHandle) -> Result<Enrollment, String> {
    let bytes = load_bytes(app).await?;
    if bytes.is_empty() {
        return Ok(Enrollment::default());
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid".into())
}
pub(crate) async fn enroll(
    app: &tauri::AppHandle,
    client: &elo_core::app::ClientApp,
    routes: Vec<elo_core::app::push::Route>,
) -> Result<(), String> {
    let gate = app.state::<Incoming>();
    let generation = gate.fence.lock().map_err(|_| "unavailable")?.epoch();
    let _guard = gate.enrollment.lock().await;
    let previous_bytes = load_bytes(app).await?;
    let mut previous: Enrollment = if previous_bytes.is_empty() {
        Enrollment::default()
    } else {
        serde_json::from_slice(&previous_bytes).map_err(|_| "invalid")?
    };
    let bindings = client
        .call_delegate_bindings(time(), std::mem::take(&mut previous.bindings))
        .await
        .map_err(|_| "unavailable")?;
    previous.prune_leaves(time());
    let enrollment = Enrollment {
        bindings,
        routes: routes.into_iter().map(RingRoute::from).collect(),
        pending_leaves: previous.pending_leaves,
    };
    save_enrollment(app, &enrollment, &previous_bytes).await?;
    gate.fence
        .lock()
        .map_err(|_| "unavailable")?
        .resume(generation);
    Ok(())
}
async fn save_enrollment(
    app: &tauri::AppHandle,
    enrollment: &Enrollment,
    previous_bytes: &[u8],
) -> Result<(), String> {
    let bytes = Zeroizing::new(serde_json::to_vec(enrollment).map_err(|_| "invalid")?);
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("full".into());
    }
    // Compare original bytes so loading a legacy route still removes its old
    // notification-send key at the next successful enrollment.
    if bytes.as_slice() != previous_bytes {
        storage(
            app,
            json!({"op":"store","payload":STANDARD.encode(bytes.as_slice())}),
        )
        .await?;
    }
    Ok(())
}

/// Persist before sending so a killed process cannot lose an uncertain Leave.
async fn leave(app: &tauri::AppHandle, offer: &Offer) -> Result<(), String> {
    let issued = time();
    let signed = offer
        .prepared
        .signed(
            Operation::Leave {
                call_id: offer.target.call_id.clone(),
            },
            issued,
        )
        .map_err(str::to_owned)?;
    let request_id = elo_core::record::random_hex::<16>().map_err(|_| "unavailable")?;
    {
        let gate = app.state::<Incoming>();
        let _guard = gate.enrollment.lock().await;
        let previous = load_bytes(app).await?;
        let mut enrollment: Enrollment = if previous.is_empty() {
            Enrollment::default()
        } else {
            serde_json::from_slice(&previous).map_err(|_| "invalid")?
        };
        enrollment
            .begin_leave(
                PendingLeave {
                    call_id: offer.target.call_id.clone(),
                    credential: offer.prepared.binding.credential,
                    request_id: request_id.clone(),
                    until: issued.saturating_add(calls::COMMAND_TTL),
                },
                time(),
            )
            .map_err(str::to_owned)?;
        save_enrollment(app, &enrollment, &previous).await?;
    }
    // Expiry is checked again by the service when it applies the command.
    super::transport::send_signed(socket_url(&offer.prepared)?, signed).await?;
    let gate = app.state::<Incoming>();
    let _guard = gate.enrollment.lock().await;
    let previous = load_bytes(app).await?;
    let mut enrollment: Enrollment = if previous.is_empty() {
        Enrollment::default()
    } else {
        serde_json::from_slice(&previous).map_err(|_| "invalid")?
    };
    enrollment.acknowledge_leave(&request_id);
    enrollment.prune_leaves(time());
    save_enrollment(app, &enrollment, &previous).await
}

async fn require_settled_leave(app: &tauri::AppHandle, offer: &Offer) -> Result<(), String> {
    let gate = app.state::<Incoming>();
    let _guard = gate.enrollment.lock().await;
    let enrollment = load(app).await?;
    if enrollment.leave_pending(
        &offer.target.call_id,
        offer.prepared.binding.credential,
        time(),
    ) {
        return Err("unavailable".into());
    }
    Ok(())
}

pub(crate) fn setup(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let target = app.clone();
        let gate = app.state::<Incoming>();
        let channel = gate.channel.get_or_init(|| {
            tauri::ipc::Channel::<Value>::new(move |body| {
                if let Ok(mut event) = body.deserialize::<Value>() {
                    // Preserve OS action order before independently scheduled
                    // handlers wait for admission or the serialized transport.
                    if event["action"] == "mute" {
                        let generation = target
                            .state::<Incoming>()
                            .mute_generation
                            .fetch_add(1, Ordering::SeqCst)
                            + 1;
                        event["controlGeneration"] = generation.into();
                    }
                    let app = target.clone();
                    let ticket = observe(&app, &event);
                    tauri::async_runtime::spawn(async move {
                        handle(app, event, ticket).await;
                    });
                }
                Ok(())
            })
        });
        let _ = plugin(&app, "incomingListener", json!({"channel":channel})).await;
        if let Ok(status) = plugin(&app, "incomingStatus", json!({})).await {
            let events: Vec<_> = status["pending"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|event| (event.clone(), observe(&app, event)))
                .collect();
            for (event, ticket) in events {
                handle(app.clone(), event, ticket).await;
            }
        }
    });
}

fn observe(app: &tauri::AppHandle, event: &Value) -> Option<presentation::Ticket> {
    app.state::<Incoming>()
        .fence
        .lock()
        .ok()?
        .observe(event, time())
}

fn permitted(app: &tauri::AppHandle, ticket: &presentation::Ticket) -> bool {
    app.state::<Incoming>()
        .fence
        .lock()
        .is_ok_and(|fence| fence.permits(ticket, time()))
}

fn uuid() -> Result<String, String> {
    let value = elo_core::record::random_hex::<16>().map_err(|_| "unavailable")?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..]
    ))
}
fn system(offer: &Offer, op: &str) -> Value {
    json!({"op":op,"callId":offer.target.call_id,"invitationId":offer.target.invitation_id})
}
async fn prepare(
    app: &tauri::AppHandle,
    event: &Value,
    ticket: presentation::Ticket,
) -> Result<Arc<Offer>, String> {
    let current = || {
        app.state::<Incoming>().fence.lock().is_ok_and(|fence| {
            if event["action"] == "decline" {
                fence.current(&ticket, time())
            } else {
                fence.permits(&ticket, time())
            }
        })
    };
    if !current() {
        return Err("ended".into());
    }
    let enrollment = load(app).await?;
    let (prepared, target) =
        super::transport::lookup(enrollment, event, time()).map_err(str::to_owned)?;
    let prepared = Arc::new(prepared);
    let call = command(&prepared, Operation::Subscribe).await?;
    prepared
        .validate(&call["call"], &target, true)
        .map_err(str::to_owned)?;
    if !current() {
        return Err("ended".into());
    }
    Ok(Arc::new(Offer {
        prepared,
        target,
        live: AtomicBool::new(true),
        answering: AtomicBool::new(false),
        ticket,
    }))
}

async fn finish_offer(app: &tauri::AppHandle, offer: &Arc<Offer>, reason: &str) {
    if !offer.live.swap(false, Ordering::SeqCst) {
        return;
    }
    let mut request = system(offer, "ended");
    request["reason"] = reason.into();
    let _ = native(app, request).await;
    if let Ok(mut offers) = app.state::<Incoming>().offers.lock() {
        offers.remove(&offer.target.invitation_id);
    }
    let _=app.emit("elo-call-presentation",json!({"call_id":offer.target.call_id,"invitation_id":offer.target.invitation_id,"presented":false}));
}

async fn watch(app: tauri::AppHandle, offer: Arc<Offer>) {
    // The socket carries current cancellation/answer events; VoIP pushes are
    // never abused for cancellations or background polling.
    let result = async {
        let config = WebSocketConfig::default()
            .max_message_size(Some(2 * 1024 * 1024))
            .max_frame_size(Some(2 * 1024 * 1024));
        let (mut socket, _) = tokio::time::timeout(
            Duration::from_secs(6),
            connect_async_with_config(
                socket_url(&offer.prepared).map_err(|_| "invalid")?,
                Some(config),
                true,
            ),
        )
        .await
        .map_err(|_| "unavailable")?
        .map_err(|_| "unavailable")?;
        let signed = offer.prepared.signed(Operation::Subscribe, time())?;
        socket
            .send(Message::Text(signed.to_string().into()))
            .await
            .map_err(|_| "unavailable")?;
        while offer.live.load(Ordering::SeqCst) {
            let remaining = offer.target.expires.saturating_sub(time());
            if remaining == 0 && !offer.answering.load(Ordering::SeqCst) {
                return Err("unanswered");
            }
            let event =
                tokio::time::timeout(Duration::from_secs(remaining.max(1).min(5)), socket.next())
                    .await;
            let event = match event {
                Ok(Some(Ok(event))) => event,
                Err(_) => continue,
                _ => return Err("unavailable"),
            };
            match event {
                Message::Text(text) => {
                    let event: Value = serde_json::from_str(&text).map_err(|_| "invalid")?;
                    if event["type"] == "ended" && event["call_id"] == offer.target.call_id {
                        return Err("ended");
                    }
                    if matches!(event["type"].as_str(), Some("error" | "access_revoked")) {
                        return Err("unauthorized");
                    }
                    if matches!(event["type"].as_str(), Some("presence" | "result")) {
                        let call = &event["call"];
                        if offer.answering.load(Ordering::SeqCst) {
                            continue;
                        }
                        let identity = offer.prepared.binding.identity.to_string();
                        if call["participants"][identity].is_object() {
                            return Err("answered_elsewhere");
                        }
                        offer.prepared.validate(call, &offer.target, true)?;
                    }
                }
                Message::Ping(bytes) => {
                    socket
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(|_| "unavailable")?;
                }
                Message::Close(_) => return Err("unavailable"),
                _ => {}
            }
        }
        Ok::<(), &str>(())
    }
    .await;
    if !offer.answering.load(Ordering::SeqCst) {
        finish_offer(&app, &offer, result.err().unwrap_or("ended")).await;
    }
}

async fn handle(app: tauri::AppHandle, event: Value, ticket: Option<presentation::Ticket>) {
    let Some(event_id) = event["eventId"].as_str().filter(|id| id.len() <= 64) else {
        return;
    };
    {
        let gate = app.state::<Incoming>();
        let Ok(mut events) = gate.events.lock() else {
            return;
        };
        if !events.insert(event_id.into()) {
            return;
        }
        if events.len() > 128 {
            events.pop_first();
        }
    }
    let action = event["action"].as_str().unwrap_or("");
    if action == "presentation" {
        let _ = app.emit("elo-call-presentation", json!({}));
        return;
    }
    let id = event["invitationId"].as_str().unwrap_or("");
    let gate = app.state::<Incoming>();
    if matches!(action, "decline" | "end" | "ended") {
        // The status path verifies this terminal hint locally and suppresses
        // only its exact invitation while the signed close travels separately.
        let _ = app.emit("elo-call-presentation", json!({}));
    }
    // Push delivery and an immediate system answer can arrive concurrently.
    // Publish one verified Offer before either callback may act on it.
    let offer = {
        let _preparing = gate.prepare.lock().await;
        let previous = gate
            .offers
            .lock()
            .ok()
            .and_then(|offers| offers.get(id).cloned())
            .filter(|offer| event["callId"] == offer.target.call_id);
        if let Some(offer) = previous {
            Ok(offer)
        } else if matches!(action, "incoming" | "answer" | "decline") {
            let mut result = match ticket.clone() {
                Some(ticket) => prepare(&app, &event, ticket).await,
                None => Err("invalid".into()),
            };
            if let Ok(offer) = &result {
                if action != "decline" {
                    if let Ok(fence) = gate.fence.lock() {
                        if fence.permits(&offer.ticket, time()) {
                            if let Ok(mut offers) = gate.offers.lock() {
                                offers.insert(id.into(), offer.clone());
                            }
                        } else {
                            result = Err("ended".into());
                        }
                    } else {
                        result = Err("unavailable".into());
                    }
                }
            }
            result
        } else {
            Err("ended".into())
        }
    };
    if let Ok(offer) = offer {
        if action == "incoming" {
            if !gate
                .fence
                .lock()
                .is_ok_and(|fence| fence.ringing(&offer.ticket, time()))
            {
                let _ = native(&app, json!({"op":"ack","eventId":event_id})).await;
                return;
            }
            let mut update = system(&offer, "update");
            update["name"] = offer.prepared.binding.name.clone().into();
            let _ = native(&app, update).await;
            let _ = app.emit(
                "elo-call-presentation",
                json!({"call_id":offer.target.call_id,"invitation_id":id,"presented":true}),
            );
            tauri::async_runtime::spawn(watch(app.clone(), offer));
        } else if action == "answer" {
            if let Err(_error) = answer(&app, offer.clone()).await {
                finish_offer(&app, &offer, "failed").await;
            }
        } else if action == "decline" {
            let _ = command(
                &offer.prepared,
                Operation::Decline {
                    call_id: offer.target.call_id.clone(),
                    invitation_id: offer.target.invitation_id.clone(),
                },
            )
            .await;
            finish_offer(&app, &offer, "declined").await;
        } else if matches!(action, "end" | "ended") {
            // A waiting invitation can share the ongoing group's call ID. Its
            // timeout must not end another invitation or a later activation.
            let active = gate
                .active
                .lock()
                .ok()
                .and_then(|active| active.clone())
                .filter(|active| {
                    Arc::ptr_eq(&active.offer, &offer) && active.offer.target.invitation_id == id
                });
            if let Some(active) = active {
                finish_active(&app, &active).await;
            }
            finish_offer(&app, &offer, "ended").await;
        } else if action == "mute" {
            let active = gate
                .active
                .lock()
                .ok()
                .and_then(|active| active.clone())
                .filter(|active| {
                    active.live.load(Ordering::SeqCst)
                        && Arc::ptr_eq(&active.offer, &offer)
                        && active.offer.target.invitation_id == id
                });
            if let (Some(active), Some(muted)) = (active, event["muted"].as_bool()) {
                if system_mute(
                    &app,
                    &active,
                    muted,
                    event["controlGeneration"].as_u64().unwrap_or(0),
                    event["systemMuteRevision"].as_u64(),
                )
                .await
                .is_err()
                {
                    finish_active(&app, &active).await;
                }
            }
        }
    } else if matches!(action, "incoming" | "answer") {
        let _=native(&app,json!({"op":"ended","callId":event["callId"],"invitationId":event["invitationId"],"reason":"failed"})).await;
    }
    let _ = native(&app, json!({"op":"ack","eventId":event_id})).await;
}

/// A system action has no unlocked profile. It uses only this call's admitted
/// delegation, and cannot unmute capture before a fresh signed Media acceptance.
async fn system_mute(
    app: &tauri::AppHandle,
    active: &Arc<Active>,
    muted: bool,
    generation: u64,
    system_revision: Option<u64>,
) -> Result<(), String> {
    let _updating = active.media_updates.lock().await;
    if !active.live.load(Ordering::SeqCst)
        || app
            .state::<Incoming>()
            .mute_generation
            .load(Ordering::SeqCst)
            != generation
    {
        return Ok(());
    }
    let revision = active.media_revision.fetch_add(1, Ordering::SeqCst) + 1;
    // Keep the driver's desired capture muted until the requested signed Media
    // state has been accepted, including when this action requests unmute.
    active.desired.lock().map_err(|_| "unavailable")?["audio_muted"] = true.into();
    let is_current = || {
        active.live.load(Ordering::SeqCst)
            && app
                .state::<Incoming>()
                .mute_generation
                .load(Ordering::SeqCst)
                == generation
            && active.media_revision.load(Ordering::SeqCst) == revision
            && app
                .state::<Incoming>()
                .active
                .lock()
                .ok()
                .and_then(|value| value.clone())
                .is_some_and(|value| Arc::ptr_eq(&value, active))
    };
    if !is_current() {
        return Ok(());
    }
    let mut desired: calls::MediaState =
        serde_json::from_value(active.desired.lock().map_err(|_| "unavailable")?.clone())
            .map_err(|_| "invalid")?;
    desired.audio_muted = muted;
    let result = command(
        &active.offer.prepared,
        Operation::Media {
            call_id: active.offer.target.call_id.clone(),
            state: desired,
        },
    )
    .await;
    // A newer action owns cleanup and capture, even when our old request failed.
    if !is_current() {
        return Ok(());
    }
    let result = result?;
    let call = &result["call"];
    active
        .offer
        .prepared
        .validate(call, &active.offer.target, false)
        .map_err(str::to_owned)?;
    let participant = &call["participants"][active.offer.prepared.binding.identity.to_string()];
    if participant["credential_id"] != json!(active.offer.prepared.binding.credential)
        || participant["delegation"]
            != STANDARD.encode(active.offer.prepared.delegate.certificate().bytes())
        || participant["media"] != json!(desired)
    {
        return Err("unauthorized".into());
    }
    {
        let current = app.state::<Incoming>();
        let current = current.active.lock().map_err(|_| "unavailable")?;
        if !active.live.load(Ordering::SeqCst)
            || app
                .state::<Incoming>()
                .mute_generation
                .load(Ordering::SeqCst)
                != generation
            || active.media_revision.load(Ordering::SeqCst) != revision
            || !current
                .as_ref()
                .is_some_and(|value| Arc::ptr_eq(value, active))
        {
            return Ok(());
        }
        *active.desired.lock().map_err(|_| "unavailable")? = json!(desired);
        *active
            .system_mute_revision
            .lock()
            .map_err(|_| "unavailable")? = system_revision;
    }
    if !active.capture_ready.load(Ordering::SeqCst) {
        return Ok(());
    }
    if !is_current() {
        return Ok(());
    }
    let response = tokio::time::timeout(Duration::from_secs(6), crate::native_media::dispatch(
        app.clone(), json!({"op":"update","id":active.id,"state":desired,
            "speaker_muted":active.speaker_muted.load(Ordering::SeqCst), "system_mute_revision":system_revision}),
    )).await;
    if !is_current() {
        return Ok(());
    }
    let response = response.map_err(|_| "unavailable")??;
    if response["error"].is_string() {
        return Err("unavailable".into());
    }
    Ok(())
}

async fn answer(app: &tauri::AppHandle, offer: Arc<Offer>) -> Result<(), String> {
    let gate = app.state::<Incoming>();
    let _guard = gate.transition.lock().await;
    if !offer.live.load(Ordering::SeqCst) || !permitted(app, &offer.ticket) {
        return Err("ended".into());
    }
    if offer.answering.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let current = command(&offer.prepared, Operation::Subscribe).await?;
    if !permitted(app, &offer.ticket) {
        return Err("ended".into());
    }
    offer
        .prepared
        .validate(&current["call"], &offer.target, true)
        .map_err(str::to_owned)?;
    // Allocate fallible local identifiers before changing either live call.
    let id = uuid()?;
    let activation = uuid()?;
    let target = crate::native_session::Target {
        url: socket_url(&offer.prepared)?,
        call_id: offer.target.call_id.clone(),
        context: offer.prepared.context(),
    };
    shutdown_active(app).await;
    crate::native_media::end_for_replacement(app).await?;
    require_settled_leave(app, &offer).await?;
    if !permitted(app, &offer.ticket) {
        return Err("ended".into());
    }
    let joined = command(
        &offer.prepared,
        Operation::Join {
            call_id: offer.target.call_id.clone(),
            invitation_id: Some(offer.target.invitation_id.clone()),
        },
    )
    .await?;
    if !permitted(app, &offer.ticket) {
        let _ = leave(app, &offer).await;
        return Err("ended".into());
    }
    if let Err(error) = offer
        .prepared
        .validate(&joined["call"], &offer.target, false)
    {
        let _ = leave(app, &offer).await;
        return Err(error.into());
    }
    let joined = match command(
        &offer.prepared,
        Operation::Media {
            call_id: offer.target.call_id.clone(),
            state: calls::MediaState {
                audio_muted: false,
                video_published: false,
                screen_published: false,
            },
        },
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            let _ = leave(app, &offer).await;
            return Err(error);
        }
    };
    let active = Arc::new(Active {
        offer: offer.clone(),
        id,
        activation,
        call: Mutex::new(joined["call"].clone()),
        connected: AtomicBool::new(false),
        live: AtomicBool::new(true),
        capture_ready: AtomicBool::new(joined["call"]["kind"] == "direct"),
        desired: Mutex::new(
            json!({"audio_muted":false,"video_published":false,"screen_published":false}),
        ),
        media_updates: tokio::sync::Mutex::new(()),
        cleanup: tokio::sync::Mutex::new(()),
        media_revision: AtomicU64::new(0),
        system_mute_revision: Mutex::new(None),
        speaker_muted: AtomicBool::new(false),
    });
    let installed = {
        let fence = gate.fence.lock().map_err(|_| "unavailable")?;
        if fence.permits(&offer.ticket, time()) {
            *gate.active.lock().map_err(|_| "unavailable")? = Some(active.clone());
            true
        } else {
            false
        }
    };
    if !installed {
        let _ = leave(app, &offer).await;
        return Err("ended".into());
    }
    let capture = async {
    if !offer.live.load(Ordering::SeqCst) || !permitted(app,&offer.ticket) {return Err("ended".into());}
    offer.prepared.validate(&joined["call"],&offer.target,false).map_err(str::to_owned)?;
    if joined["call"]["participants"][offer.prepared.binding.identity.to_string()]["delegation"]!=STANDARD.encode(offer.prepared.delegate.certificate().bytes()) {return Err("unauthorized".into());}
    let mut authorization=system(&offer,"authorize");authorization["mediaId"]=active.id.clone().into();
    native(app,authorization).await?;
    plugin(app,"setCallState",json!({"active":true,"sessionId":offer.target.call_id,"activation":active.activation,"camera":false})).await?;
    if joined["call"]["kind"]=="direct" {
    crate::native_media::dispatch(app.clone(),json!({"op":"start","id":active.id,"ice_servers":[]})).await?;
    crate::native_media::dispatch(app.clone(),json!({"op":"update","id":active.id,"state":{"audio_muted":false,"video_published":false,"screen_published":false},"speaker_muted":false})).await?;
    }
    if !offer.live.load(Ordering::SeqCst) || !permitted(app,&offer.ticket) {return Err("ended".into());}
    Ok::<(),String>(())
    }.await;
    if let Err(error) = capture {
        finish_active(app, &active).await;
        return Err(error);
    }
    let target_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let app = target_app;
        let mut driver = Driver {
            app: app.clone(),
            active: active.clone(),
        };
        let _ = crate::native_session::run(&mut driver, &target).await;
        finish_active(&app, &active).await;
    });
    let _=app.emit("elo-call-presentation",json!({"call_id":offer.target.call_id,"invitation_id":offer.target.invitation_id,"presented":true}));
    Ok(())
}

struct Driver {
    app: tauri::AppHandle,
    active: Arc<Active>,
}
impl crate::native_session::Driver for Driver {
    fn live(&self) -> bool {
        self.active.live.load(Ordering::SeqCst)
    }
    async fn operation(&mut self, op: &str, fields: Value) -> Result<Value, &'static str> {
        // finish_active sends Leave only after persisting its restart fence.
        if op == "call_authorization" && fields["operation"]["type"] == "leave" {
            return Err("ended");
        }
        if !self.live() {
            return Err("ended");
        }
        let call = self.active.call.lock().map_err(|_| "unavailable")?.clone();
        self.active.offer.prepared.operation(op, fields, &call)
    }
    async fn media(&mut self, mut request: Value) -> Result<Value, &'static str> {
        if !self.live() {
            return Err("ended");
        }
        request["id"] = self.active.id.clone().into();
        let op = request["op"].as_str().ok_or("invalid")?.to_owned();
        if op == "group_reset" {
            self.active.capture_ready.store(false, Ordering::SeqCst);
        }
        if op == "update" {
            request["state"] = self
                .active
                .desired
                .lock()
                .map_err(|_| "unavailable")?
                .clone();
            request["speaker_muted"] = self.active.speaker_muted.load(Ordering::SeqCst).into();
            request["system_mute_revision"] = json!(
                *self
                    .active
                    .system_mute_revision
                    .lock()
                    .map_err(|_| "unavailable")?
            );
        }
        let result = tokio::time::timeout(
            Duration::from_secs(if op == "group_start" { 12 } else { 6 }),
            crate::native_media::dispatch(self.app.clone(), request),
        )
        .await
        .map_err(|_| "unavailable")?
        .map_err(|_| "unavailable")?;
        if result["error"].is_string() {
            return Err("unavailable");
        }
        if op == "group_start" {
            self.active.capture_ready.store(true, Ordering::SeqCst);
        }
        Ok(result)
    }
    async fn changed(&mut self, call: &Value, connected: bool) -> Result<(), &'static str> {
        self.active
            .offer
            .prepared
            .validate(call, &self.active.offer.target, false)?;
        *self.active.call.lock().map_err(|_| "unavailable")? = call.clone();
        if connected && !self.active.connected.swap(true, Ordering::SeqCst) {
            native(&self.app, system(&self.active.offer, "connected"))
                .await
                .map_err(|_| "unavailable")?;
            let _ = self.app.emit(
                "elo-call-presentation",
                json!({"call_id":self.active.offer.target.call_id,"presented":true}),
            );
        }
        Ok(())
    }
}

async fn native_presented(app: &tauri::AppHandle, identity: &str) -> Result<Vec<Value>, String> {
    let gate = app.state::<Incoming>();
    // One retry covers an answer/end arriving during local verification. No
    // socket, signed Subscribe, or network-backed Offer is used for UI ownership.
    for _ in 0..2 {
        let (generation, dismissed) = {
            let fence = gate.fence.lock().map_err(|_| "unavailable")?;
            let Some(generation) = fence.snapshot() else {
                return Ok(Vec::new());
            };
            (generation, fence.dismissed(time()))
        };
        let snapshot = plugin(app, "incomingStatus", json!({})).await?;
        let bytes = load_bytes(app).await?;
        let mut hints: Vec<_> = snapshot["presentationHints"]
            .as_array()
            .into_iter()
            .flatten()
            .take(4)
            .cloned()
            .collect();
        // An OS decline must not briefly become an in-app Answer while its
        // signed network operation is pending. These hints are still verified
        // locally and expire with the original invitation, never after it.
        hints.extend(dismissed);
        let presented = presentation::verified_hints(
            &bytes,
            &json!({"presentationHints":hints}),
            identity,
            time(),
        );
        let current = plugin(app, "incomingStatus", json!({})).await?;
        if snapshot["presentationRevision"].as_u64().is_some()
            && snapshot["presentationRevision"] == current["presentationRevision"]
            && gate
                .fence
                .lock()
                .is_ok_and(|fence| fence.snapshot() == Some(generation))
        {
            return Ok(presented);
        }
    }
    Ok(Vec::new())
}

pub(crate) async fn status(app: &tauri::AppHandle, identity: &str) -> Result<Value, String> {
    let gate = app.state::<Incoming>();
    let presented = native_presented(app, identity).await?;
    let active = gate.active.lock().map_err(|_| "unavailable")?.clone();
    let active=active.filter(|active|active.live.load(Ordering::SeqCst) && active.offer.prepared.binding.identity.to_string()==identity).map(|active| {
        let call=active.call.lock().map(|call|call.clone()).unwrap_or(Value::Null);
        json!({"identity":identity,"call":call,"session_id":active.id,"activation":active.activation,
            "media":call["participants"][identity]["media"],"connected":active.connected.load(Ordering::SeqCst)})
    });
    Ok(json!({"active":active,"presented":presented}))
}
pub(crate) async fn owns_activity(
    app: &tauri::AppHandle,
    identity: &str,
    session_id: &str,
    activation: &str,
) -> bool {
    app.state::<Incoming>()
        .active
        .lock()
        .ok()
        .and_then(|active| active.clone())
        .is_some_and(|active| {
            active.live.load(Ordering::SeqCst)
                && active.offer.prepared.binding.identity.to_string() == identity
                && active.offer.target.call_id == session_id
                && active.activation == activation
        })
}
pub(crate) async fn media(
    app: &tauri::AppHandle,
    identity: &str,
    request: &Value,
) -> Option<Result<Value, String>> {
    let active = app
        .state::<Incoming>()
        .active
        .lock()
        .ok()
        .and_then(|active| active.clone())?;
    if !active.live.load(Ordering::SeqCst)
        || active.offer.prepared.binding.identity.to_string() != identity
        || request["id"] != active.id
    {
        return None;
    }
    let op = request["op"].as_str()?;
    if op == "stop" {
        finish_active(app, &active).await;
        return Some(Ok(json!({})));
    }
    if !["poll", "render", "speaker", "update"].contains(&op) {
        return Some(Err("invalid".into()));
    }
    if op == "update" {
        active.media_revision.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut desired) = active.desired.lock() {
            *desired = request["state"].clone();
        }
    }
    if op == "speaker" && request["credential"].is_null() {
        active
            .speaker_muted
            .store(request["muted"] == true, Ordering::SeqCst);
    }
    if !active.capture_ready.load(Ordering::SeqCst) {
        return Some(Ok(if op == "poll" {
            json!({"connection":"connecting","native_owned":true,"signals":[],"tiles":[],"call":active.call.lock().ok().map(|v|v.clone())})
        } else {
            json!({})
        }));
    }
    let mut request = request.clone();
    if op == "update" {
        request["system_mute_revision"] = json!(*active.system_mute_revision.lock().ok()?);
    }
    if op == "poll" {
        request["op"] = "snapshot".into();
    }
    let result = crate::native_media::dispatch(app.clone(), request).await;
    Some(result.map(|mut snapshot| {
        if op == "poll" {
            let call = active
                .call
                .lock()
                .map(|call| call.clone())
                .unwrap_or(Value::Null);
            snapshot["call"] = call.clone();
            snapshot["signals"] = json!([]);
            snapshot["native_owned"] = true.into();
            snapshot["remote"] = call["participants"]
                .as_object()
                .and_then(|people| {
                    people
                        .iter()
                        .find(|(id, _)| *id != identity)
                        .map(|(_, p)| p["credential_id"].clone())
                })
                .unwrap_or(Value::Null);
        }
        snapshot
    }))
}
async fn finish_active(app: &tauri::AppHandle, active: &Arc<Active>) {
    // Replacement waits for a previously started Leave, not just live=false.
    let _cleanup = active.cleanup.lock().await;
    if !active.live.swap(false, Ordering::SeqCst) {
        return;
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(6),
        crate::native_media::dispatch(app.clone(), json!({"op":"stop","id":active.id})),
    )
    .await;
    let _ = leave(app, &active.offer).await;
    let _=plugin(app,"setCallState",json!({"active":false,"sessionId":active.offer.target.call_id,"activation":active.activation,"camera":false})).await;
    finish_offer(app, &active.offer, "ended").await;
    if let Ok(mut current) = app.state::<Incoming>().active.lock() {
        if current
            .as_ref()
            .is_some_and(|value| Arc::ptr_eq(value, active))
        {
            current.take();
        }
    }
    let _ = app.emit(
        "call-session-ended",
        json!({"sessionId":active.offer.target.call_id,"activation":active.activation}),
    );
}
async fn shutdown_active(app: &tauri::AppHandle) {
    let active = app
        .state::<Incoming>()
        .active
        .lock()
        .ok()
        .and_then(|active| active.clone());
    if let Some(active) = active {
        finish_active(app, &active).await;
    }
}
pub(crate) async fn end_active(
    app: &tauri::AppHandle,
    identity: &str,
    call_id: &str,
    activation: Option<&str>,
) {
    let active = app
        .state::<Incoming>()
        .active
        .lock()
        .ok()
        .and_then(|active| active.clone());
    if let Some(active) = active.filter(|active| {
        active.offer.prepared.binding.identity.to_string() == identity
            && active.offer.target.call_id == call_id
            && activation.is_none_or(|a| a == active.activation)
    }) {
        finish_active(app, &active).await;
    }
}
pub(crate) async fn shutdown(app: &tauri::AppHandle) {
    if let Ok(mut fence) = app.state::<Incoming>().fence.lock() {
        fence.suspend();
    }
    let _ = app.emit("elo-call-presentation", json!({}));
    shutdown_active(app).await;
    let offers = app
        .state::<Incoming>()
        .offers
        .lock()
        .map(|offers| offers.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    for offer in offers {
        finish_offer(app, &offer, "ended").await;
    }
    let gate = app.state::<Incoming>();
    let _guard = gate.enrollment.lock().await;
    if let Ok(mut enrollment) = load(app).await {
        enrollment.prune_leaves(time());
        enrollment.bindings.clear();
        enrollment.routes.clear();
        if enrollment.pending_leaves.is_empty() {
            let _ = storage(app, json!({"op":"clear"})).await;
        } else {
            // Clear delegation secrets immediately; retain only the bounded
            // command fence until its passive expiry, even across reenrollment.
            let _ = save_enrollment(app, &enrollment, &[]).await;
        }
    }
}

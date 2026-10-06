//! Media and background membership belong to one explicitly joined, unlocked session.
use serde_json::Value;
#[cfg(all(mobile, feature = "mobile-push"))]
use tauri::{Emitter, Manager};

#[derive(Default)]
pub(crate) struct MediaGate {
    #[cfg(all(mobile, feature = "mobile-push"))]
    current: std::sync::Mutex<Option<MediaSession>>,
    #[cfg(all(mobile, feature = "mobile-push"))]
    activity: tokio::sync::Mutex<Option<CallActivity>>,
    #[cfg(all(mobile, feature = "mobile-push"))]
    route_channel: std::sync::OnceLock<tauri::ipc::Channel<Value>>,
    #[cfg(all(mobile, feature = "mobile-push"))]
    system_controls: tokio::sync::Mutex<()>,
    #[cfg(all(mobile, feature = "mobile-push"))]
    end_transition: tokio::sync::Mutex<()>,
    #[cfg(all(mobile, feature = "mobile-push"))]
    mute_generation: std::sync::atomic::AtomicU64,
}
#[cfg(all(mobile, feature = "mobile-push"))]
struct MediaSession {
    id: String,
    identity: String,
    token: std::sync::Arc<()>,
    task: Option<tokio::task::AbortHandle>,
    call: Value,
    group: bool,
    capture_ready: bool,
    desired: Option<Value>,
    speaker_muted: bool,
}
#[cfg(all(mobile, feature = "mobile-push"))]
struct CallActivity {
    id: String,
    identity: String,
    activation: String,
    context: Value,
    token: std::sync::Arc<()>,
    lease: tokio::task::AbortHandle,
}

#[cfg(all(mobile, feature = "mobile-push"))]
pub(crate) async fn dispatch(app: tauri::AppHandle, request: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>().call(
            "nativeMedia",
            serde_json::json!({"payload": request.to_string()}),
        )
    })
    .await
    .map_err(|_| "unavailable".to_owned())?
}

#[cfg(all(mobile, feature = "mobile-push"))]
struct LeaseDriver {
    app: tauri::AppHandle,
    call_id: String,
    activation: String,
    context: Value,
    token: std::sync::Arc<()>,
}
#[cfg(all(mobile, feature = "mobile-push"))]
impl crate::call_lease::Driver for LeaseDriver {
    async fn signed(&mut self, operation: &'static str) -> Result<Value, ()> {
        let app = self.app.clone();
        let state = app.state::<crate::State>();
        let mut runtime = state.lock().await;
        let client = runtime.client.as_mut().ok_or(())?;
        if client.identity_id().to_string()
            != self.context["expected_identity"].as_str().ok_or(())?
            || !self.live().await
        {
            return Err(());
        }
        let mut request = self.context.clone();
        request["op"] = "call_authorization".into();
        request["include_proof"] = true.into();
        request["operation"] = serde_json::json!({"type":operation,"call_id":self.call_id});
        let signed = client.operate(request).await.map_err(|_| ())?;
        Ok(serde_json::json!({"command":signed["command"],"proof":signed["proof"]}))
    }
    async fn live(&mut self) -> bool {
        self.app
            .state::<MediaGate>()
            .activity
            .lock()
            .await
            .as_ref()
            .is_some_and(|session| std::sync::Arc::ptr_eq(&session.token, &self.token))
    }
    async fn finished(&mut self, _reason: &'static str) {
        let gate = self.app.state::<MediaGate>();
        let mut current = gate.activity.lock().await;
        if current
            .as_ref()
            .is_some_and(|session| std::sync::Arc::ptr_eq(&session.token, &self.token))
        {
            current.take();
            let _ = stop_capture(&self.app).await;
            let _ = session_activity(
                self.app.clone(),
                &self.call_id,
                &self.activation,
                false,
                false,
            )
            .await;
            let _ = self.app.emit(
                "call-session-ended",
                serde_json::json!({"sessionId":self.call_id,"activation":self.activation}),
            );
        }
    }
}

async fn stop_capture(app: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        let previous = app
            .state::<MediaGate>()
            .current
            .lock()
            .map_err(|_| "unavailable")?
            .take();
        if let Some(previous) = previous {
            if let Some(task) = previous.task {
                task.abort();
            }
            let _ = dispatch(
                app.clone(),
                serde_json::json!({"op":"system_call_end","id":previous.id}),
            )
            .await;
        }
        dispatch(app.clone(), serde_json::json!({"op":"shutdown"})).await?;
    }
    let _ = app;
    Ok(())
}

pub(crate) async fn shutdown(app: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        let gate = app.state::<MediaGate>();
        let mut current = gate.activity.lock().await;
        let session = current.take();
        if let Some(session) = &session {
            session.lease.abort();
        }
        let capture = stop_capture(app).await;
        let activity = if let Some(session) = session {
            session_activity(app.clone(), &session.id, &session.activation, false, false).await
        } else {
            Ok(())
        };
        return capture.and(activity);
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    stop_capture(app).await
}

/// Called only after an explicit system answer or End & answer. Release the
/// existing signed membership before joining a replacement conversation.
#[cfg(all(mobile, feature = "mobile-push"))]
pub(crate) async fn end_for_replacement(app: &tauri::AppHandle) -> Result<(), String> {
    end_matching(app, None).await.map(|_| ())
}

#[cfg(all(mobile, feature = "mobile-push"))]
async fn end_matching(
    app: &tauri::AppHandle,
    expected: Option<(&str, &str)>,
) -> Result<bool, String> {
    let transition_gate = app.state::<MediaGate>();
    // Keep replacements behind the old signed Leave. Taking activity alone is
    // insufficient: a second answer could otherwise rejoin that room first.
    let _ending = transition_gate.end_transition.lock().await;
    let context = {
        let gate = app.state::<MediaGate>();
        let mut activity = gate.activity.lock().await;
        if expected.is_some_and(|(id, activation)| {
            activity
                .as_ref()
                .is_none_or(|session| session.id != id || session.activation != activation)
        }) {
            return Ok(false);
        }
        let previous = activity.take();
        if let Some(session) = previous {
            session.lease.abort();
            stop_capture(app).await?;
            session_activity(app.clone(), &session.id, &session.activation, false, false).await?;
            let _ = app.emit(
                "call-session-ended",
                serde_json::json!({"sessionId":session.id,"activation":session.activation}),
            );
            Some((session.context, session.id))
        } else {
            None
        }
    };
    if let Some((mut context, id)) = context {
        let signed = {
            let state = app.state::<crate::State>();
            let mut runtime = state.lock().await;
            let client = runtime.client.as_mut().ok_or("unavailable")?;
            if context["expected_identity"] != client.identity_id().to_string() {
                return Err("unauthorized".into());
            }
            context["op"] = "call_authorization".into();
            context["include_proof"] = true.into();
            context["operation"] = serde_json::json!({"type":"leave","call_id":id});
            client
                .operate(context.clone())
                .await
                .map_err(|_| "unavailable")?
        };
        crate::incoming_calls::send_signed(control_socket(&context)?, signed).await?;
    }
    Ok(true)
}

#[cfg(all(mobile, feature = "mobile-push"))]
fn control_socket(context: &Value) -> Result<String, String> {
    let mut url = reqwest::Url::parse(context["audience"].as_str().ok_or("invalid")?)
        .map_err(|_| "invalid")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("unauthorized".into());
    }
    url.set_scheme("wss").map_err(|_| "invalid")?;
    url.set_path(&format!("{}/connect", url.path().trim_end_matches('/')));
    Ok(url.to_string())
}

#[cfg(all(mobile, feature = "mobile-push"))]
async fn system_action(app: tauri::AppHandle, value: Value) {
    let (Some(id), Some(activation)) = (value["sessionId"].as_str(), value["activation"].as_str())
    else {
        return;
    };
    if value["action"] == "end" {
        let _ = end_matching(&app, Some((id, activation))).await;
        return;
    }
    if value["action"] != "mute" || !value["muted"].is_boolean() {
        return;
    }
    let Some(system_mute_revision) = value["systemMuteRevision"]
        .as_u64()
        .filter(|value| *value > 0)
    else {
        return;
    };
    let gate = app.state::<MediaGate>();
    let generation = value["controlGeneration"].as_u64().unwrap_or(0);
    let current_generation = || {
        gate.mute_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            == generation
    };
    if !current_generation() {
        return;
    }
    let (mut request, mut context, token, previous_call) = {
        let activity = gate.activity.lock().await;
        let Some(owner) = activity
            .as_ref()
            .filter(|s| s.id == id && s.activation == activation)
        else {
            return;
        };
        let Ok(mut current) = gate.current.lock() else {
            return;
        };
        let Some(session) = current
            .as_mut()
            .filter(|s| s.identity == owner.identity && s.call["call_id"] == id)
        else {
            return;
        };
        let mut desired = session.desired.clone().unwrap_or_else(|| {
            serde_json::json!({
                "op":"update", "id":session.id,
                "state":session.call["participants"][&owner.identity]["media"],
                "speaker_muted":session.speaker_muted
            })
        });
        if !desired["state"].is_object() {
            return;
        }
        desired["state"]["audio_muted"] = value["muted"].clone();
        if value["muted"] == true {
            session.desired = Some(desired.clone());
        }
        (
            desired,
            owner.context.clone(),
            session.token.clone(),
            session.call.clone(),
        )
    };
    // Capture must stay muted even while an older system request is waiting
    // for the network. Do not queue the desired mute behind that request.
    let _control = gate.system_controls.lock().await;
    if !current_generation() {
        return;
    }
    // The system can always mute locally. Publishing again requires the same
    // signed, current admission as the in-app microphone control.
    context["op"] = "call_authorization".into();
    context["include_proof"] = true.into();
    context["operation"] =
        serde_json::json!({"type":"media", "call_id":id, "state":request["state"]});
    let signed = {
        let state = app.state::<crate::State>();
        let mut runtime = state.lock().await;
        let Some(client) = runtime.client.as_mut() else {
            return;
        };
        if context["expected_identity"] != client.identity_id().to_string() {
            return;
        }
        match client.operate(context.clone()).await {
            Ok(value) => value,
            Err(_) => return,
        }
    };
    let Ok(url) = control_socket(&context) else {
        return;
    };
    let accepted = crate::incoming_calls::send_signed(url, signed).await;
    if !current_generation() {
        return;
    }
    let Ok(accepted) = accepted else {
        let _ = end_matching(&app, Some((id, activation))).await;
        return;
    };
    let identity = context["expected_identity"].as_str().unwrap_or("");
    let call = &accepted["call"];
    if call["call_id"] != id
        || call["config_id"] != previous_call["config_id"]
        || call["scope"] != previous_call["scope"]
        || call["participants"][identity]["credential_id"]
            != previous_call["participants"][identity]["credential_id"]
        || call["participants"][identity]["media"] != request["state"]
    {
        let _ = end_matching(&app, Some((id, activation))).await;
        return;
    }
    {
        let activity = gate.activity.lock().await;
        if !current_generation()
            || !activity
                .as_ref()
                .is_some_and(|s| s.id == id && s.activation == activation)
        {
            return;
        }
        let Ok(mut current) = gate.current.lock() else {
            return;
        };
        let Some(session) = current
            .as_mut()
            .filter(|s| std::sync::Arc::ptr_eq(&s.token, &token))
        else {
            return;
        };
        request["system_mute_revision"] = system_mute_revision.into();
        request["speaker_muted"] = session.speaker_muted.into();
        session.desired = Some(request.clone());
        if session.group && !session.capture_ready {
            return;
        }
    }
    let _ = dispatch(app.clone(), request).await;
}

#[cfg(all(mobile, feature = "mobile-push"))]
fn route_channel(app: &tauri::AppHandle) -> tauri::ipc::Channel<Value> {
    let gate = app.state::<MediaGate>();
    gate.route_channel
        .get_or_init(|| {
            let target = app.clone();
            tauri::ipc::Channel::<Value>::new(move |body| {
                if let Ok(mut value) = body.deserialize::<Value>() {
                    let valid_id = value["sessionId"].as_str().is_some_and(|id| {
                        id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    });
                    let valid_activation = value["activation"].as_str().is_some_and(|id| {
                        id.len() == 36
                            && id
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
                    });
                    if valid_id && valid_activation {
                        if value["action"].is_string() {
                            if value["action"] == "mute" {
                                let generation = target
                                    .state::<MediaGate>()
                                    .mute_generation
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                                    + 1;
                                value["controlGeneration"] = generation.into();
                            }
                            tauri::async_runtime::spawn(system_action(target.clone(), value));
                            return Ok(());
                        }
                        let _ = target.emit(
                            "call-audio-route-changed",
                            serde_json::json!({
                                "sessionId":value["sessionId"], "activation":value["activation"]
                            }),
                        );
                    }
                }
                Ok(())
            })
        })
        .clone()
}

#[cfg(all(mobile, feature = "mobile-push"))]
async fn session_activity(
    app: tauri::AppHandle,
    session_id: &str,
    activation: &str,
    active: bool,
    camera: bool,
) -> Result<(), String> {
    // Keep channel construction outside this async future: callbacks can end
    // a session and return here without a recursive Send inference cycle.
    let channel = route_channel(&app);
    let args = serde_json::json!({"sessionId":session_id,"active":active,"camera":camera,"routeChannel":channel,"activation":activation});
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
            .call("setCallState", args)
            .map(|_| ())
    })
    .await
    .map_err(|_| "unavailable".to_owned())?
}

/// Output routing is local to the unlocked, explicitly joined session. It never
/// changes the remote media flags or terminates a call when a route is unavailable.
#[tauri::command]
pub(crate) async fn native_call_audio(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::State>,
    identity: String,
    session_id: String,
    activation: String,
    output_id: Option<String>,
) -> Result<Value, String> {
    if output_id
        .as_ref()
        .is_some_and(|id| id.is_empty() || id.len() > 512)
    {
        return Err("invalid".into());
    }
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        let runtime = state.lock().await;
        if runtime
            .client
            .as_ref()
            .ok_or("unauthorized")?
            .identity_id()
            .to_string()
            != identity
        {
            return Err("unauthorized".into());
        }
        let background =
            crate::incoming_calls::owns_activity(&app, &identity, &session_id, &activation).await;
        let gate = app.state::<MediaGate>();
        let current = gate.activity.lock().await;
        if !background
            && !current.as_ref().is_some_and(|session| {
                session.identity == identity
                    && session.id == session_id
                    && session.activation == activation
            })
        {
            return Err("ended".into());
        }
        // The activity guard prevents a delayed route change from affecting the
        // next session. Native code checks the same ID and activation on its main queue.
        drop(runtime);
        let target = app.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            target
                .state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
                .call(
                    "callAudio",
                    serde_json::json!({"sessionId":session_id,"activation":activation,"outputId":output_id}),
                )
        })
        .await
        .map_err(|_| "unavailable".to_owned())?;
        drop(current);
        result
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = (app, state, identity, session_id, activation, output_id);
        Err("unavailable".into())
    }
}

/// Background execution is independent of push opt-in and never starts from a push.
// Keep the named IPC fields separate from Tauri's injected app/state arguments.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub(crate) async fn native_call_state(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::State>,
    identity: String,
    session_id: String,
    activation: String,
    active: bool,
    camera: bool,
    context: Option<Value>,
) -> Result<(), String> {
    if session_id.len() != 32
        || !session_id.bytes().all(|b| b.is_ascii_hexdigit())
        || activation.len() != 36
        || !activation
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err("invalid".into());
    }
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        use base64::Engine;
        let transition_gate = app.state::<MediaGate>();
        // Acquire before Runtime to preserve the global Runtime -> activity
        // ordering while excluding an in-flight end/replacement transition.
        let _starting = if active {
            Some(transition_gate.end_transition.lock().await)
        } else {
            None
        };
        let mut runtime = state.lock().await;
        let client = runtime.client.as_mut().ok_or("unauthorized")?;
        if client.identity_id().to_string() != identity {
            return Err("unauthorized".into());
        }
        if crate::incoming_calls::owns_activity(&app, &identity, &session_id, &activation).await {
            drop(runtime);
            if !active {
                crate::incoming_calls::end_active(&app, &identity, &session_id, Some(&activation))
                    .await;
                return Ok(());
            }
            return session_activity(app.clone(), &session_id, &activation, true, camera).await;
        }
        let gate = app.state::<MediaGate>();
        let mut current = gate.activity.lock().await;
        if current.as_ref().is_some_and(|s| {
            s.id != session_id || s.identity != identity || s.activation != activation
        }) {
            return if active {
                Err("already_joined".into())
            } else {
                Ok(())
            };
        }
        if !active {
            // Stopping capture needs no profile keys. Let the explicit Leave
            // acquire the profile while the native plugin completes teardown.
            drop(runtime);
            if let Some(previous) = current.take() {
                previous.lease.abort();
                let capture = stop_capture(&app).await;
                let activity =
                    session_activity(app.clone(), &session_id, &activation, false, false).await;
                capture.and(activity)?;
            }
            return Ok(());
        }
        let supplied = context.ok_or("invalid")?;
        if let Some(previous) = current.as_ref() {
            for key in ["target_space", "hosting_space_id", "space", "stream"] {
                if supplied[key] != previous.context[key] {
                    return Err("unauthorized".into());
                }
            }
            drop(runtime);
            return session_activity(app.clone(), &session_id, &activation, true, camera).await;
        }
        crate::release_policy::require_online(&app)?;
        let mut verified = serde_json::json!({"expected_identity":identity,"op":"call_endpoint"});
        for key in ["target_space", "hosting_space_id", "space", "stream"] {
            let value = supplied[key].as_str().ok_or("invalid")?;
            if value.len() > 128 {
                return Err("invalid".into());
            }
            verified[key] = value.into();
        }
        let endpoint = client
            .operate(verified.clone())
            .await
            .map_err(|_| "unauthorized")?;
        let audience = endpoint["url"].as_str().ok_or("invalid")?;
        let mut url = reqwest::Url::parse(audience).map_err(|_| "invalid")?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("invalid".into());
        }
        verified["audience"] = audience.into();
        // Extract only the device identity from a freshly signed local command.
        // The server still checks the signature and admission on every lease renewal.
        let mut auth = verified.clone();
        auth["op"] = "call_authorization".into();
        auth["operation"] = serde_json::json!({"type":"heartbeat","call_id":session_id});
        let signed = client.operate(auth).await.map_err(|_| "unauthorized")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(signed["command"].as_str().ok_or("invalid")?)
            .map_err(|_| "invalid")?;
        let record = elo_core::record::SignedRecord::parse(&bytes).map_err(|_| "invalid")?;
        let credential = record.body()["credential_id"]
            .as_str()
            .ok_or("invalid")?
            .to_owned();
        url.set_scheme("wss").map_err(|_| "invalid")?;
        url.set_path(&format!("{}/connect", url.path().trim_end_matches('/')));
        session_activity(app.clone(), &session_id, &activation, true, camera).await?;
        let token = std::sync::Arc::new(());
        let target = crate::call_lease::Target {
            url: url.to_string(),
            call_id: session_id.clone(),
            identity: identity.clone(),
            credential,
            config_id: record.body()["config_id"]
                .as_str()
                .ok_or("invalid")?
                .to_owned(),
            scope: serde_json::json!({"hosting_space_id":verified["hosting_space_id"],"conversation":{"space_id":verified["space"],"stream_id":verified["stream"]}}),
        };
        let task = tokio::spawn(crate::call_lease::run(
            LeaseDriver {
                app: app.clone(),
                call_id: session_id.clone(),
                activation: activation.clone(),
                context: verified.clone(),
                token: token.clone(),
            },
            target,
        ));
        *current = Some(CallActivity {
            id: session_id,
            identity,
            activation,
            context: verified,
            token,
            lease: task.abort_handle(),
        });
        Ok(())
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = (app, state, identity, activation, active, camera, context);
        Ok(())
    }
}

#[tauri::command]
pub(crate) async fn native_call_media(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::State>,
    identity: String,
    request: Value,
) -> Result<Value, String> {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        let mut request = request;
        if request.to_string().len() > 196608 {
            return Err("invalid".into());
        }
        let op = request["op"].as_str().ok_or("invalid")?.to_owned();
        if ![
            "permissions",
            "start",
            "poll",
            "offer",
            "signal",
            "update",
            "speaker",
            "render",
            "stop",
        ]
        .contains(&op.as_str())
        {
            return Err("invalid".into());
        }
        if op == "permissions" {
            let runtime = state.lock().await;
            let client = runtime.client.as_ref().ok_or("unauthorized")?;
            if client.identity_id().to_string() != identity {
                return Err("unauthorized".into());
            }
            drop(runtime);
            return dispatch(app, request).await;
        }
        let id = request["id"].as_str().ok_or("invalid")?.to_owned();
        if id.len() != 36 || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err("invalid".into());
        }
        if op != "start" {
            let runtime = state.lock().await;
            if runtime
                .client
                .as_ref()
                .ok_or("unauthorized")?
                .identity_id()
                .to_string()
                != identity
            {
                return Err("unauthorized".into());
            }
            drop(runtime);
            if let Some(result) = crate::incoming_calls::media(&app, &identity, &request).await {
                return result;
            }
        }
        if op == "start" {
            crate::release_policy::require_online(&app)?;
            let mut runtime = state.lock().await;
            let client = runtime.client.as_mut().ok_or("unauthorized")?;
            if client.identity_id().to_string() != identity {
                return Err("unauthorized".into());
            }
            let supplied = &request["context"];
            let gate = app.state::<MediaGate>();
            let mut activity = gate.activity.lock().await;
            let active = activity
                .as_mut()
                .filter(|session| {
                    session.identity == identity
                        && supplied["call_id"] == session.id
                        && supplied["activation"] == session.activation
                })
                .ok_or("ended")?;
            for key in ["target_space", "hosting_space_id", "space", "stream"] {
                if supplied[key] != active.context[key] {
                    return Err("unauthorized".into());
                }
            }
            let mut auth = active.context.clone();
            auth["op"] = "call_authorization".into();
            auth["include_proof"] = true.into();
            auth["operation"] = serde_json::json!({"type":"heartbeat","call_id":active.id});
            let signed = client.operate(auth).await.map_err(|_| "unauthorized")?;
            let context = crate::native_session::verified_context(&active.context, &signed)
                .map_err(str::to_owned)?;
            let mut url = reqwest::Url::parse(context["audience"].as_str().ok_or("invalid")?)
                .map_err(|_| "invalid")?;
            url.set_scheme("wss").map_err(|_| "invalid")?;
            url.set_path(&format!("{}/connect", url.path().trim_end_matches('/')));
            let token = std::sync::Arc::new(());
            {
                let mut current = gate.current.lock().map_err(|_| "unavailable")?;
                if current.is_some() {
                    return Err("already_joined".into());
                }
                *current = Some(MediaSession {
                    id: id.clone(),
                    identity: identity.clone(),
                    token: token.clone(),
                    task: None,
                    call: Value::Null,
                    group: context["kind"] == "group",
                    capture_ready: context["kind"] != "group",
                    desired: None,
                    speaker_muted: false,
                });
            }
            // UI-provided ICE and SDP never enter native negotiation. The server
            // supplies TURN access only after current signed participant admission.
            let result = if context["kind"] == "group" {
                Ok(serde_json::json!({}))
            } else {
                dispatch(
                    app.clone(),
                    serde_json::json!({"op":"start","id":id,"ice_servers":[]}),
                )
                .await
            };
            if result
                .as_ref()
                .map_or(true, |value| value["error"].is_string())
            {
                gate.current.lock().map_err(|_| "unavailable")?.take();
                return result;
            }
            active.lease.abort();
            let target = crate::native_session::Target {
                url: url.to_string(),
                call_id: active.id.clone(),
                context: context.clone(),
            };
            let mut driver = SessionDriver {
                app: app.clone(),
                id: id.clone(),
                identity: identity.clone(),
                context,
                token: token.clone(),
                activity_token: active.token.clone(),
                call_id: active.id.clone(),
                activation: active.activation.clone(),
                system_started: false,
                system_connected: false,
                display_name: supplied["display_name"]
                    .as_str()
                    .unwrap_or("elo.now")
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(120)
                    .collect(),
            };
            let task = tokio::spawn(async move {
                let _ = crate::native_session::run(&mut driver, &target).await;
                driver.finished().await;
            });
            active.lease = task.abort_handle();
            gate.current
                .lock()
                .map_err(|_| "unavailable")?
                .as_mut()
                .ok_or("ended")?
                .task = Some(task.abort_handle());
            return result;
        }
        {
            let gate = app.state::<MediaGate>();
            let mut current = gate.current.lock().map_err(|_| "unavailable")?;
            if !current
                .as_ref()
                .is_some_and(|session| session.id == id && session.identity == identity)
            {
                return if op == "stop" {
                    Ok(serde_json::json!({}))
                } else {
                    Err("ended".into())
                };
            }
            if op == "stop" {
                if let Some(previous) = current.take() {
                    if let Some(task) = previous.task {
                        task.abort();
                    }
                }
            }
            if matches!(op.as_str(), "offer" | "signal") {
                return Err("native_owned".into());
            }
            if let Some(session) = current.as_mut() {
                if op == "update" {
                    gate.mute_generation
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if let Some(revision) = session
                        .desired
                        .as_ref()
                        .and_then(|previous| previous["system_mute_revision"].as_u64())
                    {
                        request["system_mute_revision"] = revision.into();
                    }
                    session.desired = Some(request.clone());
                }
                if op == "speaker" && request["credential"].is_null() {
                    session.speaker_muted = request["muted"] == true;
                }
                if session.group && !session.capture_ready && op != "stop" {
                    return if op == "poll" {
                        Ok(
                            serde_json::json!({"connection":"connecting","native_owned":true,"signals":[],"tiles":[],"call":session.call}),
                        )
                    } else {
                        Ok(serde_json::json!({}))
                    };
                }
            }
        }
        if op == "stop" {
            let _ = dispatch(
                app.clone(),
                serde_json::json!({"op":"system_call_end","id":id}),
            )
            .await;
        }
        if op == "poll" {
            let mut snapshot =
                dispatch(app.clone(), serde_json::json!({"op":"snapshot","id":id})).await?;
            let gate = app.state::<MediaGate>();
            let current = gate.current.lock().map_err(|_| "unavailable")?;
            let session = current
                .as_ref()
                .filter(|session| session.id == id && session.identity == identity)
                .ok_or("ended")?;
            snapshot["call"] = session.call.clone();
            snapshot["native_owned"] = true.into();
            snapshot["signals"] = serde_json::json!([]);
            let remote = session.call["participants"].as_object().and_then(|people| {
                people
                    .iter()
                    .find(|(person, _)| **person != identity)
                    .map(|(_, participant)| participant["credential_id"].clone())
            });
            snapshot["remote"] = remote.clone().unwrap_or(Value::Null);
            snapshot["connection"] =
                visible_connection(session.group, remote.is_some(), &snapshot["connection"]);
            return Ok(snapshot);
        }
        dispatch(app, request).await
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = (app, state, identity, request);
        Err("unavailable".into())
    }
}

#[cfg(any(test, all(mobile, feature = "mobile-push")))]
fn visible_connection(group: bool, has_remote: bool, transport: &Value) -> Value {
    if !group && !has_remote {
        // A locally admitted microphone is not an answered direct call.
        "connecting".into()
    } else if matches!(transport.as_str(), Some("failed" | "closed")) {
        // The native controller owns retry and terminal shutdown.
        "disconnected".into()
    } else {
        transport.clone()
    }
}

#[cfg(all(mobile, feature = "mobile-push"))]
struct SessionDriver {
    app: tauri::AppHandle,
    id: String,
    identity: String,
    context: Value,
    token: std::sync::Arc<()>,
    activity_token: std::sync::Arc<()>,
    call_id: String,
    activation: String,
    system_started: bool,
    system_connected: bool,
    display_name: String,
}
#[cfg(all(mobile, feature = "mobile-push"))]
impl SessionDriver {
    async fn finished(&mut self) {
        let gate = self.app.state::<MediaGate>();
        let mut activity = gate.activity.lock().await;
        if !activity
            .as_ref()
            .is_some_and(|session| std::sync::Arc::ptr_eq(&session.token, &self.activity_token))
        {
            return;
        }
        {
            let Ok(mut current) = gate.current.lock() else {
                return;
            };
            if !current
                .as_ref()
                .is_some_and(|session| std::sync::Arc::ptr_eq(&session.token, &self.token))
            {
                return;
            }
            // Taking our abort handle does not abort this cleanup. Holding the
            // activity gate prevents a replacement from starting during shutdown.
            current.take();
        }
        activity.take();
        let _ = dispatch(
            self.app.clone(),
            serde_json::json!({"op":"system_call_end","id":self.id}),
        )
        .await;
        let _ = stop_capture(&self.app).await;
        let _ = session_activity(
            self.app.clone(),
            &self.call_id,
            &self.activation,
            false,
            false,
        )
        .await;
        let _ = self.app.emit(
            "call-session-ended",
            serde_json::json!({"sessionId":self.call_id,"activation":self.activation}),
        );
    }
}
#[cfg(all(mobile, feature = "mobile-push"))]
impl crate::native_session::Driver for SessionDriver {
    fn live(&self) -> bool {
        self.app
            .state::<MediaGate>()
            .current
            .lock()
            .is_ok_and(|current| {
                current
                    .as_ref()
                    .is_some_and(|session| std::sync::Arc::ptr_eq(&session.token, &self.token))
            })
    }
    async fn operation(&mut self, op: &str, fields: Value) -> Result<Value, &'static str> {
        if !self.live() {
            return Err("ended");
        }
        let state = self.app.state::<crate::State>();
        let mut runtime = state.lock().await;
        let client = runtime.client.as_mut().ok_or("unauthorized")?;
        if client.identity_id().to_string() != self.identity || !self.live() {
            return Err("unauthorized");
        }
        let mut request = self.context.clone();
        request["op"] = op.into();
        for (key, value) in fields.as_object().ok_or("invalid")? {
            request[key] = value.clone();
        }
        if matches!(op, "call_encrypt_signal" | "call_open_signal") {
            let gate = self.app.state::<MediaGate>();
            let current = gate.current.lock().map_err(|_| "unavailable")?;
            let call = &current
                .as_ref()
                .filter(|session| std::sync::Arc::ptr_eq(&session.token, &self.token))
                .ok_or("ended")?
                .call;
            bind_signal_participant(&mut request, op, call, &self.context)?;
        }
        let value = client.operate(request).await.map_err(|_| "unauthorized")?;
        if !self.live() {
            return Err("ended");
        }
        if op == "call_authorization" {
            crate::native_session::validate_command(&self.context, &value)?;
        }
        if op == "call_open_signal" && value["signal"]["config_id"] != self.context["config_id"] {
            return Err("unauthorized");
        }
        Ok(value)
    }
    async fn media(&mut self, mut request: Value) -> Result<Value, &'static str> {
        if !self.live() {
            return Err("ended");
        }
        if !self.system_started {
            let started=tokio::time::timeout(std::time::Duration::from_secs(6),dispatch(self.app.clone(),serde_json::json!({"op":"system_call_start","id":self.id,"call_id":self.call_id,"activation":self.activation,"name":self.display_name}))).await.map_err(|_|"unavailable")?.map_err(|_|"unavailable")?;
            if started["error"].is_string() {
                return Err("unavailable");
            }
            self.system_started = true;
        }
        request["id"] = self.id.clone().into();
        let op = request["op"].as_str().ok_or("invalid")?.to_owned();
        {
            let gate = self.app.state::<MediaGate>();
            let mut current = gate.current.lock().map_err(|_| "unavailable")?;
            let session = current
                .as_mut()
                .filter(|s| std::sync::Arc::ptr_eq(&s.token, &self.token))
                .ok_or("ended")?;
            if op == "group_reset" {
                session.capture_ready = false;
            }
            if op == "update" {
                if let Some(desired) = &session.desired {
                    request = desired.clone();
                    request["id"] = self.id.clone().into();
                }
                request["speaker_muted"] = session.speaker_muted.into();
            }
        }
        let value = tokio::time::timeout(
            std::time::Duration::from_secs(if op == "group_start" { 12 } else { 6 }),
            dispatch(self.app.clone(), request),
        )
        .await
        .map_err(|_| "unavailable")?
        .map_err(|_| "unavailable")?;
        if op == "group_start" {
            let gate = self.app.state::<MediaGate>();
            if let Some(session) = gate
                .current
                .lock()
                .map_err(|_| "unavailable")?
                .as_mut()
                .filter(|s| std::sync::Arc::ptr_eq(&s.token, &self.token))
            {
                session.capture_ready = true;
            }
        }
        if !self.live() {
            return Err("ended");
        }
        if value["error"].is_string() {
            return Err("unavailable");
        }
        Ok(value)
    }
    async fn changed(&mut self, call: &Value, connected: bool) -> Result<(), &'static str> {
        {
            let gate = self.app.state::<MediaGate>();
            let mut current = gate.current.lock().map_err(|_| "unavailable")?;
            let session = current
                .as_mut()
                .filter(|session| std::sync::Arc::ptr_eq(&session.token, &self.token))
                .ok_or("ended")?;
            session.call = call.clone();
        }
        if connected && self.system_started && !self.system_connected {
            let result = dispatch(
                self.app.clone(),
                serde_json::json!({"op":"system_call_connected","id":self.id}),
            )
            .await
            .map_err(|_| "unavailable")?;
            if result["error"].is_string() {
                return Err("unavailable");
            }
            self.system_connected = true;
        }
        Ok(())
    }
}

/// Certificates come from the last scoped, verified participant snapshot, never
/// from an incoming ciphertext or WebView-supplied certificate.
#[cfg(any(test, all(mobile, feature = "mobile-push")))]
fn bind_signal_participant(
    request: &mut Value,
    op: &str,
    call: &Value,
    context: &Value,
) -> Result<(), &'static str> {
    if request["call_id"] != call["call_id"]
        || request["epoch"] != call["key_epoch"]
        || call["config_id"] != context["config_id"]
    {
        return Err("unauthorized");
    }
    let (field, credential) = match op {
        "call_encrypt_signal" => (
            "recipient_delegation",
            request["to"].as_str().ok_or("invalid")?,
        ),
        "call_open_signal" => (
            "sender_delegation",
            request["from"].as_str().ok_or("invalid")?,
        ),
        _ => return Err("invalid"),
    };
    let participant = call["participants"]
        .as_object()
        .ok_or("invalid")?
        .values()
        .find(|participant| participant["credential_id"] == credential)
        .ok_or("unauthorized")?;
    let delegation = participant.get("delegation").cloned();
    request.as_object_mut().ok_or("invalid")?.remove(field);
    if let Some(delegation) = delegation.filter(|value| !value.is_null()) {
        if !delegation.is_string() {
            return Err("unauthorized");
        }
        request[field] = delegation;
    }
    request["audience"] = context["audience"].clone();
    Ok(())
}

#[cfg(test)]
mod delegated_signal_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn direct_call_waits_for_remote_transport_while_group_keeps_room_state() {
        assert_eq!(
            visible_connection(false, false, &json!("connected")),
            "connecting"
        );
        assert_eq!(
            visible_connection(false, true, &json!("connecting")),
            "connecting"
        );
        assert_eq!(
            visible_connection(false, true, &json!("connected")),
            "connected"
        );
        assert_eq!(
            visible_connection(true, false, &json!("connected")),
            "connected"
        );
        assert_eq!(
            visible_connection(false, true, &json!("failed")),
            "disconnected"
        );
    }
    #[test]
    fn uses_only_current_participant_certificate_for_both_signal_directions() {
        let call = json!({"call_id":"call","key_epoch":2,"config_id":"head","participants":{"peer":{"credential_id":"peer-device","delegation":"current-certificate"}}});
        let context = json!({"config_id":"head","audience":"https://private.example/calls/v1"});
        for (op, peer, certificate) in [
            ("call_encrypt_signal", "to", "recipient_delegation"),
            ("call_open_signal", "from", "sender_delegation"),
        ] {
            let mut request = json!({"call_id":"call","epoch":2});
            request[peer] = "peer-device".into();
            request[certificate] = "untrusted".into();
            bind_signal_participant(&mut request, op, &call, &context).unwrap();
            assert_eq!(request[certificate], "current-certificate");
            assert_eq!(request["audience"], context["audience"]);
            request["epoch"] = 1.into();
            assert_eq!(
                bind_signal_participant(&mut request, op, &call, &context),
                Err("unauthorized")
            );
            request["epoch"] = 2.into();
            request[peer] = "removed-device".into();
            assert_eq!(
                bind_signal_participant(&mut request, op, &call, &context),
                Err("unauthorized")
            );
        }
    }
    #[test]
    fn ordinary_participant_does_not_inherit_a_supplied_delegation() {
        let call = json!({"call_id":"call","key_epoch":1,"config_id":"head","participants":{"peer":{"credential_id":"peer-device"}}});
        let mut request = json!({"call_id":"call","epoch":1,"to":"peer-device","recipient_delegation":"untrusted"});
        bind_signal_participant(
            &mut request,
            "call_encrypt_signal",
            &call,
            &json!({"config_id":"head","audience":"https://host.example/calls/v1"}),
        )
        .unwrap();
        assert!(request.get("recipient_delegation").is_none());
    }
}

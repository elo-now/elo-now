//! Media and background membership belong to one explicitly joined, unlocked session.
use serde_json::Value;
#[cfg(all(mobile, feature = "mobile-push"))]
use tauri::{Emitter, Manager};

#[derive(Default)]
pub(crate) struct MediaGate {
    #[cfg(all(target_os = "ios", feature = "mobile-push"))]
    current: std::sync::Mutex<Option<MediaSession>>,
    #[cfg(all(mobile, feature = "mobile-push"))]
    activity: tokio::sync::Mutex<Option<CallActivity>>,
    #[cfg(all(mobile, feature = "mobile-push"))]
    route_channel: std::sync::OnceLock<tauri::ipc::Channel<Value>>,
}
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
struct MediaSession {
    id: String,
    identity: String,
    token: std::sync::Arc<()>,
    task: Option<tokio::task::AbortHandle>,
    call: Value,
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

#[cfg(all(target_os = "ios", feature = "mobile-push"))]
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
    #[cfg(all(target_os = "ios", feature = "mobile-push"))]
    {
        if let Some(previous) = app
            .state::<MediaGate>()
            .current
            .lock()
            .map_err(|_| "unavailable")?
            .take()
        {
            if let Some(task) = previous.task {
                task.abort();
            }
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

#[cfg(all(mobile, feature = "mobile-push"))]
async fn session_activity(
    app: tauri::AppHandle,
    session_id: &str,
    activation: &str,
    active: bool,
    camera: bool,
) -> Result<(), String> {
    let gate = app.state::<MediaGate>();
    // Tauri retains native channels for the process lifetime. Reuse one channel
    // instead of registering another closure for every session/camera update.
    let channel = gate.route_channel.get_or_init(|| {
        let target = app.clone();
        tauri::ipc::Channel::<Value>::new(move |body| {
            if let Ok(value) = body.deserialize::<Value>() {
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
    });
    let args = serde_json::json!({"sessionId":session_id,"active":active,"camera":camera,"routeChannel":channel,"activation":activation});
    drop(gate);
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
        let gate = app.state::<MediaGate>();
        let current = gate.activity.lock().await;
        if !current.as_ref().is_some_and(|session| {
            session.identity == identity
                && session.id == session_id
                && session.activation == activation
        }) {
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
        let mut runtime = state.lock().await;
        let client = runtime.client.as_mut().ok_or("unauthorized")?;
        if client.identity_id().to_string() != identity {
            return Err("unauthorized".into());
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
    #[cfg(all(target_os = "ios", feature = "mobile-push"))]
    {
        if request.to_string().len() > 196608 {
            return Err("invalid".into());
        }
        let op = request["op"].as_str().ok_or("invalid")?;
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
        .contains(&op)
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
                });
            }
            // UI-provided ICE and SDP never enter native negotiation. The server
            // supplies TURN access only after current signed participant admission.
            let result = dispatch(
                app.clone(),
                serde_json::json!({"op":"start","id":id,"ice_servers":[]}),
            )
            .await;
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
            if matches!(op, "offer" | "signal") {
                return Err("native_owned".into());
            }
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
            if session.call.is_object() && remote.is_none() {
                snapshot["connection"] = "connected".into();
            } else if matches!(snapshot["connection"].as_str(), Some("failed" | "closed")) {
                // The native controller owns retry and terminal shutdown.
                snapshot["connection"] = "disconnected".into();
            }
            return Ok(snapshot);
        }
        dispatch(app, request).await
    }
    #[cfg(not(all(target_os = "ios", feature = "mobile-push")))]
    {
        let _ = (app, state, identity, request);
        Err("unavailable".into())
    }
}

#[cfg(all(target_os = "ios", feature = "mobile-push"))]
struct SessionDriver {
    app: tauri::AppHandle,
    id: String,
    identity: String,
    context: Value,
    token: std::sync::Arc<()>,
    activity_token: std::sync::Arc<()>,
    call_id: String,
    activation: String,
}
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
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
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
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
        request["id"] = self.id.clone().into();
        let value = tokio::time::timeout(
            std::time::Duration::from_secs(6),
            dispatch(self.app.clone(), request),
        )
        .await
        .map_err(|_| "unavailable")?
        .map_err(|_| "unavailable")?;
        if !self.live() {
            return Err("ended");
        }
        if value["error"].is_string() {
            return Err("unavailable");
        }
        Ok(value)
    }
    async fn changed(&mut self, call: &Value, _connected: bool) -> Result<(), &'static str> {
        let gate = self.app.state::<MediaGate>();
        let mut current = gate.current.lock().map_err(|_| "unavailable")?;
        let session = current
            .as_mut()
            .filter(|session| std::sync::Arc::ptr_eq(&session.token, &self.token))
            .ok_or("ended")?;
        session.call = call.clone();
        Ok(())
    }
}

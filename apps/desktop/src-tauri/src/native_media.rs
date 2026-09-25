//! Native media and its participant lease are bound to one unlocked profile.
use serde_json::Value;
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
use tauri::Manager;

#[derive(Default)]
pub(crate) struct MediaGate {
    #[cfg(all(target_os = "ios", feature = "mobile-push"))]
    pub(crate) current: std::sync::Mutex<Option<MediaSession>>,
}
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
pub(crate) struct MediaSession {
    pub(crate) id: String,
    pub(crate) identity: String,
    pub(crate) lease: Option<tokio::task::AbortHandle>,
    pub(crate) incoming: Option<Value>,
    pub(crate) incoming_context: Option<Value>,
    pub(crate) incoming_cancel: Option<tokio::sync::watch::Sender<bool>>,
}
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
impl MediaSession {
    fn cancel(self) {
        if let Some(lease) = self.lease {
            lease.abort();
        }
    }
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

#[cfg(all(target_os = "ios", feature = "mobile-push"))]
struct LeaseDriver {
    app: tauri::AppHandle,
    id: String,
    call_id: String,
    context: Value,
}
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
impl crate::call_lease::Driver for LeaseDriver {
    async fn signed(&mut self, operation: &'static str) -> Result<Value, ()> {
        let state = self.app.state::<crate::State>();
        let mut runtime = state.lock().await;
        let client = runtime.client.as_mut().ok_or(())?;
        if client.identity_id().to_string()
            != self.context["expected_identity"].as_str().ok_or(())?
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
        dispatch(
            self.app.clone(),
            serde_json::json!({"op":"health","id":self.id}),
        )
        .await
        .is_ok_and(|value| value["live"] == true)
    }
    async fn finished(&mut self, _reason: &'static str) {
        let owns = {
            let gate = self.app.state::<MediaGate>();
            let Ok(mut current) = gate.current.lock() else {
                return;
            };
            if current
                .as_ref()
                .is_some_and(|session| session.id == self.id)
            {
                current.take();
                true
            } else {
                false
            }
        };
        if owns {
            let _ = dispatch(
                self.app.clone(),
                serde_json::json!({"op":"end_call","id":self.id,"call_id":self.call_id}),
            )
            .await;
        }
    }
}

pub(crate) async fn shutdown(app: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(all(target_os = "ios", feature = "mobile-push"))]
    {
        if let Some(session) = app
            .state::<MediaGate>()
            .current
            .lock()
            .map_err(|_| "unavailable")?
            .take()
        {
            session.cancel();
        }
        dispatch(app.clone(), serde_json::json!({"op":"shutdown"})).await?;
    }
    let _ = app;
    Ok(())
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
        let mut request = request;
        if request.to_string().len() > 196608 {
            return Err("invalid".into());
        }
        let op = request["op"].as_str().ok_or("invalid")?;
        if op == "incoming_status" {
            return crate::incoming_answer::status(&app, &identity).await;
        }
        if matches!(op, "answer" | "decline") {
            return crate::incoming_answer::action(
                &app,
                &identity,
                op,
                request["call_id"].as_str().ok_or("invalid")?,
            )
            .await;
        }
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
            "handoff",
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
            let call_id = supplied["call_id"].as_str().ok_or("invalid")?.to_owned();
            if call_id.len() != 32 || !call_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid".into());
            }
            let mut context =
                serde_json::json!({"expected_identity":identity,"op":"call_endpoint"});
            for key in ["target_space", "hosting_space_id", "space", "stream"] {
                context[key] = supplied[key].as_str().ok_or("invalid")?.into();
            }
            // Endpoint selection stays in the profile's verified hosting metadata.
            let endpoint = client
                .operate(context.clone())
                .await
                .map_err(|_| "unauthorized")?;
            let audience = endpoint["url"].as_str().ok_or("invalid")?;
            let mut url = reqwest::Url::parse(audience).map_err(|_| "invalid")?;
            if url.scheme() != "https"
                || url.username() != ""
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err("invalid".into());
            }
            context["audience"] = audience.into();
            url.set_scheme("wss").map_err(|_| "invalid")?;
            url.set_path(&format!("{}/connect", url.path().trim_end_matches('/')));
            {
                let gate = app.state::<MediaGate>();
                let mut current = gate.current.lock().map_err(|_| "unavailable")?;
                if current.is_some() {
                    return Err("already_joined".into());
                }
                *current = Some(MediaSession {
                    id: id.clone(),
                    identity: identity.clone(),
                    lease: None,
                    incoming: None,
                    incoming_context: None,
                    incoming_cancel: None,
                });
            }
            let result = dispatch(app.clone(), request.clone()).await;
            if result
                .as_ref()
                .map_or(true, |value| value["error"].is_string())
            {
                app.state::<MediaGate>()
                    .current
                    .lock()
                    .map_err(|_| "unavailable")?
                    .take();
                return result;
            }
            let target = crate::call_lease::Target {
                url: url.to_string(),
                call_id: call_id.clone(),
                identity,
                scope: serde_json::json!({"hosting_space_id":context["hosting_space_id"],"conversation":{"space_id":context["space"],"stream_id":context["stream"]}}),
            };
            let driver = LeaseDriver {
                app: app.clone(),
                id: id.clone(),
                call_id,
                context,
            };
            let task = tokio::spawn(crate::call_lease::run(driver, target));
            let gate = app.state::<MediaGate>();
            let mut current = gate.current.lock().map_err(|_| "unavailable")?;
            if let Some(session) = current.as_mut().filter(|session| session.id == id) {
                session.lease = Some(task.abort_handle());
            } else {
                task.abort();
            }
            return result;
        }
        if op == "handoff" {
            let runtime = state.lock().await;
            if runtime
                .client
                .as_ref()
                .map(|c| c.identity_id().to_string())
                .as_deref()
                != Some(identity.as_str())
            {
                return Err("unauthorized".into());
            }
            let gate = app.state::<MediaGate>();
            let mut current = gate.current.lock().map_err(|_| "unavailable")?;
            let session = current
                .as_mut()
                .filter(|s| s.id == id && s.identity == identity)
                .ok_or("ended")?;
            let incoming = session.incoming.as_ref().ok_or("ended")?;
            if incoming["phase"] != "connected" {
                return Err("unavailable".into());
            }
            let call_id = incoming["call_id"].as_str().ok_or("invalid")?.to_owned();
            let context = session.incoming_context.clone().ok_or("invalid")?;
            let mut url = reqwest::Url::parse(context["audience"].as_str().ok_or("invalid")?)
                .map_err(|_| "invalid")?;
            url.set_scheme("wss").map_err(|_| "invalid")?;
            url.set_path(&format!("{}/connect", url.path().trim_end_matches('/')));
            let target = crate::call_lease::Target {
                url: url.to_string(),
                call_id: call_id.clone(),
                identity: identity.clone(),
                scope: serde_json::json!({"hosting_space_id":context["hosting_space_id"],"conversation":{"space_id":context["space"],"stream_id":context["stream"]}}),
            };
            if let Some(task) = session.lease.take() {
                task.abort();
            }
            // The foreground controller already authenticated its socket. Keep
            // this exact media peer and transfer only signaling ownership.
            session.incoming = None;
            session.incoming_context = None;
            let task = tokio::spawn(crate::call_lease::run(
                LeaseDriver {
                    app: app.clone(),
                    id,
                    call_id,
                    context,
                },
                target,
            ));
            session.lease = Some(task.abort_handle());
            return Ok(serde_json::json!({}));
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
                if let Some(session) = current.take() {
                    if let Some(incoming) = &session.incoming {
                        request["op"] = "end_call".into();
                        request["call_id"] = incoming["call_id"].clone();
                    }
                    session.cancel();
                }
            } else if current
                .as_ref()
                .is_some_and(|session| session.incoming.is_some())
            {
                // The native coordinator is the sole consumer of SDP/ICE. UI
                // polling can observe tracks without stealing queued signals.
                if op == "poll" {
                    request["op"] = "snapshot".into();
                } else if matches!(op, "offer" | "signal") {
                    return Err("unauthorized".into());
                }
            }
        }
        dispatch(app, request).await
    }
    #[cfg(not(all(target_os = "ios", feature = "mobile-push")))]
    {
        let _ = (app, state, identity, request);
        Err("unavailable".into())
    }
}

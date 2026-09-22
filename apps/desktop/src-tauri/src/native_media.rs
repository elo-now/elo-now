//! Native media and its participant lease are bound to one unlocked profile.
use serde_json::Value;
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
use tauri::Manager;

#[derive(Default)]
pub(crate) struct MediaGate {
    #[cfg(all(target_os = "ios", feature = "mobile-push"))]
    current: std::sync::Mutex<Option<MediaSession>>,
}
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
struct MediaSession {
    id: String,
    identity: String,
    lease: Option<tokio::task::AbortHandle>,
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
async fn dispatch(app: tauri::AppHandle, request: Value) -> Result<Value, String> {
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
                    session.cancel();
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

//! Bridges CallKit Answer directly to the unlocked Rust session, not JavaScript.
use crate::{
    incoming_call,
    native_media::{MediaGate, MediaSession, dispatch},
};
use serde_json::{Value, json};
use tauri::Manager;

async fn plugin(
    app: &tauri::AppHandle,
    method: &'static str,
    args: Value,
) -> Result<Value, String> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
            .call(method, args)
    })
    .await
    .map_err(|_| "unavailable".to_owned())?
}
pub(crate) fn setup(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let target = app.clone();
        let channel = tauri::ipc::Channel::<Value>::new(move |event| {
            let Ok(event) = event.deserialize::<Value>() else {
                return Ok(());
            };
            if let Some(call_id) = event["ended"].as_str() {
                let gate = target.state::<MediaGate>();
                if let Ok(current) = gate.current.lock() {
                    if let Some(session) = current.as_ref().filter(|session| {
                        session
                            .incoming
                            .as_ref()
                            .is_some_and(|call| call["call_id"] == call_id)
                    }) {
                        if let Some(cancel) = &session.incoming_cancel {
                            let _ = cancel.send(true);
                        }
                    }
                }
                return Ok(());
            }
            if event["answer"] != true {
                return Ok(());
            }
            let app = target.clone();
            tauri::async_runtime::spawn(async move {
                let _ = begin(&app, None).await;
            });
            Ok(())
        });
        let _ = plugin(&app, "callListener", json!({"channel":channel})).await;
    });
}
pub(crate) async fn status(app: &tauri::AppHandle, identity: &str) -> Result<Value, String> {
    begin(app, Some(identity)).await?;
    let state = app.state::<crate::State>();
    let runtime = state.lock().await;
    if runtime
        .client
        .as_ref()
        .map(|c| c.identity_id().to_string())
        .as_deref()
        != Some(identity)
    {
        return Err("unauthorized".into());
    }
    let gate = app.state::<MediaGate>();
    let current = gate.current.lock().map_err(|_| "unavailable")?;
    Ok(
        json!({"incoming":current.as_ref().filter(|s| s.identity == identity).and_then(|s| s.incoming.clone())}),
    )
}
pub(crate) async fn action(
    app: &tauri::AppHandle,
    identity: &str,
    action: &str,
    call_id: &str,
) -> Result<Value, String> {
    if !matches!(action, "answer" | "decline")
        || call_id.len() != 32
        || !call_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid".into());
    }
    let raw = plugin(app, "callStatus", json!({})).await?;
    let incoming = &raw["incoming"];
    let state = app.state::<crate::State>();
    let runtime = state.lock().await;
    let client = runtime.client.as_ref().ok_or("unauthorized")?;
    if client.identity_id().to_string() != identity {
        return Err("unauthorized".into());
    }
    if incoming["id"] != call_id {
        return Ok(json!({"handled":false}));
    }
    if action == "answer" {
        crate::release_policy::require_online(app)?;
        client
            .open_call_notification(incoming["target"].as_str().ok_or("invalid")?)
            .map_err(|_| "unauthorized")?;
    }
    drop(runtime);
    plugin(app, "callAction", json!({"action":action,"callId":call_id})).await
}
async fn begin(app: &tauri::AppHandle, expected: Option<&str>) -> Result<(), String> {
    if app
        .state::<MediaGate>()
        .current
        .lock()
        .map_err(|_| "unavailable")?
        .is_some()
    {
        return Ok(());
    }
    let raw = plugin(app, "callStatus", json!({})).await?;
    let raw = &raw["incoming"];
    if raw["action"] != "answer" || raw["ui_owned"] == true {
        return Ok(());
    }
    let call_id = raw["id"].as_str().ok_or("invalid")?.to_owned();
    if call_id.len() != 32 || !call_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid".into());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "invalid")?
        .as_secs_f64();
    if !raw["expires"]
        .as_f64()
        .is_some_and(|expires| expires > now && expires <= now + 60.0)
    {
        return Ok(());
    }
    crate::release_policy::require_online(app)?;
    let state = app.state::<crate::State>();
    let mut runtime = state.lock().await;
    // A push never unlocks a cold profile or reads its key from disk.
    let Some(client) = runtime.client.as_mut() else {
        drop(runtime);
        let _ = plugin(
            app,
            "callAction",
            json!({"action":"unlock","callId":call_id}),
        )
        .await;
        return Ok(());
    };
    let identity = client.identity_id().to_string();
    if expected.is_some_and(|expected| expected != identity) {
        return Err("unauthorized".into());
    }
    let mut context = client
        .incoming_call_context(raw["target"].as_str().ok_or("invalid")?)
        .map_err(|_| "unauthorized")?;
    let mut request = context.clone();
    request["op"] = "call_endpoint".into();
    let endpoint = client.operate(request).await.map_err(|_| "unauthorized")?;
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
    context["audience"] = audience.into();
    url.set_scheme("wss").map_err(|_| "invalid")?;
    url.set_path(&format!("{}/connect", url.path().trim_end_matches('/')));
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "unavailable")?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let id = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    let (cancel, cancellation) = tokio::sync::watch::channel(false);
    {
        let gate = app.state::<MediaGate>();
        let mut current = gate.current.lock().map_err(|_| "unavailable")?;
        if current.is_some() {
            return Ok(());
        }
        *current = Some(MediaSession {
            id: id.clone(),
            identity: identity.clone(),
            lease: None,
            incoming: Some(json!({"id":id,"call_id":call_id,"phase":"connecting","call":null})),
            incoming_context: Some(context.clone()),
            incoming_cancel: Some(cancel),
        });
    }
    let target = incoming_call::Target {
        url: url.to_string(),
        call_id: call_id.clone(),
        context: context.clone(),
    };
    let mut driver = AnswerDriver {
        app: app.clone(),
        id: id.clone(),
        identity,
        call_id,
        context,
        connected: false,
        cancellation,
    };
    // Keep the profile lock until the task is registered: Log out cancels it
    // atomically with removing the in-memory session.
    let task = tauri::async_runtime::spawn(async move {
        let _ = incoming_call::run(&mut driver, &target).await;
        driver.finish().await;
    });
    let gate = app.state::<MediaGate>();
    let mut current = gate.current.lock().map_err(|_| "unavailable")?;
    if let Some(session) = current.as_mut().filter(|s| s.id == id) {
        session.lease = Some(task.inner().abort_handle());
    } else {
        task.abort();
    }
    Ok(())
}
struct AnswerDriver {
    app: tauri::AppHandle,
    id: String,
    identity: String,
    call_id: String,
    context: Value,
    connected: bool,
    cancellation: tokio::sync::watch::Receiver<bool>,
}
impl AnswerDriver {
    async fn finish(&self) {
        let owned = {
            let gate = self.app.state::<MediaGate>();
            let Ok(mut current) = gate.current.lock() else {
                return;
            };
            if current.as_ref().is_some_and(|s| s.id == self.id) {
                current.take();
                true
            } else {
                false
            }
        };
        if owned {
            let _ = dispatch(
                self.app.clone(),
                json!({"op":"end_call","id":self.id,"call_id":self.call_id}),
            )
            .await;
        }
    }
}
impl incoming_call::Driver for AnswerDriver {
    fn cancellation(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        Some(self.cancellation.clone())
    }
    fn live(&self) -> bool {
        self.app
            .state::<MediaGate>()
            .current
            .lock()
            .is_ok_and(|state| state.as_ref().is_some_and(|s| s.id == self.id))
    }
    async fn operation(&mut self, op: &str, fields: Value) -> Result<Value, &'static str> {
        if !self.live() {
            return Err("ended");
        }
        crate::release_policy::require_online(&self.app).map_err(|_| "updateRequired")?;
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
        client.operate(request).await.map_err(|_| "unauthorized")
    }
    async fn media(&mut self, mut request: Value) -> Result<Value, &'static str> {
        if !self.live() {
            return Err("ended");
        }
        request["id"] = self.id.clone().into();
        request["call_id"] = self.call_id.clone().into();
        let value = dispatch(self.app.clone(), request)
            .await
            .map_err(|_| "unavailable")?;
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
                .filter(|s| s.id == self.id)
                .ok_or("ended")?;
            session.incoming = Some(json!({"id":self.id,"call_id":self.call_id,"call":call,
                "phase":if connected {"connected"} else {"connecting"}}));
        }
        if connected && !self.connected {
            plugin(
                &self.app,
                "callAction",
                json!({"action":"connected","callId":self.call_id}),
            )
            .await
            .map_err(|_| "unavailable")?;
            self.connected = true;
        }
        Ok(())
    }
}

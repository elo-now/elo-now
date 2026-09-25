//! Native tokens and route-owner capabilities never enter the web view or a profile backup.
use elo_core::app::ClientApp;
use serde_json::{Value, json};

#[cfg(any(all(mobile, feature = "mobile-push"), test))]
fn obsolete_registration(bytes: &[u8], endpoint: &str) -> Result<bool, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "Invalid notification settings".to_owned())?;
    let version = value["v"].as_u64().ok_or("Invalid notification settings")?;
    let saved_endpoint = value["route"]["endpoint"]
        .as_str()
        .ok_or("Invalid notification settings")?;
    Ok(version != 2 || saved_endpoint != endpoint)
}

#[cfg(any(all(mobile, feature = "mobile-push"), test))]
fn discard_obsolete_registration(
    file: &std::path::Path,
    bytes: &[u8],
    endpoint: &str,
    disable: impl FnOnce() -> Result<(), String>,
) -> Result<bool, String> {
    if !obsolete_registration(bytes, endpoint)? {
        return Ok(false);
    }
    disable()?;
    std::fs::remove_file(file).map_err(|_| "Could not remove notification settings")?;
    Ok(true)
}

#[cfg(test)]
mod registration_tests {
    use super::{discard_obsolete_registration, obsolete_registration};

    #[test]
    fn only_matching_notification_registrations_are_reused() {
        let endpoint = "https://notifications.example.test/wake/";
        for (version, saved_endpoint, obsolete) in [
            (2, endpoint, false),
            (1, endpoint, true),
            (2, "https://previous.example.test/wake/", true),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "v":version,"route":{"endpoint":saved_endpoint},
                "legacy_field":"does not need migration"
            }))
            .unwrap();
            assert_eq!(obsolete_registration(&bytes, endpoint).unwrap(), obsolete);
        }
        for bytes in [b"invalid".as_slice(), b"{}", b"{\"v\":2,\"route\":{}}"] {
            assert!(obsolete_registration(bytes, endpoint).is_err());
        }
    }

    #[test]
    fn obsolete_registration_is_removed_only_after_native_delivery_is_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("push-registration.json");
        let endpoint = "https://notifications.example.test/";
        let bytes = serde_json::to_vec(&serde_json::json!({
            "v":1,"route":{"endpoint":endpoint}
        }))
        .unwrap();
        std::fs::write(&file, &bytes).unwrap();
        assert!(
            discard_obsolete_registration(&file, &bytes, endpoint, || Err("unavailable".into()))
                .is_err()
        );
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        assert!(discard_obsolete_registration(&file, &bytes, endpoint, || Ok(())).unwrap());
        assert!(!file.exists());

        let current = serde_json::to_vec(&serde_json::json!({
            "v":2,"route":{"endpoint":endpoint}
        }))
        .unwrap();
        std::fs::write(&file, &current).unwrap();
        assert!(
            !discard_obsolete_registration(&file, &current, endpoint, || panic!(
                "Current registration must stay enabled"
            ))
            .unwrap()
        );
        assert_eq!(std::fs::read(&file).unwrap(), current);
    }
}

pub fn configure_client(client: &mut ClientApp) -> Result<(), String> {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        let url = env!("ELO_CONFIGURED_WAKE");
        client
            .configure_push(url, cfg!(debug_assertions))
            .map_err(|_| "Invalid notification service configuration".to_owned())?;
    }
    let _ = client;
    Ok(())
}

#[tauri::command]
pub async fn push_task(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::State>,
    op: String,
    expected_identity: Option<String>,
) -> Result<Value, String> {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        if op == "hint" {
            use tauri::Manager;
            // UI feedback must not wait behind the profile's network operation.
            // Expose only the same opaque tap ID as status, never native tokens
            // or an unverified destination. Normal status still verifies identity.
            let adapter = app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>();
            let native = adapter.call("status", json!({}))?;
            let opened = native["opened"].as_str().map(|encoded| {
                elo_core::ids::ObjectId::of_ciphertext(encoded.as_bytes()).to_string()
            });
            return Ok(json!({"opened":opened}));
        }
        mobile::operate(app, state, op, expected_identity).await
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = (app, state, op, expected_identity);
        Ok(json!({"available":false,"enabled":false,"pending":false,"wake":false}))
    }
}

pub async fn changed(app: &tauri::AppHandle, client: &ClientApp) -> bool {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        return mobile::changed(app, client).await.unwrap_or(true);
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = (app, client);
        false
    }
}
pub async fn suspend(app: &tauri::AppHandle) -> Result<(), String> {
    let media = crate::native_media::shutdown(app).await;
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        let notifications = mobile::suspend(app).await;
        return media.and(notifications);
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = app;
        media
    }
}
/// Called only after every account service durably accepted deletion.
pub fn forget(app: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        return mobile::forget(app);
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = app;
        Ok(())
    }
}

pub fn messages_read(
    app: &tauri::AppHandle,
    client: &ClientApp,
    request: &Value,
) -> Result<(), String> {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        return mobile::messages_read(app, client, request);
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = (app, client, request);
        Ok(())
    }
}

#[cfg(all(mobile, feature = "mobile-push"))]
mod mobile {
    use super::*;
    use elo_core::{
        app::push::{Route, endpoint},
        record, vault,
    };
    use serde::{Deserialize, Serialize};
    use std::time::Duration;
    use tauri::Manager;
    use tauri_plugin_notification::NotificationExt;
    use zeroize::Zeroizing;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Device {
        v: u8,
        identity: String,
        enabled: bool,
        active: bool,
        route: Route,
        owner: String,
        token: String,
        next_attempt: u64,
        policy: Value,
        revision: u64,
        acknowledged: u64,
        #[serde(default)]
        generation: u64,
        #[serde(default)]
        reads: Vec<PendingRead>,
        #[serde(default)]
        calls_enabled: bool,
        #[serde(default)]
        calls_policy: String,
        #[serde(default)]
        calls_updated: u64,
        #[serde(default)]
        call_ringtone: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PendingRead {
        receipt: Value,
        expires: u64,
    }
    fn valid_hex(value: &str, bytes: usize) -> bool {
        value.len() == bytes * 2
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn random<const N: usize>() -> Result<String, String> {
        let mut bytes = [0u8; N];
        getrandom::fill(&mut bytes).map_err(|_| "Cannot prepare notifications")?;
        Ok(record::encode_hex(&bytes))
    }
    fn time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs())
            .unwrap_or(0)
    }
    fn path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
        Ok(app
            .path()
            .app_data_dir()
            .map_err(|_| "Cannot open notification settings")?
            .join("push-registration.json"))
    }
    fn save(app: &tauri::AppHandle, device: &Device) -> Result<(), String> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(device).map_err(|_| "Cannot save notification settings")?,
        );
        vault::write_private(&path(app)?, &bytes, true)
            .map_err(|_| "Cannot save notification settings".into())
    }
    fn load(app: &tauri::AppHandle, url: &str) -> Result<Option<Device>, String> {
        let file = path(app)?;
        if !file.exists() {
            return Ok(None);
        }
        let bytes = Zeroizing::new(
            vault::read_private(&file).map_err(|_| "Cannot read notification settings")?,
        );
        if discard_obsolete_registration(&file, &bytes, url, || {
            // Never send a saved capability to an endpoint from an old build.
            // Stop local delivery before discarding an unusable registration;
            // normal notification setup will obtain a fresh route and token.
            app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
                .call("disable", json!({}))
                .map(|_| ())
                .map_err(|_| "Could not turn off notifications".to_owned())
        })? {
            return Ok(None);
        }
        let device: Device =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid notification settings")?;
        if device.v != 2
            || device.route.endpoint != url
            || !valid_hex(&device.route.id, 16)
            || !valid_hex(&device.identity, 32)
            || !valid_hex(&device.owner, 32)
            || !valid_hex(&device.route.notify_key, 32)
            || !valid_hex(&device.route.scope_key, 32)
        {
            return Err("Notification settings do not match this application.".into());
        }
        Ok(Some(device))
    }
    async fn request(
        app: &tauri::AppHandle,
        device: &Device,
        suffix: &str,
        body: Option<Value>,
        method: reqwest::Method,
    ) -> Result<Value, String> {
        crate::release_policy::require_online(app)?;
        let base = endpoint(&device.route.endpoint, cfg!(debug_assertions))
            .map_err(|_| "Invalid notification service")?;
        let url = base
            .join(&format!("v1/routes/{}{suffix}", device.route.id))
            .map_err(|_| "Invalid notification service")?;
        // Registration waits for the provider to send its possession challenge.
        // Its bounded provider call can take longer than ordinary route updates.
        let timeout = if suffix.is_empty() && method == reqwest::Method::POST {
            Duration::from_secs(12)
        } else {
            Duration::from_secs(4)
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| "Could not connect to notifications")?;
        let mut request = client.request(method, url).bearer_auth(&device.owner);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| "Could not connect to notifications. Try again.")?;
        if !response.status().is_success() {
            return Err("Could not update notifications. Try again.".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Could not read notification setup")?
        {
            if bytes.len() + chunk.len() > 4096 {
                return Err("Invalid notification setup response".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|_| "Invalid notification setup response".into())
    }
    async fn policy(
        app: &tauri::AppHandle,
        client: &ClientApp,
        device: &mut Device,
    ) -> Result<(), String> {
        let policy = client
            .notification_policy(&device.route)
            .map_err(|_| "Could not read notification preferences")?;
        if policy != device.policy {
            if elo_core::app::push::policy_requires_rotation(&device.policy, &policy) {
                device.route.notify_key = random::<32>()?;
            }
            device.policy = policy;
            device.revision = device
                .revision
                .checked_add(1)
                .ok_or("Invalid notification revision")?;
            save(app, device)?;
        }
        // Persist the revision before sending. An interrupted call retries the identical policy.
        if device.active && device.acknowledged != device.revision {
            let mut body = device.policy.clone();
            body["revision"] = json!(device.revision);
            body["notify_key"] = json!(device.route.notify_key);
            request(app, device, "/policy", Some(body), reqwest::Method::PUT).await?;
            device.acknowledged = device.revision;
            save(app, device)?;
            client
                .advertise_wake_route(Some(device.route.clone()))
                .map_err(|_| "Could not share notification availability")?;
        }
        call_policy(app, client, device).await?;
        Ok(())
    }
    async fn call_policy(
        app: &tauri::AppHandle,
        client: &ClientApp,
        device: &mut Device,
    ) -> Result<(), String> {
        if !device.active {
            return Ok(());
        }
        let adapter = app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>();
        let copy: Value = serde_json::from_str(include_str!("../../src/locales/native.en.json"))
            .map_err(|_| "Invalid call labels")?;
        let native = adapter.call("callConfigure",json!({"enabled":device.calls_enabled,
            "ringtone":device.call_ringtone,"labels":{"incoming":copy["calls.nativeIncoming"],"answer":copy["calls.nativeAnswer"],"decline":copy["calls.nativeDecline"],"unlock":copy["calls.unlockToAnswer"],"connected":copy["calls.nativeConnected"]},
            "registration":device.route.id,"endpoint":device.route.endpoint}))?;
        let token = if cfg!(target_os = "ios") {
            native["token"].as_str().unwrap_or("")
        } else {
            &device.token
        };
        if device.calls_enabled && token.is_empty() {
            return Ok(());
        }
        if !device.calls_enabled && device.calls_policy.is_empty() {
            return Ok(());
        }
        let subscriptions = if device.calls_enabled {
            client
                .notification_call_subscriptions(&device.route)
                .map_err(|_| "Could not read incoming call preferences")?
        } else {
            vec![]
        };
        let mut semantic = json!({"ownership_version":1,"enabled":device.calls_enabled,"token":token,"subscriptions":subscriptions});
        if let Some(items) = semantic["subscriptions"].as_array_mut() {
            for item in items {
                item.as_object_mut().unwrap().remove("target");
            }
        }
        let digest =
            elo_core::ids::ObjectId::of_ciphertext(semantic.to_string().as_bytes()).to_string();
        if digest == device.calls_policy && device.calls_updated + 86400 > time() {
            return Ok(());
        }
        #[cfg(target_os = "ios")]
        if device.calls_enabled {
            let challenge = request(
                app,
                device,
                "/voip/challenge",
                Some(json!({"token":token})),
                reqwest::Method::POST,
            )
            .await?;
            if challenge["verified"] != true {
                if challenge["identity"] != json!(client.identity_id()) {
                    return Err(
                        "Could not verify this device for incoming calls. Try again.".into(),
                    );
                }
                let proof = adapter.call(
                    "voipOwnership",
                    json!({"identity":client.identity_id(),"nonce":challenge["nonce"]}),
                )?;
                if proof["token"] != token {
                    return Err(
                        "Could not verify this device for incoming calls. Try again.".into(),
                    );
                }
                request(
                    app,
                    device,
                    "/voip/proof",
                    Some(proof),
                    reqwest::Method::POST,
                )
                .await?;
            }
        }
        request(app, device,"/calls",Some(json!({"enabled":device.calls_enabled,"platform":if cfg!(target_os="ios"){"ios"}else{"android"},
            "token":token,"subscriptions":subscriptions})),reqwest::Method::PUT).await?;
        device.calls_policy = digest;
        device.calls_updated = time();
        save(app, device)
    }
    pub(super) fn messages_read(
        app: &tauri::AppHandle,
        client: &ClientApp,
        request: &Value,
    ) -> Result<(), String> {
        let url = env!("ELO_CONFIGURED_WAKE");
        let Some(mut device) = load(app, url)? else {
            return Ok(());
        };
        if !device.enabled || device.identity != client.identity_id().to_string() {
            return Ok(());
        }
        let receipts = client
            .notification_read_receipts(&device.route, request)
            .map_err(|_| "Could not update read notifications")?;
        let expires = time() + 86400;
        device.reads.retain(|r| r.expires > time());
        for receipt in receipts {
            if !device.reads.iter().any(|r| r.receipt == receipt) {
                device.reads.push(PendingRead { receipt, expires });
            }
        }
        // This is best-effort notification bookkeeping, not message history.
        // Keep recent receipts within the private registration-file budget.
        let excess = device.reads.len().saturating_sub(1024);
        device.reads.drain(..excess);
        save(app, &device)
    }
    async fn flush_reads(app: &tauri::AppHandle, device: &mut Device) -> Result<(), String> {
        device.reads.retain(|r| r.expires > time());
        let count = device.reads.len().min(32);
        if count > 0 {
            let receipts = device.reads[..count]
                .iter()
                .map(|r| &r.receipt)
                .collect::<Vec<_>>();
            request(
                app,
                device,
                "/read",
                Some(json!({"events":receipts})),
                reqwest::Method::POST,
            )
            .await?;
            device.reads.drain(..count);
            save(app, device)?;
        }
        Ok(())
    }
    pub(super) async fn changed(
        app: &tauri::AppHandle,
        client: &ClientApp,
    ) -> Result<bool, String> {
        let url = env!("ELO_CONFIGURED_WAKE");
        let Some(mut device) = load(app, url)? else {
            return Ok(false);
        };
        if !device.enabled || device.identity != client.identity_id().to_string() {
            return Ok(false);
        }
        if device.generation != client.notification_generation() {
            device.active = false;
            save(app, &device)?;
            return Ok(true);
        }
        policy(app, client, &mut device).await?;
        Ok(!device.active || device.acknowledged != device.revision)
    }
    pub(super) async fn suspend(app: &tauri::AppHandle) -> Result<(), String> {
        let url = env!("ELO_CONFIGURED_WAKE");
        let adapter = app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>();
        // Disable local delivery even if saved registration data cannot be read.
        let disabled = adapter
            .call("disable", json!({}))
            .map_err(|_| "Could not turn off notifications".to_owned());
        if let Some(mut saved) = load(app, url)? {
            saved.enabled = false;
            saved.active = false;
            save(app, &saved)?;
            // Keep the owner capability for revocation retries after an offline logout.
            if request(app, &saved, "", None, reqwest::Method::DELETE)
                .await
                .is_ok()
            {
                std::fs::remove_file(path(app)?)
                    .map_err(|_| "Could not save notification settings")?;
            }
        }
        disabled.map(|_| ())
    }
    pub(super) fn forget(app: &tauri::AppHandle) -> Result<(), String> {
        let adapter = app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>();
        let _: Value = adapter
            .call("disable", json!({}))
            .map_err(|_| "Could not turn off notifications")?;
        let path = path(app)?;
        if path.exists() {
            std::fs::remove_file(path).map_err(|_| "Could not remove notification settings")?;
        }
        Ok(())
    }
    pub(super) async fn operate(
        app: tauri::AppHandle,
        state: tauri::State<'_, crate::State>,
        op: String,
        expected: Option<String>,
    ) -> Result<Value, String> {
        let url = env!("ELO_CONFIGURED_WAKE");
        let adapter = app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>();
        let mut native: Value = adapter
            .call("status", json!({}))
            .map_err(|_| "Could not read notification settings")?;
        if native["available"] != true {
            return Ok(json!({"available":false,"enabled":false,"pending":false,"wake":false}));
        }
        let mut state = state.lock().await;
        let revision = state.view_revision;
        let client = state.client.as_mut().ok_or("Unlock your profile first")?;
        let _history = (op == "maintain").then(|| {
            app.state::<crate::background_history::BackgroundHistory>()
                .publish(client.history_snapshot(), revision)
        });
        let identity = client.identity_id().to_string();
        if expected.as_deref() != Some(identity.as_str()) {
            return Err("The open profile has changed".into());
        }
        let mut device = load(&app, url)?;
        if op == "disable" {
            suspend(&app).await?;
            client
                .advertise_wake_route(None)
                .map_err(|_| "Could not update notification settings")?;
            return Ok(
                json!({"available":true,"enabled":false,"pending":load(&app,url)?.is_some(),"wake":false}),
            );
        }
        if let Some(saved) = device.as_ref()
            && (saved.identity != identity || !saved.enabled || native["permission"] == false)
        {
            suspend(&app).await?;
            client
                .advertise_wake_route(None)
                .map_err(|_| "Could not update notification settings")?;
            device = load(&app, url)?;
            if device.is_some() {
                return Ok(json!({"available":true,"enabled":false,"pending":true,"wake":false}));
            }
        }
        if op.starts_with("calls_") {
            let saved = device
                .as_mut()
                .filter(|d| d.enabled && d.active)
                .ok_or("Enable system notifications first.")?;
            match op.as_str() {
                "calls_enable" | "calls_disable" => {
                    saved.calls_enabled = op == "calls_enable";
                    saved.calls_updated = 0;
                    save(&app, saved)?;
                    call_policy(&app, client, saved).await?;
                }
                _ if op.starts_with("calls_ringtone:") => {
                    let tone = op.trim_start_matches("calls_ringtone:");
                    if !["classic", "chime", "pulse", "silent"].contains(&tone) {
                        return Err("Invalid call ringtone".into());
                    }
                    saved.call_ringtone = tone.into();
                    save(&app, saved)?;
                    call_policy(&app, client, saved).await?;
                }
                "calls_status" => {
                    let result = adapter
                        .call("callStatus", json!({}))
                        .map_err(|_| "Could not read incoming call")?;
                    let mut incoming = result["incoming"].clone();
                    if let Some(target) = incoming["target"].as_str() {
                        incoming["target"] =
                            client.open_call_notification(target).unwrap_or(Value::Null);
                    }
                    return Ok(
                        json!({"incoming":if incoming["id"].is_string() {json!({"id":incoming["id"],"action":incoming["action"],"target":incoming["target"],"expires":incoming["expires"],"event":incoming["event"],"muted":incoming["muted"]})}else{Value::Null}}),
                    );
                }
                _ if op.starts_with("calls_answering:")
                    || op.starts_with("calls_connected:")
                    || op.starts_with("calls_end:")
                    || op.starts_with("calls_ack:") =>
                {
                    let mut parts = op.split(':');
                    let action = parts.next().ok_or("Invalid call action")?;
                    let id = parts.next().ok_or("Invalid call action")?;
                    let event = parts.next();
                    if parts.next().is_some()
                        || event.is_some_and(|e| {
                            e.len() != 36 || !e.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
                        })
                        || !valid_hex(id, 16)
                    {
                        return Err("Invalid call action".into());
                    }
                    return adapter.call(
                        "callAction",
                        json!({"action":action.trim_start_matches("calls_"),"callId":id,"event":event}),
                    );
                }
                _ => return Err("Unknown call action".into()),
            }
        }
        if op == "enable" {
            if app
                .notification()
                .request_permission()
                .map_err(|_| "Could not request notifications")?
                != tauri_plugin_notification::PermissionState::Granted
            {
                return Err("Allow notifications in system settings.".into());
            }
            if device.is_none() {
                device = Some(Device {
                    v: 2,
                    identity: identity.clone(),
                    enabled: true,
                    active: false,
                    route: Route {
                        endpoint: url.into(),
                        id: random::<16>()?,
                        notify_key: random::<32>()?,
                        scope_key: random::<32>()?,
                        since: time() * 1000,
                    },
                    owner: random::<32>()?,
                    token: String::new(),
                    next_attempt: 0,
                    policy: Value::Null,
                    revision: 0,
                    acknowledged: 0,
                    generation: client.notification_generation(),
                    reads: Vec::new(),
                    calls_enabled: false,
                    calls_policy: String::new(),
                    calls_updated: 0,
                    call_ringtone: "classic".into(),
                });
            }
            let saved = device.as_mut().ok_or("Could not prepare notifications")?;
            save(&app, saved)?;
            let registered: Value = adapter
                .call("register", json!({"registration":saved.route.id}))
                .map_err(|_| "Could not register notifications. Try again.")?;
            saved.token = registered["token"]
                .as_str()
                .ok_or("Could not register notifications")?
                .into();
            saved.next_attempt = 0;
            save(&app, saved)?;
            native = adapter
                .call("status", json!({}))
                .map_err(|_| "Could not read notifications")?;
        } else if op != "maintain"
            && op != "status"
            && !op.starts_with("ack:")
            && !op.starts_with("calls_")
        {
            return Err("Unknown notification action".into());
        }
        if let Some(saved) = device.as_mut()
            && saved.enabled
            && (op == "maintain" || op == "enable")
        {
            if let Some(token) = native["token"].as_str()
                && !saved.token.is_empty()
                && (saved.token != token || saved.generation != client.notification_generation())
            {
                // Require acknowledgement before replacing the revocation capability.
                request(&app, saved, "", None, reqwest::Method::DELETE).await?;
                saved.route.id = random::<16>()?;
                saved.route.notify_key = random::<32>()?;
                saved.route.scope_key = random::<32>()?;
                saved.route.since = time() * 1000;
                saved.owner = random::<32>()?;
                saved.active = false;
                saved.next_attempt = 0;
                saved.policy = Value::Null;
                saved.revision = 0;
                saved.acknowledged = 0;
                saved.token = token.into();
                saved.generation = client.notification_generation();
                saved.reads.clear();
                saved.calls_policy.clear();
                saved.calls_updated = 0;
                save(&app, saved)?;
                let _: Value = adapter
                    .call("register", json!({"registration":saved.route.id}))
                    .map_err(|_| "Could not refresh notifications")?;
                native = adapter
                    .call("status", json!({}))
                    .map_err(|_| "Could not read notifications")?;
            }
            if saved.token.is_empty()
                && let Some(token) = native["token"].as_str()
            {
                saved.token = token.into();
                saved.generation = client.notification_generation();
            }
            // A lost policy acknowledgement may leave the server on the new
            // notify key. Retry that durable revision before renewing the route.
            if saved.active && saved.acknowledged != saved.revision {
                policy(&app, client, saved).await?;
            }
            if !saved.token.is_empty() && saved.next_attempt <= time() {
                saved.next_attempt = time() + 15;
                save(&app, saved)?;
                let result = request(
                    &app, saved,
                    "",
                    Some(json!({"token":saved.token,"notify_key":saved.route.notify_key,"binding":client.account_route_binding(&saved.route.endpoint,&saved.route.id,&saved.token).map_err(|_|"Could not register notification identity")?})),
                    reqwest::Method::POST,
                )
                .await?;
                saved.active = result["active"] == true;
                if !saved.active {
                    saved.acknowledged = 0;
                }
                if saved.active {
                    saved.next_attempt = time() + 86400;
                }
                save(&app, saved)?;
            }
            if !saved.active
                && let Some(challenge) = native["challenge"].as_str()
            {
                let result = request(
                    &app,
                    saved,
                    "/confirm",
                    Some(json!({"challenge":challenge})),
                    reqwest::Method::POST,
                )
                .await?;
                saved.active = result["active"] == true;
                if !saved.active {
                    saved.acknowledged = 0;
                }
                if saved.active {
                    saved.next_attempt = time() + 86400;
                }
                save(&app, saved)?;
            }
            policy(&app, client, saved).await?;
            if saved.active {
                // A read acknowledgement must not turn a healthy notification
                // registration into a pending-settings error while offline.
                let _ = flush_reads(&app, saved).await;
            }
            if saved.active && saved.revision == saved.acknowledged {
                client
                    .advertise_wake_route(Some(saved.route.clone()))
                    .map_err(|_| "Could not share notification availability")?;
            }
        }
        let mut opened = Value::Null;
        if device
            .as_ref()
            .is_some_and(|d| d.enabled && d.identity == identity)
            && let Some(encoded) = native["opened"].as_str()
        {
            let id = elo_core::ids::ObjectId::of_ciphertext(encoded.as_bytes()).to_string();
            if op == format!("ack:{id}") {
                let _: Value = adapter
                    .call("ack", json!({"opened":encoded}))
                    .map_err(|_| "Could not acknowledge notification")?;
            } else {
                opened = json!({"id":id,"target":client.open_notification(encoded).unwrap_or(Value::Null)});
            }
        }
        // A received hint can be consumed here: foreground sync always catches up independently.
        if let Some(wake) = native["wake"].as_str() {
            let _: Value = adapter
                .call("ack", json!({"wake":wake}))
                .map_err(|_| "Could not acknowledge notification")?;
        }
        Ok(
            json!({"available":true,"enabled":device.as_ref().is_some_and(|d|d.enabled),
            "pending":device.as_ref().is_some_and(|d|d.enabled && (!d.active || d.acknowledged!=d.revision)),
            "callsEnabled":device.as_ref().is_some_and(|d|d.calls_enabled),
            "callsPending":device.as_ref().is_some_and(|d| d.calls_enabled && (d.calls_policy.is_empty() || d.calls_updated == 0)),
            "wake":native["wake"].is_string(),"opened":opened}),
        )
    }
}

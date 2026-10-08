//! Native tokens and route-owner capabilities never enter the web view or a profile backup.
use elo_core::app::ClientApp;
use serde_json::{Value, json};

#[cfg(any(all(mobile, feature = "mobile-push"), test))]
#[path = "push_preferences.rs"]
mod preferences;

#[cfg(any(all(mobile, feature = "mobile-push"), test))]
#[path = "push_round.rs"]
mod round;

#[cfg(all(mobile, feature = "mobile-push"))]
pub fn setup(app: &tauri::AppHandle) {
    use tauri::{Emitter, Manager};
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let target = app.clone();
        // A content-free hint wakes the verified status flow. Native tokens and
        // unverified notification targets never enter the web view.
        let channel = tauri::ipc::Channel::<Value>::new(move |_| {
            let _ = target.emit("push-changed", ());
            Ok(())
        });
        let _ = app
            .state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
            .call("statusListener", json!({"channel":channel}));
    });
}

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
    // Desktop clients also send wakes to mobile recipients. Only receiving
    // native push notifications requires the mobile plugin.
    client
        .configure_push(env!("ELO_CONFIGURED_WAKE"), cfg!(debug_assertions))
        .map_err(|_| "Invalid notification service configuration".to_owned())
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
pub async fn suspend(app: &tauri::AppHandle, client: Option<&ClientApp>) -> Result<(), String> {
    crate::foreground_ringtone::shutdown(app).await;
    #[cfg(all(mobile, feature = "mobile-push"))]
    crate::incoming_calls::shutdown(app).await;
    let media = crate::native_media::shutdown(app).await;
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        // Preference persistence must never prevent local delivery from stopping.
        let remembered = client
            .map(|client| mobile::remember(app, client))
            .transpose();
        let notifications = mobile::suspend(app).await;
        return media.and(notifications).and(remembered.map(|_| ()));
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = (app, client);
        media
    }
}
/// Called only after every account service durably accepted deletion.
pub fn forget(app: &tauri::AppHandle, identity: &str) -> Result<(), String> {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        return mobile::forget(app, identity);
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = (app, identity);
        Ok(())
    }
}

pub fn update(app: &tauri::AppHandle, result: &Value) {
    #[cfg(all(mobile, feature = "mobile-push"))]
    {
        mobile::update(app, result);
        if result["result"]["private_settings_changed"]
            .as_u64()
            .unwrap_or(0)
            > 0
        {
            mobile::schedule_private_read_cleanup(app);
        }
    }
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    let _ = (app, result);
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
    use super::preferences::Preferences;
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
        #[serde(default)]
        incoming_token: String,
        #[serde(default)]
        incoming_renew: u64,
        #[serde(default)]
        next_registration_attempt: u64,
        next_attempt: u64,
        policy: Value,
        revision: u64,
        acknowledged: u64,
        #[serde(default)]
        generation: u64,
        #[serde(default)]
        reads: Vec<PendingRead>,
        #[serde(default)]
        cleared: Vec<PendingRead>,
    }
    #[derive(Clone, Serialize, Deserialize)]
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
    fn path(app: &tauri::AppHandle, url: &str) -> Result<std::path::PathBuf, String> {
        let root = app
            .path()
            .app_data_dir()
            .map_err(|_| "Cannot open notification settings")?;
        if url == env!("ELO_CONFIGURED_WAKE") {
            return Ok(root.join("push-registration.json"));
        }
        let directory = root.join("push-registrations");
        std::fs::create_dir_all(&directory).map_err(|_| "Cannot open notification settings")?;
        Ok(directory.join(format!(
            "{}.json",
            elo_core::ids::ObjectId::of_ciphertext(url.as_bytes())
        )))
    }
    fn registered_endpoints(app: &tauri::AppHandle) -> Result<Vec<String>, String> {
        let mut urls = vec![env!("ELO_CONFIGURED_WAKE").to_owned()];
        let root = app
            .path()
            .app_data_dir()
            .map_err(|_| "Cannot open notification settings")?
            .join("push-registrations");
        if root.exists() {
            for file in std::fs::read_dir(root).map_err(|_| "Cannot open notification settings")? {
                let file = file
                    .map_err(|_| "Cannot read notification settings")?
                    .path();
                if file.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                if urls.len() >= 33 {
                    return Err("Too many notification registrations".into());
                }
                let bytes = Zeroizing::new(
                    vault::read_private(&file).map_err(|_| "Cannot read notification settings")?,
                );
                let value: Value =
                    serde_json::from_slice(&bytes).map_err(|_| "Invalid notification settings")?;
                let url = value["route"]["endpoint"]
                    .as_str()
                    .ok_or("Invalid notification settings")?;
                endpoint(url, cfg!(debug_assertions))
                    .map_err(|_| "Invalid notification settings")?;
                if path(app, url)? != file {
                    return Err("Invalid notification registration location".into());
                }
                urls.push(url.to_owned());
            }
        }
        Ok(urls)
    }
    fn native_status(app: &tauri::AppHandle, registration: Option<&str>) -> Result<Value, String> {
        app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
            .call("status", json!({"registration":registration}))
    }
    fn save(app: &tauri::AppHandle, device: &Device) -> Result<(), String> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(device).map_err(|_| "Cannot save notification settings")?,
        );
        vault::write_private(&path(app, &device.route.endpoint)?, &bytes, true)
            .map_err(|_| "Cannot save notification settings".into())
    }
    fn load(app: &tauri::AppHandle, url: &str) -> Result<Option<Device>, String> {
        let file = path(app, url)?;
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
        let mut value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid notification settings")?;
        if let Some(fields) = value.as_object_mut() {
            for key in [
                "calls_enabled",
                "calls_policy",
                "calls_updated",
                "call_ringtone",
            ] {
                fields.remove(key);
            }
        }
        let device: Device =
            serde_json::from_value(value).map_err(|_| "Invalid notification settings")?;
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
    fn choices(client: &ClientApp, device: Option<&Device>) -> Result<Preferences, String> {
        let identity = client.identity_id().to_string();
        if let Some(saved) = Preferences::load(client.profile_path(), &identity)? {
            return Ok(saved);
        }
        let mut prefs = Preferences::new(&identity);
        // Adopt an existing opt-in once. An old suspended route is not consent.
        if device.is_some_and(|d| d.identity == identity && d.enabled) {
            prefs.enabled = true;
            prefs.save(client.profile_path())?;
        }
        Ok(prefs)
    }
    pub(super) fn remember(app: &tauri::AppHandle, client: &ClientApp) -> Result<(), String> {
        for url in registered_endpoints(app)? {
            if let Some(device) = load(app, &url)? {
                choices(client, Some(&device))?;
            }
        }
        Ok(())
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
    fn prepare_policy(
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
        Ok(())
    }
    fn enrollment_routes(
        app: &tauri::AppHandle,
        client: &ClientApp,
        current: Option<&Device>,
    ) -> Result<Vec<elo_core::app::push::Route>, String> {
        let identity = client.identity_id().to_string();
        let mut routes = Vec::new();
        for url in client.notification_endpoints() {
            let saved = load(app, &url)?;
            let device = current
                .filter(|device| device.route.endpoint == url)
                .or(saved.as_ref());
            if let Some(device) = device
                .filter(|device| device.enabled && device.active && device.identity == identity)
            {
                routes.push(device.route.clone());
            }
        }
        routes.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(routes)
    }

    async fn policy(
        app: &tauri::AppHandle,
        client: &ClientApp,
        device: &mut Device,
    ) -> Result<(), String> {
        prepare_policy(app, client, device)?;
        // Persist the revision before sending. An interrupted call retries the identical policy.
        if device.active && device.acknowledged != device.revision {
            // Publishing a new ring scope may deliver a push immediately. Its
            // matching call-only keys and receive route must already be durable.
            // Enrollment reuses unchanged delegates, including across hosts.
            let routes = enrollment_routes(app, client, Some(device))?;
            crate::incoming_calls::enroll(app, client, routes)
                .await
                .map_err(|_| "Could not update notification settings")?;
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
        Ok(())
    }
    static UNREAD: std::sync::Mutex<(crate::notification_counts::Counts, u64)> =
        std::sync::Mutex::new((crate::notification_counts::Counts::new(), 0));

    pub(super) fn update(app: &tauri::AppHandle, result: &Value) {
        let view = result.get("view").unwrap_or(result);
        if !view["streams"].is_array() {
            return;
        }
        let mut state = UNREAD.lock().expect("notification unread state");
        if let Some(count) = state.0.update(view) {
            let changed = (count > 0) != (state.1 > 0);
            state.1 = count;
            drop(state);
            if changed {
                schedule_reconcile(app);
            }
        }
    }
    static RECONCILE_PENDING: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static RECONCILE_RUNNING: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    fn schedule_reconcile(app: &tauri::AppHandle) {
        use std::sync::atomic::Ordering::SeqCst;
        RECONCILE_PENDING.store(true, SeqCst);
        if RECONCILE_RUNNING.swap(true, SeqCst) {
            return;
        }
        let app = app.clone();
        // OS notification-center callbacks never delay message send/read or profile unlock.
        tauri::async_runtime::spawn_blocking(move || {
            loop {
                RECONCILE_PENDING.store(false, SeqCst);
                let _ = reconcile(&app);
                if RECONCILE_PENDING.load(SeqCst) {
                    continue;
                }
                RECONCILE_RUNNING.store(false, SeqCst);
                if !RECONCILE_PENDING.load(SeqCst) || RECONCILE_RUNNING.swap(true, SeqCst) {
                    break;
                }
            }
        });
    }
    fn reconcile(app: &tauri::AppHandle) -> Result<(), String> {
        for url in registered_endpoints(app)? {
            reconcile_route(app, &url)?;
        }
        Ok(())
    }
    fn reconcile_route(app: &tauri::AppHandle, url: &str) -> Result<(), String> {
        let Some(device) = load(app, url)? else {
            return Ok(());
        };
        if !device.enabled || !device.policy["scopes"].is_array() {
            return Ok(());
        }
        let scopes = device.policy["scopes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|s| s["enabled"] == true)
            .map(|s| s["scope"].clone())
            .collect::<Vec<_>>();
        let receipts = device
            .cleared
            .iter()
            .filter(|r| r.expires > time())
            .map(|r| &r.receipt)
            .collect::<Vec<_>>();
        let state = UNREAD.lock().expect("notification unread state");
        if state.0.identity != device.identity {
            return Ok(());
        }
        let unread = state.1 > 0;
        drop(state);
        let labels: Value = serde_json::from_str(include_str!("../../src/locales/native.en.json"))
            .map_err(|_| "Invalid notification labels")?;
        let _: Value = app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>().call("reconcile", json!({
            "registration":device.route.id,"unread":unread,"receipts":receipts,"scopes":scopes,"labels":labels
        }))?;
        Ok(())
    }
    pub(super) fn messages_read(
        app: &tauri::AppHandle,
        client: &ClientApp,
        request: &Value,
    ) -> Result<(), String> {
        for url in registered_endpoints(app)? {
            let Some(mut device) = load(app, &url)? else {
                continue;
            };
            if !device.enabled || device.identity != client.identity_id().to_string() {
                continue;
            }
            let receipts = client
                .notification_read_receipts(&device.route, request)
                .map_err(|_| "Could not update read notifications")?;
            record_read_receipts(app, &mut device, receipts)?;
        }
        schedule_reconcile(app);
        Ok(())
    }
    fn record_read_receipts(
        app: &tauri::AppHandle,
        device: &mut Device,
        receipts: Vec<Value>,
    ) -> Result<(), String> {
        let expires = time() + 86400;
        device.reads.retain(|r| r.expires > time());
        device.cleared.retain(|r| r.expires > time());
        for receipt in receipts {
            if !device.cleared.iter().any(|r| r.receipt == receipt) {
                device.cleared.push(PendingRead {
                    receipt: receipt.clone(),
                    expires,
                });
            }
            if !device.reads.iter().any(|r| r.receipt == receipt) {
                device.reads.push(PendingRead { receipt, expires });
            }
        }
        // This is best-effort notification bookkeeping, not message history.
        // Keep recent receipts within the private registration-file budget.
        let excess = device.reads.len().saturating_sub(1024);
        device.reads.drain(..excess);
        let excess = device.cleared.len().saturating_sub(1024);
        device.cleared.drain(..excess);
        save(app, device)
    }
    static PRIVATE_READ_CLEANUP_RUNNING: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static PRIVATE_READ_CLEANUP_PENDING: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    pub(super) fn schedule_private_read_cleanup(app: &tauri::AppHandle) {
        use std::sync::atomic::Ordering::SeqCst;
        PRIVATE_READ_CLEANUP_PENDING.store(true, SeqCst);
        if PRIVATE_READ_CLEANUP_RUNNING.swap(true, SeqCst) {
            return;
        }
        let app = app.clone();
        // Remote read state must clear that chat's delivered notifications even
        // while another chat remains unread. This needs no relay network request
        // and runs after the operation releases its profile lock.
        tauri::async_runtime::spawn(async move {
            loop {
                PRIVATE_READ_CLEANUP_PENDING.store(false, SeqCst);
                let state = app.state::<crate::State>();
                let runtime = state.lock().await;
                if let Some(client) = runtime.client.as_ref() {
                    for url in registered_endpoints(&app).unwrap_or_default() {
                        if let Ok(Some(mut device)) = load(&app, &url) {
                            if device.enabled && device.identity == client.identity_id().to_string()
                            {
                                if let Ok(native) = native_status(&app, Some(&device.route.id)) {
                                    let _ = reconcile_delivered(&app, client, &mut device, &native)
                                        .await;
                                    schedule_reconcile(&app);
                                }
                            }
                        }
                    }
                }
                drop(runtime);
                if PRIVATE_READ_CLEANUP_PENDING.load(SeqCst) {
                    continue;
                }
                PRIVATE_READ_CLEANUP_RUNNING.store(false, SeqCst);
                if !PRIVATE_READ_CLEANUP_PENDING.load(SeqCst)
                    || PRIVATE_READ_CLEANUP_RUNNING.swap(true, SeqCst)
                {
                    break;
                }
            }
        });
    }

    async fn reconcile_delivered(
        app: &tauri::AppHandle,
        client: &ClientApp,
        device: &mut Device,
        native: &Value,
    ) -> Result<(), String> {
        if native["registration"] != device.route.id || native["enabled"] != true {
            return Ok(());
        }
        let Some(delivered) = native["delivered"].as_array() else {
            return Ok(());
        };
        let receipts = client
            .notification_delivered_read_receipts(&device.route, delivered)
            .await
            .map_err(|_| "Could not update read notifications")?;
        if !receipts.is_empty() {
            record_read_receipts(app, device, receipts)?;
        }
        Ok(())
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
        let mut pending = false;
        for url in client.notification_endpoints() {
            pending |= changed_route(app, client, &url).await?;
        }
        Ok(pending)
    }
    async fn changed_route(
        app: &tauri::AppHandle,
        client: &ClientApp,
        url: &str,
    ) -> Result<bool, String> {
        let Some(mut device) = load(app, url)? else {
            return Ok(true);
        };
        if !device.enabled || device.identity != client.identity_id().to_string() {
            return Ok(false);
        }
        if device.generation != client.notification_generation() {
            device.active = false;
            save(app, &device)?;
            return Ok(true);
        }
        prepare_policy(app, client, &mut device)?;
        Ok(!device.active || device.acknowledged != device.revision)
    }
    pub(super) async fn suspend(app: &tauri::AppHandle) -> Result<(), String> {
        // Stop local delivery before any network or private-file operation.
        app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
            .call("disable", json!({}))?;
        let endpoints = registered_endpoints(app)?;
        for url in &endpoints {
            if let Some(mut saved) = load(app, url)?
                && saved.enabled
            {
                saved.enabled = false;
                saved.active = false;
                saved.next_attempt = 0;
                save(app, &saved)?;
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        for url in endpoints {
            if let Some(result) = super::round::until(deadline, suspend_route(app, &url)).await {
                result?;
            } else {
                break;
            }
        }
        Ok(())
    }
    async fn suspend_route(app: &tauri::AppHandle, url: &str) -> Result<(), String> {
        if let Some(mut saved) = load(app, url)? {
            app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
                .call("remove", json!({"registration":saved.route.id}))?;
            if saved.enabled {
                saved.enabled = false;
                saved.active = false;
                saved.next_attempt = 0;
            }
            if saved.next_attempt > time() {
                return Ok(());
            }
            saved.next_attempt = time() + 30;
            save(app, &saved)?;
            if request(app, &saved, "", None, reqwest::Method::DELETE)
                .await
                .is_ok()
            {
                std::fs::remove_file(path(app, url)?)
                    .map_err(|_| "Could not save notification settings")?;
            }
        }
        Ok(())
    }
    pub(super) fn forget(app: &tauri::AppHandle, identity: &str) -> Result<(), String> {
        app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
            .call("disable", json!({}))?;
        for url in registered_endpoints(app)? {
            if load(app, &url)?.is_none_or(|device| device.identity != identity) {
                continue;
            }
            let file = path(app, &url)?;
            if file.exists() {
                std::fs::remove_file(file).map_err(|_| "Could not remove notification settings")?;
            }
        }
        Ok(())
    }
    pub(super) async fn operate(
        app: tauri::AppHandle,
        state: tauri::State<'_, crate::State>,
        op: String,
        expected: Option<String>,
    ) -> Result<Value, String> {
        let adapter = app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>();
        let native: Value = adapter
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
        let mut endpoints = client.notification_endpoints();
        if !matches!(op.as_str(), "enable" | "disable" | "maintain" | "status")
            && !op.starts_with("ack:")
        {
            return Err("Unknown notification action".into());
        }
        if op == "disable" {
            let mut prefs = choices(client, None)?;
            prefs.enabled = false;
            prefs.save(client.profile_path())?;
            crate::incoming_calls::shutdown(&app).await;
            suspend(&app).await?;
            client
                .advertise_wake_route(None)
                .map_err(|_| "Could not update notification settings")?;
            return Ok(json!({"available":true,"enabled":false,"pending":false,"wake":false}));
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
            let mut prefs = choices(client, None)?;
            prefs.enabled = true;
            prefs.save(client.profile_path())?;
        }
        let mut stale = Vec::new();
        for url in registered_endpoints(&app)? {
            if op != "status" && !endpoints.contains(&url) {
                if let Some(mut saved) = load(&app, &url)? {
                    adapter.call("remove", json!({"registration":saved.route.id}))?;
                    if saved.enabled {
                        saved.enabled = false;
                        saved.active = false;
                        saved.next_attempt = 0;
                        save(&app, &saved)?;
                    }
                }
                stale.push(url);
            }
        }
        let mut round = super::round::Round::new(
            choices(client, None)?.enabled && native["permission"] == true,
        );
        let maintenance = matches!(op.as_str(), "maintain" | "enable");
        if maintenance {
            // Capture every locally verified tap before an offline hosting service
            // can consume the network budget. Status does not contact a relay.
            for url in &endpoints {
                if let Ok(value) = operate_route(&app, client, url, "status").await {
                    round.snapshot(json!({"opened":value["opened"],"wake":value["wake"]}));
                }
            }
        }
        let mut work = endpoints
            .drain(..)
            .map(|url| (url, false))
            .collect::<Vec<_>>();
        if maintenance {
            work.extend(stale.into_iter().map(|url| (url, true)));
        }
        static NEXT_HOST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        if maintenance && !work.is_empty() {
            let start = NEXT_HOST.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % work.len();
            work.rotate_left(start);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        for (url, stale) in work {
            if stale {
                // Retired hosts participate in the same rotation, so a repeatedly
                // unavailable active host cannot starve revocation retries.
                if let Some(result) = super::round::until(deadline, suspend_route(&app, &url)).await
                {
                    result?;
                } else {
                    round.defer();
                    break;
                }
            } else if maintenance {
                // Each side effect persists its capability/revision before awaiting
                // the network, so cancellation safely retries on a later round.
                match super::round::until(deadline, operate_route(&app, client, &url, &op)).await {
                    Some(value) => round.accept(value),
                    None => {
                        round.defer();
                        break;
                    }
                }
            } else {
                round.accept(operate_route(&app, client, &url, &op).await);
            }
        }
        if maintenance && choices(client, None)?.enabled {
            match enrollment_routes(&app, client, None) {
                Ok(routes) => {
                    if crate::incoming_calls::enroll(&app, client, routes)
                        .await
                        .is_err()
                    {
                        round.defer();
                    }
                }
                Err(_) => round.defer(),
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            for url in client.notification_endpoints() {
                if !matches!(
                    super::round::until(deadline, incoming_binding(&app, &url)).await,
                    Some(Ok(()))
                ) {
                    round.defer();
                }
            }
        }
        round.finish()
    }

    async fn incoming_binding(app: &tauri::AppHandle, url: &str) -> Result<(), String> {
        let Some(mut saved) = load(app, url)? else {
            return Ok(());
        };
        if !saved.enabled || !saved.active {
            return Ok(());
        }
        let native = app
            .state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
            .call("incomingStatus", json!({}))?;
        let (provider, token) = if cfg!(target_os = "ios") {
            (
                "apns",
                native["voipToken"].as_str().unwrap_or_default().to_string(),
            )
        } else {
            ("fcm", saved.token.clone())
        };
        if token.is_empty() {
            return Ok(());
        }
        let sandbox = provider == "apns" && native["apnsSandbox"].as_bool().unwrap_or(false);
        // A differently signed installation must renew even if a token remains unchanged.
        let binding = format!("{provider}:{sandbox}:{token}");
        if binding == saved.incoming_token && saved.incoming_renew > time() {
            return Ok(());
        }
        let mut payload = json!({"provider":provider});
        if provider == "apns" {
            payload["token"] = token.into();
            payload["sandbox"] = sandbox.into();
        }
        request(
            app,
            &saved,
            "/ring-binding",
            Some(payload),
            reqwest::Method::PUT,
        )
        .await?;
        saved.incoming_token = binding;
        saved.incoming_renew = time() + 12 * 3600;
        save(app, &saved)
    }

    async fn operate_route(
        app: &tauri::AppHandle,
        client: &mut ClientApp,
        url: &str,
        op: &str,
    ) -> Result<Value, String> {
        let adapter = app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>();
        let identity = client.identity_id().to_string();
        let mut device = load(app, url)?;
        let mut native = native_status(app, device.as_ref().map(|d| d.route.id.as_str()))?;
        let prefs = choices(client, device.as_ref())?;
        if let Some(saved) = device.as_ref()
            && (saved.identity != identity
                || !saved.enabled
                || !prefs.enabled
                || native["permission"] == false)
        {
            // A status read must not wait for an offline logout's server cleanup.
            let cleanup_due =
                saved.enabled || native["enabled"] == true || saved.next_attempt <= time();
            if matches!(op, "maintain" | "enable") && cleanup_due {
                suspend_route(app, url).await?;
                client
                    .withdraw_wake_route(url)
                    .map_err(|_| "Could not update notification settings")?;
                device = load(app, url)?;
                native = native_status(app, device.as_ref().map(|d| d.route.id.as_str()))?;
            }
            if device.is_some() {
                schedule_reconcile(app);
                let enabled = prefs.enabled && native["permission"] == true;
                return Ok(json!({"available":true,"enabled":enabled,"pending":true,"wake":false}));
            }
        }
        // Local delivery cleanup must finish before any registration/policy
        // network attempt can fail while the phone is offline.
        if matches!(op, "status" | "maintain") {
            let local = if let Some(saved) = device.as_mut() {
                reconcile_delivered(app, client, saved, &native).await
            } else {
                Ok(())
            };
            schedule_reconcile(app);
            local?;
        }
        let automatic = preferences::should_resume(
            prefs.enabled,
            native["permission"] == true,
            op == "maintain",
            device
                .as_ref()
                .is_none_or(|d| d.token.is_empty() || native["registration"] != d.route.id),
            time(),
            device.as_ref().map_or(0, |d| d.next_registration_attempt),
        );
        if op == "enable" || automatic {
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
                    incoming_token: String::new(),
                    incoming_renew: 0,
                    next_registration_attempt: 0,
                    next_attempt: 0,
                    policy: Value::Null,
                    revision: 0,
                    acknowledged: 0,
                    generation: client.notification_generation(),
                    reads: Vec::new(),
                    cleared: Vec::new(),
                });
            }
            let saved = device.as_mut().ok_or("Could not prepare notifications")?;
            saved.next_registration_attempt = time() + 30;
            save(app, saved)?;
            let registered: Value = adapter
                .call(
                    "register",
                    json!({"registration":saved.route.id,"background":automatic}),
                )
                .map_err(|_| "Could not register notifications. Try again.")?;
            if !automatic {
                saved.token = registered["token"]
                    .as_str()
                    .ok_or("Could not register notifications")?
                    .into();
                saved.next_attempt = 0;
                save(app, saved)?;
            }
            native = native_status(app, Some(&saved.route.id))?;
        } else if op != "maintain" && op != "status" && !op.starts_with("ack:") {
            return Err("Unknown notification action".into());
        }
        if let Some(saved) = device.as_mut()
            && saved.enabled
            && !automatic
            && (op == "maintain" || op == "enable")
        {
            if let Some(token) = native["token"].as_str()
                && !saved.token.is_empty()
                && (saved.token != token || saved.generation != client.notification_generation())
            {
                // Require acknowledgement before replacing the revocation capability.
                request(app, saved, "", None, reqwest::Method::DELETE).await?;
                let old_registration = saved.route.id.clone();
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
                saved.incoming_token.clear();
                saved.incoming_renew = 0;
                saved.generation = client.notification_generation();
                saved.reads.clear();
                save(app, saved)?;
                adapter.call("remove", json!({"registration":old_registration}))?;
                let _: Value = adapter
                    .call("register", json!({"registration":saved.route.id}))
                    .map_err(|_| "Could not refresh notifications")?;
                native = native_status(app, Some(&saved.route.id))?;
            }
            if saved.token.is_empty()
                && native["registration"] == saved.route.id
                && let Some(token) = native["token"].as_str()
            {
                saved.token = token.into();
                saved.incoming_token.clear();
                saved.incoming_renew = 0;
                saved.generation = client.notification_generation();
            }
            // A lost policy acknowledgement may leave the server on the new
            // notify key. Retry that durable revision before renewing the route.
            if saved.active && saved.acknowledged != saved.revision {
                policy(app, client, saved).await?;
            }
            if !saved.token.is_empty() && saved.next_attempt <= time() {
                saved.next_attempt = time() + 15;
                save(app, saved)?;
                let result = request(
                    app, saved,
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
                save(app, saved)?;
            }
            if !saved.active
                && let Some(challenge) = native["challenge"].as_str()
            {
                let result = request(
                    app,
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
                save(app, saved)?;
            }
            policy(app, client, saved).await?;
            if saved.active {
                // A read acknowledgement must not turn a healthy notification
                // registration into a pending-settings error while offline.
                let _ = flush_reads(app, saved).await;
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
        schedule_reconcile(app);
        let enabled = prefs.enabled && native["permission"] == true;
        let current = device
            .as_ref()
            .filter(|d| d.enabled && d.identity == identity);
        Ok(json!({"available":true,"enabled":enabled,
            "pending":enabled && current.is_none_or(|d| !d.active || d.acknowledged != d.revision),
            "wake":native["wake"].is_string(),"opened":opened}))
    }
}

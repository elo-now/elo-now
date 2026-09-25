use elo_core::app::{ClientApp, ProfileDraft};
use tauri::{Emitter, Manager};
use tokio::sync::Mutex;
#[cfg(target_os = "android")]
mod android_files;
#[cfg(target_os = "android")]
mod android_tls;
mod background_history;
#[cfg(any(all(target_os = "ios", feature = "mobile-push"), test))]
mod call_lease;
mod control_recovery;
#[cfg(debug_assertions)]
mod demo;
#[cfg(desktop)]
mod desktop_activity;
mod download_protection;
mod exchange;
#[cfg(all(target_os = "ios", feature = "mobile-push"))]
mod incoming_answer;
#[cfg(any(all(target_os = "ios", feature = "mobile-push"), test))]
mod incoming_call;
mod mail;
mod native_media;
mod profiles;
mod push;
mod recovery_clipboard;
mod recovery_progress;
mod release_policy;
mod sensitive_request;
#[cfg(test)]
#[path = "../service_endpoints.rs"]
mod service_endpoints;
mod team_replica;
#[derive(Default)]
struct Runtime {
    client: Option<ClientApp>,
    draft: Option<ProfileDraft>,
    demo_names: Option<serde_json::Value>,
    recovery: Option<ProfileDraft>,
    backup: Option<zeroize::Zeroizing<Vec<u8>>>,
    pair_source: Option<elo_core::app::pairing::PairSource>,
    pair_target: Option<elo_core::app::pairing::PairTarget>,
    recovery_qr: Option<String>,
    control_recovery: Option<serde_json::Value>,
    view_revision: u64,
}
type State = Mutex<Runtime>;

impl Runtime {
    fn detach_profile(&mut self) -> Option<ClientApp> {
        let old = std::mem::take(self);
        self.view_revision = old.view_revision.wrapping_add(1);
        old.client
    }
}

#[derive(Default)]
struct AttachmentTransfers(
    std::sync::Mutex<std::collections::HashMap<String, elo_core::app::AttachmentCancellation>>,
);

impl AttachmentTransfers {
    fn begin(&self, id: &str) -> Result<elo_core::app::AttachmentCancellation, String> {
        if id.len() != 36
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err("Invalid attachment transfer.".into());
        }
        let mut transfers = self
            .0
            .lock()
            .map_err(|_| "Attachment transfer state is unavailable.")?;
        if transfers.contains_key(id) {
            return Err("Attachment transfer is already running.".into());
        }
        let cancellation = elo_core::app::AttachmentCancellation::default();
        transfers.insert(id.to_owned(), cancellation.clone());
        Ok(cancellation)
    }

    fn finish(&self, id: &str) {
        if let Ok(mut transfers) = self.0.lock() {
            transfers.remove(id);
        }
    }

    fn cancel(&self, id: &str) {
        if let Ok(transfers) = self.0.lock()
            && let Some(cancellation) = transfers.get(id)
        {
            cancellation.cancel();
        }
    }
}

#[derive(Clone, serde::Serialize)]
struct AttachmentTransferProgress {
    transfer_id: String,
    received: u64,
    total: u64,
}

#[tauri::command]
async fn open_demo(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    person: String,
) -> Result<serde_json::Value, String> {
    #[cfg(debug_assertions)]
    {
        let mut state = state.lock().await;
        if state.client.is_some() {
            return Err("Lock the open profile first".into());
        }
        let base = app.path().app_data_dir().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
        let (mut client, names) = demo::open(&base, &person)
            .await
            .map_err(|e| e.to_string())?;
        team_replica::configure(&mut client)?;
        push::configure_client(&mut client)?;
        client.enable_spaces().await.map_err(|e| e.to_string())?;
        client.enable_paged_views();
        let mut view = client.view().await.map_err(|e| e.to_string())?;
        view["demo_names"] = names.clone();
        state.draft = None;
        state.demo_names = Some(names);
        state.client = Some(client);
        app.state::<background_history::BackgroundHistory>()
            .resume();
        #[cfg(desktop)]
        desktop_activity::update(&app, &view);
        Ok(view)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (app, state, person);
        Err("Demo profiles are available only in development builds".into())
    }
}

#[tauri::command]
fn profile_environment(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let base = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let directory = profiles::active(&app).map_err(|e| e.to_string())?;
    Ok(
        serde_json::json!({"mobile": cfg!(mobile), "platform":std::env::consts::OS, "directory":directory,
        "has_profile":directory.exists(), "demo_helpers":cfg!(debug_assertions),
        "demo_space_available":cfg!(feature = "team-test-replica"),
        "demo_space_id":team_replica::demo_space_id(),
        "saved_profiles":profiles::saved(&app).map_err(|e| e.to_string())?}),
    )
}
fn profile_directory(
    app: &tauri::AppHandle,
    directory: String,
) -> Result<std::path::PathBuf, String> {
    if cfg!(mobile) {
        profiles::active(app).map_err(|e| e.to_string())
    } else {
        let path = std::path::PathBuf::from(directory);
        if !path.is_absolute() {
            return Err("Choose an absolute profile directory".into());
        }
        Ok(path)
    }
}
#[tauri::command]
async fn prepare_profile(state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    let mut state = state.lock().await;
    if state.client.is_some() {
        return Err("Lock the open profile first".into());
    }
    let draft = ProfileDraft::new().map_err(|e| e.to_string())?;
    let card = serde_json::to_value(draft.card()).map_err(|e| e.to_string())?;
    state.draft = Some(draft);
    Ok(card)
}
#[tauri::command]
async fn cancel_profile(state: tauri::State<'_, State>) -> Result<(), String> {
    state.lock().await.draft = None;
    Ok(())
}
#[tauri::command]
async fn create_profile(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    directory: String,
    password: String,
    initial_channel: String,
    name: String,
    acknowledged: bool,
) -> Result<serde_json::Value, String> {
    let secret: age::secrecy::SecretString = password.into();
    let mut state = state.lock().await;
    if state.client.is_some() {
        return Err("Lock the open profile first".into());
    }
    if !acknowledged {
        return Err("Save your recovery words and identity ID first".into());
    }
    let draft = state
        .draft
        .as_ref()
        .ok_or("Prepare a recovery card first")?;
    // All platforms allocate the next app-managed profile automatically.
    // Keep the legacy command argument for existing desktop callers.
    let path = profiles::registration_path(&app).map_err(|e| e.to_string())?;
    let _ = directory;
    let mut client = draft
        .save_named(path.clone(), secret, &initial_channel, &name)
        .await
        .map_err(|e| e.to_string())?;
    push::configure_client(&mut client)?;
    client
        .begin_space_setup()
        .await
        .map_err(|e| e.to_string())?;
    client.enable_paged_views();
    let view = client.view().await.map_err(|e| e.to_string())?;
    if let Err(error) = profiles::select(&app, &path) {
        let _ = client.close().await;
        return Err(error.to_string());
    }
    state.draft = None;
    state.client = Some(client);
    app.state::<background_history::BackgroundHistory>()
        .resume();
    #[cfg(desktop)]
    desktop_activity::update(&app, &view);
    Ok(view)
}
#[tauri::command]
async fn unlock(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    directory: String,
    password: String,
    allow_insecure_loopback: bool,
    biometric_key: Option<String>,
    biometric_profile: Option<String>,
    biometric_identity: Option<String>,
) -> Result<serde_json::Value, String> {
    #[cfg(debug_assertions)]
    let timing = std::time::Instant::now();
    let mut secret: age::secrecy::SecretString = password.into();
    let mut state = state.lock().await;
    if let Some(key) = biometric_key {
        secret = profiles::biometric_password(
            &app,
            biometric_profile
                .as_deref()
                .ok_or("dataNeedsReenrollment")?,
            biometric_identity
                .as_deref()
                .ok_or("dataNeedsReenrollment")?,
            key.into(),
        )
        .map_err(|e| e.to_string())?;
    }
    #[cfg(debug_assertions)]
    let queued = timing.elapsed();
    if state.client.is_some() {
        return Err("Lock the open profile first".into());
    }
    let mut client = ClientApp::open(
        profile_directory(&app, directory)?,
        secret,
        allow_insecure_loopback,
    )
    .await
    .map_err(|e| e.to_string())?;
    #[cfg(debug_assertions)]
    history_timing(
        &app,
        "unlock_profile",
        queued,
        timing.elapsed().saturating_sub(queued),
    );
    #[cfg(debug_assertions)]
    let timing = std::time::Instant::now();
    team_replica::configure(&mut client)?;
    push::configure_client(&mut client)?;
    client.enable_spaces().await.map_err(|e| e.to_string())?;
    client.enable_paged_views();
    #[cfg(debug_assertions)]
    history_timing(
        &app,
        "unlock_spaces",
        std::time::Duration::ZERO,
        timing.elapsed(),
    );
    #[cfg(debug_assertions)]
    let timing = std::time::Instant::now();
    let view = client.view().await.map_err(|e| e.to_string())?;
    #[cfg(debug_assertions)]
    history_timing(
        &app,
        "unlock_view",
        std::time::Duration::ZERO,
        timing.elapsed(),
    );
    state.draft = None;
    state.client = Some(client);
    app.state::<background_history::BackgroundHistory>()
        .resume();
    #[cfg(desktop)]
    desktop_activity::update(&app, &view);
    Ok(view)
}
#[tauri::command]
async fn lock(app: tauri::AppHandle, state: tauri::State<'_, State>) -> Result<(), String> {
    app.state::<background_history::BackgroundHistory>()
        .suspend();
    let mut state = state.lock().await;
    // Revoke local access before fallible cleanup. Keep the mutex until stores
    // close so a concurrent unlock cannot race the previous session's shutdown.
    let client = state.detach_profile();
    #[cfg(desktop)]
    desktop_activity::clear(&app);
    let notifications = push::suspend(&app).await;
    let profile = close_locked_profile(client).await;
    let files = exchange::clear(&app);
    notifications
        .map_err(|_| "profile_logout_notifications_pending".to_owned())
        .and(profile.map_err(|_| "profile_logout_cleanup_pending".to_owned()))
        .and(files.map_err(|_| "profile_logout_cleanup_pending".to_owned()))
}

async fn close_locked_profile(client: Option<ClientApp>) -> Result<(), String> {
    let Some(client) = client else { return Ok(()) };
    let route = client.advertise_wake_route(None).map_err(|e| e.to_string());
    let close = client.close().await.map_err(|e| e.to_string());
    route.and(close)
}

#[cfg(test)]
mod logout_tests {
    use super::*;

    #[tokio::test]
    async fn broken_notification_state_does_not_keep_the_profile_or_store_open() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("profile");
        let password: age::secrecy::SecretString = "synthetic logout password".into();
        let client = ProfileDraft::new()
            .unwrap()
            .save(profile.clone(), password.clone(), "Test")
            .await
            .unwrap();
        let identity = client.identity_id();
        let mut runtime = Runtime {
            client: Some(client),
            draft: Some(ProfileDraft::new().unwrap()),
            recovery: Some(ProfileDraft::new().unwrap()),
            backup: Some(zeroize::Zeroizing::new(vec![1, 2, 3])),
            recovery_qr: Some("synthetic recovery data".into()),
            control_recovery: Some(serde_json::json!({"test": true})),
            view_revision: 4,
            ..Default::default()
        };
        elo_core::vault::write_private(
            &profile.join("invitations.age"),
            b"invalid synthetic state",
            true,
        )
        .unwrap();
        let detached = runtime.detach_profile();
        assert!(runtime.client.is_none());
        assert!(runtime.draft.is_none());
        assert!(runtime.recovery.is_none());
        assert!(runtime.backup.is_none());
        assert!(runtime.recovery_qr.is_none());
        assert!(runtime.control_recovery.is_none());
        assert_eq!(runtime.view_revision, 5);
        assert!(close_locked_profile(detached).await.is_err());
        // A cleanup error must not leave the database worker or its file lock
        // alive. A new session still requires the correct profile password.
        std::fs::remove_file(profile.join("invitations.age")).unwrap();
        assert!(
            ClientApp::open(profile.clone(), "wrong".into(), false)
                .await
                .is_err()
        );
        let reopened = ClientApp::open(profile, password, false).await.unwrap();
        assert_eq!(reopened.identity_id(), identity);
        reopened.close().await.unwrap();
    }
}
#[tauri::command]
async fn verify_password(state: tauri::State<'_, State>, password: String) -> Result<(), String> {
    let candidate: age::secrecy::SecretString = password.into();
    let state = state.lock().await;
    if state
        .client
        .as_ref()
        .ok_or("The profile is locked")?
        .password_matches(&candidate)
    {
        Ok(())
    } else {
        Err("The password is incorrect".into())
    }
}

#[tauri::command]
async fn attachment_transfer(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    transfers: tauri::State<'_, AttachmentTransfers>,
    mut request: serde_json::Value,
    transfer_id: String,
) -> Result<serde_json::Value, String> {
    release_policy::require_online(&app)?;
    let cancellation = transfers.begin(&transfer_id)?;
    let progress_app = app.clone();
    let progress_id = transfer_id.clone();
    let result = {
        let mut state = state.lock().await;
        let outcome = match state.client.as_mut() {
            Some(client) => match release_policy::require_online(&app)
                .and_then(|()| exchange::resolve_transfer(&app, &mut request))
            {
                Err(error) => Err(error),
                Ok(()) => client
                    .operate_attachment_transfer(request, cancellation, move |received, total| {
                        let _ = progress_app.emit(
                            "attachment-transfer-progress",
                            AttachmentTransferProgress {
                                transfer_id: progress_id.clone(),
                                received,
                                total,
                            },
                        );
                    })
                    .await
                    .map_err(|error| error.to_string()),
            },
            None => Err("The profile is locked".into()),
        };
        outcome.map(|mut result| {
            state.view_revision = state.view_revision.saturating_add(1);
            annotate_result(
                &mut result,
                state.client.as_ref().map(ClientApp::identity_id),
                state.view_revision,
                state.demo_names.as_ref(),
            );
            #[cfg(desktop)]
            desktop_activity::update(&app, &result);
            result
        })
    };
    transfers.finish(&transfer_id);
    result
}

#[tauri::command]
fn cancel_attachment_transfer(
    transfers: tauri::State<'_, AttachmentTransfers>,
    transfer_id: String,
) {
    transfers.cancel(&transfer_id);
}
fn application_operation(op: &str) -> bool {
    matches!(
        op,
        "view"
            | "history_page"
            | "set_profile_name"
            | "set_profile_details"
            | "create_chat"
            | "create_group"
            | "set_chat_group"
            | "set_chat_muted"
            | "set_user_blocked"
            | "message_debug"
            | "send"
            | "request_message"
            | "sync"
            | "sync_live"
            | "remove_member"
            | "message_action"
            | "remind"
            | "reminder_remove"
            | "mark_read"
            | "mark_unread"
            | "call_endpoint"
            | "call_authorization"
            | "call_encrypt_signal"
            | "call_open_signal"
            | "space_join_demo"
            | "space_list"
            | "space_refresh"
            | "space_create"
            | "space_setup_done"
            | "space_select"
            | "space_disconnect"
            | "space_preview"
            | "space_join"
            | "space_manage"
            | "space_invite"
            | "space_revoke"
            | "space_decide"
            | "space_role_change"
            | "space_role_decide"
            | "space_contact"
            | "space_contact_update"
            | "space_delete"
            | "space_storage"
            | "space_storage_prune"
            | "space_attachment_settings"
            | "space_attachment_retention"
            | "space_attachment_cleanup_preview"
            | "space_attachment_cleanup"
            | "contact_add_members"
            | "contact_create_chat"
            | "contact_preview"
            | "contact_add"
            | "create_dm"
            | "contact_open"
            | "invitation_ignore"
            | "invitation_sync"
            | "invitation_activity"
            | "invitation_notifications_seen"
            | "invitation_dismiss"
            | "invitation_create"
            | "invitation_list"
            | "invitation_disable"
            | "contact_create"
            | "invitation_preview"
            | "invitation_request"
            | "invitation_receive"
            | "invitation_decline"
            | "invitation_approve"
            | "invitation_join"
    )
}
#[tauri::command]
async fn operate(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    mut request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // New core/CLI operations require an explicit native capability review.
    if !application_operation(request["op"].as_str().unwrap_or_default()) {
        return Err("Unsupported application operation.".into());
    }
    #[cfg(debug_assertions)]
    let timing = std::time::Instant::now();
    #[cfg(debug_assertions)]
    let timed_operation = match request["op"].as_str() {
        Some("history_page") => Some("history_page"),
        Some("space_select") => Some("space_select"),
        Some("space_preview") => Some("space_preview"),
        Some("space_join") => Some("space_join"),
        Some("sync_live") => Some("sync_live"),
        Some("invitation_sync") => Some("invitation_sync"),
        _ => None,
    };
    let history_access = app.state::<background_history::BackgroundHistory>();
    let mut state = if request["op"] == "history_page" {
        loop {
            // Register before checking the snapshot, so a pass starting between
            // this check and lock acquisition cannot leave history queued behind it.
            let changed = history_access.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(result) = history_access.read(&request).await {
                #[cfg(debug_assertions)]
                history_timing(
                    &app,
                    "history_page",
                    std::time::Duration::ZERO,
                    timing.elapsed(),
                );
                return Ok(result);
            }
            tokio::select! {
                guard = state.lock() => break guard,
                _ = changed => {},
            }
        }
    } else {
        state.lock().await
    };
    release_policy::require_operation(&app, &request)?;
    #[cfg(desktop)]
    if request["_desktop_background"] == true && !desktop_activity::hidden(&app) {
        return Ok(serde_json::json!({}));
    }
    #[cfg(debug_assertions)]
    let queued = timing.elapsed();
    let preferences_changed = request["op"] == "set_user_blocked"
        || request["op"] == "set_chat_muted"
        || request["op"] == "space_disconnect"
        || request["op"] == "space_delete";
    let read_request = (request["op"] == "mark_read").then(|| request.clone());
    let revision = state.view_revision;
    let client = state.client.as_mut().ok_or("The profile is locked")?;
    // Invitation discovery also waits on the network while holding the runtime.
    // Keep existing local history readable until that pass publishes its changes.
    let _history = matches!(
        request["op"].as_str(),
        Some("sync" | "sync_live" | "invitation_sync")
    )
    .then(|| {
        app.state::<background_history::BackgroundHistory>()
            .publish(client.history_snapshot(), revision)
    });
    if request["op"] == "space_create" {
        // Host selection is native configuration, never a renderer-supplied URL.
        request["host"] = serde_json::json!(env!("ELO_CONFIGURED_SPACE_HOST"));
    }
    let mut result = if request["op"] == "space_join_demo" {
        if request["expected_identity"] != serde_json::json!(client.identity_id()) {
            return Err("The open profile has changed.".into());
        }
        team_replica::join_demo(client).await?;
        serde_json::json!({"view":client.view().await.map_err(|e|e.to_string())?})
    } else {
        let outcome = client.operate(request).await.map_err(|e| e.to_string());
        if outcome.is_err() && preferences_changed {
            // A durable safety preference may have committed before a later
            // local cleanup failed. Still propagate its restrictive policy.
            let _ = push::changed(&app, client).await;
            #[cfg(desktop)]
            if let Ok(view) = client.view().await {
                desktop_activity::update(&app, &view);
            }
        }
        exchange::clear_disconnected(&app, &client.connected_space_ids())?;
        outcome?
    };
    if preferences_changed && let Some(client) = state.client.as_ref() {
        result["notification_pending"] = serde_json::json!(push::changed(&app, client).await);
    }
    #[cfg(debug_assertions)]
    if let Some(timings) = result
        .as_object_mut()
        .and_then(|value| value.remove("_space_join_timing"))
    {
        for (key, label) in [
            ("prepare", "space_join_prepare"),
            ("server", "space_join_server"),
            ("install", "space_join_install"),
        ] {
            if let Some(ms) = timings[key].as_u64() {
                history_timing(
                    &app,
                    label,
                    std::time::Duration::ZERO,
                    std::time::Duration::from_millis(ms),
                );
            }
        }
    }
    if let Some(request) = read_request
        && let Some(client) = state.client.as_ref()
    {
        // Persist opaque receipts locally; network retries run in push maintenance.
        push::messages_read(&app, client, &request)?;
    }
    state.view_revision = state.view_revision.saturating_add(1);
    annotate_result(
        &mut result,
        state.client.as_ref().map(ClientApp::identity_id),
        state.view_revision,
        state.demo_names.as_ref(),
    );
    #[cfg(desktop)]
    desktop_activity::update(&app, &result);
    #[cfg(debug_assertions)]
    if let Some(operation) = timed_operation {
        history_timing(
            &app,
            operation,
            queued,
            timing.elapsed().saturating_sub(queued),
        );
    }
    Ok(result)
}

#[cfg(debug_assertions)]
fn history_timing(
    app: &tauri::AppHandle,
    operation: &str,
    queued: std::time::Duration,
    work: std::time::Duration,
) {
    // Timing only: never log request values, profile IDs or message content.
    let line = format!(
        "elo {operation}: queue={}ms work={}ms",
        queued.as_millis(),
        work.as_millis()
    );
    eprintln!("{line}");
    if option_env!("TAURI_ELO_HISTORY_TIMING") == Some("1")
        && let Ok(directory) = app.path().app_cache_dir()
        && std::fs::create_dir_all(&directory).is_ok()
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(directory.join("history-operation-timing.log"))
    {
        use std::io::Write;
        if file.metadata().is_ok_and(|m| m.len() > 256 * 1024) {
            let _ = file.set_len(0);
        }
        let _ = writeln!(file, "{line}");
    }
}

fn annotate_result(
    result: &mut serde_json::Value,
    identity: Option<elo_core::ids::IdentityId>,
    revision: u64,
    demo_names: Option<&serde_json::Value>,
) {
    result["identity"] = serde_json::json!(identity);
    if let Some(history) = result.get_mut("history").filter(|value| value.is_object()) {
        history["revision"] = serde_json::json!(revision);
    }
    if let Some(view) = result.get_mut("view").filter(|value| value.is_object()) {
        view["revision"] = serde_json::json!(revision);
        if let Some(names) = demo_names {
            view["demo_names"] = names.clone();
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "ios")]
    let builder = builder.plugin(tauri_plugin_elo_privacy::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(android_files::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(recovery_clipboard::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(release_policy::init());
    #[cfg(desktop)]
    let builder = builder.manage(desktop_activity::Activity::default());
    #[cfg(desktop)]
    let builder = builder.manage(recovery_clipboard::ClipboardState::default());
    #[cfg(mobile)]
    let builder = builder
        .plugin(tauri_plugin_biometry::init())
        .plugin(tauri_plugin_barcode_scanner::init())
        .plugin(tauri_plugin_sharekit::init());
    #[cfg(all(mobile, feature = "mobile-push"))]
    let builder = builder.plugin(tauri_plugin_elo_push::init());
    builder
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(State::default())
        .manage(release_policy::Checks::default())
        .manage(native_media::MediaGate::default())
        .manage(AttachmentTransfers::default())
        .manage(exchange::ExchangeFiles::default())
        .manage(background_history::BackgroundHistory::default())
        .manage(recovery_progress::RecoveryJobs::default())
        .setup(|app| {
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            if let Some(window) = app.get_webview_window("main") {
                window.set_decorations(false)?;
            }
            release_policy::setup(app.handle());
            #[cfg(all(target_os = "ios", feature = "mobile-push"))]
            incoming_answer::setup(app.handle());
            exchange::clear(app.handle()).map_err(std::io::Error::other)?;
            #[cfg(desktop)]
            desktop_activity::setup(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            profile_environment,
            open_demo,
            prepare_profile,
            cancel_profile,
            create_profile,
            unlock,
            lock,
            verify_password,
            attachment_transfer,
            cancel_attachment_transfer,
            operate,
            push::push_task,
            native_media::native_call_media,
            profiles::profile_task,
            exchange::choose_attachment,
            exchange::stage_attachment,
            exchange::discard_exchange,
            exchange::prepare_export,
            exchange::save_export,
            mail::open_mail_draft,
            exchange::invitation_qr,
            recovery_clipboard::copy_recovery_code,
            control_recovery::control_task,
            release_policy::release_policy,
            release_policy::check_release_policy,
            release_policy::open_update
        ])
        .build(tauri::generate_context!())
        .expect("application runtime failed")
        .run(|_app, _event| {
            #[cfg(desktop)]
            match _event {
                tauri::RunEvent::WindowEvent { label, event, .. } if label == "main" => match event
                {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        desktop_activity::close(_app, &api)
                    }
                    tauri::WindowEvent::Focused(true) => desktop_activity::resume(_app),
                    _ => {}
                },
                #[cfg(target_os = "macos")]
                tauri::RunEvent::Reopen { .. } => desktop_activity::show(_app),
                _ => {}
            }
        });
}

#[cfg(test)]
mod result_metadata_tests {
    use super::*;
    #[test]
    fn renderer_cannot_call_filesystem_or_future_core_operations() {
        for op in [
            "file_share",
            "file_download",
            "attachment_upload",
            "attachment_download",
            "history_import",
            "recovery_export",
            "unknown_future_operation",
        ] {
            assert!(!application_operation(op), "{op}");
        }
        for op in [
            "send",
            "space_join",
            "history_page",
            "call_endpoint",
            "call_authorization",
        ] {
            assert!(application_operation(op), "{op}");
        }
    }
    #[test]
    fn idle_demo_sync_keeps_the_absent_view_and_still_carries_its_identity() {
        let identity = elo_core::ids::IdentityId::from_bytes([1; 32]);
        let names = serde_json::json!({"synthetic":"Alex"});
        let mut result = serde_json::json!({"view":null,"result":{"more":true}});
        annotate_result(&mut result, Some(identity), 7, Some(&names));
        assert!(result["view"].is_null());
        assert_eq!(result["identity"], serde_json::json!(identity));
        assert_eq!(result["result"]["more"], true);
        result["view"] = serde_json::json!({"identity":identity});
        annotate_result(&mut result, Some(identity), 8, Some(&names));
        assert_eq!(result["view"]["revision"], 8);
        assert_eq!(result["view"]["demo_names"], names);
    }
}

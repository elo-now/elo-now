use elo_core::app::{ClientApp, ProfileDraft};
use tauri::Manager;
use tokio::sync::Mutex;
#[cfg(target_os = "android")]
mod android_tls;
mod background_history;
#[cfg(debug_assertions)]
mod demo;
mod exchange;
mod profiles;
mod push;
mod recovery_progress;
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
    view_revision: u64,
}
type State = Mutex<Runtime>;

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
        serde_json::json!({"mobile": cfg!(mobile), "directory":directory,
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
    let mut client = draft
        .save_named(
            profile_directory(&app, directory)?,
            secret,
            &initial_channel,
            &name,
        )
        .await
        .map_err(|e| e.to_string())?;
    push::configure_client(&mut client)?;
    client
        .begin_space_setup()
        .await
        .map_err(|e| e.to_string())?;
    client.enable_paged_views();
    let view = client.view().await.map_err(|e| e.to_string())?;
    state.draft = None;
    state.client = Some(client);
    app.state::<background_history::BackgroundHistory>()
        .resume();
    Ok(view)
}
#[tauri::command]
async fn unlock(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    directory: String,
    password: String,
    allow_insecure_loopback: bool,
) -> Result<serde_json::Value, String> {
    let secret: age::secrecy::SecretString = password.into();
    let mut state = state.lock().await;
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
    team_replica::configure(&mut client)?;
    push::configure_client(&mut client)?;
    client.enable_spaces().await.map_err(|e| e.to_string())?;
    client.enable_paged_views();
    let view = client.view().await.map_err(|e| e.to_string())?;
    state.draft = None;
    state.client = Some(client);
    app.state::<background_history::BackgroundHistory>()
        .resume();
    Ok(view)
}
#[tauri::command]
async fn lock(app: tauri::AppHandle, state: tauri::State<'_, State>) -> Result<(), String> {
    app.state::<background_history::BackgroundHistory>()
        .suspend();
    let mut state = state.lock().await;
    push::suspend(&app).await?;
    state.draft = None;
    state.demo_names = None;
    state.recovery = None;
    state.backup = None;
    state.pair_source = None;
    state.pair_target = None;
    state.recovery_qr = None;
    if let Some(client) = state.client.take() {
        client
            .advertise_wake_route(None)
            .map_err(|e| e.to_string())?;
        client.close().await.map_err(|e| e.to_string())?;
    }
    exchange::clear(&app).map_err(|e| e.to_string())?;
    Ok(())
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
async fn operate(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    #[cfg(debug_assertions)]
    let timing = std::time::Instant::now();
    #[cfg(debug_assertions)]
    let timed_operation = match request["op"].as_str() {
        Some("history_page") => Some("history_page"),
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
    #[cfg(debug_assertions)]
    let queued = timing.elapsed();
    let preferences_changed =
        request["op"] == "set_chat_muted" || request["op"] == "space_disconnect";
    let read_request = (request["op"] == "mark_read").then(|| request.clone());
    let revision = state.view_revision;
    let client = state.client.as_mut().ok_or("The profile is locked")?;
    let _history = matches!(
        request["op"].as_str(),
        Some("sync_live" | "invitation_sync")
    )
    .then(|| {
        app.state::<background_history::BackgroundHistory>()
            .publish(client.history_snapshot(), revision)
    });
    let mut result = if request["op"] == "space_join_demo" {
        if request["expected_identity"] != serde_json::json!(client.identity_id()) {
            return Err("The open profile has changed.".into());
        }
        team_replica::join_demo(client).await?;
        serde_json::json!({"view":client.view().await.map_err(|e|e.to_string())?})
    } else {
        client.operate(request).await.map_err(|e| e.to_string())?
    };
    if preferences_changed && let Some(client) = state.client.as_ref() {
        result["notification_pending"] = serde_json::json!(push::changed(&app, client).await);
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
        .manage(background_history::BackgroundHistory::default())
        .manage(recovery_progress::RecoveryJobs::default())
        .setup(|app| {
            exchange::clear(app.handle()).map_err(std::io::Error::other)?;
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
            operate,
            push::push_task,
            profiles::profile_task,
            exchange::choose_import,
            exchange::prepare_export,
            exchange::save_export,
            exchange::invitation_qr
        ])
        .run(tauri::generate_context!())
        .expect("application runtime failed");
}

#[cfg(test)]
mod result_metadata_tests {
    use super::*;
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

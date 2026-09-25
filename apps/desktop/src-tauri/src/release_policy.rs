//! Cached release requirements restrict online work without delaying local access.
use elo_core::{
    client_policy::{ClientPolicy, MAX_BYTES, PATH, Release},
    vault,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager};

pub const UPDATE_REQUIRED: &str = "updateRequired";
const CHECK_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct Checks {
    policy: std::sync::Mutex<Option<ClientPolicy>>,
    checked: tokio::sync::Mutex<Option<std::time::Instant>>,
}

#[derive(Serialize, Deserialize)]
struct Cached {
    origin: String,
    policy: ClientPolicy,
}

async fn fetch(origin: &str) -> Result<ClientPolicy, ()> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| ())?;
    let mut response = client
        .get(format!("{origin}{PATH}"))
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|n| n > MAX_BYTES as u64)
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if bytes.len() + chunk.len() > MAX_BYTES {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    let policy: ClientPolicy = serde_json::from_slice(&bytes).map_err(|_| ())?;
    policy.validate().map_err(|_| ())?;
    Ok(policy)
}

fn origin() -> String {
    reqwest::Url::parse(env!("ELO_CONFIGURED_SPACE_HOST"))
        .expect("validated service address")
        .origin()
        .ascii_serialization()
}
fn installed(app: &tauri::AppHandle) -> Release {
    let config = app.config();
    let build = match std::env::consts::OS {
        "android" => config.bundle.android.version_code.unwrap_or(0),
        "ios" => config
            .bundle
            .ios
            .bundle_version
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        "macos" => config
            .bundle
            .macos
            .bundle_version
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        _ => 0,
    };
    Release {
        version: app.package_info().version.to_string(),
        build,
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
/// No network or profile mutex: safe to consult at every native entry point.
pub(crate) fn required(app: &tauri::AppHandle) -> bool {
    app.state::<Checks>()
        .policy
        .lock()
        .expect("release policy")
        .as_ref()
        .is_some_and(|policy| {
            policy
                .required(std::env::consts::OS, &installed(app), now())
                .unwrap_or(false)
        })
}
pub(crate) fn require_online(app: &tauri::AppHandle) -> Result<(), String> {
    if required(app) {
        Err(UPDATE_REQUIRED.into())
    } else {
        Ok(())
    }
}

/// Read-only navigation and private device preferences stay available. New
/// operations default to restricted until their local-only behavior is reviewed.
fn local_operation(request: &serde_json::Value) -> bool {
    match request["op"].as_str().unwrap_or_default() {
        "view"
        | "history_page"
        | "message_debug"
        | "space_list"
        | "space_select"
        | "space_setup_done"
        | "mark_read"
        | "mark_unread"
        | "remind"
        | "reminder_remove"
        | "create_group"
        | "set_chat_group"
        | "set_chat_muted"
        | "set_user_blocked"
        | "invitation_notifications_seen"
        | "invitation_list"
        | "invitation_activity"
        | "call_encrypt_signal"
        | "call_open_signal" => true,
        // Existing media sessions may finish normally.
        "call_authorization" => matches!(
            request["operation"]["type"].as_str(),
            Some("heartbeat" | "leave" | "decline" | "media" | "signal" | "connect_media")
        ),
        _ => false,
    }
}
pub(crate) fn require_operation(
    app: &tauri::AppHandle,
    request: &serde_json::Value,
) -> Result<(), String> {
    if local_operation(request) {
        Ok(())
    } else {
        require_online(app)
    }
}

fn cache(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    app.path()
        .app_data_dir()
        .ok()
        .map(|p| p.join("client-policy.json"))
}
/// Initialize from disk before any background work starts. Never wait for HTTP.
pub(crate) fn setup(app: &tauri::AppHandle) {
    let cached = cache(app).and_then(|path| {
        std::fs::symlink_metadata(&path)
            .ok()
            .filter(|m| {
                m.is_file() && !m.file_type().is_symlink() && m.len() <= (MAX_BYTES + 4096) as u64
            })
            .and_then(|_| vault::read_private(&path).ok())
            .and_then(|bytes| serde_json::from_slice::<Cached>(&bytes).ok())
            .filter(|cached| cached.origin == origin() && cached.policy.validate().is_ok())
    });
    *app.state::<Checks>().policy.lock().expect("release policy") = cached.map(|c| c.policy);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            check_release_policy(app.clone()).await;
            // Also notice a scheduled minimum becoming effective between fetches.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}
#[tauri::command]
pub fn release_policy(app: tauri::AppHandle) -> bool {
    required(&app)
}

#[tauri::command]
pub async fn check_release_policy(app: tauri::AppHandle) -> bool {
    let state = app.state::<Checks>();
    let mut checked = state.checked.lock().await;
    if checked.is_none_or(|time| time.elapsed() >= CHECK_INTERVAL) {
        *checked = Some(std::time::Instant::now());
        if let Ok(policy) = fetch(&origin()).await {
            if let Some(path) = cache(&app) {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(bytes) = serde_json::to_vec(&Cached {
                    origin: origin(),
                    policy: policy.clone(),
                }) {
                    let _ = vault::write_private(&path, &bytes, true);
                }
            }
            *state.policy.lock().expect("release policy") = Some(policy);
        }
        // Outages retain the last confirmed policy, including explicit rollback.
    }
    let required = required(&app);
    let _ = app.emit("release-policy", required);
    required
}

#[cfg(desktop)]
fn download_url() -> &'static str {
    match std::env::consts::OS {
        "macos" if option_env!("ELO_DISTRIBUTION_CHANNEL") == Some("mac-app-store") => {
            "https://apps.apple.com/app/id6814766127"
        }
        _ => "https://github.com/elo-now/elo-now/releases/latest",
    }
}

#[cfg(target_os = "android")]
struct AndroidDownloads(tauri::plugin::PluginHandle<tauri::Wry>);
#[cfg(target_os = "android")]
pub fn init() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("elo-release-policy")
        .setup(|app, api| {
            app.manage(AndroidDownloads(
                api.register_android_plugin("now.elo", "ReleasePolicyPlugin")?,
            ));
            Ok(())
        })
        .build()
}
#[tauri::command]
pub async fn open_update(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(target_os = "android")]
    return app
        .state::<AndroidDownloads>()
        .0
        .run_mobile_plugin::<serde_json::Value>("openUpdate", ())
        .map(|_| ())
        .map_err(|_| "Could not open the download page.".into());
    #[cfg(target_os = "ios")]
    {
        app.state::<tauri_plugin_elo_privacy::Privacy>()
            .call("openUpdate", serde_json::json!({}))
            .map_err(|_| "Could not open the download page.".to_owned())
    }
    #[cfg(desktop)]
    {
        let _ = app;
        tauri::async_runtime::spawn_blocking(|| {
            #[cfg(target_os = "macos")]
            let result = std::process::Command::new("/usr/bin/open")
                .arg(download_url())
                .status();
            #[cfg(target_os = "windows")]
            let result = std::process::Command::new("rundll32.exe")
                .args(["url.dll,FileProtocolHandler", download_url()])
                .status();
            #[cfg(target_os = "linux")]
            let result = std::process::Command::new("xdg-open")
                .arg(download_url())
                .status();
            if result.is_ok_and(|status| status.success()) {
                Ok(())
            } else {
                Err("Could not open the download page.".into())
            }
        })
        .await
        .map_err(|_| "Could not open the download page.".to_owned())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn offline_navigation_stays_available_but_network_work_and_shared_edits_do_not() {
        for op in [
            "view",
            "history_page",
            "space_select",
            "space_list",
            "mark_read",
            "remind",
            "set_chat_muted",
        ] {
            assert!(local_operation(&json!({"op":op})), "{op}");
        }
        for op in [
            "send",
            "sync",
            "sync_live",
            "invitation_sync",
            "space_create",
            "space_join",
            "set_profile_details",
            "message_action",
            "space_delete",
            "contact_open",
            "call_endpoint",
            "attachment_upload",
            "attachment_download",
            "future_operation",
        ] {
            assert!(!local_operation(&json!({"op":op})), "{op}");
        }
    }

    #[test]
    fn existing_calls_can_continue_but_new_admission_is_blocked() {
        for kind in [
            "heartbeat",
            "leave",
            "decline",
            "media",
            "signal",
            "connect_media",
        ] {
            assert!(
                local_operation(&json!({"op":"call_authorization", "operation":{"type":kind}})),
                "{kind}"
            );
        }
        for kind in ["start", "join", "subscribe", "unknown"] {
            assert!(
                !local_operation(&json!({"op":"call_authorization", "operation":{"type":kind}})),
                "{kind}"
            );
        }
    }
}

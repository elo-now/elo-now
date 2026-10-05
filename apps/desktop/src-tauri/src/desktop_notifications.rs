//! Desktop-only, opt-in local alerts. OS payloads contain no profile or chat data.
//! Click identifiers are random in-memory capabilities, rechecked against the
//! currently unlocked verified view before the renderer receives a destination.
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex, time::Instant};
use tauri::{Emitter, Manager};
#[cfg(target_os = "macos")]
#[path = "desktop_notifications/macos.rs"]
mod platform;
#[cfg(any(target_os = "windows", target_os = "linux"))]
#[path = "desktop_notifications/other.rs"]
mod platform;

mod policy;
#[cfg(target_os = "macos")]
use policy::TTL;
pub(crate) use policy::{Category, Sound, Target};
use policy::{Registry, apply_history_page, valid_target};
#[derive(Default)]
pub(crate) struct Notifications(Mutex<Registry>, tokio::sync::Mutex<()>);
fn settings_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|_| "Notification settings unavailable")?
        .join("desktop-notifications.json"))
}
pub(crate) fn setup(app: &tauri::AppHandle) {
    let enabled = settings_path(app)
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .is_some_and(|value| value == json!({"v":1,"enabled":true}));
    app.state::<Notifications>()
        .0
        .lock()
        .expect("notification state")
        .enabled = enabled;
    platform::setup(app);
}
fn save_enabled(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let path = settings_path(app)?;
    std::fs::create_dir_all(path.parent().ok_or("Notification settings unavailable")?)
        .map_err(|_| "Notification settings unavailable")?;
    std::fs::write(path, json!({"v":1,"enabled":enabled}).to_string())
        .map_err(|_| "Could not save notification settings".to_owned())?;
    let state = app.state::<Notifications>();
    let mut state = state
        .0
        .lock()
        .map_err(|_| "Notification state unavailable")?;
    state.enabled = enabled;
    if !enabled {
        state.entries.clear();
        state.opened = None;
    }
    Ok(())
}
pub(super) fn clicked(app: &tauri::AppHandle, id: &str) {
    let state = app.state::<Notifications>();
    let accepted = if let Ok(mut state) = state.0.lock() {
        state.prune(Instant::now());
        if state.enabled && state.entries.contains_key(id) {
            state.opened = Some(id.to_owned());
            true
        } else {
            false
        }
    } else {
        false
    };
    if accepted {
        crate::desktop_activity::show(app);
        // No identities or destinations cross an event while the profile is locked.
        let _ = app.emit("desktop-notification-opened", ());
    }
}
async fn verify_target(
    client: &elo_core::app::ClientApp,
    target: &Target,
    arriving: bool,
) -> Result<bool, String> {
    let mut view = client
        .view()
        .await
        .map_err(|_| "Cannot verify notification target")?;
    if valid_target(&view, target, arriving) {
        return Ok(true);
    }
    // Paged views intentionally omit older records. Resolve against the same
    // verified local history projection, without network or scope selection.
    if target.category != Category::Message || view["paged"] != true {
        return Ok(false);
    }
    let request = json!({"op":"history_page","expected_identity":target.identity,
        "expected_space":view["active_space"],"target_space":target.space_context,
        "space":target.space,"stream":target.stream,"around":target.record});
    let Ok(page) = client.history_snapshot().history_page(&request).await else {
        return Ok(false);
    };
    if !apply_history_page(&mut view, target, &page) {
        return Ok(false);
    }
    Ok(valid_target(&view, target, arriving))
}
fn catalog(category: Category) -> &'static str {
    static TEXT: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        serde_json::from_str(include_str!("../../src/locales/desktop.en.json"))
            .expect("desktop English catalog")
    })
    .get(match category {
        Category::Message => "desktop.notification.message",
        Category::Session => "desktop.notification.session",
    })
    .expect("desktop notification translation")
}

#[tauri::command]
pub(crate) async fn desktop_notification_task(
    app: tauri::AppHandle,
    op: String,
    expected_identity: Option<String>,
    target: Option<Target>,
    sound: Option<Sound>,
) -> Result<Value, String> {
    let serial = app.state::<Notifications>();
    let _serial = serial.1.lock().await;
    match op.as_str() {
        "status" | "enable" | "disable" => {
            if op == "disable" {
                let ids = app
                    .state::<Notifications>()
                    .0
                    .lock()
                    .map_err(|_| "Notification state unavailable")?
                    .entries
                    .keys()
                    .cloned()
                    .collect();
                save_enabled(&app, false)?;
                platform::clear(ids);
            }
            let permission = platform::permission(op == "enable").await?;
            if op == "enable" && matches!(permission.as_str(), "granted" | "system") {
                save_enabled(&app, true)?;
            }
            let enabled = app
                .state::<Notifications>()
                .0
                .lock()
                .map_err(|_| "Notification state unavailable")?
                .enabled;
            Ok(
                json!({"available":platform::available(),"enabled":enabled,"permission":permission,
                "click_supported":platform::click_supported().await,"custom_sound":platform::custom_sound()}),
            )
        }
        "show" => {
            let target = target.ok_or("Notification target missing")?;
            if expected_identity.as_deref() != Some(&target.identity) {
                return Err("The open profile has changed.".into());
            }
            if !background(&app) || !platform::available() {
                return Ok(json!({"shown":false}));
            }
            let permission = platform::permission(false).await?;
            if !matches!(permission.as_str(), "granted" | "system") {
                return Ok(json!({"shown":false}));
            }
            let state = app.state::<crate::State>();
            let state = state.lock().await;
            let Some(client) = state.client.as_ref() else {
                return Ok(json!({"shown":false}));
            };
            if client.identity_id().to_string() != target.identity {
                return Ok(json!({"shown":false}));
            }
            if !verify_target(client, &target, true).await? {
                return Ok(json!({"shown":false}));
            }
            if !background(&app) {
                return Ok(json!({"shown":false}));
            }
            let category = target.category;
            let id = app
                .state::<Notifications>()
                .0
                .lock()
                .map_err(|_| "Notification state unavailable")?
                .insert(target, Instant::now());
            let Some(id) = id else {
                return Ok(json!({"shown":false}));
            };
            // Keep the profile guard until enqueue has completed, avoiding a lock/profile switch race.
            match platform::show(&app, &id, catalog(category), sound.unwrap_or_default()).await {
                Ok(()) => Ok(json!({"shown":true})),
                Err(error) => {
                    app.state::<Notifications>()
                        .0
                        .lock()
                        .map_err(|_| "Notification state unavailable")?
                        .entries
                        .remove(&id);
                    Err(error)
                }
            }
        }
        "take_opened" => {
            let pending = {
                let state = app.state::<Notifications>();
                let mut state = state
                    .0
                    .lock()
                    .map_err(|_| "Notification state unavailable")?;
                state.prune(Instant::now());
                state.opened.as_ref().and_then(|id| {
                    state
                        .entries
                        .get(id)
                        .map(|entry| (id.clone(), entry.target.clone()))
                })
            };
            let Some((id, target)) = pending else {
                return Ok(json!({"target":null,"pending":false}));
            };
            let state = app.state::<crate::State>();
            let state = state.lock().await;
            let Some(client) = state.client.as_ref() else {
                return Ok(json!({"target":null,"pending":true}));
            };
            if expected_identity.as_deref() != Some(&target.identity)
                || client.identity_id().to_string() != target.identity
            {
                return Ok(json!({"target":null,"pending":true}));
            }
            let valid = verify_target(client, &target, false).await?;
            let registry = app.state::<Notifications>();
            let mut registry = registry
                .0
                .lock()
                .map_err(|_| "Notification state unavailable")?;
            if registry.opened.as_deref() != Some(&id) {
                return Ok(json!({"target":null,"pending":true}));
            }
            registry.opened = None;
            Ok(json!({"target":if valid {Some(target)} else {None},"pending":false}))
        }
        _ => Err("Unsupported notification operation.".into()),
    }
}
fn background(app: &tauri::AppHandle) -> bool {
    app.get_webview_window("main")
        .is_some_and(|window| !window.is_focused().unwrap_or(true))
}

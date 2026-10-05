use super::Sound;
use std::sync::atomic::{AtomicUsize, Ordering};
static WAITING: AtomicUsize = AtomicUsize::new(0);
pub(super) fn setup(_app: &tauri::AppHandle) {}
pub(super) fn available() -> bool {
    true
}
pub(super) async fn permission(_ask: bool) -> Result<String, String> {
    // These backends expose no portable permission query. The OS still owns
    // app notification settings and Focus/DND; never report a fabricated grant.
    Ok("system".into())
}
pub(super) async fn click_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            notify_rust::get_capabilities().is_ok_and(|caps| caps.iter().any(|c| c == "actions"))
        })
        .await
        .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        true
    }
}
pub(super) fn custom_sound() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "server_dependent"
    }
    #[cfg(target_os = "windows")]
    {
        "system_default"
    }
}
pub(super) async fn show(
    app: &tauri::AppHandle,
    id: &str,
    body: &str,
    sound: Sound,
) -> Result<(), String> {
    // A broken desktop daemon cannot allocate an unbounded number of listeners.
    if WAITING
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < 32).then_some(n + 1)
        })
        .is_err()
    {
        return Err("Notification service busy".into());
    }
    let app = app.clone();
    let id = id.to_owned();
    let body = body.to_owned();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                WAITING.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _guard = Guard;
        let mut notification = notify_rust::Notification::new();
        notification.summary("elo.now").body(&body).timeout(8000);
        #[cfg(target_os = "windows")]
        {
            notification.app_id(&app.config().identifier);
            // notify-rust's Windows backend supports system sounds only. A
            // missing sound produces a silent toast; custom choices use Default.
            if sound != Sound::None {
                notification.sound_name("Default");
            }
        }
        #[cfg(target_os = "linux")]
        {
            use tauri::Manager;
            notification
                .appname("elo.now")
                .action("default", "")
                .hint(notify_rust::Hint::DesktopEntry(
                    app.config().identifier.clone(),
                ))
                .hint(notify_rust::Hint::SuppressSound(sound == Sound::None));
            if let Some(file) = sound.file() {
                if let Ok(path) = app
                    .path()
                    .resolve(file, tauri::path::BaseDirectory::Resource)
                {
                    notification.hint(notify_rust::Hint::SoundFile(
                        path.to_string_lossy().into_owned(),
                    ));
                }
            }
        }
        match notification.show() {
            Ok(handle) => {
                let _ = tx.send(Ok(()));
                // Default is a body click on Windows. wait_for_action would
                // misclassify that as closed; use the typed response instead.
                let _ = handle.wait_for_response(|response: &notify_rust::NotificationResponse| {
                    if matches!(response, notify_rust::NotificationResponse::Default)
                        || matches!(response, notify_rust::NotificationResponse::Action(key) if key == "default") {
                        super::clicked(&app, &id);
                    }
                });
            }
            Err(_) => {
                let _ = tx.send(Err("Notification delivery failed".to_owned()));
            }
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .map_err(|_| "Notification delivery timed out")?
        .map_err(|_| "Notification delivery failed")?
}
pub(super) fn clear(_ids: Vec<String>) {}

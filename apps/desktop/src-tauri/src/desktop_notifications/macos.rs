use super::Sound;
use mac_usernotifications::{AuthorizationStatus, Notification};
use std::time::Duration;

pub(super) fn available() -> bool {
    mac_usernotifications::check_bundle().is_ok()
}
pub(super) fn setup(_app: &tauri::AppHandle) {}
pub(super) async fn click_supported() -> bool {
    available()
}
pub(super) fn custom_sound() -> &'static str {
    "supported"
}
pub(super) async fn permission(ask: bool) -> Result<String, String> {
    if !available() {
        return Ok("unavailable".into());
    }
    if ask {
        tokio::time::timeout(
            Duration::from_secs(120),
            mac_usernotifications::request_auth(),
        )
        .await
        .map_err(|_| "Notification permission request timed out")?
        .map_err(|_| "Notification permission unavailable")?;
    }
    let settings = tokio::time::timeout(
        Duration::from_secs(5),
        mac_usernotifications::get_notification_settings(),
    )
    .await
    .map_err(|_| "Notification permission unavailable")?
    .map_err(|_| "Notification permission unavailable")?;
    Ok(match settings.authorization_status {
        AuthorizationStatus::Authorized | AuthorizationStatus::Provisional => "granted",
        AuthorizationStatus::NotDetermined => "prompt",
        _ => "denied",
    }
    .into())
}
pub(super) async fn show(
    app: &tauri::AppHandle,
    id: &str,
    body: &str,
    sound: Sound,
) -> Result<(), String> {
    let notification = Notification::new()
        .title("elo.now")
        .message(body)
        .id(&format!("elo-desktop-{id}"))
        .timeout(super::TTL)
        .maybe_sound(sound.file());
    // UserNotifications owns presentation, sound settings and Focus. No media
    // player fallback: it would bypass a deliberately quiet system setting.
    let handle = tokio::time::timeout(Duration::from_secs(5), notification.send())
        .await
        .map_err(|_| "Notification delivery timed out")?
        .map_err(|_| "Notification delivery failed")?;
    let app = app.clone();
    let id = id.to_owned();
    tauri::async_runtime::spawn(async move {
        if let Ok(response) = handle.response().await
            && response.is_default_action()
        {
            super::clicked(&app, &id);
        }
    });
    Ok(())
}
pub(super) fn clear(ids: Vec<String>) {
    if !available() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        // Capture exact ids before disabling; an asynchronous cleanup must not
        // remove a newer alert after a subsequent explicit opt-in.
        for id in ids {
            let id = format!("elo-desktop-{id}");
            mac_usernotifications::close_delivered(&id).await;
            mac_usernotifications::cancel_pending(&id).await;
        }
    });
}

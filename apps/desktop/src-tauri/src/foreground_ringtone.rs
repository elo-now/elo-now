//! Short foreground-only audio leases. No microphone, routing or call admission.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

static EPOCH: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    token: String,
    revision: u64,
    active: bool,
    expires: u64,
}

impl Request {
    fn valid(&self) -> bool {
        self.token.len() == 36
            && self.token.bytes().enumerate().all(|(index, value)| {
                if [8, 13, 18, 23].contains(&index) {
                    value == b'-'
                } else {
                    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
                }
            })
            && self.revision <= 9_007_199_254_740_991
            && self.expires <= 9_007_199_254_740_991
    }
}

#[cfg(all(mobile, feature = "mobile-push"))]
async fn send(app: &tauri::AppHandle, request: serde_json::Value) -> Result<(), String> {
    use tauri::Manager;
    let app = app.clone();
    // A timeout cannot cancel a queued native callback. Native epoch checks and
    // token tombstones reject that callback after shutdown or cancellation.
    let delivery = tauri::async_runtime::spawn_blocking(move || {
        app.state::<tauri_plugin_elo_push::Push<tauri::Wry>>().call(
            "foregroundRingtone",
            serde_json::json!({"payload": request.to_string()}),
        )
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), delivery)
        .await
        .map_err(|_| "unavailable".to_owned())?
        .map_err(|_| "unavailable".to_owned())??;
    Ok(())
}

#[tauri::command]
pub(crate) async fn native_call_ringtone(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::State>,
    identity: String,
    request: Request,
) -> Result<(), String> {
    if !request.valid() {
        return Err("invalid".into());
    }
    let epoch = EPOCH.load(Ordering::Acquire);
    // Cancellation works after locking. Never hold the profile mutex during a
    // native callback. The native generation fences delivery across logout.
    if request.active {
        let runtime = state.lock().await;
        if runtime
            .client
            .as_ref()
            .is_none_or(|client| client.identity_id().to_string() != identity)
        {
            return Err("unauthorized".into());
        }
    }
    if request.active && EPOCH.load(Ordering::Acquire) != epoch {
        return Ok(());
    }
    #[cfg(all(mobile, feature = "mobile-push"))]
    let result = {
        let mut payload = serde_json::to_value(&request).map_err(|_| "invalid")?;
        payload["epoch"] = epoch.into();
        let result = send(&app, payload.clone()).await;
        if result.is_err() && request.active {
            payload["active"] = false.into();
            // Retire even a token whose start has not arrived yet. No delivery
            // mutex: cancellation must not wait behind a stalled native call.
            let _ = send(&app, payload).await;
        }
        result
    };
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    let result = {
        let _ = app;
        Ok(())
    };
    result
}

pub(crate) async fn shutdown(app: &tauri::AppHandle) {
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    #[cfg(all(mobile, feature = "mobile-push"))]
    let _ = send(app, serde_json::json!({"stopAll": true, "epoch": epoch})).await;
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    let _ = (app, epoch);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ringtone_requests_are_bounded_and_cannot_inject_native_operations() {
        let valid = serde_json::json!({"token":"00112233-4455-6677-8899-aabbccddeeff","revision":1,"active":true,"expires":1234});
        assert!(
            serde_json::from_value::<Request>(valid.clone())
                .unwrap()
                .valid()
        );
        let mut injected = valid.clone();
        injected["stopAll"] = true.into();
        assert!(serde_json::from_value::<Request>(injected).is_err());
        let mut injected = valid.clone();
        injected["epoch"] = 500.into();
        assert!(serde_json::from_value::<Request>(injected).is_err());
        for token in [
            "",
            "00112233/4455-6677-8899-aabbccddeeff",
            "00112233-4455-6677-8899-aabbccddeefg",
        ] {
            let mut value = valid.clone();
            value["token"] = token.into();
            assert!(!serde_json::from_value::<Request>(value).unwrap().valid());
        }
    }
}

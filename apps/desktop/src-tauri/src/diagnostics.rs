//! Beta diagnostics: no payloads, identities, URLs or arbitrary error strings.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};
use tauri::Manager;

static SENDER: OnceLock<mpsc::SyncSender<Value>> = OnceLock::new();
static POLICY: Mutex<Option<Policy>> = Mutex::new(None);
const SUPPORTED: bool = cfg!(all(
    feature = "beta-diagnostics",
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    )
));

#[derive(Serialize, Deserialize)]
struct Choice {
    enabled: bool,
    installation: String,
}
struct Policy {
    choice: Choice,
    path: std::path::PathBuf,
    recent: Vec<(String, Instant)>,
}

fn send(value: Value) {
    if let Some(sender) = SENDER.get() {
        let _ = sender.try_send(value);
    }
}

pub fn setup(app: &tauri::AppHandle) {
    if !SUPPORTED {
        return;
    }
    let Ok(directory) = app.path().app_config_dir() else {
        return;
    };
    let path = directory.join("beta-diagnostics.json");
    let choice = std::fs::read(&path)
        .ok()
        .filter(|b| b.len() < 1024)
        .and_then(|b| serde_json::from_slice::<Choice>(&b).ok())
        .filter(|c| {
            c.installation.len() == 32 && c.installation.bytes().all(|b| b.is_ascii_hexdigit())
        })
        .unwrap_or_else(|| {
            let mut bytes = [0_u8; 16];
            let _ = getrandom::fill(&mut bytes);
            let enabled = false;
            Choice {
                enabled,
                installation: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            }
        });
    if std::fs::create_dir_all(directory).is_err() {
        return;
    }
    let Ok(bytes) = serde_json::to_vec(&choice) else {
        return;
    };
    if std::fs::write(&path, bytes).is_err() {
        return;
    }
    let (sender, receiver) = mpsc::sync_channel::<Value>(64);
    if SENDER.set(sender).is_err() {
        return;
    }
    let app = app.clone();
    let initial =
        json!({"op":"configure","enabled":choice.enabled,"installation":choice.installation});
    let _ = std::thread::Builder::new()
        .name("elo-diagnostics".into())
        .spawn(move || {
            native(&app, initial);
            for event in receiver {
                native(&app, event);
            }
        });
    if let Ok(mut guard) = POLICY.lock() {
        *guard = Some(Policy {
            choice,
            path,
            recent: Vec::new(),
        });
    }
    event("event", "runtime", "started", None);
}

fn native(app: &tauri::AppHandle, value: Value) {
    #[cfg(all(mobile, feature = "mobile-push"))]
    if let Some(push) = app.try_state::<tauri_plugin_elo_push::Push<tauri::Wry>>() {
        let _ = push.call("diagnostics", json!({"payload":value.to_string()}));
    }
    #[cfg(all(target_os = "macos", feature = "beta-diagnostics"))]
    elo_diagnostics_macos::command(&value.to_string());
    let _ = (app, value);
}

fn allowed(source: &str, code: &str) -> bool {
    if code.len() > 100
        || !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return false;
    }
    match source {
        "ui" => include_str!("../../src/locales/en.ts").contains(&format!("\"{code}\":")),
        "call" => matches!(code, "idle" | "connecting" | "connected" | "reconnecting"),
        "core" => super::application_operation(code),
        "ipc" => include_str!("../build.rs").contains(&format!("\"{code}\",")),
        "runtime" => matches!(
            code,
            "started" | "javascript_error" | "unhandled_rejection" | "react_error"
        ),
        "test" => code == "diagnostics_test",
        "session" => [
            include_str!("native_session.rs"),
            include_str!("native_session/group.rs"),
            include_str!("native_media.rs"),
        ]
        .iter()
        .any(|s| s.contains(&format!("c\"{code}\""))),
        "media" => matches!(
            code,
            "system_call_start"
                | "group_start"
                | "group_update"
                | "group_reset"
                | "start"
                | "update"
                | "stop"
                | "poll"
                | "signal"
                | "timeout"
                | "native_failure"
        ),
        _ => false,
    }
}

pub fn event(kind: &str, source: &str, code: &str, elapsed_ms: Option<u64>) {
    if !matches!(kind, "error" | "event") || !allowed(source, code) {
        return;
    }
    let Ok(mut guard) = POLICY.lock() else {
        return;
    };
    let Some(policy) = guard.as_mut() else {
        return;
    };
    if !policy.choice.enabled {
        return;
    }
    let now = Instant::now();
    policy
        .recent
        .retain(|(_, at)| now.duration_since(*at) < Duration::from_secs(10));
    let key = format!("{kind}.{source}.{code}");
    if policy.recent.len() >= 64 || policy.recent.iter().any(|(k, _)| k == &key) {
        return;
    }
    policy.recent.push((key, now));
    send(
        json!({"kind":kind,"source":source,"code":code,"elapsed_ms":elapsed_ms.map(|ms|ms.min(600_000))}),
    );
}

#[tauri::command]
pub async fn diagnostic_task(request: Value) -> Result<Value, String> {
    match request["op"].as_str() {
        Some("event") => {
            event(
                request["kind"].as_str().unwrap_or(""),
                request["source"].as_str().unwrap_or(""),
                request["code"].as_str().unwrap_or(""),
                request["elapsed_ms"].as_u64(),
            );
            Ok(Value::Null)
        }
        Some("status") | Some("set") => {
            let mut guard = POLICY.lock().map_err(|_| "Diagnostics unavailable")?;
            let Some(policy) = guard.as_mut() else {
                return Ok(json!({"available":false,"enabled":false}));
            };
            if request["op"] == "set" {
                let enabled = request["enabled"]
                    .as_bool()
                    .ok_or("Invalid diagnostics setting")?;
                let choice = Choice {
                    enabled,
                    installation: policy.choice.installation.clone(),
                };
                let bytes = serde_json::to_vec(&choice).map_err(|_| "Diagnostics unavailable")?;
                std::fs::write(&policy.path, bytes).map_err(|_| "Diagnostics unavailable")?;
                policy.choice = choice;
                if let Some(sender) = SENDER.get() {
                    sender.send(json!({"op":"configure","enabled":enabled,"installation":policy.choice.installation}))
                        .map_err(|_| "Diagnostics unavailable")?;
                }
            }
            Ok(
                json!({"available":SUPPORTED,"enabled":policy.choice.enabled,"installation":policy.choice.installation}),
            )
        }
        _ => Err("Invalid diagnostics operation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payloads_and_unknown_labels_never_leave_the_process() {
        for secret in [
            "https://host/invite#token",
            "age-secret-key",
            "Marek",
            "password=secret",
            "error.generic\nsecret",
        ] {
            assert!(!allowed("ui", secret));
            assert!(!allowed("media", secret));
            assert!(!allowed("core", secret));
        }
        assert!(!allowed("unknown", "error.generic"));
        assert!(allowed("ui", "error.generic"));
        assert!(allowed("core", "space_join"));
        assert!(allowed("session", "group:before_group_start"));
    }
}

//! Recovery codes use native clipboard expiry, never a renderer clipboard reader.
use tauri::Manager;
use zeroize::Zeroizing;

const FAILED: &str = "Could not copy the recovery code.";

#[cfg(desktop)]
#[derive(Default)]
pub struct ClipboardState(std::sync::Mutex<Option<(arboard::Clipboard, u64)>>);

#[cfg(target_os = "android")]
struct MobileClipboard(tauri::plugin::PluginHandle<tauri::Wry>);

#[cfg(target_os = "android")]
pub fn init() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("elo-recovery-clipboard")
        .setup(|app, api| {
            app.manage(MobileClipboard(
                api.register_android_plugin("now.elo", "RecoveryClipboardPlugin")?,
            ));
            Ok(())
        })
        .build()
}

#[tauri::command]
pub async fn copy_recovery_code(app: tauri::AppHandle, text: String) -> Result<(), String> {
    let text = Zeroizing::new(text);
    if text.is_empty() || text.len() > 2048 || text.contains('\0') {
        return Err(FAILED.into());
    }
    #[cfg(target_os = "android")]
    {
        app.state::<MobileClipboard>()
            .0
            .run_mobile_plugin::<serde_json::Value>(
                "copyRecoveryCode",
                serde_json::json!({"text": text.as_str()}),
            )
            .map_err(|_| FAILED.to_owned())?;
    }
    #[cfg(target_os = "ios")]
    {
        app.state::<tauri_plugin_elo_privacy::Privacy>()
            .call(
                "copyRecoveryCode",
                serde_json::json!({"text": text.as_str()}),
            )
            .map_err(|_| FAILED.to_owned())?;
    }
    #[cfg(desktop)]
    {
        let owner = app.clone();
        let fingerprint = elo_core::ids::ObjectId::of_ciphertext(text.as_bytes());
        let generation = tauri::async_runtime::spawn_blocking(move || {
            let state = owner.state::<ClipboardState>();
            let mut slot = state.0.lock().map_err(|_| FAILED)?;
            if slot.is_none() {
                *slot = Some((arboard::Clipboard::new().map_err(|_| FAILED)?, 0));
            }
            let (clipboard, generation) = slot.as_mut().unwrap();
            #[cfg(target_os = "macos")]
            use arboard::SetExtApple;
            #[cfg(target_os = "linux")]
            use arboard::SetExtLinux;
            #[cfg(target_os = "windows")]
            use arboard::SetExtWindows;
            #[cfg(target_os = "windows")]
            let set = clipboard.set().exclude_from_monitoring();
            #[cfg(not(target_os = "windows"))]
            let set = clipboard.set().exclude_from_history();
            set.text(text.as_str()).map_err(|_| FAILED)?;
            *generation = generation.wrapping_add(1);
            Ok::<_, &'static str>(*generation)
        })
        .await
        .map_err(|_| FAILED.to_owned())?
        .map_err(str::to_owned)?;
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let state = app.state::<ClipboardState>();
                let Ok(mut slot) = state.0.lock() else {
                    return;
                };
                let Some((clipboard, current)) = slot.as_mut() else {
                    return;
                };
                if *current != generation {
                    return;
                }
                if let Ok(value) = clipboard.get_text() {
                    let value = Zeroizing::new(value);
                    // Do not erase a different item copied by the user later.
                    if elo_core::ids::ObjectId::of_ciphertext(value.as_bytes()) == fingerprint {
                        let _ = clipboard.clear();
                    }
                }
            })
            .await;
        });
    }
    Ok(())
}

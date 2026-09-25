//! Native, profile-scoped management recovery. Paths never cross the bridge.
use crate::State;
use elo_core::app::control_recovery::MAX_CONTROL_PACKAGE;
use serde_json::{Value, json};
use std::io::Read;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_fs::{FsExt, OpenOptions};
use zeroize::Zeroizing;

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .ok_or_else(|| "Invalid management recovery request.".into())
}
async fn export(app: &tauri::AppHandle, value: Value) -> Result<Value, String> {
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_CONTROL_PACKAGE {
        return Err("Management recovery file is too large.".into());
    }
    if cfg!(target_os = "ios") {
        let path = crate::exchange::new_path(app, "elo-control")?;
        elo_core::vault::write_private(&path, &bytes, false).map_err(|e| e.to_string())?;
        crate::exchange::share_generated_file(
            app,
            path,
            "application/octet-stream",
            "elo-management.elo-control",
        )?;
        Ok(json!({"saved":true}))
    } else {
        Ok(
            json!({"saved":crate::profiles::save(app, &bytes, "elo-management.elo-control").await.map_err(|e|e.to_string())?}),
        )
    }
}

#[tauri::command]
pub async fn control_task(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    mut request: Value,
) -> Result<Value, String> {
    let runtime = &*state;
    let mut state = runtime.lock().await;
    if state.client.is_none() {
        return Err("The profile is locked".into());
    }
    match text(&request, "op")? {
        "cancel" => {
            state.control_recovery = None;
            Ok(json!({}))
        }
        "request" => Ok(
            json!({"code":state.client.as_ref().unwrap().control_recovery_request(),"device":state.client.as_ref().unwrap().control_recovery_device()}),
        ),
        "choices" => state
            .client
            .as_ref()
            .unwrap()
            .control_recovery_choices(text(&request, "code")?)
            .await
            .map_err(|e| e.to_string()),
        "export" => {
            let client = state.client.as_ref().unwrap();
            let package = client
                .control_recovery_export(
                    text(&request, "code")?,
                    text(&request, "space")?
                        .parse()
                        .map_err(|_| "Invalid Space.")?,
                    text(&request, "stream")?
                        .parse()
                        .map_err(|_| "Invalid chat.")?,
                    text(&request, "device")?
                        .parse()
                        .map_err(|_| "Invalid recovery device.")?,
                )
                .await
                .map_err(|e| e.to_string())?;
            export(&app, package).await
        }
        "preview" => {
            let picker = elo_core::record::random_hex::<32>().map_err(|e| e.to_string())?;
            let space_context = state
                .client
                .as_ref()
                .unwrap()
                .active_space_id()
                .map(str::to_owned);
            state.control_recovery = Some(json!({"picker":picker}));
            let generation = app.state::<crate::exchange::ExchangeFiles>().generation();
            drop(state);
            let (tx, rx) = tokio::sync::oneshot::channel();
            app.dialog().file().pick_file(move |file| {
                let _ = tx.send(file);
            });
            let Some(file) = rx.await.map_err(|_| "File picker closed unexpectedly")? else {
                return Ok(Value::Null);
            };
            let source = app
                .fs()
                .open(file, OpenOptions::new().read(true).clone())
                .map_err(|e| e.to_string())?;
            let mut bytes = Zeroizing::new(Vec::new());
            source
                .take(MAX_CONTROL_PACKAGE as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            let package = elo_core::app::control_recovery::parse_package(&bytes)
                .map_err(|_| "Invalid management recovery file.")?;
            let mut state = runtime.lock().await;
            if state.client.is_none()
                || app.state::<crate::exchange::ExchangeFiles>().generation() != generation
                || state.control_recovery.as_ref().map(|v| &v["picker"]) != Some(&json!(picker))
            {
                return Err("The open profile has changed".into());
            }
            state.control_recovery = None;
            if state.client.as_ref().unwrap().active_space_id() != space_context.as_deref() {
                return Err("The selected Space has changed. Try again.".into());
            }
            let preview = state
                .client
                .as_mut()
                .unwrap()
                .control_recovery_preview(&package)
                .await
                .map_err(|e| e.to_string())?;
            state.control_recovery =
                Some(json!({"package":package,"preview":preview,"space_context":space_context}));
            Ok(preview)
        }
        "confirm" => {
            crate::release_policy::require_online(&app)?;
            let pending = state
                .control_recovery
                .as_ref()
                .ok_or("Review a recovery file first.")?
                .clone();
            if !pending["preview"].is_object()
                || request["package_id"] != pending["preview"]["package_id"]
                || request["confirmed"] != true
            {
                return Err("Review the members and confirm recovery first.".into());
            }
            if pending["space_context"] != json!(state.client.as_ref().unwrap().active_space_id()) {
                return Err("The selected Space has changed. Try again.".into());
            }
            let password = match request["password"].take() {
                Value::String(password) if password.len() <= 1024 => Zeroizing::new(password),
                _ => return Err("Invalid password.".into()),
            };
            let client = state.client.as_mut().unwrap();
            if !client.password_matches(&password.as_str().into()) {
                return Err("The password is incorrect".into());
            }
            let words = match request["words"].take() {
                Value::String(words) if words.len() <= 2048 => Zeroizing::new(words),
                _ => Zeroizing::new(String::new()),
            };
            let mut confirmation = pending["preview"].clone();
            confirmation["confirmed"] = true.into();
            let result = client
                .control_recovery_confirm(&pending["package"], &confirmation, &words)
                .await
                .map_err(|e| e.to_string())?;
            state.control_recovery = None;
            state.view_revision = state.view_revision.wrapping_add(1);
            Ok(result)
        }
        "share" => {
            let package = state
                .client
                .as_ref()
                .unwrap()
                .control_recovery_share(
                    text(&request, "space")?
                        .parse()
                        .map_err(|_| "Invalid Space.")?,
                    text(&request, "stream")?
                        .parse()
                        .map_err(|_| "Invalid chat.")?,
                )
                .map_err(|e| e.to_string())?;
            export(&app, package).await
        }
        _ => Err("Invalid management recovery request.".into()),
    }
}

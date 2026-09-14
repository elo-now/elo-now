//! File exchange is scoped to explicit native dialogs and an app-owned private
//! staging directory. No generic filesystem permission is granted to JavaScript.
use crate::State;
use std::{
    io::{Read, Write},
    path::PathBuf,
};
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_fs::{FsExt, OpenOptions};
use zeroize::Zeroizing;
const MAX_EXCHANGE: usize = 12 * 1024 * 1024;
#[tauri::command]
pub async fn invitation_qr(
    state: tauri::State<'_, State>,
    link: String,
) -> Result<Vec<String>, String> {
    if state.lock().await.client.is_none() {
        return Err("The profile is locked".into());
    }
    if !(link.starts_with("elo://exchange/v1#")
        || link.starts_with(elo_core::app::space_service::PREFIX))
        || !link.is_ascii()
        || link.len() > 64 * 1024
    {
        return Err("This response is too large for QR. Use Share instead.".into());
    }
    // Frames are a transport container only. The Rust core verifies the complete
    // signed exchange after reassembly; a frame identifier never grants trust.
    let id = elo_core::ids::RecordId::of_record_bytes(link.as_bytes()).to_string();
    let parts = link.as_bytes().chunks(900).collect::<Vec<_>>();
    let contents = if link.len() <= 1800 {
        vec![link]
    } else {
        parts
            .iter()
            .enumerate()
            .map(|(index, part)| {
                format!(
                    "eloqr:1:{}:{index}:{}:{}",
                    &id[..16],
                    parts.len(),
                    std::str::from_utf8(part).unwrap_or_default()
                )
            })
            .collect()
    };
    uniform_qr_codes(&contents)?
        .into_iter()
        .map(|qr| {
            Ok(qr
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(512, 512)
                .build())
        })
        .collect()
}

fn uniform_qr_codes(contents: &[String]) -> Result<Vec<qrcode::QrCode>, String> {
    let codes = contents
        .iter()
        .map(|text| qrcode::QrCode::new(text.as_bytes()).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let Some(version) = codes
        .iter()
        .max_by_key(|code| code.width())
        .map(|code| code.version())
    else {
        return Ok(codes);
    };
    // Keep the same module grid and quiet zone throughout the sequence,
    // including the shorter final part. Encoding mode also affects capacity.
    codes
        .into_iter()
        .zip(contents)
        .map(|(code, text)| {
            if code.version() == version {
                Ok(code)
            } else {
                qrcode::QrCode::with_version(text.as_bytes(), version, qrcode::EcLevel::M)
                    .map_err(|e| e.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn qr_sequence_keeps_one_grid_for_different_lengths_and_encoding_modes() {
        let contents = vec![
            "aZ9_-".repeat(180),
            "7".repeat(1100),
            "short final part".into(),
        ];
        let codes = super::uniform_qr_codes(&contents).unwrap();
        let largest_width = contents
            .iter()
            .map(|text| qrcode::QrCode::new(text).unwrap().width())
            .max()
            .unwrap();
        assert_eq!(codes.len(), contents.len());
        assert!(codes.iter().all(|code| code.width() == largest_width));
        assert!(
            codes
                .iter()
                .all(|code| code.error_correction_level() == qrcode::EcLevel::M)
        );
        // A standalone code still uses the smallest grid that fits its data.
        let single = super::uniform_qr_codes(&contents[2..]).unwrap();
        assert_eq!(
            single[0].width(),
            qrcode::QrCode::new(&contents[2]).unwrap().width()
        );
    }
}
fn directory(app: &tauri::AppHandle) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let base = app.path().app_cache_dir()?;
    std::fs::create_dir_all(&base)?;
    let dir = base.join("elo-exchange-v1");
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("Unsafe exchange directory".into());
        }
    } else {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir)?;
    }
    Ok(dir)
}
pub fn clear(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for item in std::fs::read_dir(directory(app)?)? {
        let item = item?;
        // Only files created by this module; never recurse into other folders.
        if item.file_name().to_string_lossy().starts_with("elo-") && !item.file_type()?.is_dir() {
            std::fs::remove_file(item.path())?;
        }
    }
    Ok(())
}
pub(crate) fn new_path(app: &tauri::AppHandle, extension: &str) -> Result<PathBuf, String> {
    Ok(directory(app).map_err(|e| e.to_string())?.join(format!(
        "elo-{}.{}",
        elo_core::record::random_hex::<16>().map_err(|e| e.to_string())?,
        extension
    )))
}

/// Called only with a private file generated by the native recovery operations.
/// JavaScript receives no path and no generic share-file capability.
pub(crate) fn share_generated_file(
    app: &tauri::AppHandle,
    path: PathBuf,
    mime_type: &str,
    title: &str,
) -> Result<(), String> {
    #[cfg(mobile)]
    {
        use tauri_plugin_sharekit::ShareExt;
        let window = app
            .get_webview_window("main")
            .ok_or("The app window is unavailable")?;
        let url = tauri::Url::from_file_path(path).map_err(|_| "Invalid export file")?;
        app.share()
            .share_file(
                window,
                url.into(),
                tauri_plugin_sharekit::ShareFileOptions {
                    mime_type: Some(mime_type.into()),
                    title: Some(title.into()),
                    position: None,
                },
            )
            .map_err(|e| e.to_string())
    }
    #[cfg(not(mobile))]
    {
        let _ = (app, path, mime_type, title);
        Err("Use the desktop save dialog".into())
    }
}
#[tauri::command]
pub async fn choose_import(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
) -> Result<Option<String>, String> {
    if state.lock().await.client.is_none() {
        return Err("The profile is locked".into());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog().file().pick_file(move |file| {
        let _ = tx.send(file);
    });
    let Some(file) = rx.await.map_err(|_| "File picker closed unexpectedly")? else {
        return Ok(None);
    };
    let guard = state.lock().await;
    if guard.client.is_none() {
        return Err("The profile is locked".into());
    }
    let source = app
        .fs()
        .open(file, OpenOptions::new().read(true).clone())
        .map_err(|e| e.to_string())?;
    let mut bytes = Zeroizing::new(Vec::new());
    source
        .take(MAX_EXCHANGE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_EXCHANGE {
        return Err("Exchange files must not exceed 12 MiB".into());
    }
    let path = new_path(&app, "import")?;
    elo_core::vault::write_private(&path, &bytes, false).map_err(|e| e.to_string())?;
    Ok(Some(path.to_string_lossy().into_owned()))
}
#[tauri::command]
pub async fn prepare_export(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    kind: String,
) -> Result<String, String> {
    if state.lock().await.client.is_none() {
        return Err("The profile is locked".into());
    }
    let extension = match kind.as_str() {
        "invite_create" | "invite_request" | "history_request" | "device_export" => "json",
        "invite_approve" | "export_config" | "history_preview" | "recovery_export" => "age",
        "file_download" => "bin",
        _ => return Err("This operation does not export a file".into()),
    };
    Ok(new_path(&app, extension)?.to_string_lossy().into_owned())
}
#[tauri::command]
pub async fn save_export(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    path: String,
) -> Result<bool, String> {
    let guard = state.lock().await;
    if guard.client.is_none() {
        return Err("The profile is locked".into());
    }
    let path = PathBuf::from(path);
    let base = directory(&app).map_err(|e| e.to_string())?;
    if path.parent() != Some(base.as_path())
        || !path
            .file_name()
            .is_some_and(|s| s.to_string_lossy().starts_with("elo-"))
    {
        return Err("Only an app-created exchange file may be exported".into());
    }
    let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_EXCHANGE as u64 {
        return Err("Invalid export file".into());
    }
    let bytes = Zeroizing::new(std::fs::read(&path).map_err(|e| e.to_string())?);
    let name = path
        .file_name()
        .ok_or("Invalid export name")?
        .to_string_lossy()
        .into_owned();
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(name)
        .save_file(move |file| {
            let _ = tx.send(file);
        });
    let Some(file) = rx.await.map_err(|_| "File picker closed unexpectedly")? else {
        return Ok(false);
    };
    let mut destination = app
        .fs()
        .open(
            file,
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .clone(),
        )
        .map_err(|e| e.to_string())?;
    destination.write_all(&bytes).map_err(|e| e.to_string())?;
    destination.sync_all().map_err(|e| e.to_string())?;
    // Keep the private source until lock, including after uncertain provider writes.
    Ok(true)
}

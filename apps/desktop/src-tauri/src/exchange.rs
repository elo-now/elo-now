//! File exchange is scoped to explicit native dialogs and an app-owned private
//! staging directory. No generic filesystem permission is granted to JavaScript.
use crate::State;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_fs::{FsExt, OpenOptions};
use zeroize::Zeroizing;
const MAX_EXCHANGE: usize = 12 * 1024 * 1024;
const MAX_ATTACHMENT: usize = 5 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Upload,
    Download,
}
#[derive(Default)]
pub(crate) struct ExchangeFiles(Mutex<BTreeMap<String, (PathBuf, Purpose)>>, AtomicU64);
impl ExchangeFiles {
    pub(crate) fn generation(&self) -> u64 {
        self.1.load(Ordering::SeqCst)
    }
    fn reset(&self) -> Result<(), String> {
        let mut files = self.0.lock().map_err(|_| "Exchange is unavailable")?;
        files.clear();
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn issue(&self, path: PathBuf, purpose: Purpose) -> Result<String, String> {
        let mut files = self.0.lock().map_err(|_| "Exchange is unavailable")?;
        if files.len() >= 128 {
            return Err("Too many pending exchange files".into());
        }
        let handle = elo_core::record::random_hex::<32>().map_err(|e| e.to_string())?;
        files.insert(handle.clone(), (path, purpose));
        Ok(handle)
    }
    fn resolve(&self, handle: &str, purpose: Purpose) -> Result<PathBuf, String> {
        self.0
            .lock()
            .map_err(|_| "Exchange is unavailable")?
            .get(handle)
            .filter(|(_, allowed)| *allowed == purpose)
            .map(|(path, _)| path.clone())
            .ok_or_else(|| "Invalid exchange handle".into())
    }
}

// Renderer values are capabilities issued by native pickers, never filesystem paths.
pub(crate) fn resolve_transfer(
    app: &tauri::AppHandle,
    request: &mut serde_json::Value,
) -> Result<(), String> {
    let (field, purpose) = match request["op"].as_str() {
        Some("attachment_upload") => ("path", Purpose::Upload),
        Some("attachment_download") => ("output", Purpose::Download),
        _ => return Err("Unsupported attachment transfer".into()),
    };
    let handle = request[field].as_str().ok_or("Invalid exchange handle")?;
    let path = app.state::<ExchangeFiles>().resolve(handle, purpose)?;
    if purpose == Purpose::Upload {
        validate_file(&path)?;
    }
    request[field] = serde_json::json!(path);
    Ok(())
}
fn validate_file(path: &std::path::Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_EXCHANGE as u64 {
        return Err("Invalid exchange file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err("Invalid exchange file".into());
        }
    }
    Ok(())
}

fn attachment_name(name: &str) -> String {
    let name = name.trim().chars().take(255).collect::<String>();
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.chars().any(|character| {
            elo_core::record::unsafe_display_character(character) || matches!(character, '/' | '\\')
        })
    {
        "attachment.bin".to_owned()
    } else {
        name
    }
}

fn selected_attachment_name(
    file: &tauri_plugin_fs::FilePath,
    display_name: Option<&str>,
) -> String {
    if let Some(name) = display_name.filter(|name| !name.trim().is_empty()) {
        return attachment_name(name);
    }
    // Only file URLs have path names. Content-provider IDs are not filenames.
    let path = file.clone().into_path().ok();
    attachment_name(
        path.as_deref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("attachment.bin"),
    )
}
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
    fn opaque_handles_reject_paths_wrong_purpose_and_old_sessions() {
        let files = super::ExchangeFiles::default();
        let path = std::path::PathBuf::from("/tmp/native-selected-file");
        let handle = files.issue(path.clone(), super::Purpose::Upload).unwrap();
        assert_ne!(handle, path.to_string_lossy());
        assert_eq!(
            files.resolve(&handle, super::Purpose::Upload).unwrap(),
            path
        );
        assert!(
            files
                .resolve("/etc/passwd", super::Purpose::Upload)
                .is_err()
        );
        assert!(files.resolve(&handle, super::Purpose::Download).is_err());
        let generation = files.generation();
        files.reset().unwrap();
        assert_ne!(files.generation(), generation);
        assert!(files.resolve(&handle, super::Purpose::Upload).is_err());
    }
    #[test]
    fn misleading_filename_direction_controls_are_rejected() {
        assert_eq!(
            super::attachment_name("report\u{202e}fdp.exe"),
            "attachment.bin"
        );
        assert_eq!(
            super::attachment_name("report\u{200b}.pdf"),
            "attachment.bin"
        );
    }
    #[test]
    fn selected_attachment_uses_provider_name_not_document_id() {
        let document = "content://com.android.providers.downloads.documents/document/75"
            .parse()
            .unwrap();
        assert_eq!(
            super::selected_attachment_name(&document, Some("Redmi attachment test.txt")),
            "Redmi attachment test.txt"
        );
        assert_eq!(
            super::selected_attachment_name(&document, None),
            "attachment.bin"
        );
        assert_eq!(
            super::selected_attachment_name(&document, Some("../secret")),
            "attachment.bin"
        );
        let local = "file:///private/tmp/My%20photo.jpg".parse().unwrap();
        assert_eq!(
            super::selected_attachment_name(&local, None),
            "My photo.jpg"
        );
        let path = tauri_plugin_fs::FilePath::Path("/tmp/report.pdf".into());
        assert_eq!(super::selected_attachment_name(&path, None), "report.pdf");
    }

    #[test]
    fn attachment_names_are_bounded_and_cannot_escape_staging() {
        assert_eq!(super::attachment_name(" holiday.mov "), "holiday.mov");
        assert_eq!(super::attachment_name("../secret"), "attachment.bin");
        assert_eq!(super::attachment_name(""), "attachment.bin");
        assert_eq!(super::attachment_name(&"a".repeat(300)).len(), 255);
    }

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
    app.state::<ExchangeFiles>().reset()?;
    for item in std::fs::read_dir(directory(app)?)? {
        let item = item?;
        // Only files created by this module; never recurse into other folders.
        if item.file_name().to_string_lossy().starts_with("elo-") && !item.file_type()?.is_dir() {
            std::fs::remove_file(item.path())?;
        }
    }
    Ok(())
}
pub(crate) fn clear_disconnected(
    app: &tauri::AppHandle,
    connected: &[String],
) -> Result<(), String> {
    for item in
        std::fs::read_dir(directory(app).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?
    {
        let item = item.map_err(|e| e.to_string())?;
        let name = item.file_name();
        let name = name.to_string_lossy();
        if let Some(space) = name
            .strip_prefix("elo-space-")
            .and_then(|s| s.split('-').next())
            && space.parse::<elo_core::ids::RecordId>().is_ok()
            && !connected.iter().any(|id| id == space)
            && !item.file_type().map_err(|e| e.to_string())?.is_dir()
        {
            std::fs::remove_file(item.path()).map_err(|e| e.to_string())?;
            app.state::<ExchangeFiles>()
                .0
                .lock()
                .map_err(|_| "Exchange is unavailable")?
                .retain(|_, (path, _)| *path != item.path());
        }
    }
    Ok(())
}
pub(crate) fn new_path(app: &tauri::AppHandle, extension: &str) -> Result<PathBuf, String> {
    if app
        .state::<ExchangeFiles>()
        .0
        .lock()
        .map_err(|_| "Exchange is unavailable")?
        .len()
        >= 128
    {
        return Err("Too many pending exchange files".into());
    }
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
pub async fn choose_attachment(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
) -> Result<Option<serde_json::Value>, String> {
    let generation = {
        let guard = state.lock().await;
        if guard.client.is_none() {
            return Err("The profile is locked".into());
        }
        app.state::<ExchangeFiles>().generation()
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog().file().pick_file(move |file| {
        let _ = tx.send(file);
    });
    let Some(file) = rx.await.map_err(|_| "File picker closed unexpectedly")? else {
        return Ok(None);
    };
    // A native dialog may outlive logout or a profile change.
    let guard = state.lock().await;
    if guard.client.is_none() || app.state::<ExchangeFiles>().generation() != generation {
        return Err("The profile is locked".into());
    }
    #[cfg(target_os = "android")]
    let display_name = crate::android_files::display_name(&app, &file);
    #[cfg(not(target_os = "android"))]
    let display_name: Option<String> = None;
    let name = selected_attachment_name(&file, display_name.as_deref());
    let mut source = app
        .fs()
        .open(file, OpenOptions::new().read(true).clone())
        .map_err(|e| e.to_string())?;
    let path = new_path(&app, "attachment")?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&path).map_err(|e| e.to_string())?;
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut size = 0usize;
    loop {
        let read = source.read(&mut buffer).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read).ok_or("Attachment is too large")?;
        if size > MAX_ATTACHMENT {
            drop(output);
            let _ = std::fs::remove_file(&path);
            return Err("Attachment files cannot exceed 5 MB.".into());
        }
        output
            .write_all(&buffer[..read])
            .map_err(|e| e.to_string())?;
    }
    output.sync_all().map_err(|e| e.to_string())?;
    Ok(Some(serde_json::json!({
        "path": app.state::<ExchangeFiles>().issue(path, Purpose::Upload)?,
        "name": name,
        "size_bytes": size,
    })))
}

#[tauri::command]
pub async fn stage_attachment(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    name: String,
    data: String,
) -> Result<serde_json::Value, String> {
    let guard = state.lock().await;
    if guard.client.is_none() {
        return Err("The profile is locked".into());
    }
    // Reject oversized input before decoding so the WebView cannot use this
    // narrow command as an unbounded allocation path.
    let maximum_encoded = MAX_ATTACHMENT.div_ceil(3) * 4;
    if data.len() > maximum_encoded || !data.is_ascii() {
        return Err("Attachment files cannot exceed 5 MB.".into());
    }
    let bytes = Zeroizing::new(
        STANDARD
            .decode(data)
            .map_err(|_| "Could not safely open this attachment.")?,
    );
    if bytes.len() > MAX_ATTACHMENT {
        return Err("Attachment files cannot exceed 5 MB.".into());
    }
    let path = new_path(&app, "attachment")?;
    elo_core::vault::write_private(&path, &bytes, false).map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "path": app.state::<ExchangeFiles>().issue(path, Purpose::Upload)?,
        "name": attachment_name(&name),
        "size_bytes": bytes.len(),
    }))
}

#[tauri::command]
pub async fn discard_exchange(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    path: String,
) -> Result<(), String> {
    if state.lock().await.client.is_none() {
        return Err("The profile is locked".into());
    }
    let Some((path, _)) = app
        .state::<ExchangeFiles>()
        .0
        .lock()
        .map_err(|_| "Exchange is unavailable")?
        .remove(&path)
    else {
        return Ok(());
    };
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}
#[tauri::command]
pub async fn prepare_export(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    kind: String,
) -> Result<String, String> {
    let guard = state.lock().await;
    let client = guard.client.as_ref().ok_or("The profile is locked")?;
    let extension = match kind.as_str() {
        "file_download" => "bin",
        _ => return Err("This operation does not export a file".into()),
    };
    let path = if let Some(space) = client.active_space_id() {
        directory(&app).map_err(|e| e.to_string())?.join(format!(
            "elo-space-{space}-{}.{}",
            elo_core::record::random_hex::<16>().map_err(|e| e.to_string())?,
            extension
        ))
    } else {
        new_path(&app, extension)?
    };
    app.state::<ExchangeFiles>().issue(path, Purpose::Download)
}
#[tauri::command]
pub async fn save_export(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    path: String,
    filename: Option<String>,
) -> Result<bool, String> {
    let guard = state.lock().await;
    if guard.client.is_none() {
        return Err("The profile is locked".into());
    }
    let path = app
        .state::<ExchangeFiles>()
        .resolve(&path, Purpose::Download)?;
    validate_file(&path)?;
    let name = filename
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 255
                && *name != "."
                && *name != ".."
                && !name
                    .chars()
                    .any(|c| elo_core::record::unsafe_display_character(c) || c == '/' || c == '\\')
        })
        .unwrap_or_else(|| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "elo-export.bin".into())
        });
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
    let destination_path = file.clone().into_path().ok();
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
    let mut source = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    std::io::copy(&mut source, &mut destination).map_err(|e| e.to_string())?;
    destination.sync_all().map_err(|e| e.to_string())?;
    if let Some(path) = destination_path {
        crate::download_protection::mark(&path).map_err(
            |_| "Could not mark this download as untrusted. Choose another destination.",
        )?;
    }
    // Keep the private source until lock, including after uncertain provider writes.
    Ok(true)
}

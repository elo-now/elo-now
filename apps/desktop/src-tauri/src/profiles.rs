//! Scoped local profile lifecycle. Recovery reserves a new directory and never
//! overwrites an existing profile; only an explicit confirmed removal deletes one.
use crate::State;
use age::secrecy::SecretString;
use base64::{Engine, engine::general_purpose::STANDARD};
use elo_core::app::{
    ClientApp, ProfileDraft,
    pairing::{PairSource, PairTarget},
    profile_backup, recovery_qr,
};
use elo_core::{record, vault};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_fs::{FsExt, OpenOptions};
use zeroize::Zeroizing;
type Result<T> = elo_core::app::Result<T>;

fn base(app: &tauri::AppHandle) -> Result<PathBuf> {
    Ok(app.path().app_data_dir()?)
}
fn valid_name(name: &str) -> bool {
    name == "profile"
        || name.strip_prefix("profile-").is_some_and(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn index(app: &tauri::AppHandle) -> Result<Value> {
    let path = base(app)?.join("profiles.json");
    if !path.try_exists()? {
        return Ok(json!({"active":"profile","saved":["profile"]}));
    }
    let bytes = vault::read_private(&path)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    let active = value["active"]
        .as_str()
        .ok_or("Invalid profile selection")?;
    let saved = value["saved"]
        .as_array()
        .ok_or("Invalid profile selection")?;
    if !valid_name(active)
        || saved.len() > 32
        || !saved.iter().any(|v| v == active)
        || saved
            .iter()
            .any(|v| v.as_str().is_none_or(|s| !valid_name(s)))
    {
        return Err("Invalid profile selection".into());
    }
    Ok(value)
}
pub fn active(app: &tauri::AppHandle) -> Result<PathBuf> {
    Ok(base(app)?.join(
        index(app)?["active"]
            .as_str()
            .ok_or("Invalid profile selection")?,
    ))
}
pub fn saved(app: &tauri::AppHandle) -> Result<Vec<Value>> {
    let mut entries = Vec::new();
    for value in index(app)?["saved"]
        .as_array()
        .ok_or("Invalid profile selection")?
    {
        let name = value.as_str().ok_or("Invalid profile selection")?;
        let path = base(app)?.join(name);
        if !path.try_exists()? {
            continue;
        }
        let public: Value =
            serde_json::from_slice(&vault::read_private(&path.join("profile.json"))?)?;
        entries.push(
            json!({"id":name,"identity":public["identity_id"],"active":path == active(app)?}),
        );
    }
    Ok(entries)
}
fn select(app: &tauri::AppHandle, path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid profile selection")?;
    if path.parent() != Some(base(app)?.as_path()) || !valid_name(name) {
        return Err("Invalid profile selection".into());
    }
    let mut value = index(app)?;
    let list = value["saved"]
        .as_array_mut()
        .ok_or("Invalid profile selection")?;
    if !list.iter().any(|v| v == name) {
        if list.len() >= 32 {
            return Err("Remove an unused saved profile before adding another".into());
        }
        list.push(json!(name));
    }
    value["active"] = json!(name);
    vault::write_private(
        &base(app)?.join("profiles.json"),
        &serde_json::to_vec(&value)?,
        true,
    )?;
    Ok(())
}
fn new_profile(app: &tauri::AppHandle) -> Result<PathBuf> {
    if index(app)?["saved"]
        .as_array()
        .is_none_or(|list| list.len() >= 32)
    {
        return Err("Remove an unused saved profile before adding another".into());
    }
    Ok(base(app)?.join(format!("profile-{}", record::random_hex::<16>()?)))
}
// A private pointer allows the same selected archive to find its exclusively
// reserved checkpoint after process death. It contains no password or key.
fn recovery_pointer(app: &tauri::AppHandle, bytes: &[u8]) -> Result<PathBuf> {
    Ok(base(app)?.join(format!(
        "restore-{}.json",
        elo_core::ids::ObjectId::of_ciphertext(bytes)
    )))
}
fn recovery_destination(app: &tauri::AppHandle, bytes: &[u8]) -> Result<PathBuf> {
    let pointer = recovery_pointer(app, bytes)?;
    if pointer.try_exists()? {
        let name: String = serde_json::from_slice(&vault::read_private(&pointer)?)?;
        if !valid_name(&name) || name == "profile" {
            return Err("Invalid recovery checkpoint".into());
        }
        let path = base(app)?.join(name);
        if !path.exists()
            || path.join(".initializing").exists()
            || path.join("profile.json").exists()
        {
            return Ok(path);
        }
        // A process can stop after mkdir but before the first checkpoint is
        // published. Reserve a fresh destination instead of adopting/deleting
        // that unverified directory; no profile data was committed there.
    }
    let path = new_profile(app)?;
    vault::write_private(
        &pointer,
        &serde_json::to_vec(
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or("Invalid recovery path")?,
        )?,
        pointer.try_exists()?,
    )?;
    Ok(path)
}
fn check_removable(path: &Path) -> Result<()> {
    fn check_files(path: &Path, root: bool) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("Unsafe profile directory".into());
        }
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("Unexpected profile file")?;
            if root && name == "spaces" && entry.file_type()?.is_dir() {
                for child in std::fs::read_dir(entry.path())? {
                    let child = child?;
                    let id = child.file_name();
                    id.to_str()
                        .ok_or("Invalid Space directory")?
                        .parse::<elo_core::ids::SpaceId>()?;
                    check_files(&child.path(), false)?;
                }
            } else if !entry.file_type()?.is_file()
                || !(matches!(
                    name,
                    "profile.json"
                        | "vault.age"
                        | "workspace.age"
                        | "profile-details.age"
                        | "read-state.age"
                        | "invitations.age"
                        | "client.sqlite"
                        | "client.sqlite-wal"
                        | "client.sqlite-shm"
                        | "client.sqlite-journal"
                        | ".elo-client.lock"
                ) || (root && name == "spaces.age"))
            {
                return Err(
                    "This profile contains additional files. Move them before removing it".into(),
                );
            }
        }
        Ok(())
    }
    check_files(path, true)
}
fn remove_profile_files(path: &Path) -> Result<()> {
    check_removable(path)?;
    // Validate the complete tree first; only application-owned files are removed.
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            for child in std::fs::read_dir(entry.path())? {
                let child = child?;
                for file in std::fs::read_dir(child.path())? {
                    std::fs::remove_file(file?.path())?;
                }
                std::fs::remove_dir(child.path())?;
            }
            std::fs::remove_dir(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    std::fs::remove_dir(path)?;
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| "Missing profile input".into())
}
fn svg(code: &str) -> Result<String> {
    if code.len() > 4096 {
        return Err("This code is too large".into());
    }
    Ok(qrcode::QrCode::new(code)?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(768, 768)
        .build())
}
fn qr_png(code: &str) -> Result<Vec<u8>> {
    let qr = qrcode::QrCode::new(code)?;
    let width = qr.width();
    let scale = 8u32;
    let size = (width as u32 + 8) * scale;
    let mut image = image::GrayImage::from_pixel(size, size, image::Luma([255]));
    for y in 0..width {
        for x in 0..width {
            if qr[(x, y)] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        image.put_pixel(
                            (x as u32 + 4) * scale + dx,
                            (y as u32 + 4) * scale + dy,
                            image::Luma([0]),
                        );
                    }
                }
            }
        }
    }
    let mut png = std::io::Cursor::new(Vec::new());
    image.write_to(&mut png, image::ImageFormat::Png)?;
    Ok(png.into_inner())
}

fn qr_from_image(bytes: &[u8]) -> Result<String> {
    if bytes.len() > 12 * 1024 * 1024 {
        return Err("Choose a smaller PNG or JPEG image".into());
    }
    let format = image::guess_format(bytes)?;
    if !matches!(format, image::ImageFormat::Png | image::ImageFormat::Jpeg) {
        return Err("Choose a PNG or JPEG image".into());
    }
    let mut reader = image::ImageReader::with_format(std::io::Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode()?.into_luma8();
    let mut image = rqrr::PreparedImage::prepare(image);
    let mut codes = image
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, code)| code))
        .filter(|code| {
            code.len() <= 4096
                && (code.starts_with(recovery_qr::PREFIX)
                    || code.starts_with("elo-recovery:1:")
                    || code.starts_with(elo_core::app::pairing::PREFIX))
        })
        .collect::<Vec<_>>();
    codes.sort();
    codes.dedup();
    if codes.len() != 1 {
        return Err("Choose an image with one recovery or device code".into());
    }
    codes.pop().ok_or_else(|| "No recovery code found".into())
}

async fn pick(app: &tauri::AppHandle) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog().file().pick_file(move |value| {
        let _ = tx.send(value);
    });
    let Some(file) = rx.await? else {
        return Ok(None);
    };
    let source = app.fs().open(file, OpenOptions::new().read(true).clone())?;
    let mut bytes = Zeroizing::new(Vec::new());
    source
        .take(profile_backup::MAX_BACKUP as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > profile_backup::MAX_BACKUP {
        return Err("Profile backup is too large".into());
    }
    Ok(Some(bytes))
}
async fn save(app: &tauri::AppHandle, bytes: &[u8], filename: &str) -> Result<bool> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(filename)
        .save_file(move |value| {
            let _ = tx.send(value);
        });
    let Some(file) = rx.await? else {
        return Ok(false);
    };
    let mut destination = app.fs().open(
        file,
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .clone(),
    )?;
    destination.write_all(bytes)?;
    destination.sync_all()?;
    Ok(true)
}

#[tauri::command]
pub async fn profile_task(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    request: Value,
) -> std::result::Result<Value, String> {
    run(&app, state, request).await.map_err(|e| e.to_string())
}
async fn run(app: &tauri::AppHandle, state: tauri::State<'_, State>, v: Value) -> Result<Value> {
    let op = text(&v, "op")?;
    if op == "pause_recovery" {
        return Ok(json!({"paused":crate::recovery_progress::pause(app, text(&v,"request_id")?)}));
    }
    let mut state = state.lock().await;
    match op {
        "cancel" => {
            state.recovery = None;
            state.backup = None;
            state.pair_source = None;
            state.pair_target = None;
            state.recovery_qr = None;
        }
        "select" => {
            if state.client.is_some() {
                return Err("Log out before changing profiles".into());
            }
            let id = text(&v, "id")?;
            if !saved(app)?.iter().any(|entry| entry["id"] == id) {
                return Err("Saved profile not found".into());
            }
            select(app, &base(app)?.join(id))?;
        }
        "check_recovery" => {
            if state.client.is_some() {
                return Err("Log out before recovering a profile".into());
            }
            let draft = ProfileDraft::recover(text(&v, "words")?, text(&v, "identity")?)?;
            let result = serde_json::to_value(draft.card())?;
            state.recovery = Some(draft);
            return Ok(result);
        }
        "read_recovery_qr" => {
            if state.client.is_some() {
                return Err("Log out before recovering a profile".into());
            }
            let draft =
                recovery_qr::decode(text(&v, "code")?, text(&v, "password")?.to_string().into())?;
            let result = serde_json::to_value(draft.card())?;
            state.recovery = Some(draft);
            return Ok(result);
        }
        "recovery_material" => {
            let client = state.client.as_ref().ok_or("The profile is locked")?;
            let draft =
                ProfileDraft::recover(text(&v, "words")?, &client.identity_id().to_string())?;
            return Ok(serde_json::to_value(draft.card())?);
        }
        "recovery_qr" => {
            let draft;
            let card = if let Some(client) = &state.client {
                draft =
                    ProfileDraft::recover(text(&v, "words")?, &client.identity_id().to_string())?;
                draft.card()
            } else {
                state
                    .recovery
                    .as_ref()
                    .or(state.draft.as_ref())
                    .ok_or("Prepare a recovery key first")?
                    .card()
            };
            let code = recovery_qr::encode(card, text(&v, "password")?.to_string().into())?;
            let image = svg(&code)?;
            state.recovery_qr = Some(code);
            return Ok(json!({"svg":image}));
        }
        "save_recovery_qr" | "share_recovery_qr" => {
            let code = state
                .recovery_qr
                .as_ref()
                .ok_or("Create the encrypted recovery QR first")?;
            let png = qr_png(code)?;
            if op == "share_recovery_qr" {
                let path = crate::exchange::new_path(app, "png")?;
                vault::write_private(&path, &png, false)?;
                crate::exchange::share_generated_file(app, path, "image/png", "elo-recovery.png")?;
                return Ok(json!({"shared":true}));
            }
            return Ok(json!({"saved":save(app, &png, "elo-recovery.png").await?}));
        }
        "read_qr_image" => {
            let bytes = if let Some(data) = v["image"].as_str() {
                if data.len() > 16 * 1024 * 1024 + 128 {
                    return Err("Choose a smaller PNG or JPEG image".into());
                }
                let encoded = data
                    .strip_prefix("data:image/png;base64,")
                    .or_else(|| data.strip_prefix("data:image/jpeg;base64,"))
                    .ok_or("Choose a PNG or JPEG image")?;
                Zeroizing::new(STANDARD.decode(encoded).map_err(|_| "Invalid image")?)
            } else {
                let Some(bytes) = pick(app).await? else {
                    return Ok(json!({"code":null}));
                };
                bytes
            };
            return Ok(json!({"code":qr_from_image(&bytes)?}));
        }
        "choose_backup" => {
            if state.client.is_some() {
                return Err("Log out before recovering a profile".into());
            }
            if let Some(bytes) = pick(app).await? {
                state.backup = Some(bytes);
            }
            let resumable = state.backup.as_ref().is_some_and(|bytes| {
                (|| -> Result<bool> {
                    let pointer = recovery_pointer(app, bytes)?;
                    if !pointer.try_exists()? {
                        return Ok(false);
                    }
                    let name: String = serde_json::from_slice(&vault::read_private(&pointer)?)?;
                    Ok(valid_name(&name) && name != "profile" && base(app)?.join(name).is_dir())
                })()
                .unwrap_or(false)
            });
            return Ok(json!({"selected":state.backup.is_some(),"resume":resumable}));
        }
        "clear_qr" => {
            state.recovery_qr = None;
        }
        "clear_backup" => {
            state.backup = None;
        }
        "recover" => {
            if state.client.is_some() {
                return Err("Log out before recovering a profile".into());
            }
            let draft = state
                .recovery
                .as_ref()
                .ok_or("Check the recovery key first")?;
            let password: SecretString = text(&v, "password")?.to_string().into();
            let path = match state.backup.as_ref() {
                Some(bytes) => recovery_destination(app, bytes)?,
                None => new_profile(app)?,
            };
            let job = crate::recovery_progress::Job::start(app, text(&v, "request_id")?)?;
            let mut client = if let Some(bytes) = &state.backup {
                if path.exists() && !path.join(".initializing").exists() {
                    // A crash after the commit but before updating profiles.json.
                    ClientApp::open(path.clone(), password, false).await?
                } else {
                    profile_backup::restore(
                        profile_backup::RestoreRequest {
                            directory: path.clone(),
                            bytes,
                            secret: draft.card().phrase.clone().into(),
                            expected: draft.card().identity_id,
                            password,
                            allow_loopback: false,
                            resume: true,
                            paged: true,
                        },
                        &job.progress,
                    )
                    .await?
                }
            } else {
                draft
                    .save_named(path.clone(), password, "General", text(&v, "name")?)
                    .await?
            };
            if client.identity_id() != draft.card().identity_id {
                client.close().await?;
                return Err("This backup belongs to a different profile".into());
            }
            crate::team_replica::configure(&mut client)?;
            crate::push::configure_client(&mut client)?;
            client.enable_spaces().await?;
            client.enable_paged_views();
            let view = client.view().await?;
            if let Err(e) = select(app, &path) {
                client.close().await?;
                return Err(e);
            }
            if let Some(bytes) = &state.backup {
                // The profile is already committed and selected. A leftover
                // pointer can safely reopen it after an interrupted cleanup.
                let _ = std::fs::remove_file(recovery_pointer(app, bytes)?);
            }
            state.recovery = None;
            state.backup = None;
            state.recovery_qr = None;
            state.client = Some(client);
            app.state::<crate::background_history::BackgroundHistory>()
                .resume();
            return Ok(view);
        }
        "backup" => {
            let client = state.client.as_ref().ok_or("The profile is locked")?;
            let backup = client
                .export_recovery_backup_with_report(text(&v, "words")?)
                .await?;
            let omitted_messages = backup.omitted_messages;
            let bytes = Zeroizing::new(backup.bytes);
            if cfg!(mobile) {
                let path = crate::exchange::new_path(app, "elo-backup")?;
                vault::write_private(&path, &bytes, false)?;
                crate::exchange::share_generated_file(
                    app,
                    path,
                    "application/octet-stream",
                    "elo-profile.elo-backup",
                )?;
                return Ok(
                    json!({"shared":true,"saved":false,"omitted_messages":omitted_messages}),
                );
            }
            return Ok(
                json!({"saved":save(app, &bytes, "elo-profile.elo-backup").await?,"omitted_messages":omitted_messages}),
            );
        }
        "pair_start" => {
            let source =
                PairSource::new(state.client.as_ref().ok_or("The profile is locked")?).await?;
            let link = source.link()?;
            let image = svg(&link)?;
            let expires = source.expires_at();
            state.pair_source = Some(source);
            return Ok(json!({"svg":image,"code":link,"expires":expires}));
        }
        "pair_poll" => {
            return state
                .pair_source
                .as_mut()
                .ok_or("Create a device code first")?
                .poll()
                .await;
        }
        "pair_approve" => {
            let crate::Runtime {
                client,
                pair_source,
                ..
            } = &mut *state;
            let client = client.as_ref().ok_or("The profile is locked")?;
            if !client.password_matches(&text(&v, "password")?.to_string().into())
                || v["confirmed"] != true
            {
                return Err("Confirm the device and enter your profile password".into());
            }
            pair_source
                .as_mut()
                .ok_or("Create a device code first")?
                .approve(client, text(&v, "id")?, text(&v, "code")?)
                .await?;
        }
        "pair_request" => {
            if state.client.is_some() {
                return Err("Log out before linking this device".into());
            }
            let target = PairTarget::new(text(&v, "code")?, text(&v, "name")?, false)?;
            target.send().await?;
            let summary = target.summary()?;
            state.pair_target = Some(target);
            return Ok(summary);
        }
        "pair_receive" => {
            return state
                .pair_target
                .as_mut()
                .ok_or("Scan a device code first")?
                .poll()
                .await;
        }
        "pair_finish" => {
            if state.client.is_some() {
                return Err("Log out before linking this device".into());
            }
            if v["confirmed"] != true {
                return Err("Compare and confirm the code on both devices".into());
            }
            let path = new_profile(app)?;
            let target = state
                .pair_target
                .as_mut()
                .ok_or("Scan a device code first")?;
            let mut client = target
                .finish(
                    path.clone(),
                    text(&v, "password")?.to_string().into(),
                    text(&v, "code")?,
                )
                .await?;
            crate::team_replica::configure(&mut client)?;
            crate::push::configure_client(&mut client)?;
            client.enable_spaces().await?;
            client.enable_paged_views();
            let view = client.view().await?;
            if let Err(e) = select(app, &path) {
                client.close().await?;
                return Err(e);
            }
            state.pair_target = None;
            state.client = Some(client);
            app.state::<crate::background_history::BackgroundHistory>()
                .resume();
            return Ok(view);
        }
        "remove" => {
            let client = state.client.as_ref().ok_or("The profile is locked")?;
            if v["confirmed"] != true
                || text(&v, "identity")? != client.identity_id().to_string()
                || !client.password_matches(&text(&v, "password")?.to_string().into())
            {
                return Err("Confirm removal and enter your profile password".into());
            }
            let path = client.profile_path().to_path_buf();
            // Limit deletion to registry-owned profile directories, never demos,
            // exports or a caller-supplied desktop folder with unrelated files.
            if path != active(app)? || path.parent() != Some(base(app)?.as_path()) {
                return Err("Only the selected app-managed profile can be removed here".into());
            }
            check_removable(&path)?;
            app.state::<crate::background_history::BackgroundHistory>()
                .suspend();
            crate::push::suspend(app).await?;
            state
                .client
                .take()
                .ok_or("The profile is locked")?
                .close()
                .await?;
            remove_profile_files(&path)?;
            let mut registry = index(app)?;
            registry["saved"]
                .as_array_mut()
                .ok_or("Invalid profile selection")?
                .retain(|v| {
                    Some(v.as_str().unwrap_or("")) != path.file_name().and_then(|s| s.to_str())
                });
            let next = registry["saved"]
                .as_array()
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or(json!("profile"));
            if registry["saved"].as_array().is_some_and(Vec::is_empty) {
                registry["saved"] = json!(["profile"]);
            }
            registry["active"] = next;
            vault::write_private(
                &base(app)?.join("profiles.json"),
                &serde_json::to_vec(&registry)?,
                true,
            )?;
            state.draft = None;
            state.recovery = None;
            state.backup = None;
            state.pair_source = None;
            state.pair_target = None;
            state.recovery_qr = None;
            crate::exchange::clear(app)?;
        }
        _ => {
            return Err("Unknown profile operation".into());
        }
    }
    Ok(json!({"ok":true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_recovery_image_roundtrips_and_contact_codes_are_rejected() {
        let card = ProfileDraft::new().unwrap();
        let code = recovery_qr::encode(card.card(), "synthetic QR password".into()).unwrap();
        let png = qr_png(&code).unwrap();
        assert!(code.starts_with("elo recovery v1\n"));
        assert!(!code.contains("://"));
        assert_eq!(qr_from_image(&png).unwrap(), code);
        let draft = recovery_qr::decode(
            &qr_from_image(&png).unwrap(),
            "synthetic QR password".into(),
        )
        .unwrap();
        assert_eq!(draft.card().identity_id, card.card().identity_id);
        assert!(qr_from_image(&qr_png("elo://exchange/v1#public-contact").unwrap()).is_err());
        assert!(qr_from_image(b"not an image").is_err());
    }
    #[test]
    fn removal_preserves_other_profiles_and_refuses_unrelated_files_or_links() {
        let root = std::env::temp_dir().join(format!(
            "elo-remove-test-{}",
            record::random_hex::<16>().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let profile = root.join("profile");
        let other = root.join("other");
        std::fs::create_dir(&profile).unwrap();
        std::fs::create_dir(&other).unwrap();
        std::fs::write(profile.join("vault.age"), b"synthetic vault").unwrap();
        std::fs::write(other.join("vault.age"), b"keep").unwrap();
        std::fs::write(profile.join("my-notes.txt"), b"keep").unwrap();
        assert!(remove_profile_files(&profile).is_err());
        assert!(profile.join("vault.age").exists());
        std::fs::remove_file(profile.join("my-notes.txt")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(other.join("vault.age"), profile.join("workspace.age"))
                .unwrap();
            assert!(remove_profile_files(&profile).is_err());
            std::fs::remove_file(profile.join("workspace.age")).unwrap();
        }
        let spaces = profile.join("spaces");
        std::fs::create_dir(&spaces).unwrap();
        let child = spaces.join("ab".repeat(32));
        std::fs::create_dir(&child).unwrap();
        std::fs::write(profile.join("spaces.age"), b"synthetic catalog").unwrap();
        std::fs::write(child.join("vault.age"), b"synthetic child vault").unwrap();
        std::fs::write(child.join("client.sqlite"), b"synthetic child store").unwrap();
        std::fs::write(child.join("my-notes.txt"), b"keep").unwrap();
        assert!(remove_profile_files(&profile).is_err());
        assert!(profile.join("vault.age").exists());
        assert!(child.join("client.sqlite").exists());
        std::fs::remove_file(child.join("my-notes.txt")).unwrap();
        #[cfg(unix)]
        {
            let link = spaces.join("cd".repeat(32));
            std::os::unix::fs::symlink(&other, &link).unwrap();
            assert!(remove_profile_files(&profile).is_err());
            assert!(child.join("vault.age").exists());
            std::fs::remove_file(link).unwrap();
        }
        remove_profile_files(&profile).unwrap();
        assert_eq!(std::fs::read(other.join("vault.age")).unwrap(), b"keep");
        assert!(!profile.exists());
        assert!(!valid_name("../profile"));
        assert!(!valid_name("profile-../../other"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

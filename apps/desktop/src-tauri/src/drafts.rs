//! Draft commands remain local and cannot resolve arbitrary renderer file paths.
use crate::State;
use elo_core::app::drafts::{DraftContent, DraftScope};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    path: String,
    name: String,
    size_bytes: u64,
}
#[tauri::command]
pub async fn draft_load(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    scope: DraftScope,
) -> Result<Value, String> {
    let mut state = state.lock().await;
    let client = state.client.as_ref().ok_or("Unlock the profile first.")?;
    let draft = client
        .load_conversation_draft(&scope)
        .map_err(|error| error.to_string())?;
    let attachment = draft
        .attachment
        .map(|(name, bytes)| -> Result<Value, String> {
            let path = crate::exchange::restore_draft_attachment(&app, &bytes)?;
            Ok(json!({ "path": path, "name": name, "size_bytes": bytes.len() }))
        })
        .transpose()?;
    if state.draft_session.is_none() {
        state.draft_session =
            Some(elo_core::record::random_hex::<32>().map_err(|error| error.to_string())?);
    }
    Ok(
        json!({"session": state.draft_session, "draft": {"text": draft.content.text, "expiry": draft.content.expiry, "mentions": draft.content.mentions, "attachment": attachment}}),
    )
}
#[tauri::command]
pub async fn draft_save(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    session: String,
    scope: DraftScope,
    content: DraftContent,
    attachment: Option<Attachment>,
) -> Result<(), String> {
    let mut state = state.lock().await;
    if state.draft_session.as_deref() != Some(&session) {
        return Err("The draft session is no longer active.".into());
    }
    let client = state.client.as_ref().ok_or("Unlock the profile first.")?;
    let scope_key = serde_json::to_string(&scope).map_err(|error| error.to_string())?;
    let cache_key = attachment
        .as_ref()
        .map(|file| format!("{scope_key}:{}", file.path));
    let cached = cache_key
        .as_ref()
        .and_then(|key| state.draft_attachments.get(key))
        .cloned();
    let staged = attachment
        .map(|attachment| -> Result<_, String> {
            let mut request = json!({"op":"attachment_upload", "path": attachment.path});
            crate::exchange::resolve_transfer(&app, &mut request)?;
            let path = std::path::PathBuf::from(
                request["path"]
                    .as_str()
                    .ok_or("Invalid draft attachment.")?,
            );
            if std::fs::metadata(&path)
                .map_err(|error| error.to_string())?
                .len()
                != attachment.size_bytes
            {
                return Err("Invalid draft attachment.".into());
            }
            Ok((path, attachment.name))
        })
        .transpose()?;
    let saved = client
        .save_conversation_draft_cached(
            &scope,
            content,
            staged
                .as_ref()
                .map(|(path, name)| (path.as_path(), name.as_str())),
            cached,
        )
        .map_err(|error| error.to_string())?;
    state
        .draft_attachments
        .retain(|key, _| !key.starts_with(&format!("{scope_key}:")));
    if let (Some(key), Some(saved)) = (cache_key, saved) {
        state.draft_attachments.insert(key, saved);
    }
    Ok(())
}

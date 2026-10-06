//! Draft commands remain local and cannot resolve arbitrary renderer file paths.
use crate::State;
use elo_core::app::drafts::{DraftContent, DraftScope};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(crate) struct DraftSessions {
    epoch: Option<String>,
    conversations: BTreeMap<String, ConversationSession>,
    cleanup: BTreeMap<String, BTreeSet<String>>,
}
#[derive(Default)]
struct ConversationSession {
    token: String,
    generation: u64,
    scopes: BTreeSet<String>,
    handles: BTreeSet<String>,
}
fn conversation_key(scope: &DraftScope) -> Result<String, String> {
    let mut scope = scope.clone();
    scope.thread = None;
    serde_json::to_string(&scope).map_err(|error| error.to_string())
}
impl DraftSessions {
    fn for_epoch(&mut self, epoch: Option<&str>) {
        if self.epoch.as_deref() != epoch {
            self.conversations.clear();
            self.cleanup.clear();
            self.epoch = epoch.map(str::to_owned);
        }
    }
    fn load(&mut self, scope: &DraftScope, generation: u64) -> Result<String, String> {
        let key = conversation_key(scope)?;
        if !self.conversations.contains_key(&key) {
            self.conversations.insert(
                key.clone(),
                ConversationSession {
                    token: elo_core::record::random_hex::<32>()
                        .map_err(|error| error.to_string())?,
                    generation,
                    ..Default::default()
                },
            );
        }
        let session = self
            .conversations
            .get_mut(&key)
            .expect("draft session inserted");
        if session.generation != generation {
            session.token =
                elo_core::record::random_hex::<32>().map_err(|error| error.to_string())?;
            session.generation = generation;
        }
        session
            .scopes
            .insert(serde_json::to_string(scope).map_err(|error| error.to_string())?);
        Ok(session.token.clone())
    }
    fn verify(&self, scope: &DraftScope, token: &str, generation: u64) -> Result<(), String> {
        let scope_key = serde_json::to_string(scope).map_err(|error| error.to_string())?;
        if self
            .conversations
            .get(&conversation_key(scope)?)
            .is_none_or(|session| {
                session.token != token
                    || session.generation != generation
                    || !session.scopes.contains(&scope_key)
            })
        {
            return Err("The draft session is no longer active.".into());
        }
        Ok(())
    }
    fn track(&mut self, scope: &DraftScope, handle: String) -> Result<(), String> {
        self.conversations
            .get_mut(&conversation_key(scope)?)
            .ok_or("The draft session is no longer active.")?
            .handles
            .insert(handle);
        Ok(())
    }
    fn revoke(&mut self, scope: &DraftScope) -> Result<ConversationSession, String> {
        let key = conversation_key(scope)?;
        let mut revoked = self.conversations.remove(&key).unwrap_or_default();
        revoked
            .handles
            .extend(self.cleanup.remove(&key).unwrap_or_default());
        Ok(revoked)
    }
}

/// Called under RuntimeMutex after a durable local deletion, including retries.
pub(crate) fn delete_conversation(
    app: &tauri::AppHandle,
    state: &mut crate::Runtime,
    request: &Value,
) -> Result<(), String> {
    let client = state.client.as_ref().ok_or("Unlock the profile first.")?;
    let scope = client
        .conversation_draft_scope(request)
        .map_err(|error| error.to_string())?;
    // Revoke first even if disk cleanup fails: queued old saves must stay denied.
    state.drafts.for_epoch(state.draft_session.as_deref());
    let revoked = state.drafts.revoke(&scope)?;
    state.draft_attachments.retain(|key, _| {
        !revoked
            .scopes
            .iter()
            .any(|scope| key.starts_with(&format!("{scope}:")))
    });
    let mut result = Ok(());
    for handle in revoked.handles {
        let cleanup = crate::exchange::discard_handle(app, &handle);
        if cleanup.is_err() {
            state
                .drafts
                .cleanup
                .entry(conversation_key(&scope)?)
                .or_default()
                .insert(handle);
        }
        if result.is_ok() {
            result = cleanup;
        }
    }
    result
}

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
        .await
        .map_err(|error| error.to_string())?;
    if state.draft_session.is_none() {
        state.draft_session =
            Some(elo_core::record::random_hex::<32>().map_err(|error| error.to_string())?);
    }
    let epoch = state.draft_session.clone();
    state.drafts.for_epoch(epoch.as_deref());
    let session = state.drafts.load(&scope, draft.history_generation)?;
    let attachment = draft
        .attachment
        .map(|(name, bytes)| -> Result<Value, String> {
            let path = crate::exchange::restore_draft_attachment(&app, &bytes)?;
            state.drafts.track(&scope, path.clone())?;
            Ok(json!({ "path": path, "name": name, "size_bytes": bytes.len() }))
        })
        .transpose()?;
    Ok(
        json!({"session": session, "draft": {"text": draft.content.text, "expiry": draft.content.expiry, "mentions": draft.content.mentions, "attachment": attachment}}),
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
    let epoch = state.draft_session.clone();
    state.drafts.for_epoch(epoch.as_deref());
    let generation = state
        .client
        .as_ref()
        .ok_or("Unlock the profile first.")?
        .conversation_draft_generation(&scope)
        .await
        .map_err(|error| error.to_string())?;
    state.drafts.verify(&scope, &session, generation)?;
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
            state.drafts.track(&scope, attachment.path)?;
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
    let saved = state
        .client
        .as_ref()
        .ok_or("Unlock the profile first.")?
        .save_conversation_draft_cached(
            &scope,
            content,
            staged
                .as_ref()
                .map(|(path, name)| (path.as_path(), name.as_str())),
            cached,
        )
        .await
        .map_err(|error| error.to_string())?;
    state
        .draft_attachments
        .retain(|key, _| !key.starts_with(&format!("{scope_key}:")));
    if let (Some(key), Some(saved)) = (cache_key, saved) {
        state.draft_attachments.insert(key, saved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(stream: &str) -> DraftScope {
        serde_json::from_value(json!({
            "identity":"11".repeat(32), "credential":"22".repeat(32),
            "active_space":"33".repeat(32), "space":"44".repeat(32),
            "stream":stream.repeat(16), "thread":null
        }))
        .unwrap()
    }
    #[test]
    fn deleting_one_chat_revokes_all_threads_without_revoking_other_drafts() {
        let mut sessions = DraftSessions::default();
        sessions.for_epoch(Some("unlocked profile"));
        let chat = scope("55");
        let mut thread = chat.clone();
        thread.thread = Some(elo_core::ids::RecordId::from_bytes([7; 32]));
        let other = scope("66");
        let token = sessions.load(&chat, 0).unwrap();
        // Even if post-commit cleanup was interrupted, a durable deletion epoch
        // invalidates old saves before a later message makes the chat visible.
        assert!(sessions.verify(&chat, &token, 1).is_err());
        let renewed = sessions.load(&chat, 1).unwrap();
        assert_ne!(renewed, token);
        sessions.verify(&chat, &renewed, 1).unwrap();
        assert!(sessions.verify(&chat, &token, 1).is_err());
        let token = sessions.load(&chat, 0).unwrap();
        assert_eq!(sessions.load(&thread, 0).unwrap(), token);
        let other_token = sessions.load(&other, 0).unwrap();
        sessions.track(&chat, "chat attachment".into()).unwrap();
        sessions.track(&thread, "reply attachment".into()).unwrap();
        sessions.track(&other, "other attachment".into()).unwrap();
        let revoked = sessions.revoke(&chat).unwrap();
        assert_eq!(revoked.scopes.len(), 2);
        assert_eq!(
            revoked.handles,
            ["chat attachment".into(), "reply attachment".into()].into()
        );
        assert!(sessions.verify(&chat, &token, 0).is_err());
        assert!(sessions.verify(&thread, &token, 0).is_err());
        sessions.verify(&other, &other_token, 0).unwrap();
        let renewed = sessions.load(&chat, 0).unwrap();
        assert_ne!(renewed, token);
        assert!(sessions.verify(&chat, &token, 0).is_err());
        sessions.verify(&chat, &renewed, 0).unwrap();
    }

    #[test]
    fn draft_tokens_cannot_cross_chat_device_compartment_or_unlock_epoch() {
        let mut sessions = DraftSessions::default();
        sessions.for_epoch(Some("first unlock"));
        let chat = scope("55");
        let token = sessions.load(&chat, 0).unwrap();
        let mut other = chat.clone();
        other.credential = elo_core::ids::RecordId::from_bytes([8; 32]);
        assert!(sessions.verify(&other, &token, 0).is_err());
        other = chat.clone();
        other.active_space = Some("99".repeat(32));
        assert!(sessions.verify(&other, &token, 0).is_err());
        assert!(sessions.verify(&scope("66"), &token, 0).is_err());
        sessions.for_epoch(Some("second unlock"));
        assert!(sessions.verify(&chat, &token, 0).is_err());
        assert_ne!(sessions.load(&chat, 0).unwrap(), token);
    }
}

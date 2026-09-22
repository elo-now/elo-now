use super::*;
use crate::{
    attachments::{
        AttachmentAvailability, AttachmentRetention, MAX_ATTACHMENT_FILE_SIZE,
        MAX_SPACE_ATTACHMENT_STORAGE,
    },
    authority::Capability,
};
use sha2::{Digest, Sha256};

const RESERVATION_TTL_MS: u64 = 15 * 60 * 1000;
const ACCESS_TTL_MS: u64 = 5 * 60 * 1000;
const UNLINKED_UPLOAD_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HostedAttachmentState {
    Reserved,
    Uploaded,
    Available,
    DeletingExpired,
    DeletingDeleted,
    Expired,
    Deleted,
    Missing,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostedAttachment {
    object_id: AttachmentObjectId,
    issuer: IdentityId,
    plaintext_size: u64,
    encrypted_size: u64,
    ciphertext_sha256: String,
    created_at_ms: u64,
    expires_at_ms: Option<u64>,
    reservation_expires_at_ms: u64,
    state: HostedAttachmentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message_id: Option<RecordId>,
}

impl HostedAttachment {
    fn availability(&self) -> Option<AttachmentAvailability> {
        Some(match self.state {
            HostedAttachmentState::Available | HostedAttachmentState::DeletingExpired => {
                AttachmentAvailability::Available
            }
            HostedAttachmentState::Expired => AttachmentAvailability::Expired,
            HostedAttachmentState::Deleted | HostedAttachmentState::DeletingDeleted => {
                AttachmentAvailability::Deleted
            }
            HostedAttachmentState::Missing => AttachmentAvailability::Missing,
            HostedAttachmentState::Reserved | HostedAttachmentState::Uploaded => return None,
        })
    }

    fn counts_as_used(&self) -> bool {
        matches!(
            self.state,
            HostedAttachmentState::Available
                | HostedAttachmentState::DeletingExpired
                | HostedAttachmentState::DeletingDeleted
        )
    }

    fn counts_as_reserved(&self) -> bool {
        matches!(
            self.state,
            HostedAttachmentState::Reserved | HostedAttachmentState::Uploaded
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttachmentAccess {
    attachment: AttachmentId,
    kind: String,
    expires_at_ms: u64,
}

#[derive(Clone, Debug)]
pub struct AttachmentTransferGrant {
    pub attachment_id: AttachmentId,
    pub object_id: AttachmentObjectId,
    pub encrypted_size: u64,
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug)]
pub struct AttachmentCleanupTarget {
    pub attachment_id: AttachmentId,
    pub object_id: AttachmentObjectId,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttachmentStorageUsage {
    pub used_bytes: u64,
    pub reserved_bytes: u64,
    pub files: usize,
}

fn token_hash(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"elo.now/attachment-access/v1\0");
    digest.update(value.as_bytes());
    crate::record::encode_hex(&digest.finalize())
}

pub(super) fn bytes_in_state(state: &ServiceState) -> (u64, u64) {
    state
        .attachments
        .values()
        .fold((0, 0), |(used, reserved), attachment| {
            (
                used + attachment
                    .counts_as_used()
                    .then_some(attachment.encrypted_size)
                    .unwrap_or(0),
                reserved
                    + attachment
                        .counts_as_reserved()
                        .then_some(attachment.encrypted_size)
                        .unwrap_or(0),
            )
        })
}

impl ClientApp {
    pub fn set_attachment_storage_available(&self, available: bool) -> Result<()> {
        let mut state = self.service_state()?;
        if state.attachment_policy.enabled != available {
            state.attachment_policy.enabled = available;
            self.save_service_state(&state)?;
        }
        Ok(())
    }

    fn attachment_member_capability(
        &self,
        credential: &VerifiedCredential,
        capability: Capability,
    ) -> bool {
        if !self
            .space_access_members()
            .is_ok_and(|members| members.contains(&credential.identity()))
        {
            return false;
        }
        self.authorities
            .0
            .first()
            .and_then(|authority| authority.head().ok())
            .and_then(|head| {
                head.members.iter().find(|member| {
                    member.identity_id == credential.identity()
                        && member.credential_ids.contains(&credential.id())
                })
            })
            .is_some_and(|member| member.capabilities.contains(&capability))
    }

    pub(super) fn attachment_space_command(
        &mut self,
        state: &mut ServiceState,
        credential: &VerifiedCredential,
        owner: bool,
        command: &Command,
        current: u64,
    ) -> Option<Result<Value>> {
        let read = self.attachment_member_capability(credential, Capability::Read);
        let post = self.attachment_member_capability(credential, Capability::Post);
        let result = match command.action.as_str() {
            "attachment_settings" if read => {
                let (used, reserved) = bytes_in_state(state);
                Ok(
                    json!({"policy":state.attachment_policy,"used_bytes":used,"reserved_bytes":reserved}),
                )
            }
            "attachment_reserve" if post => {
                if let Err(error) = state.attachment_policy.validate() {
                    return Some(Err(error.into()));
                }
                if !state.attachment_policy.enabled {
                    return Some(Err("Attachments are disabled for this Space.".into()));
                }
                let attachment: AttachmentId = match field(&command.body, "attachment_id")
                    .and_then(|value| value.parse().map_err(Into::into))
                {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error.into())),
                };
                let object_id: AttachmentObjectId = match field(&command.body, "object_id")
                    .and_then(|value| value.parse().map_err(Into::into))
                {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error.into())),
                };
                let plaintext_size = command.body["plaintext_size"].as_u64().unwrap_or(u64::MAX);
                let encrypted_size = command.body["encrypted_size"].as_u64().unwrap_or(u64::MAX);
                let expected = crate::attachments::crypto::encrypted_size(plaintext_size);
                let checksum = match field(&command.body, "ciphertext_sha256") {
                    Ok(value) if crate::record::hex::<32>(value).is_ok() => value.to_owned(),
                    _ => return Some(Err("Invalid attachment checksum.".into())),
                };
                if plaintext_size > MAX_ATTACHMENT_FILE_SIZE || encrypted_size != expected {
                    return Some(Err("Attachment files cannot exceed 5 MB.".into()));
                }
                if state.attachments.contains_key(&attachment)
                    || state
                        .attachments
                        .values()
                        .any(|entry| entry.object_id == object_id)
                {
                    return Some(Err("Attachment identifiers must be unique.".into()));
                }
                let (used, reserved) = bytes_in_state(state);
                if used
                    .checked_add(reserved)
                    .and_then(|value| value.checked_add(encrypted_size))
                    .is_none_or(|value| value > MAX_SPACE_ATTACHMENT_STORAGE)
                {
                    return Some(Err(format!(
                        "Attachment storage is full. {} MB of 200 MB is currently used.",
                        used.div_ceil(1024 * 1024)
                    )
                    .into()));
                }
                let raw_token = match record::random_hex::<32>() {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error.into())),
                };
                let created_at_ms = current;
                state.attachments.insert(
                    attachment,
                    HostedAttachment {
                        object_id,
                        issuer: credential.identity(),
                        plaintext_size,
                        encrypted_size,
                        ciphertext_sha256: checksum,
                        created_at_ms,
                        expires_at_ms: state.attachment_policy.expires_at(created_at_ms),
                        reservation_expires_at_ms: current + RESERVATION_TTL_MS,
                        state: HostedAttachmentState::Reserved,
                        message_id: None,
                    },
                );
                state.attachment_access.insert(
                    token_hash(&raw_token),
                    AttachmentAccess {
                        attachment,
                        kind: "upload".into(),
                        expires_at_ms: current + RESERVATION_TTL_MS,
                    },
                );
                if let Err(error) = self.save_service_state(state) {
                    return Some(Err(error));
                }
                let stored = &state.attachments[&attachment];
                Ok(
                    json!({"attachment_id":attachment,"object_id":object_id,"upload_token":raw_token,
                    "created_at_ms":created_at_ms,"expires_at_ms":stored.expires_at_ms}),
                )
            }
            "attachment_cancel" if post => {
                let attachment: AttachmentId = match field(&command.body, "attachment_id")
                    .and_then(|value| Ok(value.parse()?))
                {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error)),
                };
                let Some(stored) = state.attachments.get_mut(&attachment) else {
                    return Some(Ok(json!({"status":"cancelled"})));
                };
                if stored.issuer != credential.identity() || stored.message_id.is_some() {
                    return Some(Err("A sent attachment cannot be cancelled.".into()));
                }
                if !matches!(
                    stored.state,
                    HostedAttachmentState::Deleted
                        | HostedAttachmentState::Expired
                        | HostedAttachmentState::Missing
                ) {
                    stored.state = HostedAttachmentState::DeletingDeleted;
                }
                state
                    .attachment_access
                    .retain(|_, access| access.attachment != attachment);
                if let Err(error) = self.save_service_state(state) {
                    return Some(Err(error));
                }
                Ok(json!({"status":"cancelled"}))
            }
            "attachment_commit" if post => {
                let attachment: AttachmentId = match field(&command.body, "attachment_id")
                    .and_then(|value| Ok(value.parse()?))
                {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error)),
                };
                let Some(stored) = state.attachments.get_mut(&attachment) else {
                    return Some(Err("Attachment upload reservation was not found.".into()));
                };
                if stored.issuer != credential.identity()
                    || !matches!(
                        stored.state,
                        HostedAttachmentState::Uploaded | HostedAttachmentState::Available
                    )
                {
                    return Some(Err("Attachment upload is incomplete.".into()));
                }
                stored.state = HostedAttachmentState::Available;
                if let Err(error) = self.save_service_state(state) {
                    return Some(Err(error));
                }
                Ok(json!({"status":"available"}))
            }
            "attachment_link" if post => {
                let attachment: AttachmentId = match field(&command.body, "attachment_id")
                    .and_then(|value| Ok(value.parse()?))
                {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error)),
                };
                let message: RecordId =
                    match field(&command.body, "message_id").and_then(|value| Ok(value.parse()?)) {
                        Ok(value) => value,
                        Err(error) => return Some(Err(error)),
                    };
                let Some(stored) = state.attachments.get_mut(&attachment) else {
                    return Some(Err("Attachment was not found.".into()));
                };
                if stored.issuer != credential.identity()
                    || !matches!(stored.state, HostedAttachmentState::Available)
                {
                    return Some(Err("Attachment is not available.".into()));
                }
                stored.message_id = Some(message);
                if let Err(error) = self.save_service_state(state) {
                    return Some(Err(error));
                }
                Ok(json!({"status":"linked"}))
            }
            "attachment_download" if read => {
                let attachment: AttachmentId = match field(&command.body, "attachment_id")
                    .and_then(|value| Ok(value.parse()?))
                {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error)),
                };
                let Some(stored) = state.attachments.get(&attachment) else {
                    return Some(Ok(json!({"status":"missing"})));
                };
                let Some(availability) = stored.availability() else {
                    return Some(Ok(json!({"status":"missing"})));
                };
                if availability != AttachmentAvailability::Available {
                    return Some(Ok(json!({"status":availability})));
                }
                let raw_token = match record::random_hex::<32>() {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error.into())),
                };
                state.attachment_access.insert(
                    token_hash(&raw_token),
                    AttachmentAccess {
                        attachment,
                        kind: "download".into(),
                        expires_at_ms: current + ACCESS_TTL_MS,
                    },
                );
                if let Err(error) = self.save_service_state(state) {
                    return Some(Err(error));
                }
                Ok(json!({"status":"available","download_token":raw_token}))
            }
            "attachment_status" if read => {
                let Some(ids) = command.body["attachment_ids"]
                    .as_array()
                    .filter(|ids| ids.len() <= 64)
                else {
                    return Some(Err("Request up to 64 attachment states.".into()));
                };
                let mut result = serde_json::Map::new();
                for value in ids {
                    let Some(text) = value.as_str() else {
                        return Some(Err("Invalid attachment ID.".into()));
                    };
                    let Ok(id) = text.parse::<AttachmentId>() else {
                        return Some(Err("Invalid attachment ID.".into()));
                    };
                    let availability = state
                        .attachments
                        .get(&id)
                        .and_then(HostedAttachment::availability)
                        .unwrap_or(AttachmentAvailability::Missing);
                    result.insert(
                        text.into(),
                        serde_json::to_value(availability).expect("availability"),
                    );
                }
                Ok(Value::Object(result))
            }
            "attachment_retention" if owner => {
                let retention = match command.body["days"].as_u64() {
                    None if command.body["days"].is_null() => AttachmentRetention::Never,
                    Some(value @ (1 | 7 | 30 | 90 | 365)) => {
                        AttachmentRetention::Days(value as u32)
                    }
                    _ => return Some(Err("Choose Never, 1, 7, 30, 90 or 365 days.".into())),
                };
                state.attachment_policy.retention = retention;
                for attachment in state.attachments.values_mut() {
                    if matches!(attachment.state, HostedAttachmentState::Available) {
                        attachment.expires_at_ms =
                            state.attachment_policy.expires_at(attachment.created_at_ms);
                    }
                }
                if let Err(error) = self.save_service_state(state) {
                    return Some(Err(error));
                }
                Ok(json!({"policy":state.attachment_policy}))
            }
            "attachment_cleanup_preview" if owner => {
                let days = command.body["days"]
                    .as_u64()
                    .filter(|days| (1..=36500).contains(days));
                let Some(days) = days else {
                    return Some(Err(
                        "Enter a whole number of days between 1 and 36500.".into()
                    ));
                };
                let before_ms = current.saturating_sub(days * 86_400_000);
                let (files, bytes) = state
                    .attachments
                    .values()
                    .filter(|attachment| {
                        matches!(attachment.state, HostedAttachmentState::Available)
                            && attachment.created_at_ms <= before_ms
                    })
                    .fold((0u64, 0u64), |(files, bytes), attachment| {
                        (files + 1, bytes + attachment.encrypted_size)
                    });
                Ok(json!({"files":files,"bytes":bytes,"before_ms":before_ms,"days":days}))
            }
            "attachment_cleanup" if owner => {
                let before_ms = command.body["before_ms"]
                    .as_u64()
                    .filter(|value| *value <= current);
                if command.body["confirmed"] != true || before_ms.is_none() {
                    return Some(Err("Confirm attachment cleanup first.".into()));
                }
                let before_ms = before_ms.unwrap();
                let mut files = 0u64;
                let mut bytes = 0u64;
                for attachment in state.attachments.values_mut().filter(|attachment| {
                    matches!(attachment.state, HostedAttachmentState::Available)
                        && attachment.created_at_ms <= before_ms
                }) {
                    files += 1;
                    bytes += attachment.encrypted_size;
                    attachment.state = HostedAttachmentState::DeletingDeleted;
                }
                if let Err(error) = self.save_service_state(state) {
                    return Some(Err(error));
                }
                Ok(json!({"files":files,"bytes":bytes,"status":"scheduled"}))
            }
            _ if command.action.starts_with("attachment_") => {
                Err("You do not have permission to manage these attachments.".into())
            }
            _ => return None,
        };
        Some(result)
    }

    pub fn attachment_upload_grant(
        &self,
        token: &str,
        current: u64,
    ) -> Result<AttachmentTransferGrant> {
        let state = self.service_state()?;
        let access = state
            .attachment_access
            .get(&token_hash(token))
            .filter(|access| access.kind == "upload" && access.expires_at_ms >= current)
            .ok_or("Attachment upload authorization expired.")?;
        let attachment = state
            .attachments
            .get(&access.attachment)
            .ok_or("Attachment upload was not found.")?;
        if !matches!(attachment.state, HostedAttachmentState::Reserved) {
            return Err("Attachment upload is no longer pending.".into());
        }
        Ok(AttachmentTransferGrant {
            attachment_id: access.attachment,
            object_id: attachment.object_id,
            encrypted_size: attachment.encrypted_size,
            ciphertext_sha256: attachment.ciphertext_sha256.clone(),
        })
    }

    pub fn attachment_upload_complete(&self, token: &str, current: u64) -> Result<()> {
        let mut state = self.service_state()?;
        let key = token_hash(token);
        let access = state
            .attachment_access
            .remove(&key)
            .filter(|access| access.kind == "upload" && access.expires_at_ms >= current)
            .ok_or("Attachment upload authorization expired.")?;
        let attachment = state
            .attachments
            .get_mut(&access.attachment)
            .ok_or("Attachment upload was not found.")?;
        if !matches!(attachment.state, HostedAttachmentState::Reserved) {
            return Err("Attachment upload is no longer pending.".into());
        }
        attachment.state = HostedAttachmentState::Uploaded;
        self.save_service_state(&state)
    }

    pub fn attachment_download_grant(
        &self,
        token: &str,
        current: u64,
    ) -> Result<AttachmentTransferGrant> {
        let state = self.service_state()?;
        let access = state
            .attachment_access
            .get(&token_hash(token))
            .filter(|access| access.kind == "download" && access.expires_at_ms >= current)
            .ok_or("Attachment download authorization expired.")?;
        let attachment = state
            .attachments
            .get(&access.attachment)
            .ok_or("Attachment was not found.")?;
        if !matches!(attachment.state, HostedAttachmentState::Available) {
            return Err("Attachment is no longer available.".into());
        }
        Ok(AttachmentTransferGrant {
            attachment_id: access.attachment,
            object_id: attachment.object_id,
            encrypted_size: attachment.encrypted_size,
            ciphertext_sha256: attachment.ciphertext_sha256.clone(),
        })
    }

    pub fn attachment_cleanup_targets(
        &self,
        current: u64,
        limit: usize,
    ) -> Result<Vec<AttachmentCleanupTarget>> {
        let mut state = self.service_state()?;
        state
            .attachment_access
            .retain(|_, access| access.expires_at_ms >= current);
        let mut remove = Vec::new();
        for (id, attachment) in &mut state.attachments {
            if matches!(attachment.state, HostedAttachmentState::Reserved)
                && attachment.reservation_expires_at_ms < current
            {
                remove.push(*id);
            } else if matches!(attachment.state, HostedAttachmentState::Uploaded)
                && attachment.reservation_expires_at_ms < current
            {
                attachment.state = HostedAttachmentState::DeletingDeleted;
            } else if matches!(attachment.state, HostedAttachmentState::Available)
                && attachment
                    .expires_at_ms
                    .is_some_and(|expires| expires <= current)
            {
                attachment.state = HostedAttachmentState::DeletingExpired;
            } else if matches!(attachment.state, HostedAttachmentState::Available)
                && attachment.message_id.is_none()
                && attachment
                    .created_at_ms
                    .saturating_add(UNLINKED_UPLOAD_TTL_MS)
                    <= current
            {
                attachment.state = HostedAttachmentState::DeletingDeleted;
            }
        }
        for id in remove {
            state.attachments.remove(&id);
            state
                .attachment_access
                .retain(|_, access| access.attachment != id);
        }
        let targets = state
            .attachments
            .iter()
            .filter(|(_, attachment)| {
                matches!(
                    attachment.state,
                    HostedAttachmentState::DeletingExpired | HostedAttachmentState::DeletingDeleted
                )
            })
            .take(limit)
            .map(|(id, attachment)| AttachmentCleanupTarget {
                attachment_id: *id,
                object_id: attachment.object_id,
            })
            .collect();
        self.save_service_state(&state)?;
        Ok(targets)
    }

    pub fn attachment_all_targets(&self) -> Result<Vec<AttachmentCleanupTarget>> {
        Ok(self
            .service_state()?
            .attachments
            .iter()
            .filter(|(_, attachment)| {
                !matches!(
                    attachment.state,
                    HostedAttachmentState::Expired | HostedAttachmentState::Deleted
                )
            })
            .map(|(id, attachment)| AttachmentCleanupTarget {
                attachment_id: *id,
                object_id: attachment.object_id,
            })
            .collect())
    }

    pub fn attachment_storage_usage(&self) -> Result<AttachmentStorageUsage> {
        let state = self.service_state()?;
        let (used_bytes, reserved_bytes) = bytes_in_state(&state);
        Ok(AttachmentStorageUsage {
            used_bytes,
            reserved_bytes,
            files: state
                .attachments
                .values()
                .filter(|attachment| attachment.counts_as_used())
                .count(),
        })
    }

    pub fn attachment_cleanup_complete(&self, id: AttachmentId) -> Result<()> {
        let mut state = self.service_state()?;
        let attachment = state
            .attachments
            .get_mut(&id)
            .ok_or("Attachment was not found.")?;
        attachment.state = match attachment.state {
            HostedAttachmentState::DeletingExpired => HostedAttachmentState::Expired,
            HostedAttachmentState::DeletingDeleted => HostedAttachmentState::Deleted,
            _ => return Err("Attachment cleanup was not pending.".into()),
        };
        self.save_service_state(&state)
    }

    pub fn attachment_mark_missing(&self, id: AttachmentId) -> Result<()> {
        let mut state = self.service_state()?;
        let attachment = state
            .attachments
            .get_mut(&id)
            .ok_or("Attachment was not found.")?;
        attachment.state = HostedAttachmentState::Missing;
        self.save_service_state(&state)
    }
}

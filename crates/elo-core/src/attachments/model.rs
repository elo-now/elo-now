use crate::ids::{AttachmentId, AttachmentObjectId};
use serde::{Deserialize, Serialize};

pub const MAX_ATTACHMENT_FILE_SIZE: u64 = 5 * 1024 * 1024;
pub const MAX_SPACE_ATTACHMENT_STORAGE: u64 = 50_000_000;
pub const ATTACHMENT_CHUNK_BYTES: u32 = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentRetention {
    Never,
    Days(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttachmentPolicy {
    pub enabled: bool,
    pub max_file_bytes: u64,
    pub max_space_bytes: u64,
    pub retention: AttachmentRetention,
}

impl Default for AttachmentPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_file_bytes: MAX_ATTACHMENT_FILE_SIZE,
            max_space_bytes: MAX_SPACE_ATTACHMENT_STORAGE,
            retention: AttachmentRetention::Never,
        }
    }
}

impl AttachmentPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_file_bytes != MAX_ATTACHMENT_FILE_SIZE
            || self.max_space_bytes != MAX_SPACE_ATTACHMENT_STORAGE
            || matches!(self.retention, AttachmentRetention::Days(0))
        {
            return Err("Invalid attachment policy.");
        }
        Ok(())
    }

    pub fn expires_at(&self, created_at_ms: u64) -> Option<u64> {
        match self.retention {
            AttachmentRetention::Never => None,
            AttachmentRetention::Days(days) => {
                created_at_ms.checked_add(u64::from(days).checked_mul(86_400_000)?)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentAvailability {
    Available,
    Expired,
    Deleted,
    Missing,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttachmentEncryption {
    pub algorithm: String,
    pub key: String,
    pub nonce_prefix: String,
    pub chunk_bytes: u32,
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttachmentDescriptor {
    pub id: AttachmentId,
    pub name: String,
    pub mime: String,
    pub plaintext_size: u64,
    pub encrypted_size: u64,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub object_id: AttachmentObjectId,
    pub encryption: AttachmentEncryption,
}

impl AttachmentDescriptor {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.name.is_empty()
            || self.name.len() > 255
            || self.name == "."
            || self.name == ".."
            || self
                .name
                .chars()
                .any(|c| crate::record::unsafe_display_character(c) || c == '/' || c == '\\')
            || self.mime.is_empty()
            || self.mime.len() > 127
            || !self.mime.contains('/')
            || !self.mime.bytes().all(|b| b.is_ascii_graphic())
            || self.plaintext_size > MAX_ATTACHMENT_FILE_SIZE
            || self.encrypted_size
                != crate::attachments::crypto::encrypted_size(self.plaintext_size)
            || self.encryption.algorithm != "xchacha20-poly1305-chunks-v1"
            || self.encryption.chunk_bytes != ATTACHMENT_CHUNK_BYTES
            || crate::record::hex::<32>(&self.encryption.ciphertext_sha256).is_err()
        {
            return Err("Invalid attachment descriptor.");
        }
        use base64::{Engine, engine::general_purpose::STANDARD};
        let key = STANDARD
            .decode(&self.encryption.key)
            .map_err(|_| "Invalid attachment key.")?;
        let nonce = STANDARD
            .decode(&self.encryption.nonce_prefix)
            .map_err(|_| "Invalid attachment nonce.")?;
        if key.len() != 32 || nonce.len() != 16 {
            return Err("Invalid attachment encryption metadata.");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_defaults_are_canonical() {
        let policy = AttachmentPolicy::default();
        assert!(policy.validate().is_ok());
        assert_eq!(policy.max_file_bytes, 5 * 1024 * 1024);
        assert_eq!(policy.max_space_bytes, 50_000_000);
        assert_eq!(policy.expires_at(1), None);
    }

    #[test]
    fn retention_uses_attachment_creation_time() {
        let policy = AttachmentPolicy {
            retention: AttachmentRetention::Days(30),
            ..AttachmentPolicy::default()
        };
        assert_eq!(policy.expires_at(1_000), Some(2_592_001_000));
    }
}

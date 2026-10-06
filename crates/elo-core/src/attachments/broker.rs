//! Direct, device-signed requests to the independent attachment broker.
//! Provider credentials belong only in a configure request over pinned HTTPS.
//! They must never be sent through the Space API or persisted in client views.
use crate::{
    authority::{Authority, CallAuthorityProof, Capability},
    ids::{AttachmentObjectId, RecordId, SpaceId, StreamId},
    record::{self, RecordError, Result, SignedRecord},
    vault::Session,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const COMMAND_TTL: u64 = 60;
pub const CONFIGURE_TTL: u64 = 180;
pub const TRANSFER_TTL: u64 = 120;
pub const MAX_REQUEST_BYTES: usize = 9 * 1024 * 1024;

// Deliberately no Debug: configuration contains limited provider credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderConfig {
    MegaFolder {
        folder_link: String,
        write_auth: String,
    },
    S3Compatible {
        endpoint: String,
        region: String,
        bucket: String,
        access_key: String,
        secret_key: String,
    },
}
impl Drop for ProviderConfig {
    fn drop(&mut self) {
        match self {
            Self::MegaFolder {
                folder_link,
                write_auth,
            } => {
                folder_link.zeroize();
                write_auth.zeroize();
            }
            Self::S3Compatible {
                access_key,
                secret_key,
                ..
            } => {
                access_key.zeroize();
                secret_key.zeroize();
            }
        }
    }
}
impl ProviderConfig {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MegaFolder { .. } => "mega_folder",
            Self::S3Compatible { .. } => "s3_compatible",
        }
    }
    pub fn validate(&self) -> Result<()> {
        let values: Vec<&str> = match self {
            Self::MegaFolder {
                folder_link,
                write_auth,
            } => vec![folder_link, write_auth],
            Self::S3Compatible {
                endpoint,
                region,
                bucket,
                access_key,
                secret_key,
            } => vec![endpoint, region, bucket, access_key, secret_key],
        };
        if values
            .iter()
            .any(|v| v.is_empty() || v.len() > 4096 || v.chars().any(char::is_control))
        {
            return Err(RecordError::Json);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Status,
    Configure {
        expected_revision: u64,
        provider: ProviderConfig,
        retention_hours: u32,
    },
    ConfigureManaged {
        expected_revision: u64,
        retention_hours: u32,
    },
    Policy {
        expected_revision: u64,
        retention_hours: u32,
    },
    Disable {
        expected_revision: u64,
    },
    Reserve {
        object_id: AttachmentObjectId,
        encrypted_size: u64,
        ciphertext_sha256: String,
    },
    Complete {
        object_id: AttachmentObjectId,
    },
    Download {
        object_id: AttachmentObjectId,
    },
    Cancel {
        object_id: AttachmentObjectId,
    },
}
impl Operation {
    pub fn ttl(&self) -> u64 {
        if matches!(self, Self::Configure { .. } | Self::ConfigureManaged { .. }) {
            CONFIGURE_TTL
        } else {
            COMMAND_TTL
        }
    }
    pub fn validate(&self, _now: u64) -> Result<()> {
        match self {
            Self::Configure {
                expected_revision,
                provider,
                retention_hours,
            } => {
                if *expected_revision >= record::MAX_INTEGER
                    || !matches!(retention_hours, 1 | 12 | 24)
                {
                    return Err(RecordError::Json);
                }
                provider.validate()?;
            }
            Self::ConfigureManaged {
                expected_revision,
                retention_hours,
            }
            | Self::Policy {
                expected_revision,
                retention_hours,
            } => {
                if *expected_revision >= record::MAX_INTEGER
                    || !matches!(retention_hours, 1 | 12 | 24)
                {
                    return Err(RecordError::Json);
                }
            }
            Self::Reserve {
                encrypted_size,
                ciphertext_sha256,
                ..
            } => {
                record::hex::<32>(ciphertext_sha256)?;
                if *encrypted_size == 0
                    || *encrypted_size
                        > super::crypto::encrypted_size(super::MAX_ATTACHMENT_FILE_SIZE)
                {
                    return Err(RecordError::Json);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub command: String,
    pub proof: CallAuthorityProof,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub v: u8,
    pub kind: String,
    pub audience: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub config_id: RecordId,
    pub credential_id: RecordId,
    pub nonce: String,
    pub work: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub operation: Operation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageStatus {
    pub configured: bool,
    pub enabled: bool,
    pub provider: Option<String>,
    pub revision: u64,
    pub used_bytes: u64,
    pub max_space_bytes: u64,
    pub max_file_bytes: u64,
    /// None means an owner has not signed a policy; new reservations are blocked.
    pub retention_hours: Option<u32>,
}

// Transfer tokens must not appear in diagnostic Debug output.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Status {
        status: StorageStatus,
    },
    Transfer {
        object_id: AttachmentObjectId,
        url: String,
        token: String,
        expires_at: u64,
        object_expires_at_ms: u64,
    },
    Complete {
        object_id: AttachmentObjectId,
    },
    Cancelled {
        object_id: AttachmentObjectId,
    },
}

pub fn require_member(authority: &Authority, credential: RecordId, write: bool) -> Result<()> {
    if !authority.is_owner_managed() || authority.is_forked() {
        return Err(RecordError::Authority);
    }
    let genesis: crate::authority::SpaceGenesis = authority.genesis().decode()?;
    if genesis.nonce != authority.stream().to_string()
        || authority.head()?.chat_kind != Some(crate::authority::ChatKind::Chat)
    {
        return Err(RecordError::Authority);
    }
    let device = authority.credential(credential)?;
    if !authority.head()?.members.iter().any(|member| {
        member.identity_id == device.identity()
            && member.credential_ids.contains(&credential)
            && member.capabilities.contains(&Capability::Read)
            && (!write || member.capabilities.contains(&Capability::Post))
    }) {
        return Err(RecordError::Authority);
    }
    Ok(())
}

pub fn sign_command(
    authority: &Authority,
    session: &Session,
    audience: &str,
    operation: Operation,
    now: u64,
) -> Result<SignedRecord> {
    require_member(
        authority,
        session.credential().id(),
        !matches!(operation, Operation::Status | Operation::Download { .. }),
    )?;
    if audience.is_empty() || audience.len() > 2048 || audience.chars().any(char::is_control) {
        return Err(RecordError::Authority);
    }
    operation.validate(now)?;
    let mut command = Command {
        v: 1,
        kind: "storage.command".into(),
        audience: audience.into(),
        space_id: authority.space(),
        stream_id: authority.stream(),
        config_id: authority.head_id().ok_or(RecordError::Authority)?,
        credential_id: session.credential().id(),
        nonce: record::random_hex::<16>()?,
        work: String::new(),
        issued_at: now,
        expires_at: now.saturating_add(operation.ttl()),
        operation,
    };
    if matches!(
        command.operation,
        Operation::Configure {
            expected_revision: 0,
            ..
        } | Operation::ConfigureManaged {
            expected_revision: 0,
            ..
        }
    ) {
        let base = work_base(&command)?;
        for nonce in 0..u64::MAX {
            if valid_work(&base, nonce) {
                command.work = record::encode_hex(&nonce.to_be_bytes());
                break;
            }
        }
    }
    SignedRecord::sign(
        &serde_json::to_vec(&command).map_err(|_| RecordError::Json)?,
        session.signing_key(),
    )
}

pub fn verify_command(
    authority: &Authority,
    signed: &SignedRecord,
    audience: &str,
    now: u64,
) -> Result<Command> {
    let command: Command = signed.decode()?;
    if command.v != 1
        || command.kind != "storage.command"
        || command.audience != audience
        || command.space_id != authority.space()
        || command.stream_id != authority.stream()
        || Some(command.config_id) != authority.head_id()
        || command.issued_at > now.saturating_add(15)
        || command.expires_at <= now
        || command.expires_at <= command.issued_at
        || command.expires_at > command.issued_at.saturating_add(command.operation.ttl())
    {
        return Err(RecordError::Authority);
    }
    record::hex::<16>(&command.nonce)?;
    require_member(
        authority,
        command.credential_id,
        !matches!(
            command.operation,
            Operation::Status | Operation::Download { .. }
        ),
    )?;
    signed.verify_signature(authority.credential(command.credential_id)?.key())?;
    if matches!(
        command.operation,
        Operation::Configure { .. }
            | Operation::ConfigureManaged { .. }
            | Operation::Policy { .. }
            | Operation::Disable { .. }
    ) && !authority.can_manage(command.credential_id)
    {
        return Err(RecordError::Authority);
    }
    command.operation.validate(now)?;
    if matches!(
        command.operation,
        Operation::Configure {
            expected_revision: 0,
            ..
        } | Operation::ConfigureManaged {
            expected_revision: 0,
            ..
        }
    ) {
        let nonce = u64::from_be_bytes(record::hex::<8>(&command.work)?);
        if !valid_work(&work_base(&command)?, nonce) {
            return Err(RecordError::Authority);
        }
    } else if !command.work.is_empty() {
        return Err(RecordError::Json);
    }
    Ok(command)
}

fn work_base(command: &Command) -> Result<[u8; 32]> {
    let mut blank = command.clone();
    blank.work.clear();
    let bytes = serde_json::to_vec(&blank).map_err(|_| RecordError::Json)?;
    let mut hash = Sha256::new();
    hash.update(b"elo.now/storage-registration/v1\0");
    hash.update(bytes);
    Ok(hash.finalize().into())
}
fn valid_work(base: &[u8; 32], nonce: u64) -> bool {
    let mut hash = Sha256::new();
    hash.update(base);
    hash.update(nonce.to_be_bytes());
    let out = hash.finalize();
    out[0] == 0 && out[1] == 0 && out[2] < 16
}

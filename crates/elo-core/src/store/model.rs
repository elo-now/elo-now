use crate::ids::{MailboxId, ObjectId, PeerId, RecordId, SpaceId, StreamId};

use super::StoreError;

pub const MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_INITIAL_TARGETS: usize = 128;
pub const MAX_QUERY_LIMIT: usize = 128;
pub(crate) const QUEUE_CAPACITY: usize = 8;

/// Local scheduling time, never an authorization timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime(i64);

impl LocalTime {
    pub fn from_millis(value: u64) -> Result<Self, StoreError> {
        i64::try_from(value)
            .map(Self)
            .map_err(|_| StoreError::InvalidInput("timestamp exceeds SQLite INTEGER"))
    }

    pub const fn as_millis(self) -> i64 {
        self.0
    }
}

/// A local index, not proof that the referenced record/config is authentic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMetadata {
    kind: String,
    space_id: Option<SpaceId>,
    stream_id: Option<StreamId>,
    config_id: Option<RecordId>,
}

impl RecordMetadata {
    pub fn new(
        kind: impl Into<String>,
        space_id: Option<SpaceId>,
        stream_id: Option<StreamId>,
        config_id: Option<RecordId>,
    ) -> Result<Self, StoreError> {
        let kind = kind.into();
        if kind.is_empty()
            || kind.len() > 64
            || !kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(StoreError::InvalidInput("invalid index kind"));
        }
        Ok(Self {
            kind,
            space_id,
            stream_id,
            config_id,
        })
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub const fn space_id(&self) -> Option<SpaceId> {
        self.space_id
    }
    pub const fn stream_id(&self) -> Option<StreamId> {
        self.stream_id
    }
    pub const fn config_id(&self) -> Option<RecordId> {
        self.config_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeliveryTarget {
    pub peer_id: PeerId,
    pub mailbox_id: MailboxId,
}

/// Prepared input to one local commit. Bytes are NOT logged by Debug.
///
/// This storage-only constructor does not validate ciphertext or signatures. The
/// eventual domain layer must do that before calling it. Retry reuses this input;
/// do not re-encrypt. Initial targets are immutable through this operation.
#[derive(Clone)]
pub struct PreparedLocalRecord {
    pub(crate) record_id: RecordId,
    pub(crate) object_id: ObjectId,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) metadata: RecordMetadata,
    pub(crate) targets: Vec<DeliveryTarget>,
    pub(crate) created: LocalTime,
}

impl PreparedLocalRecord {
    pub fn new(
        record_id: RecordId,
        ciphertext: Vec<u8>,
        metadata: RecordMetadata,
        mut targets: Vec<DeliveryTarget>,
        created: LocalTime,
    ) -> Result<Self, StoreError> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_OBJECT_BYTES {
            return Err(StoreError::InvalidInput(
                "object must contain 1..=16 MiB of bytes",
            ));
        }
        if targets.len() > MAX_INITIAL_TARGETS {
            return Err(StoreError::InvalidInput(
                "too many initial delivery targets",
            ));
        }
        targets.sort_unstable();
        if targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StoreError::InvalidInput(
                "duplicate initial delivery target",
            ));
        }
        Ok(Self {
            record_id,
            object_id: ObjectId::of_ciphertext(&ciphertext),
            ciphertext,
            metadata,
            targets,
            created,
        })
    }

    pub const fn record_id(&self) -> RecordId {
        self.record_id
    }
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitDisposition {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitResult {
    pub record_id: RecordId,
    pub object_id: ObjectId,
    pub disposition: CommitDisposition,
    pub target_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreStats {
    pub objects: u64,
    pub records: u64,
    pub sources: u64,
    pub pending: u64,
    pub inflight: u64,
    pub stored: u64,
    pub held: u64,
    pub rejected: u64,
}

/// A particular attempt. Its private counter prevents stale completion updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryAttempt {
    pub(crate) record_id: RecordId,
    pub(crate) object_id: ObjectId,
    pub(crate) target: DeliveryTarget,
    pub(crate) number: i64,
}

impl DeliveryAttempt {
    pub const fn record_id(self) -> RecordId {
        self.record_id
    }
    pub const fn object_id(self) -> ObjectId {
        self.object_id
    }
    pub const fn target(self) -> DeliveryTarget {
        self.target
    }
    pub const fn number(self) -> i64 {
        self.number
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDelivery {
    pub record_id: RecordId,
    pub object_id: ObjectId,
    pub target: DeliveryTarget,
    pub attempts: i64,
    pub next_attempt_local_ms: i64,
}

/// Only constant, non-secret error codes are persisted in the outbox.
#[derive(Debug, Clone, Copy)]
pub enum RetryReason {
    NetworkUnavailable,
    Timeout,
    RemoteUnavailable,
}

impl RetryReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkUnavailable => "NETWORK_UNAVAILABLE",
            Self::Timeout => "TIMEOUT",
            Self::RemoteUnavailable => "REMOTE_UNAVAILABLE",
        }
    }
}

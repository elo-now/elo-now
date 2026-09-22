//! Bounded metadata exchanged only by authenticated call-control and wake services.
use super::CallScope;
use crate::ids::{IdentityId, RecordId, SpaceId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub identity: IdentityId,
    pub credential: RecordId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum Notice {
    Ring {
        call_id: String,
        scope: String,
        head: RecordId,
        caller: IdentityId,
        recipients: Vec<Recipient>,
        expires: u64,
        video: bool,
    },
    End {
        call_id: String,
    },
}

impl Notice {
    pub fn call_id(&self) -> &str {
        match self {
            Self::Ring { call_id, .. } | Self::End { call_id } => call_id,
        }
    }
    pub fn valid(&self, now: u64) -> bool {
        if crate::record::hex::<16>(self.call_id()).is_err() {
            return false;
        }
        match self {
            Self::End { .. } => true,
            Self::Ring {
                scope,
                caller,
                recipients,
                expires,
                ..
            } => {
                crate::record::hex::<32>(scope).is_ok()
                    && *expires > now
                    && *expires <= now.saturating_add(60)
                    && !recipients.is_empty()
                    && recipients.len() <= 16
                    && recipients.iter().all(|r| r.identity != *caller)
                    && recipients
                        .iter()
                        .map(|r| r.credential)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == recipients.len()
            }
        }
    }
}

pub fn scope(hosting: SpaceId, conversation: CallScope) -> String {
    let mut hash = Sha256::new();
    hash.update(b"elo.now/call-notification-scope/v1\0");
    hash.update(hosting.as_bytes());
    hash.update(conversation.space_id.as_bytes());
    hash.update(conversation.stream_id.as_bytes());
    crate::record::encode_hex(&hash.finalize())
}

//! Message-specific capabilities. Seeds remain inside authenticated encrypted
//! records; the Replica receives only public keys and context-bound signatures.
use crate::{
    ids::{IdentityId, MailboxId, ObjectId, PeerId, RecordId},
    record::{self, RecordError},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const WINDOW_MS: u64 = 300_000;

/// Supplied by the authenticated transport, never by the control JSON body.
#[derive(Clone, Copy, Serialize)]
pub struct Actor {
    pub identity: IdentityId,
    pub credential: RecordId,
}
impl From<&crate::identity::VerifiedCredential> for Actor {
    fn from(value: &crate::identity::VerifiedCredential) -> Self {
        Self {
            identity: value.identity(),
            credential: value.id(),
        }
    }
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Request,
    Accept,
}

#[derive(Serialize)]
pub struct Context {
    pub operation: Operation,
    pub replica: PeerId,
    pub mailbox: MailboxId,
    pub object: ObjectId,
    pub record: RecordId,
    pub actor: Actor,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub expires_ms: u64,
    pub nonce: String,
    pub signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub record_id: RecordId,
    pub proof: Proof,
}

pub fn public_key(seed: &str) -> record::Result<String> {
    let seed = zeroize::Zeroizing::new(record::hex::<32>(seed)?);
    Ok(record::encode_hex(
        SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
    ))
}
pub fn valid_key(key: &str) -> bool {
    record::hex::<32>(key)
        .ok()
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .is_some_and(|key| !key.is_weak())
}
impl Proof {
    fn bytes(&self, context: &Context) -> record::Result<Vec<u8>> {
        serde_json::to_vec(&(
            "elo.message-access.v1",
            context,
            self.expires_ms,
            &self.nonce,
        ))
        .map_err(|_| RecordError::Json)
    }
    pub fn issue(seed: &str, context: &Context, now: u64) -> record::Result<Self> {
        let seed = zeroize::Zeroizing::new(record::hex::<32>(seed)?);
        let mut proof = Self {
            expires_ms: now.checked_add(WINDOW_MS).ok_or(RecordError::Json)?,
            nonce: record::random_hex::<16>()?,
            signature: String::new(),
        };
        proof.signature = record::encode_hex(
            &SigningKey::from_bytes(&seed)
                .sign(&proof.bytes(context)?)
                .to_bytes(),
        );
        Ok(proof)
    }
    pub fn verify(&self, key: &str, context: &Context, now: u64) -> record::Result<()> {
        // A captured proof cannot start a fresh window after its signed deadline.
        if self.expires_ms <= now
            || self.expires_ms > now.saturating_add(WINDOW_MS + 120_000)
            || record::hex::<16>(&self.nonce).is_err()
        {
            return Err(RecordError::Authority);
        }
        let key = VerifyingKey::from_bytes(&record::hex::<32>(key)?)
            .map_err(|_| RecordError::Authority)?;
        key.verify_strict(
            &self.bytes(context)?,
            &Signature::from_bytes(&record::hex::<64>(&self.signature)?),
        )
        .map_err(|_| RecordError::Authority)
    }
}

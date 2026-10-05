//! Upload authorization for the ciphertext behind short invitation links.
//! Only the independently pinned hosting WitnessGate may supply the freshness
//! lease accepted here. The public read route returns ciphertext alone.
mod ingress;
mod routes;
pub(super) use routes::{download, upload};
mod store;
pub(crate) use ingress::Ingress;
pub(crate) use store::{Error, Result, Store};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use elo_core::{
    authority::{Authority, WitnessPin},
    ids::{IdentityId, ObjectId, RecordId, SpaceId, StreamId},
    record::{self, SignedRecord},
    witness::VerifiedFreshness,
};
use serde::{Deserialize, Serialize};

const SIGNED_RECORD_BYTES: usize = 16_384;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UploadRequest {
    pub command: String,
    pub policy: String,
    pub ciphertext: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UploadCommand {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub audience: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub authority_head: RecordId,
    pub credential_id: RecordId,
    pub policy_id: RecordId,
    pub ciphertext_id: ObjectId,
    pub ciphertext_size: u64,
    pub ciphertext_expires_at_ms: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Fields are private so unverified requests cannot reach Store::put through the
/// public module interface. Host-level account/device revocations must also be
/// checked for both identities before committing while the Space guard is held.
pub(crate) struct PreparedUpload {
    command: UploadCommand,
    policy_issuer: RecordId,
    uploader: IdentityId,
    issuer: IdentityId,
    ciphertext: Vec<u8>,
    pin: WitnessPin,
}
impl PreparedUpload {
    pub fn uploader(&self) -> (IdentityId, RecordId) {
        (self.uploader, self.command.credential_id)
    }
    pub fn policy_issuer(&self) -> (IdentityId, RecordId) {
        (self.issuer, self.policy_issuer)
    }
    pub fn digest(&self) -> ObjectId {
        self.command.ciphertext_id
    }
    pub fn ciphertext_expires_at_ms(&self) -> u64 {
        self.command.ciphertext_expires_at_ms
    }

    /// Recheck after any awaited witness/worker operation. The caller must hold
    /// the hosted Space's serving/client/account guards across this short commit
    /// and call WitnessGate::check to recheck the persisted global witness floor.
    pub fn commit(
        &self,
        store: &mut Store,
        authority: &Authority,
        freshness: &VerifiedFreshness,
        now_ms: u64,
    ) -> Result<bool> {
        require_authority(authority, &self.pin, &self.command, freshness, now_ms)?;
        if !authority.can_manage(self.policy_issuer) {
            return Err(Error::Unauthorized);
        }
        store.put(
            &store::Binding {
                space: self.command.space_id,
                stream: self.command.stream_id,
                policy: self.command.policy_id,
                digest: self.command.ciphertext_id,
                size: self.command.ciphertext_size,
                expires_at_ms: self.command.ciphertext_expires_at_ms,
            },
            &self.ciphertext,
            now_ms,
        )
    }
}

fn decode(encoded: &str) -> Result<SignedRecord> {
    if encoded.len() > SIGNED_RECORD_BYTES {
        return Err(Error::Invalid);
    }
    SignedRecord::parse(&STANDARD.decode(encoded).map_err(|_| Error::Invalid)?)
        .map_err(|_| Error::Invalid)
}

pub(crate) fn prepare(
    request: UploadRequest,
    authority: &Authority,
    configured_pin: &WitnessPin,
    expected_audience: &str,
    freshness: &VerifiedFreshness,
    now_ms: u64,
) -> Result<PreparedUpload> {
    if request.ciphertext.len() > store::MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
        return Err(Error::Invalid);
    }
    let signed = decode(&request.command)?;
    let command: UploadCommand = signed.decode().map_err(|_| Error::Invalid)?;
    if command.audience != expected_audience {
        return Err(Error::Unauthorized);
    }
    require_authority(authority, configured_pin, &command, freshness, now_ms)?;
    let credential = authority
        .credential(command.credential_id)
        .map_err(|_| Error::Unauthorized)?;
    signed
        .verify_signature(credential.key())
        .map_err(|_| Error::Unauthorized)?;
    let policy_record = decode(&request.policy)?;
    let policy = authority
        .verify_witness_invitation(&policy_record, now_ms)
        .map_err(|_| Error::Unauthorized)?;
    if policy_record.id() != command.policy_id
        || command.ciphertext_expires_at_ms > policy.expires_at_ms
    {
        return Err(Error::Unauthorized);
    }
    let ciphertext = STANDARD
        .decode(request.ciphertext)
        .map_err(|_| Error::Invalid)?;
    if !(113..=store::MAX_CIPHERTEXT_BYTES).contains(&ciphertext.len())
        || ciphertext[0] != 1
        || command.ciphertext_size != ciphertext.len() as u64
        || command.ciphertext_id != store::ciphertext_id(&ciphertext)
    {
        return Err(Error::Invalid);
    }
    Ok(PreparedUpload {
        policy_issuer: policy.issuer_credential_id,
        uploader: credential.identity(),
        issuer: authority
            .credential(policy.issuer_credential_id)
            .map_err(|_| Error::Unauthorized)?
            .identity(),
        command,
        ciphertext,
        pin: configured_pin.clone(),
    })
}

fn require_authority(
    authority: &Authority,
    configured_pin: &WitnessPin,
    command: &UploadCommand,
    freshness: &VerifiedFreshness,
    now_ms: u64,
) -> Result<()> {
    command
        .nonce
        .parse::<RecordId>()
        .map_err(|_| Error::Invalid)?;
    let head = authority.head().map_err(|_| Error::Unauthorized)?;
    let lease = freshness.body();
    if command.v != 1
        || command.kind != "invitation.descriptor.put"
        || command.expires_at_ms <= command.issued_at_ms
        || command.expires_at_ms - command.issued_at_ms > 60_000
        || command.expires_at_ms > record::MAX_INTEGER
        || command.issued_at_ms > now_ms.saturating_add(5_000)
        || now_ms >= command.expires_at_ms
        || command.ciphertext_expires_at_ms <= now_ms
        || command.ciphertext_expires_at_ms > now_ms.saturating_add(store::MAX_TTL_MS)
        || command.ciphertext_expires_at_ms > record::MAX_INTEGER
        || authority.witness_pin() != Some(configured_pin)
        || head.v != 4
        || authority.space() != command.space_id
        || authority.stream() != command.stream_id
        || authority.head_id() != Some(command.authority_head)
        || !authority.can_manage(command.credential_id)
        || lease.audience != configured_pin.url
        || lease.witness_key_generation != configured_pin.key_generation
        || lease.space_id != command.space_id
        || lease.stream_id != command.stream_id
        || lease.authority_head != command.authority_head
        || !freshness.is_valid(now_ms)
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

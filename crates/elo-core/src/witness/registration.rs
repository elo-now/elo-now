//! A hosting operator authorizes one bounded Space allocation before the
//! independent witness records it. The verifier supplies the trusted host key.
use crate::{
    ids::{IdentityId, RecordId, SpaceId, StreamId},
    record::{self, RecordError, SignedRecord},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const MAX_TICKET_BYTES: usize = 8192;
pub const MAX_TICKET_LIFETIME_MS: u64 = 600_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationHost {
    pub host: String,
    pub public_key: String,
}

impl RegistrationHost {
    pub fn validate(&self) -> record::Result<()> {
        if self.host.len() > 2048 {
            return Err(RecordError::Framing);
        }
        crate::app::space_host::validate_host(&self.host, true)
            .map_err(|_| RecordError::Authority)?;
        VerifyingKey::from_bytes(&record::hex::<32>(&self.public_key)?)
            .map_err(|_| RecordError::Signature)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationTicket {
    pub v: u8,
    pub kind: String,
    pub audience: String,
    pub witness_public_key: String,
    pub witness_key_generation: u64,
    pub host: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub authority_head: RecordId,
    pub creator_identity: IdentityId,
    pub credential_id: RecordId,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub reservation_id: String,
}

impl RegistrationTicket {
    pub fn validate(&self) -> record::Result<()> {
        if self.host.len() > 2048 {
            return Err(RecordError::Framing);
        }
        crate::app::space_host::validate_host(&self.host, true)
            .map_err(|_| RecordError::Authority)?;
        crate::authority::WitnessPin {
            url: self.audience.clone(),
            public_key: self.witness_public_key.clone(),
            key_generation: self.witness_key_generation,
        }
        .validate()?;
        record::hex::<32>(&self.reservation_id)?;
        if self.v != 1
            || self.kind != "witness.registration_ticket"
            || self.issued_at_ms >= self.expires_at_ms
            || self.expires_at_ms > record::MAX_INTEGER
            || self.expires_at_ms - self.issued_at_ms > MAX_TICKET_LIFETIME_MS
        {
            return Err(RecordError::Authority);
        }
        Ok(())
    }

    pub fn sign(&self, key: &[u8; 32]) -> record::Result<SignedRecord> {
        self.validate()?;
        SignedRecord::sign_bounded(
            &serde_json::to_vec(self).map_err(|_| RecordError::Json)?,
            &SigningKey::from_bytes(key),
            MAX_TICKET_BYTES,
        )
    }

    /// Parsing does not establish trust. The caller must verify the returned
    /// record against its operator-configured key and bind every target field.
    pub fn parse(encoded: &str) -> record::Result<(Self, SignedRecord)> {
        if encoded.len() > MAX_TICKET_BYTES * 2 {
            return Err(RecordError::Framing);
        }
        let bytes = STANDARD.decode(encoded).map_err(|_| RecordError::Framing)?;
        let signed = SignedRecord::parse_bounded(&bytes, MAX_TICKET_BYTES)?;
        let body: Self = signed.decode()?;
        body.validate()?;
        Ok((body, signed))
    }
}

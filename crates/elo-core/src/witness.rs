//! Public, signed requests and nonce-bound freshness for independent authorization.
pub mod link;

use crate::{
    authority::{
        CallAuthorityProof, WitnessAdmissionEvidence, WitnessAdmissionEvidenceV2,
        WitnessJoinRequestEvidence,
    },
    ids::{RecordId, SpaceId, StreamId},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<CallAuthorityProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_work: Option<u64>,
}

impl Request {
    fn registration_work_prefix(&self) -> crate::record::Result<sha2::Sha256> {
        use crate::record::RecordError;
        use sha2::{Digest, Sha256};
        let proof = self.proof.as_ref().ok_or(RecordError::Authority)?;
        // Registration only accepts the initial, single-owner configuration.
        // Bound untrusted work before verifying any supplied authority chain.
        if self.command.len() > 16_384
            || proof.v != 1
            || proof.checkpoint.is_some()
            || proof.configs.len() != 1
            || proof.credentials.len() != 1
            || proof.genesis.len() + proof.configs[0].len() + proof.credentials[0].len() > 65_536
        {
            return Err(RecordError::Framing);
        }
        let proof = serde_json::to_vec(proof).map_err(|_| RecordError::Json)?;
        let mut prefix = Sha256::new();
        prefix.update(b"elo.witness.registration-work.v1\0");
        prefix.update(Sha256::digest(self.command.as_bytes()));
        prefix.update(Sha256::digest(&proof));
        Ok(prefix)
    }

    pub fn verify_registration_work(&self) -> crate::record::Result<()> {
        use sha2::Digest;
        let nonce = self
            .registration_work
            .ok_or(crate::record::RecordError::Authority)?;
        if nonce > crate::record::MAX_INTEGER {
            return Err(crate::record::RecordError::Authority);
        }
        let mut hash = self.registration_work_prefix()?;
        hash.update(nonce.to_be_bytes());
        let digest = hash.finalize();
        if digest[0] != 0 || digest[1] != 0 || digest[2] & 0xf0 != 0 {
            return Err(crate::record::RecordError::Authority);
        }
        Ok(())
    }

    /// Run on a blocking worker, after signing the final registration command.
    /// Work cannot be reused for a different command, witness, owner or proof.
    pub fn solve_registration_work(&mut self) -> crate::record::Result<()> {
        use sha2::Digest;
        let prefix = self.registration_work_prefix()?;
        for nonce in 0..=crate::record::MAX_INTEGER {
            let mut hash = prefix.clone();
            hash.update(nonce.to_be_bytes());
            let digest = hash.finalize();
            if digest[0] == 0 && digest[1] == 0 && digest[2] & 0xf0 == 0 {
                self.registration_work = Some(nonce);
                return Ok(());
            }
        }
        Err(crate::record::RecordError::Authority)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub audience: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub credential_id: RecordId,
    pub authority_head: RecordId,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Register,
    RegisterInvitation {
        policy: String,
    },
    RevokeInvitation {
        policy_id: RecordId,
    },
    Challenge {
        policy_id: RecordId,
        credential: String,
        client_nonce: String,
    },
    Admit {
        credential: String,
        evidence: WitnessAdmissionEvidence,
    },
    ChallengeV2 {
        credential: String,
        request: WitnessJoinRequestEvidence,
        client_nonce: String,
    },
    AdmitV2 {
        credential: String,
        evidence: WitnessAdmissionEvidenceV2,
    },
    OwnerUpdate {
        proposal: String,
        credentials: Vec<String>,
    },
    Read,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadRequest {
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub nonce: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<CallAuthorityProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    pub sequence: u64,
    pub record_id: Option<RecordId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub v: u8,
    pub kind: String,
    pub audience: String,
    pub sequence: u64,
    pub previous: Option<RecordId>,
    pub request_id: RecordId,
    pub space_id: SpaceId,
    pub authority_head: RecordId,
    pub state_digest: String,
    pub accepted_at_ms: u64,
    pub event: String,
    pub witness_key_generation: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Freshness {
    pub v: u8,
    pub kind: String,
    pub audience: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub authority_head: RecordId,
    pub position: Position,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub witness_key_generation: u64,
}

/// This lease is local and must be discarded on lock, process restart or resume
/// from sleep. A cache hit never extends its deadline.
pub struct VerifiedFreshness {
    body: Freshness,
    requested_at: std::time::Instant,
}

impl VerifiedFreshness {
    pub fn body(&self) -> &Freshness {
        &self.body
    }

    pub fn is_valid(&self, now_ms: u64) -> bool {
        self.requested_at.elapsed() < std::time::Duration::from_secs(30)
            && now_ms >= self.body.issued_at_ms.saturating_sub(5_000)
            && now_ms < self.body.expires_at_ms
    }
}

/// Trust comes from the configured key, never a pin contained in the response.
/// `requested_at` must be captured before sending this freshly generated nonce.
/// Persist the resulting position and verify authority ancestry before adopting
/// another membership head. A valid signature is not a substitute for freshness.
pub fn verify_freshness(
    pin: &crate::authority::WitnessPin,
    request: &HeadRequest,
    encoded: &str,
    requested_at: std::time::Instant,
    now_ms: u64,
    floor: Option<&Position>,
) -> crate::record::Result<VerifiedFreshness> {
    use crate::record::{self, RecordError, SignedRecord};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    pin.validate()?;
    record::hex::<32>(&request.nonce)?;
    if encoded.len() > 16_384 {
        return Err(RecordError::Framing);
    }
    let signed = SignedRecord::parse(&STANDARD.decode(encoded).map_err(|_| RecordError::Json)?)?;
    signed.verify_signature(&pin.key()?)?;
    let body: Freshness = signed.decode()?;
    if body.v != 1
        || body.kind != "witness.freshness"
        || body.audience != pin.url
        || body.witness_key_generation != pin.key_generation
        || body.nonce != request.nonce
        || body.space_id != request.space_id
        || body.stream_id != request.stream_id
        || body.position.sequence == 0
        || body.position.record_id.is_none()
        || body.expires_at_ms <= body.issued_at_ms
        || body.expires_at_ms - body.issued_at_ms > 30_000
        || body.issued_at_ms > now_ms.saturating_add(5_000)
        || floor.is_some_and(|floor| {
            body.position.sequence < floor.sequence
                || (body.position.sequence == floor.sequence
                    && body.position.record_id != floor.record_id)
        })
    {
        return Err(RecordError::Authority);
    }
    let result = VerifiedFreshness { body, requested_at };
    if !result.is_valid(now_ms) {
        return Err(RecordError::Authority);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::WitnessPin,
        record::{self, SignedRecord},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::SigningKey;
    use std::time::{Duration, Instant};

    #[test]
    fn freshness_rejects_replayed_nonce_stale_time_pin_and_floor_forks() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let pin = WitnessPin {
            url: "https://witness.example.test/witness/v1".into(),
            public_key: record::encode_hex(key.verifying_key().as_bytes()),
            key_generation: 1,
        };
        let mut request = HeadRequest {
            space_id: SpaceId::from_bytes([2; 32]),
            stream_id: StreamId::from_bytes([3; 16]),
            nonce: record::random_hex::<32>().unwrap(),
        };
        let body = Freshness {
            v: 1,
            kind: "witness.freshness".into(),
            audience: pin.url.clone(),
            nonce: request.nonce.clone(),
            space_id: request.space_id,
            stream_id: request.stream_id,
            authority_head: RecordId::from_bytes([4; 32]),
            position: Position {
                sequence: 3,
                record_id: Some(RecordId::from_bytes([5; 32])),
            },
            issued_at_ms: 10_000,
            expires_at_ms: 40_000,
            witness_key_generation: 1,
        };
        let encoded = STANDARD.encode(
            SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &key)
                .unwrap()
                .bytes(),
        );
        let start = Instant::now();
        let valid = verify_freshness(&pin, &request, &encoded, start, 10_000, None).unwrap();
        assert!(valid.is_valid(39_999));
        assert!(!valid.is_valid(40_000));
        assert!(
            verify_freshness(
                &pin,
                &request,
                &encoded,
                start - Duration::from_secs(31),
                10_000,
                None
            )
            .is_err()
        );
        assert!(verify_freshness(&pin, &request, &encoded, start, 40_000, None).is_err());
        assert!(
            verify_freshness(
                &pin,
                &request,
                &encoded,
                start,
                10_000,
                Some(&Position {
                    sequence: 4,
                    record_id: body.position.record_id
                })
            )
            .is_err()
        );
        assert!(
            verify_freshness(
                &pin,
                &request,
                &encoded,
                start,
                10_000,
                Some(&Position {
                    sequence: 3,
                    record_id: Some(RecordId::from_bytes([6; 32]))
                })
            )
            .is_err()
        );
        let mut wrong_pin = pin.clone();
        wrong_pin.public_key =
            record::encode_hex(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
        assert!(verify_freshness(&wrong_pin, &request, &encoded, start, 10_000, None).is_err());
        request.nonce = record::random_hex::<32>().unwrap();
        assert!(verify_freshness(&pin, &request, &encoded, start, 10_000, None).is_err());
    }
}

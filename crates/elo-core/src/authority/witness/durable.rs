//! Durable approval binds a candidate request, while possession remains fresh.
use super::*;

const MAX_REQUEST_MS: u64 = 24 * 60 * 60 * 1_000;

/// The device-signed record ID is the stable request ID. Neither this request
/// nor an owner approval authorizes admission without a fresh possession proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessJoinRequest {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub policy_id: RecordId,
    pub credential_id: RecordId,
    pub contact_id: RecordId,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub witness_key_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessJoinRequestEvidence {
    pub policy: String,
    pub device_request: String,
    pub invitation_request: String,
    pub contact: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessApprovalV2 {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub authority_head: RecordId,
    pub issuer_credential_id: RecordId,
    pub request_id: RecordId,
    pub readmission: bool,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessChallengeV2 {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub client_nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub policy_id: RecordId,
    pub credential_id: RecordId,
    pub request_id: RecordId,
    pub authority_head: RecordId,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub witness_key_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAdmissionIntentV2 {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub policy_id: RecordId,
    pub request_id: RecordId,
    pub challenge_id: RecordId,
    pub credential_id: RecordId,
    pub contact_id: RecordId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAdmissionEvidenceV2 {
    pub request: WitnessJoinRequestEvidence,
    pub challenge: String,
    pub device_intent: String,
    pub invitation_intent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    pub admitted_at_ms: u64,
}

impl Authority {
    /// This verifies the public request only. The service also checks durable
    /// policy revocation/use state before issuing a challenge or admitting it.
    pub fn verify_witness_join_request(
        &self,
        evidence: &WitnessJoinRequestEvidence,
        candidate: &VerifiedCredential,
        now_ms: u64,
    ) -> Result<WitnessJoinRequest> {
        let pin = self.witness_pin().ok_or(RecordError::Authority)?;
        let policy_record = decode(&evidence.policy)?;
        let policy = self.verify_witness_invitation(&policy_record, now_ms)?;
        let device = decode(&evidence.device_request)?;
        let invitation = decode(&evidence.invitation_request)?;
        if device.body_bytes() != invitation.body_bytes() {
            return Err(RecordError::Authority);
        }
        device.verify_signature(candidate.key())?;
        invitation.verify_signature(&public_key(&policy.invitation_public_key)?)?;
        let request: WitnessJoinRequest = device.decode()?;
        record::hex::<32>(&request.nonce)?;
        let contact_record = decode(&evidence.contact)?;
        let contact =
            crate::invite::shared::verify_contact(&contact_record, candidate, now_ms / 1_000)?;
        if request.v != 1
            || request.kind != "witness.join_request"
            || request.space_id != self.space()
            || request.stream_id != self.stream()
            || request.policy_id != policy_record.id()
            || request.credential_id != candidate.id()
            || request.contact_id != contact_record.id()
            || request.witness_key_generation != pin.key_generation
            || request.issued_at_ms < policy.not_before_ms
            || request.issued_at_ms > now_ms.saturating_add(5_000)
            || request.expires_at_ms <= request.issued_at_ms
            || request.expires_at_ms - request.issued_at_ms > MAX_REQUEST_MS
            || request.expires_at_ms > policy.expires_at_ms
            || request.expires_at_ms
                > contact
                    .expires_at
                    .checked_mul(1_000)
                    .ok_or(RecordError::Authority)?
            || now_ms >= request.expires_at_ms
        {
            return Err(RecordError::Authority);
        }
        Ok(request)
    }

    pub fn prepare_witness_admission_v2(
        &self,
        evidence: WitnessAdmissionEvidenceV2,
        witness_key: &SigningKey,
    ) -> Result<SignedRecord> {
        self.require_witness_signer(witness_key)?;
        let config = self.witness_admission_config_v2(evidence)?;
        let signed = config.sign(witness_key)?;
        let mut trial = self.clone();
        if trial.apply_config(signed.clone())? != ConfigAdmission::Applied {
            return Err(RecordError::Authority);
        }
        Ok(signed)
    }

    pub(super) fn witness_admission_config_v2(
        &self,
        evidence: WitnessAdmissionEvidenceV2,
    ) -> Result<StreamConfig> {
        if self.is_forked() || evidence.admitted_at_ms > record::MAX_INTEGER {
            return Err(RecordError::Authority);
        }
        let device_record = decode(&evidence.device_intent)?;
        let invitation_record = decode(&evidence.invitation_intent)?;
        if device_record.body_bytes() != invitation_record.body_bytes() {
            return Err(RecordError::Authority);
        }
        let intent: WitnessAdmissionIntentV2 = device_record.decode()?;
        record::hex::<32>(&intent.nonce)?;
        let candidate = self.credential(intent.credential_id)?;
        let request = self.verify_witness_join_request(
            &evidence.request,
            candidate,
            evidence.admitted_at_ms,
        )?;
        let request_id = decode(&evidence.request.device_request)?.id();
        let policy_record = decode(&evidence.request.policy)?;
        let policy = self.verify_witness_invitation(&policy_record, evidence.admitted_at_ms)?;
        device_record.verify_signature(candidate.key())?;
        invitation_record.verify_signature(&public_key(&policy.invitation_public_key)?)?;
        let pin = self.witness_pin().ok_or(RecordError::Authority)?;
        let challenge_record = decode(&evidence.challenge)?;
        challenge_record.verify_signature(&pin.key()?)?;
        let challenge: WitnessChallengeV2 = challenge_record.decode()?;
        record::hex::<32>(&challenge.nonce)?;
        record::hex::<32>(&challenge.client_nonce)?;
        let challenge_head = self.config(challenge.authority_head)?;
        if challenge.v != 2
            || challenge.kind != "witness.challenge"
            || challenge.space_id != self.space()
            || challenge.stream_id != self.stream()
            || challenge.policy_id != request.policy_id
            || challenge.credential_id != request.credential_id
            || challenge.request_id != request_id
            || !self.proves_config_at(challenge.authority_head, challenge_head.sequence)
            || challenge.witness_key_generation != pin.key_generation
            || challenge.issued_at_ms < request.issued_at_ms.saturating_sub(5_000)
            || challenge.issued_at_ms >= challenge.expires_at_ms
            || challenge.expires_at_ms > request.expires_at_ms
            || challenge.expires_at_ms - challenge.issued_at_ms > MAX_CHALLENGE_MS
            || evidence.admitted_at_ms < challenge.issued_at_ms
            || evidence.admitted_at_ms >= challenge.expires_at_ms
            || intent.v != 2
            || intent.kind != "witness.admission"
            || intent.space_id != self.space()
            || intent.stream_id != self.stream()
            || intent.policy_id != request.policy_id
            || intent.request_id != request_id
            || intent.challenge_id != challenge_record.id()
            || intent.credential_id != request.credential_id
            || intent.contact_id != request.contact_id
        {
            return Err(RecordError::Authority);
        }
        let approval = if let Some(encoded) = &evidence.approval {
            let signed = decode(encoded)?;
            let body: WitnessApprovalV2 = signed.decode()?;
            record::hex::<16>(&body.nonce)?;
            if body.v != 2
                || body.kind != "witness.approval"
                || body.space_id != self.space()
                || body.stream_id != self.stream()
                || body.request_id != request_id
                || body.expires_at_ms > request.expires_at_ms
                || body.expires_at_ms <= evidence.admitted_at_ms
            {
                return Err(RecordError::Authority);
            }
            Some(AdmissionApproval {
                signed,
                issuer: body.issuer_credential_id,
                head: body.authority_head,
                readmission: body.readmission,
            })
        } else {
            None
        };
        self.finish_witness_admission(ValidatedAdmission {
            candidate,
            policy,
            policy_id: policy_record.id(),
            challenge_nonce: challenge.nonce,
            request_id,
            config_nonce: intent.nonce[..32].into(),
            admitted_at_ms: evidence.admitted_at_ms,
            approval,
            evidence: WitnessConfigEvidence::AdmissionV2 { evidence },
        })
    }
}

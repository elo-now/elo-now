//! Candidate-side witnessed admission. Pending requests remain in memory and
//! contain public signatures, never the invitation seed or its derived key.
use super::*;
use crate::{
    authority::{
        WitnessAdmissionEvidence, WitnessAdmissionIntent, WitnessApproval, WitnessChallenge,
        WitnessConfigEvidence, WitnessPin,
    },
    witness::{Command, Operation, Position, Receipt, Request, Response, link::VerifiedDescriptor},
};
use std::time::{Duration, Instant};

const ERROR: &str = "Chat permissions need to be refreshed.";
const RESPONSE_BYTES: usize = 9 * 1024 * 1024;

/// A policy requirement, not a reinterpretation of an unsigned HTTP error.
pub enum WitnessAdmissionOutcome {
    ApprovalRequired,
    Admitted(Box<Authority>),
}

/// No serde/Debug implementation: future callers must explicitly choose which
/// public evidence to deliver to an owner. Mutation permission expires with its
/// challenge; acknowledged attempts may continue read-only reconciliation.
pub struct PendingWitnessAdmission {
    authority: Authority,
    pin: WitnessPin,
    evidence: WitnessAdmissionEvidence,
    credential_id: RecordId,
    challenge_head: RecordId,
    expires_at_ms: u64,
    started: Instant,
    approval_required: bool,
    submitted: Option<SubmittedAdmission>,
}

struct SubmittedAdmission {
    command: Command,
    signed: SignedRecord,
    evidence: WitnessAdmissionEvidence,
    receipt: Option<Receipt>,
}

impl PendingWitnessAdmission {
    pub fn approval_request(&self) -> &WitnessAdmissionEvidence {
        &self.evidence
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn requires_approval(&self) -> bool {
        self.approval_required
    }
}

pub(super) fn verify_ack(
    pin: &WitnessPin,
    signed_request: &SignedRecord,
    command: &Command,
    encoded: &str,
    event: &str,
    now_ms: u64,
    floor: Option<&Position>,
) -> Result<(Receipt, Position)> {
    if encoded.len() > 16_384 {
        return Err(ERROR.into());
    }
    let signed = decode_record(encoded)?;
    signed.verify_signature(&pin.key()?)?;
    let body: Receipt = signed.decode()?;
    record::hex::<32>(&body.state_digest)?;
    let position = Position {
        sequence: body.sequence,
        record_id: Some(signed.id()),
    };
    // Preserve conflicts observed before HTTP even if another response later
    // advances the durable floor. Only Admit may reconcile an older signed ack;
    // it still requires a full current proof and independent fresh Head below.
    if body.v != 1
        || body.kind != "witness.receipt"
        || body.audience != pin.url
        || body.witness_key_generation != pin.key_generation
        || body.request_id != signed_request.id()
        || body.space_id != command.space_id
        || body.event != event
        || body.sequence == 0
        || body.sequence > record::MAX_INTEGER
        || (body.sequence == 1) != body.previous.is_none()
        || body.accepted_at_ms < command.issued_at_ms.saturating_sub(5_000)
        || body.accepted_at_ms >= command.expires_at_ms
        || body.accepted_at_ms > now_ms.saturating_add(5_000)
        || now_ms >= command.expires_at_ms
        || floor.is_some_and(|floor| {
            (position.sequence < floor.sequence
                && !matches!(event, "device.admitted" | "device.admitted_v2"))
                || (position.sequence == floor.sequence && position.record_id != floor.record_id)
                || (position.sequence == floor.sequence.saturating_add(1)
                    && body.previous != floor.record_id)
        })
    {
        return Err(ERROR.into());
    }
    Ok((body, position))
}

fn verify_challenge(
    pin: &WitnessPin,
    command: &Command,
    encoded: &str,
    now_ms: u64,
) -> Result<WitnessChallenge> {
    let Operation::Challenge {
        policy_id,
        client_nonce,
        ..
    } = &command.operation
    else {
        return Err(ERROR.into());
    };
    if encoded.len() > 16_384 {
        return Err(ERROR.into());
    }
    let signed = decode_record(encoded)?;
    signed.verify_signature(&pin.key()?)?;
    let body: WitnessChallenge = signed.decode()?;
    record::hex::<32>(&body.nonce)?;
    if body.v != 1
        || body.kind != "witness.challenge"
        || body.space_id != command.space_id
        || body.stream_id != command.stream_id
        || body.policy_id != *policy_id
        || body.credential_id != command.credential_id
        || body.client_nonce != *client_nonce
        || body.witness_key_generation != pin.key_generation
        || body.issued_at_ms < command.issued_at_ms.saturating_sub(5_000)
        || body.issued_at_ms > now_ms.saturating_add(5_000)
        || body.expires_at_ms <= body.issued_at_ms
        || body.expires_at_ms > record::MAX_INTEGER
        || body.expires_at_ms - body.issued_at_ms > 120_000
        || now_ms >= body.expires_at_ms
    {
        return Err(ERROR.into());
    }
    Ok(body)
}

pub(super) fn known_removal(authority: &Authority, identity: IdentityId) -> Result<bool> {
    let mut head = authority.head()?;
    while let Some(previous) = head.previous_config_id {
        let old = authority.config(previous)?;
        if let Some(old_member) = old
            .members
            .iter()
            .find(|member| member.identity_id == identity)
        {
            let current = head
                .members
                .iter()
                .find(|member| member.identity_id == identity);
            if old_member
                .credential_ids
                .iter()
                .any(|id| current.is_none_or(|member| !member.credential_ids.contains(id)))
            {
                return Ok(true);
            }
        }
        head = old;
    }
    Ok(false)
}

impl ClientApp {
    pub(super) fn admission_command(
        &self,
        authority: &Authority,
        head: RecordId,
        operation: Operation,
    ) -> Result<(Command, SignedRecord)> {
        let pin = self.trusted_witness(authority)?;
        let issued_at_ms: u64 = now()?.as_millis().try_into()?;
        let command = Command {
            v: 1,
            kind: "witness.command".into(),
            nonce: record::random_hex::<32>()?,
            audience: pin.url.clone(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            credential_id: self.session.credential().id(),
            authority_head: head,
            issued_at_ms,
            expires_at_ms: issued_at_ms.checked_add(60_000).ok_or(ERROR)?,
            operation,
        };
        let signed =
            SignedRecord::sign(&serde_json::to_vec(&command)?, self.session.signing_key())?;
        Ok((command, signed))
    }

    async fn admission_exchange(&self, pin: &WitnessPin, request: &Request) -> Result<Response> {
        let endpoint = self.witness_endpoint(pin, "command")?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(10))
            .build()?;
        let response = client
            .post(endpoint)
            .json(request)
            .send()
            .await
            .map_err(|_| ERROR)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > RESPONSE_BYTES as u64)
        {
            return Err(ERROR.into());
        }
        use futures_util::StreamExt;
        let mut chunks = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|_| ERROR)?;
            if bytes.len().saturating_add(chunk.len()) > RESPONSE_BYTES {
                return Err(ERROR.into());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| ERROR.into())
    }

    /// The descriptor must have been opened with the native API origin and pin.
    /// Its invitation key signs the exact device command, never leaves this call,
    /// and is not retained in the resulting pending handle.
    pub async fn witness_prepare_admission(
        &self,
        invitation: &VerifiedDescriptor,
        name: &str,
    ) -> Result<PendingWitnessAdmission> {
        let authority = invitation.authority();
        let pin = self.trusted_witness(authority)?;
        let policy_record = decode_record(&invitation.descriptor().policy)?;
        let policy =
            authority.verify_witness_invitation(&policy_record, now()?.as_millis() as u64)?;
        let (command, signed) = self.admission_command(
            authority,
            authority.head_id().ok_or(ERROR)?,
            Operation::Challenge {
                policy_id: policy_record.id(),
                credential: STANDARD.encode(self.session.credential().record().bytes()),
                client_nonce: record::random_hex::<32>()?,
            },
        )?;
        let possession =
            SignedRecord::sign(signed.body_bytes(), invitation.invitation_signing_key())?;
        let floor = self.witness_position(pin)?;
        let started = Instant::now();
        let response = self
            .admission_exchange(
                pin,
                &Request {
                    command: STANDARD.encode(signed.bytes()),
                    invitation_signature: Some(STANDARD.encode(possession.bytes())),
                    proof: None,
                    registration_work: None,
                },
            )
            .await?;
        if response.proof.is_some() {
            return Err(ERROR.into());
        }
        let received = now()?.as_millis() as u64;
        let encoded = response.challenge.ok_or(ERROR)?;
        let challenge = verify_challenge(pin, &command, &encoded, received)?;
        let (receipt, position) = verify_ack(
            pin,
            &signed,
            &command,
            response.receipt.as_deref().ok_or(ERROR)?,
            "invitation.challenged",
            received,
            floor.as_ref(),
        )?;
        if receipt.accepted_at_ms != challenge.issued_at_ms {
            return Err(ERROR.into());
        }
        self.record_witness_receipt_position(pin, position, receipt.previous)?;
        let contact = invite::shared::contact(
            self.session.credential(),
            self.session.signing_key(),
            name,
            challenge.expires_at_ms / 1_000 + 1,
        )?;
        let intent = WitnessAdmissionIntent {
            v: 1,
            kind: "witness.admission".into(),
            nonce: record::random_hex::<32>()?,
            space_id: authority.space(),
            stream_id: authority.stream(),
            policy_id: policy_record.id(),
            challenge_id: decode_record(&encoded)?.id(),
            credential_id: self.session.credential().id(),
            contact_id: contact.id(),
        };
        let intent_body = serde_json::to_vec(&intent)?;
        let evidence = WitnessAdmissionEvidence {
            policy: invitation.descriptor().policy.clone(),
            challenge: encoded,
            device_intent: STANDARD
                .encode(SignedRecord::sign(&intent_body, self.session.signing_key())?.bytes()),
            invitation_intent: STANDARD.encode(
                SignedRecord::sign(&intent_body, invitation.invitation_signing_key())?.bytes(),
            ),
            contact: STANDARD.encode(contact.bytes()),
            approval: None,
            admitted_at_ms: 0,
        };
        Ok(PendingWitnessAdmission {
            authority: authority.clone(),
            pin: pin.clone(),
            evidence,
            credential_id: self.session.credential().id(),
            challenge_head: receipt.authority_head,
            expires_at_ms: challenge.expires_at_ms.min(policy.expires_at_ms),
            started,
            approval_required: policy.require_approval
                || known_removal(authority, self.identity_id())?,
            submitted: None,
        })
    }

    /// Before acknowledgement, retry the exact mutation within its original
    /// deadline. After acknowledgement, retry only Read and fresh Head even when
    /// the old challenge expired. A receipt alone never reports admission.
    pub async fn witness_admit(
        &self,
        pending: &mut PendingWitnessAdmission,
        approval: Option<&SignedRecord>,
    ) -> Result<WitnessAdmissionOutcome> {
        let pin = self.trusted_witness(&pending.authority)?;
        let current = now()?.as_millis() as u64;
        if pin != &pending.pin || pending.credential_id != self.session.credential().id() {
            return Err(ERROR.into());
        }
        if pending
            .submitted
            .as_ref()
            .is_none_or(|submitted| submitted.receipt.is_none())
        {
            if current >= pending.expires_at_ms
                || pending.started.elapsed() >= Duration::from_secs(120)
            {
                return Err(ERROR.into());
            }
            if pending.approval_required && approval.is_none() {
                return Ok(WitnessAdmissionOutcome::ApprovalRequired);
            }
            if let Some(approval) = approval {
                let body: WitnessApproval = approval.decode()?;
                record::hex::<16>(&body.nonce)?;
                if body.v != 1
                    || body.kind != "witness.approval"
                    || body.space_id != pending.authority.space()
                    || body.stream_id != pending.authority.stream()
                    || body.intent_id != decode_record(&pending.evidence.device_intent)?.id()
                {
                    return Err(ERROR.into());
                }
            }
            let encoded_approval = approval.map(|value| STANDARD.encode(value.bytes()));
            if let Some(submitted) = &pending.submitted {
                if submitted.evidence.approval != encoded_approval
                    || current >= submitted.command.expires_at_ms
                {
                    return Err(ERROR.into());
                }
            } else {
                let mut evidence = pending.evidence.clone();
                evidence.approval = encoded_approval;
                let (command, signed) = self.admission_command(
                    &pending.authority,
                    pending.challenge_head,
                    Operation::Admit {
                        credential: STANDARD.encode(self.session.credential().record().bytes()),
                        evidence: evidence.clone(),
                    },
                )?;
                pending.submitted = Some(SubmittedAdmission {
                    command,
                    signed,
                    evidence,
                    receipt: None,
                });
            }
            let submitted = pending.submitted.as_ref().ok_or(ERROR)?;
            let floor = self.witness_position(pin)?;
            let response = self
                .admission_exchange(
                    pin,
                    &Request {
                        command: STANDARD.encode(submitted.signed.bytes()),
                        invitation_signature: None,
                        proof: None,
                        registration_work: None,
                    },
                )
                .await?;
            if response.challenge.is_some() {
                return Err(ERROR.into());
            }
            let (receipt, position) = verify_ack(
                pin,
                &submitted.signed,
                &submitted.command,
                response.receipt.as_deref().ok_or(ERROR)?,
                "device.admitted",
                now()?.as_millis() as u64,
                floor.as_ref(),
            )?;
            self.record_admission_receipt_position(pin, position, receipt.previous)?;
            pending.submitted.as_mut().ok_or(ERROR)?.receipt = Some(receipt);
        }
        let submitted = pending.submitted.as_ref().ok_or(ERROR)?;
        let receipt = submitted.receipt.as_ref().ok_or(ERROR)?;
        // Read may advance beyond the acknowledged head. It must still include
        // that exact admission and preserve the independently persisted floor.
        let (_, read) =
            self.admission_command(&pending.authority, receipt.authority_head, Operation::Read)?;
        let reply = self
            .admission_exchange(
                pin,
                &Request {
                    command: STANDARD.encode(read.bytes()),
                    invitation_signature: None,
                    proof: None,
                    registration_work: None,
                },
            )
            .await?;
        if reply.receipt.is_some() || reply.challenge.is_some() {
            return Err(ERROR.into());
        }
        let proof = reply.proof.ok_or(ERROR)?;
        let authority = self.verify_admission_proof(pending, submitted, receipt, &proof)?;
        self.fetch_witness_freshness(&authority, Instant::now())
            .await?;
        Ok(WitnessAdmissionOutcome::Admitted(Box::new(authority)))
    }

    fn verify_admission_proof(
        &self,
        pending: &PendingWitnessAdmission,
        submitted: &SubmittedAdmission,
        receipt: &Receipt,
        proof: &crate::authority::CallAuthorityProof,
    ) -> Result<Authority> {
        let authority = proof.verify_witnessed(
            pending.authority.space(),
            pending.authority.stream(),
            &pending.pin,
        )?;
        let base = &pending.authority;
        let challenge = authority.config(pending.challenge_head)?;
        let admitted = authority.config(receipt.authority_head)?;
        if !authority.proves_config_at(base.head_id().ok_or(ERROR)?, base.head()?.sequence)
            || !authority.proves_config_at(pending.challenge_head, challenge.sequence)
            || !authority.proves_config_at(receipt.authority_head, admitted.sequence)
            || admitted.sequence <= challenge.sequence
        {
            return Err(ERROR.into());
        }
        let Some(WitnessConfigEvidence::Admission { evidence }) = &admitted.witness_evidence else {
            return Err(ERROR.into());
        };
        let mut expected = submitted.evidence.clone();
        expected.admitted_at_ms = receipt.accepted_at_ms;
        if serde_json::to_value(evidence)? != serde_json::to_value(expected)? {
            return Err(ERROR.into());
        }
        let credential = authority.credential(self.session.credential().id())?;
        if credential.record().bytes() != self.session.credential().record().bytes()
            || !authority.head()?.members.iter().any(|member| {
                member.identity_id == self.identity_id()
                    && member.credential_ids.contains(&credential.id())
                    && member.capabilities.contains(&Capability::Read)
                    && member.capabilities.contains(&Capability::Post)
            })
        {
            return Err(ERROR.into());
        }
        if let Some(local) = self.authorities.0.iter().find(|local| {
            local.space() == authority.space() && local.stream() == authority.stream()
        }) && (local.is_forked()
            || !authority.proves_config_at(local.head_id().ok_or(ERROR)?, local.head()?.sequence))
        {
            return Err(ERROR.into());
        }
        Ok(authority)
    }
}

#[cfg(test)]
mod tests;

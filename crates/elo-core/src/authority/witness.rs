//! Restricted, witness-serialized membership changes for version 4 authorities.
//! A witness signature proves ordering, never possession of an invitation key.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

mod durable;
pub use durable::{
    WitnessAdmissionEvidenceV2, WitnessAdmissionIntentV2, WitnessApprovalV2, WitnessChallengeV2,
    WitnessJoinRequest, WitnessJoinRequestEvidence,
};

const MAX_CHALLENGE_MS: u64 = 120_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessPin {
    pub url: String,
    pub public_key: String,
    pub key_generation: u64,
}

impl WitnessPin {
    pub fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.url).map_err(|_| RecordError::Authority)?;
        if self.url.len() > 2048
            || self.url.trim() != self.url
            || self.url.chars().any(char::is_control)
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.key_generation == 0
            || self.key_generation > record::MAX_INTEGER
        {
            return Err(RecordError::Authority);
        }
        self.key()?;
        Ok(())
    }

    pub fn key(&self) -> Result<VerifyingKey> {
        public_key(&self.public_key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessInvitationPolicy {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub authority_head: RecordId,
    pub issuer_credential_id: RecordId,
    pub invitation_public_key: String,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub require_approval: bool,
    pub max_uses: u64,
    pub witness_key_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessChallenge {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub client_nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub policy_id: RecordId,
    pub credential_id: RecordId,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub witness_key_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAdmissionIntent {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub policy_id: RecordId,
    pub challenge_id: RecordId,
    pub credential_id: RecordId,
    pub contact_id: RecordId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessApproval {
    pub v: u8,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub authority_head: RecordId,
    pub issuer_credential_id: RecordId,
    pub intent_id: RecordId,
    pub readmission: bool,
}

/// Base64 ELO1 records contain only public proofs, never invitation secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAdmissionEvidence {
    pub policy: String,
    pub challenge: String,
    pub device_intent: String,
    pub invitation_intent: String,
    pub contact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    pub admitted_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WitnessConfigEvidence {
    OwnerProposal {
        proposal: String,
    },
    Admission {
        evidence: WitnessAdmissionEvidence,
    },
    AdmissionV2 {
        evidence: WitnessAdmissionEvidenceV2,
    },
}

struct AdmissionApproval {
    signed: SignedRecord,
    issuer: RecordId,
    head: RecordId,
    readmission: bool,
}

struct ValidatedAdmission<'a> {
    candidate: &'a VerifiedCredential,
    policy: WitnessInvitationPolicy,
    policy_id: RecordId,
    challenge_nonce: String,
    request_id: RecordId,
    config_nonce: String,
    admitted_at_ms: u64,
    approval: Option<AdmissionApproval>,
    evidence: WitnessConfigEvidence,
}

fn public_key(value: &str) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(&record::hex(value)?).map_err(|_| RecordError::Signature)?;
    if key.is_weak() {
        return Err(RecordError::Signature);
    }
    Ok(key)
}

fn decode(value: &str) -> Result<SignedRecord> {
    if value.len() > record::MAX_RECORD.div_ceil(3) * 4 {
        return Err(RecordError::Framing);
    }
    SignedRecord::parse(&STANDARD.decode(value).map_err(|_| RecordError::Json)?)
}

fn same_config(left: &StreamConfig, right: &StreamConfig) -> Result<bool> {
    Ok(serde_json::to_value(left).map_err(|_| RecordError::Json)?
        == serde_json::to_value(right).map_err(|_| RecordError::Json)?)
}

impl Authority {
    pub fn witness_pin(&self) -> Option<&WitnessPin> {
        self.body.witness.as_ref()
    }

    fn witness_ancestry(&self) -> Result<Vec<(RecordId, &StreamConfig)>> {
        let mut result = Vec::new();
        let mut cursor = self.head;
        while let Some(id) = cursor {
            let config = self.config(id)?;
            result.push((id, config));
            cursor = config.previous_config_id;
        }
        Ok(result)
    }

    fn witness_owner_at(&self, credential: RecordId, head: RecordId) -> Result<()> {
        if self.is_forked() || self.witness_pin().is_none() || !self.can_manage(credential) {
            return Err(RecordError::Authority);
        }
        for (id, config) in self.witness_ancestry()? {
            // A later re-grant must not reactivate policies from before removal.
            if !config.owner_credential_ids.contains(&credential) {
                return Err(RecordError::Authority);
            }
            if id == head {
                return Ok(());
            }
        }
        Err(RecordError::Authority)
    }

    /// Validate public invitation authorship against the selected current head.
    /// The service must additionally enforce its durable revoke/use-count state.
    pub fn verify_witness_invitation(
        &self,
        signed: &SignedRecord,
        now_ms: u64,
    ) -> Result<WitnessInvitationPolicy> {
        let pin = self.witness_pin().ok_or(RecordError::Authority)?;
        let policy: WitnessInvitationPolicy = signed.decode()?;
        record::hex::<16>(&policy.nonce)?;
        public_key(&policy.invitation_public_key)?;
        if policy.v != 1
            || policy.kind != "witness.invitation"
            || policy.space_id != self.space()
            || policy.stream_id != self.stream()
            || policy.witness_key_generation != pin.key_generation
            || policy.max_uses == 0
            || policy.max_uses > record::MAX_INTEGER
            || policy.not_before_ms >= policy.expires_at_ms
            || policy.expires_at_ms > record::MAX_INTEGER
            || now_ms < policy.not_before_ms
            || now_ms >= policy.expires_at_ms
        {
            return Err(RecordError::Authority);
        }
        self.witness_owner_at(policy.issuer_credential_id, policy.authority_head)?;
        signed.verify_signature(self.credential(policy.issuer_credential_id)?.key())?;
        Ok(policy)
    }

    /// Preserve the complete original owner proposal beneath the witness signature.
    /// A proposal is never itself an admitted version 4 configuration.
    pub fn prepare_witness_owner_config(
        &self,
        proposal: &SignedRecord,
        witness_key: &SigningKey,
    ) -> Result<SignedRecord> {
        self.require_witness_signer(witness_key)?;
        let mut config: StreamConfig = proposal.decode()?;
        if config.witness_evidence.is_some() {
            return Err(RecordError::Authority);
        }
        config.witness_evidence = Some(WitnessConfigEvidence::OwnerProposal {
            proposal: STANDARD.encode(proposal.bytes()),
        });
        let signed = config.sign(witness_key)?;
        let mut trial = self.clone();
        if trial.apply_config(signed.clone())? != ConfigAdmission::Applied {
            return Err(RecordError::Authority);
        }
        Ok(signed)
    }

    pub fn prepare_witness_admission(
        &self,
        evidence: WitnessAdmissionEvidence,
        witness_key: &SigningKey,
    ) -> Result<SignedRecord> {
        self.require_witness_signer(witness_key)?;
        let config = self.witness_admission_config(evidence)?;
        let signed = config.sign(witness_key)?;
        let mut trial = self.clone();
        if trial.apply_config(signed.clone())? != ConfigAdmission::Applied {
            return Err(RecordError::Authority);
        }
        Ok(signed)
    }

    fn require_witness_signer(&self, key: &SigningKey) -> Result<()> {
        if self.is_forked()
            || self.witness_pin().ok_or(RecordError::Authority)?.key()? != key.verifying_key()
        {
            return Err(RecordError::Authority);
        }
        Ok(())
    }

    pub(super) fn validate_witness_transition(&self, config: &StreamConfig) -> Result<()> {
        let previous = config.previous_config_id.ok_or(RecordError::Authority)?;
        let mut prior = self.clone();
        prior.head = Some(previous);
        let parent = prior.head()?;
        if config.recovery.is_some() || config.action.operation == "controller.recovered" {
            return Err(RecordError::Authority);
        }
        match config
            .witness_evidence
            .as_ref()
            .ok_or(RecordError::Authority)?
        {
            WitnessConfigEvidence::OwnerProposal { proposal } => {
                let signed = decode(proposal)?;
                let proposed: StreamConfig = signed.decode()?;
                let mut bare = config.clone();
                bare.witness_evidence = None;
                if proposed.witness_evidence.is_some()
                    || !same_config(&bare, &proposed)?
                    || !parent
                        .owner_credential_ids
                        .contains(&config.controller_credential_id)
                {
                    return Err(RecordError::Authority);
                }
                signed.verify_signature(self.credential(config.controller_credential_id)?.key())?;
            }
            WitnessConfigEvidence::AdmissionV2 { evidence } => {
                if config.controller_credential_id != parent.controller_credential_id
                    || !same_config(
                        config,
                        &prior.witness_admission_config_v2(evidence.clone())?,
                    )?
                {
                    return Err(RecordError::Authority);
                }
            }
            WitnessConfigEvidence::Admission { evidence } => {
                // This path cannot change the controller: only an exact, restricted
                // member addition is valid under a pinned witness signature.
                if config.controller_credential_id != parent.controller_credential_id
                    || !same_config(config, &prior.witness_admission_config(evidence.clone())?)?
                {
                    return Err(RecordError::Authority);
                }
            }
        }
        Ok(())
    }

    fn witness_admission_config(&self, evidence: WitnessAdmissionEvidence) -> Result<StreamConfig> {
        if self.is_forked() || evidence.admitted_at_ms > record::MAX_INTEGER {
            return Err(RecordError::Authority);
        }
        let pin = self.witness_pin().ok_or(RecordError::Authority)?;
        let policy_record = decode(&evidence.policy)?;
        let policy = self.verify_witness_invitation(&policy_record, evidence.admitted_at_ms)?;
        let challenge_record = decode(&evidence.challenge)?;
        challenge_record.verify_signature(&pin.key()?)?;
        let challenge: WitnessChallenge = challenge_record.decode()?;
        record::hex::<32>(&challenge.nonce)?;
        record::hex::<32>(&challenge.client_nonce)?;
        if challenge.v != 1
            || challenge.kind != "witness.challenge"
            || challenge.space_id != self.space()
            || challenge.stream_id != self.stream()
            || challenge.policy_id != policy_record.id()
            || challenge.witness_key_generation != pin.key_generation
            || challenge.issued_at_ms >= challenge.expires_at_ms
            || challenge.expires_at_ms > record::MAX_INTEGER
            || challenge.expires_at_ms - challenge.issued_at_ms > MAX_CHALLENGE_MS
            || evidence.admitted_at_ms < challenge.issued_at_ms
            || evidence.admitted_at_ms >= challenge.expires_at_ms
        {
            return Err(RecordError::Authority);
        }
        let device_record = decode(&evidence.device_intent)?;
        let invitation_record = decode(&evidence.invitation_intent)?;
        if device_record.body_bytes() != invitation_record.body_bytes() {
            return Err(RecordError::Authority);
        }
        let intent: WitnessAdmissionIntent = device_record.decode()?;
        record::hex::<32>(&intent.nonce)?;
        let candidate = self.credential(intent.credential_id)?;
        device_record.verify_signature(candidate.key())?;
        invitation_record.verify_signature(&public_key(&policy.invitation_public_key)?)?;
        let contact = decode(&evidence.contact)?;
        // Identity contact cards use Unix seconds; witness evidence uses milliseconds.
        crate::invite::shared::verify_contact(
            &contact,
            candidate,
            evidence.admitted_at_ms / 1_000,
        )?;
        if intent.v != 1
            || intent.kind != "witness.admission"
            || intent.space_id != self.space()
            || intent.stream_id != self.stream()
            || intent.policy_id != policy_record.id()
            || intent.challenge_id != challenge_record.id()
            || intent.credential_id != challenge.credential_id
            || intent.contact_id != contact.id()
        {
            return Err(RecordError::Authority);
        }
        let approval = if let Some(encoded) = &evidence.approval {
            let signed = decode(encoded)?;
            let body: WitnessApproval = signed.decode()?;
            record::hex::<16>(&body.nonce)?;
            if body.v != 1
                || body.kind != "witness.approval"
                || body.space_id != self.space()
                || body.stream_id != self.stream()
                || body.intent_id != device_record.id()
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
            request_id: device_record.id(),
            config_nonce: intent.nonce[..32].into(),
            admitted_at_ms: evidence.admitted_at_ms,
            approval,
            evidence: WitnessConfigEvidence::Admission { evidence },
        })
    }

    fn finish_witness_admission(&self, admission: ValidatedAdmission<'_>) -> Result<StreamConfig> {
        let ValidatedAdmission {
            candidate,
            policy,
            policy_id,
            challenge_nonce,
            request_id,
            config_nonce,
            admitted_at_ms,
            approval,
            evidence,
        } = admission;
        let parent = self.head()?;
        let current_member = parent
            .members
            .iter()
            .find(|m| m.identity_id == candidate.identity());
        if current_member.is_some_and(|member| {
            member.identity_type != "HUMAN"
                || member.capabilities != [Capability::Read, Capability::Post]
                || member.credential_ids.contains(&candidate.id())
        }) {
            return Err(RecordError::Authority);
        }
        if let Some(authorizer) = candidate.authorizing_device()
            && !parent.members.iter().any(|member| {
                member.identity_id == candidate.identity()
                    && member.credential_ids.contains(&authorizer)
            })
        {
            return Err(RecordError::Authority);
        }
        let mut uses = 0_u64;
        let ancestry = self.witness_ancestry()?;
        let last_removal = ancestry.windows(2).find_map(|pair| {
            let previous = pair[1]
                .1
                .members
                .iter()
                .find(|member| member.identity_id == candidate.identity())?;
            let current = pair[0]
                .1
                .members
                .iter()
                .find(|member| member.identity_id == candidate.identity());
            previous
                .credential_ids
                .iter()
                .any(|id| current.is_none_or(|member| !member.credential_ids.contains(id)))
                .then_some(pair[0].1.sequence)
        });
        for (_, config) in &ancestry {
            for member in &config.members {
                for id in &member.credential_ids {
                    let previous = self.credential(*id)?;
                    if *id == candidate.id()
                        || previous.key() == candidate.key()
                        || previous.recipient() == candidate.recipient()
                    {
                        return Err(RecordError::Authority);
                    }
                }
            }
            let prior = match &config.witness_evidence {
                Some(WitnessConfigEvidence::Admission { evidence: prior }) => {
                    let prior_challenge: WitnessChallenge = decode(&prior.challenge)?.decode()?;
                    Some((
                        prior.admitted_at_ms,
                        decode(&prior.policy)?.id(),
                        prior_challenge.nonce,
                        decode(&prior.device_intent)?.id(),
                    ))
                }
                Some(WitnessConfigEvidence::AdmissionV2 { evidence: prior }) => {
                    let prior_challenge: WitnessChallengeV2 = decode(&prior.challenge)?.decode()?;
                    Some((
                        prior.admitted_at_ms,
                        decode(&prior.request.policy)?.id(),
                        prior_challenge.nonce,
                        decode(&prior.request.device_request)?.id(),
                    ))
                }
                _ => None,
            };
            if let Some((prior_time, prior_policy, prior_nonce, prior_request)) = prior {
                if prior_time > admitted_at_ms
                    || prior_nonce == challenge_nonce
                    || prior_request == request_id
                {
                    return Err(RecordError::Authority);
                }
                if prior_policy == policy_id {
                    uses += 1;
                }
            }
        }
        if uses >= policy.max_uses {
            return Err(RecordError::Authority);
        }
        // Any device removal remains a boundary even if the identity stays or
        // rejoins through another device. A re-grant never revives old approval.
        let readmission = last_removal.is_some();
        if let Some(approval) = approval {
            if readmission
                && (!approval.readmission
                    || self.config(approval.head)?.sequence
                        < last_removal.ok_or(RecordError::Authority)?)
            {
                return Err(RecordError::Authority);
            }
            self.witness_owner_at(approval.issuer, approval.head)?;
            approval
                .signed
                .verify_signature(self.credential(approval.issuer)?.key())?;
        } else if policy.require_approval || readmission {
            return Err(RecordError::Authority);
        }
        let mut next = parent.clone();
        if let Some(member) = next
            .members
            .iter_mut()
            .find(|m| m.identity_id == candidate.identity())
        {
            member.credential_ids.push(candidate.id());
            member.credential_ids.sort();
        } else {
            next.members.push(Member {
                identity_id: candidate.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: candidate.record().body()["root_public_key"]
                    .as_str()
                    .ok_or(RecordError::Authority)?
                    .into(),
                capabilities: vec![Capability::Read, Capability::Post],
                credential_ids: vec![candidate.id()],
                external: true,
            });
            next.members.sort_by_key(|member| member.identity_id);
        }
        next.sequence = next.sequence.checked_add(1).ok_or(RecordError::Authority)?;
        next.previous_config_id = self.head_id();
        next.nonce = config_nonce;
        next.action = ConfigAction {
            operation: "invite.approved".into(),
            actor_identity: self.credential(parent.controller_credential_id)?.identity(),
            request_record_id: Some(request_id),
        };
        next.witness_evidence = Some(evidence);
        Ok(next)
    }
}

#[cfg(test)]
mod tests;

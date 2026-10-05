//! Durable, native-only admission state. Public relay packets contain signatures;
//! the invitation signing key is stored only inside the encrypted profile file.
use super::*;
use crate::{
    authority::{
        CallAuthorityProof, WitnessAdmissionEvidenceV2, WitnessAdmissionIntentV2,
        WitnessApprovalV2, WitnessChallengeV2, WitnessConfigEvidence, WitnessJoinRequest,
        WitnessJoinRequestEvidence, WitnessPin,
    },
    witness::{Operation, Request, Response, link::VerifiedDescriptor},
};
use ed25519_dalek::SigningKey;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const ERROR: &str = "Chat permissions need to be refreshed.";
const STATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING: usize = 16;
const RESPONSE_BYTES: usize = 9 * 1024 * 1024;
const REQUEST_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
const STATE_FILE: &str = "witness-admissions.age";

/// Safe to send to an untrusted relay. No seed, private key or transport secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableAdmissionRequest {
    pub request_id: RecordId,
    pub name: String,
    pub address: space_service::SpaceAddress,
    pub credential: String,
    pub request: WitnessJoinRequestEvidence,
    pub expires_at_ms: u64,
}

pub enum DurableAdmissionOutcome {
    ApprovalRequired,
    Admitted(Box<Authority>),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Submitted {
    command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<String>,
}

// Deliberately private and without Debug. Serialized plaintext buffers are
// zeroized, and no caller can export this type through the renderer.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    packet: DurableAdmissionRequest,
    descriptor: String,
    invitation_signing_seed: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    submitted: Option<Submitted>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.invitation_signing_seed.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingState {
    v: u8,
    entries: BTreeMap<RecordId, Pending>,
}

impl Default for PendingState {
    fn default() -> Self {
        Self {
            v: 1,
            entries: BTreeMap::new(),
        }
    }
}

enum Exchange {
    Response(Response),
    Forbidden,
}

fn same<T: Serialize>(a: &T, b: &T) -> Result<bool> {
    Ok(serde_json::to_value(a)? == serde_json::to_value(b)?)
}

fn candidate(packet: &DurableAdmissionRequest) -> Result<VerifiedCredential> {
    let signed = decode_record(&packet.credential)?;
    let key = root_key(signed.body()["root_public_key"].as_str().ok_or(ERROR)?)?;
    Ok(VerifiedCredential::verify(signed.bytes(), &key)?)
}

fn check_packet(
    authority: &Authority,
    packet: &DurableAdmissionRequest,
    at_ms: u64,
) -> Result<WitnessJoinRequest> {
    packet.address.validate(false)?;
    let candidate = candidate(packet)?;
    let body = authority.verify_witness_join_request(&packet.request, &candidate, at_ms)?;
    let initial = authority.initial_controller();
    if packet.request_id != decode_record(&packet.request.device_request)?.id()
        || !record::valid_display_name(&packet.name)
        || packet.expires_at_ms != body.expires_at_ms
        || packet.address.scope.space != authority.space()
        || packet.address.scope.stream != authority.stream()
        || packet.address.scope.controller != initial.id()
        || packet.address.scope.root
            != initial.record().body()["root_public_key"]
                .as_str()
                .ok_or(ERROR)?
    {
        return Err(ERROR.into());
    }
    Ok(body)
}

impl ClientApp {
    fn durable_state(&self) -> Result<PendingState> {
        let path = self.directory.join(STATE_FILE);
        if !path.try_exists()? {
            return Ok(PendingState::default());
        }
        let bytes = read_exchange(&path, STATE_BYTES * 2)?;
        let plain = Zeroizing::new(crypto::open_bytes(
            &bytes,
            self.session.age_identity(),
            STATE_BYTES,
        )?);
        let state: PendingState = serde_json::from_slice(&plain)?;
        if state.v != 1
            || state.entries.len() > MAX_PENDING
            || state
                .entries
                .iter()
                .any(|(id, pending)| *id != pending.packet.request_id)
        {
            return Err(ERROR.into());
        }
        Ok(state)
    }

    fn write_durable_state(&self, state: &PendingState) -> Result<()> {
        if state.v != 1 || state.entries.len() > MAX_PENDING {
            return Err(ERROR.into());
        }
        let plain = Zeroizing::new(serde_json::to_vec(state)?);
        let encrypted = crypto::seal_bytes(
            &plain,
            &[self.session.age_identity().to_public()],
            STATE_BYTES,
        )?;
        vault::write_private(&self.directory.join(STATE_FILE), &encrypted, true)?;
        Ok(())
    }

    fn save_durable_pending(&self, pending: &Pending) -> Result<()> {
        let mut state = self.durable_state()?;
        state
            .entries
            .insert(pending.packet.request_id, pending.clone());
        self.write_durable_state(&state)
    }

    fn restore_durable_pending(
        &self,
        pending: &Pending,
        configured_api_origin: &str,
    ) -> Result<VerifiedDescriptor> {
        let pin = self.witness_pin.as_ref().ok_or(ERROR)?;
        let request: WitnessJoinRequest =
            decode_record(&pending.packet.request.device_request)?.decode()?;
        let descriptor = VerifiedDescriptor::restore_for_admission(
            &decode_record(&pending.descriptor)?,
            SigningKey::from_bytes(&pending.invitation_signing_seed),
            configured_api_origin,
            pin,
            request.issued_at_ms,
        )?;
        self.trusted_witness(descriptor.authority())?;
        if pending.packet.credential != STANDARD.encode(self.session.credential().record().bytes())
            || !same(&pending.packet.address, &descriptor.descriptor().address)?
            || pending.packet.name != descriptor.descriptor().name
            || pending.packet.request.policy != descriptor.descriptor().policy
        {
            return Err(ERROR.into());
        }
        check_packet(
            descriptor.authority(),
            &pending.packet,
            request.issued_at_ms,
        )?;
        Ok(descriptor)
    }

    /// Creates no network traffic. The request is encrypted and durable before
    /// it can be returned for relay or used by any witness mutation.
    pub fn witness_prepare_durable_admission(
        &mut self,
        invitation: &VerifiedDescriptor,
        name: &str,
    ) -> Result<DurableAdmissionRequest> {
        self.trusted_witness(invitation.authority())?;
        let at_ms = now()?.as_millis() as u64;
        invitation
            .authority()
            .verify_witness_invitation(&decode_record(&invitation.descriptor().policy)?, at_ms)?;
        let contact_expiry = at_ms
            .checked_add(REQUEST_LIFETIME_MS)
            .ok_or(ERROR)?
            .min(invitation.policy().expires_at_ms)
            / 1_000;
        let expires_at_ms = contact_expiry.checked_mul(1_000).ok_or(ERROR)?;
        if expires_at_ms <= at_ms {
            return Err("Invitation expired.".into());
        }
        let mut state = self.durable_state()?;
        // A submitted mutation may have succeeded. Retain its recovery material
        // even after expiry until reconciliation or explicit cancellation.
        state.entries.retain(|_, pending| {
            pending.packet.expires_at_ms > at_ms || pending.submitted.is_some()
        });
        let origin = reqwest::Url::parse(&invitation.descriptor().address.url)?
            .origin()
            .ascii_serialization();
        for pending in state.entries.values() {
            if pending.packet.request.policy == invitation.descriptor().policy
                && same(&pending.packet.address, &invitation.descriptor().address)?
                && pending.packet.expires_at_ms > at_ms
                && decode_record(&pending.packet.request.contact)?.body()["name"] == name
            {
                self.restore_durable_pending(pending, &origin)?;
                return Ok(pending.packet.clone());
            }
        }
        if state.entries.values().any(|pending| {
            pending.submitted.is_some()
                && pending.packet.address.scope.space == invitation.authority().space()
                && pending.packet.address.scope.stream == invitation.authority().stream()
                && pending.packet.credential
                    == STANDARD.encode(self.session.credential().record().bytes())
        }) {
            return Err(
                "An earlier admission is awaiting confirmation. Retry it before joining again."
                    .into(),
            );
        }
        if state.entries.len() >= MAX_PENDING {
            return Err(ERROR.into());
        }
        let contact = invite::shared::contact(
            self.session.credential(),
            self.session.signing_key(),
            name,
            contact_expiry,
        )?;
        let request = WitnessJoinRequest {
            v: 1,
            kind: "witness.join_request".into(),
            nonce: record::random_hex::<32>()?,
            space_id: invitation.authority().space(),
            stream_id: invitation.authority().stream(),
            policy_id: decode_record(&invitation.descriptor().policy)?.id(),
            credential_id: self.session.credential().id(),
            contact_id: contact.id(),
            issued_at_ms: at_ms,
            expires_at_ms,
            witness_key_generation: invitation.descriptor().witness.key_generation,
        };
        let body = serde_json::to_vec(&request)?;
        let signed = SignedRecord::sign(&body, self.session.signing_key())?;
        let packet = DurableAdmissionRequest {
            request_id: signed.id(),
            name: invitation.descriptor().name.clone(),
            address: invitation.descriptor().address.clone(),
            credential: STANDARD.encode(self.session.credential().record().bytes()),
            request: WitnessJoinRequestEvidence {
                policy: invitation.descriptor().policy.clone(),
                device_request: STANDARD.encode(signed.bytes()),
                invitation_request: STANDARD.encode(
                    SignedRecord::sign(&body, invitation.invitation_signing_key())?.bytes(),
                ),
                contact: STANDARD.encode(contact.bytes()),
            },
            expires_at_ms,
        };
        check_packet(invitation.authority(), &packet, at_ms)?;
        state.entries.insert(
            packet.request_id,
            Pending {
                packet: packet.clone(),
                descriptor: STANDARD.encode(invitation.signed_record().bytes()),
                invitation_signing_seed: invitation.invitation_signing_key().to_bytes(),
                approval: None,
                submitted: None,
            },
        );
        self.write_durable_state(&state)?;
        Ok(packet)
    }

    /// Public metadata only. A listing does not renew a challenge or grant.
    pub fn witness_durable_admissions(&self) -> Result<Vec<DurableAdmissionRequest>> {
        let state = self.durable_state()?;
        let mut pending: Vec<_> = state.entries.values().collect();
        // An uncertain mutation must not be hidden by an older approval wait.
        // Scope recovery below handles more than one uncertain request together.
        pending.sort_by_key(|pending| match &pending.submitted {
            Some(submitted) if submitted.receipt.is_some() => 0,
            Some(_) => 1,
            None if pending.approval.is_some() => 2,
            None => 3,
        });
        let mut result = Vec::new();
        for pending in pending {
            let origin = reqwest::Url::parse(&pending.packet.address.url)?
                .origin()
                .ascii_serialization();
            self.restore_durable_pending(pending, &origin)?;
            result.push(pending.packet.clone());
        }
        Ok(result)
    }

    /// The caller supplies the selected local General. A relay cannot choose a
    /// different Space or make an owner sign without a fresh independent head.
    pub async fn witness_approve_durable_admission(
        &self,
        authority: &Authority,
        packet: &DurableAdmissionRequest,
        readmission: bool,
    ) -> Result<SignedRecord> {
        self.trusted_witness(authority)?;
        if !authority.can_manage(self.session.credential().id()) {
            return Err(ERROR.into());
        }
        let current = self.witness_read_authority(authority).await?;
        self.check_durable_local_ancestry(&current)?;
        if !current.can_manage(self.session.credential().id()) {
            return Err(ERROR.into());
        }
        let at_ms = now()?.as_millis() as u64;
        check_packet(&current, packet, at_ms)?;
        let credential = candidate(packet)?;
        if !readmission && super::witness_admission::known_removal(&current, credential.identity())?
        {
            return Err(ERROR.into());
        }
        let approval = WitnessApprovalV2 {
            v: 2,
            kind: "witness.approval".into(),
            nonce: record::random_hex::<16>()?,
            space_id: current.space(),
            stream_id: current.stream(),
            authority_head: current.head_id().ok_or(ERROR)?,
            issuer_credential_id: self.session.credential().id(),
            request_id: packet.request_id,
            readmission,
            expires_at_ms: packet.expires_at_ms,
        };
        Ok(SignedRecord::sign(
            &serde_json::to_vec(&approval)?,
            self.session.signing_key(),
        )?)
    }

    /// The caller must first obtain an independently fresh authority. A relay
    /// may retain another owner's approval, but cannot revive consent across
    /// an owner demotion or a later removal of any candidate identity device.
    pub(super) fn witness_verify_existing_durable_approval(
        &self,
        authority: &Authority,
        packet: &DurableAdmissionRequest,
        signed: &SignedRecord,
    ) -> Result<()> {
        self.trusted_witness(authority)?;
        self.check_durable_local_ancestry(authority)?;
        let at_ms = now()?.as_millis() as u64;
        let request = check_packet(authority, packet, at_ms)?;
        let approval: WitnessApprovalV2 = signed.decode()?;
        record::hex::<16>(&approval.nonce)?;
        if approval.v != 2
            || approval.kind != "witness.approval"
            || approval.space_id != authority.space()
            || approval.stream_id != authority.stream()
            || approval.request_id != packet.request_id
            || approval.expires_at_ms <= at_ms
            || approval.expires_at_ms > request.expires_at_ms
            || !authority.can_manage(approval.issuer_credential_id)
        {
            return Err(ERROR.into());
        }
        signed.verify_signature(authority.credential(approval.issuer_credential_id)?.key())?;
        let identity = candidate(packet)?.identity();
        let approval_sequence = authority.config(approval.authority_head)?.sequence;
        let mut found_approval = false;
        let mut last_removal = None;
        let mut cursor = authority.head_id();
        while let Some(id) = cursor {
            let config = authority.config(id)?;
            if !found_approval {
                if !config
                    .owner_credential_ids
                    .contains(&approval.issuer_credential_id)
                {
                    return Err(ERROR.into());
                }
                found_approval = id == approval.authority_head;
            }
            if last_removal.is_none()
                && let Some(previous) = config.previous_config_id
            {
                let previous = authority.config(previous)?;
                let before = previous.members.iter().find(|m| m.identity_id == identity);
                let after = config.members.iter().find(|m| m.identity_id == identity);
                if before.is_some_and(|member| {
                    member
                        .credential_ids
                        .iter()
                        .any(|id| after.is_none_or(|m| !m.credential_ids.contains(id)))
                }) {
                    last_removal = Some(config.sequence);
                }
            }
            cursor = config.previous_config_id;
        }
        if !found_approval
            || last_removal
                .is_some_and(|sequence| !approval.readmission || approval_sequence < sequence)
        {
            return Err(ERROR.into());
        }
        Ok(())
    }

    async fn durable_exchange(&self, pin: &WitnessPin, request: &Request) -> Result<Exchange> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(10))
            .build()?;
        let response = client
            .post(self.witness_endpoint(pin, "command")?)
            .json(request)
            .send()
            .await
            .map_err(|_| ERROR)?;
        if response.status() == reqwest::StatusCode::FORBIDDEN {
            return Ok(Exchange::Forbidden);
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|size| size > RESPONSE_BYTES as u64)
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
        Ok(Exchange::Response(
            serde_json::from_slice(&bytes).map_err(|_| ERROR)?,
        ))
    }

    fn check_durable_admitted(
        &self,
        pending: &Pending,
        base: &Authority,
        proof: &CallAuthorityProof,
    ) -> Result<Authority> {
        let authority =
            proof.verify_witnessed(base.space(), base.stream(), self.trusted_witness(base)?)?;
        if !authority.proves_config_at(base.head_id().ok_or(ERROR)?, base.head()?.sequence) {
            return Err(ERROR.into());
        }
        let current = authority.credential(self.session.credential().id())?;
        if current.record().bytes() != self.session.credential().record().bytes()
            || !authority.head()?.members.iter().any(|m| {
                m.identity_id == self.identity_id()
                    && m.credential_ids.contains(&current.id())
                    && m.capabilities.contains(&Capability::Read)
                    && m.capabilities.contains(&Capability::Post)
            })
        {
            return Err(ERROR.into());
        }
        let mut found = false;
        let mut head = authority.head()?;
        loop {
            if let Some(WitnessConfigEvidence::AdmissionV2 { evidence }) = &head.witness_evidence
                && decode_record(&evidence.request.device_request)?.id()
                    == pending.packet.request_id
            {
                if !same(&evidence.request, &pending.packet.request)?
                    || head.action.request_record_id != Some(pending.packet.request_id)
                {
                    return Err(ERROR.into());
                }
                let intent: WitnessAdmissionIntentV2 =
                    decode_record(&evidence.device_intent)?.decode()?;
                if intent.credential_id != current.id() {
                    return Err(ERROR.into());
                }
                found = true;
            }
            let Some(previous) = head.previous_config_id else {
                break;
            };
            head = authority.config(previous)?;
        }
        if !found {
            return Err(ERROR.into());
        }
        self.check_durable_local_ancestry(&authority)?;
        Ok(authority)
    }

    fn check_durable_local_ancestry(&self, authority: &Authority) -> Result<()> {
        let check = |client: &ClientApp| -> Result<()> {
            for local in &*client.authorities.0 {
                if local.space() == authority.space()
                    && local.stream() == authority.stream()
                    && (local.is_forked()
                        || !authority.proves_config_at(
                            local.head_id().ok_or(ERROR)?,
                            local.head()?.sequence,
                        ))
                {
                    return Err(ERROR.into());
                }
            }
            Ok(())
        };
        check(self)?;
        if let Some(spaces) = &self.spaces {
            for client in spaces.clients(self) {
                check(client)?;
            }
        }
        Ok(())
    }

    async fn reconcile_durable_admission(
        &self,
        pending: &Pending,
        base: &Authority,
    ) -> Result<Option<Authority>> {
        let Some(proof) = self.read_durable_admission(base).await? else {
            return Ok(None);
        };
        let authority = self.check_durable_admitted(pending, base, &proof)?;
        self.fetch_witness_freshness(&authority, Instant::now())
            .await?;
        Ok(Some(authority))
    }

    async fn read_durable_admission(&self, base: &Authority) -> Result<Option<CallAuthorityProof>> {
        let (_, signed) =
            self.admission_command(base, base.head_id().ok_or(ERROR)?, Operation::Read)?;
        let response = self
            .durable_exchange(
                self.trusted_witness(base)?,
                &Request {
                    command: STANDARD.encode(signed.bytes()),
                    invitation_signature: None,
                    proof: None,
                    registration_work: None,
                },
            )
            .await?;
        let Exchange::Response(response) = response else {
            // An unsigned 403 is not proof of absence. A later mutation still
            // requires a new signed, nonce-bound unconsumed-request challenge.
            return Ok(None);
        };
        if response.receipt.is_some() || response.challenge.is_some() {
            return Err(ERROR.into());
        }
        Ok(Some(response.proof.ok_or(ERROR)?))
    }

    /// One read resolves every uncertain request for the selected local scope.
    /// No new admission is sent, and a failed or mismatched read keeps all state.
    pub(super) async fn witness_reconcile_pending_scope(
        &self,
        scope: &team::TeamScope,
        configured_api_origin: &str,
    ) -> Result<Option<(DurableAdmissionRequest, Authority)>> {
        let state = self.durable_state()?;
        let credential = STANDARD.encode(self.session.credential().record().bytes());
        let mut pending = Vec::new();
        for entry in state.entries.values() {
            if entry.submitted.is_some()
                && entry.packet.credential == credential
                && same(&entry.packet.address.scope, scope)?
            {
                pending.push(entry);
            }
        }
        let Some(first) = pending.first() else {
            return Ok(None);
        };
        let descriptor = self.restore_durable_pending(first, configured_api_origin)?;
        let Some(proof) = self.read_durable_admission(descriptor.authority()).await? else {
            return Ok(None);
        };
        for pending in pending {
            let descriptor = self.restore_durable_pending(pending, configured_api_origin)?;
            if let Ok(authority) =
                self.check_durable_admitted(pending, descriptor.authority(), &proof)
            {
                self.fetch_witness_freshness(&authority, Instant::now())
                    .await?;
                return Ok(Some((pending.packet.clone(), authority)));
            }
        }
        Err(ERROR.into())
    }

    /// A restart or uncertain mutation first reconciles the exact stable request.
    /// Old Admit commands are never replayed. A fresh verified challenge is
    /// required before another attempt, and no result alone removes local state.
    pub async fn witness_finalize_durable_admission(
        &mut self,
        request_id: RecordId,
        configured_api_origin: &str,
        approval: Option<&SignedRecord>,
    ) -> Result<DurableAdmissionOutcome> {
        let mut state = self.durable_state()?;
        let mut pending = state.entries.remove(&request_id).ok_or(ERROR)?;
        let invitation = self.restore_durable_pending(&pending, configured_api_origin)?;
        let base = invitation.authority();
        let pin = self.trusted_witness(base)?.clone();
        if pending.submitted.is_some() {
            if let Some(authority) = self.reconcile_durable_admission(&pending, base).await? {
                return Ok(DurableAdmissionOutcome::Admitted(Box::new(authority)));
            }
            // Once a signed ACK exists, a 403 cannot authorize a new mutation.
            // Removal or a forged HTTP response must not recycle old consent.
            if pending
                .submitted
                .as_ref()
                .is_some_and(|s| s.receipt.is_some())
            {
                return Err(ERROR.into());
            }
        }
        let at_ms = now()?.as_millis() as u64;
        if at_ms >= pending.packet.expires_at_ms {
            self.witness_cancel_durable_admission(request_id)?;
            return Err("Invitation expired.".into());
        }
        if let Some(approval) = approval {
            let body: WitnessApprovalV2 = approval.decode()?;
            record::hex::<16>(&body.nonce)?;
            if body.v != 2
                || body.kind != "witness.approval"
                || body.space_id != base.space()
                || body.stream_id != base.stream()
                || body.request_id != request_id
                || body.expires_at_ms <= at_ms
                || body.expires_at_ms > pending.packet.expires_at_ms
            {
                return Err(ERROR.into());
            }
            // Its issuer/head may be newer than the descriptor. The witness and
            // returned complete proof validate signature and owner continuity.
            pending.approval = Some(STANDARD.encode(approval.bytes()));
            self.save_durable_pending(&pending)?;
        }
        if pending.approval.is_none()
            && (invitation.policy().require_approval
                || super::witness_admission::known_removal(base, self.identity_id())?)
        {
            return Ok(DurableAdmissionOutcome::ApprovalRequired);
        }
        let (command, signed) = self.admission_command(
            base,
            base.head_id().ok_or(ERROR)?,
            Operation::ChallengeV2 {
                credential: pending.packet.credential.clone(),
                request: pending.packet.request.clone(),
                client_nonce: record::random_hex::<32>()?,
            },
        )?;
        let possession =
            SignedRecord::sign(signed.body_bytes(), invitation.invitation_signing_key())?;
        let floor = self.witness_position(&pin)?;
        let started = Instant::now();
        let Exchange::Response(response) = self
            .durable_exchange(
                &pin,
                &Request {
                    command: STANDARD.encode(signed.bytes()),
                    invitation_signature: Some(STANDARD.encode(possession.bytes())),
                    proof: None,
                    registration_work: None,
                },
            )
            .await?
        else {
            return Err(ERROR.into());
        };
        if response.proof.is_some() {
            return Err(ERROR.into());
        }
        let encoded = response.challenge.ok_or(ERROR)?;
        let record = decode_record(&encoded)?;
        record.verify_signature(&pin.key()?)?;
        let challenge: WitnessChallengeV2 = record.decode()?;
        let Operation::ChallengeV2 { client_nonce, .. } = &command.operation else {
            return Err(ERROR.into());
        };
        let now_ms = now()?.as_millis() as u64;
        record::hex::<32>(&challenge.nonce)?;
        if challenge.v != 2
            || challenge.kind != "witness.challenge"
            || challenge.space_id != base.space()
            || challenge.stream_id != base.stream()
            || challenge.policy_id != decode_record(&pending.packet.request.policy)?.id()
            || challenge.credential_id != self.session.credential().id()
            || challenge.request_id != request_id
            || challenge.client_nonce != *client_nonce
            || challenge.witness_key_generation != pin.key_generation
            || challenge.issued_at_ms < command.issued_at_ms.saturating_sub(5_000)
            || challenge.issued_at_ms > now_ms.saturating_add(5_000)
            || challenge.expires_at_ms <= challenge.issued_at_ms
            || challenge.expires_at_ms - challenge.issued_at_ms > 120_000
            || challenge.expires_at_ms > pending.packet.expires_at_ms
            || now_ms >= challenge.expires_at_ms
            || started.elapsed() >= Duration::from_secs(120)
        {
            return Err(ERROR.into());
        }
        let (receipt, position) = super::witness_admission::verify_ack(
            &pin,
            &signed,
            &command,
            response.receipt.as_deref().ok_or(ERROR)?,
            "invitation.challenged_v2",
            now_ms,
            floor.as_ref(),
        )?;
        if receipt.authority_head != challenge.authority_head
            || receipt.accepted_at_ms != challenge.issued_at_ms
        {
            return Err(ERROR.into());
        }
        self.record_witness_receipt_position(&pin, position, receipt.previous)?;
        let request: WitnessJoinRequest =
            decode_record(&pending.packet.request.device_request)?.decode()?;
        let intent = WitnessAdmissionIntentV2 {
            v: 2,
            kind: "witness.admission".into(),
            nonce: record::random_hex::<32>()?,
            space_id: base.space(),
            stream_id: base.stream(),
            policy_id: request.policy_id,
            request_id,
            challenge_id: record.id(),
            credential_id: self.session.credential().id(),
            contact_id: request.contact_id,
        };
        let bytes = serde_json::to_vec(&intent)?;
        let evidence = WitnessAdmissionEvidenceV2 {
            request: pending.packet.request.clone(),
            challenge: encoded,
            device_intent: STANDARD
                .encode(SignedRecord::sign(&bytes, self.session.signing_key())?.bytes()),
            invitation_intent: STANDARD
                .encode(SignedRecord::sign(&bytes, invitation.invitation_signing_key())?.bytes()),
            approval: pending.approval.clone(),
            admitted_at_ms: 0,
        };
        let (command, signed) = self.admission_command(
            base,
            challenge.authority_head,
            Operation::AdmitV2 {
                credential: pending.packet.credential.clone(),
                evidence,
            },
        )?;
        pending.submitted = Some(Submitted {
            command: STANDARD.encode(signed.bytes()),
            receipt: None,
        });
        // Persist before the mutation can leave the process. Cancellation or
        // process termination after this point always leads to reconciliation.
        self.save_durable_pending(&pending)?;
        let floor = self.witness_position(&pin)?;
        let Exchange::Response(response) = self
            .durable_exchange(
                &pin,
                &Request {
                    command: STANDARD.encode(signed.bytes()),
                    invitation_signature: None,
                    proof: None,
                    registration_work: None,
                },
            )
            .await?
        else {
            return Err(ERROR.into());
        };
        if response.challenge.is_some() {
            return Err(ERROR.into());
        }
        let ack = response.receipt.ok_or(ERROR)?;
        let (receipt, position) = super::witness_admission::verify_ack(
            &pin,
            &signed,
            &command,
            &ack,
            "device.admitted_v2",
            now()?.as_millis() as u64,
            floor.as_ref(),
        )?;
        self.record_admission_receipt_position(&pin, position, receipt.previous)?;
        pending.submitted.as_mut().ok_or(ERROR)?.receipt = Some(ack);
        self.save_durable_pending(&pending)?;
        let authority = self
            .reconcile_durable_admission(&pending, base)
            .await?
            .ok_or(ERROR)?;
        Ok(DurableAdmissionOutcome::Admitted(Box::new(authority)))
    }

    /// Call only after the caller has durably applied this membership proof.
    pub fn witness_complete_durable_admission(
        &mut self,
        request_id: RecordId,
        applied: &Authority,
    ) -> Result<()> {
        let mut state = self.durable_state()?;
        let Some(pending) = state.entries.get(&request_id) else {
            return Ok(());
        };
        let origin = reqwest::Url::parse(&pending.packet.address.url)?
            .origin()
            .ascii_serialization();
        let descriptor = self.restore_durable_pending(pending, &origin)?;
        self.check_durable_admitted(pending, descriptor.authority(), &applied.call_proof()?)?;
        // Current independently verified membership fulfills every pending
        // request for this exact scope and device. Retaining obsolete requests
        // would restart their approval/admission flow after a successful join.
        let scope = serde_json::to_value(&pending.packet.address.scope)?;
        let credential = pending.packet.credential.clone();
        let mut obsolete = Vec::new();
        for (id, pending) in &state.entries {
            if pending.packet.credential == credential
                && serde_json::to_value(&pending.packet.address.scope)? == scope
            {
                obsolete.push(*id);
            }
        }
        for id in obsolete {
            state.entries.remove(&id);
        }
        self.write_durable_state(&state)
    }

    /// Local cancellation cannot revoke a mutation already accepted by witness.
    pub fn witness_cancel_durable_admission(&mut self, request_id: RecordId) -> Result<()> {
        let mut state = self.durable_state()?;
        if state.entries.remove(&request_id).is_some() {
            self.write_durable_state(&state)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

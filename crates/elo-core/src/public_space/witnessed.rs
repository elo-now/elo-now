//! Witnessed membership has one import path. HTTP transport state never creates
//! an invitation bearer or a competing owner-managed membership configuration.
use super::*;
use crate::witness::VerifiedFreshness;

impl PublicSpaceService {
    fn verify_witnessed_request(&self, request: &Request) -> Result<(VerifiedCredential, Command)> {
        if self.trusted_witness.is_none() || request.invitation.is_some() {
            return Err("Witnessed Space authentication is required.".into());
        }
        record::hex::<16>(&request.nonce)?;
        let credential = verify_credential(
            request
                .credential
                .as_deref()
                .ok_or("Missing device proof.")?,
        )?;
        let signed = decode_record(request.record.as_deref().ok_or("Missing signature.")?)?;
        signed.verify_signature(credential.key())?;
        let command: Command = signed.decode()?;
        if command.v != 1
            || command.kind != "space.command"
            || command.space != self.authorities.0[0].space()
            || command.nonce != request.nonce
            || time()?.abs_diff(command.issued) > 120_000
        {
            return Err("Invalid or expired Space request.".into());
        }
        let state = self.service_state()?;
        if state.revoked.contains(&credential.id())
            || state.erased_accounts.contains(&credential.identity())
        {
            return Err("This device is no longer admitted to the Space.".into());
        }
        Ok((credential, command))
    }

    /// Prepare without mutating state, then let the host query its independent
    /// witness. The caller repeats verification under its Space/client guards.
    pub fn witnessed_request_authority(&self, request: &Request) -> Result<Authority> {
        let (credential, command) = self.verify_witnessed_request(request)?;
        let previous = &self.authorities.0[0];
        let next = if command.action == "witness_sync" {
            let proof: CallAuthorityProof = serde_json::from_value(command.body["proof"].clone())?;
            if proof.checkpoint.is_some() {
                return Err("A complete witnessed authority proof is required.".into());
            }
            let next = proof.verify_witnessed(
                previous.space(),
                previous.stream(),
                self.trusted_witness
                    .as_ref()
                    .ok_or("Missing witness pin.")?,
            )?;
            if next.genesis().bytes() != previous.genesis().bytes()
                || !next.proves_config_at(
                    previous.head_id().ok_or("Missing General head.")?,
                    previous.head()?.sequence,
                )
                || !next.proves_recovery_ancestor(previous.recovery_id())
            {
                return Err("Witnessed General does not extend the stored authority.".into());
            }
            let enrollment: team::EnrollmentRequest =
                serde_json::from_value(command.body["enrollment"].clone())?;
            let (identity, device, _) = self.space_applicant(&enrollment)?;
            if identity != credential.identity() || device != credential.id() {
                return Err("This request belongs to another profile.".into());
            }
            next
        } else {
            if matches!(
                command.action.as_str(),
                "join"
                    | "invite"
                    | "revoke"
                    | "decide"
                    | "role_change"
                    | "role_decide"
                    | "authority"
                    | "authority_publish"
            ) {
                return Err("This operation requires the independent witness.".into());
            }
            previous.clone()
        };
        if self.relay_candidate(&command, &credential)? {
            return Ok(next);
        }
        if crate::calls::require_member(&next, credential.id())? != credential.identity()
            || next.credential(credential.id())?.record().bytes() != credential.record().bytes()
        {
            return Err("This exact device is not admitted by the witness.".into());
        }
        Ok(next)
    }

    /// Only the host's independently fetched lease authorizes this path. The
    /// service signer can neither produce the lease nor replace the pinned key.
    pub async fn serve_hosted_witnessed_space(
        &mut self,
        config: &ServiceConfig,
        request: Request,
        replica: &crate::replica::ReplicaStore,
        freshness: &VerifiedFreshness,
    ) -> Result<Response> {
        let next = self.witnessed_request_authority(&request)?;
        let pin = self
            .trusted_witness
            .as_ref()
            .ok_or("Missing witness pin.")?;
        let lease = freshness.body();
        if !freshness.is_valid(time()?)
            || lease.audience != pin.url
            || lease.witness_key_generation != pin.key_generation
            || lease.space_id != next.space()
            || lease.stream_id != next.stream()
            || Some(lease.authority_head) != next.head_id()
        {
            return Err("Witnessed General needs to be refreshed.".into());
        }
        let (credential, command) = self.verify_witnessed_request(&request)?;
        replica.require_active_device(credential.id())?;
        if let Some(value) = self.witnessed_relay_command(config, &credential, &command)? {
            return self.witnessed_reply(&credential, &command, &request.nonce, value);
        }
        if command.action != "witness_sync" {
            return self.serve_space_inner(config, request, Some(replica)).await;
        }
        config.address.validate(self.allow_loopback)?;
        if serde_json::to_value(self.team_scope()?)? != serde_json::to_value(&config.address.scope)?
            || config.address.service_credential.as_deref()
                != Some(self.transport_credential().as_str())
        {
            return Err("Space service configuration mismatch.".into());
        }
        let mut state = self.service_state()?;
        self.apply_device_revocations(&mut state, replica)?;
        for member in &next.head()?.members {
            if state.erased_accounts.contains(&member.identity_id) {
                return Err("Deleted accounts cannot be restored to this Space.".into());
            }
            for device in &member.credential_ids {
                replica.require_active_device(*device)?;
                if state.revoked.contains(device) {
                    return Err("Revoked devices cannot be restored to this Space.".into());
                }
            }
        }
        let old = &self.authorities.0[0];
        let mut transitions = Vec::new();
        let mut cursor = next.head_id().ok_or("Missing General head.")?;
        while Some(cursor) != old.head_id() {
            let config = next.config(cursor)?;
            transitions.push((cursor, config));
            cursor = config
                .previous_config_id
                .ok_or("Missing witnessed ancestry.")?;
        }
        // A remove-and-readmit sequence still changes the membership epoch even
        // when both events arrived in a single proof synchronization.
        for (id, config) in transitions.iter().rev() {
            let prior = next.config(
                config
                    .previous_config_id
                    .ok_or("Missing witnessed ancestry.")?,
            )?;
            for member in &prior.members {
                if !config
                    .members
                    .iter()
                    .any(|m| m.identity_id == member.identity_id)
                {
                    let epoch = state
                        .removals
                        .get(&member.identity_id)
                        .copied()
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or("Membership revision limit reached.")?;
                    state.removals.insert(member.identity_id, epoch);
                    state.removal_heads.insert(member.identity_id, *id);
                }
            }
        }
        for (id, applicant) in &mut state.applicants {
            applicant.status = if id.parse().ok().is_some_and(|id| {
                crate::calls::require_member(&next, id).ok() == Some(applicant.identity)
            }) {
                "approved"
            } else {
                "removed"
            }
            .into();
            applicant.note.clear();
        }
        let mut owners = next
            .head()?
            .members
            .iter()
            .filter(|m| {
                m.capabilities
                    .contains(&crate::authority::Capability::Manage)
            })
            .map(|m| m.identity_id)
            .collect::<Vec<_>>();
        let primary = next.primary_owner_identity()?;
        if state
            .roles
            .as_ref()
            .is_some_and(|roles| roles.primary != primary)
        {
            return Err("Space primary owner does not match its signed creation.".into());
        }
        let index = owners
            .iter()
            .position(|id| *id == primary)
            .ok_or("The primary owner cannot be removed.")?;
        owners.swap(0, index);
        let mut roles = Roles::bootstrap(&owners)?;
        roles.contact_email = state
            .roles
            .as_ref()
            .and_then(|r| r.contact_email.clone())
            .or_else(|| config.contact_email.clone());
        roles.revision = next.head()?.sequence;
        state.roles = Some(roles);
        let enrollment: team::EnrollmentRequest =
            serde_json::from_value(command.body["enrollment"].clone())?;
        let (identity, device, name) = self.space_applicant(&enrollment)?;
        if !state.applicants.contains_key(&device.to_string()) {
            state.require_applicant_capacity(identity, "", false)?;
        }
        state.applicants.insert(
            device.to_string(),
            Applicant {
                authorization: None,
                identity,
                name,
                status: "approved".into(),
                invitation: String::new(),
                note: String::new(),
                request: enrollment,
                requested_at: time()?,
            },
        );
        state.proof = next.call_proof()?;
        state.claimed = true;
        state.offers.clear();
        state.replies.clear();
        if !freshness.is_valid(time()?) {
            return Err("Witnessed General needs to be refreshed.".into());
        }
        self.save_service_state(&state)?;
        self.authorities.0[0] = next;
        let value = self
            .space_join_reply(config, &state, &device.to_string(), None)
            .await?;
        self.witnessed_reply(&credential, &command, &request.nonce, value)
    }
    fn witnessed_reply(
        &self,
        credential: &VerifiedCredential,
        command: &Command,
        nonce: &str,
        value: Value,
    ) -> Result<Response> {
        let ciphertext = crypto::seal_bytes(
            &Zeroizing::new(serde_json::to_vec(&value)?),
            &[credential.recipient()],
            LIMIT,
        )?;
        let answer = Answer {
            v: 1,
            kind: "space.response".into(),
            space: command.space,
            nonce: nonce.into(),
            body: None,
            ciphertext_hash: Some(crate::ids::ObjectId::of_ciphertext(&ciphertext).to_string()),
        };
        Ok(Response {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&answer)?, &self.signing_key)?.bytes(),
            ),
            credential: self.transport_credential(),
            ciphertext: Some(STANDARD.encode(ciphertext)),
        })
    }
}

//! Public-only hosting state for owner-managed General.
//! The sole private key signs HTTP responses and is never a General recipient.
use crate::{
    app::{
        Result,
        space_service::{
            DeletionReceipt, LIFETIMES, Request, Response, ServiceConfig, SpaceAddress,
            SpaceInvitation, validate_contact_email,
        },
        team,
    },
    authority::{Authority, CallAuthorityProof},
    crypto,
    identity::{DeviceCredential, VerifiedCredential},
    ids::{AttachmentId, AttachmentObjectId, IdentityId, RecordId, SpaceId, StreamId},
    record::{self, SignedRecord},
    vault,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
mod attachments;
mod calls;
pub(crate) mod roles;
use attachments::{AttachmentAccess, HostedAttachment, bytes_in_state};
pub use attachments::{AttachmentCleanupTarget, AttachmentStorageUsage, AttachmentTransferGrant};
use roles::Roles;
const LIMIT: usize = 8 * 1024 * 1024;
const STATE_LIMIT: usize = 32 * 1024 * 1024;

/// Original device-signed administration intent; transport signatures alone
/// never authorize changing the General recipients or its owners.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminEvidence {
    pub record: String,
    pub credential: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportSigner {
    seed: String,
    credential: String,
}
struct Authorities(Vec<Authority>);
pub struct PublicSpaceService {
    directory: PathBuf,
    signing_key: SigningKey,
    credential: VerifiedCredential,
    authorities: Authorities,
    allow_loopback: bool,
}
fn time() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64)
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| "Missing request field.".into())
}
fn decode_record(encoded: &str) -> Result<SignedRecord> {
    Ok(SignedRecord::parse(&STANDARD.decode(encoded)?)?)
}
fn verify_credential(encoded: &str) -> Result<VerifiedCredential> {
    let signed = decode_record(encoded)?;
    let root = VerifyingKey::from_bytes(&record::hex(field(signed.body(), "root_public_key")?)?)?;
    Ok(VerifiedCredential::verify(signed.bytes(), &root)?)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    v: u8,
    kind: String,
    space: SpaceId,
    nonce: String,
    issued: u64,
    action: String,
    body: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Answer {
    v: u8,
    kind: String,
    space: SpaceId,
    nonce: String,
    body: Option<Value>,
    ciphertext_hash: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    #[serde(default)]
    authorization: Option<AdminEvidence>,
    token: String,
    #[serde(default)]
    issued_at: u64,
    expires_at: u64,
    require_approval: bool,
    revoked: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Applicant {
    #[serde(default)]
    authorization: Option<AdminEvidence>,
    identity: IdentityId,
    name: String,
    status: String,
    invitation: String,
    #[serde(default)]
    note: String,
    request: team::EnrollmentRequest,
    #[serde(default)]
    requested_at: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceState {
    #[serde(default)]
    creation: Option<AdminEvidence>,
    #[serde(default)]
    journal: Vec<AdminEvidence>,
    #[serde(default)]
    committed_journal: Vec<AdminEvidence>,
    #[serde(default)]
    revocation_proofs: BTreeMap<RecordId, String>,
    #[serde(default)]
    account_deletions: BTreeMap<IdentityId, AdminEvidence>,
    proof: CallAuthorityProof,
    #[serde(default)]
    revoked: BTreeSet<RecordId>,
    #[serde(default)]
    claimed: bool,
    offers: BTreeMap<String, Offer>,
    applicants: BTreeMap<String, Applicant>,
    replies: BTreeMap<String, (u64, String, Value)>,
    #[serde(default)]
    roles: Option<Roles>,
    #[serde(default)]
    #[serde(rename = "requests", skip_serializing)]
    _legacy_requests: Value,
    #[serde(default)]
    removals: BTreeMap<IdentityId, u64>,
    #[serde(default)]
    removal_heads: BTreeMap<IdentityId, RecordId>,
    #[serde(default)]
    erased_accounts: BTreeSet<IdentityId>,
    #[serde(default)]
    attachment_policy: crate::attachments::AttachmentPolicy,
    #[serde(default)]
    attachments: BTreeMap<AttachmentId, HostedAttachment>,
    #[serde(default)]
    attachment_access: BTreeMap<String, AttachmentAccess>,
    #[serde(default)]
    call_heads: BTreeMap<String, calls::PublishedHead>,
}

impl ServiceState {
    fn device_was_declined(&self, credential: &str) -> Result<bool> {
        for evidence in self.journal.iter().rev() {
            let signed = decode_record(&evidence.record)?;
            let body = signed.body();
            if body["kind"] == "space.command"
                && body["action"] == "decide"
                && body["body"]["id"] == credential
            {
                return Ok(body["body"]["approve"] == false);
            }
        }
        Ok(false)
    }
    fn removal_blocks(&self, identity: IdentityId) -> bool {
        self.removals.contains_key(&identity)
            && !self
                .applicants
                .values()
                .any(|a| a.identity == identity && a.status == "approved")
    }
    fn reservation_is_unused(&self, now: u64) -> bool {
        !self.claimed
            && self.applicants.is_empty()
            && self.removals.is_empty()
            && self.erased_accounts.is_empty()
            && self.attachments.is_empty()
            && self.offers.values().all(|offer| offer.expires_at <= now)
    }

    fn prune_applicants(&mut self, current: u64) {
        self.applicants.retain(|_, applicant| {
            !matches!(applicant.status.as_str(), "pending" | "eligible")
                || (current.saturating_sub(applicant.requested_at) < 7 * 86_400_000
                    && (applicant.invitation.is_empty()
                        || self
                            .offers
                            .get(&applicant.invitation)
                            .is_some_and(|offer| !offer.revoked && offer.expires_at > current)))
        });
        if self.applicants.len() >= record::MAX_CHAT_CREDENTIALS {
            self.applicants.retain(|_, applicant| {
                !matches!(applicant.status.as_str(), "declined" | "removed")
            });
        }
    }

    fn require_applicant_capacity(
        &self,
        identity: IdentityId,
        invitation: &str,
        pending: bool,
    ) -> Result<()> {
        let active = |a: &&Applicant| a.status == "approved";
        if pending {
            let requests: Vec<_> = self
                .applicants
                .values()
                .filter(|a| matches!(a.status.as_str(), "pending" | "eligible"))
                .collect();
            // A leaked invitation cannot consume every slot. Revoking that invitation
            // frees its requests; approved members use a separate admission budget.
            if requests.len() >= 256
                || requests
                    .iter()
                    .filter(|a| a.invitation == invitation)
                    .count()
                    >= 32
                || requests.iter().filter(|a| a.identity == identity).count() >= 4
            {
                return Err("Space request limit reached.".into());
            }
        } else if self.applicants.values().filter(active).count() >= record::MAX_CHAT_CREDENTIALS {
            return Err("Space member limit reached.".into());
        }
        Ok(())
    }
}

fn join_note(value: &Value) -> Result<String> {
    let note = match value.get("note") {
        None => "",
        Some(Value::String(s)) => s.trim(),
        _ => return Err("Enter a note of up to 500 characters.".into()),
    };
    if note.chars().count() > 500
        || note
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err("Enter a note of up to 500 characters.".into());
    }
    Ok(note.into())
}
pub fn request_identity(request: &Request) -> Result<Option<IdentityId>> {
    let Some(record) = &request.record else {
        return Ok(None);
    };
    let credential =
        verify_credential(request.credential.as_deref().ok_or("Missing credential.")?)?;
    decode_record(record)?.verify_signature(credential.key())?;
    Ok(Some(credential.identity()))
}
impl PublicSpaceService {
    /// Host-local inspection for a verified account-deletion request.
    pub fn account_membership(
        &self,
        config: &ServiceConfig,
        identity: IdentityId,
    ) -> Result<Value> {
        let state = self.service_state()?;
        let primary = state
            .roles
            .as_ref()
            .map(|r| r.primary)
            .or_else(|| config.owners.first().copied());
        let members: BTreeSet<_> = state
            .applicants
            .values()
            .filter(|a| a.status == "approved")
            .map(|a| a.identity)
            .collect();
        Ok(
            json!({"primary":primary == Some(identity),"other_members":members.iter().any(|id| *id != identity),
            "known":primary == Some(identity) || state.applicants.values().any(|a|a.identity == identity) || state.removals.contains_key(&identity),
            "primary_identity":primary,"contact_email":state.roles.as_ref().and_then(|r|r.contact_email.as_ref())}),
        )
    }
    /// Called only by the local hosting worker after authenticated self-deletion.
    /// Minimal revocation/authority proofs remain to prevent old backups rejoining.
    pub async fn erase_service_account(
        &mut self,
        config: &ServiceConfig,
        identity: IdentityId,
        evidence: Option<&AdminEvidence>,
    ) -> Result<()> {
        if self.account_membership(config, identity)?["primary"] == true {
            return Err("Transfer primary ownership before deleting your account.".into());
        }
        let evidence = evidence.ok_or("Missing signed account deletion request.")?;
        let signed = decode_record(&evidence.record)?;
        let credential = verify_credential(&evidence.credential)?;
        signed.verify_signature(credential.key())?;
        let command: crate::app::account_deletion::Command = signed.decode()?;
        let mut endpoint = reqwest::Url::parse(&config.address.url)?;
        endpoint.set_path(crate::app::account_deletion::PATH);
        if command.v != 1
            || command.kind != "account.deletion"
            || command.action != crate::app::account_deletion::Action::Submit
            || !command.confirmed
            || command.endpoint != endpoint.as_str()
            || credential.identity() != identity
        {
            return Err("Invalid account deletion proof.".into());
        }
        let mut state = self.service_state()?;
        state.account_deletions.insert(identity, evidence.clone());
        if !state
            .journal
            .iter()
            .any(|entry| entry.record == evidence.record)
        {
            if state.journal.len() >= 4096 {
                return Err("Space administration history limit reached.".into());
            }
            state.journal.push(evidence.clone());
        }
        if state.erased_accounts.insert(identity) {
            let epoch = state
                .removals
                .get(&identity)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or("Membership revision limit reached.")?;
            state.removals.insert(identity, epoch);
        }
        state
            .applicants
            .retain(|_, applicant| applicant.identity != identity);
        if let Some(roles) = state.roles.as_mut() {
            roles.retire_member(identity);
        }
        state.replies.clear();
        self.save_service_state(&state)?;
        Ok(())
    }
    /// The host may destroy storage only after this signed primary-owner action.
    pub fn authorize_space_deletion(
        &self,
        config: &ServiceConfig,
        request: &Request,
    ) -> Result<Option<DeletionReceipt>> {
        let Some(encoded) = &request.record else {
            return Ok(None);
        };
        let signed = decode_record(encoded)?;
        let command: Command = signed.decode()?;
        if command.action != "delete" {
            return Ok(None);
        };
        let credential = verify_credential(
            request
                .credential
                .as_deref()
                .ok_or("Missing device proof.")?,
        )?;
        signed.verify_signature(credential.key())?;
        let state = self.service_state()?;
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        if request.invitation.is_some()
            || command.v != 1
            || command.kind != "space.command"
            || command.space != config.address.scope.space
            || command.nonce != request.nonce
            || time()?.abs_diff(command.issued) > 120_000
            || roles.primary != credential.identity()
            || !self.authorities.0[0].can_manage(credential.id())
            || !self.space_access_devices()?.contains(&credential.id())
            || command.body["revision"].as_u64() != Some(roles.revision)
            || command.body["confirmed"] != true
            || command.body["name"] != config.name
        {
            return Err("Only the primary owner can confirm deleting this Space.".into());
        }
        let scope = self.team_scope()?;
        if serde_json::to_value(&scope)? != serde_json::to_value(&config.address.scope)? {
            return Err("Space scope mismatch.".into());
        }
        let deleted =
            json!({"v":1,"kind":"space.deleted","space":scope.space,"deleted_at":time()?});
        Ok(Some(DeletionReceipt {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&deleted)?, &self.signing_key)?.bytes(),
            ),
            credential: STANDARD.encode(self.credential.record().bytes()),
        }))
    }
    /// Used only by the host to enforce current membership at its transport gate.
    pub fn space_access_devices(&self) -> Result<Vec<RecordId>> {
        let state = self.service_state()?;
        Ok(self.authorities.0[0]
            .head()?
            .members
            .iter()
            .filter(|m| {
                !state.erased_accounts.contains(&m.identity_id)
                    && !state.removal_blocks(m.identity_id)
            })
            .flat_map(|m| m.credential_ids.iter().copied())
            .filter(|id| !state.revoked.contains(id))
            .collect())
    }
    pub fn space_access_members(&self) -> Result<Vec<IdentityId>> {
        let state = self.service_state()?;
        let mut identities = BTreeSet::new();
        identities.extend(
            self.authorities.0[0]
                .head()?
                .members
                .iter()
                .filter(|m| {
                    !state.removal_blocks(m.identity_id)
                        && !state.erased_accounts.contains(&m.identity_id)
                })
                .map(|m| m.identity_id),
        );
        identities.extend(
            state
                .applicants
                .values()
                .filter(|a| a.status == "approved" && self.member_admitted(a.identity))
                .map(|a| a.identity),
        );
        Ok(identities.into_iter().collect())
    }
    /// Call admission binds the currently admitted device, including recovery rotation.
    pub fn space_call_device_allowed(
        &self,
        identity: IdentityId,
        credential: RecordId,
        conversation: crate::calls::CallScope,
        head: RecordId,
    ) -> Result<bool> {
        if !self.space_access_members()?.contains(&identity)
            || !self.space_access_devices()?.contains(&credential)
        {
            return Ok(false);
        }
        let authority = self.authorities.0.first().ok_or("Space unavailable.")?;
        if crate::calls::require_member(authority, credential).ok() != Some(identity) {
            return Ok(false);
        }
        if authority.space() == conversation.space_id
            && authority.stream() == conversation.stream_id
        {
            return Ok(authority.head_id() == Some(head));
        }
        let key = format!("{}:{}", conversation.space_id, conversation.stream_id);
        Ok(self
            .service_state()?
            .call_heads
            .get(&key)
            .is_some_and(|published| published.head == head))
    }
    /// Reclamation is allowed only for a newly provisioned, never-used reservation.
    /// The hosting layer separately excludes all older reservations.
    pub fn space_reservation_is_unused(&self, now: u64) -> Result<bool> {
        let state = self.service_state()?;
        Ok(state.reservation_is_unused(now))
    }
    /// Operator aggregates only; never exports messages, keys, or member identities.
    pub fn space_service_statistics(&self) -> Result<Value> {
        let state = self.service_state()?;
        let members: BTreeSet<_> = state
            .applicants
            .values()
            .filter(|a| a.status == "approved")
            .map(|a| a.identity)
            .collect();
        let pending = state
            .applicants
            .values()
            .filter(|a| a.status == "pending")
            .count();
        Ok(json!({"members":members.len(),"pending":pending}))
    }
    /// Invitation bootstrap is bounded by the creator's original signed policy.
    /// It never creates a General membership configuration.
    pub fn bootstrap_space_invitation(
        &self,
        address: &SpaceAddress,
        require_approval: bool,
    ) -> Result<String> {
        address.validate(self.allow_loopback)?;
        let scope = self.team_scope()?;
        if serde_json::to_value(&scope)? != serde_json::to_value(&address.scope)? {
            return Err("Space scope mismatch.".into());
        }
        let mut state = self.service_state()?;
        let current = time()?;
        state.prune_applicants(current);
        state
            .offers
            .retain(|_, offer| !offer.revoked && offer.expires_at > current);
        if state.offers.len() >= 128 {
            return Err("Revoke an unused invitation first.".into());
        }
        let creation = state
            .creation
            .as_ref()
            .ok_or("Missing signed Space creation request.")?;
        let creation = decode_record(&creation.record)?;
        let id = field(creation.body(), "request_id")?.to_owned();
        let issued = creation.body()["issued"]
            .as_u64()
            .ok_or("Invalid Space creation request.")?;
        if creation.body()["require_approval"]
            .as_bool()
            .unwrap_or(true)
            != require_approval
        {
            return Err("Space invitation policy mismatch.".into());
        }
        if let Some(offer) = state.offers.get(&id) {
            return SpaceInvitation {
                v: 1,
                address: address.clone(),
                token: offer.token.clone(),
            }
            .link();
        }
        let token = record::random_hex::<32>()?;
        state.offers.insert(
            id,
            Offer {
                authorization: state.creation.clone(),
                token: token.clone(),
                issued_at: issued,
                expires_at: issued
                    .checked_add(86_400_000)
                    .ok_or("Invalid invitation expiry.")?,
                require_approval,
                revoked: false,
            },
        );
        self.save_service_state(&state)?;
        SpaceInvitation {
            v: 1,
            address: address.clone(),
            token,
        }
        .link()
    }
    /// Serves one configured Space only. The caller serializes requests with the
    /// service-state lock. All authenticated results bind the request nonce.
    pub async fn serve_space(
        &mut self,
        config: &ServiceConfig,
        request: Request,
    ) -> Result<Response> {
        self.serve_space_inner(config, request, None).await
    }
    pub async fn serve_hosted_space(
        &mut self,
        config: &ServiceConfig,
        request: Request,
        replica: &crate::replica::ReplicaStore,
    ) -> Result<Response> {
        self.serve_space_inner(config, request, Some(replica)).await
    }
    async fn serve_space_inner(
        &mut self,
        config: &ServiceConfig,
        request: Request,
        replica: Option<&crate::replica::ReplicaStore>,
    ) -> Result<Response> {
        record::hex::<16>(&request.nonce)?;
        config.address.validate(self.allow_loopback)?;
        let scope = self.team_scope()?;
        if serde_json::to_value(&scope)? != serde_json::to_value(&config.address.scope)?
            || config.address.service_credential.as_deref()
                != Some(self.transport_credential().as_str())
        {
            return Err("Space service configuration mismatch.".into());
        }
        let mut state = self.service_state()?;
        let current = time()?;
        if let Some(replica) = replica {
            self.apply_device_revocations(&mut state, replica)?;
        }
        state.prune_applicants(current);
        let mut recipient = None;
        if state.roles.is_none() {
            let mut roles = Roles::bootstrap(&config.owners)?;
            if let Some(email) = &config.contact_email {
                validate_contact_email(email)?;
                roles.contact_email = Some(email.clone());
            }
            state.roles = Some(roles);
            self.save_service_state(&state)?;
        }
        let body = if let Some(token) = request.invitation {
            if request.record.is_some() || request.credential.is_some() {
                return Err("Invalid Space request.".into());
            }
            match state
                .offers
                .values()
                .find(|o| o.token == token && !o.revoked && o.expires_at > current)
            {
                Some(offer) => {
                    json!({"name":config.name,"expires_at":offer.expires_at,"require_approval":offer.require_approval,"message_lifetime_seconds":config.address.message_lifetime_seconds})
                }
                None => json!({"error":"This Space invitation has expired or was revoked."}),
            }
        } else {
            let credential = verify_credential(
                request
                    .credential
                    .as_deref()
                    .ok_or("Missing device proof.")?,
            )?;
            if let Some(replica) = replica {
                replica.require_active_device(credential.id())?;
            }
            if let Some(authorizer) = credential.authorizing_device() {
                let head = self.authorities.0[0].head()?;
                let already_enrolled = head.members.iter().any(|member| {
                    member.identity_id == credential.identity()
                        && member.credential_ids.contains(&credential.id())
                });
                if !already_enrolled {
                    // A linked device cannot resurrect a revoked/removed parent.
                    // Previously admitted companions remain independently revocable.
                    if let Some(replica) = replica {
                        replica.require_active_device(authorizer)?;
                    }
                    if !head.members.iter().any(|member| {
                        member.identity_id == credential.identity()
                            && member.credential_ids.contains(&authorizer)
                    }) {
                        return Err("The authorizing device is no longer in this Space.".into());
                    }
                }
            }
            let signed = decode_record(request.record.as_deref().ok_or("Missing signature.")?)?;
            signed.verify_signature(credential.key())?;
            let command: Command = signed.decode()?;
            if command.v != 1
                || command.kind != "space.command"
                || command.space != scope.space
                || command.nonce != request.nonce
                || current.abs_diff(command.issued) > 120_000
            {
                return Err("Invalid or expired Space request.".into());
            }
            recipient = Some(credential.recipient());
            let replay_key = format!("{}:{}", credential.id(), request.nonce);
            state
                .replies
                .retain(|_, (issued, _, _)| current.saturating_sub(*issued) <= 120_000);
            if state
                .replies
                .get(&replay_key)
                .is_some_and(|(_, record, _)| record != &signed.id().to_string())
            {
                return Err("A Space request nonce cannot be reused.".into());
            }
            let cacheable = !matches!(
                command.action.as_str(),
                "join" | "status" | "manage" | "storage" | "chat_head_check" | "device_list"
            );
            if command.action == "chat_head_check" {
                // This read has no side effects to replay. Always sign a fresh,
                // nonce-bound answer without rewriting the encrypted service
                // state or consuming the mutation replay quota.

                match self.check_space_chat_head(&state, &credential, &command.body) {
                    Ok(value) => value,
                    Err(error) => json!({"error":error.to_string()}),
                }
            } else if cacheable && let Some((_, _, reply)) = state.replies.get(&replay_key) {
                reply.clone()
            } else {
                let prefix = format!("{}:", credential.id());
                if cacheable
                    && (state.replies.len() >= 8192
                        || state
                            .replies
                            .keys()
                            .filter(|key| key.starts_with(&prefix))
                            .count()
                            >= 256)
                {
                    return Err("Space is busy. Try again.".into());
                }
                let evidence = AdminEvidence {
                    record: STANDARD.encode(signed.bytes()),
                    credential: STANDARD.encode(credential.record().bytes()),
                };
                let journaled = matches!(
                    command.action.as_str(),
                    "invite"
                        | "revoke"
                        | "decide"
                        | "role_change"
                        | "role_decide"
                        | "device_revoke"
                );
                let journal_len = state.journal.len();
                let append_intent = journaled
                    && !state
                        .journal
                        .iter()
                        .any(|entry| entry.record == evidence.record);
                if append_intent && state.journal.len() >= 4096 {
                    return Err("Space administration history limit reached.".into());
                }
                if append_intent {
                    state.journal.push(evidence.clone());
                }
                let result = self
                    .space_command(config, &mut state, &credential, command, &evidence, replica)
                    .await;
                if result.is_err() && append_intent {
                    state.journal.truncate(journal_len);
                }
                let succeeded = result.is_ok();
                let value = match result {
                    Ok(value) => value,
                    Err(error) => json!({"error":error.to_string()}),
                };
                if succeeded && cacheable {
                    state.replies.insert(
                        replay_key,
                        (
                            current,
                            signed.id().to_string(),
                            if cacheable {
                                value.clone()
                            } else {
                                Value::Null
                            },
                        ),
                    );
                }
                if succeeded {
                    state.claimed = true;
                    self.save_service_state(&state)?;
                }
                value
            }
        };
        let (body, ciphertext) = if let Some(recipient) = recipient {
            (
                None,
                Some(STANDARD.encode(crypto::seal_bytes(
                    &Zeroizing::new(serde_json::to_vec(&body)?),
                    &[recipient],
                    LIMIT,
                )?)),
            )
        } else {
            (Some(body), None)
        };
        let ciphertext_hash = ciphertext
            .as_ref()
            .map(|encoded| {
                STANDARD
                    .decode(encoded)
                    .map(|bytes| crate::ids::ObjectId::of_ciphertext(&bytes).to_string())
            })
            .transpose()?;
        let answer = Answer {
            v: 1,
            kind: "space.response".into(),
            space: scope.space,
            nonce: request.nonce,
            body,
            ciphertext_hash,
        };
        let record = SignedRecord::sign(&serde_json::to_vec(&answer)?, &self.signing_key)?;
        Ok(Response {
            record: STANDARD.encode(record.bytes()),
            credential: STANDARD.encode(self.credential.record().bytes()),
            ciphertext,
        })
    }
    async fn space_command(
        &mut self,
        config: &ServiceConfig,
        state: &mut ServiceState,
        credential: &VerifiedCredential,
        command: Command,
        evidence: &AdminEvidence,
        replica: Option<&crate::replica::ReplicaStore>,
    ) -> Result<Value> {
        let identity = credential.identity();
        if matches!(
            command.action.as_str(),
            "invite" | "revoke" | "decide" | "role_change" | "role_decide" | "device_revoke"
        ) && command.body["authority_head"] != json!(self.authorities.0[0].head_id())
        {
            return Err("General permissions have changed. Refresh and try again.".into());
        }
        if state.erased_accounts.contains(&identity) {
            return Err("This account was deleted from this service.".into());
        }
        if !matches!(
            command.action.as_str(),
            "join" | "status" | "authority" | "authority_publish"
        ) && (!self.space_access_devices()?.contains(&credential.id())
            || !self.space_access_members()?.contains(&identity))
        {
            return Err("This device is no longer admitted to the Space.".into());
        }
        let owner = self.authorities.0[0].can_manage(credential.id())
            && state
                .roles
                .as_ref()
                .ok_or("Space roles unavailable.")?
                .is_owner(identity);
        let current = time()?;

        if let Some(result) =
            self.attachment_space_command(state, credential, owner, &command, current)
        {
            return result;
        }
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        match command.action.as_str() {
            "authority" => self.authority_status(state, credential, replica),
            "authority_publish" => {
                self.publish_authority(state, credential, &command.body, replica)
            }
            "device_list" => self.space_device_list(credential),
            "device_revoke" => {
                self.space_revoke_device(state, credential, &command.body, replica)
                    .await
            }
            "chat_head_check" => self.check_space_chat_head(state, credential, &command.body),
            "call_head_publish" => self.publish_space_call_head(state, credential, &command.body),
            "contact"
                if state
                    .applicants
                    .values()
                    .any(|a| a.identity == identity && a.status == "approved") =>
            {
                Ok(json!({"contact_email":roles.contact_email}))
            }
            "contact_update" if roles.primary == identity => {
                if command.body["revision"].as_u64() != Some(roles.revision) {
                    return Err("Space roles have changed. Refresh and try again.".into());
                }
                let email = field(&command.body, "contact_email")?.trim();
                validate_contact_email(email)?;
                state.roles.as_mut().unwrap().contact_email = Some(email.into());
                state.replies.clear();
                self.save_service_state(state)?;
                Ok(json!({"contact_email":email}))
            }
            "storage" | "storage_prune" if owner => {
                let replica =
                    replica.ok_or("Storage management is not available on this server.")?;
                let days = command.body["days"]
                    .as_u64()
                    .filter(|n| (1..=36500).contains(n))
                    .ok_or("Enter a whole number of days between 1 and 36500.")?;
                let latest = current.saturating_sub(days * 86_400_000);
                let usage = if command.action == "storage_prune" {
                    let before = command.body["before_ms"]
                        .as_u64()
                        .filter(|n| *n <= latest)
                        .ok_or("Refresh the storage preview before clearing messages.")?;
                    if command.body["confirmed"] != true {
                        return Err("Confirm server message cleanup first.".into());
                    }
                    replica
                        .prune_messages(config.peer.mailbox_id, before)
                        .await?
                } else {
                    replica
                        .space_storage(config.peer.mailbox_id, latest)
                        .await?
                };
                Ok(serde_json::to_value(usage)?)
            }
            "join" => {
                let note = join_note(&command.body)?;
                let token = field(&command.body, "token")?;
                state.prune_applicants(current);
                let (offer_id, offer) = state
                    .offers
                    .iter()
                    .find(|(_, o)| o.token == token && !o.revoked && o.expires_at > current)
                    .ok_or("This Space invitation has expired or was revoked.")?;
                let request: team::EnrollmentRequest =
                    serde_json::from_value(command.body["enrollment"].clone())?;
                let (identity, device, name) = self.space_applicant(&request)?;
                if identity != credential.identity() || device != credential.id() {
                    return Err("This join request belongs to another profile.".into());
                }
                let key = credential.id().to_string();
                let declined = state.device_was_declined(&key)?;
                if !state.applicants.contains_key(&key)
                    || state
                        .applicants
                        .get(&key)
                        .is_some_and(|a| a.status == "removed" || a.status == "declined")
                {
                    let pending = !self.device_admitted(credential.id());
                    state.require_applicant_capacity(identity, offer_id, pending)?;
                    state.claimed = true;
                    state.applicants.insert(
                        key.clone(),
                        Applicant {
                            authorization: None,
                            identity,
                            name,
                            status: if self.device_admitted(credential.id()) {
                                "approved"
                            } else if state.removals.contains_key(&identity)
                                || declined
                                || (offer.require_approval && !owner)
                            {
                                "pending"
                            } else {
                                "eligible"
                            }
                            .into(),
                            invitation: offer_id.clone(),
                            note: if state.removals.contains_key(&identity)
                                || declined
                                || (offer.require_approval && !owner)
                            {
                                note.clone()
                            } else {
                                String::new()
                            },
                            request,
                            requested_at: current,
                        },
                    );
                    self.save_service_state(state)?;
                } else if let Some(applicant) = state.applicants.get_mut(&key) {
                    if applicant.status == "pending" {
                        applicant.note = note;
                    }
                    applicant.request = request;
                }
                self.space_join_reply(config, state, &key, None).await
            }
            "status" => {
                let heads = command
                    .body
                    .get("chat_heads")
                    .map(|value| {
                        value
                            .as_array()
                            .filter(|heads| heads.len() <= 64)
                            .ok_or("Space request rejected.")
                    })
                    .transpose()?;
                let key = credential.id().to_string();
                let request: team::EnrollmentRequest =
                    serde_json::from_value(command.body["enrollment"].clone())?;
                let (identity, device, name) = self.space_applicant(&request)?;
                if identity != credential.identity() || device != credential.id() {
                    return Err("This request belongs to another profile.".into());
                }
                if state.removals.contains_key(&identity)
                    && !state.applicants.contains_key(&key)
                    && !state
                        .applicants
                        .values()
                        .any(|a| a.identity == identity && a.status == "approved")
                {
                    return Ok(
                        json!({"name":config.name,"status":"removed","membership_epoch":state.removals[&identity]}),
                    );
                }
                let mut result = if let Some(applicant) = state.applicants.get_mut(&key) {
                    applicant.request = request;
                    self.space_join_reply(config, state, &key, Some(&command.body))
                        .await?
                } else {
                    // Legacy General members retain membership, with their own signed
                    // request proving the encryption recipient before any access export.
                    if identity != credential.identity()
                        || device != credential.id()
                        || !(state
                            .applicants
                            .values()
                            .any(|a| a.identity == identity && a.status == "approved")
                            || self.authorities.0[0].head()?.members.iter().any(|m| {
                                m.identity_id == identity && m.credential_ids.contains(&device)
                            }))
                    {
                        return Err("Join this Space using an invitation first.".into());
                    }
                    state.require_applicant_capacity(identity, "", false)?;
                    state.applicants.insert(
                        key.clone(),
                        Applicant {
                            authorization: None,
                            identity,
                            name,
                            status: if self.device_admitted(device) {
                                "approved"
                            } else if state.device_was_declined(&key)? {
                                "pending"
                            } else {
                                "eligible"
                            }
                            .into(),
                            invitation: String::new(),
                            note: String::new(),
                            request,
                            requested_at: current,
                        },
                    );
                    self.space_join_reply(config, state, &key, None).await?
                };
                if result["status"] == "approved"
                    && let Some(heads) = heads
                {
                    result["chat_heads"] = json!(
                        heads
                            .iter()
                            .map(|head| {
                                self.check_space_chat_head(state, credential, head)
                                    .unwrap_or_else(|error| json!({"error":error.to_string()}))
                            })
                            .collect::<Vec<_>>()
                    );
                }
                Ok(result)
            }
            "manage" if owner => {
                let (attachment_used, attachment_reserved) = bytes_in_state(state);
                let offers = state.offers.iter().map(|(id, o)| {
                    Ok(json!({"id":id,"issued_at":o.issued_at,"expires_at":o.expires_at,"require_approval":o.require_approval,"revoked":o.revoked,"link":SpaceInvitation {v:1,address:config.address.clone(),token:o.token.clone()}.link()?}))
                }).collect::<Result<Vec<_>>>()?;
                let requests = state
                    .applicants
                    .iter()
                    .filter(|(_, a)| a.status == "pending")
                    .map(|(id, a)| json!({"id":id,"identity":a.identity,"name":a.name,"note":a.note}))
                    .collect::<Vec<_>>();
                Ok(
                    json!({"offers":offers,"requests":requests,"members":self.space_role_members(state)?,"roles_revision":roles.revision,"primary_owner":roles.primary,"contact_email":roles.contact_email,"attachments":{"policy":state.attachment_policy,"used_bytes":attachment_used,"reserved_bytes":attachment_reserved}}),
                )
            }
            "invite" if owner => {
                let seconds = command.body["lifetime"]
                    .as_u64()
                    .filter(|s| LIFETIMES.contains(s))
                    .ok_or("Choose an invitation lifetime.")?;
                let approval = command.body["require_approval"]
                    .as_bool()
                    .ok_or("Choose whether approval is required.")?;
                if state.offers.len() >= 128 {
                    state
                        .offers
                        .retain(|_, o| !o.revoked && o.expires_at > current);
                }
                if state.offers.len() >= 128 {
                    return Err("Revoke an unused invitation first.".into());
                }
                let token = field(&command.body, "token")?.to_owned();
                record::hex::<32>(&token)?;
                let id = field(&command.body, "id")?.to_owned();
                record::hex::<16>(&id)?;
                if state.offers.contains_key(&id)
                    || state.offers.values().any(|offer| offer.token == token)
                {
                    return Err("Invitation identifiers must be unique.".into());
                }
                let expires_at = current
                    .checked_add(seconds * 1000)
                    .ok_or("Invalid expiry.")?;
                state.offers.insert(
                    id.clone(),
                    Offer {
                        authorization: Some(evidence.clone()),
                        token: token.clone(),
                        issued_at: current,
                        expires_at,
                        require_approval: approval,
                        revoked: false,
                    },
                );
                self.save_service_state(state)?;
                Ok(
                    json!({"id":id,"link":SpaceInvitation {v:1,address:config.address.clone(),token}.link()?,"expires_at":expires_at}),
                )
            }
            "revoke" if owner => {
                state
                    .offers
                    .get_mut(field(&command.body, "id")?)
                    .ok_or("Invitation not found.")?
                    .revoked = true;
                state.prune_applicants(current);
                self.save_service_state(state)?;
                Ok(json!({}))
            }
            "decide" if owner => {
                if command.body["approve"] == true {
                    let id = field(&command.body, "id")?;
                    let applicant = state.applicants.get(id).ok_or("Request not found.")?;
                    let head = self.authorities.0[0]
                        .head_id()
                        .ok_or("General unavailable.")?;
                    let mut denied = state.removal_heads.get(&applicant.identity) == Some(&head);
                    for evidence in &state.journal {
                        let previous = decode_record(&evidence.record)?;
                        let body = previous.body();
                        denied |= body["kind"] == "space.command"
                            && body["action"] == "decide"
                            && body["body"]["id"] == id
                            && body["body"]["approve"] == false
                            && body["body"]["authority_head"] == json!(head);
                    }
                    if denied {
                        return Err(
                            "General permissions have changed. Refresh and try again.".into()
                        );
                    }
                    state.require_applicant_capacity(identity, "", false)?;
                }
                let applicant = state
                    .applicants
                    .get_mut(field(&command.body, "id")?)
                    .ok_or("Request not found.")?;
                if applicant.status != "pending" {
                    return Err("This request has already been handled.".into());
                }
                applicant.status = if command.body["approve"]
                    .as_bool()
                    .ok_or("Choose a decision.")?
                {
                    "eligible"
                } else {
                    "declined"
                }
                .into();
                applicant.note.clear();
                applicant.authorization = Some(evidence.clone());
                self.save_service_state(state)?;
                Ok(json!({}))
            }
            "role_change" | "role_decide" => {
                let members = self.space_role_members(state)?;
                let roles = state.roles.as_mut().ok_or("Space roles unavailable.")?;
                let result = roles.apply_with_id(
                    identity,
                    &command.action,
                    &command.body,
                    &members,
                    current,
                    &decode_record(&evidence.record)?.id().to_string(),
                )?;
                if let Some(target) = result["removed_identity"].as_str() {
                    let target: IdentityId = target.parse()?;
                    let epoch = state
                        .removals
                        .get(&target)
                        .copied()
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or("Membership revision limit reached.")?;
                    state.removals.insert(target, epoch);
                    state.removal_heads.insert(
                        target,
                        self.authorities.0[0]
                            .head_id()
                            .ok_or("General unavailable.")?,
                    );
                    for applicant in state
                        .applicants
                        .values_mut()
                        .filter(|a| a.identity == target)
                    {
                        applicant.status = "removed".into();
                        applicant.note.clear();
                    }
                    state.roles.as_mut().unwrap().retire_member(target);
                    // Transport denies the removed member immediately. An admitted
                    // owner device must publish the signed General update.
                    self.save_service_state(state)?;
                }
                // Previously cached management replies must not survive a role change.
                state.replies.clear();
                self.save_service_state(state)?;
                Ok(result)
            }
            _ => Err("Only the Space owner can manage invitations.".into()),
        }
    }
    async fn space_join_reply(
        &mut self,
        config: &ServiceConfig,
        state: &ServiceState,
        key: &str,
        known: Option<&Value>,
    ) -> Result<Value> {
        let applicant = state.applicants.get(key).ok_or("Request not found.")?;
        let general = &self.authorities.0[0];
        let admitted = key.parse().ok().is_some_and(|id| self.device_admitted(id));
        if !admitted || matches!(applicant.status.as_str(), "removed" | "declined") {
            return Ok(
                json!({"name":config.name,"status":if applicant.status == "eligible" { "pending" } else { applicant.status.as_str() },"membership_epoch":state.removals.get(&applicant.identity).copied().unwrap_or(0)}),
            );
        }
        let epoch = state
            .removals
            .get(&applicant.identity)
            .copied()
            .unwrap_or(0);
        let unchanged = known.is_some_and(|known| {
            known["known_general_head"] == json!(general.head_id())
                && known["membership_epoch"].as_u64() == Some(epoch)
        });
        let packet = if unchanged {
            None
        } else {
            let contacts = state
                .applicants
                .iter()
                .filter(|(id, _)| {
                    id.parse()
                        .ok()
                        .is_some_and(|id| self.device_admitted(id) && !state.revoked.contains(&id))
                })
                .map(|(_, a)| decode_contact(&a.request.contact))
                .collect::<Result<Vec<_>>>()?;
            Some(team::EnrollmentReply {
                v: 2,
                packet: STANDARD.encode(serde_json::to_vec(
                    &json!({"proof":state.proof,"contacts":contacts}),
                )?),
            })
        };
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        Ok(
            json!({"name":config.name,"status":"approved","membership_epoch":epoch,"owner":roles.is_owner(applicant.identity),"role":roles.role(applicant.identity),"roles_revision":roles.revision,"role_requests":roles.requests_for(applicant.identity),"contact_email":roles.contact_email,"message_lifetime_seconds":config.address.message_lifetime_seconds,"peer":config.peer,"general_head":self.authorities.0[0].head_id(),"enrollment":packet}),
        )
    }

    fn space_role_members(&self, state: &ServiceState) -> Result<Vec<roles::RoleMember>> {
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        let mut members = BTreeMap::new();
        for applicant in state
            .applicants
            .values()
            .filter(|a| self.member_admitted(a.identity))
        {
            members
                .entry(applicant.identity)
                .or_insert(roles::RoleMember {
                    identity: applicant.identity,
                    name: applicant.name.clone(),
                    role: roles.role(applicant.identity).into(),
                });
        }
        Ok(members.into_values().collect())
    }
}

fn decode_contact(link: &str) -> Result<Value> {
    let encoded = link
        .strip_prefix("elo://exchange/v1#")
        .ok_or("Invalid enrollment contact.")?;
    if encoded.len() > LIMIT * 2 {
        return Err("Enrollment contact is too large.".into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    let mut plain = Vec::new();
    flate2::read::ZlibDecoder::new(bytes.as_slice())
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut plain)?;
    let value = record::strict_json(&plain, LIMIT + 72)?;
    if value["kind"] != "Contact" || value.as_object().is_none_or(|m| m.len() != 3) {
        return Err("Invalid enrollment contact.".into());
    }
    Ok(value)
}
impl PublicSpaceService {
    /// Creates only an operational response signer. Its encryption private key
    /// and credential root are discarded before returning; neither enters General.
    pub fn create(
        directory: impl AsRef<Path>,
        proof: CallAuthorityProof,
        owners: &[IdentityId],
        contact_email: Option<String>,
        allow_loopback: bool,
        creation: Option<AdminEvidence>,
    ) -> Result<Self> {
        let directory = directory.as_ref().to_path_buf();
        std::fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let key = crate::identity::generate_signing_key()?;
        let root = crate::identity::generate_signing_key()?;
        let public_recipient = age::x25519::Identity::generate().to_public();
        let credential = DeviceCredential::issue(&root, &key.verifying_key(), &public_recipient)?;
        let signer = TransportSigner {
            seed: record::encode_hex(&key.to_bytes()),
            credential: STANDARD.encode(credential.record().bytes()),
        };
        vault::write_private(
            &directory.join("transport.json"),
            &Zeroizing::new(serde_json::to_vec(&signer)?),
            false,
        )?;
        let mut roles = Roles::bootstrap(owners)?;
        roles.contact_email = contact_email;
        let state = ServiceState {
            creation,
            journal: Vec::new(),
            committed_journal: Vec::new(),
            revocation_proofs: BTreeMap::new(),
            account_deletions: BTreeMap::new(),
            proof,
            claimed: false,
            offers: BTreeMap::new(),
            applicants: BTreeMap::new(),
            replies: BTreeMap::new(),
            roles: Some(roles),
            _legacy_requests: Value::Null,
            removals: BTreeMap::new(),
            removal_heads: BTreeMap::new(),
            erased_accounts: BTreeSet::new(),
            revoked: BTreeSet::new(),
            attachment_policy: Default::default(),
            attachments: BTreeMap::new(),
            attachment_access: BTreeMap::new(),
            call_heads: BTreeMap::new(),
        };
        vault::write_private(
            &directory.join("state.json"),
            &serde_json::to_vec(&state)?,
            false,
        )?;
        Self::open(directory, allow_loopback)
    }
    pub fn open(directory: impl AsRef<Path>, allow_loopback: bool) -> Result<Self> {
        let directory = directory.as_ref().to_path_buf();
        let signer: TransportSigner = serde_json::from_slice(&Zeroizing::new(
            vault::read_private(&directory.join("transport.json"))?,
        ))?;
        let seed = Zeroizing::new(record::hex(&signer.seed)?);
        let signing_key = SigningKey::from_bytes(&seed);
        let credential = verify_credential(&signer.credential)?;
        if credential.key() != &signing_key.verifying_key() {
            return Err("Invalid transport signing key.".into());
        }
        let bytes = vault::read_private(&directory.join("state.json"))?;
        if bytes.len() > STATE_LIMIT {
            return Err("Space state is too large.".into());
        }
        let state: ServiceState = serde_json::from_slice(&bytes)?;
        let genesis = decode_record(&state.proof.genesis)?;
        let config = decode_record(
            state
                .proof
                .configs
                .last()
                .ok_or("Missing General configuration.")?,
        )?;
        let authority = state.proof.verify(
            SpaceId::from_bytes(*genesis.id().as_bytes()),
            field(config.body(), "stream_id")?.parse()?,
        )?;
        if !authority.is_owner_managed()
            || authority
                .head()?
                .members
                .iter()
                .any(|m| m.credential_ids.contains(&credential.id()))
        {
            return Err("General must be controlled by its owners.".into());
        }
        Ok(Self {
            directory,
            signing_key,
            credential,
            authorities: Authorities(vec![authority]),
            allow_loopback,
        })
    }
    pub fn transport_credential(&self) -> String {
        STANDARD.encode(self.credential.record().bytes())
    }
    pub fn team_scope(&self) -> Result<team::TeamScope> {
        let authority = &self.authorities.0[0];
        let genesis: crate::authority::SpaceGenesis = authority.genesis().decode()?;
        let root = genesis
            .owners
            .iter()
            .find(|o| o.identity_id == genesis.issuer_identity)
            .ok_or("Missing General owner.")?
            .root_public_key
            .clone();
        Ok(team::TeamScope {
            space: authority.space(),
            stream: authority.stream(),
            root,
            controller: genesis.controller_credential_id,
        })
    }
    fn service_state(&self) -> Result<ServiceState> {
        let bytes = vault::read_private(&self.directory.join("state.json"))?;
        if bytes.len() > STATE_LIMIT {
            return Err("Space state is too large.".into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    fn save_service_state(&self, state: &ServiceState) -> Result<()> {
        let bytes = serde_json::to_vec(state)?;
        if bytes.len() > STATE_LIMIT {
            return Err("Space state is too large.".into());
        }
        vault::write_private(&self.directory.join("state.json"), &bytes, true)?;
        Ok(())
    }
    fn device_admitted(&self, id: RecordId) -> bool {
        let Ok(identity) = crate::calls::require_member(&self.authorities.0[0], id) else {
            return false;
        };
        self.service_state().is_ok_and(|state| {
            !state.revoked.contains(&id)
                && !state.erased_accounts.contains(&identity)
                && !state.removal_blocks(identity)
        })
    }
    fn member_admitted(&self, identity: IdentityId) -> bool {
        self.authorities.0[0].head().is_ok_and(|head| {
            head.members
                .iter()
                .any(|member| member.identity_id == identity)
        }) && self.service_state().is_ok_and(|state| {
            !state.erased_accounts.contains(&identity) && !state.removal_blocks(identity)
        })
    }
    fn space_applicant(
        &self,
        request: &team::EnrollmentRequest,
    ) -> Result<(IdentityId, RecordId, String)> {
        let packet = decode_contact(&request.contact)?;
        let credential = verify_credential(field(&packet, "credential")?)?;
        let signed = decode_record(field(&packet, "card")?)?;
        let card = crate::invite::shared::verify_contact(&signed, &credential, time()?)?;
        let proof = decode_record(&request.proof)?;
        proof.verify_signature(credential.key())?;
        let scope = self.team_scope()?;
        let body = proof.body();
        if request.v != 1
            || body["v"] != 1
            || body["kind"] != "team.join"
            || body["space"] != json!(scope.space)
            || body["stream"] != json!(scope.stream)
            || body["controller"] != json!(scope.controller)
            || body["contact"] != json!(signed.id())
            || body.as_object().is_none_or(|v| v.len() != 6)
        {
            return Err("This request belongs to another Space.".into());
        }
        Ok((credential.identity(), credential.id(), card.name))
    }
    fn authority_status(
        &self,
        state: &ServiceState,
        requester: &VerifiedCredential,
        replica: Option<&crate::replica::ReplicaStore>,
    ) -> Result<Value> {
        let authority = &self.authorities.0[0];
        if !authority.can_manage(requester.id())
            || state.revoked.contains(&requester.id())
            || state.erased_accounts.contains(&requester.identity())
        {
            return Err("Only a current owner device can update General.".into());
        }
        if let Some(replica) = replica {
            replica.require_active_device(requester.id())?;
        }
        let pending = state
            .applicants
            .iter()
            .filter(|(id, a)| {
                a.status == "eligible"
                    && !id
                        .parse()
                        .ok()
                        .is_some_and(|id| state.revoked.contains(&id))
                    && !state.erased_accounts.contains(&a.identity)
            })
            .map(|(id, a)| json!({"credential":id,"request":a.request,"authorization":a.authorization,"invitation_authorization":state.offers.get(&a.invitation).and_then(|o| o.authorization.as_ref())}))
            .collect::<Vec<_>>();
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        let owners = authority
            .head()?
            .members
            .iter()
            .filter(|m| roles.is_owner(m.identity_id))
            .map(|m| m.identity_id)
            .collect::<Vec<_>>();
        Ok(
            json!({"proof":state.proof,"head":authority.head_id(),"pending":pending,"revoked":state.revoked,"removed":state.removals.keys().filter(|identity| !state.applicants.values().any(|a| a.identity == **identity && matches!(a.status.as_str(), "eligible" | "approved"))).collect::<Vec<_>>(),"owner_identities":owners,"journal":state.journal,"committed_journal":state.committed_journal,"revocation_proofs":state.revocation_proofs.values().collect::<Vec<_>>(),"creation":state.creation,"account_deletions":state.account_deletions.values().collect::<Vec<_>>()}),
        )
    }
    fn publish_authority(
        &mut self,
        state: &mut ServiceState,
        requester: &VerifiedCredential,
        body: &Value,
        replica: Option<&crate::replica::ReplicaStore>,
    ) -> Result<Value> {
        self.authority_status(state, requester, replica)?;
        let previous = &self.authorities.0[0];
        if body["expected_head"] != json!(previous.head_id()) {
            return Err("General permissions have changed. Refresh and try again.".into());
        }
        let proof: CallAuthorityProof = serde_json::from_value(body["proof"].clone())?;
        // Full verified ancestry is required, so a valid fork cannot replace a
        // previously committed head or omit the owner authorization at that head.
        if proof.checkpoint.is_some() || proof.genesis != state.proof.genesis {
            return Err("General authority proof does not extend this Space.".into());
        }
        let next = proof.verify(previous.space(), previous.stream())?;
        if next.head()?.action.request_record_id
            != crate::owner_admission::journal_commitment(&state.journal)?
        {
            return Err("General permissions have changed. Refresh and try again.".into());
        }
        if !next.is_owner_managed()
            || !next.proves_config_at(
                previous.head_id().ok_or("Missing General head.")?,
                previous.head()?.sequence,
            )
            || !next.proves_recovery_ancestor(previous.recovery_id())
            || next.head()?.sequence < previous.head()?.sequence
        {
            return Err("General authority proof does not extend its current head.".into());
        }
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        let mut expected_owners = Vec::new();
        for member in &next.head()?.members {
            if state.erased_accounts.contains(&member.identity_id)
                || (state.removals.contains_key(&member.identity_id)
                    && !state.applicants.values().any(|a| {
                        a.identity == member.identity_id
                            && matches!(a.status.as_str(), "eligible" | "approved")
                    }))
            {
                return Err("A removed member cannot remain in General.".into());
            }
            for id in &member.credential_ids {
                if state.revoked.contains(id) {
                    return Err("A revoked device cannot remain in General.".into());
                }
                if let Some(replica) = replica {
                    replica.require_active_device(*id)?;
                }
                let existing =
                    previous.head()?.members.iter().any(|m| {
                        m.identity_id == member.identity_id && m.credential_ids.contains(id)
                    });
                let candidate = next.credential(*id)?;
                let companion = candidate.authorizing_device().is_some_and(|parent| {
                    !state.revoked.contains(&parent)
                        && previous.head().is_ok_and(|h| {
                            h.members.iter().any(|m| {
                                m.identity_id == member.identity_id
                                    && m.credential_ids.contains(&parent)
                            })
                        })
                        && replica
                            .is_none_or(|replica| replica.require_active_device(parent).is_ok())
                });
                if !existing && candidate.authorizing_device().is_some() && !companion {
                    return Err("The authorizing device is no longer in this Space.".into());
                }
                if !existing
                    && !companion
                    && !state
                        .applicants
                        .get(&id.to_string())
                        .is_some_and(|a| a.identity == member.identity_id && a.status == "eligible")
                {
                    return Err(
                        "Approve the signed enrollment request before adding this device.".into(),
                    );
                }
                if roles.is_owner(member.identity_id) {
                    expected_owners.push(*id);
                }
            }
        }
        expected_owners.sort();
        expected_owners.dedup();
        if next.head()?.owner_credential_ids != expected_owners {
            return Err("General owners must match the approved Space roles.".into());
        }
        state.proof = proof;
        state.committed_journal = state.journal.clone();
        for (id, applicant) in &mut state.applicants {
            if id.parse().ok().is_some_and(|id| {
                crate::calls::require_member(&next, id).ok() == Some(applicant.identity)
            }) && applicant.status == "eligible"
            {
                applicant.status = "approved".into();
            }
        }
        state.replies.clear();
        self.save_service_state(state)?;
        let head = next.head_id();
        self.authorities.0[0] = next;
        Ok(json!({"head":head}))
    }
    fn apply_device_revocations(
        &self,
        state: &mut ServiceState,
        replica: &crate::replica::ReplicaStore,
    ) -> Result<()> {
        for id in self.authorities.0[0]
            .head()?
            .members
            .iter()
            .flat_map(|m| &m.credential_ids)
        {
            if let Some(proof) = replica.revocations().get(*id)? {
                state.revoked.insert(*id);
                let encoded = STANDARD.encode(proof.bytes());
                if !state.journal.iter().any(|entry| entry.record == encoded) {
                    if state.journal.len() >= 4096 {
                        return Err("Space administration history limit reached.".into());
                    }
                    let target = crate::identity::DeviceRevocation::verify(&proof)?;
                    state.journal.push(AdminEvidence {
                        record: encoded.clone(),
                        credential: STANDARD.encode(target.record().bytes()),
                    });
                }
                state.revocation_proofs.insert(*id, encoded);
            }
        }
        state.attachment_access.retain(|_, access| {
            !access
                .credential
                .is_some_and(|id| state.revoked.contains(&id))
        });
        self.save_service_state(state)
    }
    fn space_device_list(&self, requester: &VerifiedCredential) -> Result<Value> {
        let authority = &self.authorities.0[0];
        crate::calls::require_member(authority, requester.id())?;
        let member = authority
            .head()?
            .members
            .iter()
            .find(|m| m.identity_id == requester.identity())
            .ok_or("Join this Space first.")?;
        let active = self.space_access_devices()?;
        let devices = member.credential_ids.iter().filter(|id| active.contains(id)).map(|id| Ok(json!({"id":id,"credential":STANDARD.encode(authority.credential(*id)?.record().bytes())}))).collect::<Result<Vec<_>>>()?;
        Ok(json!({"devices":devices}))
    }
    async fn space_revoke_device(
        &self,
        state: &mut ServiceState,
        requester: &VerifiedCredential,
        body: &Value,
        replica: Option<&crate::replica::ReplicaStore>,
    ) -> Result<Value> {
        let replica = replica.ok_or("Device management requires a hosted Space.")?;
        crate::calls::require_member(&self.authorities.0[0], requester.id())?;
        replica.require_active_device(requester.id())?;
        let proof = decode_record(field(body, "proof")?)?;
        let target = crate::identity::DeviceRevocation::verify_request(&proof, requester)?;
        if target.identity() != requester.identity() || target.id() == requester.id() {
            return Err("Choose another device belonging to this profile.".into());
        }
        replica.revocations().insert(&proof)?;
        self.apply_device_revocations(state, replica)?;
        Ok(json!({"revoked":target.id()}))
    }
    pub async fn deliver_team_memberships(&self) -> Result<()> {
        Ok(())
    }
    pub async fn close(self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{Capability, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig};
    use crate::identity::generate_signing_key;

    struct Device {
        key: SigningKey,
        credential: VerifiedCredential,
        _recipient: age::x25519::Identity,
    }
    impl Device {
        fn new() -> Self {
            let root = generate_signing_key().unwrap();
            let key = generate_signing_key().unwrap();
            let recipient = age::x25519::Identity::generate();
            let credential =
                DeviceCredential::issue(&root, &key.verifying_key(), &recipient.to_public())
                    .unwrap();
            Self {
                key,
                credential,
                _recipient: recipient,
            }
        }
        fn child(&self) -> Self {
            let key = generate_signing_key().unwrap();
            let recipient = age::x25519::Identity::generate();
            let credential = DeviceCredential::issue_companion(
                &self.credential,
                &self.key,
                &key.verifying_key(),
                &recipient.to_public(),
            )
            .unwrap();
            Self {
                key,
                credential,
                _recipient: recipient,
            }
        }
    }
    fn initial(device: &Device) -> Authority {
        let root = field(device.credential.record().body(), "root_public_key")
            .unwrap()
            .to_owned();
        let genesis = SignedRecord::sign(
            &serde_json::to_vec(&SpaceGenesis {
                v: 2,
                kind: "space.genesis".into(),
                nonce: record::random_hex::<16>().unwrap(),
                issuer_identity: device.credential.identity(),
                owners: vec![Owner {
                    identity_id: device.credential.identity(),
                    root_public_key: root.clone(),
                }],
                controller_credential_id: device.credential.id(),
            })
            .unwrap(),
            &device.key,
        )
        .unwrap();
        let space = SpaceId::from_bytes(*genesis.id().as_bytes());
        let stream = StreamId::from_bytes([8; 16]);
        let mut authority = Authority::new(
            genesis.bytes(),
            space,
            &VerifyingKey::from_bytes(&record::hex(&root).unwrap()).unwrap(),
            device.credential.clone(),
            stream,
        )
        .unwrap();
        let config = StreamConfig {
            v: 2,
            kind: "stream.config".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: space,
            stream_id: stream,
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: device.credential.id(),
            members: vec![Member {
                identity_id: device.credential.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: root,
                capabilities: vec![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ],
                credential_ids: vec![device.credential.id()],
                external: false,
            }],
            owner_credential_ids: vec![device.credential.id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: device.credential.identity(),
                request_record_id: None,
            },
            chat_kind: None,
            recovery: None,
        };
        authority
            .apply_config(config.sign(&device.key).unwrap())
            .unwrap();
        authority
    }
    fn update(
        authority: &Authority,
        signer: &Device,
        add: Option<&Device>,
        remove: Option<RecordId>,
    ) -> Authority {
        let mut next = authority.clone();
        let mut config = next.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = next.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.controller_credential_id = signer.credential.id();
        config.action.actor_identity = signer.credential.identity();
        config.action.operation = "device.updated".into();
        if let Some(add) = add {
            next.add_credential(add.credential.clone());
            config.members[0].credential_ids.push(add.credential.id());
            config.members[0].credential_ids.sort();
            config.owner_credential_ids.push(add.credential.id());
            config.owner_credential_ids.sort();
        }
        if let Some(remove) = remove {
            config.members[0].credential_ids.retain(|id| *id != remove);
            config.owner_credential_ids.retain(|id| *id != remove);
        }
        next.apply_config(config.sign(&signer.key).unwrap())
            .unwrap();
        next
    }
    #[test]
    fn public_host_persists_only_public_general_proof_and_a_separate_transport_signer() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Device::new();
        let authority = initial(&owner);
        let service = PublicSpaceService::create(
            directory.path(),
            authority.call_proof().unwrap(),
            &[owner.credential.identity()],
            None,
            true,
            None,
        )
        .unwrap();
        assert_eq!(
            service.space_access_devices().unwrap(),
            vec![owner.credential.id()]
        );
        assert!(
            !service
                .space_access_devices()
                .unwrap()
                .contains(&service.credential.id())
        );
        let names = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from(["state.json".into(), "transport.json".into()])
        );
        for name in names {
            let bytes = std::fs::read_to_string(directory.path().join(name)).unwrap();
            assert!(!bytes.contains(&record::encode_hex(&owner.key.to_bytes())));
            assert!(!bytes.contains("AGE-SECRET-KEY"));
        }
        drop(service);
        let reopened = PublicSpaceService::open(directory.path(), true).unwrap();
        assert_eq!(reopened.authorities.0[0].head_id(), authority.head_id());
    }
    #[test]
    fn authority_publication_uses_durable_compare_and_swap_and_rejects_a_valid_fork() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Device::new();
        let authority = initial(&owner);
        let mut service = PublicSpaceService::create(
            directory.path(),
            authority.call_proof().unwrap(),
            &[owner.credential.identity()],
            None,
            true,
            None,
        )
        .unwrap();
        let child = owner.child();
        let next = update(&authority, &owner, Some(&child), None);
        let old = authority.head_id();
        let mut state = service.service_state().unwrap();
        service
            .publish_authority(
                &mut state,
                &owner.credential,
                &json!({"expected_head":old,"proof":next.call_proof().unwrap()}),
                None,
            )
            .unwrap();
        let fork = update(&authority, &owner, None, None);
        assert!(
            service
                .publish_authority(
                    &mut state,
                    &owner.credential,
                    &json!({"expected_head":old,"proof":fork.call_proof().unwrap()}),
                    None
                )
                .is_err()
        );
        assert!(
            service
                .publish_authority(
                    &mut state,
                    &owner.credential,
                    &json!({"expected_head":next.head_id(),"proof":fork.call_proof().unwrap()}),
                    None
                )
                .is_err()
        );
        drop(service);
        let reopened = PublicSpaceService::open(directory.path(), true).unwrap();
        assert_eq!(reopened.authorities.0[0].head_id(), next.head_id());
    }
    #[test]
    fn admitted_child_survives_parent_retirement_but_cannot_enroll_a_new_child_of_that_parent() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Device::new();
        let child = owner.child();
        let late = owner.child();
        let initial = initial(&owner);
        let admitted = update(&initial, &owner, Some(&child), None);
        let mut service = PublicSpaceService::create(
            directory.path(),
            admitted.call_proof().unwrap(),
            &[owner.credential.identity()],
            None,
            true,
            None,
        )
        .unwrap();
        let mut state = service.service_state().unwrap();
        state.revoked.insert(owner.credential.id());
        service.save_service_state(&state).unwrap();
        assert_eq!(
            service.space_access_devices().unwrap(),
            vec![child.credential.id()]
        );
        let removed = update(&admitted, &child, None, Some(owner.credential.id()));
        service
            .publish_authority(
                &mut state,
                &child.credential,
                &json!({"expected_head":admitted.head_id(),"proof":removed.call_proof().unwrap()}),
                None,
            )
            .unwrap();
        let stale = update(&removed, &child, Some(&late), None);
        assert!(
            service
                .publish_authority(
                    &mut state,
                    &child.credential,
                    &json!({"expected_head":removed.head_id(),"proof":stale.call_proof().unwrap()}),
                    None
                )
                .is_err()
        );
        assert!(
            service
                .authority_status(&state, &child.credential, None)
                .is_ok()
        );
    }
    #[test]
    fn publication_retries_when_administration_changes_after_the_owner_fetch() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Device::new();
        let authority = initial(&owner);
        let mut service = PublicSpaceService::create(
            directory.path(),
            authority.call_proof().unwrap(),
            &[owner.credential.identity()],
            None,
            true,
            None,
        )
        .unwrap();
        let mut state = service.service_state().unwrap();
        let invite = json!({"v":1,"kind":"space.command","space":authority.space(),"nonce":record::random_hex::<16>().unwrap(),"issued":1,"action":"invite","body":{"authority_head":authority.head_id(),"id":record::random_hex::<16>().unwrap(),"token":record::random_hex::<32>().unwrap(),"lifetime":86400,"require_approval":true}});
        let intent = SignedRecord::sign(&serde_json::to_vec(&invite).unwrap(), &owner.key).unwrap();
        state.journal.push(AdminEvidence {
            record: STANDARD.encode(intent.bytes()),
            credential: STANDARD.encode(owner.credential.record().bytes()),
        });
        service.save_service_state(&state).unwrap();
        let stale = update(&authority, &owner, None, None);
        let error = service
            .publish_authority(
                &mut state,
                &owner.credential,
                &json!({"expected_head":authority.head_id(),"proof":stale.call_proof().unwrap()}),
                None,
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "General permissions have changed. Refresh and try again."
        );
        assert_eq!(service.authorities.0[0].head_id(), authority.head_id());
        let mut config = stale.head().unwrap().clone();
        config.action.request_record_id =
            crate::owner_admission::journal_commitment(&state.journal).unwrap();
        let mut accepted = authority.clone();
        accepted
            .apply_config(config.sign(&owner.key).unwrap())
            .unwrap();
        service.publish_authority(&mut state, &owner.credential, &json!({"expected_head":authority.head_id(),"proof":accepted.call_proof().unwrap()}), None).unwrap();
        assert_eq!(service.service_state().unwrap().committed_journal.len(), 1);
    }
    #[tokio::test]
    async fn declined_device_rejoining_an_open_invitation_stays_pending_until_a_new_head_approval()
    {
        use std::io::Write;
        async fn command(
            service: &mut PublicSpaceService,
            config: &ServiceConfig,
            device: &Device,
            action: &str,
            body: Value,
        ) -> Value {
            let nonce = record::random_hex::<16>().unwrap();
            let signed = SignedRecord::sign(
                &serde_json::to_vec(&json!({"v":1,"kind":"space.command","space":config.address.scope.space,"nonce":nonce,"issued":time().unwrap(),"action":action,"body":body})).unwrap(),
                &device.key,
            ).unwrap();
            let reply = service
                .serve_space_inner(
                    config,
                    Request {
                        nonce,
                        invitation: None,
                        record: Some(STANDARD.encode(signed.bytes())),
                        credential: Some(STANDARD.encode(device.credential.record().bytes())),
                    },
                    None,
                )
                .await
                .unwrap();
            serde_json::from_slice(
                &crypto::open_bytes(
                    &STANDARD.decode(reply.ciphertext.unwrap()).unwrap(),
                    &device._recipient,
                    LIMIT,
                )
                .unwrap(),
            )
            .unwrap()
        }
        let directory = tempfile::tempdir().unwrap();
        let owner = Device::new();
        let guest = Device::new();
        let authority = initial(&owner);
        let mut service = PublicSpaceService::create(
            directory.path(),
            authority.call_proof().unwrap(),
            &[owner.credential.identity()],
            None,
            true,
            None,
        )
        .unwrap();
        let config = ServiceConfig {
            name: "Declined enrollment".into(),
            owners: vec![owner.credential.identity()],
            contact_email: None,
            address: SpaceAddress {
                url: "http://127.0.0.1:12345/team/v1/spaces".into(),
                scope: service.team_scope().unwrap(),
                message_lifetime_seconds: 86400,
                service_credential: Some(service.transport_credential()),
            },
            peer: crate::sync::PeerDescriptor {
                url: "http://127.0.0.1:12345/".into(),
                signing_public_key: record::encode_hex(owner.key.verifying_key().as_bytes()),
                mailbox_id: crate::ids::MailboxId::from_bytes([3; 32]),
                read_token: Some("11".repeat(32)),
                write_token: Some("22".repeat(32)),
            },
        };
        let contact = crate::invite::shared::contact(
            &guest.credential,
            &guest.key,
            "Guest",
            time().unwrap() + 86_400_000,
        )
        .unwrap();
        let packet = json!({"kind":"Contact","card":STANDARD.encode(contact.bytes()),"credential":STANDARD.encode(guest.credential.record().bytes())});
        let mut compressed =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        compressed
            .write_all(&serde_json::to_vec(&packet).unwrap())
            .unwrap();
        let enrollment = team::EnrollmentRequest {
            v: 1,
            contact: format!("elo://exchange/v1#{}", URL_SAFE_NO_PAD.encode(compressed.finish().unwrap())),
            proof: STANDARD.encode(SignedRecord::sign(&serde_json::to_vec(&json!({"v":1,"kind":"team.join","space":authority.space(),"stream":authority.stream(),"controller":authority.initial_controller().id(),"contact":contact.id()})).unwrap(), &guest.key).unwrap().bytes()),
        };
        let mut tokens = Vec::new();
        for require_approval in [true, false] {
            let token = record::random_hex::<32>().unwrap();
            let reply = command(&mut service, &config, &owner, "invite", json!({"authority_head":authority.head_id(),"id":record::random_hex::<16>().unwrap(),"token":token,"lifetime":86400,"require_approval":require_approval})).await;
            assert!(reply.get("error").is_none(), "{reply}");
            tokens.push(token);
        }
        let joined = command(
            &mut service,
            &config,
            &guest,
            "join",
            json!({"token":tokens[0],"enrollment":enrollment}),
        )
        .await;
        assert_eq!(joined["status"], "pending");
        let decision = json!({"authority_head":authority.head_id(),"id":guest.credential.id(),"approve":false});
        let denied = command(&mut service, &config, &owner, "decide", decision).await;
        assert!(denied.get("error").is_none(), "{denied}");
        let joined = command(
            &mut service,
            &config,
            &guest,
            "join",
            json!({"token":tokens[1],"enrollment":enrollment,"note":"Please reconsider"}),
        )
        .await;
        assert_eq!(joined["status"], "pending");
        let state = service.service_state().unwrap();
        let applicant = &state.applicants[&guest.credential.id().to_string()];
        assert_eq!(applicant.status, "pending");
        assert_eq!(applicant.note, "Please reconsider");
        assert_eq!(
            service
                .authority_status(&state, &owner.credential, None)
                .unwrap()["pending"],
            json!([])
        );
        let approve =
            json!({"authority_head":authority.head_id(),"id":guest.credential.id(),"approve":true});
        let rejected = command(&mut service, &config, &owner, "decide", approve).await;
        assert_eq!(
            rejected["error"],
            "General permissions have changed. Refresh and try again."
        );
        let mut state = service.service_state().unwrap();
        assert_eq!(
            state.journal.len(),
            3,
            "rejected approval must not enter the journal"
        );
        let mut next_config = update(&authority, &owner, None, None)
            .head()
            .unwrap()
            .clone();
        next_config.action.request_record_id =
            crate::owner_admission::journal_commitment(&state.journal).unwrap();
        let mut next = authority.clone();
        next.apply_config(next_config.sign(&owner.key).unwrap())
            .unwrap();
        service
            .publish_authority(
                &mut state,
                &owner.credential,
                &json!({"expected_head":authority.head_id(),"proof":next.call_proof().unwrap()}),
                None,
            )
            .unwrap();
        let approved = command(
            &mut service,
            &config,
            &owner,
            "decide",
            json!({"authority_head":next.head_id(),"id":guest.credential.id(),"approve":true}),
        )
        .await;
        assert!(approved.get("error").is_none(), "{approved}");
        let state = service.service_state().unwrap();
        assert_eq!(
            state.applicants[&guest.credential.id().to_string()].status,
            "eligible"
        );
        assert!(
            !state
                .device_was_declined(&guest.credential.id().to_string())
                .unwrap()
        );
    }
    #[tokio::test]
    async fn replayed_device_revocation_cannot_poison_the_administration_journal() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Device::new();
        let child = owner.child();
        let admitted = update(&initial(&owner), &owner, Some(&child), None);
        let mut service = PublicSpaceService::create(
            directory.path().join("service"),
            admitted.call_proof().unwrap(),
            &[owner.credential.identity()],
            None,
            true,
            None,
        )
        .unwrap();
        let replica = crate::replica::ReplicaStore::open(directory.path().join("replica"))
            .await
            .unwrap();
        let config = ServiceConfig {
            name: "Replay test".into(),
            owners: vec![owner.credential.identity()],
            contact_email: None,
            address: SpaceAddress {
                url: "http://127.0.0.1:12345/team/v1/spaces".into(),
                scope: service.team_scope().unwrap(),
                message_lifetime_seconds: 86400,
                service_credential: Some(service.transport_credential()),
            },
            peer: crate::sync::PeerDescriptor {
                url: "http://127.0.0.1:12345/".into(),
                signing_public_key: record::encode_hex(replica.key().as_bytes()),
                mailbox_id: crate::ids::MailboxId::from_bytes([3; 32]),
                read_token: Some("11".repeat(32)),
                write_token: Some("22".repeat(32)),
            },
        };
        let proof = crate::identity::DeviceRevocation::issue_from_device(
            &child.credential,
            &child.key,
            &owner.credential,
        )
        .unwrap();
        let nonce = record::random_hex::<16>().unwrap();
        let command = Command {
            v: 1,
            kind: "space.command".into(),
            space: admitted.space(),
            nonce: nonce.clone(),
            issued: time().unwrap(),
            action: "device_revoke".into(),
            body: json!({"authority_head":admitted.head_id(),"proof":STANDARD.encode(proof.bytes())}),
        };
        let signed =
            SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), &child.key).unwrap();
        for _ in 0..2 {
            let reply = service
                .serve_hosted_space(
                    &config,
                    Request {
                        nonce: nonce.clone(),
                        invitation: None,
                        record: Some(STANDARD.encode(signed.bytes())),
                        credential: Some(STANDARD.encode(child.credential.record().bytes())),
                    },
                    &replica,
                )
                .await
                .unwrap();
            let ciphertext = STANDARD.decode(reply.ciphertext.unwrap()).unwrap();
            let body: Value = serde_json::from_slice(
                &crypto::open_bytes(&ciphertext, &child._recipient, LIMIT).unwrap(),
            )
            .unwrap();
            assert_eq!(body["revoked"], json!(owner.credential.id()), "{body}");
        }
        let state = service.service_state().unwrap();
        assert_eq!(
            state.journal.len(),
            2,
            "one signed command and one permanent proof"
        );
        let devices = service.space_device_list(&child.credential).unwrap();
        assert_eq!(devices["devices"].as_array().unwrap().len(), 1);
        assert_eq!(devices["devices"][0]["id"], json!(child.credential.id()));
        let commitment = crate::owner_admission::journal_commitment(&state.journal).unwrap();
        let stale =
            json!({"space":admitted.space(),"stream":admitted.stream(),"head":admitted.head_id()});
        assert!(
            service
                .check_space_chat_head(&state, &child.credential, &stale)
                .is_err(),
            "an active sender cannot encrypt using a head containing a retired recipient"
        );
        let mut config = update(&admitted, &child, None, Some(owner.credential.id()))
            .head()
            .unwrap()
            .clone();
        config.action.request_record_id = commitment;
        let mut corrected = admitted.clone();
        corrected
            .apply_config(config.sign(&child.key).unwrap())
            .unwrap();
        let mut state = state;
        service.publish_authority(&mut state, &child.credential, &json!({"expected_head":admitted.head_id(),"proof":corrected.call_proof().unwrap()}), Some(&replica)).unwrap();
        service.check_space_chat_head(&state, &child.credential, &json!({"space":admitted.space(),"stream":admitted.stream(),"head":corrected.head_id()})).unwrap();
    }
}

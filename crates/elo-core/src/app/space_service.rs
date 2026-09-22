//! Identity-authenticated Space invitations. Invitation capabilities never contain
//! permanent mailbox credentials; those are encrypted for an approved device.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::time::Duration;
mod attachments;
mod calls;
mod roles;
use attachments::*;
use roles::Roles;

pub const PREFIX: &str = "elo://space/v1#";
pub const LIFETIMES: [u64; 6] = [60, 600, 1800, 3600, 86400, 100 * 365 * 86400];
const LIMIT: usize = 8 * 1024 * 1024;
const RESPONSE_LIMIT: usize = 24 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceAddress {
    pub url: String,
    pub scope: team::TeamScope,
    pub message_lifetime_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceInvitation {
    pub v: u8,
    pub address: SpaceAddress,
    pub token: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub nonce: String,
    pub invitation: Option<String>,
    pub record: Option<String>,
    pub credential: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub record: String,
    pub credential: String,
    pub ciphertext: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionReceipt {
    pub record: String,
    pub credential: String,
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
pub struct ServiceConfig {
    pub name: String,
    pub address: SpaceAddress,
    pub owners: Vec<IdentityId>,
    #[serde(default)]
    pub contact_email: Option<String>,
    pub peer: PeerDescriptor,
}

pub fn validate_message_lifetime(value: u64) -> Result<()> {
    if matches!(value, 21_600 | 43_200 | 86_400) {
        Ok(())
    } else {
        Err("Choose a server message lifetime of 6, 12 or 24 hours.".into())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
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
    identity: IdentityId,
    name: String,
    status: String,
    invitation: String,
    #[serde(default)]
    note: String,
    request: team::EnrollmentRequest,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceState {
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

/// A contact address, never an email header or proof of identity.
pub fn validate_contact_email(value: &str) -> Result<()> {
    let valid = value.len() <= 254
        && value.is_ascii()
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && local.len() <= 64
                && !local.starts_with('.')
                && !local.ends_with('.')
                && !local.contains("..")
                && local
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
                && domain.contains('.')
                && domain.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        });
    if !valid {
        return Err("Enter a valid contact email address.".into());
    }
    Ok(())
}
pub(super) fn join_note(value: &Value) -> Result<String> {
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
fn time() -> Result<u64> {
    Ok(now()?.as_millis() as u64)
}
fn verify_credential(encoded: &str) -> Result<VerifiedCredential> {
    let record = decode_record(encoded)?;
    Ok(VerifiedCredential::verify(
        record.bytes(),
        &root_key(field(record.body(), "root_public_key")?)?,
    )?)
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
impl SpaceAddress {
    pub fn validate(&self, allow_loopback: bool) -> Result<()> {
        let url = reqwest::Url::parse(&self.url)?;
        let loopback = url
            .host_str()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !service_path(url.path(), "spaces")
            || !(url.scheme() == "https" || (allow_loopback && loopback && url.scheme() == "http"))
            || root_key(&self.scope.root)?.is_weak()
            || validate_message_lifetime(self.message_lifetime_seconds).is_err()
        {
            return Err("Invalid Space address.".into());
        }
        Ok(())
    }
}

/// Hosted Spaces retain separate, canonical endpoints under one HTTPS origin.
pub(crate) fn service_path(path: &str, action: &str) -> bool {
    if path == format!("/team/v1/{action}") {
        return true;
    }
    path.strip_prefix("/spaces/")
        .and_then(|rest| rest.strip_suffix(&format!("/team/v1/{action}")))
        .is_some_and(|id| record::hex::<32>(id).is_ok())
}
impl SpaceInvitation {
    pub fn parse(value: &str, allow_loopback: bool) -> Result<Self> {
        let data = value
            .trim()
            .strip_prefix(PREFIX)
            .ok_or("Scan a Space invitation.")?;
        if data.len() > 4096 {
            return Err("Space invitation is too large.".into());
        }
        let value: Self = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(data)?)?;
        if value.v != 1 {
            return Err("Unsupported Space invitation.".into());
        }
        record::hex::<32>(&value.token)?;
        value.address.validate(allow_loopback)?;
        Ok(value)
    }
    pub fn link(&self) -> Result<String> {
        Ok(format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }
}

impl ClientApp {
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
    ) -> Result<()> {
        if self.account_membership(config, identity)?["primary"] == true {
            return Err("Transfer primary ownership before deleting your account.".into());
        }
        let mut state = self.service_state()?;
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
        self.finish_member_removals(&state).await?;
        self.erase_service_contact(identity)?;
        self.store.erase_account_content(identity).await?;
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
                SignedRecord::sign(&serde_json::to_vec(&deleted)?, self.session.signing_key())?
                    .bytes(),
            ),
            credential: STANDARD.encode(self.session.credential().record().bytes()),
        }))
    }
    fn verify_space_deletion(address: &SpaceAddress, receipt: DeletionReceipt) -> Result<Value> {
        let credential = verify_credential(&receipt.credential)?;
        if credential.id() != address.scope.controller
            || field(credential.record().body(), "root_public_key")? != address.scope.root
        {
            return Err("Unexpected Space deletion signer.".into());
        }
        let record = decode_record(&receipt.record)?;
        record.verify_signature(credential.key())?;
        let value = record.body();
        if value["v"] != 1
            || value["kind"] != "space.deleted"
            || value["space"] != json!(address.scope.space)
            || value["deleted_at"].as_u64().is_none()
        {
            return Err("Invalid Space deletion receipt.".into());
        }
        Ok(json!({"status":"deleted"}))
    }
    /// Used only by the host to enforce current membership at its transport gate.
    pub fn space_access_members(&self) -> Result<Vec<IdentityId>> {
        let state = self.service_state()?;
        let mut identities = BTreeSet::from([self.identity_id()]);
        identities.extend(
            state
                .applicants
                .values()
                .filter(|a| a.status == "approved")
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
        if !self.space_access_members()?.contains(&identity) {
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
    async fn finish_member_removals(&mut self, state: &ServiceState) -> Result<()> {
        let scope = self.team_scope()?;
        for identity in state.removals.keys() {
            if state
                .applicants
                .values()
                .any(|a| a.identity == *identity && a.status == "approved")
            {
                continue;
            }
            if self.authorities.0[0]
                .head()?
                .members
                .iter()
                .any(|m| m.identity_id == *identity)
            {
                self.remove_chat_member(
                    json!({"space":scope.space,"stream":scope.stream,"fingerprint":identity}),
                )
                .await?;
            }
        }
        Ok(())
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
    pub(super) fn space_request(
        &self,
        address: &SpaceAddress,
        action: &str,
        body: Value,
    ) -> Result<Request> {
        let nonce = record::random_hex::<16>()?;
        let command = Command {
            v: 1,
            kind: "space.command".into(),
            space: address.scope.space,
            nonce: nonce.clone(),
            issued: time()?,
            action: action.into(),
            body,
        };
        let signed =
            SignedRecord::sign(&serde_json::to_vec(&command)?, self.session.signing_key())?;
        Ok(Request {
            nonce,
            invitation: None,
            record: Some(STANDARD.encode(signed.bytes())),
            credential: Some(STANDARD.encode(self.session.credential().record().bytes())),
        })
    }
    pub(super) async fn call_space(
        &self,
        address: &SpaceAddress,
        action: &str,
        body: Value,
    ) -> Result<Value> {
        address.validate(self.allow_loopback)?;
        let request = self.space_request(address, action, body)?;
        self.space_http(address, request).await
    }
    pub(super) async fn preview_space(&self, invitation: &SpaceInvitation) -> Result<Value> {
        self.space_http(
            &invitation.address,
            Request {
                nonce: record::random_hex::<16>()?,
                invitation: Some(invitation.token.clone()),
                record: None,
                credential: None,
            },
        )
        .await
    }
    async fn space_http(&self, address: &SpaceAddress, request: Request) -> Result<Value> {
        address.validate(self.allow_loopback)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(12))
            .build()?;
        let mut response = client
            .post(&address.url)
            .json(&request)
            .send()
            .await
            .map_err(|_| "Could not connect to this Space. Try again.")?;
        let deleted = response.status() == reqwest::StatusCode::GONE;
        if !response.status().is_success() && !deleted {
            return Err("Could not update this Space. Try again.".into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > RESPONSE_LIMIT {
                return Err("Space response is too large.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        if deleted {
            return Self::verify_space_deletion(address, serde_json::from_slice(&bytes)?);
        }
        self.open_space_response(address, &request.nonce, serde_json::from_slice(&bytes)?)
    }
    pub(super) fn open_space_response(
        &self,
        address: &SpaceAddress,
        nonce: &str,
        response: Response,
    ) -> Result<Value> {
        let credential = verify_credential(&response.credential)?;
        if credential.id() != address.scope.controller
            || field(credential.record().body(), "root_public_key")? != address.scope.root
        {
            return Err("This Space has an unexpected signing key.".into());
        }
        let signed = decode_record(&response.record)?;
        signed.verify_signature(credential.key())?;
        let answer: Answer = signed.decode()?;
        if answer.v != 1
            || answer.kind != "space.response"
            || answer.space != address.scope.space
            || answer.nonce != nonce
        {
            return Err("This response belongs to another Space request.".into());
        }
        let value = match (answer.body, answer.ciphertext_hash, response.ciphertext) {
            (Some(body), None, None) => body,
            (None, Some(hash), Some(ciphertext)) => {
                if ciphertext.len() > RESPONSE_LIMIT {
                    return Err("Space response is too large.".into());
                }
                let bytes = STANDARD.decode(ciphertext)?;
                if crate::ids::ObjectId::of_ciphertext(&bytes).to_string() != hash {
                    return Err("Invalid Space response signature.".into());
                }
                serde_json::from_slice(&Zeroizing::new(crypto::open_bytes(
                    &bytes,
                    self.session.age_identity(),
                    LIMIT,
                )?))?
            }
            _ => return Err("Invalid Space response.".into()),
        };
        if let Some(error) = value["error"].as_str() {
            return Err(error.to_owned().into());
        }
        Ok(value)
    }
    fn service_state(&self) -> Result<ServiceState> {
        let path = self.directory.join("space-service.age");
        if !path.try_exists()? {
            return Ok(ServiceState::default());
        }
        let bytes = vault::read_private(&path)?;
        Ok(serde_json::from_slice(&Zeroizing::new(
            crypto::open_bytes(&bytes, self.session.age_identity(), LIMIT)?,
        ))?)
    }
    fn save_service_state(&self, state: &ServiceState) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(state)?);
        vault::write_private(
            &self.directory.join("space-service.age"),
            &crypto::seal_bytes(&bytes, &[self.session.age_identity().to_public()], LIMIT)?,
            true,
        )?;
        Ok(())
    }
    /// Local administrator bootstrap; the caller already holds the private
    /// service profile. This method is never exposed as an unauthenticated HTTP action.
    pub fn bootstrap_space_invitation(&self, address: &SpaceAddress) -> Result<String> {
        address.validate(self.allow_loopback)?;
        let scope = self.team_scope()?;
        if serde_json::to_value(&scope)? != serde_json::to_value(&address.scope)? {
            return Err("Space scope mismatch.".into());
        }
        let mut state = self.service_state()?;
        let current = time()?;
        state
            .offers
            .retain(|_, offer| !offer.revoked && offer.expires_at > current);
        if state.offers.len() >= 128 {
            return Err("Revoke an unused invitation first.".into());
        }
        let token = record::random_hex::<32>()?;
        state.offers.insert(
            record::random_hex::<16>()?,
            Offer {
                token: token.clone(),
                issued_at: current,
                expires_at: current + 86_400_000,
                require_approval: true,
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
    /// administrator profile lock. All authenticated results bind the request nonce.
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
        let peer =
            Peer::new(config.peer.clone(), self.allow_loopback)?.with_identity(&self.session);
        if !record::valid_display_name(&config.name)
            || !record::sorted_unique(&config.owners, 1, 16)
            || config.peer.read_token.is_none()
            || config.peer.write_token.is_none()
            || !self.peers.iter().any(|configured| {
                configured.id() == peer.id() && configured.mailbox() == peer.mailbox()
            })
        {
            return Err("Invalid Space service owner or mailbox configuration.".into());
        }
        if scope.space != config.address.scope.space
            || scope.controller != config.address.scope.controller
            || scope.root != config.address.scope.root
            || scope.stream != config.address.scope.stream
        {
            return Err("Space service configuration mismatch.".into());
        }
        let mut state = self.service_state()?;
        let current = time()?;
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
                "join" | "status" | "manage" | "storage"
            );
            if cacheable && let Some((_, _, reply)) = state.replies.get(&replay_key) {
                reply.clone()
            } else {
                if state.replies.len() >= 8192 {
                    return Err("Space is busy. Try again.".into());
                }
                let result = self
                    .space_command(config, &mut state, &credential, command, replica)
                    .await;
                let value = match result {
                    Ok(value) => value,
                    Err(error) => json!({"error":error.to_string()}),
                };
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
                self.save_service_state(&state)?;
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
        let record = SignedRecord::sign(&serde_json::to_vec(&answer)?, self.session.signing_key())?;
        Ok(Response {
            record: STANDARD.encode(record.bytes()),
            credential: STANDARD.encode(self.session.credential().record().bytes()),
            ciphertext,
        })
    }
    async fn space_command(
        &mut self,
        config: &ServiceConfig,
        state: &mut ServiceState,
        credential: &VerifiedCredential,
        command: Command,
        replica: Option<&crate::replica::ReplicaStore>,
    ) -> Result<Value> {
        let identity = credential.identity();
        if state.erased_accounts.contains(&identity) {
            return Err("This account was deleted from this service.".into());
        }
        let owner = state
            .roles
            .as_ref()
            .ok_or("Space roles unavailable.")?
            .is_owner(identity);
        let current = time()?;
        self.finish_member_removals(state).await?;
        if let Some(result) =
            self.attachment_space_command(state, credential, owner, &command, current)
        {
            return result;
        }
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        match command.action.as_str() {
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
                if !state.applicants.contains_key(&key)
                    || state
                        .applicants
                        .get(&key)
                        .is_some_and(|a| a.status == "removed" || a.status == "declined")
                {
                    if state.applicants.len() >= record::MAX_CHAT_CREDENTIALS {
                        return Err("Space request limit reached.".into());
                    }
                    state.applicants.insert(
                        key.clone(),
                        Applicant {
                            identity,
                            name,
                            status: if state.removals.contains_key(&identity)
                                || (offer.require_approval && !owner)
                            {
                                "pending"
                            } else {
                                "approved"
                            }
                            .into(),
                            invitation: offer_id.clone(),
                            note: if state.removals.contains_key(&identity)
                                || (offer.require_approval && !owner)
                            {
                                note.clone()
                            } else {
                                String::new()
                            },
                            request,
                        },
                    );
                    self.save_service_state(state)?;
                } else if let Some(applicant) = state.applicants.get_mut(&key) {
                    if applicant.status == "pending" {
                        applicant.note = note;
                    }
                    applicant.request = request;
                }
                self.space_join_reply(config, state, &key).await
            }
            "status" => {
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
                if let Some(applicant) = state.applicants.get_mut(&key) {
                    applicant.request = request;
                    self.space_join_reply(config, state, &key).await
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
                    state.applicants.insert(
                        key.clone(),
                        Applicant {
                            identity,
                            name,
                            status: "approved".into(),
                            invitation: String::new(),
                            note: String::new(),
                            request,
                        },
                    );
                    self.space_join_reply(config, state, &key).await
                }
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
                let token = record::random_hex::<32>()?;
                let id = record::random_hex::<16>()?;
                let expires_at = current
                    .checked_add(seconds * 1000)
                    .ok_or("Invalid expiry.")?;
                state.offers.insert(
                    id.clone(),
                    Offer {
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
                self.save_service_state(state)?;
                Ok(json!({}))
            }
            "decide" if owner => {
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
                    "approved"
                } else {
                    "declined"
                }
                .into();
                applicant.note.clear();
                self.save_service_state(state)?;
                Ok(json!({}))
            }
            "role_change" | "role_decide" => {
                let members = self.space_role_members(state)?;
                let roles = state.roles.as_mut().ok_or("Space roles unavailable.")?;
                let result =
                    roles.apply(identity, &command.action, &command.body, &members, current)?;
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
                    for applicant in state
                        .applicants
                        .values_mut()
                        .filter(|a| a.identity == target)
                    {
                        applicant.status = "removed".into();
                        applicant.note.clear();
                    }
                    state.roles.as_mut().unwrap().retire_member(target);
                    // Commit the revocation before rotating General. Every subsequent
                    // request finishes interrupted rotations before granting enrollment.
                    self.save_service_state(state)?;
                    self.finish_member_removals(state).await?;
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
    ) -> Result<Value> {
        let applicant = state.applicants.get(key).ok_or("Request not found.")?;
        if applicant.status != "approved" {
            return Ok(
                json!({"name":config.name,"status":applicant.status,"membership_epoch":state.removals.get(&applicant.identity).copied().unwrap_or(0)}),
            );
        }
        let packet = self
            .enroll_approved_space_member(applicant.request.clone())
            .await?;
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        Ok(
            json!({"name":config.name,"status":"approved","membership_epoch":state.removals.get(&applicant.identity).copied().unwrap_or(0),"owner":roles.is_owner(applicant.identity),"role":roles.role(applicant.identity),"roles_revision":roles.revision,"role_requests":roles.requests_for(applicant.identity),"contact_email":roles.contact_email,"message_lifetime_seconds":config.address.message_lifetime_seconds,"peer":config.peer,"enrollment":packet}),
        )
    }

    fn space_role_members(&self, state: &ServiceState) -> Result<Vec<roles::RoleMember>> {
        let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
        let mut members = BTreeMap::new();
        for applicant in state.applicants.values().filter(|a| a.status == "approved") {
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

#[cfg(test)]
mod deletion_tests {
    use super::*;
    #[test]
    fn contact_addresses_and_applicant_notes_have_safe_bounds() {
        for address in ["owner+family@example.test", "first.last@sub.example.test"] {
            assert!(validate_contact_email(address).is_ok());
        }
        for address in [
            "",
            " x@example.test",
            "x@example.test\n",
            "x@y@z.test",
            "x@-bad.test",
            "a..b@example.test",
            "x@example.test?cc=other@example.test",
        ] {
            assert!(validate_contact_email(address).is_err(), "{address:?}");
        }
        assert_eq!(
            join_note(&json!({"note":"  Hello\nMarek  "})).unwrap(),
            "Hello\nMarek"
        );
        assert!(join_note(&json!({"note":"ą".repeat(500)})).is_ok());
        assert!(join_note(&json!({"note":"ą".repeat(501)})).is_err());
        assert!(join_note(&json!({"note":"bad\0note"})).is_err());
        assert!(join_note(&json!({"note":42})).is_err());
        assert_eq!(join_note(&json!({})).unwrap(), "");
    }
    #[test]
    fn deletion_requires_pinned_signer_scope_and_unmodified_signature() {
        let (session, _) = Session::create().unwrap();
        let (other, _) = Session::create().unwrap();
        let address = SpaceAddress {
            url: "https://example.invalid/team/v1/spaces".into(),
            scope: team::TeamScope {
                space: SpaceId::from_bytes([1; 32]),
                stream: StreamId::from_bytes([2; 16]),
                root: field(session.credential().record().body(), "root_public_key")
                    .unwrap()
                    .into(),
                controller: session.credential().id(),
            },
            message_lifetime_seconds: 86_400,
        };
        let receipt = |signer: &Session, space: SpaceId| {
            let body = json!({"v":1,"kind":"space.deleted","space":space,"deleted_at":1});
            DeletionReceipt {
                record: STANDARD.encode(
                    SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), signer.signing_key())
                        .unwrap()
                        .bytes(),
                ),
                credential: STANDARD.encode(signer.credential().record().bytes()),
            }
        };
        let valid = receipt(&session, address.scope.space);
        assert!(ClientApp::verify_space_deletion(&address, valid.clone()).is_ok());
        assert!(
            ClientApp::verify_space_deletion(&address, receipt(&other, address.scope.space))
                .is_err()
        );
        assert!(
            ClientApp::verify_space_deletion(
                &address,
                receipt(&session, SpaceId::from_bytes([3; 32]))
            )
            .is_err()
        );
        let mut forged = valid;
        let mut bytes = STANDARD.decode(&forged.record).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        forged.record = STANDARD.encode(bytes);
        assert!(ClientApp::verify_space_deletion(&address, forged).is_err());
    }
}

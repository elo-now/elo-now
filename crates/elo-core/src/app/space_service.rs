//! Identity-authenticated Space invitations. Invitation capabilities never contain
//! permanent mailbox credentials; those are encrypted for an approved device.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::time::Duration;

pub const PREFIX: &str = "elo://space/v1#";
pub const LIFETIMES: [u64; 6] = [60, 600, 1800, 3600, 86400, 100 * 365 * 86400];
const LIMIT: usize = 8 * 1024 * 1024;
const RESPONSE_LIMIT: usize = 24 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceAddress {
    pub url: String,
    pub scope: team::TeamScope,
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
    pub peer: PeerDescriptor,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    token: String,
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
    request: team::EnrollmentRequest,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceState {
    offers: BTreeMap<String, Offer>,
    applicants: BTreeMap<String, Applicant>,
    replies: BTreeMap<String, (u64, String, Value)>,
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
            || url.path() != "/team/v1/spaces"
            || !(url.scheme() == "https" || (allow_loopback && loopback && url.scheme() == "http"))
            || root_key(&self.scope.root)?.is_weak()
        {
            return Err("Invalid Space address.".into());
        }
        Ok(())
    }
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
        if !response.status().is_success() {
            return Err("Could not update this Space. Try again.".into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > RESPONSE_LIMIT {
                return Err("Space response is too large.".into());
            }
            bytes.extend_from_slice(&chunk);
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
        record::hex::<16>(&request.nonce)?;
        config.address.validate(self.allow_loopback)?;
        let scope = self.team_scope()?;
        let peer = Peer::new(config.peer.clone(), self.allow_loopback)?;
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
                    json!({"name":config.name,"expires_at":offer.expires_at,"require_approval":offer.require_approval})
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
            let cacheable = !matches!(command.action.as_str(), "join" | "status" | "manage");
            if cacheable && let Some((_, _, reply)) = state.replies.get(&replay_key) {
                reply.clone()
            } else {
                if state.replies.len() >= 8192 {
                    return Err("Space is busy. Try again.".into());
                }
                let result = self
                    .space_command(config, &mut state, &credential, command)
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
    ) -> Result<Value> {
        let owner = config.owners.contains(&credential.identity());
        let current = time()?;
        match command.action.as_str() {
            "join" => {
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
                if !state.applicants.contains_key(&key) {
                    if state.applicants.len() >= record::MAX_CHAT_CREDENTIALS {
                        return Err("Space request limit reached.".into());
                    }
                    state.applicants.insert(
                        key.clone(),
                        Applicant {
                            identity,
                            name,
                            status: if offer.require_approval && !owner {
                                "pending"
                            } else {
                                "approved"
                            }
                            .into(),
                            invitation: offer_id.clone(),
                            request,
                        },
                    );
                    self.save_service_state(state)?;
                } else if let Some(applicant) = state.applicants.get_mut(&key) {
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
                if let Some(applicant) = state.applicants.get_mut(&key) {
                    applicant.request = request;
                    self.space_join_reply(config, state, &key).await
                } else {
                    // Legacy General members retain membership, with their own signed
                    // request proving the encryption recipient before any access export.
                    if identity != credential.identity()
                        || device != credential.id()
                        || !self.authorities.0[0].head()?.members.iter().any(|m| {
                            m.identity_id == identity && m.credential_ids.contains(&device)
                        })
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
                            request,
                        },
                    );
                    self.space_join_reply(config, state, &key).await
                }
            }
            "manage" if owner => {
                let offers = state.offers.iter().map(|(id, o)| {
                    Ok(json!({"id":id,"expires_at":o.expires_at,"require_approval":o.require_approval,"revoked":o.revoked,"link":SpaceInvitation {v:1,address:config.address.clone(),token:o.token.clone()}.link()?}))
                }).collect::<Result<Vec<_>>>()?;
                let requests = state
                    .applicants
                    .iter()
                    .filter(|(_, a)| a.status == "pending")
                    .map(|(id, a)| json!({"id":id,"identity":a.identity,"name":a.name}))
                    .collect::<Vec<_>>();
                Ok(json!({"offers":offers,"requests":requests}))
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
                self.save_service_state(state)?;
                Ok(json!({}))
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
            return Ok(json!({"name":config.name,"status":applicant.status}));
        }
        let packet = self.enroll_team_member(applicant.request.clone()).await?;
        Ok(
            json!({"name":config.name,"status":"approved","owner":config.owners.contains(&applicant.identity),"peer":config.peer,"enrollment":packet}),
        )
    }
}

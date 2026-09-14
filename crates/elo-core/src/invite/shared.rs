//! Shared invitations request access; each candidate still needs controller approval.
//! The original single-use invitation contract in the parent module is unchanged.
use crate::{
    authority::{Authority, Capability, ConfigAction, ConfigAdmission, Member},
    identity::VerifiedCredential,
    ids::{IdentityId, RecordId, SpaceId, StreamId},
    record::{self, RecordError, Result, SignedRecord},
    store::{ClientStore, LocalTime, StoreError},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

/// Write-only delivery capability, signed into the offer/request. Readers' tokens
/// are local secrets and cannot occur in this wire type.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryAddress {
    pub url: String,
    pub signing_public_key: String,
    pub mailbox_id: crate::ids::MailboxId,
    pub write_token: String,
    pub expires_at: u64,
}
impl DeliveryAddress {
    pub fn descriptor(&self) -> crate::sync::PeerDescriptor {
        crate::sync::PeerDescriptor {
            url: self.url.clone(),
            signing_public_key: self.signing_public_key.clone(),
            mailbox_id: self.mailbox_id,
            read_token: None,
            write_token: Some(self.write_token.clone()),
        }
    }
    pub fn validate(&self) -> Result<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let token = URL_SAFE_NO_PAD
            .decode(&self.write_token)
            .map_err(|_| RecordError::Authority)?;
        if token.len() != 32
            || URL_SAFE_NO_PAD.encode(&token) != self.write_token
            || self.expires_at > record::MAX_INTEGER
            || self.expires_at == 0
        {
            return Err(RecordError::Authority);
        }
        // Loopback is accepted in signed proofs for local labs; the actual client
        // separately enforces its explicit loopback policy before any network I/O.
        crate::sync::Peer::new(self.descriptor(), true).map_err(|_| RecordError::Authority)?;
        Ok(())
    }
}

/// Recipient-owned notification capability. Provider tokens and owner keys are never shared.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeRoute {
    pub endpoint: String,
    pub id: String,
    pub notify_key: String,
    #[serde(default)]
    pub scope_key: String,
    #[serde(default)]
    pub since: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake: Option<WakeRoute>,
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub base_config_id: RecordId,
    pub controller_credential_id: RecordId,
    pub name: String,
    pub capabilities: Vec<Capability>,
    pub reusable: bool,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryAddress>,
    /// A private offer is usable only by these identities. Omission keeps the
    /// existing shared invitation contract unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invitees: Vec<IdentityId>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake: Option<WakeRoute>,
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub invite_id: RecordId,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryAddress>,
}

/// Attach a route by signing the full record again; never append an unsigned URL.
pub fn with_delivery(
    signed: &SignedRecord,
    key: &SigningKey,
    route: DeliveryAddress,
) -> Result<SignedRecord> {
    signed.verify_signature(&key.verifying_key())?;
    route.validate()?;
    let mut body = signed.body().clone();
    if !matches!(
        body["kind"].as_str(),
        Some("space.invitation.shared" | "space.join.shared")
    ) {
        return Err(RecordError::Authority);
    }
    body["delivery"] = serde_json::to_value(route).map_err(|_| RecordError::Json)?;
    SignedRecord::sign(
        &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
        key,
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake: Option<WakeRoute>,
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
    pub name: String,
    pub expires_at: u64,
}

fn name_valid(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 120 && !name.chars().any(char::is_control)
}
pub fn valid_capabilities(caps: &[Capability]) -> bool {
    caps.contains(&Capability::Read)
        && caps.len() <= 3
        && caps.iter().enumerate().all(|(i, cap)| {
            matches!(
                cap,
                Capability::Read | Capability::Post | Capability::ShareHistory
            ) && !caps[..i].contains(cap)
        })
}
pub fn create(
    authority: &Authority,
    key: &SigningKey,
    name: &str,
    capabilities: Vec<Capability>,
    reusable: bool,
    expires_at: u64,
) -> Result<SignedRecord> {
    if authority.is_forked()
        || authority.controller().key() != &key.verifying_key()
        || !name_valid(name)
        || !valid_capabilities(&capabilities)
    {
        return Err(RecordError::Authority);
    }
    let offer = Offer {
        wake: None,
        v: 1,
        kind: "space.invitation.shared".into(),
        nonce: record::random_hex::<16>()?,
        space_id: authority.space(),
        stream_id: authority.stream(),
        base_config_id: authority.head_id().ok_or(RecordError::Authority)?,
        controller_credential_id: authority.controller().id(),
        name: name.into(),
        capabilities,
        reusable,
        expires_at,
        delivery: None,
        invitees: Vec::new(),
    };
    SignedRecord::sign(
        &serde_json::to_vec(&offer).map_err(|_| RecordError::Json)?,
        key,
    )
}
pub fn verify_offer(
    signed: &SignedRecord,
    controller: &VerifiedCredential,
    now: u64,
) -> Result<Offer> {
    signed.verify_signature(controller.key())?;
    let offer: Offer = signed.decode()?;
    if offer.invitees.len() > 31 || !offer.invitees.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(RecordError::Authority);
    }
    if let Some(route) = &offer.delivery {
        route.validate()?;
        if route.expires_at < offer.expires_at {
            return Err(RecordError::Authority);
        }
    }
    record::hex::<16>(&offer.nonce)?;
    if offer.v != 1
        || offer.kind != "space.invitation.shared"
        || offer.controller_credential_id != controller.id()
        || !name_valid(&offer.name)
        || !valid_capabilities(&offer.capabilities)
        || offer.expires_at <= now
    {
        return Err(RecordError::Authority);
    }
    Ok(offer)
}
pub fn request(
    offer: &SignedRecord,
    controller: &VerifiedCredential,
    candidate: &VerifiedCredential,
    key: &SigningKey,
    name: &str,
    now: u64,
) -> Result<SignedRecord> {
    let invitation = verify_offer(offer, controller, now)?;
    if !invitation.invitees.is_empty() && !invitation.invitees.contains(&candidate.identity()) {
        return Err(RecordError::Authority);
    }
    if candidate.key() != &key.verifying_key() || !name_valid(name) {
        return Err(RecordError::Authority);
    }
    let request = Request {
        wake: None,
        v: 1,
        kind: "space.join.shared".into(),
        nonce: record::random_hex::<16>()?,
        invite_id: offer.id(),
        issuer_identity: candidate.identity(),
        issuer_credential: candidate.id(),
        name: name.into(),
        delivery: None,
    };
    SignedRecord::sign(
        &serde_json::to_vec(&request).map_err(|_| RecordError::Json)?,
        key,
    )
}
pub fn verify_request(signed: &SignedRecord, candidate: &VerifiedCredential) -> Result<Request> {
    signed.verify_signature(candidate.key())?;
    let request: Request = signed.decode()?;
    if let Some(route) = &request.delivery {
        route.validate()?;
    }
    record::hex::<16>(&request.nonce)?;
    if request.v != 1
        || request.kind != "space.join.shared"
        || request.issuer_identity != candidate.identity()
        || request.issuer_credential != candidate.id()
        || !name_valid(&request.name)
    {
        return Err(RecordError::Authority);
    }
    Ok(request)
}
pub fn contact(
    candidate: &VerifiedCredential,
    key: &SigningKey,
    name: &str,
    expires_at: u64,
) -> Result<SignedRecord> {
    if candidate.key() != &key.verifying_key() || !name_valid(name) {
        return Err(RecordError::Authority);
    }
    let card = Contact {
        wake: None,
        v: 1,
        kind: "identity.contact".into(),
        nonce: record::random_hex::<16>()?,
        issuer_identity: candidate.identity(),
        issuer_credential: candidate.id(),
        name: name.into(),
        expires_at,
    };
    SignedRecord::sign(
        &serde_json::to_vec(&card).map_err(|_| RecordError::Json)?,
        key,
    )
}
pub fn verify_contact(
    signed: &SignedRecord,
    candidate: &VerifiedCredential,
    now: u64,
) -> Result<Contact> {
    signed.verify_signature(candidate.key())?;
    let card: Contact = signed.decode()?;
    record::hex::<16>(&card.nonce)?;
    if card.v != 1
        || card.kind != "identity.contact"
        || card.issuer_identity != candidate.identity()
        || card.issuer_credential != candidate.id()
        || !name_valid(&card.name)
        || card.expires_at <= now
    {
        return Err(RecordError::Authority);
    }
    Ok(card)
}

pub struct Approval {
    pub offer: SignedRecord,
    pub request: SignedRecord,
    pub credential: VerifiedCredential,
    pub confirmed_identity: IdentityId,
    pub capabilities: Vec<Capability>,
}

pub async fn approve(
    authority: &mut Authority,
    store: &ClientStore,
    approval: Approval,
    key: &SigningKey,
    own: &age::x25519::Identity,
    now: LocalTime,
) -> std::result::Result<ConfigAdmission, StoreError> {
    let invalid = || StoreError::InvalidInput("invalid shared invitation or request");
    let offer = verify_offer(
        &approval.offer,
        authority.controller(),
        now.as_millis() as u64,
    )
    .map_err(|_| invalid())?;
    let request = verify_request(&approval.request, &approval.credential).map_err(|_| invalid())?;
    if offer.space_id != authority.space()
        || offer.stream_id != authority.stream()
        || authority
            .config(offer.base_config_id)
            .map_err(|_| invalid())?
            .controller_credential_id
            != authority.controller().id()
        || request.invite_id != approval.offer.id()
        || (!offer.invitees.is_empty() && !offer.invitees.contains(&approval.credential.identity()))
        || !approval
            .capabilities
            .iter()
            .all(|cap| offer.capabilities.contains(cap))
    {
        return Err(invalid());
    }
    // Single-use offers consume the offer ID. Shared offers consume the signed
    // request ID instead, atomically with membership. Kinds domain-separate those
    // record IDs; existing v1 invitation consumption remains untouched.
    let use_id = if offer.reusable {
        approval.request.id()
    } else {
        approval.offer.id()
    };
    enroll(
        authority,
        store,
        Enrollment {
            credential: approval.credential,
            confirmed_identity: approval.confirmed_identity,
            capabilities: approval.capabilities,
            proof: approval.request.id(),
            consume: Some((use_id, approval.request.id())),
        },
        key,
        own,
        now,
    )
    .await
}

pub(crate) struct Enrollment {
    pub credential: VerifiedCredential,
    pub confirmed_identity: IdentityId,
    pub capabilities: Vec<Capability>,
    pub proof: RecordId,
    pub consume: Option<(RecordId, RecordId)>,
}
pub(crate) async fn enroll(
    authority: &mut Authority,
    store: &ClientStore,
    enrollment: Enrollment,
    key: &SigningKey,
    own: &age::x25519::Identity,
    now: LocalTime,
) -> std::result::Result<ConfigAdmission, StoreError> {
    let invalid = || StoreError::InvalidInput("invalid membership approval");
    if authority.is_forked()
        || authority.controller().key() != &key.verifying_key()
        || enrollment.confirmed_identity != enrollment.credential.identity()
        || !valid_capabilities(&enrollment.capabilities)
    {
        return Err(invalid());
    }
    let mut next = authority.clone();
    next.add_credential(enrollment.credential.clone());
    let mut config = next.head().map_err(|_| invalid())?.clone();
    if config
        .members
        .iter()
        .any(|m| m.identity_id == enrollment.confirmed_identity)
    {
        return Err(StoreError::InvalidInput(
            "identity already enrolled; use explicit device enrollment",
        ));
    }
    config.members.push(Member {
        identity_id: enrollment.confirmed_identity,
        identity_type: "HUMAN".into(),
        root_public_key: enrollment.credential.record().body()["root_public_key"]
            .as_str()
            .ok_or_else(invalid)?
            .into(),
        capabilities: enrollment.capabilities,
        credential_ids: vec![enrollment.credential.id()],
        external: true,
    });
    config.members.sort_by_key(|m| m.identity_id);
    config.sequence += 1;
    config.recovery = None;
    config.previous_config_id = next.head_id();
    config.nonce = record::random_hex::<16>().map_err(|_| invalid())?;
    config.action = ConfigAction {
        operation: "invite.approved".into(),
        actor_identity: authority.controller().identity(),
        request_record_id: Some(enrollment.proof),
    };
    let signed = config.sign(key).map_err(|_| invalid())?;
    let outcome = if let Some(consumption) = enrollment.consume {
        next.commit_invited_update(store, signed, own, now, consumption)
            .await?
    } else {
        next.commit_update(store, signed, own, now).await?
    };
    *authority = next;
    Ok(outcome)
}

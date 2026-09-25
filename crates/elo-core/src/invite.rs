//! Signed local-file invitations with explicit fingerprint approval. No URL grants READ.
pub mod shared;
use crate::{
    authority::{Authority, Capability, ConfigAction, ConfigAdmission, Member},
    identity::VerifiedCredential,
    ids::{IdentityId, RecordId, SpaceId, StreamId},
    record::{self, RecordError, Result, SignedRecord},
    store::{ClientStore, LocalTime, StoreError},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub expected_config_id: RecordId,
    pub controller_credential_id: RecordId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub invite_id: RecordId,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
}
pub fn create(authority: &Authority, key: &SigningKey) -> Result<SignedRecord> {
    if authority.is_forked() || authority.controller().key() != &key.verifying_key() {
        return Err(RecordError::Authority);
    }
    let body = Invitation {
        v: 1,
        kind: "space.invitation".into(),
        nonce: record::random_hex::<16>()?,
        space_id: authority.space(),
        stream_id: authority.stream(),
        expected_config_id: authority.head_id().ok_or(RecordError::Authority)?,
        controller_credential_id: authority.controller().id(),
    };
    SignedRecord::sign(
        &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
        key,
    )
}
pub fn request(
    invite: &SignedRecord,
    controller: &VerifiedCredential,
    candidate: &VerifiedCredential,
    key: &SigningKey,
) -> Result<SignedRecord> {
    invite.verify_signature(controller.key())?;
    let body: Invitation = invite.decode()?;
    validate(&body)?;
    if body.controller_credential_id != controller.id() || candidate.key() != &key.verifying_key() {
        return Err(RecordError::Authority);
    }
    let request = JoinRequest {
        v: 1,
        kind: "space.join.requested".into(),
        nonce: record::random_hex::<16>()?,
        invite_id: invite.id(),
        issuer_identity: candidate.identity(),
        issuer_credential: candidate.id(),
    };
    SignedRecord::sign(
        &serde_json::to_vec(&request).map_err(|_| RecordError::Json)?,
        key,
    )
}
fn validate(body: &Invitation) -> Result<()> {
    record::hex::<16>(&body.nonce)?;
    if body.v != 1 || body.kind != "space.invitation" {
        return Err(RecordError::Unsupported);
    }
    Ok(())
}
pub struct CandidateApproval {
    pub invitation: SignedRecord,
    pub request: SignedRecord,
    pub credential: VerifiedCredential,
    pub confirmed_identity: IdentityId,
    pub capabilities: Vec<Capability>,
}
pub async fn approve(
    authority: &mut Authority,
    store: &ClientStore,
    approval: CandidateApproval,
    key: &SigningKey,
    own_identity: &dyn crate::crypto::DecryptionIdentity,
    now: LocalTime,
) -> std::result::Result<ConfigAdmission, StoreError> {
    let invalid =
        || StoreError::InvalidInput("invalid invitation, proof or fingerprint confirmation");
    approval
        .invitation
        .verify_signature(authority.controller().key())
        .map_err(|_| invalid())?;
    let invite: Invitation = approval.invitation.decode().map_err(|_| invalid())?;
    validate(&invite).map_err(|_| invalid())?;
    let request: JoinRequest = approval.request.decode().map_err(|_| invalid())?;
    record::hex::<16>(&request.nonce).map_err(|_| invalid())?;
    approval
        .request
        .verify_signature(approval.credential.key())
        .map_err(|_| invalid())?;
    if authority.is_forked()
        || authority.controller().key() != &key.verifying_key()
        || invite.space_id != authority.space()
        || invite.stream_id != authority.stream()
        || Some(invite.expected_config_id) != authority.head_id()
        || invite.controller_credential_id != authority.controller().id()
        || request.v != 1
        || request.kind != "space.join.requested"
        || request.invite_id != approval.invitation.id()
        || request.issuer_identity != approval.credential.identity()
        || request.issuer_credential != approval.credential.id()
        || approval.confirmed_identity != approval.credential.identity()
    {
        return Err(invalid());
    }
    let mut next = authority.clone();
    next.add_credential(approval.credential.clone());
    let mut config = next.head().map_err(|_| invalid())?.clone();
    if config
        .members
        .iter()
        .any(|m| m.identity_id == approval.confirmed_identity)
    {
        return Err(StoreError::InvalidInput(
            "identity already enrolled; use explicit device enrollment",
        ));
    }
    config.members.push(Member {
        identity_id: approval.confirmed_identity,
        identity_type: "HUMAN".into(),
        root_public_key: approval.credential.record().body()["root_public_key"]
            .as_str()
            .ok_or_else(invalid)?
            .into(),
        capabilities: approval.capabilities,
        credential_ids: vec![approval.credential.id()],
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
        request_record_id: Some(approval.request.id()),
    };
    let signed = config.sign(key).map_err(|_| invalid())?;
    let result = next
        .commit_invited_update(
            store,
            signed,
            own_identity,
            now,
            (approval.invitation.id(), approval.request.id()),
        )
        .await?;
    *authority = next;
    Ok(result)
}

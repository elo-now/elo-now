//! Owner-verified admission intent. A hosting response cannot authorize readers.
use crate::{
    app::{Result, space_host, team},
    authority::{Authority, Capability},
    identity::{DeviceRevocation, VerifiedCredential},
    ids::{IdentityId, RecordId},
    public_space::{
        AdminEvidence,
        roles::{RoleMember, Roles},
    },
    record::{self, SignedRecord},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

const MAX_JOURNAL: usize = 4096;
const MAX_CONTACT: usize = 1024 * 1024;

pub struct ValidatedEnrollment {
    pub credential: VerifiedCredential,
    pub request: team::EnrollmentRequest,
}
pub struct ValidatedOwnerPolicy {
    pub pending: Vec<ValidatedEnrollment>,
    pub owner_identities: BTreeSet<IdentityId>,
    pub removed: BTreeSet<IdentityId>,
    pub revoked: BTreeSet<RecordId>,
    pub commitment: Option<RecordId>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    credential: RecordId,
    request: team::EnrollmentRequest,
    authorization: Option<AdminEvidence>,
    invitation_authorization: Option<AdminEvidence>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    v: u8,
    kind: String,
    space: crate::ids::SpaceId,
    nonce: String,
    issued: u64,
    action: String,
    body: Value,
}
struct Invitation {
    evidence: RecordId,
    expires: u64,
    approval: bool,
    revoked: bool,
}
fn field<'a>(body: &'a Value, name: &str) -> Result<&'a str> {
    body[name]
        .as_str()
        .ok_or_else(|| "Missing admission proof field.".into())
}
fn signed(encoded: &str) -> Result<SignedRecord> {
    if encoded.len() > MAX_CONTACT * 2 {
        return Err("Admission proof is too large.".into());
    }
    Ok(SignedRecord::parse(&STANDARD.decode(encoded)?)?)
}
fn credential(encoded: &str) -> Result<VerifiedCredential> {
    let record = signed(encoded)?;
    let root = VerifyingKey::from_bytes(&record::hex(field(record.body(), "root_public_key")?)?)?;
    Ok(VerifiedCredential::verify(record.bytes(), &root)?)
}
fn evidence(value: &AdminEvidence) -> Result<(SignedRecord, VerifiedCredential)> {
    let credential = credential(&value.credential)?;
    let record = signed(&value.record)?;
    if record.body()["kind"] == "device.revoked" {
        if DeviceRevocation::verify(&record)?.id() != credential.id() {
            return Err("Device revocation evidence changed its target.".into());
        }
    } else {
        record.verify_signature(credential.key())?;
    }
    Ok((record, credential))
}

/// Commit both the ordered intents and their exact authenticated device proofs.
/// Empty history is represented by None, including the initial configuration.
pub fn journal_commitment(journal: &[AdminEvidence]) -> Result<Option<RecordId>> {
    if journal.len() > MAX_JOURNAL {
        return Err("Space administration history is too large.".into());
    }
    if journal.is_empty() {
        return Ok(None);
    }
    let mut hash = Sha256::new();
    hash.update(b"elo.owner-general.admin-journal/v1\0");
    hash.update((journal.len() as u64).to_be_bytes());
    let mut seen = BTreeSet::new();
    for item in journal {
        let (record, credential) = evidence(item)?;
        if !seen.insert(record.id()) {
            return Err("Duplicate Space administration intent.".into());
        }
        hash.update(record.id().as_bytes());
        hash.update(credential.id().as_bytes());
    }
    Ok(Some(RecordId::from_bytes(hash.finalize().into())))
}

fn enrolled_at(authority: &Authority, head: RecordId, id: RecordId) -> Result<bool> {
    Ok(authority
        .config(head)?
        .members
        .iter()
        .any(|member| member.credential_ids.contains(&id)))
}
fn enrolled_ever(authority: &Authority, id: RecordId) -> Result<bool> {
    let mut cursor = authority.head_id();
    while let Some(head) = cursor {
        if enrolled_at(authority, head, id)? {
            return Ok(true);
        }
        cursor = authority.config(head)?.previous_config_id;
    }
    Ok(false)
}
fn removed_since(authority: &Authority, head: RecordId, id: RecordId) -> Result<bool> {
    let mut cursor = authority.head_id();
    let mut later_absent = false;
    while let Some(next) = cursor {
        let config = authority.config(next)?;
        let present = config
            .members
            .iter()
            .any(|member| member.credential_ids.contains(&id));
        if present && later_absent {
            return Ok(true);
        }
        later_absent |= !present;
        if next == head {
            return Ok(false);
        }
        cursor = config.previous_config_id;
    }
    Err("Admission intent references an unknown configuration.".into())
}
fn enrollment(
    authority: &Authority,
    pending: &Pending,
    current: u64,
) -> Result<VerifiedCredential> {
    let encoded = pending
        .request
        .contact
        .strip_prefix("elo://exchange/v1#")
        .ok_or("Invalid admission contact.")?;
    if encoded.len() > MAX_CONTACT * 2 {
        return Err("Admission contact is too large.".into());
    }
    let compressed = URL_SAFE_NO_PAD.decode(encoded)?;
    let mut plain = Vec::new();
    flate2::read::ZlibDecoder::new(compressed.as_slice())
        .take(MAX_CONTACT as u64 + 1)
        .read_to_end(&mut plain)?;
    let packet = record::strict_json(&plain, MAX_CONTACT)?;
    if packet["kind"] != "Contact" || packet.as_object().is_none_or(|object| object.len() != 3) {
        return Err("Invalid admission contact.".into());
    }
    let credential = credential(field(&packet, "credential")?)?;
    let card = signed(field(&packet, "card")?)?;
    crate::invite::shared::verify_contact(&card, &credential, current)?;
    let proof = signed(&pending.request.proof)?;
    proof.verify_signature(credential.key())?;
    let body = proof.body();
    if pending.credential != credential.id()
        || pending.request.v != 1
        || body["v"] != 1
        || body["kind"] != "team.join"
        || body["space"] != json!(authority.space())
        || body["stream"] != json!(authority.stream())
        || body["controller"] != json!(authority.initial_controller().id())
        || body["contact"] != json!(card.id())
        || body.as_object().is_none_or(|object| object.len() != 6)
    {
        return Err("Admission request belongs to another device or Space.".into());
    }
    Ok(credential)
}

/// Replay only device-signed intent extending the policy committed by the
/// locally verified General head. Ignore transport-supplied authorization claims.
pub fn verify_owner_policy(
    authority: &Authority,
    status: &Value,
    current: u64,
) -> Result<ValidatedOwnerPolicy> {
    if !authority.is_owner_managed() || authority.is_forked() {
        return Err("Owner-managed General is unavailable.".into());
    }
    let head = authority
        .head_id()
        .ok_or("Missing General configuration.")?;
    if status["head"] != json!(head) {
        return Err("General changed while verifying admission.".into());
    }
    let creation: AdminEvidence = serde_json::from_value(status["creation"].clone())?;
    let (creation_record, creator) = evidence(&creation)?;
    let creation_command: space_host::CreateCommand = creation_record.decode()?;
    if creation_command.kind != "space.create" {
        return Err("Invalid Space creation intent.".into());
    }
    let initial = space_host::verify_creation_authority(&creation_command, &creator)?
        .ok_or("Missing owner creation intent.")?;
    if initial.genesis().bytes() != authority.genesis().bytes()
        || initial.stream() != authority.stream()
    {
        return Err("Space creation intent belongs to another General.".into());
    }
    let committed: Vec<AdminEvidence> =
        serde_json::from_value(status["committed_journal"].clone())?;
    let journal: Vec<AdminEvidence> = serde_json::from_value(status["journal"].clone())?;
    if journal.len() < committed.len()
        || journal_commitment(&committed)? != authority.head()?.action.request_record_id
        || journal_commitment(&journal[..committed.len()])? != journal_commitment(&committed)?
    {
        return Err("Space administration history was omitted or changed.".into());
    }
    let commitment = journal_commitment(&journal)?;
    let primary = authority.primary_owner_identity()?;
    if primary != creator.identity() {
        return Err("Space primary owner does not match its signed creation.".into());
    }
    let mut roles = Roles::bootstrap(&[primary])?;
    let mut invitations = BTreeMap::from([(
        creation_command.request_id.clone(),
        Invitation {
            evidence: creation_record.id(),
            expires: creation_command.issued.saturating_add(86_400_000),
            approval: creation_command.require_approval,
            revoked: false,
        },
    )]);
    let mut approvals = BTreeMap::<RecordId, (usize, bool, RecordId, RecordId)>::new();
    let mut denied = BTreeSet::<(RecordId, RecordId)>::new();
    let mut removals = BTreeMap::<IdentityId, (usize, Option<RecordId>)>::new();
    let mut revoked = BTreeSet::new();
    let mut checked_boundary = false;
    for (index, item) in journal.iter().enumerate() {
        if index == committed.len() {
            check_committed_owners(authority, &roles)?;
            checked_boundary = true;
        }
        let (record, signer) = evidence(item)?;
        if record.body()["kind"] == "device.revoked" {
            if !(if index < committed.len() {
                enrolled_ever(authority, signer.id())?
            } else {
                enrolled_at(authority, head, signer.id())?
            }) {
                return Err("Only an admitted device can be revoked from this Space.".into());
            }
            if let Some(encoded) = record.body()["authorizing_device"].as_str() {
                let authorizer = credential(encoded)?;
                let admitted = if index < committed.len() {
                    enrolled_ever(authority, authorizer.id())?
                } else {
                    enrolled_at(authority, head, authorizer.id())?
                };
                if !admitted || revoked.contains(&authorizer.id()) {
                    return Err("A retired device cannot authorize a new revocation.".into());
                }
            }
            revoked.insert(signer.id());
            continue;
        }
        if record.body()["kind"] == "account.deletion" {
            let command: crate::app::account_deletion::Command = record.decode()?;
            let mut endpoint = reqwest::Url::parse(&creation_command.host)?;
            endpoint.set_path(crate::app::account_deletion::PATH);
            record::hex::<16>(&command.nonce)?;
            if command.v != 1
                || command.action != crate::app::account_deletion::Action::Submit
                || !command.confirmed
                || command.endpoint != endpoint.as_str()
                || !(if index < committed.len() {
                    enrolled_ever(authority, signer.id())?
                } else {
                    enrolled_at(authority, head, signer.id())?
                })
                || revoked.contains(&signer.id())
                || roles.is_owner(signer.identity())
            {
                return Err("Invalid signed account deletion intent.".into());
            }
            removals.insert(signer.identity(), (index, None));
            roles.retire_member(signer.identity())?;
            continue;
        }
        let command: Command = record.decode()?;
        let authorization_head: RecordId = field(&command.body, "authority_head")?.parse()?;
        record::hex::<16>(&command.nonce)?;
        if command.v != 1
            || command.kind != "space.command"
            || command.space != authority.space()
            || !authority.proves_config_ancestor(authorization_head)
            || (index >= committed.len() && authorization_head != head)
            || !enrolled_at(authority, authorization_head, signer.id())?
            || revoked.contains(&signer.id())
        {
            return Err("Space administration intent has a stale or unauthorized device.".into());
        }
        let config = authority.config(authorization_head)?;
        let owner =
            config.owner_credential_ids.contains(&signer.id()) && roles.is_owner(signer.identity());
        match command.action.as_str() {
            "invite" if owner => {
                let id = field(&command.body, "id")?.to_owned();
                record::hex::<16>(&id)?;
                record::hex::<32>(field(&command.body, "token")?)?;
                let lifetime = command.body["lifetime"]
                    .as_u64()
                    .filter(|v| crate::app::space_service::LIFETIMES.contains(v))
                    .ok_or("Invalid signed invitation lifetime.")?;
                let approval = command.body["require_approval"]
                    .as_bool()
                    .ok_or("Missing signed invitation policy.")?;
                if invitations
                    .insert(
                        id,
                        Invitation {
                            evidence: record.id(),
                            expires: command.issued.saturating_add(lifetime.saturating_mul(1000)),
                            approval,
                            revoked: false,
                        },
                    )
                    .is_some()
                {
                    return Err("A signed invitation cannot be replaced.".into());
                }
            }
            "revoke" if owner => {
                invitations
                    .get_mut(field(&command.body, "id")?)
                    .ok_or("Unknown signed invitation.")?
                    .revoked = true;
            }
            "decide" if owner => {
                let id: RecordId = field(&command.body, "id")?.parse()?;
                let approve = command.body["approve"]
                    .as_bool()
                    .ok_or("Missing signed admission decision.")?;
                // Commands sharing a head do not carry an ordered journal
                // predecessor. A host cannot turn a denial into an approval
                // by rearranging the uncommitted suffix.
                if !approve {
                    denied.insert((id, authorization_head));
                }
                approvals.insert(id, (index, approve, authorization_head, record.id()));
            }
            "role_change" if owner => {
                replay_role(
                    authority,
                    &mut roles,
                    &mut removals,
                    (index, authorization_head),
                    &command,
                    &record,
                    &signer,
                )?;
            }
            "role_decide" => {
                replay_role(
                    authority,
                    &mut roles,
                    &mut removals,
                    (index, authorization_head),
                    &command,
                    &record,
                    &signer,
                )?;
            }
            "device_revoke" => {
                let proof = signed(field(&command.body, "proof")?)?;
                let target = DeviceRevocation::verify_request(&proof, &signer)?;
                if !enrolled_at(authority, authorization_head, target.id())? {
                    return Err("Only an admitted device can be revoked from this Space.".into());
                }
                revoked.insert(target.id());
            }
            _ => return Err("Unsupported or unauthorized Space administration intent.".into()),
        }
    }
    if !checked_boundary {
        check_committed_owners(authority, &roles)?;
    }
    // Once an approved device has been admitted, the service can remove its
    // pending request. The signed journal must still preserve the admission's
    // effect on an older identity removal.
    for (id, (index, approved, approved_head, _)) in &approvals {
        if !approved
            || denied.contains(&(*id, *approved_head))
            || revoked.contains(id)
            || !enrolled_at(authority, head, *id)?
            || removed_since(authority, *approved_head, *id)?
        {
            continue;
        }
        let identity = authority.credential(*id)?.identity();
        if removals
            .get(&identity)
            .is_some_and(|(removal, removal_head)| {
                index > removal && removal_head.is_some_and(|head| head != *approved_head)
            })
        {
            removals.remove(&identity);
        }
    }
    let pending = status["pending"]
        .as_array()
        .ok_or("Missing pending admission list.")?;
    if pending.len() > record::MAX_CHAT_CREDENTIALS {
        return Err("Too many pending admissions.".into());
    }
    let mut seen = BTreeSet::new();
    let mut eligible = Vec::new();
    for raw in pending {
        let Ok(item) = serde_json::from_value::<Pending>(raw.clone()) else {
            continue;
        };
        if !seen.insert(item.credential) {
            continue;
        }
        let Ok(candidate) = enrollment(authority, &item, current) else {
            continue;
        };
        if revoked.contains(&candidate.id()) {
            continue;
        }
        let explicitly_approved = match (approvals.get(&candidate.id()), &item.authorization) {
            (Some((index, true, approved_head, record_id)), Some(proof)) => {
                evidence(proof).is_ok_and(|(record, _)| record.id() == *record_id)
                    && !denied.contains(&(candidate.id(), *approved_head))
                    && removals
                        .get(&candidate.identity())
                        .is_none_or(|(removal, removal_head)| {
                            index > removal
                                && removal_head.is_some_and(|head| head != *approved_head)
                        })
                    && !removed_since(authority, *approved_head, candidate.id())?
            }
            _ => false,
        };
        let currently_admitted = enrolled_at(authority, head, candidate.id())?;
        let explicitly_denied =
            approvals
                .get(&candidate.id())
                .is_some_and(|(_, approved, approved_head, _)| {
                    !approved || denied.contains(&(candidate.id(), *approved_head))
                });
        if explicitly_denied && !currently_admitted {
            continue;
        }
        let previously_admitted = enrolled_ever(authority, candidate.id())?;
        let companion = candidate.authorizing_device().is_some_and(|parent| {
            !revoked.contains(&parent)
                && authority.head().is_ok_and(|config| {
                    config.members.iter().any(|m| {
                        m.identity_id == candidate.identity() && m.credential_ids.contains(&parent)
                    })
                })
        });
        let open_invitation = if let Some(proof) = &item.invitation_authorization {
            evidence(proof).is_ok_and(|(record, _)| {
                invitations.values().any(|invite| {
                    invite.evidence == record.id()
                        && !invite.approval
                        && !invite.revoked
                        && invite.expires > current
                })
            })
        } else {
            false
        };
        if !currently_admitted
            && !explicitly_approved
            && !(!removals.contains_key(&candidate.identity())
                && !previously_admitted
                && (companion || open_invitation))
        {
            continue;
        }
        if explicitly_approved {
            removals.remove(&candidate.identity());
        }
        eligible.push(ValidatedEnrollment {
            credential: candidate,
            request: item.request,
        });
    }
    let removed = removals.into_keys().collect();
    Ok(ValidatedOwnerPolicy {
        pending: eligible,
        owner_identities: roles.owner_identities(),
        removed,
        revoked,
        commitment,
    })
}

fn check_committed_owners(authority: &Authority, roles: &Roles) -> Result<()> {
    let current = authority
        .head()?
        .members
        .iter()
        .filter(|m| m.capabilities.contains(&Capability::Manage))
        .map(|m| m.identity_id)
        .collect::<BTreeSet<_>>();
    if current != roles.owner_identities() {
        return Err("Committed Space roles do not match the signed General configuration.".into());
    }
    Ok(())
}
fn replay_role(
    authority: &Authority,
    roles: &mut Roles,
    removals: &mut BTreeMap<IdentityId, (usize, Option<RecordId>)>,
    (index, head): (usize, RecordId),
    command: &Command,
    record: &SignedRecord,
    signer: &VerifiedCredential,
) -> Result<()> {
    let members = authority
        .config(head)?
        .members
        .iter()
        .map(|member| RoleMember {
            identity: member.identity_id,
            name: member.identity_id.to_string(),
            role: roles.role(member.identity_id).into(),
        })
        .collect::<Vec<_>>();
    let result = roles.apply_with_id(
        signer.identity(),
        &command.action,
        &command.body,
        &members,
        command.issued,
        &record.id().to_string(),
    )?;
    if let Some(identity) = result["removed_identity"].as_str() {
        let identity = identity.parse()?;
        removals.insert(identity, (index, Some(head)));
        roles.retire_member(identity)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::{ConfigAction, Member},
        vault::Session,
    };
    use std::io::Write;

    fn fixture() -> (Session, Authority, AdminEvidence) {
        let (owner, command) = space_host::tests::owner_creation();
        let authority = space_host::verify_creation_authority(&command, owner.credential())
            .unwrap()
            .unwrap();
        let creation = AdminEvidence {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), owner.signing_key())
                    .unwrap()
                    .bytes(),
            ),
            credential: STANDARD.encode(owner.credential().record().bytes()),
        };
        (owner, authority, creation)
    }
    fn intent(
        authority: &Authority,
        signer: &Session,
        action: &str,
        mut body: Value,
    ) -> AdminEvidence {
        body["authority_head"] = json!(authority.head_id().unwrap());
        let command = json!({"v":1,"kind":"space.command","space":authority.space(),"nonce":record::random_hex::<16>().unwrap(),"issued":100,"action":action,"body":body});
        AdminEvidence {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), signer.signing_key())
                    .unwrap()
                    .bytes(),
            ),
            credential: STANDARD.encode(signer.credential().record().bytes()),
        }
    }
    fn status(
        authority: &Authority,
        creation: &AdminEvidence,
        committed: &[AdminEvidence],
        journal: &[AdminEvidence],
        pending: Vec<Value>,
    ) -> Value {
        json!({"head":authority.head_id(),"creation":creation,"committed_journal":committed,"journal":journal,"pending":pending,"revocation_proofs":[]})
    }
    fn pending(
        authority: &Authority,
        candidate: &Session,
        approval: Option<&AdminEvidence>,
        invitation: Option<&AdminEvidence>,
    ) -> Value {
        let contact = crate::invite::shared::contact(
            candidate.credential(),
            candidate.signing_key(),
            "Guest",
            100_000,
        )
        .unwrap();
        let packet = json!({"kind":"Contact","card":STANDARD.encode(contact.bytes()),"credential":STANDARD.encode(candidate.credential().record().bytes())});
        let mut compressed =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        compressed
            .write_all(&serde_json::to_vec(&packet).unwrap())
            .unwrap();
        let contact_link = format!(
            "elo://exchange/v1#{}",
            URL_SAFE_NO_PAD.encode(compressed.finish().unwrap())
        );
        let proof = json!({"v":1,"kind":"team.join","space":authority.space(),"stream":authority.stream(),"controller":authority.initial_controller().id(),"contact":contact.id()});
        let request = team::EnrollmentRequest {
            v: 1,
            contact: contact_link,
            proof: STANDARD.encode(
                SignedRecord::sign(
                    &serde_json::to_vec(&proof).unwrap(),
                    candidate.signing_key(),
                )
                .unwrap()
                .bytes(),
            ),
        };
        json!({"credential":candidate.credential().id(),"request":request,"authorization":approval,"invitation_authorization":invitation})
    }
    fn commit(
        authority: &mut Authority,
        signer: &Session,
        journal: &[AdminEvidence],
        members: Option<Vec<Member>>,
    ) {
        let mut config = authority.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = authority.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.controller_credential_id = signer.credential().id();
        if let Some(members) = members {
            config.members = members;
        }
        config.members.sort_by_key(|m| m.identity_id);
        config.owner_credential_ids = config
            .members
            .iter()
            .filter(|m| m.capabilities.contains(&Capability::Manage))
            .flat_map(|m| m.credential_ids.iter().copied())
            .collect();
        config.owner_credential_ids.sort();
        config.action = ConfigAction {
            operation: "replace".into(),
            actor_identity: signer.identity_id(),
            request_record_id: journal_commitment(journal).unwrap(),
        };
        authority
            .apply_config(config.sign(signer.signing_key()).unwrap())
            .unwrap();
    }
    fn guest_member(guest: &Session) -> Member {
        Member {
            identity_id: guest.identity_id(),
            identity_type: "HUMAN".into(),
            root_public_key: field(guest.credential().record().body(), "root_public_key")
                .unwrap()
                .into(),
            capabilities: vec![Capability::Read, Capability::Post],
            credential_ids: vec![guest.credential().id()],
            external: true,
        }
    }

    #[test]
    fn committed_history_rejects_omission_reordering_replay_and_restoring_a_revoked_invitation() {
        let (owner, mut authority, creation) = fixture();
        let guest = Session::create().unwrap().0;
        let invite = intent(
            &authority,
            &owner,
            "invite",
            json!({"id":"ab".repeat(16),"token":"cd".repeat(32),"lifetime":600,"require_approval":false}),
        );
        // The bootstrap ID is already reserved by creation; use a distinct one.
        let invite = {
            let (r, _) = evidence(&invite).unwrap();
            let mut body = r.body()["body"].clone();
            body["id"] = "cd".repeat(16).into();
            intent(&authority, &owner, "invite", body)
        };
        let revoke = intent(&authority, &owner, "revoke", json!({"id":"cd".repeat(16)}));
        let journal = vec![invite.clone(), revoke];
        let response = status(
            &authority,
            &creation,
            &[],
            &journal,
            vec![pending(&authority, &guest, None, Some(&invite))],
        );
        assert!(
            verify_owner_policy(&authority, &response, 1000)
                .unwrap()
                .pending
                .is_empty()
        );
        commit(&mut authority, &owner, &journal, None);
        verify_owner_policy(
            &authority,
            &status(&authority, &creation, &journal, &journal, vec![]),
            1000,
        )
        .unwrap();
        let omitted = vec![invite.clone()];
        assert!(
            verify_owner_policy(
                &authority,
                &status(&authority, &creation, &omitted, &omitted, vec![]),
                1000
            )
            .is_err()
        );
        let mut reordered = journal.clone();
        reordered.reverse();
        assert!(
            verify_owner_policy(
                &authority,
                &status(&authority, &creation, &reordered, &reordered, vec![]),
                1000
            )
            .is_err()
        );
        assert!(
            verify_owner_policy(
                &authority,
                &status(&authority, &creation, &journal, &omitted, vec![]),
                1000
            )
            .is_err()
        );
        let mut replay = journal.clone();
        replay.push(invite);
        assert!(
            verify_owner_policy(
                &authority,
                &status(&authority, &creation, &journal, &replay, vec![]),
                1000
            )
            .is_err()
        );
    }

    #[test]
    fn exact_owner_approval_admits_one_device_but_cannot_resurrect_it_after_removal() {
        let (owner, mut authority, creation) = fixture();
        let guest = Session::create().unwrap().0;
        let approval = intent(
            &authority,
            &owner,
            "decide",
            json!({"id":guest.credential().id(),"approve":true}),
        );
        let journal = vec![approval.clone()];
        let mut response = status(
            &authority,
            &creation,
            &[],
            &journal,
            vec![
                json!({"malformed":true}),
                pending(&authority, &guest, Some(&approval), None),
            ],
        );
        response["owner_identities"] = json!([guest.identity_id()]);
        response["revoked"] = json!([owner.credential().id()]);
        response["removed"] = json!([owner.identity_id()]);
        let verified = verify_owner_policy(&authority, &response, 1000).unwrap();
        assert_eq!(verified.pending.len(), 1);
        assert_eq!(
            verified.owner_identities,
            BTreeSet::from([owner.identity_id()])
        );
        assert!(verified.revoked.is_empty() && verified.removed.is_empty());
        authority.add_credential(guest.credential().clone());
        let mut members = authority.head().unwrap().members.clone();
        members.push(guest_member(&guest));
        commit(&mut authority, &owner, &journal, Some(members));
        let members = authority
            .head()
            .unwrap()
            .members
            .iter()
            .filter(|m| m.identity_id != guest.identity_id())
            .cloned()
            .collect();
        commit(&mut authority, &owner, &journal, Some(members));
        let response = status(
            &authority,
            &creation,
            &journal,
            &journal,
            vec![pending(&authority, &guest, Some(&approval), None)],
        );
        assert!(
            verify_owner_policy(&authority, &response, 1000)
                .unwrap()
                .pending
                .is_empty()
        );
        let response = status(
            &authority,
            &creation,
            &journal,
            &journal,
            vec![pending(&authority, &guest, Some(&approval), None)],
        );
        assert!(
            verify_owner_policy(&authority, &response, 100_001)
                .unwrap()
                .pending
                .is_empty()
        );
    }

    #[test]
    fn role_replay_requires_primary_for_owner_changes_and_preserves_member_management() {
        let (owner, mut authority, creation) = fixture();
        let guest = Session::create().unwrap().0;
        let member = Session::create().unwrap().0;
        for session in [&guest, &member] {
            authority.add_credential(session.credential().clone());
        }
        let mut members = authority.head().unwrap().members.clone();
        members.extend([guest_member(&guest), guest_member(&member)]);
        commit(&mut authority, &owner, &[], Some(members));
        let forged = intent(
            &authority,
            &guest,
            "role_change",
            json!({"revision":0,"kind":"make_owner","target":guest.identity_id()}),
        );
        assert!(
            verify_owner_policy(
                &authority,
                &status(&authority, &creation, &[], &[forged], vec![]),
                1000
            )
            .is_err()
        );
        let promote = intent(
            &authority,
            &owner,
            "role_change",
            json!({"revision":0,"kind":"make_owner","target":guest.identity_id()}),
        );
        let committed = vec![promote];
        let mut members = authority.head().unwrap().members.clone();
        members
            .iter_mut()
            .find(|m| m.identity_id == guest.identity_id())
            .unwrap()
            .capabilities = vec![
            Capability::Read,
            Capability::Post,
            Capability::ShareHistory,
            Capability::Manage,
        ];
        commit(&mut authority, &owner, &committed, Some(members));
        let policy = verify_owner_policy(
            &authority,
            &status(&authority, &creation, &committed, &committed, vec![]),
            1000,
        )
        .unwrap();
        assert_eq!(
            policy.owner_identities,
            BTreeSet::from([owner.identity_id(), guest.identity_id()])
        );
        for (actor, kind, target) in [
            (&guest, "make_owner", member.identity_id()),
            (&guest, "remove_owner", owner.identity_id()),
            (&guest, "remove_member", guest.identity_id()),
            (&owner, "remove_member", owner.identity_id()),
            (&owner, "transfer_primary", guest.identity_id()),
        ] {
            let mut journal = committed.clone();
            journal.push(intent(
                &authority,
                actor,
                "role_change",
                json!({"revision":1,"kind":kind,"target":target}),
            ));
            assert!(
                verify_owner_policy(
                    &authority,
                    &status(&authority, &creation, &committed, &journal, vec![]),
                    1000
                )
                .is_err()
            );
        }
        let mut journal = committed.clone();
        journal.push(intent(
            &authority,
            &guest,
            "role_change",
            json!({"revision":1,"kind":"remove_member","target":member.identity_id()}),
        ));
        let policy = verify_owner_policy(
            &authority,
            &status(&authority, &creation, &committed, &journal, vec![]),
            1000,
        )
        .unwrap();
        assert!(policy.removed.contains(&member.identity_id()));
        assert_eq!(
            policy.owner_identities,
            BTreeSet::from([owner.identity_id(), guest.identity_id()])
        );
    }

    #[test]
    fn device_revocation_requires_an_active_authorizer_and_duplicate_proof_is_idempotent() {
        let (owner, mut authority, creation) = fixture();
        let companion = owner.linked_companion().unwrap();
        let invented = owner.linked_companion().unwrap();
        let invented_proof = DeviceRevocation::issue_from_device(
            owner.credential(),
            owner.signing_key(),
            invented.credential(),
        )
        .unwrap();
        for unauthorized in [
            AdminEvidence {
                record: STANDARD.encode(invented_proof.bytes()),
                credential: STANDARD.encode(invented.credential().record().bytes()),
            },
            intent(
                &authority,
                &owner,
                "device_revoke",
                json!({"proof":STANDARD.encode(invented_proof.bytes())}),
            ),
        ] {
            assert!(
                verify_owner_policy(
                    &authority,
                    &status(&authority, &creation, &[], &[unauthorized], vec![]),
                    1000,
                )
                .is_err(),
                "a minted credential alone cannot consume administration history"
            );
        }
        authority.add_credential(companion.credential().clone());
        let mut members = authority.head().unwrap().members.clone();
        members[0].credential_ids.push(companion.credential().id());
        members[0].credential_ids.sort();
        commit(&mut authority, &owner, &[], Some(members));
        let proof = DeviceRevocation::issue_from_device(
            owner.credential(),
            owner.signing_key(),
            companion.credential(),
        )
        .unwrap();
        let raw = AdminEvidence {
            record: STANDARD.encode(proof.bytes()),
            credential: STANDARD.encode(companion.credential().record().bytes()),
        };
        let request = intent(
            &authority,
            &owner,
            "device_revoke",
            json!({"proof":STANDARD.encode(proof.bytes())}),
        );
        let policy = verify_owner_policy(
            &authority,
            &status(&authority, &creation, &[], &[raw.clone(), request], vec![]),
            1000,
        )
        .unwrap();
        assert_eq!(
            policy.revoked,
            BTreeSet::from([companion.credential().id()])
        );
        let mut members = authority.head().unwrap().members.clone();
        members[0].credential_ids = vec![companion.credential().id()];
        commit(&mut authority, &companion, &[], Some(members));
        assert!(
            verify_owner_policy(
                &authority,
                &status(&authority, &creation, &[], &[raw], vec![]),
                1000
            )
            .is_err()
        );
    }

    #[test]
    fn conflicting_same_head_admission_intents_cannot_be_reordered_into_a_grant() {
        let (owner, mut authority, creation) = fixture();
        let guest = Session::create().unwrap().0;
        let approve = intent(
            &authority,
            &owner,
            "decide",
            json!({"id":guest.credential().id(),"approve":true}),
        );
        let deny = intent(
            &authority,
            &owner,
            "decide",
            json!({"id":guest.credential().id(),"approve":false}),
        );
        let open_invite = intent(
            &authority,
            &owner,
            "invite",
            json!({"id":"cd".repeat(16),"token":"cd".repeat(32),"lifetime":600,"require_approval":false}),
        );
        let open_journal = vec![open_invite.clone(), deny.clone()];
        assert!(
            verify_owner_policy(
                &authority,
                &status(
                    &authority,
                    &creation,
                    &[],
                    &open_journal,
                    vec![pending(&authority, &guest, None, Some(&open_invite))]
                ),
                1000,
            )
            .unwrap()
            .pending
            .is_empty()
        );
        for journal in [
            vec![approve.clone(), deny.clone()],
            vec![deny.clone(), approve.clone()],
        ] {
            let policy = verify_owner_policy(
                &authority,
                &status(
                    &authority,
                    &creation,
                    &[],
                    &journal,
                    vec![pending(&authority, &guest, Some(&approve), None)],
                ),
                1000,
            )
            .unwrap();
            assert!(policy.pending.is_empty());
        }
        let committed = vec![deny, approve];
        commit(&mut authority, &owner, &committed, None);
        let renewed = intent(
            &authority,
            &owner,
            "decide",
            json!({"id":guest.credential().id(),"approve":true}),
        );
        let mut journal = committed.clone();
        journal.push(renewed.clone());
        assert_eq!(
            verify_owner_policy(
                &authority,
                &status(
                    &authority,
                    &creation,
                    &committed,
                    &journal,
                    vec![pending(&authority, &guest, Some(&renewed), None)]
                ),
                1000,
            )
            .unwrap()
            .pending
            .len(),
            1
        );

        authority.add_credential(guest.credential().clone());
        let mut members = authority.head().unwrap().members.clone();
        members.push(guest_member(&guest));
        commit(&mut authority, &owner, &journal, Some(members));
        let remove = intent(
            &authority,
            &owner,
            "role_change",
            json!({"revision":0,"kind":"remove_member","target":guest.identity_id()}),
        );
        let approve = intent(
            &authority,
            &owner,
            "decide",
            json!({"id":guest.credential().id(),"approve":true}),
        );
        let committed = journal;
        for suffix in [
            vec![remove.clone(), approve.clone()],
            vec![approve.clone(), remove.clone()],
        ] {
            let mut journal = committed.clone();
            journal.extend(suffix);
            let policy = verify_owner_policy(
                &authority,
                &status(
                    &authority,
                    &creation,
                    &committed,
                    &journal,
                    vec![pending(&authority, &guest, Some(&approve), None)],
                ),
                1000,
            )
            .unwrap();
            assert!(policy.removed.contains(&guest.identity_id()));
        }
    }

    #[test]
    fn account_deletion_is_signed_by_an_active_member_and_retained_by_the_commitment() {
        let (owner, mut authority, creation) = fixture();
        let guest = Session::create().unwrap().0;
        authority.add_credential(guest.credential().clone());
        let mut members = authority.head().unwrap().members.clone();
        members.push(guest_member(&guest));
        commit(&mut authority, &owner, &[], Some(members));
        let (record, _) = evidence(&creation).unwrap();
        let command: space_host::CreateCommand = record.decode().unwrap();
        let mut endpoint = reqwest::Url::parse(&command.host).unwrap();
        endpoint.set_path(crate::app::account_deletion::PATH);
        let command = json!({"v":1,"kind":"account.deletion","endpoint":endpoint.as_str(),"nonce":"ef".repeat(16),"issued":100,"action":"submit","confirmed":true});
        let deletion = AdminEvidence {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), guest.signing_key())
                    .unwrap()
                    .bytes(),
            ),
            credential: STANDARD.encode(guest.credential().record().bytes()),
        };
        let journal = vec![deletion.clone()];
        let policy = verify_owner_policy(
            &authority,
            &status(&authority, &creation, &[], &journal, vec![]),
            1000,
        )
        .unwrap();
        assert_eq!(policy.removed, BTreeSet::from([guest.identity_id()]));
        let members = authority
            .head()
            .unwrap()
            .members
            .iter()
            .filter(|member| member.identity_id != guest.identity_id())
            .cloned()
            .collect();
        commit(&mut authority, &owner, &journal, Some(members));
        let policy = verify_owner_policy(
            &authority,
            &status(&authority, &creation, &journal, &journal, vec![]),
            1000,
        )
        .unwrap();
        assert!(policy.removed.contains(&guest.identity_id()));
        let mut forged = command;
        forged["nonce"] = "de".repeat(16).into();
        let new_deletion = AdminEvidence {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&forged).unwrap(), guest.signing_key())
                    .unwrap()
                    .bytes(),
            ),
            credential: deletion.credential,
        };
        let mut altered = journal.clone();
        altered.push(new_deletion);
        assert!(
            verify_owner_policy(
                &authority,
                &status(&authority, &creation, &journal, &altered, vec![]),
                1000
            )
            .is_err()
        );
    }

    #[test]
    fn later_explicit_readmission_survives_pruning_the_completed_pending_request() {
        let (owner, mut authority, creation) = fixture();
        let guest = Session::create().unwrap().0;
        authority.add_credential(guest.credential().clone());
        let mut members = authority.head().unwrap().members.clone();
        members.push(guest_member(&guest));
        commit(&mut authority, &owner, &[], Some(members));
        let removal = intent(
            &authority,
            &owner,
            "role_change",
            json!({"revision":0,"kind":"remove_member","target":guest.identity_id()}),
        );
        let committed = vec![removal];
        let retained = authority
            .head()
            .unwrap()
            .members
            .iter()
            .filter(|member| member.identity_id != guest.identity_id())
            .cloned()
            .collect();
        commit(&mut authority, &owner, &committed, Some(retained));
        let approve = intent(
            &authority,
            &owner,
            "decide",
            json!({"id":guest.credential().id(),"approve":true}),
        );
        let mut journal = committed.clone();
        journal.push(approve.clone());
        let policy = verify_owner_policy(
            &authority,
            &status(
                &authority,
                &creation,
                &committed,
                &journal,
                vec![pending(&authority, &guest, Some(&approve), None)],
            ),
            1000,
        )
        .unwrap();
        assert_eq!(policy.pending.len(), 1);
        assert!(policy.removed.is_empty());
        let mut members = authority.head().unwrap().members.clone();
        members.push(guest_member(&guest));
        commit(&mut authority, &owner, &journal, Some(members));
        let policy = verify_owner_policy(
            &authority,
            &status(&authority, &creation, &journal, &journal, vec![]),
            1000,
        )
        .unwrap();
        assert!(policy.removed.is_empty());
    }
}

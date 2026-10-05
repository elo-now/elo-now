use super::*;
use crate::{identity::DeviceCredential, invite::shared};

struct Device {
    root: SigningKey,
    key: SigningKey,
    credential: VerifiedCredential,
}

fn device(root_seed: u8, device_seed: u8) -> Device {
    let root = SigningKey::from_bytes(&[root_seed; 32]);
    let key = SigningKey::from_bytes(&[device_seed; 32]);
    let age = age::x25519::Identity::generate();
    let credential =
        DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
    Device {
        root,
        key,
        credential,
    }
}

fn signed<T: Serialize>(body: &T, key: &SigningKey) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(body).unwrap(), key).unwrap()
}

fn encoded(record: &SignedRecord) -> String {
    STANDARD.encode(record.bytes())
}

struct Fixture {
    owner: Device,
    guest: Device,
    witness: SigningKey,
    invitation: SigningKey,
    authority: Authority,
}

fn fixture() -> Fixture {
    let owner = device(1, 2);
    let guest = device(3, 4);
    let witness = SigningKey::from_bytes(&[5; 32]);
    let invitation = SigningKey::from_bytes(&[6; 32]);
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(witness.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let genesis = SpaceGenesis {
        v: 4,
        kind: "space.genesis".into(),
        nonce: record::random_hex::<16>().unwrap(),
        issuer_identity: owner.credential.identity(),
        owners: vec![Owner {
            identity_id: owner.credential.identity(),
            root_public_key: record::encode_hex(owner.root.verifying_key().as_bytes()),
        }],
        controller_credential_id: owner.credential.id(),
        witness: Some(pin),
    };
    let genesis = signed(&genesis, &owner.key);
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &owner.root.verifying_key(),
        owner.credential.clone(),
        StreamId::from_bytes([7; 16]),
    )
    .unwrap();
    authority.add_credential(guest.credential.clone());
    let config = StreamConfig {
        v: 4,
        kind: "stream.config".into(),
        nonce: record::random_hex::<16>().unwrap(),
        space_id: authority.space(),
        stream_id: authority.stream(),
        sequence: 1,
        previous_config_id: None,
        controller_credential_id: owner.credential.id(),
        members: vec![Member {
            identity_id: owner.credential.identity(),
            identity_type: "HUMAN".into(),
            root_public_key: record::encode_hex(owner.root.verifying_key().as_bytes()),
            capabilities: vec![
                Capability::Read,
                Capability::Post,
                Capability::ShareHistory,
                Capability::Manage,
            ],
            credential_ids: vec![owner.credential.id()],
            external: false,
        }],
        owner_credential_ids: vec![owner.credential.id()],
        action: ConfigAction {
            operation: "create".into(),
            actor_identity: owner.credential.identity(),
            request_record_id: None,
        },
        chat_kind: Some(ChatKind::Chat),
        recovery: None,
        witness_evidence: None,
    };
    assert_eq!(
        authority
            .apply_config(config.sign(&owner.key).unwrap())
            .unwrap(),
        ConfigAdmission::Applied
    );
    Fixture {
        owner,
        guest,
        witness,
        invitation,
        authority,
    }
}

fn policy(f: &Fixture, approval: bool, max_uses: u64) -> SignedRecord {
    signed(
        &WitnessInvitationPolicy {
            v: 1,
            kind: "witness.invitation".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: f.authority.space(),
            stream_id: f.authority.stream(),
            authority_head: f.authority.head_id().unwrap(),
            issuer_credential_id: f.owner.credential.id(),
            invitation_public_key: record::encode_hex(f.invitation.verifying_key().as_bytes()),
            not_before_ms: 1_000,
            expires_at_ms: 10_000,
            require_approval: approval,
            max_uses,
            witness_key_generation: 1,
        },
        &f.owner.key,
    )
}

fn evidence(f: &Fixture, candidate: &Device, policy: &SignedRecord) -> WitnessAdmissionEvidence {
    let challenge = signed(
        &WitnessChallenge {
            v: 1,
            kind: "witness.challenge".into(),
            nonce: record::random_hex::<32>().unwrap(),
            client_nonce: record::random_hex::<32>().unwrap(),
            space_id: f.authority.space(),
            stream_id: f.authority.stream(),
            policy_id: policy.id(),
            credential_id: candidate.credential.id(),
            issued_at_ms: 1_100,
            expires_at_ms: 5_000,
            witness_key_generation: 1,
        },
        &f.witness,
    );
    let contact = shared::contact(&candidate.credential, &candidate.key, "Guest", 10).unwrap();
    let intent = WitnessAdmissionIntent {
        v: 1,
        kind: "witness.admission".into(),
        nonce: record::random_hex::<32>().unwrap(),
        space_id: f.authority.space(),
        stream_id: f.authority.stream(),
        policy_id: policy.id(),
        challenge_id: challenge.id(),
        credential_id: candidate.credential.id(),
        contact_id: contact.id(),
    };
    WitnessAdmissionEvidence {
        policy: encoded(policy),
        challenge: encoded(&challenge),
        device_intent: encoded(&signed(&intent, &candidate.key)),
        invitation_intent: encoded(&signed(&intent, &f.invitation)),
        contact: encoded(&contact),
        approval: None,
        admitted_at_ms: 1_200,
    }
}

fn approval(f: &Fixture, evidence: &WitnessAdmissionEvidence, readmission: bool) -> String {
    encoded(&signed(
        &WitnessApproval {
            v: 1,
            kind: "witness.approval".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: f.authority.space(),
            stream_id: f.authority.stream(),
            authority_head: f.authority.head_id().unwrap(),
            issuer_credential_id: f.owner.credential.id(),
            intent_id: decode(&evidence.device_intent).unwrap().id(),
            readmission,
        },
        &f.owner.key,
    ))
}

fn next_owner_proposal(f: &Fixture) -> StreamConfig {
    let mut config = f.authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = f.authority.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.witness_evidence = None;
    config.controller_credential_id = f.owner.credential.id();
    config.action = ConfigAction {
        operation: "replace".into(),
        actor_identity: f.owner.credential.identity(),
        request_record_id: None,
    };
    config
}

#[test]
fn open_admission_preserves_control_and_requires_an_external_trusted_pin() {
    let mut f = fixture();
    let original = f.authority.head().unwrap().clone();
    let proof = evidence(&f, &f.guest, &policy(&f, false, 5));
    let config = f
        .authority
        .prepare_witness_admission(proof, &f.witness)
        .unwrap();
    assert_eq!(
        f.authority.apply_config(config).unwrap(),
        ConfigAdmission::Applied
    );
    let head = f.authority.head().unwrap();
    assert_eq!(head.owner_credential_ids, original.owner_credential_ids);
    assert_eq!(
        head.controller_credential_id,
        original.controller_credential_id
    );
    assert_eq!(
        head.members
            .iter()
            .find(|m| m.identity_id == f.owner.credential.identity())
            .unwrap(),
        &original.members[0]
    );
    assert_eq!(
        head.members
            .iter()
            .find(|m| m.identity_id == f.guest.credential.identity())
            .unwrap()
            .capabilities,
        [Capability::Read, Capability::Post]
    );
    assert!(!f.authority.can_manage(f.guest.credential.id()));
    let public = f.authority.call_proof().unwrap();
    assert!(
        public
            .verify(f.authority.space(), f.authority.stream())
            .is_err()
    );
    let pin = f.authority.witness_pin().unwrap();
    let verified = public
        .verify_witnessed(f.authority.space(), f.authority.stream(), pin)
        .unwrap();
    assert_eq!(verified.head_id(), f.authority.head_id());
    let mut wrong = pin.clone();
    wrong.key_generation += 1;
    assert!(
        public
            .verify_witnessed(f.authority.space(), f.authority.stream(), &wrong)
            .is_err()
    );
    assert!(f.authority.sign_checkpoint(&f.owner.key).is_err());
    assert!(public.checkpoint.is_none());
}

#[test]
fn owner_changes_need_both_the_original_owner_proposal_and_witness_signature() {
    let f = fixture();
    let proposal = next_owner_proposal(&f).sign(&f.owner.key).unwrap();
    assert!(f.authority.clone().apply_config(proposal.clone()).is_err());
    let committed = f
        .authority
        .prepare_witness_owner_config(&proposal, &f.witness)
        .unwrap();
    assert_eq!(
        f.authority.clone().apply_config(committed.clone()).unwrap(),
        ConfigAdmission::Applied
    );
    let mut altered: StreamConfig = committed.decode().unwrap();
    altered.nonce = record::random_hex::<16>().unwrap();
    assert!(
        f.authority
            .clone()
            .apply_config(altered.sign(&f.witness).unwrap())
            .is_err()
    );
    let candidate_proposal = next_owner_proposal(&f).sign(&f.guest.key).unwrap();
    assert!(
        f.authority
            .prepare_witness_owner_config(&candidate_proposal, &f.witness)
            .is_err()
    );
    assert!(
        f.authority
            .prepare_witness_owner_config(&proposal, &f.guest.key)
            .is_err()
    );
}

#[test]
fn witness_cannot_add_capabilities_or_remove_anyone_with_an_admission() {
    let f = fixture();
    let signed = f
        .authority
        .prepare_witness_admission(evidence(&f, &f.guest, &policy(&f, false, 5)), &f.witness)
        .unwrap();
    for change in 0..4 {
        let mut config: StreamConfig = signed.decode().unwrap();
        match change {
            0 => config
                .members
                .iter_mut()
                .find(|m| m.identity_id == f.guest.credential.identity())
                .unwrap()
                .capabilities
                .push(Capability::ShareHistory),
            1 => config
                .members
                .retain(|m| m.identity_id != f.owner.credential.identity()),
            2 => config.controller_credential_id = f.guest.credential.id(),
            _ => config.nonce = record::random_hex::<16>().unwrap(),
        }
        assert!(
            f.authority
                .clone()
                .apply_config(config.sign(&f.witness).unwrap())
                .is_err()
        );
    }
}

#[test]
fn invitation_possession_is_verified_even_when_the_witness_signature_is_valid() {
    let f = fixture();
    let valid = evidence(&f, &f.guest, &policy(&f, false, 5));
    let mut wrong_signature = valid.clone();
    let body = decode(&valid.device_intent).unwrap();
    wrong_signature.invitation_intent =
        encoded(&SignedRecord::sign(body.body_bytes(), &f.witness).unwrap());
    assert!(
        f.authority
            .prepare_witness_admission(wrong_signature, &f.witness)
            .is_err()
    );
    let mut different_bytes = valid.clone();
    let pretty = serde_json::to_vec_pretty(body.body()).unwrap();
    different_bytes.invitation_intent =
        encoded(&SignedRecord::sign(&pretty, &f.invitation).unwrap());
    assert!(
        f.authority
            .prepare_witness_admission(different_bytes, &f.witness)
            .is_err()
    );
    let mut wrong_contact = valid.clone();
    wrong_contact.contact =
        encoded(&shared::contact(&f.owner.credential, &f.owner.key, "Owner", 10_000).unwrap());
    assert!(
        f.authority
            .prepare_witness_admission(wrong_contact, &f.witness)
            .is_err()
    );
}

#[test]
fn acceptance_time_is_bound_to_the_signed_policy_and_short_lived_challenge() {
    let f = fixture();
    let policy = policy(&f, false, 5);
    assert!(f.authority.verify_witness_invitation(&policy, 999).is_err());
    assert!(
        f.authority
            .verify_witness_invitation(&policy, 10_000)
            .is_err()
    );
    assert!(
        f.authority
            .verify_witness_invitation(&policy, 1_000)
            .is_ok()
    );
    let valid = evidence(&f, &f.guest, &policy);
    for admitted_at_ms in [1_099, 5_000, 10_001, record::MAX_INTEGER + 1] {
        let mut changed = valid.clone();
        changed.admitted_at_ms = admitted_at_ms;
        assert!(
            f.authority
                .prepare_witness_admission(changed, &f.witness)
                .is_err()
        );
    }
    assert!(
        f.authority
            .prepare_witness_admission(valid, &f.witness)
            .is_ok()
    );
}

#[test]
fn contact_expiry_uses_unix_seconds_while_admission_uses_milliseconds() {
    let f = fixture();
    let mut proof = evidence(&f, &f.guest, &policy(&f, false, 5));
    let contact = shared::contact(&f.guest.credential, &f.guest.key, "Guest", 2).unwrap();
    let mut intent: WitnessAdmissionIntent =
        decode(&proof.device_intent).unwrap().decode().unwrap();
    intent.contact_id = contact.id();
    proof.contact = encoded(&contact);
    proof.device_intent = encoded(&signed(&intent, &f.guest.key));
    proof.invitation_intent = encoded(&signed(&intent, &f.invitation));
    proof.admitted_at_ms = 1_999;
    assert!(
        f.authority
            .prepare_witness_admission(proof.clone(), &f.witness)
            .is_ok()
    );
    proof.admitted_at_ms = 2_000;
    assert!(
        f.authority
            .prepare_witness_admission(proof, &f.witness)
            .is_err()
    );
}

#[test]
fn approval_binds_the_exact_candidate_intent_and_cannot_be_omitted() {
    let f = fixture();
    let mut proof = evidence(&f, &f.guest, &policy(&f, true, 5));
    assert!(
        f.authority
            .prepare_witness_admission(proof.clone(), &f.witness)
            .is_err()
    );
    proof.approval = Some(approval(&f, &proof, false));
    assert!(
        f.authority
            .prepare_witness_admission(proof.clone(), &f.witness)
            .is_ok()
    );
    let unrelated = evidence(&f, &f.guest, &policy(&f, true, 5));
    proof.approval = Some(approval(&f, &unrelated, false));
    assert!(
        f.authority
            .prepare_witness_admission(proof, &f.witness)
            .is_err()
    );
}

#[test]
fn open_invitation_cannot_grant_an_owner_identity_another_managing_device() {
    let mut f = fixture();
    let extra_owner = device(1, 9);
    f.authority.add_credential(extra_owner.credential.clone());
    let proof = evidence(&f, &extra_owner, &policy(&f, false, 5));
    assert!(
        f.authority
            .prepare_witness_admission(proof, &f.witness)
            .is_err()
    );
}

#[test]
fn parallel_requests_rebase_to_one_chain_and_the_last_use_cannot_be_spent_twice() {
    let mut f = fixture();
    let other = device(10, 11);
    f.authority.add_credential(other.credential.clone());
    let invitation = policy(&f, false, 2);
    let first = evidence(&f, &f.guest, &invitation);
    let second = evidence(&f, &other, &invitation);
    let committed = f
        .authority
        .prepare_witness_admission(first, &f.witness)
        .unwrap();
    f.authority.apply_config(committed).unwrap();
    let committed = f
        .authority
        .prepare_witness_admission(second, &f.witness)
        .unwrap();
    f.authority.apply_config(committed).unwrap();
    assert_eq!(f.authority.head().unwrap().sequence, 3);
    assert!(!f.authority.is_forked());
    let third = device(12, 13);
    f.authority.add_credential(third.credential.clone());
    let proof = evidence(&f, &third, &invitation);
    assert!(
        f.authority
            .prepare_witness_admission(proof, &f.witness)
            .is_err()
    );
}

#[test]
fn removed_identity_requires_explicit_readmission_and_old_credentials_stay_retired() {
    let mut f = fixture();
    let invitation = policy(&f, false, 5);
    let initial = evidence(&f, &f.guest, &invitation);
    let admitted = f
        .authority
        .prepare_witness_admission(initial.clone(), &f.witness)
        .unwrap();
    f.authority.apply_config(admitted).unwrap();
    let fresh = device(3, 14);
    f.authority.add_credential(fresh.credential.clone());
    let mut proof = evidence(&f, &fresh, &invitation);
    let approval_before_removal = approval(&f, &proof, true);
    let mut removal = next_owner_proposal(&f);
    removal
        .members
        .retain(|member| member.identity_id != f.guest.credential.identity());
    removal.action.operation = "member.removed".into();
    let removal = f
        .authority
        .prepare_witness_owner_config(&removal.sign(&f.owner.key).unwrap(), &f.witness)
        .unwrap();
    f.authority.apply_config(removal).unwrap();
    let mut retired = initial;
    retired.approval = Some(approval(&f, &retired, true));
    assert!(
        f.authority
            .prepare_witness_admission(retired, &f.witness)
            .is_err()
    );
    assert!(
        f.authority
            .prepare_witness_admission(proof.clone(), &f.witness)
            .is_err()
    );
    proof.approval = Some(approval_before_removal);
    assert!(
        f.authority
            .prepare_witness_admission(proof.clone(), &f.witness)
            .is_err()
    );
    proof.approval = Some(approval(&f, &proof, false));
    assert!(
        f.authority
            .prepare_witness_admission(proof.clone(), &f.witness)
            .is_err()
    );
    proof.approval = Some(approval(&f, &proof, true));
    assert!(
        f.authority
            .prepare_witness_admission(proof, &f.witness)
            .is_ok()
    );
}

#[test]
fn stale_readmission_approval_stays_invalid_after_another_device_rejoins() {
    fn remove_guest(f: &mut Fixture) {
        let mut removal = next_owner_proposal(f);
        removal
            .members
            .retain(|member| member.identity_id != f.guest.credential.identity());
        removal.action.operation = "member.removed".into();
        let removal = f
            .authority
            .prepare_witness_owner_config(&removal.sign(&f.owner.key).unwrap(), &f.witness)
            .unwrap();
        f.authority.apply_config(removal).unwrap();
    }

    let mut f = fixture();
    let invitation = policy(&f, false, 10);
    let initial = evidence(&f, &f.guest, &invitation);
    let admitted = f
        .authority
        .prepare_witness_admission(initial, &f.witness)
        .unwrap();
    f.authority.apply_config(admitted).unwrap();
    remove_guest(&mut f);

    let pending = device(3, 14);
    f.authority.add_credential(pending.credential.clone());
    let mut stale = evidence(&f, &pending, &invitation);
    stale.approval = Some(approval(&f, &stale, true));

    for (index, device_seed) in [15, 16].into_iter().enumerate() {
        let other = device(3, device_seed);
        f.authority.add_credential(other.credential.clone());
        let mut current = evidence(&f, &other, &invitation);
        current.approval = Some(approval(&f, &current, true));
        let admitted = f
            .authority
            .prepare_witness_admission(current, &f.witness)
            .unwrap();
        f.authority.apply_config(admitted).unwrap();
        if index == 0 {
            remove_guest(&mut f);
        }
    }

    // The pending candidate was approved before the second removal. A different
    // device rejoining the identity must not reactivate that stale approval.
    assert!(
        f.authority
            .prepare_witness_admission(stale.clone(), &f.witness)
            .is_err()
    );
    stale.approval = Some(approval(&f, &stale, true));
    assert!(
        f.authority
            .prepare_witness_admission(stale, &f.witness)
            .is_ok()
    );
}

#[test]
fn removing_one_device_invalidates_prior_approval_while_the_identity_remains() {
    let mut f = fixture();
    let invitation = policy(&f, false, 10);
    let initial = evidence(&f, &f.guest, &invitation);
    let admitted = f
        .authority
        .prepare_witness_admission(initial, &f.witness)
        .unwrap();
    f.authority.apply_config(admitted).unwrap();
    let retained = device(3, 15);
    f.authority.add_credential(retained.credential.clone());
    let admitted = f
        .authority
        .prepare_witness_admission(evidence(&f, &retained, &invitation), &f.witness)
        .unwrap();
    f.authority.apply_config(admitted).unwrap();

    let pending = device(3, 16);
    f.authority.add_credential(pending.credential.clone());
    let mut proof = evidence(&f, &pending, &invitation);
    proof.approval = Some(approval(&f, &proof, true));
    let mut removal = next_owner_proposal(&f);
    let guest = removal
        .members
        .iter_mut()
        .find(|member| member.identity_id == f.guest.credential.identity())
        .unwrap();
    guest.credential_ids = vec![retained.credential.id()];
    removal.action.operation = "device.removed".into();
    let removal = f
        .authority
        .prepare_witness_owner_config(&removal.sign(&f.owner.key).unwrap(), &f.witness)
        .unwrap();
    f.authority.apply_config(removal).unwrap();

    assert!(
        f.authority
            .prepare_witness_admission(proof.clone(), &f.witness)
            .is_err()
    );
    proof.approval = None;
    assert!(
        f.authority
            .prepare_witness_admission(proof.clone(), &f.witness)
            .is_err()
    );
    proof.approval = Some(approval(&f, &proof, true));
    assert!(
        f.authority
            .prepare_witness_admission(proof, &f.witness)
            .is_ok()
    );
}

#[test]
fn reused_challenge_nonce_is_rejected_even_for_a_new_signed_candidate() {
    let mut f = fixture();
    let invitation = policy(&f, false, 5);
    let first = evidence(&f, &f.guest, &invitation);
    let original: WitnessChallenge = decode(&first.challenge).unwrap().decode().unwrap();
    let admitted = f
        .authority
        .prepare_witness_admission(first, &f.witness)
        .unwrap();
    f.authority.apply_config(admitted).unwrap();
    let other = device(10, 11);
    f.authority.add_credential(other.credential.clone());
    let mut proof = evidence(&f, &other, &invitation);
    let mut challenge: WitnessChallenge = decode(&proof.challenge).unwrap().decode().unwrap();
    challenge.nonce = original.nonce;
    let challenge = signed(&challenge, &f.witness);
    proof.challenge = encoded(&challenge);
    let mut intent: WitnessAdmissionIntent =
        decode(&proof.device_intent).unwrap().decode().unwrap();
    intent.challenge_id = challenge.id();
    proof.device_intent = encoded(&signed(&intent, &other.key));
    proof.invitation_intent = encoded(&signed(&intent, &f.invitation));
    assert!(
        f.authority
            .prepare_witness_admission(proof, &f.witness)
            .is_err()
    );
}

#[test]
fn witness_equivocation_forks_authority_and_stops_further_signing() {
    let mut f = fixture();
    let other = device(10, 11);
    f.authority.add_credential(other.credential.clone());
    let invitation = policy(&f, false, 5);
    let first = f
        .authority
        .prepare_witness_admission(evidence(&f, &f.guest, &invitation), &f.witness)
        .unwrap();
    let second = f
        .authority
        .prepare_witness_admission(evidence(&f, &other, &invitation), &f.witness)
        .unwrap();
    f.authority.apply_config(first).unwrap();
    assert_eq!(
        f.authority.apply_config(second).unwrap(),
        ConfigAdmission::Forked
    );
    assert!(f.authority.is_forked());
    assert!(!f.authority.can_manage(f.owner.credential.id()));
    assert!(
        f.authority
            .verify_witness_invitation(&invitation, 1_200)
            .is_err()
    );
    assert!(
        f.authority
            .prepare_witness_owner_config(
                &next_owner_proposal(&f).sign(&f.owner.key).unwrap(),
                &f.witness
            )
            .is_err()
    );
}

#[test]
fn removing_and_regranting_owner_authority_does_not_reactivate_old_invitations() {
    let mut f = fixture();
    let invitation = policy(&f, false, 5);
    let second_owner = device(10, 11);
    f.authority.add_credential(second_owner.credential.clone());
    let original_owner = f.authority.head().unwrap().members[0].clone();
    let mut grant = next_owner_proposal(&f);
    let mut added = original_owner.clone();
    added.identity_id = second_owner.credential.identity();
    added.root_public_key = record::encode_hex(second_owner.root.verifying_key().as_bytes());
    added.credential_ids = vec![second_owner.credential.id()];
    grant.members.push(added);
    grant.members.sort_by_key(|member| member.identity_id);
    grant
        .owner_credential_ids
        .push(second_owner.credential.id());
    grant.owner_credential_ids.sort();
    let committed = f
        .authority
        .prepare_witness_owner_config(&grant.sign(&f.owner.key).unwrap(), &f.witness)
        .unwrap();
    f.authority.apply_config(committed).unwrap();
    assert!(
        f.authority
            .verify_witness_invitation(&invitation, 1_200)
            .is_ok()
    );
    let mut remove = next_owner_proposal(&f);
    remove
        .members
        .retain(|member| member.identity_id != f.owner.credential.identity());
    remove.owner_credential_ids = vec![second_owner.credential.id()];
    let committed = f
        .authority
        .prepare_witness_owner_config(&remove.sign(&f.owner.key).unwrap(), &f.witness)
        .unwrap();
    f.authority.apply_config(committed).unwrap();
    let mut regrant = next_owner_proposal(&f);
    regrant.controller_credential_id = second_owner.credential.id();
    regrant.action.actor_identity = second_owner.credential.identity();
    regrant.members.push(original_owner);
    regrant.members.sort_by_key(|member| member.identity_id);
    regrant.owner_credential_ids.push(f.owner.credential.id());
    regrant.owner_credential_ids.sort();
    let committed = f
        .authority
        .prepare_witness_owner_config(&regrant.sign(&second_owner.key).unwrap(), &f.witness)
        .unwrap();
    f.authority.apply_config(committed).unwrap();
    assert!(f.authority.can_manage(f.owner.credential.id()));
    assert!(
        f.authority
            .verify_witness_invitation(&invitation, 1_200)
            .is_err()
    );
}

#[test]
fn invalid_pins_and_legacy_genesis_with_witness_fields_are_rejected() {
    let f = fixture();
    let pin = f.authority.witness_pin().unwrap();
    for url in [
        "http://witness.example.test",
        "https://user:secret@witness.example.test",
        "https://witness.example.test/#key",
        "https://witness.example.test/?key=x",
    ] {
        let mut invalid = pin.clone();
        invalid.url = url.into();
        assert!(invalid.validate().is_err());
    }
    let mut genesis: SpaceGenesis = f.authority.genesis().decode().unwrap();
    genesis.v = 2;
    let signed = signed(&genesis, &f.owner.key);
    assert!(
        Authority::new(
            signed.bytes(),
            signed.id().to_string().parse().unwrap(),
            &f.owner.root.verifying_key(),
            f.owner.credential.clone(),
            f.authority.stream()
        )
        .is_err()
    );
}

mod durable;

use super::*;

const LATER: u64 = 3_601_000;

fn long_policy(f: &Fixture, approval: bool, uses: u64) -> SignedRecord {
    let mut body: WitnessInvitationPolicy = policy(f, approval, uses).decode().unwrap();
    body.expires_at_ms = 86_402_000;
    signed(&body, &f.owner.key)
}

fn request(f: &Fixture, candidate: &Device, policy: &SignedRecord) -> WitnessJoinRequestEvidence {
    let contact = shared::contact(&candidate.credential, &candidate.key, "Guest", 86_401).unwrap();
    let body = WitnessJoinRequest {
        v: 1,
        kind: "witness.join_request".into(),
        nonce: record::random_hex::<32>().unwrap(),
        space_id: f.authority.space(),
        stream_id: f.authority.stream(),
        policy_id: policy.id(),
        credential_id: candidate.credential.id(),
        contact_id: contact.id(),
        issued_at_ms: 1_000,
        expires_at_ms: 86_401_000,
        witness_key_generation: 1,
    };
    WitnessJoinRequestEvidence {
        policy: encoded(policy),
        device_request: encoded(&signed(&body, &candidate.key)),
        invitation_request: encoded(&signed(&body, &f.invitation)),
        contact: encoded(&contact),
    }
}

fn approval_v2(
    f: &Fixture,
    owner: &Device,
    request: &WitnessJoinRequestEvidence,
    readmission: bool,
) -> String {
    encoded(&signed(
        &WitnessApprovalV2 {
            v: 2,
            kind: "witness.approval".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: f.authority.space(),
            stream_id: f.authority.stream(),
            authority_head: f.authority.head_id().unwrap(),
            issuer_credential_id: owner.credential.id(),
            request_id: decode(&request.device_request).unwrap().id(),
            readmission,
            expires_at_ms: 86_401_000,
        },
        &owner.key,
    ))
}

fn final_evidence(
    f: &Fixture,
    candidate: &Device,
    request: WitnessJoinRequestEvidence,
    now: u64,
) -> WitnessAdmissionEvidenceV2 {
    let body: WitnessJoinRequest = decode(&request.device_request).unwrap().decode().unwrap();
    let request_id = decode(&request.device_request).unwrap().id();
    let challenge = signed(
        &WitnessChallengeV2 {
            v: 2,
            kind: "witness.challenge".into(),
            nonce: record::random_hex::<32>().unwrap(),
            client_nonce: record::random_hex::<32>().unwrap(),
            space_id: body.space_id,
            stream_id: body.stream_id,
            policy_id: body.policy_id,
            credential_id: candidate.credential.id(),
            request_id,
            authority_head: f.authority.head_id().unwrap(),
            issued_at_ms: now,
            expires_at_ms: now + 120_000,
            witness_key_generation: 1,
        },
        &f.witness,
    );
    let intent = WitnessAdmissionIntentV2 {
        v: 2,
        kind: "witness.admission".into(),
        nonce: record::random_hex::<32>().unwrap(),
        space_id: body.space_id,
        stream_id: body.stream_id,
        policy_id: body.policy_id,
        request_id,
        challenge_id: challenge.id(),
        credential_id: candidate.credential.id(),
        contact_id: body.contact_id,
    };
    WitnessAdmissionEvidenceV2 {
        request,
        challenge: encoded(&challenge),
        device_intent: encoded(&signed(&intent, &candidate.key)),
        invitation_intent: encoded(&signed(&intent, &f.invitation)),
        approval: None,
        admitted_at_ms: now + 1,
    }
}

fn apply_owner(f: &mut Fixture, proposal: StreamConfig) {
    let update = f
        .authority
        .prepare_witness_owner_config(&proposal.sign(&f.owner.key).unwrap(), &f.witness)
        .unwrap();
    f.authority.apply_config(update).unwrap();
}

#[test]
fn durable_approval_survives_an_hour_and_a_new_challenge() {
    let f = fixture();
    let request = request(&f, &f.guest, &long_policy(&f, true, 5));
    let approval = approval_v2(&f, &f.owner, &request, false);
    let mut expired = final_evidence(&f, &f.guest, request.clone(), 1_100);
    expired.approval = Some(approval.clone());
    expired.admitted_at_ms = LATER;
    assert!(
        f.authority
            .prepare_witness_admission_v2(expired, &f.witness)
            .is_err()
    );
    // Serialization represents public relay/persistence, without preserving a lease.
    let stored = serde_json::to_vec(&request).unwrap();
    let request = serde_json::from_slice(&stored).unwrap();
    let mut fresh = final_evidence(&f, &f.guest, request, LATER);
    fresh.approval = Some(approval);
    let config = f
        .authority
        .prepare_witness_admission_v2(fresh, &f.witness)
        .unwrap();
    let mut authority = f.authority.clone();
    authority.apply_config(config).unwrap();
    let restored = authority
        .call_proof()
        .unwrap()
        .verify_witnessed(
            authority.space(),
            authority.stream(),
            authority.witness_pin().unwrap(),
        )
        .unwrap();
    assert_eq!(restored.head_id(), authority.head_id());
}

#[test]
fn durable_request_checks_exact_signatures_scope_contact_and_lifetime() {
    let f = fixture();
    let request = request(&f, &f.guest, &long_policy(&f, false, 5));
    for change in 0..10 {
        let mut altered = request.clone();
        let mut body: WitnessJoinRequest =
            decode(&altered.device_request).unwrap().decode().unwrap();
        match change {
            0 => body.credential_id = f.owner.credential.id(),
            1 => body.contact_id = f.owner.credential.id(),
            2 => body.policy_id = f.owner.credential.id(),
            3 => body.space_id = SpaceId::from_bytes([42; 32]),
            4 => body.stream_id = StreamId::from_bytes([42; 16]),
            5 => body.expires_at_ms += 1,
            6 => body.expires_at_ms = 1_001,
            7 => body.witness_key_generation += 1,
            8 => body.issued_at_ms = LATER + 5_001,
            _ => body.kind = "witness.admission".into(),
        }
        altered.device_request = encoded(&signed(&body, &f.guest.key));
        altered.invitation_request = encoded(&signed(&body, &f.invitation));
        assert!(
            f.authority
                .verify_witness_join_request(&altered, &f.guest.credential, LATER)
                .is_err(),
            "change {change}"
        );
    }
    let mut bad = request.clone();
    bad.invitation_request = bad.device_request.clone();
    assert!(
        f.authority
            .verify_witness_join_request(&bad, &f.guest.credential, LATER)
            .is_err()
    );
    let mut bad = request;
    bad.contact =
        encoded(&shared::contact(&f.guest.credential, &f.guest.key, "Changed", 86_401).unwrap());
    assert!(
        f.authority
            .verify_witness_join_request(&bad, &f.guest.credential, LATER)
            .is_err()
    );
}

#[test]
fn durable_approval_cannot_move_to_another_request_or_use_v1_approval() {
    let f = fixture();
    let policy = long_policy(&f, true, 5);
    let original = request(&f, &f.guest, &policy);
    let mut evidence = final_evidence(&f, &f.guest, original.clone(), LATER);
    evidence.approval = Some(approval_v2(
        &f,
        &f.owner,
        &request(&f, &f.guest, &policy),
        false,
    ));
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence.clone(), &f.witness)
            .is_err()
    );
    let legacy = super::evidence(&f, &f.guest, &policy);
    evidence.approval = Some(approval(&f, &legacy, false));
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence.clone(), &f.witness)
            .is_err()
    );
    evidence.approval = Some(approval_v2(&f, &f.owner, &original, false));
    let mut expired: WitnessApprovalV2 = decode(evidence.approval.as_ref().unwrap())
        .unwrap()
        .decode()
        .unwrap();
    expired.expires_at_ms = LATER;
    evidence.approval = Some(encoded(&signed(&expired, &f.owner.key)));
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence, &f.witness)
            .is_err()
    );
}

#[test]
fn durable_final_intent_and_challenge_bind_the_approved_request() {
    let f = fixture();
    let request = request(&f, &f.guest, &long_policy(&f, true, 5));
    let mut original = final_evidence(&f, &f.guest, request.clone(), LATER);
    original.approval = Some(approval_v2(&f, &f.owner, &request, false));
    for change in 0..7 {
        let mut altered = original.clone();
        let mut body: WitnessAdmissionIntentV2 =
            decode(&altered.device_intent).unwrap().decode().unwrap();
        match change {
            0 => body.request_id = f.owner.credential.id(),
            1 => body.challenge_id = f.owner.credential.id(),
            2 => body.credential_id = f.owner.credential.id(),
            3 => body.contact_id = f.owner.credential.id(),
            4 => body.policy_id = f.owner.credential.id(),
            5 => body.space_id = SpaceId::from_bytes([42; 32]),
            _ => body.v = 1,
        }
        altered.device_intent = encoded(&signed(&body, &f.guest.key));
        altered.invitation_intent = encoded(&signed(&body, &f.invitation));
        assert!(
            f.authority
                .prepare_witness_admission_v2(altered, &f.witness)
                .is_err()
        );
    }
    for change in 0..5 {
        let mut altered = original.clone();
        let mut challenge: WitnessChallengeV2 =
            decode(&altered.challenge).unwrap().decode().unwrap();
        match change {
            0 => challenge.request_id = f.owner.credential.id(),
            1 => challenge.authority_head = f.owner.credential.id(),
            2 => challenge.expires_at_ms += 1,
            3 => challenge.nonce = "invalid".into(),
            _ => challenge.witness_key_generation += 1,
        }
        let record = signed(&challenge, &f.witness);
        altered.challenge = encoded(&record);
        let mut intent: WitnessAdmissionIntentV2 =
            decode(&altered.device_intent).unwrap().decode().unwrap();
        intent.challenge_id = record.id();
        altered.device_intent = encoded(&signed(&intent, &f.guest.key));
        altered.invitation_intent = encoded(&signed(&intent, &f.invitation));
        assert!(
            f.authority
                .prepare_witness_admission_v2(altered, &f.witness)
                .is_err()
        );
    }
}

#[test]
fn durable_approval_before_device_removal_cannot_authorize_readmission() {
    let mut f = fixture();
    let policy = long_policy(&f, false, 10);
    let first = f
        .authority
        .prepare_witness_admission(super::evidence(&f, &f.guest, &policy), &f.witness)
        .unwrap();
    f.authority.apply_config(first).unwrap();
    let retained = device(3, 15);
    f.authority.add_credential(retained.credential.clone());
    let retained_config = f
        .authority
        .prepare_witness_admission(super::evidence(&f, &retained, &policy), &f.witness)
        .unwrap();
    f.authority.apply_config(retained_config).unwrap();
    let pending = device(3, 16);
    f.authority.add_credential(pending.credential.clone());
    let request = request(&f, &pending, &policy);
    let old_approval = approval_v2(&f, &f.owner, &request, true);
    let mut removal = next_owner_proposal(&f);
    removal
        .members
        .iter_mut()
        .find(|m| m.identity_id == pending.credential.identity())
        .unwrap()
        .credential_ids = vec![retained.credential.id()];
    removal.action.operation = "device.removed".into();
    apply_owner(&mut f, removal);
    let mut evidence = final_evidence(&f, &pending, request.clone(), LATER);
    evidence.approval = Some(old_approval);
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence.clone(), &f.witness)
            .is_err()
    );
    evidence.approval = Some(approval_v2(&f, &f.owner, &request, false));
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence.clone(), &f.witness)
            .is_err()
    );
    evidence.approval = Some(approval_v2(&f, &f.owner, &request, true));
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence, &f.witness)
            .is_ok()
    );
}

#[test]
fn durable_approval_is_not_reactivated_when_its_owner_is_regranted() {
    let mut f = fixture();
    let second = device(10, 11);
    f.authority.add_credential(second.credential.clone());
    let mut grant = next_owner_proposal(&f);
    let mut member = grant.members[0].clone();
    member.identity_id = second.credential.identity();
    member.root_public_key = record::encode_hex(second.root.verifying_key().as_bytes());
    member.credential_ids = vec![second.credential.id()];
    grant.members.push(member.clone());
    grant.members.sort_by_key(|m| m.identity_id);
    grant.owner_credential_ids.push(second.credential.id());
    grant.owner_credential_ids.sort();
    apply_owner(&mut f, grant);
    // The policy's author stays an owner; only the approval author is removed.
    let policy = long_policy(&f, true, 5);
    let request = request(&f, &f.guest, &policy);
    let old = approval_v2(&f, &second, &request, false);
    let mut removal = next_owner_proposal(&f);
    removal
        .members
        .retain(|m| m.identity_id != second.credential.identity());
    removal
        .owner_credential_ids
        .retain(|id| *id != second.credential.id());
    apply_owner(&mut f, removal);
    let mut grant = next_owner_proposal(&f);
    grant.members.push(member);
    grant.members.sort_by_key(|m| m.identity_id);
    grant.owner_credential_ids.push(second.credential.id());
    grant.owner_credential_ids.sort();
    apply_owner(&mut f, grant);
    let mut evidence = final_evidence(&f, &f.guest, request.clone(), LATER);
    evidence.approval = Some(old);
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence.clone(), &f.witness)
            .is_err()
    );
    evidence.approval = Some(approval_v2(&f, &second, &request, false));
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence, &f.witness)
            .is_ok()
    );
}

#[test]
fn invitation_use_limits_and_time_order_include_both_evidence_versions() {
    for v2_first in [false, true] {
        let mut f = fixture();
        let policy = long_policy(&f, false, 1);
        let config = if v2_first {
            f.authority
                .prepare_witness_admission_v2(
                    final_evidence(&f, &f.guest, request(&f, &f.guest, &policy), 1_100),
                    &f.witness,
                )
                .unwrap()
        } else {
            f.authority
                .prepare_witness_admission(super::evidence(&f, &f.guest, &policy), &f.witness)
                .unwrap()
        };
        f.authority.apply_config(config).unwrap();
        let other = device(20, 21);
        f.authority.add_credential(other.credential.clone());
        assert!(
            f.authority
                .prepare_witness_admission_v2(
                    final_evidence(&f, &other, request(&f, &other, &policy), LATER),
                    &f.witness
                )
                .is_err()
        );
        assert!(
            f.authority
                .prepare_witness_admission(super::evidence(&f, &other, &policy), &f.witness)
                .is_err()
        );
    }
}

#[test]
fn durable_request_deadline_cannot_exceed_policy_or_contact() {
    let f = fixture();
    let long = long_policy(&f, false, 5);
    for shorter_contact in [false, true] {
        let mut request = request(&f, &f.guest, &long);
        let mut body: WitnessJoinRequest =
            decode(&request.device_request).unwrap().decode().unwrap();
        if shorter_contact {
            let contact =
                shared::contact(&f.guest.credential, &f.guest.key, "Guest", 7_200).unwrap();
            body.contact_id = contact.id();
            request.contact = encoded(&contact);
        } else {
            let mut policy: WitnessInvitationPolicy = long.decode().unwrap();
            policy.expires_at_ms = 7_200_000;
            let policy = signed(&policy, &f.owner.key);
            body.policy_id = policy.id();
            request.policy = encoded(&policy);
        }
        request.device_request = encoded(&signed(&body, &f.guest.key));
        request.invitation_request = encoded(&signed(&body, &f.invitation));
        assert!(
            f.authority
                .verify_witness_join_request(&request, &f.guest.credential, LATER)
                .is_err()
        );
    }
}

#[test]
fn legacy_admission_cannot_rewind_time_after_durable_admission() {
    let mut f = fixture();
    let policy = long_policy(&f, false, 5);
    let first = f
        .authority
        .prepare_witness_admission_v2(
            final_evidence(&f, &f.guest, request(&f, &f.guest, &policy), LATER),
            &f.witness,
        )
        .unwrap();
    f.authority.apply_config(first).unwrap();
    let other = device(20, 21);
    f.authority.add_credential(other.credential.clone());
    assert!(
        f.authority
            .prepare_witness_admission(super::evidence(&f, &other, &policy), &f.witness)
            .is_err()
    );
}

#[test]
fn durable_approval_stays_invalid_after_another_device_rejoins_identity() {
    let mut f = fixture();
    let policy = long_policy(&f, false, 10);
    let initial = f
        .authority
        .prepare_witness_admission(super::evidence(&f, &f.guest, &policy), &f.witness)
        .unwrap();
    f.authority.apply_config(initial).unwrap();
    let pending = device(3, 15);
    f.authority.add_credential(pending.credential.clone());
    let request = request(&f, &pending, &policy);
    let stale = approval_v2(&f, &f.owner, &request, true);
    let mut remove = next_owner_proposal(&f);
    remove
        .members
        .retain(|m| m.identity_id != f.guest.credential.identity());
    apply_owner(&mut f, remove);
    let other = device(3, 16);
    f.authority.add_credential(other.credential.clone());
    let mut rejoin = super::evidence(&f, &other, &policy);
    rejoin.approval = Some(approval(&f, &rejoin, true));
    let config = f
        .authority
        .prepare_witness_admission(rejoin, &f.witness)
        .unwrap();
    f.authority.apply_config(config).unwrap();
    let mut evidence = final_evidence(&f, &pending, request.clone(), LATER);
    evidence.approval = Some(stale);
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence.clone(), &f.witness)
            .is_err()
    );
    evidence.approval = Some(approval_v2(&f, &f.owner, &request, true));
    assert!(
        f.authority
            .prepare_witness_admission_v2(evidence, &f.witness)
            .is_ok()
    );
}

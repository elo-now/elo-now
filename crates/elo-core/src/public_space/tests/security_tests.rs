use super::*;
use crate::{app::space_host, identity::DeviceRevocation, vault::Session};

fn fixture(path: &Path) -> (PublicSpaceService, ServiceConfig, Session) {
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
    let service = PublicSpaceService::create(
        path,
        authority.call_proof().unwrap(),
        &[owner.identity_id()],
        None,
        true,
        Some(creation),
    )
    .unwrap();
    let config = ServiceConfig {
        name: "Security regression".into(),
        owners: vec![owner.identity_id()],
        contact_email: None,
        address: SpaceAddress {
            url: "https://host.example.test/team/v1/spaces".into(),
            scope: service.team_scope().unwrap(),
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
            service_credential: Some(service.transport_credential()),
        },
        peer: crate::sync::PeerDescriptor {
            url: "https://host.example.test".into(),
            signing_public_key: record::encode_hex(service.signing_key.verifying_key().as_bytes()),
            mailbox_id: crate::ids::MailboxId::from_bytes([3; 32]),
            read_token: Some("11".repeat(32)),
            write_token: Some("22".repeat(32)),
        },
    };
    (service, config, owner)
}

fn deletion(device: &Session) -> AdminEvidence {
    let command = json!({"v":1,"kind":"account.deletion","endpoint":"https://host.example.test/accounts/v1/deletion","nonce":record::random_hex::<16>().unwrap(),"issued":100,"action":"submit","confirmed":true});
    AdminEvidence {
        record: STANDARD.encode(
            SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), device.signing_key())
                .unwrap()
                .bytes(),
        ),
        credential: STANDARD.encode(device.credential().record().bytes()),
    }
}

fn member(device: &Session, owner: bool) -> Member {
    Member {
        identity_id: device.identity_id(),
        identity_type: "HUMAN".into(),
        root_public_key: device.credential().record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into(),
        capabilities: if owner {
            vec![
                Capability::Read,
                Capability::Post,
                Capability::ShareHistory,
                Capability::Manage,
            ]
        } else {
            vec![Capability::Read, Capability::Post]
        },
        credential_ids: vec![device.credential().id()],
        external: false,
    }
}

fn next(
    authority: &Authority,
    signer: &Session,
    members: Vec<Member>,
    journal: &[AdminEvidence],
) -> Authority {
    let mut authority = authority.clone();
    let mut config = authority.head().unwrap().clone();
    config.nonce = record::random_hex::<16>().unwrap();
    config.sequence += 1;
    config.previous_config_id = authority.head_id();
    config.controller_credential_id = signer.credential().id();
    config.members = members;
    config.members.sort_by_key(|member| member.identity_id);
    config.owner_credential_ids = config
        .members
        .iter()
        .filter(|member| member.capabilities.contains(&Capability::Manage))
        .flat_map(|member| member.credential_ids.iter().copied())
        .collect();
    config.owner_credential_ids.sort();
    config.action = ConfigAction {
        operation: "replace".into(),
        actor_identity: signer.identity_id(),
        request_record_id: crate::owner_admission::journal_commitment(journal).unwrap(),
    };
    authority
        .apply_config(config.sign(signer.signing_key()).unwrap())
        .unwrap();
    authority
}

#[tokio::test]
async fn erasing_pending_or_removed_profiles_keeps_the_owner_journal_valid() {
    for removed in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let (mut service, config, owner) = fixture(directory.path());
        let pending = Session::create().unwrap().0;
        let mut state = service.service_state().unwrap();
        state.applicants.insert(
            pending.credential().id().to_string(),
            Applicant {
                authorization: None,
                identity: pending.identity_id(),
                name: "Pending profile".into(),
                status: if removed { "removed" } else { "pending" }.into(),
                invitation: "test".into(),
                note: String::new(),
                request: team::EnrollmentRequest {
                    v: 1,
                    contact: String::new(),
                    proof: String::new(),
                },
                requested_at: 100,
            },
        );
        if removed {
            state.removals.insert(pending.identity_id(), 1);
        }
        service.save_service_state(&state).unwrap();
        let proof = deletion(&pending);
        service
            .validate_account_deletion(&config, pending.identity_id(), Some(&proof))
            .unwrap();
        service
            .erase_service_account(&config, pending.identity_id(), Some(&proof))
            .await
            .unwrap();
        service
            .erase_service_account(&config, pending.identity_id(), Some(&proof))
            .await
            .unwrap();
        let mut state = service.service_state().unwrap();
        assert!(state.journal.is_empty());
        assert!(state.committed_journal.is_empty());
        assert!(state.applicants.is_empty());
        assert!(state.erased_accounts.contains(&pending.identity_id()));
        let status = service
            .authority_status(&state, owner.credential(), None)
            .unwrap();
        crate::owner_admission::verify_owner_policy(&service.authorities.0[0], &status, 1000)
            .unwrap();
        let authority = &service.authorities.0[0];
        let successor = next(
            authority,
            &owner,
            authority.head().unwrap().members.clone(),
            &[],
        );
        service.publish_authority(&mut state, owner.credential(), &json!({"expected_head":authority.head_id(),"proof":successor.call_proof().unwrap()}), None).unwrap();
    }
}

#[tokio::test]
async fn erasure_preflight_rejects_an_unenrolled_signer_without_changing_live_membership() {
    let directory = tempfile::tempdir().unwrap();
    let (mut service, config, owner) = fixture(directory.path());
    let (guest, recovery) = Session::create().unwrap();
    let recovered = Session::recover(&recovery, guest.identity_id()).unwrap();
    let mut authority = service.authorities.0[0].clone();
    authority.add_credential(guest.credential().clone());
    let mut members = authority.head().unwrap().members.clone();
    members.push(member(&guest, false));
    service.authorities.0[0] = next(&authority, &owner, members, &[]);
    let mut state = service.service_state().unwrap();
    state.proof = service.authorities.0[0].call_proof().unwrap();
    service.save_service_state(&state).unwrap();
    let proof = deletion(&recovered);
    assert!(
        service
            .validate_account_deletion(&config, guest.identity_id(), Some(&proof))
            .is_err()
    );
    assert!(
        service
            .erase_service_account(&config, guest.identity_id(), Some(&proof))
            .await
            .is_err()
    );
    let state = service.service_state().unwrap();
    assert!(state.journal.is_empty());
    assert!(state.erased_accounts.is_empty());
    assert!(
        service
            .space_access_devices()
            .unwrap()
            .contains(&guest.credential().id())
    );

    let proof = deletion(&guest);
    service
        .validate_account_deletion(&config, guest.identity_id(), Some(&proof))
        .unwrap();
    service
        .erase_service_account(&config, guest.identity_id(), Some(&proof))
        .await
        .unwrap();
    let mut state = service.service_state().unwrap();
    let status = service
        .authority_status(&state, owner.credential(), None)
        .unwrap();
    let policy =
        crate::owner_admission::verify_owner_policy(&service.authorities.0[0], &status, 1000)
            .unwrap();
    assert!(policy.removed.contains(&guest.identity_id()));
    let authority = &service.authorities.0[0];
    let successor = next(
        authority,
        &owner,
        vec![member(&owner, true)],
        &state.journal,
    );
    service
        .publish_authority(
            &mut state,
            owner.credential(),
            &json!({"expected_head":authority.head_id(),"proof":successor.call_proof().unwrap()}),
            None,
        )
        .unwrap();
}

#[tokio::test]
async fn minted_unadmitted_devices_cannot_fill_revocations_or_the_administration_journal() {
    let directory = tempfile::tempdir().unwrap();
    let (service, _, owner) = fixture(&directory.path().join("service"));
    let replica = crate::replica::ReplicaStore::open(directory.path().join("replica"))
        .await
        .unwrap();
    let target = owner.linked_companion().unwrap();
    let proof = DeviceRevocation::issue_from_device(
        owner.credential(),
        owner.signing_key(),
        target.credential(),
    )
    .unwrap();
    let mut state = service.service_state().unwrap();
    assert!(
        service
            .space_revoke_device(
                &mut state,
                owner.credential(),
                &json!({"proof":STANDARD.encode(proof.bytes())}),
                Some(&replica)
            )
            .await
            .is_err()
    );
    assert!(state.journal.is_empty());
    assert!(state.revoked.is_empty());
    assert!(
        replica
            .revocations()
            .get(target.credential().id())
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn revoked_device_churn_limits_new_companions_without_blocking_existing_members() {
    let directory = tempfile::tempdir().unwrap();
    let (mut service, _, owner) = fixture(&directory.path().join("service"));
    let replica = crate::replica::ReplicaStore::open(directory.path().join("replica"))
        .await
        .unwrap();
    // Represents previously admitted devices retired in other hosted Spaces.
    for _ in 0..16 {
        let retired = owner.linked_companion().unwrap();
        let proof = DeviceRevocation::issue_from_device(
            owner.credential(),
            owner.signing_key(),
            retired.credential(),
        )
        .unwrap();
        replica.revocations().insert(&proof).unwrap();
    }
    let companion = owner.linked_companion().unwrap();
    let authority = &service.authorities.0[0];
    let mut proof_authority = authority.clone();
    proof_authority.add_credential(companion.credential().clone());
    let mut members = authority.head().unwrap().members.clone();
    members[0].credential_ids.push(companion.credential().id());
    members[0].credential_ids.sort();
    let enlarged = next(&proof_authority, &owner, members, &[]);
    let unchanged = next(
        authority,
        &owner,
        authority.head().unwrap().members.clone(),
        &[],
    );
    let expected_head = authority.head_id();
    let mut state = service.service_state().unwrap();
    assert!(
        service
            .publish_authority(
                &mut state,
                owner.credential(),
                &json!({"expected_head":expected_head,"proof":enlarged.call_proof().unwrap()}),
                Some(&replica)
            )
            .is_err()
    );
    service
        .publish_authority(
            &mut state,
            owner.credential(),
            &json!({"expected_head":expected_head,"proof":unchanged.call_proof().unwrap()}),
            Some(&replica),
        )
        .unwrap();
}

#[test]
fn owner_signature_cannot_remove_another_owner_or_member_without_an_accepted_intent() {
    let directory = tempfile::tempdir().unwrap();
    let (mut service, _, owner) = fixture(directory.path());
    let coowner = Session::create().unwrap().0;
    let guest = Session::create().unwrap().0;
    let mut authority = service.authorities.0[0].clone();
    authority.add_credential(coowner.credential().clone());
    authority.add_credential(guest.credential().clone());
    let members = vec![
        member(&owner, true),
        member(&coowner, true),
        member(&guest, false),
    ];
    let admitted = next(&authority, &owner, members.clone(), &[]);
    service.authorities.0[0] = admitted.clone();
    let mut state = service.service_state().unwrap();
    state.proof = admitted.call_proof().unwrap();
    state.roles = Some(Roles::bootstrap(&[owner.identity_id(), coowner.identity_id()]).unwrap());
    service.save_service_state(&state).unwrap();
    for victim in [
        owner.identity_id(),
        coowner.identity_id(),
        guest.identity_id(),
    ] {
        let forged = next(
            &admitted,
            &coowner,
            members
                .iter()
                .filter(|m| m.identity_id != victim)
                .cloned()
                .collect(),
            &[],
        );
        assert!(service.publish_authority(&mut state, coowner.credential(), &json!({"expected_head":admitted.head_id(),"proof":forged.call_proof().unwrap()}), None).is_err());
        assert_eq!(service.authorities.0[0].head_id(), admitted.head_id());
    }
    for capabilities in [
        vec![Capability::Read],
        vec![Capability::Read, Capability::Post, Capability::ShareHistory],
    ] {
        let mut altered = members.clone();
        altered
            .iter_mut()
            .find(|member| member.identity_id == guest.identity_id())
            .unwrap()
            .capabilities = capabilities;
        let forged = next(&admitted, &coowner, altered, &[]);
        assert!(service.publish_authority(&mut state, coowner.credential(), &json!({"expected_head":admitted.head_id(),"proof":forged.call_proof().unwrap()}), None).is_err());
    }
    let unchanged = next(&admitted, &coowner, members.clone(), &[]);
    let jumped = next(&unchanged, &coowner, members, &[]);
    assert!(
        service
            .publish_authority(
                &mut state,
                coowner.credential(),
                &json!({"expected_head":admitted.head_id(),"proof":jumped.call_proof().unwrap()}),
                None
            )
            .is_err()
    );
    service
        .publish_authority(
            &mut state,
            coowner.credential(),
            &json!({"expected_head":admitted.head_id(),"proof":unchanged.call_proof().unwrap()}),
            None,
        )
        .unwrap();
}

use super::*;
use crate::authority::ChatKind;

fn notes(owner: &Device, general: &Authority) -> Authority {
    let root = field(owner.credential.record().body(), "root_public_key")
        .unwrap()
        .to_owned();
    let genesis = SignedRecord::sign(
        &serde_json::to_vec(&SpaceGenesis {
            witness: None,
            v: 3,
            kind: "space.genesis".into(),
            nonce: record::random_hex::<16>().unwrap(),
            issuer_identity: owner.credential.identity(),
            owners: vec![Owner {
                identity_id: owner.credential.identity(),
                root_public_key: root.clone(),
            }],
            controller_credential_id: owner.credential.id(),
        })
        .unwrap(),
        &owner.key,
    )
    .unwrap();
    let stream = crate::notes::stream(
        general.space(),
        general.stream(),
        owner.credential.identity(),
    );
    let mut authority = Authority::new(
        genesis.bytes(),
        SpaceId::from_bytes(*genesis.id().as_bytes()),
        &VerifyingKey::from_bytes(&record::hex(&root).unwrap()).unwrap(),
        owner.credential.clone(),
        stream,
    )
    .unwrap();
    let member = general.head().unwrap().members[0].clone();
    for id in &member.credential_ids {
        authority.add_credential(general.credential(*id).unwrap().clone());
    }
    let config = StreamConfig {
        witness_evidence: None,
        v: 3,
        kind: "stream.config".into(),
        nonce: stream.to_string(),
        space_id: authority.space(),
        stream_id: stream,
        sequence: 1,
        previous_config_id: None,
        controller_credential_id: owner.credential.id(),
        members: vec![member.clone()],
        owner_credential_ids: member.credential_ids,
        action: ConfigAction {
            operation: "create".into(),
            actor_identity: owner.credential.identity(),
            request_record_id: None,
        },
        chat_kind: Some(ChatKind::Direct),
        recovery: None,
    };
    authority
        .apply_config(config.sign(&owner.key).unwrap())
        .unwrap();
    authority
}

#[test]
fn notes_registry_checks_full_ancestry_devices_identity_scope_and_persists_cas() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Device::new();
    let child = owner.child();
    let outsider = Device::new();
    let general = update(&initial(&owner), &owner, Some(&child), None);
    let mut service = PublicSpaceService::create(
        dir.path(),
        general.call_proof().unwrap(),
        &[owner.credential.identity()],
        None,
        true,
        None,
    )
    .unwrap();
    let mut state = service.service_state().unwrap();
    state.applicants.insert(
        owner.credential.id().to_string(),
        Applicant {
            authorization: None,
            identity: owner.credential.identity(),
            name: "Owner".into(),
            status: "approved".into(),
            invitation: String::new(),
            note: String::new(),
            request: team::EnrollmentRequest {
                v: 1,
                contact: String::new(),
                proof: String::new(),
            },
            requested_at: time().unwrap(),
        },
    );
    let original = notes(&owner, &general);
    let proof = original.call_proof().unwrap();
    let body = json!({"general_head":general.head_id(),"proof":proof});
    assert!(
        service
            .notes_command(&mut state, &outsider.credential, &body)
            .is_err()
    );
    assert!(
        crate::notes::verify(&proof, &initial(&owner), owner.credential.identity()).is_err(),
        "different hosting Space"
    );
    assert!(crate::notes::verify(&proof, &general, outsider.credential.identity()).is_err());
    service
        .notes_command(&mut state, &owner.credential, &body)
        .unwrap();
    let unchanged = serde_json::to_value(&state.notes).unwrap();
    assert!(
        service
            .publish_space_call_head(
                &mut state,
                &owner.credential,
                &json!({"space":original.space(),"stream":original.stream(),"proof":proof})
            )
            .is_err()
    );
    let competing = notes(&child, &general);
    let winner = service
        .notes_command(
            &mut state,
            &child.credential,
            &json!({"general_head":general.head_id(),"proof":competing.call_proof().unwrap()}),
        )
        .unwrap();
    assert_eq!(winner["proof"], json!(proof));
    assert_eq!(serde_json::to_value(&state.notes).unwrap(), unchanged);
    assert_eq!(
        state.call_heads.len(),
        1,
        "a losing creation cannot register another private chat"
    );
    let mut next = original.clone();
    let mut config = next.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = next.head_id();
    config.nonce = "98".repeat(16);
    config.action.operation = "device.updated".into();
    next.apply_config(config.sign(&owner.key).unwrap()).unwrap();
    let proposal = json!({"general_head":general.head_id(),"proof":next.call_proof().unwrap()});
    assert!(
        service
            .notes_command(&mut state, &owner.credential, &proposal)
            .is_err(),
        "CAS is mandatory"
    );
    let mut proposal = proposal;
    proposal["expected_head"] = json!(original.head_id());
    service
        .notes_command(&mut state, &owner.credential, &proposal)
        .unwrap();
    assert!(
        service
            .notes_command(&mut state, &owner.credential, &body)
            .is_err(),
        "old complete proof cannot roll back state"
    );
    let mut fork = original.clone();
    let mut config = fork.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = fork.head_id();
    config.nonce = "99".repeat(16);
    config.action.operation = "device.updated".into();
    fork.apply_config(config.sign(&owner.key).unwrap()).unwrap();
    assert!(service.notes_command(&mut state,&owner.credential,&json!({"general_head":general.head_id(),"expected_head":next.head_id(),"proof":fork.call_proof().unwrap()})).is_err());
    state.revoked.insert(child.credential.id());
    assert!(
        service
            .notes_command(
                &mut state,
                &child.credential,
                &json!({"general_head":general.head_id()})
            )
            .is_err()
    );
    let reduced = update(&general, &owner, None, Some(child.credential.id()));
    service.authorities.0[0] = reduced.clone();
    assert!(
        crate::notes::verify(
            &next.call_proof().unwrap(),
            &reduced,
            owner.credential.identity()
        )
        .is_err(),
        "stale recipient set is unusable after revocation"
    );
    let mut narrowed = next.clone();
    let mut config = narrowed.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = narrowed.head_id();
    config.nonce = "97".repeat(16);
    config.action.operation = "device.updated".into();
    config.members[0].credential_ids = vec![owner.credential.id()];
    config.owner_credential_ids = vec![owner.credential.id()];
    narrowed
        .apply_config(config.sign(&owner.key).unwrap())
        .unwrap();
    service.notes_command(&mut state,&owner.credential,&json!({"general_head":reduced.head_id(),"expected_head":next.head_id(),"proof":narrowed.call_proof().unwrap()})).unwrap();
    state.proof = reduced.call_proof().unwrap();
    service.save_service_state(&state).unwrap();
    drop(service);
    let reopened = PublicSpaceService::open(dir.path(), true).unwrap();
    assert_eq!(
        reopened.service_state().unwrap().notes[&owner.credential.identity()]
            .configs
            .len(),
        3
    );
    let after = crate::notes::verify(
        &narrowed.call_proof().unwrap(),
        &reduced,
        owner.credential.identity(),
    )
    .unwrap();
    assert!(
        !after.head().unwrap().members[0]
            .credential_ids
            .contains(&child.credential.id())
    );
}

use elo_core::{
    authority::{
        Authority, Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig,
    },
    calls::{self, CallKind, InitialMedia, Operation, SignalPayload},
    ids::{RecordId, SpaceId, StreamId},
    record::{SignedRecord, encode_hex, random_hex},
    vault::{RecoveryCard, Session},
};

const AUDIENCE: &str = "https://calls.example.test/calls/v1";
const NOW: u64 = 1_800_000_000;

fn member(session: &Session, post: bool) -> Member {
    Member {
        identity_id: session.identity_id(),
        identity_type: "HUMAN".into(),
        root_public_key: session.credential().record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into(),
        capabilities: if post {
            vec![Capability::Read, Capability::Post]
        } else {
            vec![Capability::Read]
        },
        credential_ids: vec![session.credential().id()],
        external: false,
    }
}

fn authority(owner: &Session, card: &RecoveryCard, people: &[(&Session, bool)]) -> Authority {
    let root = card.recover_root(owner.identity_id()).unwrap();
    let genesis = SpaceGenesis {
        v: 1,
        kind: "space.genesis".into(),
        nonce: random_hex::<16>().unwrap(),
        issuer_identity: owner.identity_id(),
        owners: vec![Owner {
            identity_id: owner.identity_id(),
            root_public_key: encode_hex(root.verifying_key().as_bytes()),
        }],
        controller_credential_id: owner.credential().id(),
    };
    let record = SignedRecord::sign(&serde_json::to_vec(&genesis).unwrap(), &root).unwrap();
    let mut a = Authority::new(
        record.bytes(),
        record.id().to_string().parse().unwrap(),
        &root.verifying_key(),
        owner.credential().clone(),
        StreamId::from_bytes([7; 16]),
    )
    .unwrap();
    let mut members = people
        .iter()
        .map(|(person, post)| member(person, *post))
        .collect::<Vec<_>>();
    members
        .iter_mut()
        .find(|m| m.identity_id == owner.identity_id())
        .unwrap()
        .capabilities = vec![
        Capability::Read,
        Capability::Post,
        Capability::ShareHistory,
        Capability::Manage,
    ];
    members.sort_by_key(|m| m.identity_id);
    for (person, _) in people {
        a.add_credential(person.credential().clone());
    }
    let config = StreamConfig {
        v: 1,
        kind: "stream.config".into(),
        nonce: random_hex::<16>().unwrap(),
        space_id: a.space(),
        stream_id: a.stream(),
        sequence: 1,
        previous_config_id: None,
        controller_credential_id: owner.credential().id(),
        members,
        owner_credential_ids: vec![owner.credential().id()],
        action: ConfigAction {
            operation: "create".into(),
            actor_identity: owner.identity_id(),
            request_record_id: None,
        },
        chat_kind: Some(ChatKind::Chat),
        recovery: None,
    };
    a.apply_config(config.sign(owner.signing_key()).unwrap())
        .unwrap();
    a
}

#[test]
fn commands_bind_audience_scope_head_device_expiry_and_operation() {
    let (owner, card) = Session::create().unwrap();
    let peer = Session::create().unwrap().0;
    let reader = Session::create().unwrap().0;
    let a = authority(
        &owner,
        &card,
        &[(&owner, true), (&peer, true), (&reader, false)],
    );
    let op = Operation::Start {
        kind: CallKind::Group,
        initial_media: InitialMedia::Audio,
    };
    let signed = calls::sign_command(&a, &peer, a.space(), AUDIENCE, op.clone(), NOW).unwrap();
    let command = calls::verify_command(&a, &signed, AUDIENCE, NOW).unwrap();
    assert_eq!(command.credential_id, peer.credential().id());
    assert!(calls::verify_command(&a, &signed, "https://other.example.test", NOW).is_err());
    assert!(calls::verify_command(&a, &signed, AUDIENCE, NOW + 60).is_err());
    assert!(calls::verify_command(&a, &signed, AUDIENCE, NOW - 16).is_err());
    assert!(calls::sign_command(&a, &reader, a.space(), AUDIENCE, op, NOW).is_err());
    assert!(
        calls::sign_command(
            &a,
            &Session::create().unwrap().0,
            a.space(),
            AUDIENCE,
            Operation::Subscribe,
            NOW
        )
        .is_err()
    );
    for (name, value) in [
        (
            "config_id",
            serde_json::json!(RecordId::from_bytes([9; 32])),
        ),
        ("credential_id", serde_json::json!(owner.credential().id())),
        ("expires_at", serde_json::json!(NOW + 61)),
        ("kind", serde_json::json!("notification.sender")),
        (
            "operation",
            serde_json::json!({"type":"join","call_id":"../bad"}),
        ),
        (
            "scope",
            serde_json::json!({"space_id":SpaceId::from_bytes([1;32]),"stream_id":a.stream()}),
        ),
    ] {
        let mut body = signed.body().clone();
        body[name] = value;
        let forged =
            SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), peer.signing_key()).unwrap();
        assert!(
            calls::verify_command(&a, &forged, AUDIENCE, NOW).is_err(),
            "{name}"
        );
    }
}

#[test]
fn proof_roundtrip_is_content_addressed_and_rejects_substitution_or_incomplete_chain() {
    let (owner, card) = Session::create().unwrap();
    let peer = Session::create().unwrap().0;
    let mut a = authority(&owner, &card, &[(&owner, true), (&peer, true)]);
    let mut next = a.head().unwrap().clone();
    next.sequence += 1;
    next.previous_config_id = a.head_id();
    next.nonce = random_hex::<16>().unwrap();
    next.action.operation = "replace".into();
    a.apply_config(next.sign(owner.signing_key()).unwrap())
        .unwrap();
    let proof = a.call_proof().unwrap();
    let copy = proof.verify(a.space(), a.stream()).unwrap();
    assert_eq!(copy.head_id(), a.head_id());
    assert!(
        proof
            .verify(SpaceId::from_bytes([1; 32]), a.stream())
            .is_err()
    );
    assert!(
        proof
            .verify(a.space(), StreamId::from_bytes([2; 16]))
            .is_err()
    );
    let mut missing = proof.clone();
    missing.configs.remove(0);
    assert!(missing.verify(a.space(), a.stream()).is_err());
    let mut duplicate = proof.clone();
    duplicate.credentials.push(duplicate.credentials[0].clone());
    assert!(duplicate.verify(a.space(), a.stream()).is_err());
    let mut forged = proof;
    forged.genesis = "invalid".into();
    assert!(forged.verify(a.space(), a.stream()).is_err());
}

#[test]
fn encrypted_signal_requires_recipient_current_membership_call_and_signature() {
    let (owner, card) = Session::create().unwrap();
    let peer = Session::create().unwrap().0;
    let outsider = Session::create().unwrap().0;
    let mut a = authority(&owner, &card, &[(&owner, true), (&peer, true)]);
    let call = random_hex::<16>().unwrap();
    let key = random_hex::<32>().unwrap();
    let ciphertext = calls::seal_signal(
        &a,
        &owner,
        &call,
        peer.credential().id(),
        SignalPayload::MediaKey {
            epoch: 1,
            key: key.clone(),
        },
        NOW,
    )
    .unwrap();
    assert!(!ciphertext.contains(&key));
    let signal = calls::open_signal(&a, &peer, &call, &ciphertext, NOW).unwrap();
    assert_eq!(signal.from, owner.credential().id());
    match signal.payload {
        SignalPayload::MediaKey { epoch, key: got } => {
            assert_eq!(epoch, 1);
            assert_eq!(got, key);
        }
        _ => panic!("wrong payload"),
    }
    assert!(calls::open_signal(&a, &owner, &call, &ciphertext, NOW).is_err());
    assert!(calls::open_signal(&a, &outsider, &call, &ciphertext, NOW).is_err());
    assert!(calls::open_signal(&a, &peer, &random_hex::<16>().unwrap(), &ciphertext, NOW).is_err());
    assert!(calls::open_signal(&a, &peer, &call, &ciphertext, NOW + 60).is_err());
    let command =
        calls::sign_command(&a, &peer, a.space(), AUDIENCE, Operation::Subscribe, NOW).unwrap();
    let mut next = a.head().unwrap().clone();
    next.members.retain(|m| m.identity_id != peer.identity_id());
    next.sequence += 1;
    next.previous_config_id = a.head_id();
    next.nonce = random_hex::<16>().unwrap();
    next.action.operation = "replace".into();
    a.apply_config(next.sign(owner.signing_key()).unwrap())
        .unwrap();
    assert!(calls::verify_command(&a, &command, AUDIENCE, NOW).is_err());
    assert!(calls::open_signal(&a, &peer, &call, &ciphertext, NOW).is_err());
    assert!(
        calls::seal_signal(
            &a,
            &owner,
            &call,
            peer.credential().id(),
            SignalPayload::Offer { sdp: "v=0".into() },
            NOW
        )
        .is_err()
    );
}

#[test]
fn signalling_payloads_are_bounded_and_do_not_accept_invalid_key_epochs() {
    let (owner, card) = Session::create().unwrap();
    let peer = Session::create().unwrap().0;
    let a = authority(&owner, &card, &[(&owner, true), (&peer, true)]);
    let call = random_hex::<16>().unwrap();
    for payload in [
        SignalPayload::MediaKey {
            epoch: 0,
            key: "a".repeat(64),
        },
        SignalPayload::MediaKey {
            epoch: 1,
            key: "short".into(),
        },
        SignalPayload::RequestKey { epoch: 0 },
        SignalPayload::Offer {
            sdp: "x".repeat(49 * 1024),
        },
        SignalPayload::Answer { sdp: "".into() },
        SignalPayload::Ice {
            candidate: "x".repeat(4097),
            sdp_mid: None,
            sdp_mline_index: None,
        },
    ] {
        assert!(
            calls::seal_signal(&a, &owner, &call, peer.credential().id(), payload, NOW).is_err()
        );
    }
}

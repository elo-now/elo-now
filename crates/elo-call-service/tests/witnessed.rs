mod support;
use elo_call_service::{engine::Engine, registry::Limits};
use elo_core::{
    authority::WitnessPin,
    calls::{CallKind, InitialMedia, Operation},
    record::encode_hex,
};
use support::{AUDIENCE, Fixture, NOW};

fn pin() -> WitnessPin {
    WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: encode_hex(
            ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                .verifying_key()
                .as_bytes(),
        ),
        key_generation: 1,
    }
}

#[test]
fn witnessed_general_requires_the_external_deployment_pin() {
    let correct = pin();
    let f = Fixture::with_witness(false, Some(correct.clone()));
    let mut wrong_key = correct.clone();
    wrong_key.public_key = encode_hex(
        ed25519_dalek::SigningKey::from_bytes(&[18; 32])
            .verifying_key()
            .as_bytes(),
    );
    let mut wrong_origin = correct.clone();
    wrong_origin.url = "https://other.example.test/witness/v1".into();
    let mut wrong_generation = correct.clone();
    wrong_generation.key_generation += 1;
    for configured in [
        None,
        Some(wrong_key),
        Some(wrong_origin),
        Some(wrong_generation),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open_with_witness(
            &dir.path().join("calls.sqlite"),
            AUDIENCE.into(),
            Limits::default(),
            configured,
        )
        .unwrap();
        let request = f.request(&f.owner, Operation::Subscribe, NOW, true);
        // Device authorship alone does not establish the witness trust root.
        let job = engine.preparation(request, None).unwrap();
        assert!(job.authenticate(NOW).is_ok());
        assert!(job.verify(NOW).is_err());
    }
}

#[test]
fn witnessed_general_starts_joins_and_reloads_with_a_pinned_proof() {
    let f = Fixture::with_witness(false, Some(pin()));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calls.sqlite");
    let mut engine =
        Engine::open_with_witness(&path, AUDIENCE.into(), Limits::default(), Some(pin())).unwrap();
    let start = f.request(
        &f.owner,
        Operation::Start {
            kind: CallKind::Group,
            initial_media: InitialMedia::Audio,
        },
        NOW,
        true,
    );
    let prepared = engine.prepare(start, None, NOW).unwrap();
    let call_id = engine.execute(prepared, NOW).unwrap().call.unwrap().call_id;
    let join = f.request(
        &f.peer,
        Operation::Join {
            call_id,
            invitation_id: None,
        },
        NOW + 1,
        true,
    );
    let prepared = engine.prepare(join, None, NOW + 1).unwrap();
    assert_eq!(
        engine
            .execute(prepared, NOW + 1)
            .unwrap()
            .call
            .unwrap()
            .participants
            .len(),
        2
    );
    let cached = f.request(&f.owner, Operation::Subscribe, NOW + 2, false);
    assert!(engine.prepare(cached, None, NOW + 2).is_ok());
    drop(engine);
    let engine =
        Engine::open_with_witness(&path, AUDIENCE.into(), Limits::default(), Some(pin())).unwrap();
    assert!(
        engine
            .prepare(
                f.request(&f.owner, Operation::Subscribe, NOW + 3, true),
                None,
                NOW + 3
            )
            .is_ok()
    );
}

#[test]
fn configured_witness_still_allows_ordinary_private_chats() {
    let f = Fixture::new(true);
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open_with_witness(
        &dir.path().join("calls.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
        Some(pin()),
    )
    .unwrap();
    assert!(
        engine
            .prepare(
                f.request(&f.owner, Operation::Subscribe, NOW, true),
                None,
                NOW
            )
            .is_ok()
    );
}

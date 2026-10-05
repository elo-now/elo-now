use super::*;
use tempfile::TempDir;

const NOW: u64 = 1_800_000_000_000;

struct Fixture {
    directory: TempDir,
    journal: Journal,
    space: SpaceId,
    head: RecordId,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[5; 32]);
        let key_path = directory.path().join("key");
        elo_core::vault::write_private(&key_path, &key.to_bytes(), false).unwrap();
        let pin = WitnessPin {
            url: "https://witness.example.test/witness/v1".into(),
            public_key: record::encode_hex(key.verifying_key().as_bytes()),
            key_generation: 1,
        };
        let mut journal =
            Journal::open(&directory.path().join("data"), &key_path, pin, NOW).unwrap();
        let space = SpaceId::from_bytes([7; 32]);
        let head = RecordId::from_bytes([8; 32]);
        // Journal integrity is independent of the authority verifier: these
        // opaque values stand for already verified records at this layer.
        let tx = journal.db.transaction().unwrap();
        tx.execute(
            "INSERT INTO spaces(space,stream,proof) VALUES(?1,'stream','current proof')",
            [space.to_string()],
        )
        .unwrap();
        tx.execute("INSERT INTO policies(space,id,record,revoked,uses) VALUES(?1,'policy','signed policy',1,1)", [space.to_string()]).unwrap();
        tx.execute("INSERT INTO challenges(id,space,policy,credential,record,expires,intent) VALUES('challenge',?1,'policy','credential','signed challenge',?2,'used intent')", params![space.to_string(), (NOW + 1_000) as i64]).unwrap();
        tx.execute("INSERT INTO tombstones(space,credential,identity) VALUES(?1,'removed credential','removed identity')", [space.to_string()]).unwrap();
        append(
            &tx,
            &journal.key,
            &journal.pin,
            Event {
                request: RecordId::from_bytes([9; 32]),
                space,
                head,
                name: "device.admitted",
                now: NOW,
            },
            Response {
                receipt: None,
                proof: None,
                challenge: None,
            },
        )
        .unwrap();
        tx.commit().unwrap();
        verify_materialized(&journal.db, &journal.pin).unwrap();
        Self {
            directory,
            journal,
            space,
            head,
        }
    }

    fn activation(&self) -> Activation {
        let startup = self.journal.startup().unwrap();
        Activation {
            startup_nonce: startup.startup_nonce,
            expected_position: startup.observed_position,
            public_key: startup.public_key,
            key_generation: startup.key_generation,
            expires_at_ms: NOW + 1_000,
        }
    }
}

#[test]
fn partial_restore_of_any_authority_table_is_rejected_despite_current_receipts() {
    for restore in [
        "UPDATE spaces SET proof='old proof'",
        "UPDATE policies SET revoked=0",
        "UPDATE policies SET uses=0",
        "UPDATE challenges SET intent=NULL",
        "UPDATE challenges SET expires=expires+1000",
        "DELETE FROM tombstones",
        "DELETE FROM spaces",
    ] {
        let mut fixture = Fixture::new();
        let activation = fixture.activation();
        let position_before = position(&fixture.journal.db).unwrap();
        fixture.journal.db.execute(restore, []).unwrap();
        assert_eq!(position(&fixture.journal.db).unwrap(), position_before);
        assert!(
            verify_materialized_space(&fixture.journal.db, fixture.space, &fixture.journal.pin)
                .is_err(),
            "{restore}"
        );
        assert!(
            fixture.journal.activate(activation, NOW).is_err(),
            "{restore}"
        );
        let path = fixture.directory.path().to_path_buf();
        let pin = fixture.journal.pin.clone();
        drop(fixture.journal);
        assert!(
            Journal::open(&path.join("data"), &path.join("key"), pin, NOW).is_err(),
            "{restore}"
        );
    }
}

#[test]
fn digest_is_signed_with_the_transaction_and_rollback_keeps_the_old_snapshot() {
    let mut fixture = Fixture::new();
    let prior = position(&fixture.journal.db).unwrap();
    let prior_digest = state_digest(&fixture.journal.db, fixture.space).unwrap();
    let tx = fixture.journal.db.transaction().unwrap();
    tx.execute("UPDATE policies SET uses=uses+1", []).unwrap();
    let response = append(
        &tx,
        &fixture.journal.key,
        &fixture.journal.pin,
        Event {
            request: RecordId::from_bytes([10; 32]),
            space: fixture.space,
            head: fixture.head,
            name: "device.admitted",
            now: NOW,
        },
        Response {
            receipt: None,
            proof: None,
            challenge: None,
        },
    )
    .unwrap();
    let signed = decode(response.receipt.as_ref().unwrap()).unwrap();
    signed
        .verify_signature(&fixture.journal.pin.key().unwrap())
        .unwrap();
    let receipt: Receipt = signed.decode().unwrap();
    assert_ne!(receipt.state_digest, prior_digest);
    assert_eq!(
        receipt.state_digest,
        state_digest(&tx, fixture.space).unwrap()
    );
    verify_materialized_space(&tx, fixture.space, &fixture.journal.pin).unwrap();
    tx.rollback().unwrap();
    assert_eq!(position(&fixture.journal.db).unwrap(), prior);
    assert_eq!(
        state_digest(&fixture.journal.db, fixture.space).unwrap(),
        prior_digest
    );
    verify_materialized_space(&fixture.journal.db, fixture.space, &fixture.journal.pin).unwrap();
}

#[test]
fn canonical_digest_ignores_row_insertion_order_but_preserves_types_and_boundaries() {
    let mut fixture = Fixture::new();
    let space = fixture.space.to_string();
    fixture.journal.db.execute("INSERT INTO policies(space,id,record,revoked,uses) VALUES(?1,'a','one',0,0), (?1,'z','two',0,0)", [&space]).unwrap();
    let ordered = state_digest(&fixture.journal.db, fixture.space).unwrap();
    let tx = fixture.journal.db.transaction().unwrap();
    tx.execute("DELETE FROM policies WHERE id IN ('a','z')", [])
        .unwrap();
    tx.execute("INSERT INTO policies(space,id,record,revoked,uses) VALUES(?1,'z','two',0,0), (?1,'a','one',0,0)", [&space]).unwrap();
    assert_eq!(state_digest(&tx, fixture.space).unwrap(), ordered);
    tx.execute(
        "UPDATE policies SET record=record||char(0) WHERE id='a'",
        [],
    )
    .unwrap();
    assert_ne!(state_digest(&tx, fixture.space).unwrap(), ordered);
    tx.rollback().unwrap();
}

#[test]
fn state_without_a_signed_receipt_cannot_be_activated() {
    let mut fixture = Fixture::new();
    let activation = fixture.activation();
    fixture
        .journal
        .db
        .execute(
            "INSERT INTO tombstones(space,credential,identity) VALUES(?1,'orphan','orphan')",
            [SpaceId::from_bytes([11; 32]).to_string()],
        )
        .unwrap();
    assert!(fixture.journal.activate(activation, NOW).is_err());
}

#[test]
fn unchanged_materialized_snapshot_reopens_but_still_requires_activation() {
    let fixture = Fixture::new();
    let expected = position(&fixture.journal.db).unwrap();
    let path = fixture.directory.path().to_path_buf();
    let pin = fixture.journal.pin.clone();
    drop(fixture.journal);
    let mut journal = Journal::open(&path.join("data"), &path.join("key"), pin, NOW).unwrap();
    assert!(!journal.ready(NOW));
    let startup = journal.startup().unwrap();
    journal
        .activate(
            Activation {
                startup_nonce: startup.startup_nonce,
                expected_position: expected,
                public_key: startup.public_key,
                key_generation: startup.key_generation,
                expires_at_ms: NOW + 1000,
            },
            NOW,
        )
        .unwrap();
    assert!(journal.ready(NOW));
}

#[test]
fn a_frozen_or_rolled_back_clock_seals_the_process_without_automatic_reactivation() {
    for frozen in [false, true] {
        let mut fixture = Fixture::new();
        fixture.journal.activate(fixture.activation(), NOW).unwrap();
        if frozen {
            // Simulate monotonic elapsed time without waiting in the test.
            // Repeated requests must not reset the original wall-clock anchor.
            fixture.journal.monotonic = Instant::now() - std::time::Duration::from_secs(4);
            assert!(fixture.journal.ready(NOW));
            fixture.journal.monotonic = Instant::now() - std::time::Duration::from_secs(6);
            assert!(!fixture.journal.ready(NOW));
        } else {
            assert!(!fixture.journal.ready(NOW - 1));
        }
        assert!(!fixture.journal.ready(NOW));
        assert!(fixture.journal.activate(fixture.activation(), NOW).is_err());
    }
}

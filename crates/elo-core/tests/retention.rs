mod common;
use common::*;
use elo_core::retention_access::{Context, Operation, Proof, public_key};
use elo_core::{
    crypto,
    erasure::{self, RetentionClaim},
    ids::{ObjectId, RecordId},
    replica::{
        ChildMailbox, MailboxDescriptor, ReplicaError, ReplicaStore, TransferHint, VerifiedPruned,
    },
    store::{ClientStore, DeliveryTarget, LocalTime, PreparedLocalRecord, RecordMetadata},
    sync::SyncClient,
    vault::Session,
};
use rusqlite::Connection;
const REQUEST_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ACCEPT_SECRET: &str = "2222222222222222222222222222222222222222222222222222222222222222";
fn proof(
    replica: &ReplicaStore,
    mailbox: elo_core::ids::MailboxId,
    session: &Session,
    object: ObjectId,
    record: RecordId,
    accept: bool,
) -> Proof {
    let context = Context {
        operation: if accept {
            Operation::Accept
        } else {
            Operation::Request
        },
        replica: replica.peer_id(),
        mailbox,
        object,
        record,
        actor: session.credential().into(),
    };
    Proof::issue(
        if accept {
            ACCEPT_SECRET
        } else {
            REQUEST_SECRET
        },
        &context,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    )
    .unwrap()
}

fn time(n: u64) -> LocalTime {
    LocalTime::from_millis(n).unwrap()
}

fn retained_object(
    session: &Session,
    ciphertext: Vec<u8>,
    subjects: Vec<elo_core::ids::IdentityId>,
    retention: RetentionClaim,
) -> Vec<u8> {
    erasure::wrap_subjects_with_retention(
        ciphertext,
        session.credential(),
        session.signing_key(),
        subjects,
        Some(retention),
    )
    .unwrap()
}

#[tokio::test]
async fn expired_body_requires_request_and_can_be_refilled_for_five_minutes() {
    let dir = tempfile::tempdir().unwrap();
    let replica = ReplicaStore::open(dir.path()).await.unwrap();
    let mailbox = replica.create_mailbox(100_000).await.unwrap();
    let alice = Session::create().unwrap().0;
    let bob = Session::create().unwrap().0;
    replica
        .set_space_members(
            mailbox.mailbox_id,
            vec![alice.identity_id(), bob.identity_id()],
        )
        .await
        .unwrap();
    let record = RecordId::from_bytes([31; 32]);
    let nonce = "01010101010101010101010101010101".to_string();
    let subjects = vec![alice.identity_id(), bob.identity_id()];
    let body = retained_object(
        &alice,
        b"encrypted message body".to_vec(),
        subjects.clone(),
        RetentionClaim::MessageBody {
            locator_nonce: nonce.clone(),
            record_id: record,
            lifetime_seconds: 21_600,
            direct_peer: None,
            request_key: public_key(REQUEST_SECRET).unwrap(),
            accept_key: None,
        },
    );
    let body_id = ObjectId::of_ciphertext(&body);
    let locator = retained_object(
        &alice,
        b"encrypted message locator".to_vec(),
        subjects,
        RetentionClaim::MessageLocator {
            locator_nonce: nonce,
            body_object_id: body_id,
            record_id: record,
            lifetime_seconds: 21_600,
            request_key: public_key(REQUEST_SECRET).unwrap(),
        },
    );
    let locator_id = ObjectId::of_ciphertext(&locator);
    for (id, bytes) in [(locator_id, locator), (body_id, body.clone())] {
        replica
            .post_authenticated(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                id,
                bytes,
                TransferHint::Eager,
                true,
                Some(alice.credential().into()),
            )
            .await
            .unwrap();
    }
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    raw.execute(
        "UPDATE message_bodies SET expires_local_ms=received_local_ms WHERE object_id=?1",
        [body_id.to_string()],
    )
    .unwrap();
    replica.maintain_message_lifetime().await.unwrap();
    assert!(matches!(
        replica
            .get(mailbox.mailbox_id, mailbox.read_token.clone(), body_id)
            .await,
        Err(ReplicaError::NotFound)
    ));
    assert_eq!(
        replica
            .get(mailbox.mailbox_id, mailbox.read_token.clone(), locator_id)
            .await
            .unwrap(),
        erasure::wrap_subjects_with_retention(
            b"encrypted message locator".to_vec(),
            alice.credential(),
            alice.signing_key(),
            vec![alice.identity_id(), bob.identity_id()],
            Some(RetentionClaim::MessageLocator {
                locator_nonce: "01010101010101010101010101010101".into(),
                body_object_id: body_id,
                record_id: record,
                lifetime_seconds: 21_600,
                request_key: public_key(REQUEST_SECRET).unwrap(),
            }),
        )
        .unwrap()
    );
    assert!(matches!(
        replica
            .post_authenticated(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                body_id,
                body.clone(),
                TransferHint::Eager,
                true,
                Some(bob.credential().into()),
            )
            .await,
        Err(ReplicaError::Expired)
    ));
    replica
        .request_message(
            mailbox.mailbox_id,
            bob.credential().into(),
            body_id,
            record,
            proof(&replica, mailbox.mailbox_id, &bob, body_id, record, false),
        )
        .await
        .unwrap();
    assert_eq!(
        replica
            .inventory(mailbox.mailbox_id, mailbox.read_token.clone(), 0, 128)
            .await
            .unwrap()
            .requested_messages,
        vec![body_id]
    );
    replica
        .set_space_members(mailbox.mailbox_id, vec![alice.identity_id()])
        .await
        .unwrap();
    assert!(
        replica
            .inventory(mailbox.mailbox_id, mailbox.read_token.clone(), 0, 128)
            .await
            .unwrap()
            .requested_messages
            .is_empty()
    );
    replica
        .set_space_members(
            mailbox.mailbox_id,
            vec![alice.identity_id(), bob.identity_id()],
        )
        .await
        .unwrap();
    replica
        .request_message(
            mailbox.mailbox_id,
            bob.credential().into(),
            body_id,
            record,
            proof(&replica, mailbox.mailbox_id, &bob, body_id, record, false),
        )
        .await
        .unwrap();
    replica
        .post_authenticated(
            mailbox.mailbox_id,
            mailbox.write_token.clone(),
            body_id,
            body.clone(),
            TransferHint::Eager,
            true,
            Some(bob.credential().into()),
        )
        .await
        .unwrap();
    assert_eq!(
        replica
            .get(mailbox.mailbox_id, mailbox.read_token, body_id)
            .await
            .unwrap(),
        body
    );
}

#[tokio::test]
async fn direct_peer_acceptance_removes_only_the_body() {
    let dir = tempfile::tempdir().unwrap();
    let replica = ReplicaStore::open(dir.path()).await.unwrap();
    let mailbox = replica.create_mailbox(100_000).await.unwrap();
    let alice = Session::create().unwrap().0;
    let bob = Session::create().unwrap().0;
    let record = RecordId::from_bytes([32; 32]);
    let nonce = "02020202020202020202020202020202".to_string();
    let subjects = vec![alice.identity_id(), bob.identity_id()];
    let body = retained_object(
        &alice,
        b"direct encrypted body".to_vec(),
        subjects.clone(),
        RetentionClaim::MessageBody {
            locator_nonce: nonce.clone(),
            record_id: record,
            lifetime_seconds: 86_400,
            direct_peer: Some(bob.identity_id()),
            request_key: public_key(REQUEST_SECRET).unwrap(),
            accept_key: Some(public_key(ACCEPT_SECRET).unwrap()),
        },
    );
    let body_id = ObjectId::of_ciphertext(&body);
    let locator = retained_object(
        &alice,
        b"direct encrypted locator".to_vec(),
        subjects,
        RetentionClaim::MessageLocator {
            locator_nonce: nonce,
            body_object_id: body_id,
            record_id: record,
            lifetime_seconds: 86_400,
            request_key: public_key(REQUEST_SECRET).unwrap(),
        },
    );
    let locator_id = ObjectId::of_ciphertext(&locator);
    for (id, bytes) in [(locator_id, locator.clone()), (body_id, body)] {
        replica
            .post_authenticated(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                id,
                bytes,
                TransferHint::Eager,
                true,
                Some(alice.credential().into()),
            )
            .await
            .unwrap();
    }
    assert!(matches!(
        replica
            .accept_message(
                mailbox.mailbox_id,
                alice.credential().into(),
                body_id,
                record,
                proof(&replica, mailbox.mailbox_id, &alice, body_id, record, true)
            )
            .await,
        Err(ReplicaError::Unauthorized)
    ));
    replica
        .accept_message(
            mailbox.mailbox_id,
            bob.credential().into(),
            body_id,
            record,
            proof(&replica, mailbox.mailbox_id, &bob, body_id, record, true),
        )
        .await
        .unwrap();
    assert!(matches!(
        replica
            .get(mailbox.mailbox_id, mailbox.read_token.clone(), body_id)
            .await,
        Err(ReplicaError::NotFound)
    ));
    assert_eq!(
        replica
            .get(mailbox.mailbox_id, mailbox.read_token, locator_id)
            .await
            .unwrap(),
        locator
    );
}

#[tokio::test]
async fn pruning_is_scoped_preserves_control_and_new_copies_and_blocks_resurrection() {
    let dir = tempfile::tempdir().unwrap();
    let replica = ReplicaStore::open(dir.path()).await.unwrap();
    let a = replica.create_mailbox(100_000).await.unwrap();
    let b = replica.create_mailbox(100_000).await.unwrap();
    let child = ChildMailbox {
        descriptor: MailboxDescriptor::random().unwrap(),
        quota_bytes: 10_000,
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 600_000,
    };
    replica
        .create_child(a.mailbox_id, a.write_token.clone(), child.clone())
        .await
        .unwrap();
    let old = b"PUBLIC OLD MESSAGE COPY".to_vec();
    let id = ObjectId::of_ciphertext(&old);
    let protected = b"PUBLIC CONTROL COPY".to_vec();
    let protected_id = ObjectId::of_ciphertext(&protected);
    for (mailbox, bytes, message) in [
        (&a, old.clone(), true),
        (&b, old.clone(), true),
        (&child.descriptor, old.clone(), true),
        (&a, protected.clone(), false),
    ] {
        replica
            .post_classified(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                ObjectId::of_ciphertext(&bytes),
                bytes,
                TransferHint::Eager,
                message,
            )
            .await
            .unwrap();
    }
    // A duplicate request cannot turn a pre-existing control object into a message.
    replica
        .post_classified(
            a.mailbox_id,
            a.write_token.clone(),
            protected_id,
            protected.clone(),
            TransferHint::Eager,
            true,
        )
        .await
        .unwrap();
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    raw.execute("UPDATE message_copies SET stored_local_ms=0", [])
        .unwrap();
    let recent = b"PUBLIC NEW MESSAGE COPY".to_vec();
    let recent_id = ObjectId::of_ciphertext(&recent);
    replica
        .post_classified(
            a.mailbox_id,
            a.write_token.clone(),
            recent_id,
            recent.clone(),
            TransferHint::Eager,
            true,
        )
        .await
        .unwrap();
    let preview = replica.space_storage(a.mailbox_id, 1).await.unwrap();
    assert_eq!(preview.removable_copies, 2);
    assert_eq!(preview.removable_bytes, old.len() as u64 * 2);
    assert_eq!(
        replica
            .prune_messages(a.mailbox_id, 1)
            .await
            .unwrap()
            .removable_bytes,
        preview.removable_bytes
    );
    assert_eq!(
        replica
            .space_storage(a.mailbox_id, 1)
            .await
            .unwrap()
            .used_bytes,
        preview.used_bytes - preview.removable_bytes
    );
    assert_eq!(
        replica
            .get(a.mailbox_id, a.read_token.clone(), protected_id)
            .await
            .unwrap(),
        protected
    );
    assert_eq!(
        replica
            .get(a.mailbox_id, a.read_token.clone(), recent_id)
            .await
            .unwrap(),
        recent
    );
    assert_eq!(
        replica
            .get(b.mailbox_id, b.read_token.clone(), id)
            .await
            .unwrap(),
        old
    );
    assert_eq!(
        replica
            .prune_messages(a.mailbox_id, 1)
            .await
            .unwrap()
            .removable_copies,
        0
    );
    let key = *replica.key();
    drop(raw);
    drop(replica);
    let replica = ReplicaStore::open(dir.path()).await.unwrap();
    for mailbox in [&a, &child.descriptor] {
        let Err(ReplicaError::Pruned(proof)) = replica
            .post(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                id,
                old.clone(),
                TransferHint::Eager,
            )
            .await
        else {
            panic!("pruned ciphertext was accepted")
        };
        VerifiedPruned::verify(&proof, &key, mailbox.mailbox_id, id).unwrap();
        assert!(VerifiedPruned::verify(&proof, &key, b.mailbox_id, id).is_err());
        assert!(VerifiedPruned::verify(&proof, &key, mailbox.mailbox_id, recent_id).is_err());
        assert!(
            VerifiedPruned::verify(
                &proof,
                &person(70).key.verifying_key(),
                mailbox.mailbox_id,
                id
            )
            .is_err()
        );
        assert!(matches!(
            replica
                .get(mailbox.mailbox_id, mailbox.read_token.clone(), id)
                .await,
            Err(ReplicaError::Pruned(_))
        ));
    }
    replica.delete_mailbox_tree(a.mailbox_id).await.unwrap();
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    assert_eq!(
        raw.query_row::<i64, _, _>("SELECT COUNT(*) FROM pruned_objects", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        replica.get(b.mailbox_id, b.read_token, id).await.unwrap(),
        old
    );
}

#[tokio::test]
async fn quota_retry_and_pruned_http_proof_preserve_history_even_after_old_backup_restore() {
    let alice = person(21);
    let authority = authority(&[&alice]);
    let record = message(&alice, &authority);
    let bytes = crypto::seal_chat(
        &record,
        &authority.credentials.values().cloned().collect::<Vec<_>>(),
    )
    .unwrap();
    let id = ObjectId::of_ciphertext(&bytes);
    let remote = tempfile::tempdir().unwrap();
    let replica = ReplicaStore::open(remote.path()).await.unwrap();
    let mailbox = replica
        .create_mailbox((bytes.len() - 1) as u64)
        .await
        .unwrap();
    let (url, server) = server(replica.clone()).await;
    let peers = [peer(&url, &replica, &mailbox, true, true)];
    let local = tempfile::tempdir().unwrap();
    let store = ClientStore::open(local.path()).await.unwrap();
    store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                record.id(),
                bytes.clone(),
                RecordMetadata::new(
                    "chat.message",
                    Some(authority.space),
                    Some(authority.stream),
                    Some(authority.config),
                )
                .unwrap(),
                vec![DeliveryTarget {
                    peer_id: replica.peer_id(),
                    mailbox_id: mailbox.mailbox_id,
                }],
                time(100),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let sync = SyncClient {
        store: &store,
        identity: &alice.age,
        credential: alice.credential.id(),
        authority: &authority,
        peers: &peers,
    };
    let full = sync.once(time(100)).await.unwrap();
    assert_eq!(full.quota_exceeded, 1);
    assert_eq!(full.retry, 1);
    assert_eq!(store.get_object(id).await.unwrap(), Some(bytes.clone()));
    let queued_backup = store.message_backup_image(4 * 1024 * 1024).await.unwrap();
    let raw = Connection::open(remote.path().join("replica.sqlite")).unwrap();
    raw.execute("UPDATE mailboxes SET quota_bytes=100000", [])
        .unwrap();
    assert_eq!(sync.once(time(100_000)).await.unwrap().stored, 1);
    let old_backup = store.message_backup_image(4 * 1024 * 1024).await.unwrap();
    raw.execute("UPDATE message_copies SET stored_local_ms=0", [])
        .unwrap();
    assert_eq!(
        replica
            .prune_messages(mailbox.mailbox_id, 1)
            .await
            .unwrap()
            .removable_copies,
        1
    );
    assert_eq!(sync.once(time(200_000)).await.unwrap().pruned, 1);
    let settled = sync.once(time(300_000)).await.unwrap();
    assert_eq!(
        (settled.pruned, settled.retry, settled.repair_pending),
        (0, 0, 0)
    );
    assert_eq!(store.get_object(id).await.unwrap(), Some(bytes.clone()));
    assert_eq!(store.stats().await.unwrap().records, 1);
    assert_eq!(
        store
            .display_sources(authority.space, authority.stream)
            .await
            .unwrap()[0]
            .status,
        "LOCAL"
    );
    let current_backup = store.message_backup_image(4 * 1024 * 1024).await.unwrap();
    store.close().await.unwrap();
    for (backup, expected_pruned) in [(queued_backup, 1), (old_backup, 1), (current_backup, 0)] {
        let restored = tempfile::tempdir().unwrap();
        std::fs::write(restored.path().join("client.sqlite"), backup).unwrap();
        let restored = ClientStore::open(restored.path()).await.unwrap();
        let report = SyncClient {
            store: &restored,
            identity: &alice.age,
            credential: alice.credential.id(),
            authority: &authority,
            peers: &peers,
        }
        .once(time(400_000))
        .await
        .unwrap();
        assert_eq!(report.pruned, expected_pruned);
        assert_eq!(report.repaired, 0);
        assert_eq!(restored.get_object(id).await.unwrap(), Some(bytes.clone()));
        assert_eq!(restored.stats().await.unwrap().records, 1);
        restored.close().await.unwrap();
    }
    assert!(matches!(
        peers[0].get(id, bytes.len() as u64).await,
        Err(elo_core::sync::SyncError::Pruned(_))
    ));
    server.abort();
    let _ = server.await;
}

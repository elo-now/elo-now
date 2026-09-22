mod common;
use common::*;
use elo_core::{
    crypto,
    replica::{ReplicaStore, TransferHint},
    store::{ClientStore, DeliveryTarget, LocalTime, PreparedLocalRecord, RecordMetadata},
    sync::{ChatAuthority, Peer, PeerDescriptor, SyncClient, retry_delay_ms},
};
use rusqlite::Connection;
fn now() -> LocalTime {
    LocalTime::from_millis(100).unwrap()
}
#[tokio::test]
async fn ciphertext_and_cursor_survive_restart_before_validation() {
    let alice = person(21);
    let charlie = person(31);
    let authority = authority(&[&alice, &charlie]);
    let record = message(&alice, &authority);
    let credentials = authority.credentials.values().cloned().collect::<Vec<_>>();
    let bytes = crypto::seal_chat(&record, &credentials).unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let replica = ReplicaStore::open(remote.path()).await.unwrap();
    let d = replica.create_mailbox(1024 * 1024).await.unwrap();
    let id = elo_core::ids::ObjectId::of_ciphertext(&bytes);
    replica
        .post(
            d.mailbox_id,
            d.write_token.clone(),
            id,
            bytes.clone(),
            TransferHint::Eager,
        )
        .await
        .unwrap();
    let page = replica
        .inventory(d.mailbox_id, d.read_token, 0, 128)
        .await
        .unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    store
        .stage_inbox(
            replica.peer_id(),
            d.mailbox_id,
            page.storage_generation.clone(),
            page.entries[0].clone(),
            Some(bytes),
            now(),
        )
        .await
        .unwrap();
    store.close().await.unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    assert_eq!(
        store
            .cursor(replica.peer_id(), d.mailbox_id)
            .await
            .unwrap()
            .unwrap()
            .arrival_seq,
        1
    );
    assert_eq!(store.pending_inbox(128).await.unwrap().len(), 1);
    let report = SyncClient {
        store: &store,
        identity: &charlie.age,
        credential: charlie.credential.id(),
        authority: &authority,
        peers: &[],
    }
    .once(now())
    .await
    .unwrap();
    assert_eq!(report.accepted, 1);
    assert_eq!(store.stats().await.unwrap().records, 1);
    assert!(store.pending_inbox(128).await.unwrap().is_empty());
    store.close().await.unwrap();
}
#[tokio::test]
async fn alice_offline_charlie_reopens_and_second_replica_deduplicates() {
    let alice = person(21);
    let charlie = person(31);
    let authority = authority(&[&alice, &charlie]);
    let record = message(&alice, &authority);
    let credentials = authority.credentials.values().cloned().collect::<Vec<_>>();
    let bytes = crypto::seal_chat(&record, &credentials).unwrap();
    let mut dirs = Vec::new();
    let mut servers = Vec::new();
    let mut writers = Vec::new();
    let mut readers = Vec::new();
    let mut targets = Vec::new();
    for _ in 0..2 {
        let dir = tempfile::TempDir::new().unwrap();
        let replica = ReplicaStore::open(dir.path()).await.unwrap();
        let d = replica.create_mailbox(1024 * 1024).await.unwrap();
        let (url, server) = server(replica.clone()).await;
        let writer = peer(&url, &replica, &d, false, true);
        targets.push(DeliveryTarget {
            peer_id: writer.id(),
            mailbox_id: writer.mailbox(),
        });
        writers.push(writer);
        readers.push(peer(&url, &replica, &d, true, false));
        servers.push(server);
        dirs.push(dir);
    }
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let input = PreparedLocalRecord::new(
        record.id(),
        bytes,
        RecordMetadata::new(
            "chat.message",
            Some(authority.space),
            Some(authority.stream),
            Some(authority.config),
        )
        .unwrap(),
        targets,
        now(),
    )
    .unwrap();
    store.commit_local_record_with_outbox(input).await.unwrap();
    store.close().await.unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let report = SyncClient {
        store: &store,
        identity: &alice.age,
        credential: alice.credential.id(),
        authority: &authority,
        peers: &writers,
    }
    .once(now())
    .await
    .unwrap();
    assert_eq!(report.stored, 2);
    assert_eq!(store.stats().await.unwrap().stored, 2);
    store.close().await.unwrap();
    drop(alice);
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let client = SyncClient {
        store: &store,
        identity: &charlie.age,
        credential: charlie.credential.id(),
        authority: &authority,
        peers: &readers,
    };
    let first = client.once(now()).await.unwrap();
    assert_eq!(first.accepted, 2);
    assert_eq!(
        first.received_messages,
        vec![record.id()],
        "the same message in two replicas notifies only once"
    );
    assert!(
        client
            .foreground(now(), 1)
            .await
            .unwrap()
            .received_messages
            .is_empty()
    );
    assert_eq!(client.once(now()).await.unwrap().downloaded, 0);
    assert_eq!(store.stats().await.unwrap().records, 1);
    store.close().await.unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    for id in store.message_sources().await.unwrap() {
        let record =
            crypto::open_record(&store.get_object(id).await.unwrap().unwrap(), &charlie.age)
                .unwrap();
        authority.verify(&record, charlie.credential.id()).unwrap();
    }
    assert_eq!(store.stats().await.unwrap().records, 1);
    store.close().await.unwrap();
    for server in servers {
        server.abort();
    }
}

#[tokio::test]
async fn foreground_sync_uploads_before_a_stalled_reader_and_restarts_without_duplicate_alerts() {
    let alice = person(21);
    let charlie = person(31);
    let authority = authority(&[&alice, &charlie]);
    let record = message(&alice, &authority);
    let bytes = crypto::seal_chat(
        &record,
        &authority.credentials.values().cloned().collect::<Vec<_>>(),
    )
    .unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let replica = ReplicaStore::open(remote.path()).await.unwrap();
    let mailbox = replica.create_mailbox(1024 * 1024).await.unwrap();
    // A healthy mobile route may need more than two seconds for an upload.
    // Repeatedly cancelling it must not leave an otherwise valid message queued.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let router = elo_core::http::router(replica.clone()).layer(axum::middleware::from_fn(
        |request: axum::extract::Request, next: axum::middleware::Next| async move {
            if request.method() == axum::http::Method::POST {
                tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
            }
            next.run(request).await
        },
    ));
    let running = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let writer = peer(&url, &replica, &mailbox, false, true);
    let slow_dir = tempfile::TempDir::new().unwrap();
    let slow_replica = ReplicaStore::open(slow_dir.path()).await.unwrap();
    let slow_mailbox = slow_replica.create_mailbox(1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let slow_url = format!("http://{}/", listener.local_addr().unwrap());
    let stalled = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().fallback(|| async {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            }),
        )
        .await
        .unwrap();
    });
    let peers = vec![
        peer(&slow_url, &slow_replica, &slow_mailbox, true, false),
        writer.clone(),
    ];
    let local = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(local.path()).await.unwrap();
    store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                record.id(),
                bytes,
                RecordMetadata::new(
                    "chat.message",
                    Some(authority.space),
                    Some(authority.stream),
                    Some(authority.config),
                )
                .unwrap(),
                vec![DeliveryTarget {
                    peer_id: writer.id(),
                    mailbox_id: writer.mailbox(),
                }],
                now(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let report = SyncClient {
        store: &store,
        identity: &alice.age,
        credential: alice.credential.id(),
        authority: &authority,
        peers: &peers,
    }
    .foreground(now(), 0)
    .await
    .unwrap();
    assert_eq!(report.stored, 1);
    assert_eq!(report.retry, 1);
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    assert_eq!(store.stats().await.unwrap().stored, 1);
    store.close().await.unwrap();
    drop(alice);
    let destination = tempfile::TempDir::new().unwrap();
    let peers = vec![peer(&url, &replica, &mailbox, true, false)];
    let store = ClientStore::open(destination.path()).await.unwrap();
    let report = SyncClient {
        store: &store,
        identity: &charlie.age,
        credential: charlie.credential.id(),
        authority: &authority,
        peers: &peers,
    }
    .foreground(now(), 0)
    .await
    .unwrap();
    assert_eq!(report.received_messages, vec![record.id()]);
    assert_eq!(report.accepted, 1);
    store.close().await.unwrap();
    let store = ClientStore::open(destination.path()).await.unwrap();
    let report = SyncClient {
        store: &store,
        identity: &charlie.age,
        credential: charlie.credential.id(),
        authority: &authority,
        peers: &peers,
    }
    .foreground(now(), 1)
    .await
    .unwrap();
    assert!(report.received_messages.is_empty());
    assert_eq!(store.stats().await.unwrap().records, 1);
    store.close().await.unwrap();
    running.abort();
    stalled.abort();
    drop(slow_replica);
    drop(replica);
}
#[tokio::test]
async fn inbox_failure_rolls_back_blob_and_cursor() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let raw = Connection::open(dir.path().join("client.sqlite")).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_cursor BEFORE INSERT ON peer_cursors BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
    let bytes = b"PUBLIC TEST".to_vec();
    let peer = elo_core::ids::PeerId::from_bytes([1; 32]);
    let mailbox = elo_core::ids::MailboxId::from_bytes([2; 32]);
    let entry = elo_core::replica::InventoryEntry {
        arrival_seq: 1,
        object_id: elo_core::ids::ObjectId::of_ciphertext(&bytes),
        size_bytes: bytes.len() as u64,
        transfer_hint: TransferHint::Eager,
    };
    assert!(
        store
            .stage_inbox(peer, mailbox, "01".repeat(32), entry, Some(bytes), now())
            .await
            .is_err()
    );
    assert_eq!(store.stats().await.unwrap().objects, 0);
    assert!(store.cursor(peer, mailbox).await.unwrap().is_none());
    assert!(store.pending_inbox(128).await.unwrap().is_empty());
    store.close().await.unwrap();
}
#[tokio::test]
async fn lazy_and_malformed_objects_do_not_block_later_valid_records() {
    let alice = person(21);
    let charlie = person(31);
    let authority = authority(&[&alice, &charlie]);
    let record = message(&alice, &authority);
    let bytes = crypto::seal_chat(
        &record,
        &authority.credentials.values().cloned().collect::<Vec<_>>(),
    )
    .unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let replica = ReplicaStore::open(remote.path()).await.unwrap();
    let d = replica.create_mailbox(1024 * 1024).await.unwrap();
    for (b, hint) in [
        (b"not age".to_vec(), TransferHint::Eager),
        (b"lazy file".to_vec(), TransferHint::Lazy),
        (bytes, TransferHint::Eager),
    ] {
        replica
            .post(
                d.mailbox_id,
                d.write_token.clone(),
                elo_core::ids::ObjectId::of_ciphertext(&b),
                b,
                hint,
            )
            .await
            .unwrap();
    }
    let (url, server) = server(replica.clone()).await;
    let peers = [peer(&url, &replica, &d, true, false)];
    let local = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(local.path()).await.unwrap();
    let report = SyncClient {
        store: &store,
        identity: &charlie.age,
        credential: charlie.credential.id(),
        authority: &authority,
        peers: &peers,
    }
    .once(now())
    .await
    .unwrap();
    assert_eq!(
        (
            report.downloaded,
            report.rejected,
            report.deferred,
            report.accepted
        ),
        (2, 1, 1, 1)
    );
    assert_eq!(store.stats().await.unwrap().objects, 2);
    store.close().await.unwrap();
    server.abort();
}
#[test]
fn endpoint_and_backoff_bounds_are_explicit() {
    let key = person(21);
    let mut d = PeerDescriptor {
        url: "http://127.0.0.1:9999".into(),
        signing_public_key: elo_core::record::encode_hex(key.key.verifying_key().as_bytes()),
        mailbox_id: elo_core::ids::MailboxId::from_bytes([1; 32]),
        read_token: None,
        write_token: None,
    };
    assert!(Peer::new(d.clone(), false).is_err());
    assert!(Peer::new(d.clone(), true).is_ok());
    for url in [
        "http://example.com",
        "http://localhost",
        "https://user:password@example.com",
        "https://example.com/?token=x",
        "https://example.com/prefix",
        "file:///tmp/example",
    ] {
        d.url = url.into();
        assert!(Peer::new(d.clone(), true).is_err());
    }
    assert_eq!(
        (
            retry_delay_ms(1, 0),
            retry_delay_ms(2, 0),
            retry_delay_ms(3, 0),
            retry_delay_ms(1000, 0)
        ),
        (1000, 2000, 4000, 60000)
    );
    assert!(retry_delay_ms(1, 43) > 1000);
}
#[tokio::test]
async fn migration_preserves_existing_v1_state_and_rejects_altered_schema() {
    let dir = tempfile::TempDir::new().unwrap();
    let raw = Connection::open(dir.path().join("client.sqlite")).unwrap();
    raw.execute_batch(include_str!("../../../migrations/001_client.sql"))
        .unwrap();
    drop(raw);
    let store = ClientStore::open(dir.path()).await.unwrap();
    store.close().await.unwrap();
    let raw = Connection::open(dir.path().join("client.sqlite")).unwrap();
    assert_eq!(
        raw.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        8
    );
    let bad = tempfile::TempDir::new().unwrap();
    let raw = Connection::open(bad.path().join("client.sqlite")).unwrap();
    raw.execute_batch(include_str!("../../../migrations/001_client.sql"))
        .unwrap();
    raw.execute_batch("CREATE TABLE alien(x)").unwrap();
    assert!(ClientStore::open(bad.path()).await.is_err());
    assert_eq!(
        raw.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn foreground_backlog_resumes_between_pages_and_admission_batches_without_duplicates() {
    struct SlowAuthority(elo_core::sync::FixedDemoAuthority);
    impl ChatAuthority for SlowAuthority {
        fn verify(
            &self,
            record: &elo_core::record::SignedRecord,
            recipient: elo_core::ids::RecordId,
        ) -> Result<elo_core::sync::VerifiedChat, elo_core::record::RecordError> {
            // Deterministically exhaust the admission budget while still using
            // real signature, authority, recipient and ciphertext validation.
            std::thread::sleep(std::time::Duration::from_millis(25));
            self.0.verify(record, recipient)
        }
    }
    let alice = person(21);
    let bob = person(31);
    let authority = authority(&[&alice, &bob]);
    let credentials = authority.credentials.values().cloned().collect::<Vec<_>>();
    let tmp = tempfile::tempdir().unwrap();
    let replica = ReplicaStore::open(tmp.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
    let mut expected = std::collections::BTreeSet::new();
    for n in 1..=257 {
        let mut chat = message(&alice, &authority).chat().unwrap();
        chat.logical_time = n;
        chat.payload.text = format!("Backlog {n}");
        let signed = chat.sign(&alice.key).unwrap();
        expected.insert(signed.id());
        let cipher = crypto::seal_chat(&signed, &credentials).unwrap();
        replica
            .post(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                elo_core::ids::ObjectId::of_ciphertext(&cipher),
                cipher,
                TransferHint::Eager,
            )
            .await
            .unwrap();
    }
    let (url, server) = server(replica.clone()).await;
    let peers = vec![peer(&url, &replica, &mailbox, true, false)];
    let authority = SlowAuthority(authority);
    let mut seen = std::collections::BTreeSet::new();
    let mut complete = false;
    for round in 0..30 {
        // Each pass uses a freshly reopened store, including the scan position
        // and the already downloaded but not yet verified ciphertext inbox.
        let store = ClientStore::open(tmp.path().join("client")).await.unwrap();
        let report = SyncClient {
            store: &store,
            identity: &bob.age,
            credential: bob.credential.id(),
            authority: &authority,
            peers: &peers,
        }
        .foreground(LocalTime::from_millis(100 + round).unwrap(), round as usize)
        .await
        .unwrap();
        if round == 0 {
            assert!(report.more);
            assert!(report.accepted > 0 && report.accepted < 128);
            assert!(!store.pending_inbox(128).await.unwrap().is_empty());
        }
        assert_eq!(report.retry, 0);
        for id in report.received_messages {
            assert!(seen.insert(id), "duplicate notification after restart");
        }
        if !report.more {
            assert_eq!(seen, expected);
            complete = true;
        }
        store.close().await.unwrap();
        if complete {
            break;
        }
    }
    assert!(complete, "backlog did not drain in bounded passes");
    let store = ClientStore::open(tmp.path().join("client")).await.unwrap();
    assert_eq!(store.stats().await.unwrap().records, 257);
    let idle = SyncClient {
        store: &store,
        identity: &bob.age,
        credential: bob.credential.id(),
        authority: &authority,
        peers: &peers,
    }
    .foreground(now(), 0)
    .await
    .unwrap();
    assert!(
        !idle.more,
        "routine reconciliation is not a new-message backlog"
    );
    assert!(idle.received_messages.is_empty());
    store.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn notification_receive_skips_old_scan_and_outbox_without_skipping_authority_checks() {
    let alice = person(21);
    let bob = person(31);
    let outsider = person(41);
    let authority = authority(&[&alice, &bob]);
    let credentials = authority.credentials.values().cloned().collect::<Vec<_>>();
    let tmp = tempfile::tempdir().unwrap();
    let replica = ReplicaStore::open(tmp.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
    let (url, server) = server(replica.clone()).await;
    let peers = vec![peer(&url, &replica, &mailbox, true, true)];
    let store = ClientStore::open(tmp.path().join("client")).await.unwrap();
    let mut last_id = None;
    for n in 1..=132 {
        // Leave the full scan on its first historical page before a tap arrives.
        if n == 131 {
            let sync = SyncClient {
                store: &store,
                identity: &bob.age,
                credential: bob.credential.id(),
                authority: &authority,
                peers: &peers,
            };
            for _ in 0..4 {
                sync.once(now()).await.unwrap();
            }
            assert_eq!(store.stats().await.unwrap().records, 130);
            let raw = Connection::open(tmp.path().join("client/client.sqlite")).unwrap();
            assert_eq!(
                raw.query_row("SELECT after_seq FROM replica_scans", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                130
            );
            sync.foreground(now(), 0).await.unwrap();
            assert_eq!(
                raw.query_row("SELECT after_seq FROM replica_scans", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                128
            );
        }
        let author = if n == 132 { &outsider } else { &alice };
        let mut chat = message(author, &authority).chat().unwrap();
        chat.logical_time = n;
        chat.payload.text = format!("Arrival {n}");
        let signed = chat.sign(&author.key).unwrap();
        if n == 131 {
            last_id = Some(signed.id());
        }
        let cipher = crypto::seal_chat(&signed, &credentials).unwrap();
        replica
            .post(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                elo_core::ids::ObjectId::of_ciphertext(&cipher),
                cipher,
                TransferHint::Eager,
            )
            .await
            .unwrap();
    }
    let outgoing = message(&bob, &authority);
    store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                outgoing.id(),
                crypto::seal_chat(&outgoing, &credentials).unwrap(),
                RecordMetadata::new(
                    "chat.message",
                    Some(authority.space),
                    Some(authority.stream),
                    Some(authority.config),
                )
                .unwrap(),
                vec![DeliveryTarget {
                    peer_id: peers[0].id(),
                    mailbox_id: peers[0].mailbox(),
                }],
                now(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let report = SyncClient {
        store: &store,
        identity: &bob.age,
        credential: bob.credential.id(),
        authority: &authority,
        peers: &peers,
    }
    .receive_foreground(now(), 0)
    .await
    .unwrap();
    assert_eq!(
        report.downloaded, 2,
        "do not scan old pages before receiving a tapped message"
    );
    assert_eq!(report.received_messages, vec![last_id.unwrap()]);
    assert_eq!(
        report.rejected, 1,
        "decryptable ciphertext still requires valid chat authority"
    );
    assert_eq!(
        report.stored, 0,
        "do not upload before pending membership discovery"
    );
    let raw = Connection::open(tmp.path().join("client/client.sqlite")).unwrap();
    assert_eq!(
        raw.query_row("SELECT after_seq FROM replica_scans", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        128
    );
    assert_eq!(
        store
            .cursor(peers[0].id(), peers[0].mailbox())
            .await
            .unwrap()
            .unwrap()
            .arrival_seq,
        132
    );
    store.close().await.unwrap();
    let store = ClientStore::open(tmp.path().join("client")).await.unwrap();
    let report = SyncClient {
        store: &store,
        identity: &bob.age,
        credential: bob.credential.id(),
        authority: &authority,
        peers: &peers,
    }
    .once(now())
    .await
    .unwrap();
    assert!(
        report.received_messages.is_empty(),
        "a normal pass after restart must not alert twice"
    );
    assert_eq!(report.stored, 1);
    assert_eq!(
        report.repaired, 0,
        "a receive-only page must not mark earlier copies missing"
    );
    store.close().await.unwrap();
    server.abort();
}

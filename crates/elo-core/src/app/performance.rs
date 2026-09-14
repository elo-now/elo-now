//! Opt-in measurements on disposable profiles, using production crypto/store paths.
//! No Demo credentials, external network endpoints, or timing assertions.
use super::*;
use crate::{identity::DeviceCredential, replica::ReplicaStore};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::time::Instant;

fn report(value: Value) {
    println!("ELO_PERF {value}");
}

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn distribution(mut samples: Vec<f64>) -> Value {
    samples.sort_by(f64::total_cmp);
    json!({"n":samples.len(),"p50_ms":samples[samples.len()/2],
        "p95_ms":samples[(samples.len()*95).div_ceil(100)-1]})
}

pub(super) fn message(app: &ClientApp, index: usize, sequence: u64) -> SignedRecord {
    let a = &app.authorities.0[index];
    a.prepare_chat(
        ChatMessage {
            v: 1,
            kind: "chat.message".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: a.space(),
            stream_id: a.stream(),
            issuer_identity: app.session.identity_id(),
            issuer_credential: app.session.credential().id(),
            config_id: a.head_id().unwrap(),
            audience: vec![],
            recipient_credentials: vec![],
            logical_time: sequence,
            created_at: "2026-09-13T12:00:00Z".into(),
            parents: vec![],
            payload: TextPayload {
                text: format!(
                    "Synthetic performance message {sequence}: {}",
                    "test content ".repeat(16)
                ),
                sender_name: Some("Performance fixture".into()),
                thread_root: None,
                action: None,
            },
        },
        app.session.signing_key(),
    )
    .unwrap()
}

pub(super) async fn profile(path: PathBuf) -> ClientApp {
    ProfileDraft::new()
        .unwrap()
        .save_named(
            path,
            "synthetic performance password".into(),
            "Performance",
            "Performance fixture",
        )
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "opt-in release benchmark; creates only temporary synthetic profiles"]
async fn measure_recipient_crypto_and_loopback_transport() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = profile(tmp.path().join("profile")).await;
    let replica = ReplicaStore::open(tmp.path().join("replica"))
        .await
        .unwrap();
    let listener = crate::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = crate::http::router(replica.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut previous = 1u64;
    let mut recipient = None;
    for count in [10u64, 100, 1000] {
        let mailbox = replica.create_mailbox(256 * 1024 * 1024).await.unwrap();
        let peer = Peer::new(
            PeerDescriptor {
                url: url.clone(),
                signing_public_key: record::encode_hex(replica.key().as_bytes()),
                mailbox_id: mailbox.mailbox_id,
                read_token: Some(mailbox.read_token),
                write_token: Some(mailbox.write_token),
            },
            true,
        )
        .unwrap();
        let a = &mut app.authorities.0[0];
        let mut config = a.head().unwrap().clone();
        for n in previous..count {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&n.to_le_bytes());
            seed[31] = 91;
            let root = SigningKey::from_bytes(&seed);
            seed[31] = 92;
            let key = SigningKey::from_bytes(&seed);
            let age = age::x25519::Identity::generate();
            let c = DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
            config.members.push(Member {
                identity_id: c.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
                capabilities: vec![Capability::Read, Capability::Post],
                credential_ids: vec![c.id()],
                external: false,
            });
            recipient = Some((age, c.id()));
            a.add_credential(c);
        }
        config.members.sort_by_key(|m| m.identity_id);
        config.sequence += 1;
        config.previous_config_id = a.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.action.operation = "replace".into();
        a.apply_config(config.sign(app.session.signing_key()).unwrap())
            .unwrap();
        previous = count;
        let mut credentials = config
            .members
            .iter()
            .flat_map(|m| &m.credential_ids)
            .map(|id| a.credential(*id).unwrap().clone())
            .collect::<Vec<_>>();
        credentials.sort_by_key(|c| c.id());
        let (reader, reader_credential) = recipient.as_ref().unwrap();
        let mut prepare = vec![];
        let mut seal = vec![];
        let mut open = vec![];
        let mut verify = vec![];
        let mut transport = vec![];
        let mut packet_bytes = 0;
        for n in 0..21 {
            let start = Instant::now();
            let record = message(&app, 0, n + 1);
            let prepared = ms(start);
            let start = Instant::now();
            let cipher = crypto::seal_chat(&record, &credentials).unwrap();
            let sealed = ms(start);
            packet_bytes = cipher.len();
            let start = Instant::now();
            let opened = crypto::open_record(&cipher, reader).unwrap();
            let decrypted = ms(start);
            assert_eq!(opened.bytes(), record.bytes());
            let start = Instant::now();
            app.authorities.0[0]
                .verify(&opened, *reader_credential)
                .unwrap();
            let verified = ms(start);
            let id = crate::ids::ObjectId::of_ciphertext(&cipher);
            let start = Instant::now();
            peer.post(id, cipher.clone(), crate::replica::TransferHint::Eager)
                .await
                .unwrap();
            assert_eq!(peer.get(id, cipher.len() as u64).await.unwrap(), cipher);
            let transported = ms(start);
            if n > 0 {
                prepare.push(prepared);
                seal.push(sealed);
                open.push(decrypted);
                verify.push(verified);
                transport.push(transported);
            }
        }
        report(
            json!({"case":"recipients","recipients":count,"ciphertext_bytes":packet_bytes,
            "prepare_sign":distribution(prepare),"seal":distribution(seal),"open":distribution(open),
            "verify_authority":distribution(verify),"loopback_post_and_get":distribution(transport)}),
        );
        let backlog = if count == 100 { 1000 } else { 21 };
        for n in 21..backlog {
            let record = message(&app, 0, n + 1);
            let cipher = crypto::seal_chat(&record, &credentials).unwrap();
            peer.post(
                crate::ids::ObjectId::of_ciphertext(&cipher),
                cipher,
                crate::replica::TransferHint::Eager,
            )
            .await
            .unwrap();
        }
        let reader_path = tmp.path().join(format!("reader-{count}"));
        let mut store = ClientStore::open(&reader_path).await.unwrap();
        let peers = [peer];
        let start = Instant::now();
        let mut rounds = 0;
        let mut first_batch_ms = 0.0;
        loop {
            let result = SyncClient {
                store: &store,
                identity: reader,
                credential: *reader_credential,
                authority: &app.authorities.0[0],
                peers: &peers,
            }
            .once(LocalTime::from_millis(1000 + rounds).unwrap())
            .await
            .unwrap();
            assert_eq!(result.rejected, 0);
            assert_eq!(result.retry, 0);
            rounds += 1;
            let accepted = store.stats().await.unwrap().records;
            if rounds == 1 {
                first_batch_ms = ms(start);
                // Resume the durable inbox/cursor from a new SQLite worker.
                store.close().await.unwrap();
                store = ClientStore::open(&reader_path).await.unwrap();
            }
            if accepted == backlog {
                break;
            }
            assert!(rounds < backlog + 10, "backlog failed to converge");
        }
        let sync_ms = ms(start);
        let replay = SyncClient {
            store: &store,
            identity: reader,
            credential: *reader_credential,
            authority: &app.authorities.0[0],
            peers: &peers,
        }
        .once(LocalTime::from_millis(10_000).unwrap())
        .await
        .unwrap();
        assert_eq!(replay.accepted, 0);
        assert_eq!(store.stats().await.unwrap().records, backlog);
        report(
            json!({"case":"loopback_backlog","recipients":count,"messages":backlog,
            "first_batch_ms":first_batch_ms,"complete_ms":sync_ms,"rounds":rounds,
            "restarted_after_first_batch":true,"duplicates":0}),
        );
        store.close().await.unwrap();
    }
    server.abort();
    let _ = server.await;
    app.close().await.unwrap();
}

fn database_digest(path: &Path) -> String {
    let db = rusqlite::Connection::open_with_flags(
        path.join("client.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut hash = Sha256::new();
    // Check every retained record and ciphertext, including data outside the UI.
    for sql in [
        "SELECT record_id FROM records ORDER BY record_id",
        "SELECT record_id || ':' || object_id || ':' || source_index FROM record_sources ORDER BY record_id,object_id,source_index",
    ] {
        let mut q = db.prepare(sql).unwrap();
        for row in q.query_map([], |r| r.get::<_, String>(0)).unwrap() {
            hash.update(row.unwrap().as_bytes());
        }
    }
    let mut q = db
        .prepare("SELECT object_id,ciphertext FROM objects ORDER BY object_id")
        .unwrap();
    let rows = q
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .unwrap();
    for row in rows {
        let (id, cipher) = row.unwrap();
        assert_eq!(crate::ids::ObjectId::of_ciphertext(&cipher).to_string(), id);
        hash.update(id.as_bytes());
    }
    record::encode_hex(&hash.finalize())
}

fn assert_backup_subset(source: &Path, restored: &Path) {
    let db = rusqlite::Connection::open_with_flags(
        source.join("client.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.execute(
        "ATTACH DATABASE ?1 AS recovered",
        [restored.join("client.sqlite").to_str().unwrap()],
    )
    .unwrap();
    db.execute_batch("PRAGMA query_only=ON").unwrap();
    for table in ["records", "record_sources", "objects"] {
        let count: i64 = db.query_row(&format!(
            "SELECT count(*) FROM (SELECT * FROM recovered.{table} EXCEPT SELECT * FROM main.{table})"
        ), [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0, "Backup must contain unchanged source rows");
    }
}

#[tokio::test]
#[ignore = "opt-in release benchmark; set ELO_PERF_COUNTS=10000,100000,500000"]
async fn measure_history_view_and_recovery() {
    let counts = std::env::var("ELO_PERF_COUNTS")
        .unwrap_or_else(|_| "1000".into())
        .split(',')
        .map(|s| s.parse::<u64>().unwrap())
        .collect::<Vec<_>>();
    assert!(
        counts.iter().all(|n| (1..=500_000).contains(n)) && counts.windows(2).all(|p| p[0] < p[1])
    );
    let chats = std::env::var("ELO_PERF_CHATS")
        .unwrap_or_else(|_| "100".into())
        .parse::<u64>()
        .unwrap();
    assert!((1..=1000).contains(&chats), "Keep synthetic runs bounded");
    let tmp = tempfile::tempdir().unwrap();
    let directory = tmp.path().join("profile");
    let mut app = profile(directory.clone()).await;
    for i in 1..chats {
        app.create_chat(&format!("Performance {i}"), None, ChatKind::Chat)
            .await
            .unwrap();
    }
    assert_eq!(app.pins.len(), chats as usize);
    report(json!({"case":"chat_setup","requested":chats,"created":app.pins.len()}));
    let base_records = app.store.stats().await.unwrap().records;
    let credentials = vec![app.session.credential().clone()];
    let mut generated = 0u64;
    for count in counts {
        let start = Instant::now();
        for n in generated..count {
            let index = (n % chats) as usize;
            let a = &app.authorities.0[index];
            let r = message(&app, index, n + 1);
            let cipher = crypto::seal_chat(&r, &credentials).unwrap();
            app.store
                .commit_local_record_with_outbox(
                    PreparedLocalRecord::new(
                        r.id(),
                        cipher,
                        RecordMetadata::new(
                            "chat.message",
                            Some(a.space()),
                            Some(a.stream()),
                            a.head_id(),
                        )
                        .unwrap(),
                        vec![],
                        LocalTime::from_millis(n + 1).unwrap(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            if (n + 1) % 10_000 == 0 {
                report(json!({"case":"generation_progress","messages":n+1,"batch_ms":ms(start)}));
            }
        }
        let generation_ms = ms(start);
        generated = count;
        assert_eq!(
            app.store.stats().await.unwrap().records,
            base_records + count
        );
        let mut samples = vec![];
        let mut visible = 0;
        let mut json_bytes = 0;
        for _ in 0..3 {
            let start = Instant::now();
            let view = app.view().await.unwrap();
            samples.push(ms(start));
            visible = view["streams"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["rows"].as_array().unwrap().len())
                .sum::<usize>();
            json_bytes = serde_json::to_vec(&view).unwrap().len();
            assert_eq!(visible, count.min(chats * 1000) as usize);
        }
        let digest = database_digest(&directory);
        let start = Instant::now();
        let backup = app
            .export_profile_with_report("synthetic backup password".into())
            .await;
        let export_ms = ms(start);
        let recovery = match backup {
            Ok(backup) => {
                let omitted = backup.omitted_messages as u64;
                let included_data_bytes = backup.included_data_bytes;
                let bytes = backup.bytes;
                let size = bytes.len();
                let start = Instant::now();
                let restored = ClientApp::restore_profile(
                    tmp.path().join(format!("restored-{count}")),
                    &bytes,
                    "synthetic backup password".into(),
                    app.identity_id(),
                    "synthetic restored password".into(),
                    false,
                )
                .await
                .unwrap();
                let restore_ms = ms(start);
                assert_eq!(
                    restored.store.stats().await.unwrap().records,
                    base_records + count - omitted
                );
                assert_eq!(database_digest(&directory), digest);
                if omitted == 0 {
                    assert_eq!(database_digest(restored.profile_path()), digest);
                } else {
                    assert_backup_subset(&directory, restored.profile_path());
                }
                let start = Instant::now();
                let v = restored.view().await.unwrap();
                let view_ms = ms(start);
                assert_eq!(
                    v["streams"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s["rows"].as_array().unwrap().len())
                        .sum::<usize>(),
                    ((count - omitted).min(chats * 1000)) as usize
                );
                restored.close().await.unwrap();
                json!({"complete":omitted == 0,"restored":true,"omitted_messages":omitted,"included_data_bytes":included_data_bytes,"bytes":size,"export_ms":export_ms,"restore_ms":restore_ms,"first_view_ms":view_ms})
            }
            Err(error) => json!({"complete":false,"error":error.to_string(),"export_ms":export_ms}),
        };
        app.close().await.unwrap();
        let database_bytes = std::fs::metadata(directory.join("client.sqlite"))
            .unwrap()
            .len();
        let start = Instant::now();
        app = ClientApp::open(
            directory.clone(),
            "synthetic performance password".into(),
            false,
        )
        .await
        .unwrap();
        let reopen_ms = ms(start);
        assert_eq!(database_digest(&directory), digest);
        let start = Instant::now();
        app.view().await.unwrap();
        let first_view_ms = ms(start);
        // Exercise the actual send command, including its full returned projection.
        let pin = app.pins[0].clone();
        let start = Instant::now();
        app.operate(json!({"op":"send","space":pin.space,"stream":pin.stream,
            "text":"Synthetic timed send","created_at":"2026-09-13T12:00:00Z"}))
            .await
            .unwrap();
        let send_ms = ms(start);
        report(
            json!({"case":"history","generated_messages":count,"chats":chats,
            "generation_batch_ms":generation_ms,"database_bytes":database_bytes,"visible_messages":visible,
            "view_json_bytes":json_bytes,"view":distribution(samples),"reopen_ms":reopen_ms,
            "first_view_ms":first_view_ms,"send_with_view_ms":send_ms,"recovery":recovery}),
        );
        // The timed command is a real extra record; retain it in subsequent counts.
        generated += 1;
    }
    app.close().await.unwrap();
}

#[tokio::test]
#[ignore = "opt-in release benchmark; ELO_PERF_RECOVERY_MESSAGES up to 100000"]
async fn measure_resumable_backup_recovery() {
    use super::profile_backup::{RestoreProgress, RestoreRequest, RestoreStage, restore};
    let count = std::env::var("ELO_PERF_RECOVERY_MESSAGES")
        .unwrap_or_else(|_| "100000".into())
        .parse::<u64>()
        .unwrap();
    assert!((100..=100000).contains(&count));
    let tmp = tempfile::tempdir().unwrap();
    // An operator may reuse only a disposable fixture produced by this test
    // after stopping an overlong run. Normal runs create and delete their data.
    let reuse = std::env::var_os("ELO_PERF_RECOVERY_SOURCE").map(PathBuf::from);
    let directory = reuse.clone().unwrap_or_else(|| tmp.path().join("source"));
    let mut app = if reuse.is_some() {
        ClientApp::open(
            directory.clone(),
            "synthetic performance password".into(),
            false,
        )
        .await
        .unwrap()
    } else {
        profile(directory.clone()).await
    };
    if reuse.is_none() {
        for n in 1..100 {
            app.create_chat(&format!("Recovery {n}"), None, ChatKind::Chat)
                .await
                .unwrap();
        }
    }
    assert_eq!(app.pins.len(), 100);
    app.enable_spaces().await.unwrap();
    app.enable_paged_views();
    let stored = app.store.stats().await.unwrap().records;
    let base = if reuse.is_some() {
        stored.checked_sub(count).unwrap()
    } else {
        stored
    };
    let start = Instant::now();
    for n in if reuse.is_some() { count } else { 0 }..count {
        let index = (n % 100) as usize;
        let a = &app.authorities.0[index];
        let r = message(&app, index, n + 1);
        let cipher = crypto::seal_chat(&r, &[app.session.credential().clone()]).unwrap();
        app.store
            .commit_local_record_with_outbox(
                PreparedLocalRecord::new(
                    r.id(),
                    cipher,
                    RecordMetadata::new(
                        "chat.message",
                        Some(a.space()),
                        Some(a.stream()),
                        a.head_id(),
                    )
                    .unwrap(),
                    vec![],
                    LocalTime::from_millis(n + 1).unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        if (n + 1) % 25000 == 0 {
            report(json!({"case":"recovery_generation","messages":n+1,"elapsed_ms":ms(start)}));
        }
    }
    let digest = database_digest(&directory);
    let start = Instant::now();
    let backup = app
        .export_profile_with_report("synthetic recovery backup password".into())
        .await
        .unwrap();
    let export_ms = ms(start);
    report(
        json!({"case":"recovery_export","source_messages":count,"included_data_bytes":backup.included_data_bytes,"archive_bytes":backup.bytes.len(),"omitted_messages":backup.omitted_messages,"export_ms":export_ms}),
    );
    let destination = tmp.path().join("restored");
    let request = || RestoreRequest {
        directory: destination.clone(),
        bytes: &backup.bytes,
        secret: "synthetic recovery backup password".into(),
        expected: app.identity_id(),
        password: "synthetic recovered password".into(),
        allow_loopback: false,
        resume: true,
        paged: true,
    };
    let start = Instant::now();
    assert!(
        restore(
            request(),
            &RestoreProgress::new(|stage, _, _| stage != RestoreStage::Opening)
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .starts_with("Recovery paused.")
    );
    let checkpoint_ms = ms(start);
    let start = Instant::now();
    let restored = restore(request(), &RestoreProgress::default())
        .await
        .unwrap();
    let resume_ms = ms(start);
    assert_eq!(
        restored.store.stats().await.unwrap().records,
        base + count - backup.omitted_messages as u64
    );
    assert_eq!(
        restored.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    restored.close().await.unwrap();
    assert_eq!(database_digest(&directory), digest);
    assert_backup_subset(&directory, &destination);
    report(
        json!({"case":"resumable_recovery","source_messages":count,"chats":100,"included_data_bytes":backup.included_data_bytes,"archive_bytes":backup.bytes.len(),"omitted_messages":backup.omitted_messages,"export_ms":export_ms,"to_checkpoint_ms":checkpoint_ms,"resume_to_open_ms":resume_ms,"source_unchanged":true,"restored_rows_are_source_subset":true}),
    );
    app.close().await.unwrap();
}

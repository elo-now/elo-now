use super::*;
use crate::app::space_service::{ServiceConfig, SpaceAddress};
use crate::public_space::PublicSpaceService;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex;

const PASSWORD: &str = "synthetic private notes profile password";

async fn install_general(app: &mut ClientApp, general: &Authority, address: &SpaceAddress) {
    let old = app
        .authorities
        .0
        .iter()
        .position(|a| a.space() == general.space() && a.stream() == general.stream());
    let merged = general
        .merge_into_store(
            old.map(|i| &app.authorities.0[i]),
            &app.store,
            app.session.age_identity(),
            now().unwrap(),
        )
        .await
        .unwrap();
    if let Some(i) = old {
        app.authorities.0[i] = merged;
    } else {
        app.pins.push(Pin {
            personal_seed: Some(false),
            name: "General".into(),
            chat_kind: Some(ChatKind::Chat),
            space: general.space(),
            stream: general.stream(),
            root: address.scope.root.clone(),
            group: None,
            created_at: 1,
        });
        app.authorities.0.push(merged);
    }
    app.call_host = Some(address.clone());
    app.session.allow_live_owner_grants().unwrap();
    app.session
        .activate_linked_owner_controller(general)
        .unwrap();
    app.persist_vault().unwrap();
    app.persist_workspace().unwrap();
}

async fn paired_copy(
    app: &ClientApp,
    device: &Session,
    path: PathBuf,
    address: &SpaceAddress,
) -> ClientApp {
    let secret = "synthetic encrypted device transfer passphrase";
    let backup = app.export_device_copy(secret.into(), device).await.unwrap();
    let mut paired = ClientApp::restore_profile(
        path,
        &backup,
        secret.into(),
        app.identity_id(),
        PASSWORD.into(),
        true,
    )
    .await
    .unwrap();
    paired.call_host = Some(address.clone());
    let general = paired.notes_general().unwrap();
    paired.session.allow_live_owner_grants().unwrap();
    paired
        .session
        .activate_linked_owner_controller(&general)
        .unwrap();
    paired.persist_vault().unwrap();
    paired
}

async fn enroll(app: &ClientApp, service: &Arc<Mutex<PublicSpaceService>>, config: &ServiceConfig) {
    let request = app
        .space_request(
            &config.address,
            "status",
            json!({
        "enrollment":app.team_enrollment_request(&config.address.scope).unwrap()}),
        )
        .unwrap();
    let nonce = request.nonce.clone();
    let response = service
        .lock()
        .await
        .serve_space(config, request)
        .await
        .unwrap();
    assert_eq!(
        app.open_space_response(&config.address, &nonce, response)
            .unwrap()["status"],
        "approved"
    );
}

#[tokio::test]
async fn notes_concurrent_creation_reopen_and_two_devices_use_one_private_encrypted_chat() {
    let temp = tempfile::tempdir().unwrap();
    let mut a = ProfileDraft::new()
        .unwrap()
        .save_named(temp.path().join("a"), PASSWORD.into(), "General", "Alex")
        .await
        .unwrap();
    a.allow_loopback = true;
    let second = a.session.linked_companion().unwrap();
    let request = "41".repeat(16);
    let proof = a.owner_general_creation(&request).unwrap();
    let genesis = decode_record(&proof.genesis).unwrap();
    let mut general = proof
        .verify(
            SpaceId::from_bytes(*genesis.id().as_bytes()),
            request.parse().unwrap(),
        )
        .unwrap();
    general.add_credential(second.credential().clone());
    let mut next = general.head().unwrap().clone();
    next.sequence += 1;
    next.previous_config_id = general.head_id();
    next.nonce = "42".repeat(16);
    next.action.operation = "device.updated".into();
    next.members[0]
        .credential_ids
        .push(second.credential().id());
    next.members[0].credential_ids.sort();
    next.owner_credential_ids = next.members[0].credential_ids.clone();
    general
        .apply_config(next.sign(a.session.signing_key()).unwrap())
        .unwrap();
    let replica = crate::replica::ReplicaStore::open(temp.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let peer = PeerDescriptor {
        url: origin.clone(),
        signing_public_key: record::encode_hex(replica.key().as_bytes()),
        mailbox_id: mailbox.mailbox_id,
        read_token: Some(mailbox.read_token),
        write_token: Some(mailbox.write_token),
    };
    a.ensure_peer(peer.clone()).unwrap();
    let creation = space_host::CreateCommand {
        v: 2,
        kind: "space.create".into(),
        host: format!("{origin}/spaces/v1/create"),
        request_id: request,
        issued: now().unwrap().as_millis() as u64,
        name: "Notes test Space".into(),
        contact_email: "owner@example.invalid".into(),
        message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
        require_approval: false,
        authority: Some(proof),
    };
    let creation = SignedRecord::sign(
        &serde_json::to_vec(&creation).unwrap(),
        a.session.signing_key(),
    )
    .unwrap();
    let creation = crate::public_space::AdminEvidence {
        record: STANDARD.encode(creation.bytes()),
        credential: STANDARD.encode(a.session.credential().record().bytes()),
    };
    let service = PublicSpaceService::create(
        temp.path().join("host"),
        general.call_proof().unwrap(),
        &[a.identity_id()],
        None,
        true,
        Some(creation),
    )
    .unwrap();
    let address = SpaceAddress {
        url: format!("{origin}/team/v1/spaces"),
        scope: service.team_scope().unwrap(),
        message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
        service_credential: Some(service.transport_credential()),
    };
    let config = ServiceConfig {
        name: "Notes test Space".into(),
        address: address.clone(),
        owners: vec![a.identity_id()],
        contact_email: None,
        peer,
    };
    install_general(&mut a, &general, &address).await;
    let mut b = paired_copy(&a, &second, temp.path().join("b"), &address).await;
    let service = Arc::new(Mutex::new(service));
    enroll(&a, &service, &config).await;
    enroll(&b, &service, &config).await;
    replica
        .set_admitted_devices(service.lock().await.space_access_devices().unwrap())
        .unwrap();
    let replica_access = replica.clone();
    let lose_notes_ack = Arc::new(AtomicBool::new(false));
    let app = crate::http::router(replica, &origin).route(
        "/team/v1/spaces",
        axum::routing::post({
            let service = service.clone();
            let config = config.clone();
            let lose_notes_ack = lose_notes_ack.clone();
            let replica = replica_access.clone();
            move |axum::Json(request): axum::Json<space_service::Request>| {
                let service = service.clone();
                let config = config.clone();
                let lose_notes_ack = lose_notes_ack.clone();
                let replica = replica.clone();
                async move {
                    let command = decode_record(request.record.as_deref().unwrap()).unwrap();
                    let notes_update = command.body()["action"] == "notes"
                        && !command.body()["body"]["expected_head"].is_null();
                    let mut service = service.lock().await;
                    let reply = service.serve_hosted_space(&config, request, &replica).await;
                    replica
                        .set_admitted_devices(service.space_access_devices().unwrap())
                        .unwrap();
                    if reply.is_ok() && notes_update && lose_notes_ack.swap(false, Ordering::SeqCst)
                    {
                        return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
                    }
                    reply
                        .map(axum::Json)
                        .map_err(|_| axum::http::StatusCode::FORBIDDEN)
                }
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Normal hosted setup registers the local seed before device refresh.
    let seed = &a.authorities.0[0];
    a.call_space(
        &address,
        "call_head_publish",
        json!({"space":seed.space(),"stream":seed.stream(),"proof":seed.call_proof().unwrap()}),
    )
    .await
    .unwrap();
    let pa = a.prepare_notes(&general).unwrap().call_proof().unwrap();
    let pb = b.prepare_notes(&general).unwrap().call_proof().unwrap();
    assert_ne!(
        pa.genesis, pb.genesis,
        "devices have distinct private namespaces"
    );
    let claim = |proof| json!({"general_head":general.head_id(),"proof":proof});
    let (ra, rb) = tokio::join!(
        a.call_space(&address, "notes", claim(pa)),
        b.call_space(&address, "notes", claim(pb))
    );
    assert_eq!(
        ra.unwrap()["proof"],
        rb.unwrap()["proof"],
        "one immutable CAS winner"
    );
    let open =
        |app: &ClientApp| json!({"op":"contact_open","identity":app.identity_id(),"name":"Notes"});
    let first = a.operate(open(&a)).await.unwrap();
    let other = b.operate(open(&b)).await.unwrap();
    assert_eq!(first["stream"], other["stream"]);
    let stream: StreamId = serde_json::from_value(first["stream"].clone()).unwrap();
    let notes = a
        .authorities
        .0
        .iter()
        .find(|a| a.stream() == stream)
        .unwrap()
        .clone();
    assert_eq!(notes.head().unwrap().v, 3);
    assert_eq!(notes.head().unwrap().members.len(), 1);
    assert_eq!(notes.head().unwrap().members[0].credential_ids.len(), 2);
    assert_ne!(notes.space(), general.space());
    if notes.controller().id() != a.session.credential().id() {
        std::mem::swap(&mut a, &mut b);
    }
    let send = |app: &ClientApp, text: &str| {
        json!({"op":"send","space":notes.space(),"stream":stream,"text":text,
        "created_at":"2026-10-02T12:00:00Z","expires_in_hours":1,"expected_identity":app.identity_id()})
    };
    a.operate(send(&a, "Only my accepted devices can read A"))
        .await
        .unwrap();
    b.operate(send(&b, "Only my accepted devices can read B"))
        .await
        .unwrap();
    for _ in 0..2 {
        a.operate(json!({"op":"sync"})).await.unwrap();
        b.operate(json!({"op":"sync"})).await.unwrap();
    }
    for app in [&a, &b] {
        let originals = app.originals(&notes).await.unwrap();
        let messages = originals
            .iter()
            .filter(|(r, _)| r.body()["kind"] == "chat.message")
            .collect::<Vec<_>>();
        assert_eq!(
            messages.len(),
            2,
            "records: {:?}; peers: {}",
            originals
                .iter()
                .map(|(r, _)| r.body()["kind"].clone())
                .collect::<Vec<_>>(),
            app.peers.len()
        );
        for (message, _) in messages {
            let chat = message.chat().unwrap();
            assert_eq!(chat.audience, vec![app.identity_id()]);
            assert_eq!(chat.recipient_credentials.len(), 2);
            assert!(chat.payload.expires_at_ms.is_some());
            let credentials = chat
                .recipient_credentials
                .iter()
                .map(|id| notes.credential(*id).unwrap().clone())
                .collect::<Vec<_>>();
            let encrypted = crypto::seal_chat(message, &credentials).unwrap();
            let stranger = age::x25519::Identity::generate();
            assert!(crypto::open_object(&encrypted, &stranger).is_err());
        }
        assert!(app.invitation_state().unwrap().session_notices.is_empty());
    }
    // Read/unread and thread preferences use private encrypted transport, even
    // though the referenced message belongs to an ordinary conversation.
    let marker_stream = general.stream();
    let marker_space = general.space();
    let created = a
        .operate(
            json!({"op":"send","space":marker_space,"stream":marker_stream,
        "text":"Read privately on another approved device","created_at":"2026-10-02T12:00:00Z"}),
        )
        .await
        .unwrap();
    let marker: RecordId = created["sent"]["id"].as_str().unwrap().parse().unwrap();
    for _ in 0..2 {
        a.operate(json!({"op":"sync"})).await.unwrap();
        b.operate(json!({"op":"sync"})).await.unwrap();
    }
    let mark = |op| json!({"op":op,"space":marker_space,"stream":marker_stream,"records":[marker]});
    a.operate(mark("mark_unread")).await.unwrap();
    a.operate(json!({"op":"thread_follow","space":marker_space,"stream":marker_stream,"message":marker,"followed":true})).await.unwrap();
    for _ in 0..2 {
        a.operate(json!({"op":"sync"})).await.unwrap();
        b.operate(json!({"op":"sync"})).await.unwrap();
    }
    assert!(
        b.read
            .unread
            .get(&marker_stream.to_string())
            .unwrap()
            .contains(&marker.to_string())
    );
    assert_eq!(b.private_thread_follows(marker_stream, true), vec![marker]);
    let source = a.store.private_settings_sources(0).await.unwrap()[0]
        .1
        .clone();
    let cipher = a.store.get_object(source.object).await.unwrap().unwrap();
    let mut unsupported = crypto::open_object(&cipher, a.session.age_identity())
        .unwrap()
        .chat()
        .unwrap();
    let mut payload: Value = serde_json::from_str(&unsupported.payload.text).unwrap();
    payload["v"] = json!(2);
    unsupported.payload.text = serde_json::to_string(&payload).unwrap();
    unsupported.issuer_credential = b.session.credential().id();
    unsupported.nonce = record::random_hex::<16>().unwrap();
    let unsupported = notes
        .prepare_chat(unsupported, b.session.signing_key())
        .unwrap();
    let recipients = unsupported
        .chat()
        .unwrap()
        .recipient_credentials
        .iter()
        .map(|id| notes.credential(*id).unwrap().clone())
        .collect::<Vec<_>>();
    let cipher = crypto::seal_chat(&unsupported, &recipients).unwrap();
    a.store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                unsupported.id(),
                cipher,
                RecordMetadata::new(
                    "chat.private-settings",
                    Some(notes.space()),
                    Some(stream),
                    notes.head_id(),
                )
                .unwrap(),
                vec![],
                now().unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let unsupported_source = a
        .store
        .private_settings_sources(0)
        .await
        .unwrap()
        .into_iter()
        .find(|(_, source)| source.record == unsupported.id())
        .unwrap()
        .1;
    assert!(
        a.verify_private_settings_source(&unsupported_source)
            .await
            .is_err()
    );
    a.receive_private_settings().await.unwrap();
    assert!(a.read.unread[&marker_stream.to_string()].contains(&marker.to_string()));
    // An unsupported schema must not prevent the next valid remote read.
    b.operate(mark("mark_read")).await.unwrap();
    b.operate(json!({"op":"thread_follow","space":marker_space,"stream":marker_stream,"message":marker,"followed":false})).await.unwrap();
    for _ in 0..2 {
        b.operate(json!({"op":"sync"})).await.unwrap();
        a.operate(json!({"op":"sync"})).await.unwrap();
    }
    assert!(
        !a.read
            .unread
            .get(&marker_stream.to_string())
            .unwrap()
            .contains(&marker.to_string())
    );
    assert!(
        a.read
            .seen
            .get(&marker_stream.to_string())
            .unwrap()
            .contains(&marker.to_string())
    );
    assert_eq!(a.private_thread_follows(marker_stream, false), vec![marker]);
    assert!(a.private_thread_follows(marker_stream, true).is_empty());
    // Private events are not rendered as messages or delivered as notifications.
    let visible = a.view().await.unwrap();
    let visible_notes = visible["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["stream"] == json!(stream))
        .unwrap();
    assert_eq!(visible_notes["rows"].as_array().unwrap().len(), 2);
    assert_eq!(visible_notes["unread_count"], 0);
    assert_eq!(visible_notes["unfollowed_threads"], json!([]));
    assert_eq!(
        visible["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["stream"] == json!(marker_stream))
            .unwrap()["unfollowed_threads"],
        json!([marker])
    );
    // A temporarily unavailable Notes authority cannot consume the inbox cursor.
    let authorities = a.authorities.clone();
    a.authorities
        .0
        .retain(|authority| authority.stream() != stream);
    let mut read = (*a.read).clone();
    read.private_settings
        .as_mut()
        .unwrap()
        .reset_cursor_for_test();
    a.read = read.into();
    assert!(!a.receive_private_settings().await.unwrap());
    assert_eq!(a.read.private_settings.as_ref().unwrap().cursor(), 0);
    a.authorities = authorities;
    a.receive_private_settings().await.unwrap();
    assert!(a.read.private_settings.as_ref().unwrap().cursor() > 0);
    let private_sources = a.store.private_settings_sources(0).await.unwrap();
    assert!(!private_sources.is_empty());
    for (_, source) in private_sources {
        let ciphertext = a.store.get_object(source.object).await.unwrap().unwrap();
        assert!(crypto::open_object(&ciphertext, &age::x25519::Identity::generate()).is_err());
        let event = crypto::open_object(&ciphertext, a.session.age_identity()).unwrap();
        assert_eq!(event.chat().unwrap().audience, vec![a.identity_id()]);
        assert_eq!(event.chat().unwrap().kind, "chat.private-settings");
    }
    // A formerly accepted issuer cannot send new private preferences after
    // its credential is removed from the currently pinned Notes head.
    let mut b_source = None;
    for (_, source) in a.store.private_settings_sources(0).await.unwrap() {
        let ciphertext = a.store.get_object(source.object).await.unwrap().unwrap();
        let candidate = crypto::open_object(&ciphertext, a.session.age_identity()).unwrap();
        if candidate.chat().unwrap().issuer_credential == b.session.credential().id()
            && serde_json::from_str::<Value>(&candidate.chat().unwrap().payload.text).unwrap()["v"]
                == 1
        {
            b_source = Some(source);
            break;
        }
    }
    let b_source = b_source.unwrap();
    a.verify_private_settings_source(&b_source).await.unwrap();
    let mut narrowed = notes.clone();
    let mut next = narrowed.head().unwrap().clone();
    next.sequence += 1;
    next.previous_config_id = narrowed.head_id();
    next.nonce = record::random_hex::<16>().unwrap();
    next.action.operation = "device.updated".into();
    next.members[0]
        .credential_ids
        .retain(|id| *id != b.session.credential().id());
    next.owner_credential_ids = next.members[0].credential_ids.clone();
    narrowed
        .apply_config(next.sign(a.session.signing_key()).unwrap())
        .unwrap();
    let notes_index = a
        .authorities
        .0
        .iter()
        .position(|authority| authority.stream() == stream)
        .unwrap();
    a.authorities.0[notes_index] = narrowed;
    assert!(a.verify_private_settings_source(&b_source).await.is_err());
    a.authorities.0[notes_index] = notes.clone();
    // Pair after Notes already exists. A lost Notes ACK must not roll back
    // General pairing or cause a second Notes namespace on retry.
    let third = a.session.linked_companion().unwrap();
    lose_notes_ack.store(true, Ordering::SeqCst);
    a.authorize_linked_owner_device(third.credential())
        .await
        .unwrap();
    assert!(
        !lose_notes_ack.load(Ordering::SeqCst),
        "exercise the lost Notes ACK"
    );
    assert_eq!(
        a.authorities
            .0
            .iter()
            .find(|n| n.stream() == stream)
            .unwrap()
            .head()
            .unwrap()
            .members[0]
            .credential_ids
            .len(),
        2
    );
    a.authorize_linked_owner_device(third.credential())
        .await
        .unwrap();
    let current_notes = a
        .authorities
        .0
        .iter()
        .find(|n| n.stream() == stream)
        .unwrap()
        .clone();
    assert_eq!(
        current_notes.head().unwrap().members[0]
            .credential_ids
            .len(),
        3
    );
    assert_eq!(
        current_notes.head().unwrap().sequence,
        2,
        "retry imports the already committed grant"
    );
    let mut c = paired_copy(&a, &third, temp.path().join("c"), &address).await;
    enroll(&c, &service, &config).await;
    assert_eq!(c.operate(open(&c)).await.unwrap()["stream"], json!(stream));
    install_general(&mut b, &a.notes_general().unwrap(), &address).await;
    b.operate(open(&b)).await.unwrap();
    let count = a.pins.len();
    a.operate(open(&a)).await.unwrap();
    assert_eq!(a.pins.len(), count);
    let path = a.directory.clone();
    a.close().await.unwrap();
    // The granting controller is closed while both accepted devices write and
    // replicate normally through their own admitted credentials.
    b.operate(send(&b, "B while the Notes controller is offline"))
        .await
        .unwrap();
    c.operate(send(&c, "C while the Notes controller is offline"))
        .await
        .unwrap();
    for _ in 0..2 {
        b.operate(json!({"op":"sync"})).await.unwrap();
        c.operate(json!({"op":"sync"})).await.unwrap();
    }
    for app in [&b, &c] {
        let originals = app.originals(&current_notes).await.unwrap();
        assert_eq!(
            originals
                .iter()
                .filter(|(r, _)| r.body()["kind"] == "chat.message")
                .count(),
            4
        );
    }
    let mut a = ClientApp::open(path, PASSWORD.into(), true).await.unwrap();
    a.call_host = Some(address.clone());
    assert_eq!(a.operate(open(&a)).await.unwrap()["stream"], json!(stream));
    assert_eq!(a.pins.len(), count);
    assert_eq!(a.private_thread_follows(marker_stream, false), vec![marker]);
    assert!(a.read.seen[&marker_stream.to_string()].contains(&marker.to_string()));
    let restored = PublicSpaceService::open(temp.path().join("host"), true).unwrap();
    *service.lock().await = restored;
    assert_eq!(b.operate(open(&b)).await.unwrap()["stream"], json!(stream));
    server.abort();
    let _ = server.await;
    a.close().await.unwrap();
    b.close().await.unwrap();
    c.close().await.unwrap();
}

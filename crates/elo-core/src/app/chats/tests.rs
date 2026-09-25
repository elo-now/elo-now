use super::*;
use crate::vault::ControllerMode;
use tempfile::TempDir;

const PASSWORD: &str = "public synthetic chat creation password";

async fn profile(path: PathBuf) -> ClientApp {
    ProfileDraft::new()
        .unwrap()
        .save(path, PASSWORD.into(), "General")
        .await
        .unwrap()
}

// Exercise the normal signed configuration importer with a real foreign chat.
async fn share(owner: &mut ClientApp, guest: &mut ClientApp, output: &Path) {
    let a = &mut owner.authorities.0[0];
    let credential = guest.session.credential();
    a.add_credential(credential.clone());
    let mut config = a.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = a.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.action.operation = "replace".into();
    config.members.push(Member {
        identity_id: credential.identity(),
        identity_type: "HUMAN".into(),
        root_public_key: credential.record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into(),
        capabilities: vec![Capability::Read, Capability::Post],
        credential_ids: vec![credential.id()],
        external: true,
    });
    config.members.sort_by_key(|m| m.identity_id);
    a.commit_update(
        &owner.store,
        config.sign(owner.session.signing_key()).unwrap(),
        owner.session.age_identity(),
        now().unwrap(),
    )
    .await
    .unwrap();
    let pin = owner.pins[0].clone();
    owner
        .operate(json!({"op":"export_config", "space":pin.space,
            "stream":pin.stream, "credential":credential.id(), "output":output}))
        .await
        .unwrap();
    guest
        .operate(json!({"op":"import_stream", "space":pin.space,
            "stream":pin.stream, "root":pin.root, "path":output, "name":"Shared"}))
        .await
        .unwrap();
}

#[tokio::test]
async fn message_backup_keeps_file_messages_without_sent_or_downloaded_content() {
    let temp = TempDir::new().unwrap();
    let mut app = profile(temp.path().join("profile")).await;
    let mut owner = profile(temp.path().join("owner")).await;
    share(&mut owner, &mut app, &temp.path().join("share.age")).await;
    let chat = app.pins[1].clone();
    let replica = crate::replica::ReplicaStore::open(temp.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
    let listener = crate::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let descriptor = PeerDescriptor {
        url: format!("http://{}", listener.local_addr().unwrap()),
        signing_public_key: record::encode_hex(replica.key().as_bytes()),
        mailbox_id: mailbox.mailbox_id,
        read_token: Some(mailbox.read_token),
        write_token: Some(mailbox.write_token),
    };
    app.allow_loopback = true;
    owner.allow_loopback = true;
    app.ensure_peer(descriptor.clone()).unwrap();
    owner.ensure_peer(descriptor).unwrap();
    let server = tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, crate::http::router(replica, &origin))
        }
        .await
        .unwrap();
    });
    let sent = temp.path().join("sent.txt");
    let received = temp.path().join("received.txt");
    std::fs::write(&sent, b"Synthetic sent file".repeat(4096)).unwrap();
    std::fs::write(&received, b"Synthetic received file".repeat(4096)).unwrap();
    owner
        .operate(
            json!({"op":"file_share", "space":chat.space, "stream":chat.stream, "path":received}),
        )
        .await
        .unwrap();
    owner.operate(json!({"op":"sync"})).await.unwrap();
    app.operate(json!({"op":"sync"})).await.unwrap();
    app.operate(json!({"op":"file_share", "space":chat.space, "stream":chat.stream, "path":sent}))
        .await
        .unwrap();
    app.operate(
        json!({"op":"send", "space":chat.space, "stream":chat.stream,
        "text":"Both attachment messages survive backup", "created_at":"2026-09-13T12:00:00Z"}),
    )
    .await
    .unwrap();
    app.operate(json!({"op":"sync"})).await.unwrap();
    let view = app.view().await.unwrap();
    let rows = view["streams"][1]["rows"].as_array().unwrap();
    let attachments: Vec<_> = rows
        .iter()
        .filter(|row| row["body"]["kind"] == "file.shared")
        .collect();
    assert_eq!(attachments.len(), 2);
    let received_row = attachments
        .iter()
        .find(|row| row["body"]["filename"] == "received.txt")
        .unwrap();
    let record = received_row["id"].clone();
    app.operate(
        json!({"op":"file_download", "space":chat.space, "stream":chat.stream,
        "record":record, "output":temp.path().join("download.txt")}),
    )
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(temp.path().join("download.txt")).unwrap(),
        std::fs::read(&received).unwrap()
    );
    let objects: Vec<crate::ids::ObjectId> = attachments
        .iter()
        .map(|row| serde_json::from_value(row["body"]["object_id"].clone()).unwrap())
        .collect();
    for object in &objects {
        assert!(app.store.get_object(*object).await.unwrap().is_some());
    }
    let before = app.store.backup_image(8 * 1024 * 1024).await.unwrap();
    let backup = app.export_profile(PASSWORD.into()).await.unwrap();
    // Trusted device linking remains a separate complete copy.
    let device_copy = app
        .export_device_copy(PASSWORD.into(), &app.session)
        .await
        .unwrap();
    assert!(device_copy.len() > backup.len() + 100_000);
    assert_eq!(
        app.store.backup_image(8 * 1024 * 1024).await.unwrap(),
        before
    );
    let mut restored = ClientApp::restore_profile(
        temp.path().join("restored"),
        &backup,
        PASSWORD.into(),
        app.identity_id(),
        PASSWORD.into(),
        true,
    )
    .await
    .unwrap();
    let restored_view = restored.view().await.unwrap();
    assert_eq!(
        restored_view["streams"][1]["rows"],
        view["streams"][1]["rows"]
    );
    for object in objects {
        assert!(restored.store.get_object(object).await.unwrap().is_none());
    }
    let peers = std::mem::take(&mut restored.peers);
    let output = temp.path().join("restored-download.txt");
    let request = json!({"op":"file_download", "space":chat.space, "stream":chat.stream,
        "record":record, "output":output});
    assert!(restored.operate(request.clone()).await.is_err());
    assert!(!output.exists());
    restored.peers = peers;
    restored.operate(request).await.unwrap();
    assert_eq!(
        std::fs::read(output).unwrap(),
        std::fs::read(received).unwrap()
    );
    restored.close().await.unwrap();
    app.close().await.unwrap();
    owner.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn hundred_chats_keep_large_read_state_through_import_restart_and_backup() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("many-chats");
    let mut app = profile(path.clone()).await;
    for i in 1..98 {
        let kind = if i % 2 == 0 {
            ChatKind::Chat
        } else {
            ChatKind::Direct
        };
        app.create_chat(&format!("Synthetic chat {i}"), None, kind)
            .await
            .unwrap();
    }
    app.operate(json!({"op":"create_chat", "name":"Created after chat 32"}))
        .await
        .unwrap();
    assert_eq!(app.pins.len(), 99);
    let mut owner = profile(temp.path().join("owner")).await;
    share(&mut owner, &mut app, &temp.path().join("import.age")).await;
    owner.close().await.unwrap();
    assert_eq!(app.pins.len(), 100);

    // Model a long-lived read-marker file independently of stored history.
    // Distinct seen/unread IDs exceed both the former 64k total and 2 MiB cap.
    // This fixture contains markers, not 200,000 stored messages.
    let mut read = ReadState {
        v: 1,
        ..ReadState::default()
    };
    for (i, pin) in app.pins.iter().enumerate() {
        read.seen.insert(
            pin.stream.to_string(),
            (0..1000).map(|n| format!("{i:08x}{n:056x}")).collect(),
        );
        read.unread.insert(
            pin.stream.to_string(),
            (1000..2000).map(|n| format!("{i:08x}{n:056x}")).collect(),
        );
        if i < 99 {
            read.muted_streams.insert(pin.stream);
        }
    }
    assert!(serde_json::to_vec(&read).unwrap().len() > MAX_EXCHANGE);
    app.write_read_state(&read).unwrap();
    app.read = read.into();
    let chat = app.pins.last().unwrap().clone();
    let sent = app
        .operate(
            json!({"op":"send", "space":chat.space, "stream":chat.stream,
            "text":"The hundredth chat keeps its history", "created_at":"2026-09-13T12:00:00Z"}),
        )
        .await
        .unwrap();
    let id = sent["view"]["streams"][99]["rows"][0]["id"].clone();
    for op in ["mark_read", "mark_unread"] {
        app.operate(json!({"op":op, "space":chat.space, "stream":chat.stream,
            "records":[id]}))
            .await
            .unwrap();
    }
    app.operate(json!({"op":"set_chat_muted", "space":chat.space,
        "stream":chat.stream, "muted":true}))
        .await
        .unwrap();
    assert_eq!(app.read.seen.len(), 100);
    assert_eq!(app.read.unread.len(), 100);
    assert_eq!(app.read.muted_streams.len(), 100);
    let expected_pins = serde_json::to_value(&app.pins).unwrap();
    let expected_read = serde_json::to_value(&app.read).unwrap();
    let expected_view = app.view().await.unwrap();
    assert_eq!(expected_view["streams"][99]["unread_count"], 1);

    // Resource bounds still reject oversized metadata without overwriting it.
    let before = std::fs::read(path.join("read-state.age")).unwrap();
    let mut oversized = app.read.clone();
    for i in 100..150 {
        oversized.seen.insert(
            format!("{i:032x}"),
            (0..1000).map(|n| format!("{i:08x}{n:056x}")).collect(),
        );
    }
    oversized.validate().unwrap();
    assert!(serde_json::to_vec(&oversized).unwrap().len() > MAX_READ_STATE);
    assert!(app.write_read_state(&oversized).is_err());
    assert_eq!(std::fs::read(path.join("read-state.age")).unwrap(), before);
    assert_eq!(serde_json::to_value(&app.read).unwrap(), expected_read);

    let identity = app.identity_id();
    app.close().await.unwrap();
    let app = ClientApp::open(path, PASSWORD.into(), false).await.unwrap();
    assert_eq!(app.view().await.unwrap(), expected_view);
    assert_eq!(serde_json::to_value(&app.read).unwrap(), expected_read);
    let backup = app.export_profile(PASSWORD.into()).await.unwrap();
    app.close().await.unwrap();
    let restored = ClientApp::restore_profile(
        temp.path().join("restored"),
        &backup,
        PASSWORD.into(),
        identity,
        PASSWORD.into(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(serde_json::to_value(&restored.pins).unwrap(), expected_pins);
    assert_eq!(serde_json::to_value(&restored.read).unwrap(), expected_read);
    let view = restored.view().await.unwrap();
    assert_eq!(view["streams"].as_array().unwrap().len(), 100);
    assert_eq!(
        view["streams"][99]["rows"],
        expected_view["streams"][99]["rows"]
    );
    assert_eq!(view["streams"][99]["unread_count"], 1);
    assert!(
        view["streams"]
            .as_array()
            .unwrap()
            .iter()
            .all(|chat| chat["muted"] == true)
    );
    restored.close().await.unwrap();
}

#[tokio::test]
async fn create_chat_without_recovery_is_private_durable_and_ignores_selected_guest_chat() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("owner");
    // profile() drops its only recovery card before returning.
    let mut app = profile(path.clone()).await;
    let mut other = profile(temp.path().join("other")).await;
    share(&mut app, &mut other, &temp.path().join("own.age")).await;
    share(&mut other, &mut app, &temp.path().join("foreign.age")).await;
    let before = app.view().await.unwrap();
    let original = before["streams"][0].clone();
    let foreign = before["streams"][1].clone();
    assert_eq!(original["members"].as_array().unwrap().len(), 2);
    assert_eq!(original["can_manage_members"], true);
    assert_eq!(foreign["can_manage_members"], false);
    let vault_before = std::fs::read(path.join("vault.age")).unwrap();

    let response = app
        .operate(json!({"op":"create_chat", "name":"  Weekend plans  ",
            "space":foreign["space"], "stream":foreign["stream"],
            "recovery_card":temp.path().join("does-not-exist.json")}))
        .await
        .unwrap();
    let chat = response["view"]["streams"][2].clone();
    assert_eq!(chat["name"], "Weekend plans");
    assert_eq!(chat["space"], original["space"]);
    assert_ne!(chat["space"], foreign["space"]);
    assert_ne!(chat["stream"], original["stream"]);
    assert_eq!(chat["members"].as_array().unwrap().len(), 1);
    assert_eq!(chat["members"][0]["identity_id"], before["identity"]);
    assert_eq!(chat["owners"].as_array().unwrap().len(), 1);
    assert_eq!(chat["can_post"], true);
    assert_eq!(chat["can_manage_members"], true);
    assert_eq!(response["view"]["streams"][0], original);
    assert_eq!(response["view"]["streams"][1], foreign);
    app.operate(
        json!({"op":"send", "space":chat["space"], "stream":chat["stream"],
        "text":"Only the new chat receives this message", "created_at":"2026-09-09T12:00:00Z"}),
    )
    .await
    .unwrap();
    let sent = app.view().await.unwrap();
    let body = &sent["streams"][2]["rows"][0]["body"];
    assert_eq!(body["recipient_credentials"], json!([before["credential"]]));
    assert_eq!(sent["streams"][0], original);
    assert_eq!(sent["streams"][1], foreign);
    assert_eq!(std::fs::read(path.join("vault.age")).unwrap(), vault_before);
    app.close().await.unwrap();
    other.close().await.unwrap();

    let mut reopened = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(reopened.view().await.unwrap(), sent);
    reopened
        .operate(json!({"op":"create_chat", "name":"Another chat"}))
        .await
        .unwrap();
    assert_eq!(reopened.pins.len(), 4);
    assert_eq!(std::fs::read(path.join("vault.age")).unwrap(), vault_before);
    for name in ["", "   ", &"a".repeat(121)] {
        assert!(
            reopened
                .create_chat(name, None, ChatKind::Chat)
                .await
                .is_err()
        );
    }
    assert_eq!(reopened.pins.len(), 4);
    // A guest-only profile cannot turn imported membership into ownership.
    reopened
        .authorities
        .0
        .retain(|a| a.space().to_string() == foreign["space"]);
    reopened
        .pins
        .retain(|p| p.space.to_string() == foreign["space"]);
    assert_eq!(reopened.pins.len(), 1);
    assert!(
        reopened
            .create_chat("Unauthorized", None, ChatKind::Chat)
            .await
            .is_err()
    );
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn create_chat_fails_closed_for_followers_retirement_forks_and_recovered_generations() {
    let temp = TempDir::new().unwrap();
    let draft = ProfileDraft::new().unwrap();
    let mut app = draft
        .save(temp.path().join("profile"), PASSWORD.into(), "General")
        .await
        .unwrap();
    let original = app.authorities.0[0].clone();
    let vault_before = std::fs::read(app.directory.join("vault.age")).unwrap();
    for mode in [ControllerMode::Follower, ControllerMode::Retired] {
        app.session.controller_mode = mode;
        assert_eq!(
            app.view().await.unwrap()["streams"][0]["can_manage_members"],
            false
        );
        assert!(
            app.create_chat("Unauthorized", None, ChatKind::Chat)
                .await
                .is_err()
        );
        assert_eq!(app.pins.len(), 1);
    }
    app.session.controller_mode = ControllerMode::Active;
    let grants = app.session.controller_spaces.take();
    app.session.controller_spaces = Some(vec![]);
    assert_eq!(
        app.view().await.unwrap()["streams"][0]["can_manage_members"],
        false
    );
    assert!(
        app.create_chat("No grant", None, ChatKind::Chat)
            .await
            .is_err()
    );
    app.session.controller_spaces = grants;
    let a = &mut app.authorities.0[0];
    let mut config = a.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = a.head_id();
    config.action.operation = "replace".into();
    for _ in 0..2 {
        config.nonce = record::random_hex::<16>().unwrap();
        a.apply_config(config.sign(app.session.signing_key()).unwrap())
            .unwrap();
    }
    assert!(a.is_forked());
    assert!(
        app.create_chat("Forked", None, ChatKind::Chat)
            .await
            .is_err()
    );
    assert_eq!(
        app.view().await.unwrap()["streams"][0]["can_manage_members"],
        false
    );

    let root = draft
        .card()
        .recover_root(app.session.identity_id())
        .unwrap();
    let mut fresh = Session::recover(draft.card(), app.session.identity_id()).unwrap();
    let mut recovered = original;
    recovered.add_credential(fresh.credential().clone());
    let certificate = recovered.sign_recovery(fresh.credential(), &root).unwrap();
    let config = recovered
        .prepare_recovery(&certificate, fresh.signing_key())
        .unwrap();
    recovered.apply_config(config).unwrap();
    fresh.activate_recovered_controller(&recovered).unwrap();
    app.session = fresh;
    app.authorities.0 = vec![recovered].into();
    assert_eq!(
        app.view().await.unwrap()["streams"][0]["can_manage_members"],
        true
    );
    assert_eq!(
        app.create_chat("Recovered", None, ChatKind::Chat)
            .await
            .unwrap_err()
            .to_string(),
        "new chat after controller recovery is not supported"
    );
    assert_eq!(app.pins.len(), 1);
    assert_eq!(
        std::fs::read(app.directory.join("vault.age")).unwrap(),
        vault_before
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn chat_type_creation_is_validated_and_legacy_dm_migration_is_durable() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("owner");
    let mut owner = profile(path.clone()).await;
    let before = owner.view().await.unwrap();
    for value in [json!("unknown"), json!(false), Value::Null, json!(1)] {
        assert!(
            owner
                .operate(json!({"op":"create_chat", "name":"Invalid", "chat_kind":value}))
                .await
                .is_err()
        );
        assert_eq!(owner.view().await.unwrap(), before);
    }
    // Reproduce a legacy signed stream without touching any existing fixture bytes.
    let source = &owner.authorities.0[0];
    let stream = record::random_hex::<16>().unwrap().parse().unwrap();
    let mut authority = Authority::new(
        source.genesis().bytes(),
        source.space(),
        &root_key(&owner.pins[0].root).unwrap(),
        owner.session.credential().clone(),
        stream,
    )
    .unwrap();
    let mut config = source.head().unwrap().clone();
    config.stream_id = stream;
    config.chat_kind = None;
    config.nonce = record::random_hex::<16>().unwrap();
    authority
        .commit_update(
            &owner.store,
            config.sign(owner.session.signing_key()).unwrap(),
            owner.session.age_identity(),
            now().unwrap(),
        )
        .await
        .unwrap();
    owner.authorities.0[0] = authority;
    owner.pins[0].stream = stream;
    owner.pins[0].chat_kind = None;
    owner
        .write_workspace(&Workspace {
            v: 2,
            pins: owner.pins.clone(),
            groups: vec![],
        })
        .unwrap();
    let mut alice = profile(temp.path().join("alice")).await;
    share(&mut owner, &mut alice, &temp.path().join("alice.age")).await;
    let original_head = owner.authorities.0[0].head_id();
    let original_vault = std::fs::read(path.join("vault.age")).unwrap();
    let snapshot_before = owner
        .store
        .authority_snapshot(owner.pins[0].space, stream)
        .await
        .unwrap();
    owner.close().await.unwrap();
    let mut owner = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(owner.pins[0].chat_kind, Some(ChatKind::Direct));
    assert_eq!(owner.authorities.0[0].head_id(), original_head);
    assert_eq!(
        owner
            .store
            .authority_snapshot(owner.pins[0].space, stream)
            .await
            .unwrap(),
        snapshot_before
    );
    assert_eq!(
        std::fs::read(path.join("vault.age")).unwrap(),
        original_vault
    );
    // The next invitation publishes the legacy choice, so a third participant gets it too.
    owner.ensure_chat_kind(0).await.unwrap();
    let mut bob = profile(temp.path().join("bob")).await;
    share(&mut owner, &mut bob, &temp.path().join("bob.age")).await;
    assert_eq!(owner.authorities.0[0].head().unwrap().members.len(), 3);
    assert_eq!(
        owner.view().await.unwrap()["streams"][0]["chat_kind"],
        "direct"
    );
    assert_eq!(
        bob.view().await.unwrap()["streams"][1]["chat_kind"],
        "direct"
    );
    let expected = owner.view().await.unwrap();
    owner.close().await.unwrap();
    let owner = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(owner.view().await.unwrap(), expected);
    assert_eq!(
        std::fs::read(path.join("vault.age")).unwrap(),
        original_vault
    );
    owner.close().await.unwrap();
    alice.close().await.unwrap();
    bob.close().await.unwrap();
}

#[tokio::test]
async fn personal_seed_stays_hidden_after_device_updates_without_hiding_real_chats() {
    let temp = TempDir::new().unwrap();
    let draft = ProfileDraft::new().unwrap();
    let mut app = draft
        .save(temp.path().join("profile"), PASSWORD.into(), "General")
        .await
        .unwrap();
    app.allow_loopback = true;
    app.create_chat("General", None, ChatKind::Chat)
        .await
        .unwrap();
    let seed = app.pins[0].clone();
    let ordinary = app.pins[1].clone();
    let foreign = profile(temp.path().join("foreign")).await;
    let descriptor = team::TeamDescriptor {
        v: 1,
        url: "http://127.0.0.1:9/team/v1/enroll".into(),
        token: "ab".repeat(32),
        scope: foreign.team_scope().unwrap(),
        message_lifetime_seconds: 86400,
    };
    app.configure_team(descriptor.clone()).unwrap();
    let authority = &mut app.authorities.0[0];
    let mut config = authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = authority.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.action.operation = "replace".into();
    authority
        .commit_update(
            &app.store,
            config.sign(app.session.signing_key()).unwrap(),
            app.session.age_identity(),
            now().unwrap(),
        )
        .await
        .unwrap();
    // Reproduce an existing seed written before the explicit marker existed.
    app.pins[0].personal_seed = None;
    app.persist_workspace().unwrap();
    app.close().await.unwrap();
    let mut app = ClientApp::open(temp.path().join("profile"), PASSWORD.into(), true)
        .await
        .unwrap();
    app.configure_team(descriptor).unwrap();
    assert_eq!(app.pins[0].personal_seed, Some(true));
    assert_eq!(app.pins[1].personal_seed, Some(false));
    app.pins.swap(0, 1);
    app.authorities.0.swap(0, 1);
    for paged in [false, true] {
        if paged {
            app.enable_paged_views();
        }
        let view = app.view().await.unwrap();
        assert_eq!(view["streams"].as_array().unwrap().len(), 1);
        assert_eq!(view["streams"][0]["stream"], json!(ordinary.stream));
    }
    let recovered =
        ProfileDraft::recover(&draft.card().phrase, &draft.card().identity_id.to_string())
            .unwrap()
            .save(temp.path().join("recovered"), PASSWORD.into(), "General")
            .await
            .unwrap();
    let request = recovered.control_recovery_request();
    let choices = app.control_recovery_choices(&request).await.unwrap();
    assert_eq!(choices["chats"].as_array().unwrap().len(), 1);
    assert_eq!(choices["chats"][0]["stream"], json!(ordinary.stream));
    assert!(
        app.control_recovery_export(
            &request,
            seed.space,
            seed.stream,
            recovered.control_recovery_device()
        )
        .await
        .is_err()
    );
    app.operate(json!({"op":"send", "space":seed.space, "stream":seed.stream, "text":"Preserve existing history", "created_at":"2026-09-25T09:00:00Z"})).await.unwrap();
    assert_eq!(
        app.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "a seed with real history stays accessible"
    );
    assert_eq!(
        app.control_recovery_choices(&request).await.unwrap()["chats"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    recovered.close().await.unwrap();
    foreign.close().await.unwrap();
    app.close().await.unwrap();
}

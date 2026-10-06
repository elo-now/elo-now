use super::*;
use crate::{
    ids::{MailboxId, ObjectId, PeerId},
    replica::{InventoryEntry, TransferHint},
};

const PASSWORD: &str = "synthetic local deletion password";

#[tokio::test]
async fn unverified_locator_pointers_cannot_delete_or_deny_another_conversations_records() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = profile(&temp.path().join("profile")).await;
    app.create_chat("Remove here", None, ChatKind::Chat)
        .await
        .unwrap();
    app.create_chat("Keep here", None, ChatKind::Chat)
        .await
        .unwrap();
    let pin = app.pins[1].clone();
    let other = app.pins[2].clone();
    let at = now().unwrap().as_millis() as u64;
    let kept = performance::message(&app, 2, at);
    let future = performance::message(&app, 2, at + 1000);
    assert!(receive(&app, 2, &kept, 1).await);
    let kept_object = app
        .store
        .display_sources(other.space, other.stream)
        .await
        .unwrap()[0]
        .object;
    for (sequence, target) in [(2, kept.id()), (3, future.id())] {
        let mut chat = performance::message(&app, 1, at).chat().unwrap();
        chat.kind = "chat.locator".into();
        chat.payload.text.clear();
        chat.payload.sender_name = None;
        chat.locator = Some(MessageLocator {
            message_record_id: target,
            body_object_id: kept_object,
            locator_nonce: record::random_hex::<16>().unwrap(),
            request_secret: "b1".repeat(32),
        });
        let locator = app.authorities.0[1]
            .prepare_chat(chat, app.session.signing_key())
            .unwrap();
        assert!(receive(&app, 1, &locator, sequence).await);
    }
    app.operate(json!({"op":"delete_chat_local","space":pin.space,"stream":pin.stream}))
        .await
        .unwrap();
    assert!(app.store.get_object(kept_object).await.unwrap().is_some());
    assert_eq!(
        app.originals(&app.authorities.0[2]).await.unwrap()[0]
            .0
            .id(),
        kept.id()
    );
    assert!(receive(&app, 2, &future, 4).await);
    assert!(receive(&app, 2, &kept, 5).await);
    assert_eq!(app.originals(&app.authorities.0[2]).await.unwrap().len(), 2);
    app.close().await.unwrap();
}

#[tokio::test]
async fn local_delete_protects_hosted_general_and_notes_without_matching_names() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = profile(&temp.path().join("profile")).await;
    app.create_chat("Renamed General", None, ChatKind::Chat)
        .await
        .unwrap();
    let general = app.pins[1].clone();
    let scope = team::TeamScope {
        space: general.space,
        stream: general.stream,
        root: general.root.clone(),
        controller: app.session.credential().id(),
    };
    let notes_stream = crate::notes::stream(scope.space, scope.stream, app.identity_id());
    app.create_chat_at("Renamed Notes", None, ChatKind::Direct, Some(notes_stream))
        .await
        .unwrap();
    let notes = app.pins[2].clone();
    app.call_host = Some(space_service::SpaceAddress {
        url: "https://example.invalid/team/v1/spaces".into(),
        scope: scope.clone(),
        message_lifetime_seconds: Default::default(),
        service_credential: None,
    });
    app.team = Some(team::TeamDescriptor {
        v: 1,
        url: "https://example.invalid/team/v1/enroll".into(),
        token: "00".repeat(32),
        scope,
        message_lifetime_seconds: Default::default(),
        service_credential: None,
    });
    for pin in [&general, &notes] {
        assert!(
            app.operate(json!({"op":"delete_chat_local","space":pin.space,"stream":pin.stream}))
                .await
                .is_err()
        );
        assert_eq!(
            app.store
                .local_chat_state(pin.space, pin.stream)
                .await
                .unwrap()
                .generation,
            0
        );
    }
    app.close().await.unwrap();
}

#[tokio::test]
async fn local_delete_returns_its_commit_receipt_when_an_unrelated_history_view_fails() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = profile(&temp.path().join("profile")).await;
    app.create_chat("Remove this", None, ChatKind::Chat)
        .await
        .unwrap();
    app.create_chat("Broken ciphertext fixture", None, ChatKind::Chat)
        .await
        .unwrap();
    let removed = app.pins[1].clone();
    let broken = &app.authorities.0[2];
    app.store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                RecordId::from_bytes([91; 32]),
                vec![42; 50],
                RecordMetadata::new(
                    "chat.message",
                    Some(broken.space()),
                    Some(broken.stream()),
                    broken.head_id(),
                )
                .unwrap(),
                vec![],
                now().unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let result = app
        .operate(json!({"op":"delete_chat_local","space":removed.space,"stream":removed.stream}))
        .await
        .unwrap();
    assert_eq!(result["deleted_chat"]["history_generation"], 1);
    assert_eq!(result["cleanup_pending"], true);
    assert!(result["view"].is_null());
    assert!(
        app.store
            .local_chat_state(removed.space, removed.stream)
            .await
            .unwrap()
            .hidden
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn local_delete_removes_verified_attachment_ciphertext_without_provider_requests() {
    use crate::attachments::{AttachmentDescriptor, AttachmentEncryption};
    let temp = tempfile::tempdir().unwrap();
    let mut app = profile(&temp.path().join("profile")).await;
    app.create_chat("Attachment fixture", None, ChatKind::Chat)
        .await
        .unwrap();
    app.create_chat("Forwarded attachment", None, ChatKind::Chat)
        .await
        .unwrap();
    let pin = app.pins[1].clone();
    let retained_pin = app.pins[2].clone();
    let input = temp.path().join("input");
    let encrypted = temp.path().join("ciphertext");
    std::fs::write(&input, b"synthetic attachment").unwrap();
    let plan = crate::attachments::crypto::plan(20).unwrap();
    let encrypted_result =
        crate::attachments::crypto::encrypt_file(&input, &encrypted, &plan, |_| {}).unwrap();
    let descriptor = AttachmentDescriptor {
        id: AttachmentId::from_bytes([61; 16]),
        name: "fixture.txt".into(),
        mime: "text/plain".into(),
        plaintext_size: 20,
        encrypted_size: encrypted_result.encrypted_size,
        created_at_ms: 1,
        expires_at_ms: None,
        object_id: AttachmentObjectId::from_bytes([62; 16]),
        external_storage: Some("https://provider.example.invalid/storage/v1".into()),
        encryption: AttachmentEncryption {
            algorithm: "xchacha20-poly1305-chunks-v1".into(),
            key: STANDARD.encode(plan.key.as_slice()),
            nonce_prefix: STANDARD.encode(plan.nonce_prefix),
            chunk_bytes: crate::attachments::ATTACHMENT_CHUNK_BYTES,
            ciphertext_sha256: encrypted_result.ciphertext_sha256.clone(),
        },
    };
    let share = crate::files::prepare_external(
        &app.authorities.0[1],
        app.session.credential().id(),
        descriptor.clone(),
        app.session.signing_key(),
    )
    .unwrap();
    let forwarded = crate::files::prepare_external(
        &app.authorities.0[2],
        app.session.credential().id(),
        descriptor.clone(),
        app.session.signing_key(),
    )
    .unwrap();
    app.store
        .commit_attachment_share(forwarded, vec![], now().unwrap())
        .await
        .unwrap();
    let record = share.shared.id();
    app.store
        .commit_attachment_share(share, vec![], now().unwrap())
        .await
        .unwrap();
    crate::attachments::cache::store(
        &app.directory,
        &encrypted,
        &encrypted_result.ciphertext_sha256,
    )
    .unwrap();
    let cache = app
        .directory
        .join("attachment-cache")
        .join(format!("{}.ciphertext", encrypted_result.ciphertext_sha256));
    assert!(cache.is_file());
    // A blocked sender is excluded from presentation, but its verified storage
    // references must still participate in cleanup and shared-cache ownership.
    let blocked = BTreeMap::from([(app.identity_id(), "Synthetic blocked sender")]);
    vault::write_private(
        &app.directory.join("blocked.age"),
        &crypto::seal_bytes(
            &serde_json::to_vec(&blocked).unwrap(),
            &[app.session.age_identity().to_public()],
            1024 * 1024,
        )
        .unwrap(),
        false,
    )
    .unwrap();
    app.blocked = blocking::Blocked::open(&app.directory, app.session.age_identity()).unwrap();
    assert!(
        app.originals(&app.authorities.0[1])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        app.originals(&app.authorities.0[2])
            .await
            .unwrap()
            .is_empty()
    );
    let result = app
        .operate(json!({"op":"delete_chat_local","space":pin.space,"stream":pin.stream}))
        .await
        .unwrap();
    assert_eq!(
        result["deleted_chat"]["attachment_records"],
        json!([record])
    );
    assert!(
        cache.exists(),
        "another verified conversation still references these encrypted bytes"
    );
    let request = json!({"space":pin.space,"stream":pin.stream,"record":record,"expected_identity":app.identity_id(),"expected_space":null});
    assert!(
        app.cached_attachment(&request, &temp.path().join("restored"))
            .await
            .is_err()
    );
    assert!(!temp.path().join("restored").exists());
    app.operate(
        json!({"op":"delete_chat_local","space":retained_pin.space,"stream":retained_pin.stream}),
    )
    .await
    .unwrap();
    assert!(!cache.exists());
    app.close().await.unwrap();
}

#[tokio::test]
async fn local_delete_rejects_history_bundle_replay_without_touching_another_signed_scope() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = profile(&temp.path().join("profile")).await;
    app.create_chat("Same label", None, ChatKind::Chat)
        .await
        .unwrap();
    app.create_chat("Same label", None, ChatKind::Chat)
        .await
        .unwrap();
    let pin = app.pins[1].clone();
    let old = performance::message(&app, 1, 100);
    let other = performance::message(&app, 2, 200);
    assert!(receive(&app, 2, &other, 1).await);
    let authority = &app.authorities.0[1];
    let request = history::create_request(
        authority,
        app.session.credential().id(),
        2,
        None,
        app.session.signing_key(),
    )
    .unwrap();
    let grant = history::approve(
        authority,
        &request,
        app.session.credential().id(),
        std::slice::from_ref(&old),
        app.session.signing_key(),
    )
    .unwrap();
    assert!(
        history::approve(
            authority,
            &request,
            app.session.credential().id(),
            std::slice::from_ref(&other),
            app.session.signing_key()
        )
        .is_err()
    );
    let cipher = history::seal(authority, &grant).unwrap();
    let bundle = history::VerifiedBundle::open(
        &cipher,
        app.session.age_identity(),
        app.session.credential().id(),
        authority,
        &request,
    )
    .unwrap();
    app.store
        .import_history(bundle, now().unwrap())
        .await
        .unwrap();
    assert_eq!(
        app.originals(&app.authorities.0[1]).await.unwrap()[0]
            .0
            .id(),
        old.id()
    );
    app.operate(json!({"op":"delete_chat_local","space":pin.space,"stream":pin.stream}))
        .await
        .unwrap();
    let bundle = history::VerifiedBundle::open(
        &cipher,
        app.session.age_identity(),
        app.session.credential().id(),
        &app.authorities.0[1],
        &request,
    )
    .unwrap();
    app.store
        .import_history(bundle, now().unwrap())
        .await
        .unwrap();
    assert!(
        app.store
            .get_object(ObjectId::of_ciphertext(&cipher))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        app.originals(&app.authorities.0[1])
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        app.originals(&app.authorities.0[2]).await.unwrap()[0]
            .0
            .id(),
        other.id()
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn local_delete_denies_a_missing_locator_body_and_never_removes_authority() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = profile(&temp.path().join("profile")).await;
    app.create_chat("Locator fixture", None, ChatKind::Chat)
        .await
        .unwrap();
    let pin = app.pins[1].clone();
    let authority = &app.authorities.0[1];
    let body = performance::message(&app, 1, now().unwrap().as_millis() as u64 + 60_000);
    let credentials = body
        .chat()
        .unwrap()
        .recipient_credentials
        .into_iter()
        .map(|id| authority.credential(id).unwrap().clone())
        .collect::<Vec<_>>();
    let ciphertext = crypto::seal_chat(&body, &credentials).unwrap();
    let object = ObjectId::of_ciphertext(&ciphertext);
    let mut chat = body.chat().unwrap();
    chat.kind = "chat.locator".into();
    chat.nonce = record::random_hex::<16>().unwrap();
    chat.payload.text.clear();
    chat.payload.sender_name = None;
    chat.locator = Some(MessageLocator {
        message_record_id: body.id(),
        body_object_id: object,
        locator_nonce: body.chat().unwrap().nonce,
        request_secret: "a1".repeat(32),
    });
    let locator = authority
        .prepare_chat(chat, app.session.signing_key())
        .unwrap();
    assert!(receive(&app, 1, &locator, 1).await);
    let head = app.authorities.0[1].head_id();
    app.operate(json!({"op":"delete_chat_local","space":pin.space,"stream":pin.stream}))
        .await
        .unwrap();
    assert_eq!(app.authorities.0[1].head_id(), head);
    assert!(
        app.store
            .authority_snapshot(pin.space, pin.stream)
            .await
            .unwrap()
            .is_some()
    );
    assert!(app.operate(json!({"op":"request_message","space":pin.space,"stream":pin.stream,"locator":locator.id()})).await.is_err());
    assert!(!receive(&app, 1, &body, 2).await);
    app.store
        .stage_inbox(
            PeerId::from_bytes([1; 32]),
            MailboxId::from_bytes([2; 32]),
            "03".repeat(32),
            InventoryEntry {
                arrival_seq: 3,
                object_id: object,
                size_bytes: ciphertext.len() as u64,
                transfer_hint: TransferHint::Eager,
            },
            Some(ciphertext),
            now().unwrap(),
        )
        .await
        .unwrap();
    let item = app.store.pending_inbox(128).await.unwrap().remove(0);
    assert!(
        !app.store
            .finish_inbox(
                item,
                Some(
                    app.authorities.0[1]
                        .verify(&body, app.session.credential().id())
                        .unwrap()
                ),
                now().unwrap()
            )
            .await
            .unwrap()
    );
    assert!(app.store.pending_inbox(128).await.unwrap().is_empty());
    assert!(app.store.get_object(object).await.unwrap().is_none());
    app.close().await.unwrap();
}

async fn profile(path: &Path) -> ClientApp {
    ProfileDraft::new()
        .unwrap()
        .save(path.to_path_buf(), PASSWORD.into(), "General")
        .await
        .unwrap()
}

async fn receive(app: &ClientApp, index: usize, record: &SignedRecord, sequence: u64) -> bool {
    let authority = &app.authorities.0[index];
    let credentials = record
        .chat()
        .unwrap()
        .recipient_credentials
        .into_iter()
        .map(|id| authority.credential(id).unwrap().clone())
        .collect::<Vec<_>>();
    // Re-encryption deliberately gives a replay a different transport object.
    let ciphertext = crypto::seal_chat(record, &credentials).unwrap();
    let object = ObjectId::of_ciphertext(&ciphertext);
    app.store
        .stage_inbox(
            PeerId::from_bytes([1; 32]),
            MailboxId::from_bytes([2; 32]),
            "03".repeat(32),
            InventoryEntry {
                arrival_seq: sequence,
                object_id: object,
                size_bytes: ciphertext.len() as u64,
                transfer_hint: TransferHint::Eager,
            },
            Some(ciphertext),
            now().unwrap(),
        )
        .await
        .unwrap();
    let item = app
        .store
        .pending_inbox(128)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.object == object)
        .unwrap();
    app.store
        .finish_inbox(
            item,
            Some(
                authority
                    .verify(record, app.session.credential().id())
                    .unwrap(),
            ),
            now().unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn local_delete_survives_restart_blocks_replay_and_old_offline_messages_but_accepts_new() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profile");
    let mut app = profile(&path).await;
    app.create_chat("Same label", None, ChatKind::Chat)
        .await
        .unwrap();
    app.create_chat("Same label", None, ChatKind::Chat)
        .await
        .unwrap();
    let pin = app.pins[1].clone();
    let other = app.pins[2].clone();
    let at = now().unwrap().as_millis() as u64;
    let old = performance::message(&app, 1, at - 1000);
    let future_old = performance::message(&app, 1, at + 86_400_000);
    let unseen_old = performance::message(&app, 1, at - 500);
    let other_message = performance::message(&app, 2, at);
    assert!(receive(&app, 1, &old, 1).await);
    assert!(receive(&app, 1, &future_old, 2).await);
    assert!(receive(&app, 2, &other_message, 3).await);
    app.read.seen.insert(
        pin.stream.to_string(),
        vec![old.id().to_string(), other_message.id().to_string()],
    );
    app.read
        .seen
        .get_mut(&pin.stream.to_string())
        .unwrap()
        .sort();
    app.enable_paged_views();
    let history_request = json!({"op":"history_page","expected_identity":app.identity_id(),"space":pin.space,"stream":pin.stream,"history_generation":0});
    let snapshot = app.history_snapshot();
    assert_eq!(
        snapshot.history_page(&history_request).await.unwrap()["history"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let deleted = app
        .operate(json!({"op":"delete_chat_local","space":pin.space,"stream":pin.stream}))
        .await
        .unwrap();
    assert_eq!(deleted["deleted_chat"]["history_generation"], 1);
    assert_eq!(deleted["cleanup_pending"], false);
    assert_eq!(
        app.read.seen[&pin.stream.to_string()],
        vec![other_message.id().to_string()],
        "read buckets retain unrelated signed records even when stream identifiers collide"
    );
    assert!(
        deleted["view"]["streams"]
            .as_array()
            .unwrap()
            .iter()
            .all(|stream| stream["stream"] != json!(pin.stream))
    );
    assert!(
        snapshot.history_page(&history_request).await.is_err(),
        "a snapshot captured before removal must not return cached content"
    );
    assert_eq!(
        app.originals(&app.authorities.0[2]).await.unwrap()[0]
            .0
            .id(),
        other_message.id()
    );
    assert!(!receive(&app, 1, &old, 4).await);
    assert!(
        !receive(&app, 1, &future_old, 5).await,
        "known IDs cannot bypass deletion using a future signed clock"
    );
    assert!(!receive(&app, 1, &unseen_old, 6).await);
    assert!(
        app.store
            .local_chat_state(pin.space, pin.stream)
            .await
            .unwrap()
            .hidden
    );
    assert!(
        app.originals(&app.authorities.0[1])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        app.operate(
            json!({"op":"request_message","space":pin.space,"stream":pin.stream,"locator":old.id()})
        )
        .await
        .is_err()
    );
    app.close().await.unwrap();

    let mut app = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert!(
        app.store
            .local_chat_state(pin.space, pin.stream)
            .await
            .unwrap()
            .hidden
    );
    assert!(!receive(&app, 1, &future_old, 7).await);
    let mut reply = performance::message(&app, 1, now().unwrap().as_millis() as u64 + 1000)
        .chat()
        .unwrap();
    reply.payload.thread_root = Some(old.id());
    let fresh = app.authorities.0[1]
        .prepare_chat(reply, app.session.signing_key())
        .unwrap();
    assert!(receive(&app, 1, &fresh, 8).await);
    let state = app
        .store
        .local_chat_state(pin.space, pin.stream)
        .await
        .unwrap();
    assert!(!state.hidden);
    assert_eq!(state.generation, 1);
    assert_eq!(
        app.originals(&app.authorities.0[1])
            .await
            .unwrap()
            .iter()
            .map(|(r, _)| r.id())
            .collect::<Vec<_>>(),
        vec![fresh.id()]
    );
    assert!(
        app.operate(history_request.clone()).await.is_err(),
        "old renderer requests cannot accept new history under the previous generation"
    );
    let mut history_request = history_request;
    history_request["history_generation"] = json!(1);
    let history = app.operate(history_request).await.unwrap();
    assert_eq!(history["history"]["history_generation"], 1);
    assert!(
        history["history"]["context"].as_array().unwrap().is_empty(),
        "a new reply must not restore its removed parent"
    );
    assert_eq!(
        app.originals(&app.authorities.0[2]).await.unwrap()[0]
            .0
            .id(),
        other_message.id()
    );
    assert_eq!(app.pins[2].stream, other.stream);
    app.close().await.unwrap();
}

#[tokio::test]
async fn local_delete_protects_seed_and_does_not_transfer_device_markers() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = profile(&temp.path().join("profile")).await;
    let seed = app.pins[0].clone();
    assert!(
        app.operate(json!({"op":"delete_chat_local","space":seed.space,"stream":seed.stream}))
            .await
            .is_err()
    );
    app.create_chat("Ordinary chat", None, ChatKind::Chat)
        .await
        .unwrap();
    let pin = app.pins[1].clone();
    app.operate(json!({"op":"delete_chat_local","space":pin.space,"stream":pin.stream}))
        .await
        .unwrap();
    for (index, image) in [
        app.store
            .message_backup_image(4 * 1024 * 1024)
            .await
            .unwrap(),
        app.store
            .local_content_backup_image(4 * 1024 * 1024)
            .await
            .unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        let path = temp.path().join(format!("transfer-{index}"));
        std::fs::create_dir(&path).unwrap();
        vault::write_private(&path.join("client.sqlite"), &image, false).unwrap();
        let transferred = ClientStore::open(&path).await.unwrap();
        assert_eq!(
            transferred
                .local_chat_state(pin.space, pin.stream)
                .await
                .unwrap(),
            crate::store::LocalChatState::default()
        );
        transferred.close().await.unwrap();
    }
    assert!(
        app.store
            .local_chat_state(pin.space, pin.stream)
            .await
            .unwrap()
            .hidden
    );
    // The exact same signed scope can be deliberately reopened without copying
    // its previously removed messages into the new local window.
    app.store
        .reveal_local_chat(pin.space, pin.stream)
        .await
        .unwrap();
    assert!(
        !app.store
            .local_chat_state(pin.space, pin.stream)
            .await
            .unwrap()
            .hidden
    );
    assert_eq!(
        app.store
            .local_chat_state(pin.space, pin.stream)
            .await
            .unwrap()
            .generation,
        1
    );
    app.close().await.unwrap();
}

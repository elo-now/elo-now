use super::*;

async fn fixture(directory: &Path) -> (ClientApp, DraftScope) {
    let app = ProfileDraft::new()
        .unwrap()
        .save(
            directory.to_owned(),
            "synthetic draft password".into(),
            "Draft test",
        )
        .await
        .unwrap();
    let scope = DraftScope {
        identity: app.session.identity_id(),
        credential: app.session.credential().id(),
        active_space: None,
        space: app.pins[0].space,
        stream: app.pins[0].stream,
        thread: None,
    };
    (app, scope)
}
#[tokio::test]
async fn encrypted_text_and_attachment_survive_close_and_reopen_then_clear() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("profile");
    let (app, scope) = fixture(&profile).await;
    let staging = temporary.path().join("selected.txt");
    std::fs::write(&staging, b"private draft attachment").unwrap();
    let content = DraftContent {
        text: "Private text @Alice".into(),
        expiry: Some(24),
        mentions: vec![DraftMention {
            identity_id: scope.identity,
            label: "Alice".into(),
            start: 13,
            end: 19,
        }],
    };
    app.save_conversation_draft(&scope, content.clone(), Some((&staging, "notes.txt")))
        .await
        .unwrap();
    for entry in std::fs::read_dir(profile.join("drafts")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(b"Private text".len())
                .any(|part| part == b"Private text")
        );
        assert!(
            !bytes
                .windows(b"private draft attachment".len())
                .any(|part| part == b"private draft attachment")
        );
    }
    app.close().await.unwrap();
    std::fs::remove_file(staging).unwrap();
    let app = ClientApp::open(profile.clone(), "synthetic draft password".into(), true)
        .await
        .unwrap();
    let draft = app.load_conversation_draft(&scope).await.unwrap();
    assert_eq!(draft.content, content);
    assert_eq!(
        draft.attachment.unwrap().1.as_slice(),
        b"private draft attachment"
    );
    app.save_conversation_draft(&scope, DraftContent::default(), None)
        .await
        .unwrap();
    assert!(
        app.load_conversation_draft(&scope)
            .await
            .unwrap()
            .content
            .text
            .is_empty()
    );
    assert_eq!(
        std::fs::read_dir(profile.join("drafts")).unwrap().count(),
        0
    );
    app.close().await.unwrap();
}
#[tokio::test]
async fn drafts_are_bound_to_identity_device_space_and_thread() {
    let temporary = tempfile::tempdir().unwrap();
    let (app, scope) = fixture(&temporary.path().join("profile")).await;
    let content = DraftContent {
        text: "General draft".into(),
        ..Default::default()
    };
    app.save_conversation_draft(&scope, content.clone(), None)
        .await
        .unwrap();
    let mut thread = scope.clone();
    thread.thread = Some(RecordId::from_bytes([7; 32]));
    assert!(
        app.load_conversation_draft(&thread)
            .await
            .unwrap()
            .content
            .text
            .is_empty()
    );
    app.save_conversation_draft(
        &thread,
        DraftContent {
            text: "Reply draft".into(),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        app.load_conversation_draft(&scope).await.unwrap().content,
        content
    );
    let mut wrong = scope.clone();
    wrong.identity = IdentityId::from_bytes([8; 32]);
    assert!(app.load_conversation_draft(&wrong).await.is_err());
    let mut wrong = scope.clone();
    wrong.credential = RecordId::from_bytes([8; 32]);
    assert!(app.load_conversation_draft(&wrong).await.is_err());
    let mut wrong = scope.clone();
    wrong.space = SpaceId::from_bytes([8; 32]);
    assert!(app.load_conversation_draft(&wrong).await.is_err());
    let mut wrong = scope.clone();
    wrong.active_space = Some("another-space".into());
    assert!(app.load_conversation_draft(&wrong).await.is_err());
    app.close().await.unwrap();
}

#[tokio::test]
async fn a_cached_staged_attachment_is_not_read_again_for_text_only_changes() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("profile");
    let (app, scope) = fixture(&profile).await;
    let staging = temporary.path().join("image.jpg");
    std::fs::write(&staging, b"synthetic image bytes").unwrap();
    let cached = app
        .save_conversation_draft_cached(
            &scope,
            DraftContent::default(),
            Some((&staging, "image.jpg")),
            None,
        )
        .await
        .unwrap();
    // The native layer separately validates a still-live staging capability.
    // Removing this fixture proves the core uses the sealed cache instead of
    // reading or encrypting attachment bytes again for a text edit.
    std::fs::remove_file(&staging).unwrap();
    app.save_conversation_draft_cached(
        &scope,
        DraftContent {
            text: "Caption".into(),
            ..Default::default()
        },
        Some((&staging, "image.jpg")),
        cached,
    )
    .await
    .unwrap();
    let loaded = app.load_conversation_draft(&scope).await.unwrap();
    assert_eq!(loaded.content.text, "Caption");
    assert_eq!(
        loaded.attachment.unwrap().1.as_slice(),
        b"synthetic image bytes"
    );
    assert_eq!(
        std::fs::read_dir(profile.join("drafts")).unwrap().count(),
        2
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn a_draft_copied_into_another_scope_cannot_be_opened() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("profile");
    let (app, scope) = fixture(&profile).await;
    app.save_conversation_draft(
        &scope,
        DraftContent {
            text: "Private root draft".into(),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap();
    let mut thread = scope.clone();
    thread.thread = Some(RecordId::from_bytes([7; 32]));
    let directory = profile.join("drafts");
    std::fs::copy(
        ClientApp::draft_path(&directory, &scope).unwrap(),
        ClientApp::draft_path(&directory, &thread).unwrap(),
    )
    .unwrap();
    assert!(app.load_conversation_draft(&thread).await.is_err());
    app.close().await.unwrap();
}

#[tokio::test]
async fn deleting_conversation_drafts_removes_threads_and_attachments_only_in_that_chat() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("profile");
    let (mut app, scope) = fixture(&profile).await;
    app.create_chat("Another chat", None, ChatKind::Chat)
        .await
        .unwrap();
    let other = DraftScope {
        space: app.pins[1].space,
        stream: app.pins[1].stream,
        ..scope.clone()
    };
    let thread = DraftScope {
        thread: Some(RecordId::from_bytes([7; 32])),
        ..scope.clone()
    };
    let attachment = temporary.path().join("attachment");
    std::fs::write(&attachment, b"local draft file").unwrap();
    for (draft_scope, text) in [
        (&scope, "Root draft"),
        (&thread, "Thread draft"),
        (&other, "Keep this draft"),
    ] {
        app.save_conversation_draft(
            draft_scope,
            DraftContent {
                text: text.into(),
                ..Default::default()
            },
            Some((&attachment, "draft.txt")),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        std::fs::read_dir(profile.join("drafts")).unwrap().count(),
        6
    );
    app.delete_conversation_drafts(&scope).unwrap();
    assert_eq!(
        app.load_conversation_draft(&scope)
            .await
            .unwrap()
            .content
            .text,
        ""
    );
    assert_eq!(
        app.load_conversation_draft(&thread)
            .await
            .unwrap()
            .content
            .text,
        ""
    );
    let retained = app.load_conversation_draft(&other).await.unwrap();
    assert_eq!(retained.content.text, "Keep this draft");
    assert_eq!(&*retained.attachment.unwrap().1, b"local draft file");
    assert_eq!(
        std::fs::read_dir(profile.join("drafts")).unwrap().count(),
        2
    );
    app.delete_conversation_drafts(&scope).unwrap();
    let wrong = DraftScope {
        credential: RecordId::from_bytes([8; 32]),
        ..other.clone()
    };
    assert!(app.delete_conversation_drafts(&wrong).is_err());
    assert_eq!(
        app.load_conversation_draft(&other)
            .await
            .unwrap()
            .content
            .text,
        "Keep this draft"
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn persisted_deletion_generation_prevents_old_draft_revival_after_restart_and_new_messages() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("profile");
    let (app, scope) = fixture(&profile).await;
    let attachment = temporary.path().join("attachment");
    std::fs::write(&attachment, b"discarded attachment").unwrap();
    app.save_conversation_draft(
        &scope,
        DraftContent {
            text: "Old unsent text".into(),
            ..Default::default()
        },
        Some((&attachment, "old.txt")),
    )
    .await
    .unwrap();
    // Simulate old encrypted files surviving a crash/partial cleanup. The SQL
    // deletion generation is durable independently of those filesystem remnants.
    app.store
        .delete_chat_local(scope.space, scope.stream, now().unwrap())
        .await
        .unwrap();
    assert!(app.load_conversation_draft(&scope).await.is_err());
    assert!(
        app.save_conversation_draft(&scope, DraftContent::default(), None)
            .await
            .is_err()
    );
    app.close().await.unwrap();
    let app = ClientApp::open(profile.clone(), "synthetic draft password".into(), true)
        .await
        .unwrap();
    app.store
        .reveal_local_chat(scope.space, scope.stream)
        .await
        .unwrap();
    let fresh = app.load_conversation_draft(&scope).await.unwrap();
    assert_eq!(fresh.content, DraftContent::default());
    assert!(fresh.attachment.is_none());
    app.save_conversation_draft(
        &scope,
        DraftContent {
            text: "New generation draft".into(),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        app.load_conversation_draft(&scope)
            .await
            .unwrap()
            .content
            .text,
        "New generation draft"
    );
    app.close().await.unwrap();
}

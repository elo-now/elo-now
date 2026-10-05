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
    let draft = app.load_conversation_draft(&scope).unwrap();
    assert_eq!(draft.content, content);
    assert_eq!(
        draft.attachment.unwrap().1.as_slice(),
        b"private draft attachment"
    );
    app.save_conversation_draft(&scope, DraftContent::default(), None)
        .unwrap();
    assert!(
        app.load_conversation_draft(&scope)
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
        .unwrap();
    let mut thread = scope.clone();
    thread.thread = Some(RecordId::from_bytes([7; 32]));
    assert!(
        app.load_conversation_draft(&thread)
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
    .unwrap();
    assert_eq!(
        app.load_conversation_draft(&scope).unwrap().content,
        content
    );
    let mut wrong = scope.clone();
    wrong.identity = IdentityId::from_bytes([8; 32]);
    assert!(app.load_conversation_draft(&wrong).is_err());
    let mut wrong = scope.clone();
    wrong.credential = RecordId::from_bytes([8; 32]);
    assert!(app.load_conversation_draft(&wrong).is_err());
    let mut wrong = scope.clone();
    wrong.space = SpaceId::from_bytes([8; 32]);
    assert!(app.load_conversation_draft(&wrong).is_err());
    let mut wrong = scope.clone();
    wrong.active_space = Some("another-space".into());
    assert!(app.load_conversation_draft(&wrong).is_err());
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
    .unwrap();
    let loaded = app.load_conversation_draft(&scope).unwrap();
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
    .unwrap();
    let mut thread = scope.clone();
    thread.thread = Some(RecordId::from_bytes([7; 32]));
    let directory = profile.join("drafts");
    std::fs::copy(
        ClientApp::draft_path(&directory, &scope).unwrap(),
        ClientApp::draft_path(&directory, &thread).unwrap(),
    )
    .unwrap();
    assert!(app.load_conversation_draft(&thread).is_err());
    app.close().await.unwrap();
}

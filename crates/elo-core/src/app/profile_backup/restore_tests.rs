use super::super::tests::{PASSWORD, message, profile};
use super::*;

async fn import(
    path: &Path,
    bytes: &[u8],
    identity: IdentityId,
    password: &str,
    progress: RestoreProgress,
) -> Result<ClientApp> {
    restore(
        RestoreRequest {
            directory: path.to_owned(),
            bytes,
            secret: PASSWORD.into(),
            expected: identity,
            password: password.into(),
            allow_loopback: true,
            resume: true,
            paged: true,
        },
        &progress,
    )
    .await
}
fn paused_at(stage: RestoreStage, count: usize) -> RestoreProgress {
    RestoreProgress::new(move |current, done, _| current != stage || done < count)
}

#[tokio::test]
async fn resume_checks_archive_password_and_signature_then_commits_once() {
    let tmp = tempfile::tempdir().unwrap();
    let mut source = profile(tmp.path().join("source")).await;
    source.set_profile_name("Before recovery").unwrap();
    let source_details = std::fs::read(source.directory.join("profile-details.age")).unwrap();
    let id = source.identity_id();
    let mut expected = Vec::new();
    for n in 1..=8 {
        expected.push(message(&source, n, None, None).await);
    }
    let original = source.store.stats().await.unwrap().records;
    let bytes = source
        .export_snapshot(PASSWORD.into(), false, MAX_FILES)
        .await
        .unwrap()
        .bytes;
    let destination = tmp.path().join("restored");
    let error = import(
        &destination,
        &bytes,
        id,
        PASSWORD,
        paused_at(RestoreStage::Saving, 1),
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().starts_with("Recovery paused."));
    assert!(destination.join(".initializing").exists());
    assert!(
        ClientApp::open(destination.clone(), PASSWORD.into(), true)
            .await
            .is_err()
    );
    // Another valid encryption of the same data is not the checkpoint's archive.
    let another = source
        .export_snapshot(PASSWORD.into(), false, MAX_FILES)
        .await
        .unwrap()
        .bytes;
    assert!(
        import(
            &destination,
            &another,
            id,
            PASSWORD,
            RestoreProgress::default()
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("same backup")
    );
    let journal = vault::read_private(&destination.join(".initializing")).unwrap();
    let mut altered: Value = serde_json::from_slice(&journal).unwrap();
    altered["checkpoint"]["opening"] = json!(true);
    vault::write_private(
        &destination.join(".initializing"),
        &serde_json::to_vec(&altered).unwrap(),
        true,
    )
    .unwrap();
    assert!(
        import(
            &destination,
            &bytes,
            id,
            PASSWORD,
            RestoreProgress::default()
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("signature")
    );
    vault::write_private(&destination.join(".initializing"), &journal, true).unwrap();
    let stray = destination.join("unrelated-user-file");
    vault::write_private(&stray, b"preserve this", false).unwrap();
    assert!(
        import(
            &destination,
            &bytes,
            id,
            PASSWORD,
            RestoreProgress::default()
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&stray).unwrap(), b"preserve this");
    std::fs::remove_file(stray).unwrap();
    let scratch = destination.join(".elo-0123456789abcdef0123456789abcdef.tmp");
    vault::write_private(&scratch, b"interrupted atomic write", false).unwrap();
    assert!(
        import(
            &destination,
            &bytes,
            id,
            PASSWORD,
            paused_at(RestoreStage::Opening, 0)
        )
        .await
        .is_err()
    );
    assert!(!scratch.exists());
    assert!(
        import(
            &destination,
            &bytes,
            id,
            "different valid password",
            RestoreProgress::default()
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("password chosen")
    );
    // SQLite and settings may have been opened before the process was stopped.
    assert!(
        import(
            &destination,
            &bytes,
            id,
            PASSWORD,
            paused_at(RestoreStage::Ready, 1)
        )
        .await
        .is_err()
    );
    let mut restored = import(
        &destination,
        &bytes,
        id,
        PASSWORD,
        RestoreProgress::default(),
    )
    .await
    .unwrap();
    assert!(!destination.join(".initializing").exists());
    assert!(restored.session.controller_mode() == vault::ControllerMode::Follower);
    assert_eq!(restored.store.stats().await.unwrap().records, original);
    for record in expected {
        assert!(restored.store.previously_accepted(record).await.unwrap());
    }
    assert_eq!(restored.view().await.unwrap()["name"], "Before recovery");
    restored.enable_spaces().await.unwrap();
    restored.enable_paged_views();
    let renamed = restored
        .operate(json!({"op":"set_profile_name","name":"After recovery"}))
        .await
        .unwrap();
    assert_eq!(renamed["view"]["name"], "After recovery");
    restored.close().await.unwrap();
    let reopened = ClientApp::open(destination.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(reopened.identity_id(), id);
    assert_eq!(reopened.view().await.unwrap()["name"], "After recovery");
    reopened.close().await.unwrap();
    // A completed directory is never adopted by a new core import.
    assert!(
        import(
            &destination,
            &bytes,
            id,
            PASSWORD,
            RestoreProgress::default()
        )
        .await
        .is_err()
    );
    assert_eq!(source.store.stats().await.unwrap().records, original);
    assert_eq!(source.view().await.unwrap()["name"], "Before recovery");
    assert_eq!(
        std::fs::read(source.directory.join("profile-details.age")).unwrap(),
        source_details
    );
    source.close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_rejects_links_without_changing_their_targets() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let source = profile(tmp.path().join("source")).await;
    let id = source.identity_id();
    let bytes = source
        .export_snapshot(PASSWORD.into(), false, MAX_FILES)
        .await
        .unwrap()
        .bytes;
    let destination = tmp.path().join("restored");
    assert!(
        import(
            &destination,
            &bytes,
            id,
            PASSWORD,
            paused_at(RestoreStage::Saving, 0)
        )
        .await
        .is_err()
    );
    let target = tmp.path().join("existing-data");
    vault::write_private(&target, b"existing data", false).unwrap();
    let linked = destination.join("client.sqlite");
    symlink(&target, &linked).unwrap();
    assert!(
        import(
            &destination,
            &bytes,
            id,
            PASSWORD,
            RestoreProgress::default()
        )
        .await
        .is_err()
    );
    std::fs::remove_file(&linked).unwrap();
    std::fs::hard_link(&target, &linked).unwrap();
    assert!(
        import(
            &destination,
            &bytes,
            id,
            PASSWORD,
            RestoreProgress::default()
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(target).unwrap(), b"existing data");
    source.close().await.unwrap();
}

#[test]
fn recovery_tree_accepts_only_local_cache_for_an_archived_space() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("restore");
    private_directory(&root).unwrap();
    private_directory(&root.join("spaces")).unwrap();
    let id = "ab".repeat(32);
    let child = root.join("spaces").join(&id);
    private_directory(&child).unwrap();
    let relative = format!("spaces/{id}/space-vault-cache.age");
    let files = BTreeMap::from([(format!("spaces/{id}/vault.age"), Zeroizing::new(vec![1]))]);
    vault::write_private(&root.join(&relative), b"synthetic encrypted cache", false).unwrap();
    safe_tree(&root, &files).unwrap();
    assert!(!super::super::valid_backup_path(&relative));
    assert!(safe_tree(&root, &BTreeMap::new()).is_err());
    vault::write_private(
        &root.join("space-vault-cache.age"),
        b"unexpected root cache",
        false,
    )
    .unwrap();
    assert!(safe_tree(&root, &files).is_err());
    std::fs::remove_file(root.join("space-vault-cache.age")).unwrap();
    #[cfg(unix)]
    {
        std::fs::remove_file(root.join(&relative)).unwrap();
        std::os::unix::fs::symlink(temp.path().join("outside"), root.join(&relative)).unwrap();
        assert!(safe_tree(&root, &files).is_err());
    }
}

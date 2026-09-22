use elo_core::app::{ClientApp, ProfileDraft};
use serde_json::json;
use tempfile::TempDir;

const PASSWORD: &str = "public synthetic onboarding password";

#[tokio::test]
async fn acknowledged_card_creates_private_profile_and_durable_channel_without_root_file() {
    let temp = TempDir::new().unwrap();
    let directory = temp.path().join("profile");
    let draft = ProfileDraft::new().unwrap();
    assert_eq!(draft.card().phrase.split_whitespace().count(), 24);
    let identity = draft.card().identity_id;
    let phrase = draft.card().phrase.as_bytes().to_vec();
    let mut app = draft
        .save(directory.clone(), PASSWORD.into(), "General")
        .await
        .unwrap();
    let view = app.view().await.unwrap();
    assert!(app.password_matches(&PASSWORD.into()));
    assert!(!app.password_matches(&"incorrect password".into()));
    assert_eq!(view["identity"], identity.to_string());
    assert_eq!(view["streams"].as_array().unwrap().len(), 1);
    assert_eq!(view["streams"][0]["can_post"], true);
    assert_eq!(view["streams"][0]["members"].as_array().unwrap().len(), 1);
    assert_eq!(view["replicas"], json!([]));
    app.operate(json!({"op":"send", "space": view["streams"][0]["space"], "stream":view["streams"][0]["stream"], "text":"Synthetic first mobile message", "created_at":"2026-09-09T12:00:00Z"})).await.unwrap();
    let current = app.view().await.unwrap();
    let record = current["streams"][0]["rows"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(current["streams"][0]["rows"][0]["unread"], false);
    assert_eq!(current["streams"][0]["unread_count"], 0);
    app.operate(json!({"op":"mark_read", "space": view["streams"][0]["space"], "stream":view["streams"][0]["stream"], "records":[record]})).await.unwrap();
    let encrypted_read_state = std::fs::read(directory.join("read-state.age")).unwrap();
    assert!(
        !encrypted_read_state
            .windows(record.len())
            .any(|window| window == record.as_bytes())
    );
    app.close().await.unwrap();
    drop(draft);
    assert!(!directory.join(".initializing").exists());
    for entry in std::fs::read_dir(&directory).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            let bytes = std::fs::read(entry.path()).unwrap();
            assert!(!bytes.windows(phrase.len()).any(|w| w == phrase));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    assert!(
        ClientApp::open(directory.clone(), "incorrect password".into(), false)
            .await
            .is_err()
    );
    let app = ClientApp::open(directory, PASSWORD.into(), false)
        .await
        .unwrap();
    let reopened = app.view().await.unwrap();
    assert_eq!(reopened["credential"], view["credential"]);
    assert_eq!(reopened["streams"][0]["rows"].as_array().unwrap().len(), 1);
    assert_eq!(
        reopened["streams"][0]["rows"][0]["body"]["payload"]["text"],
        "Synthetic first mobile message"
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn onboarding_rejects_existing_and_incomplete_profiles_without_overwriting_them() {
    let temp = TempDir::new().unwrap();
    let draft = ProfileDraft::new().unwrap();
    let invalid = temp.path().join("invalid");
    assert!(
        draft
            .save(invalid.clone(), "short".into(), "General")
            .await
            .is_err()
    );
    assert!(!invalid.exists());
    let existing = temp.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    std::fs::write(existing.join("user.txt"), "preserve me").unwrap();
    assert!(
        draft
            .save(existing.clone(), PASSWORD.into(), "General")
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(existing.join("user.txt")).unwrap(),
        b"preserve me"
    );
    assert!(!existing.join("vault.age").exists());
    std::fs::write(existing.join(".initializing"), "incomplete").unwrap();
    assert!(
        ClientApp::open(existing, PASSWORD.into(), false)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("interrupted")
    );
}

#[tokio::test]
async fn initial_transport_and_controller_survive_password_reopen_without_read_capability() {
    use elo_core::{sync::PeerDescriptor, vault::Session};
    let temp = TempDir::new().unwrap();
    let directory = temp.path().join("hosted");
    let peer: PeerDescriptor = serde_json::from_value(json!({
        "url": "https://replica.example/spaces/00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff/replica/",
        "signing_public_key": elo_core::record::encode_hex(
            ed25519_dalek::SigningKey::from_bytes(&[76;32]).verifying_key().as_bytes()),
        "mailbox_id": "ab".repeat(32),
        "read_token": null,
        "write_token": "synthetic-host-write"
    }))
    .unwrap();
    let mut invalid = peer.clone();
    invalid.url = "http://example.test/".into();
    assert!(
        ProfileDraft::new()
            .unwrap()
            .with_peer(invalid, false)
            .is_err()
    );
    let draft = ProfileDraft::new()
        .unwrap()
        .with_peer(peer.clone(), false)
        .unwrap();
    let mut app = draft
        .save_named(directory.clone(), PASSWORD.into(), "General", "elo.now")
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    let space = serde_json::from_value(before["streams"][0]["space"].clone()).unwrap();
    assert!(!app.ensure_peer(peer.clone()).unwrap());
    app.close().await.unwrap();
    let persisted = Session::open(
        &std::fs::read(directory.join("vault.age")).unwrap(),
        PASSWORD.into(),
        draft.card().identity_id,
    )
    .unwrap();
    assert!(persisted.can_control(space));
    assert_eq!(persisted.peers().len(), 1);
    assert_eq!(persisted.peers()[0].read_token, None);
    assert_eq!(persisted.peers()[0].write_token, peer.write_token);
    assert_eq!(persisted.peers()[0].url, peer.url);
    let app = ClientApp::open(directory, PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(app.view().await.unwrap(), before);
    app.close().await.unwrap();
}

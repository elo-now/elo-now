use elo_core::app::{ClientApp, ProfileDraft, recovery_qr};
use serde_json::json;
use tempfile::TempDir;
const PASSWORD: &str = "synthetic existing profile password";
const NEW_PASSWORD: &str = "synthetic new device password";

#[test]
fn recovery_normalizes_whitespace_and_case_but_never_guesses_words_or_identity() {
    let original = ProfileDraft::new().unwrap();
    let id = original.card().identity_id.to_string();
    let words = format!(
        "  \n{}\t ",
        original.card().phrase.to_uppercase().replace(' ', "  \n\t")
    );
    let restored = ProfileDraft::recover(&words, &format!("  {}\n", id.to_uppercase())).unwrap();
    assert_eq!(restored.card().phrase, original.card().phrase);
    assert_eq!(restored.card().identity_id, original.card().identity_id);
    assert!(ProfileDraft::recover("one two three", &id).is_err());
    let other = ProfileDraft::new().unwrap();
    assert!(ProfileDraft::recover(&words, &other.card().identity_id.to_string()).is_err());
    assert!(ProfileDraft::recover(&format!("{} extra", original.card().phrase), &id).is_err());
}

#[test]
fn private_qr_requires_its_password_and_is_distinct_from_public_contact_codes() {
    let original = ProfileDraft::new().unwrap();
    let encoded = recovery_qr::encode(original.card(), NEW_PASSWORD.into()).unwrap();
    assert!(!encoded.contains(&original.card().phrase));
    let restored = recovery_qr::decode(&encoded, NEW_PASSWORD.into()).unwrap();
    assert_eq!(restored.card().identity_id, original.card().identity_id);
    assert_eq!(restored.card().phrase, original.card().phrase);
    let legacy = encoded.replacen(recovery_qr::PREFIX, "elo-recovery:1:", 1);
    assert_eq!(
        recovery_qr::decode(&legacy, NEW_PASSWORD.into())
            .unwrap()
            .card()
            .identity_id,
        original.card().identity_id
    );
    let camera_text = format!("  {}  ", encoded.replace('\n', "   "));
    assert_eq!(
        recovery_qr::decode(&camera_text, NEW_PASSWORD.into())
            .unwrap()
            .card()
            .identity_id,
        original.card().identity_id
    );
    assert!(recovery_qr::decode(&encoded, PASSWORD.into()).is_err());
    assert!(recovery_qr::encode(original.card(), "123456".into()).is_err());
    assert!(recovery_qr::encode(original.card(), "😀😀😀".into()).is_err());
    assert!(recovery_qr::decode("elo://exchange/v1#public", NEW_PASSWORD.into()).is_err());
    let mut damaged = encoded;
    damaged.truncate(damaged.len() - 12);
    assert!(recovery_qr::decode(&damaged, NEW_PASSWORD.into()).is_err());
}

#[tokio::test]
async fn complete_backup_keeps_committed_history_profile_and_read_state_without_cloning_control() {
    let temp = TempDir::new().unwrap();
    let draft = ProfileDraft::new().unwrap();
    let id = draft.card().identity_id;
    let source = temp.path().join("source");
    let mut app = draft
        .save_named(
            source.clone(),
            PASSWORD.into(),
            "History",
            "Recovery tester",
        )
        .await
        .unwrap();
    let view = app.view().await.unwrap();
    let stream = &view["streams"][0];
    app.operate(
        json!({"op":"send", "space":stream["space"], "stream":stream["stream"],
        "text":"History committed while WAL is open", "created_at":"2026-09-10T12:00:00Z"}),
    )
    .await
    .unwrap();
    app.operate(json!({"op":"create_group","name":"Private group"}))
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    let ciphertext = app
        .export_recovery_backup(&draft.card().phrase)
        .await
        .unwrap();
    assert!(!ciphertext.windows(7).any(|w| w == b"History"));
    assert!(
        !ciphertext
            .windows(draft.card().phrase.len())
            .any(|w| w == draft.card().phrase.as_bytes())
    );
    let target = temp.path().join("restored");
    let restored = ClientApp::restore_profile(
        target.clone(),
        &ciphertext,
        draft.card().phrase.clone().into(),
        id,
        NEW_PASSWORD.into(),
        false,
    )
    .await
    .unwrap();
    let after = restored.view().await.unwrap();
    assert_eq!(before["identity"], after["identity"]);
    assert_eq!(before["name"], after["name"]);
    assert_eq!(before["groups"], after["groups"]);
    assert_eq!(before["streams"][0]["rows"], after["streams"][0]["rows"]);
    assert_eq!(after["streams"][0]["can_manage_members"], false);
    assert_eq!(
        app.view().await.unwrap()["streams"][0]["can_manage_members"],
        true
    );
    restored.close().await.unwrap();
    assert!(
        ClientApp::open(target.clone(), PASSWORD.into(), false)
            .await
            .is_err()
    );
    let reopened = ClientApp::open(target, NEW_PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(
        reopened.view().await.unwrap()["streams"][0]["rows"],
        after["streams"][0]["rows"]
    );
    reopened.close().await.unwrap();
    let bad = temp.path().join("bad");
    assert!(
        ClientApp::restore_profile(
            bad.clone(),
            &ciphertext,
            PASSWORD.into(),
            id,
            NEW_PASSWORD.into(),
            false
        )
        .await
        .is_err()
    );
    assert!(!bad.exists());
    let existing_vault = std::fs::read(source.join("vault.age")).unwrap();
    assert!(
        ClientApp::restore_profile(
            source.clone(),
            &ciphertext,
            draft.card().phrase.clone().into(),
            id,
            NEW_PASSWORD.into(),
            false
        )
        .await
        .is_err()
    );
    assert_eq!(
        std::fs::read(source.join("vault.age")).unwrap(),
        existing_vault
    );
    assert!(app.view().await.is_ok());
    app.close().await.unwrap();
}

#[tokio::test]
async fn words_only_recover_the_identity_with_fresh_device_keys_and_preserve_existing_profile() {
    let temp = TempDir::new().unwrap();
    let draft = ProfileDraft::new().unwrap();
    let first = draft
        .save_named(
            temp.path().join("original"),
            PASSWORD.into(),
            "Original",
            "First",
        )
        .await
        .unwrap();
    let original = first.view().await.unwrap();
    let recovered =
        ProfileDraft::recover(&draft.card().phrase, &draft.card().identity_id.to_string()).unwrap();
    let second = recovered
        .save_named(
            temp.path().join("new"),
            NEW_PASSWORD.into(),
            "General",
            "Second",
        )
        .await
        .unwrap();
    let restored = second.view().await.unwrap();
    assert_eq!(original["identity"], restored["identity"]);
    assert_ne!(original["credential"], restored["credential"]);
    assert_ne!(
        original["streams"][0]["stream"],
        restored["streams"][0]["stream"]
    );
    assert_eq!(first.view().await.unwrap()["streams"], original["streams"]);
    second.close().await.unwrap();
    first.close().await.unwrap();
}

#[tokio::test]
async fn pairing_is_scoped_explicit_retryable_and_retrievable_without_the_source() {
    use axum::{
        extract::Request,
        http::{Method, StatusCode},
        middleware::{self, Next},
        response::IntoResponse,
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use elo_core::{
        app::pairing::{PREFIX, PairSource, PairTarget},
        record::encode_hex,
        replica::ReplicaStore,
        sync::PeerDescriptor,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let temp = TempDir::new().unwrap();
    let store = ReplicaStore::open(temp.path().join("replica"))
        .await
        .unwrap();
    let mailbox = store.create_mailbox(256 * 1024 * 1024).await.unwrap();
    let lose_ack = Arc::new(AtomicBool::new(false));
    let flag = lose_ack.clone();
    let router = elo_core::http::router(store.clone()).layer(middleware::from_fn(
        move |request: Request, next: Next| {
            let flag = flag.clone();
            async move {
                let upload =
                    request.method() == Method::POST && request.uri().path().contains("/objects/");
                let response = next.run(request).await;
                if upload && response.status().is_success() && flag.swap(false, Ordering::SeqCst) {
                    StatusCode::SERVICE_UNAVAILABLE.into_response()
                } else {
                    response
                }
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let path = temp.path().join("source");
    let draft = ProfileDraft::new().unwrap();
    let source = draft
        .save_named(path.clone(), PASSWORD.into(), "Pair test", "Source")
        .await
        .unwrap();
    source.close().await.unwrap();
    let mut app = ClientApp::open(path, PASSWORD.into(), true).await.unwrap();
    app.ensure_peer(PeerDescriptor {
        url: format!("http://{address}"),
        signing_public_key: encode_hex(store.key().as_bytes()),
        mailbox_id: mailbox.mailbox_id,
        read_token: Some(mailbox.read_token.clone()),
        write_token: Some(mailbox.write_token.clone()),
    })
    .unwrap();
    let view = app.view().await.unwrap();
    let stream = &view["streams"][0];
    app.operate(json!({"op":"send", "space":stream["space"], "stream":stream["stream"], "text":"Private pairing history", "created_at":"2026-09-10T12:00:00Z"})).await.unwrap();
    let before = app.view().await.unwrap();
    let mut source = PairSource::new(&app).await.unwrap();
    let link = source.link().unwrap();
    let packet = URL_SAFE_NO_PAD
        .decode(link.strip_prefix(PREFIX).unwrap())
        .unwrap();
    let packet_text = std::str::from_utf8(&packet).unwrap();
    assert!(!packet_text.contains(&mailbox.read_token));
    assert!(!packet_text.contains(&mailbox.write_token));
    assert!(PairTarget::new(&link, "HTTPS enforced", false).is_err());
    let mut expired: serde_json::Value = serde_json::from_slice(&packet).unwrap();
    assert_eq!(expired["expires"].as_u64(), Some(source.expires_at()));
    expired["expires"] = json!(0);
    let expired_link = format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&expired).unwrap())
    );
    assert!(PairTarget::new(&expired_link, "Expired", true).is_err());
    let mut target = PairTarget::new(&link, "Companion", true).unwrap();
    let mut other = PairTarget::new(&link, "Unapproved", true).unwrap();
    target.send().await.unwrap();
    target.send().await.unwrap();
    other.send().await.unwrap();
    let pending = source.poll().await.unwrap();
    assert_eq!(pending["requests"].as_array().unwrap().len(), 2);
    let request = pending["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Companion")
        .unwrap();
    let comparison = target.summary().unwrap()["code"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(request["code"], comparison);
    let destination = temp.path().join("linked");
    assert!(
        target
            .finish(destination.clone(), NEW_PASSWORD.into(), &comparison)
            .await
            .is_err()
    );
    assert!(!destination.exists());
    assert!(
        source
            .approve(&app, request["id"].as_str().unwrap(), "wrong code")
            .await
            .is_err()
    );
    lose_ack.store(true, Ordering::SeqCst);
    assert!(
        source
            .approve(&app, request["id"].as_str().unwrap(), &comparison)
            .await
            .is_err()
    );
    let db = rusqlite::Connection::open(temp.path().join("replica/replica.sqlite")).unwrap();
    let objects_before: i64 = db
        .query_row("SELECT count(*) FROM objects", [], |r| r.get(0))
        .unwrap();
    source
        .approve(&app, request["id"].as_str().unwrap(), &comparison)
        .await
        .unwrap();
    let objects_after: i64 = db
        .query_row("SELECT count(*) FROM objects", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        objects_after,
        objects_before + 1,
        "retry reuses the committed backup ciphertext; only its manifest is new"
    );
    let wrong = pending["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Unapproved")
        .unwrap();
    assert!(
        source
            .approve(
                &app,
                wrong["id"].as_str().unwrap(),
                wrong["code"].as_str().unwrap()
            )
            .await
            .is_err()
    );
    app.close().await.unwrap();
    drop(source);
    assert_eq!(other.poll().await.unwrap()["ready"], false);
    assert_eq!(target.poll().await.unwrap()["ready"], true);
    let linked = target
        .finish(destination.clone(), NEW_PASSWORD.into(), &comparison)
        .await
        .unwrap();
    let after = linked.view().await.unwrap();
    assert_eq!(before["streams"][0]["rows"], after["streams"][0]["rows"]);
    assert_eq!(after["streams"][0]["can_manage_members"], false);
    assert!(
        target
            .finish(temp.path().join("replay"), NEW_PASSWORD.into(), &comparison)
            .await
            .is_err()
    );
    assert!(!temp.path().join("replay").exists());
    linked.close().await.unwrap();
    let reopened = ClientApp::open(destination, NEW_PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(
        reopened.view().await.unwrap()["identity"],
        before["identity"]
    );
    reopened.close().await.unwrap();
    server.abort();
}

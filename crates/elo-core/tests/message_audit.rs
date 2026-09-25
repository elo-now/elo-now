use elo_core::{
    app::{ClientApp, ProfileDraft},
    replica::ReplicaStore,
    sync::PeerDescriptor,
};
use serde_json::{Value, json};

const PASSWORD: &str = "synthetic message audit test password";
fn scope(view: &Value, op: &str) -> Value {
    json!({"op":op,"space":view["streams"][0]["space"],"stream":view["streams"][0]["stream"]})
}

#[tokio::test]
async fn audit_is_scoped_read_only_private_and_persistent_with_signed_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), PASSWORD.into(), "General", "Alex")
        .await
        .unwrap();
    app.close().await.unwrap();
    app = ClientApp::open(path.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    let replica = ReplicaStore::open(dir.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(1024 * 1024).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let node = replica.clone();
    let server = tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, elo_core::http::router(node, &origin))
        }
        .await
        .unwrap();
    });
    app.ensure_peer(PeerDescriptor {
        url,
        signing_public_key: elo_core::record::encode_hex(replica.key().as_bytes()),
        mailbox_id: mailbox.mailbox_id,
        read_token: Some(mailbox.read_token.clone()),
        write_token: Some(mailbox.write_token.clone()),
    })
    .unwrap();
    let first = app.view().await.unwrap();
    let mut send = scope(&first, "send");
    send["text"] = json!("PRIVATE TEXT excluded from diagnostic output");
    send["created_at"] = json!("2026-09-11T13:00:00Z");
    let after = app.operate(send).await.unwrap()["view"].clone();
    let id = after["streams"][0]["rows"][0]["id"].clone();
    let mut debug = scope(&first, "message_debug");
    debug["record"] = id.clone();
    let before = app.view().await.unwrap();
    let pending = app.operate(debug.clone()).await.unwrap()["result"].clone();
    assert_eq!(
        app.view().await.unwrap(),
        before,
        "debug must not mark read or mutate view"
    );
    assert_eq!(pending["author"], first["identity"]);
    assert_eq!(pending["author_name"], "Alex");
    assert_eq!(pending["state"], "QUEUED");
    assert_eq!(pending["events"][0]["kind"], "QUEUED");
    app.operate(json!({"op":"sync"})).await.unwrap();
    for active in [true, false] {
        let mut action = scope(&first, "message_action");
        action["created_at"] = json!("2026-09-11T13:01:00Z");
        action["action"] = json!({"type":"reaction","target":id,"emoji":"👍","active":active});
        app.operate(action).await.unwrap();
    }
    let result = app.operate(debug.clone()).await.unwrap()["result"].clone();
    assert_eq!(result["targets"][0]["state"], "STORED");
    assert!(
        result["targets"][0]["receipt"]["arrival_seq"]
            .as_u64()
            .unwrap()
            > 0
    );
    let events = result["events"].as_array().unwrap();
    assert_eq!(events[1]["kind"], "UPLOAD_STARTED");
    assert_eq!(events[2]["kind"], "STORED");
    assert!(events[2]["http_status"].as_u64().unwrap() >= 200);
    assert_eq!(result["actions"].as_array().unwrap().len(), 2);
    assert_eq!(result["actions"][0]["actor"], first["identity"]);
    assert_eq!(result["actions"][1]["action"]["active"], false);
    let output = serde_json::to_string(&result).unwrap();
    for secret in [
        "PRIVATE TEXT excluded from diagnostic output",
        &mailbox.read_token,
        &mailbox.write_token,
        PASSWORD,
    ] {
        assert!(!output.contains(secret));
    }
    let mut wrong = debug.clone();
    wrong["expected_identity"] = json!("wrong profile");
    assert!(app.operate(wrong).await.is_err());
    let mut wrong = debug.clone();
    wrong["stream"] = json!("aa".repeat(16));
    assert!(app.operate(wrong).await.is_err());
    let mut wrong = debug.clone();
    wrong["record"] = json!("bb".repeat(32));
    assert!(app.operate(wrong).await.is_err());
    app.close().await.unwrap();
    let mut app = ClientApp::open(path, PASSWORD.into(), true).await.unwrap();
    assert_eq!(app.operate(debug).await.unwrap()["result"], result);
    app.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn http_error_is_recorded_without_response_body_or_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile");
    let app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), PASSWORD.into(), "General", "Alex")
        .await
        .unwrap();
    app.close().await.unwrap();
    let mut app = ClientApp::open(path, PASSWORD.into(), true).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().fallback(|| async {
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    "sensitive untrusted server response",
                )
            }),
        )
        .await
        .unwrap();
    });
    let key = ed25519_dalek::SigningKey::from_bytes(&[82; 32]);
    app.ensure_peer(PeerDescriptor {
        url,
        signing_public_key: elo_core::record::encode_hex(key.verifying_key().as_bytes()),
        mailbox_id: "aa".repeat(32).parse().unwrap(),
        read_token: None,
        write_token: Some("PRIVATE_TRANSPORT_TOKEN".into()),
    })
    .unwrap();
    let first = app.view().await.unwrap();
    let mut send = scope(&first, "send");
    send["text"] = json!("private message");
    send["created_at"] = json!("2026-09-11T13:00:00Z");
    let after = app.operate(send).await.unwrap()["view"].clone();
    app.operate(json!({"op":"sync_live"})).await.unwrap();
    let mut debug = scope(&first, "message_debug");
    debug["record"] = after["streams"][0]["rows"][0]["id"].clone();
    let audit = app.operate(debug).await.unwrap()["result"].clone();
    assert_eq!(audit["targets"][0]["state"], "PENDING");
    let last = audit["events"].as_array().unwrap().last().unwrap();
    assert_eq!(last["error"], "HTTP");
    assert_eq!(last["http_status"], 401);
    let output = audit.to_string();
    for secret in [
        "sensitive untrusted server response",
        "PRIVATE_TRANSPORT_TOKEN",
        "private message",
    ] {
        assert!(!output.contains(secret));
    }
    app.close().await.unwrap();
    server.abort();
}

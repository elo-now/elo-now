use elo_core::app::{ClientApp, ProfileDraft};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASSWORD: &str = "public synthetic chat mute password";

fn request(chat: &Value, muted: Value) -> Value {
    json!({"op":"set_chat_muted", "space":chat["space"], "stream":chat["stream"], "muted":muted})
}

#[tokio::test]
async fn mute_is_private_durable_and_preserves_history_unread_and_backups() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("profile");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(path.clone(), PASSWORD.into(), "General")
        .await
        .unwrap();
    let chat = app.view().await.unwrap()["streams"][0].clone();
    assert_eq!(chat["muted"], false);
    app.operate(
        json!({"op":"send", "space":chat["space"], "stream":chat["stream"],
        "text":"History survives mute", "created_at":"2026-09-12T12:00:00Z"}),
    )
    .await
    .unwrap();
    let record = app.view().await.unwrap()["streams"][0]["rows"][0]["id"].clone();
    app.operate(json!({"op":"mark_unread", "space":chat["space"], "stream":chat["stream"], "records":[record]})).await.unwrap();
    // An unmuted save omits the new optional field, matching legacy read-state.
    app.close().await.unwrap();
    let mut app = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(app.view().await.unwrap()["streams"][0]["muted"], false);
    app.operate(json!({"op":"create_chat", "name":"General"}))
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    app.operate(request(&chat, json!(true))).await.unwrap();
    let muted = app.view().await.unwrap();
    assert_eq!(muted["streams"][0]["muted"], true);
    assert_eq!(muted["streams"][1], before["streams"][1]);
    for key in [
        "head",
        "controller",
        "members",
        "rows",
        "unread_count",
        "can_post",
    ] {
        assert_eq!(muted["streams"][0][key], before["streams"][0][key]);
    }
    // Mute is not a shared record and never changes transport targets/counts.
    assert_eq!(muted["counts"], before["counts"]);
    let encrypted = std::fs::read(path.join("read-state.age")).unwrap();
    for value in ["muted_streams", chat["stream"].as_str().unwrap()] {
        assert!(
            !encrypted
                .windows(value.len())
                .any(|bytes| bytes == value.as_bytes())
        );
    }
    // Muting never prevents sending, and read markers continue to work.
    app.operate(
        json!({"op":"send", "space":chat["space"], "stream":chat["stream"],
        "text":"Posting while muted", "created_at":"2026-09-12T12:01:00Z"}),
    )
    .await
    .unwrap();
    let expected = app.view().await.unwrap()["streams"][0].clone();
    assert_eq!(expected["rows"].as_array().unwrap().len(), 2);
    assert_eq!(expected["unread_count"], 1);
    let identity = app.identity_id();
    let backup = app.export_profile(PASSWORD.into()).await.unwrap();
    app.close().await.unwrap();
    let mut restored = ClientApp::restore_profile(
        temp.path().join("restored"),
        &backup,
        PASSWORD.into(),
        identity,
        PASSWORD.into(),
        false,
    )
    .await
    .unwrap();
    let restored_chat = restored.view().await.unwrap()["streams"][0].clone();
    assert_eq!(restored_chat["muted"], true);
    assert_eq!(restored_chat["rows"], expected["rows"]);
    assert_eq!(restored_chat["unread_count"], 1);
    // A restored follower can mute/unmute without controller rights.
    restored
        .operate(request(&chat, json!(false)))
        .await
        .unwrap();
    restored.close().await.unwrap();
    let mut app = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(app.view().await.unwrap()["streams"][0], expected);
    app.operate(request(&chat, json!(false))).await.unwrap();
    assert_eq!(app.view().await.unwrap()["streams"][0]["unread_count"], 1);
    app.close().await.unwrap();
    let app = ClientApp::open(path, PASSWORD.into(), false).await.unwrap();
    assert_eq!(app.view().await.unwrap()["streams"][0]["muted"], false);
    app.close().await.unwrap();
}

#[tokio::test]
async fn mute_rejects_invalid_scope_and_failed_writes_without_changing_the_view() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("profile");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(path.clone(), PASSWORD.into(), "General")
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    let chat = &before["streams"][0];
    for value in [Value::Null, json!("true"), json!(1), json!([])] {
        assert!(app.operate(request(chat, value)).await.is_err());
    }
    for (key, value) in [("space", "ff".repeat(32)), ("stream", "ff".repeat(16))] {
        let mut invalid = request(chat, json!(true));
        invalid[key] = json!(value);
        assert!(app.operate(invalid).await.is_err());
    }
    assert_eq!(app.view().await.unwrap(), before);
    // Simulate a failed private-state write; no optimistic native state escapes.
    std::fs::create_dir(path.join("read-state.age")).unwrap();
    assert!(app.operate(request(chat, json!(true))).await.is_err());
    assert_eq!(app.view().await.unwrap(), before);
    std::fs::remove_dir(path.join("read-state.age")).unwrap();
    app.close().await.unwrap();
}

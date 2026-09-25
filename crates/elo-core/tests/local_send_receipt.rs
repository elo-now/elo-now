use elo_core::app::{ClientApp, ProfileDraft};
use serde_json::json;
use tempfile::TempDir;

#[tokio::test]
async fn send_receipt_identifies_the_durable_record_and_local_device_is_always_listed() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("profile");
    let password = "synthetic local send test password";
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), password.into(), "General", "Sender")
        .await
        .unwrap();
    let view = app.view().await.unwrap();
    let chat = &view["streams"][0];
    let devices = app.linked_devices().await.unwrap();
    assert_eq!(devices["devices"].as_array().unwrap().len(), 1);
    assert_eq!(devices["devices"][0]["id"], view["credential"]);
    assert_eq!(devices["devices"][0]["current"], true);
    let response = app.operate(json!({"op":"send", "space":chat["space"], "stream":chat["stream"], "text":"Immediate local echo", "created_at":"2026-09-25T12:00:00Z"})).await.unwrap();
    let receipt = response["sent"].clone();
    let row = &response["view"]["streams"][0]["rows"][0];
    assert_eq!(receipt["id"], row["id"]);
    assert_eq!(receipt["logical_time"], row["body"]["logical_time"]);
    assert!(receipt["id"].is_string());
    app.close().await.unwrap();
    let reopened = ClientApp::open(path, password.into(), false).await.unwrap();
    assert_eq!(
        reopened.view().await.unwrap()["streams"][0]["rows"][0]["id"],
        receipt["id"]
    );
    reopened.close().await.unwrap();
}

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

#[tokio::test]
async fn message_expiry_is_signed_persisted_and_validated_before_sending() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("expiry-profile");
    let password = "synthetic expiry integration password";
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), password.into(), "General", "Sender")
        .await
        .unwrap();
    let chat = app.view().await.unwrap()["streams"][0].clone();
    let request = |hours: serde_json::Value| {
        json!({"op":"send", "space":chat["space"], "stream":chat["stream"],
        "text":"Expiring text", "created_at":"2026-09-30T10:00:00Z", "expires_in_hours":hours})
    };
    for bad in [json!(0), json!(2), json!(25), json!(1.5), json!("1")] {
        assert_eq!(
            app.operate(request(bad)).await.unwrap_err().to_string(),
            "message_expiry_invalid"
        );
    }
    for hours in [1, 12, 24] {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let response = app.operate(request(json!(hours))).await.unwrap();
        let deadline = response["sent"]["expires_at_ms"].as_u64().unwrap();
        assert!(deadline >= before + hours * 3_600_000);
        assert!(deadline < before + hours * 3_600_000 + 5_000);
        let id = &response["sent"]["id"];
        let row = response["view"]["streams"][0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| &row["id"] == id)
            .unwrap();
        assert_eq!(row["body"]["payload"]["expires_at_ms"], deadline);
    }
    let response = app.operate(request(serde_json::Value::Null)).await.unwrap();
    assert!(response["sent"]["expires_at_ms"].is_null());
    app.close().await.unwrap();
    let app = ClientApp::open(path, password.into(), false).await.unwrap();
    let rows = app.view().await.unwrap()["streams"][0]["rows"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(
        rows.iter()
            .filter(|row| row["body"]["payload"]["expires_at_ms"].is_number())
            .count(),
        3
    );
    app.close().await.unwrap();
}

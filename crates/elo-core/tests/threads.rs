use elo_core::{
    app::{ClientApp, ProfileDraft},
    replica::ReplicaStore,
    vault,
};
use serde_json::{Value, json};
use tempfile::TempDir;
const PASSWORD: &str = "synthetic reply integration password";
fn scope(chat: &Value, op: &str) -> Value {
    json!({"op":op,"space":chat["space"],"stream":chat["stream"]})
}
fn chat<'a>(view: &'a Value, id: &str) -> &'a Value {
    view["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["stream"] == id)
        .unwrap()
}
fn send(chat: &Value, text: &str, target: Option<&str>) -> Value {
    let mut request = scope(chat, "send");
    request["text"] = json!(text);
    request["created_at"] = json!("2026-09-10T18:00:00Z");
    if let Some(target) = target {
        request["reply_to"] = json!(target);
    }
    request
}
#[tokio::test]
async fn replies_survive_missing_original_history_offline_delivery_and_restart() {
    let temp = TempDir::new().unwrap();
    let owner_path = temp.path().join("owner");
    let reader_path = temp.path().join("reader");
    for (path, name) in [(&owner_path, "Alex"), (&reader_path, "Maya")] {
        ProfileDraft::new()
            .unwrap()
            .save_named(path.clone(), PASSWORD.into(), "General", name)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
    }
    let replica = ReplicaStore::open(temp.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(32 * 1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let descriptor = json!({"url":format!("http://{}",listener.local_addr().unwrap()),"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
    let peer = temp.path().join("peer.json");
    vault::write_private(&peer, &serde_json::to_vec(&descriptor).unwrap(), false).unwrap();
    let server = tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, elo_core::http::router(replica, &origin))
        }
        .await
        .unwrap()
    });
    let mut owner = ClientApp::open(owner_path.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    let mut reader = ClientApp::open(reader_path.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    for app in [&mut owner, &mut reader] {
        app.operate(json!({"op":"add_peer","path":peer}))
            .await
            .unwrap();
    }
    let channel = owner.view().await.unwrap()["streams"][0].clone();
    let stream = channel["stream"].as_str().unwrap();
    let root_view = owner
        .operate(send(&channel, "Original written before Maya joined", None))
        .await
        .unwrap();
    let original = chat(&root_view["view"], stream)["rows"][0].clone();
    let root = original["id"].as_str().unwrap();
    assert!(original["body"]["payload"].get("thread_root").is_none());
    owner.operate(json!({"op":"sync"})).await.unwrap();
    let offer_path = temp.path().join("offer.json");
    let request_path = temp.path().join("request.json");
    let config_path = temp.path().join("approved.age");
    let mut offer = scope(&channel, "invite_create");
    offer["output"] = json!(offer_path);
    owner.operate(offer).await.unwrap();
    let exchange: Value =
        serde_json::from_slice(&vault::read_private(&offer_path).unwrap()).unwrap();
    let reader_identity = reader.view().await.unwrap()["identity"].clone();
    reader.operate(json!({"op":"invite_request","path":offer_path,"space":exchange["space"],"root":exchange["root"],"output":request_path})).await.unwrap();
    let mut approval = scope(&channel, "invite_approve");
    approval["path"] = json!(request_path);
    approval["fingerprint"] = reader_identity;
    approval["output"] = json!(config_path);
    approval["post"] = json!(true);
    owner.operate(approval).await.unwrap();
    reader.operate(json!({"op":"import_stream","path":config_path,"space":exchange["space"],"stream":exchange["stream"],"root":exchange["root"],"name":"Replies"})).await.unwrap();
    let first = owner
        .operate(send(
            &channel,
            "Reply received before its original",
            Some(root),
        ))
        .await
        .unwrap();
    let reply = chat(&first["view"], stream)["rows"][1].clone();
    let reply_id = reply["id"].as_str().unwrap();
    assert_eq!(reply["body"]["payload"]["thread_root"], root);
    assert_eq!(reply["body"]["payload"]["sender_name"], "Alex");
    assert_eq!(
        chat(&first["view"], stream)["rows"][0]["body"],
        original["body"]
    );
    owner.operate(json!({"op":"sync"})).await.unwrap();
    reader.operate(json!({"op":"sync"})).await.unwrap();
    let missing = reader.view().await.unwrap();
    assert_eq!(chat(&missing, stream)["rows"].as_array().unwrap().len(), 1);
    assert_eq!(chat(&missing, stream)["rows"][0]["id"], reply_id);
    assert_eq!(chat(&missing, stream)["unread_count"], 1);
    assert!(
        reader
            .operate(send(&channel, "Must wait for the original", Some(reply_id)))
            .await
            .is_err()
    );
    assert_eq!(reader.view().await.unwrap(), missing);
    // Neither malformed input nor a record from another chat may create an outbox entry.
    for target in [json!(null), json!(7), json!("bad"), json!("00".repeat(32))] {
        let mut bad = send(&channel, "Must not be saved", None);
        bad["reply_to"] = target;
        assert!(reader.operate(bad).await.is_err());
    }
    let own = missing["streams"][0].clone();
    assert!(
        reader
            .operate(send(&own, "Cross-chat reply must fail", Some(reply_id)))
            .await
            .is_err()
    );
    assert_eq!(reader.view().await.unwrap(), missing);
    // Explicitly share only the original. Its old audience/signature are not rewritten.
    let history_request = temp.path().join("history.request");
    let history_bundle = temp.path().join("history.age");
    let mut request = scope(&channel, "history_request");
    request["count"] = json!(20);
    request["output"] = json!(history_request);
    reader.operate(request).await.unwrap();
    let mut request = scope(&channel, "history_preview");
    request["path"] = json!(history_request);
    let preview = owner.operate(request.clone()).await.unwrap();
    request["op"] = json!("history_approve");
    request["expected_request"] = preview["request_id"].clone();
    request["selection"] = json!([root]);
    request["output"] = json!(history_bundle);
    owner.operate(request).await.unwrap();
    let mut import = scope(&channel, "history_import");
    import["request"] = json!(history_request);
    import["path"] = json!(history_bundle);
    reader.operate(import.clone()).await.unwrap();
    reader.operate(import).await.unwrap();
    let with_root = reader.view().await.unwrap();
    assert_eq!(
        chat(&with_root, stream)["rows"].as_array().unwrap().len(),
        2
    );
    assert_eq!(chat(&with_root, stream)["rows"][0]["id"], root);
    assert_eq!(
        chat(&with_root, stream)["rows"][0]["body"],
        original["body"]
    );
    assert_eq!(chat(&with_root, stream)["unread_count"], 2);
    // A read marker for the original leaves its offscreen reply unread.
    let mut seen = scope(&channel, "mark_read");
    seen["records"] = json!([root]);
    reader.operate(seen).await.unwrap();
    assert_eq!(
        chat(&reader.view().await.unwrap(), stream)["unread_count"],
        1
    );
    owner.close().await.unwrap();
    let sent = reader
        .operate(send(
            &channel,
            "Reply to a reply stays in the original thread",
            Some(reply_id),
        ))
        .await
        .unwrap();
    let last = chat(&sent["view"], stream)["rows"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(last["body"]["payload"]["thread_root"], root);
    reader.operate(json!({"op":"sync"})).await.unwrap();
    reader.close().await.unwrap();
    let mut owner = ClientApp::open(owner_path.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    owner.operate(json!({"op":"sync"})).await.unwrap();
    let delivered = owner.view().await.unwrap();
    assert_eq!(
        chat(&delivered, stream)["rows"].as_array().unwrap().len(),
        3
    );
    assert_eq!(chat(&delivered, stream)["rows"][2]["id"], last["id"]);
    assert_eq!(chat(&delivered, stream)["rows"][2]["body"], last["body"]);
    owner.close().await.unwrap();
    let reopened = ClientApp::open(owner_path, PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(reopened.view().await.unwrap(), delivered);
    reopened.close().await.unwrap();
    let reopened = ClientApp::open(reader_path.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    let restored = reopened.view().await.unwrap();
    assert_eq!(chat(&restored, stream)["rows"][0]["unread"], false);
    assert_eq!(chat(&restored, stream)["rows"][1]["unread"], true);
    reopened.close().await.unwrap();
    let db = std::fs::read(reader_path.join("client.sqlite")).unwrap();
    let plain = b"Reply to a reply stays in the original thread";
    assert!(!db.windows(plain.len()).any(|bytes| bytes == plain));
    server.abort();
}

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use elo_core::{
    app::{
        ClientApp, ProfileDraft,
        push::{Route, scope},
    },
    replica::ReplicaStore,
    vault,
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const PASSWORD: &str = "synthetic notification delivery password";
#[derive(Default)]
struct Delivery {
    fail: AtomicBool,
    attempts: Mutex<Vec<Value>>,
    expected_key: Mutex<String>,
}
async fn receive(
    State(delivery): State<Arc<Delivery>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> StatusCode {
    assert_eq!(
        headers["authorization"],
        format!("Bearer {}", delivery.expected_key.lock().unwrap())
    );
    delivery.attempts.lock().unwrap().push(body);
    if delivery.fail.load(Ordering::SeqCst) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::ACCEPTED
    }
}
async fn profile(root: &Path, name: &str) -> ClientApp {
    let path = root.join(name);
    ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), PASSWORD.into(), "General", name)
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    ClientApp::open(path, PASSWORD.into(), true).await.unwrap()
}
async fn contact(owner: &mut ClientApp, other: &mut ClientApp) {
    let code = other
        .operate(json!({"op":"contact_create","name":other.view().await.unwrap()["name"]}))
        .await
        .unwrap();
    let preview = owner
        .operate(json!({"op":"contact_preview","link":code["link"]}))
        .await
        .unwrap();
    owner.operate(json!({"op":"contact_add","link":code["link"],"trusted":true,"confirmed_contact":preview["id"]})).await.unwrap();
}
fn chat<'a>(view: &'a Value, stream: &Value) -> &'a Value {
    view["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["stream"] == *stream)
        .unwrap()
}

#[tokio::test]
async fn encrypted_message_wake_retries_after_sender_restart_while_recipient_is_closed() {
    check_encrypted_message_wake(false, false).await;
}

#[tokio::test]
async fn notifications_enabled_after_contact_exchange_arrive_through_signed_discovery() {
    check_encrypted_message_wake(true, false).await;
}

#[tokio::test]
async fn rotated_notify_key_is_rediscovered_on_the_same_day_and_survives_sender_restart() {
    check_encrypted_message_wake(true, true).await;
}

async fn check_encrypted_message_wake(discover_route: bool, rotate: bool) {
    let temp = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let delivery = Arc::new(Delivery::default());
    *delivery.expected_key.lock().unwrap() = "b".repeat(64);
    delivery.fail.store(true, Ordering::SeqCst);
    let router = Router::new()
        .route("/v1/routes/{id}/wake", post(receive))
        .with_state(delivery.clone());
    let wake_server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut sender = profile(temp.path(), "Sender").await;
    let mut recipient = profile(temp.path(), "Recipient").await;
    for app in [&mut sender, &mut recipient] {
        app.configure_push(&url, true).unwrap();
    }
    let mut route = Route {
        endpoint: url.clone(),
        id: "a".repeat(32),
        notify_key: "b".repeat(64),
        scope_key: "c".repeat(64),
        since: 1,
    };
    if !discover_route {
        recipient.advertise_wake_route(Some(route.clone())).unwrap();
    }
    contact(&mut sender, &mut recipient).await;
    contact(&mut recipient, &mut sender).await;

    let replica_server = replica_server(temp.path(), &mut [&mut sender, &mut recipient]).await;
    if discover_route {
        // Both contact cards predate opt-in: no route is embedded in either card.
        // Exercise the same all-Space advertisement used by native maintenance.
        sender.enable_spaces().await.unwrap();
        recipient.enable_spaces().await.unwrap();
        recipient.advertise_wake_route(Some(route.clone())).unwrap();
        recipient.advertise_wake_route(Some(route.clone())).unwrap();
        recipient
            .operate(json!({"op":"invitation_sync","force":true}))
            .await
            .unwrap();
        sender
            .operate(json!({"op":"invitation_sync","force":true}))
            .await
            .unwrap();
    }
    if rotate {
        route.notify_key = "d".repeat(64);
        recipient.advertise_wake_route(Some(route.clone())).unwrap();
        recipient
            .operate(json!({"op":"invitation_sync","force":true}))
            .await
            .unwrap();
        sender
            .operate(json!({"op":"invitation_sync","force":true}))
            .await
            .unwrap();
        *delivery.expected_key.lock().unwrap() = route.notify_key.clone();
    }
    let created = sender.operate(json!({"op":"contact_create_chat","request_id":"01".repeat(16),"name":"Private notification test","chat_kind":"chat","people":[recipient.view().await.unwrap()["identity"]]})).await.unwrap();
    let stream = created["stream"].clone();
    let channel = chat(&created["view"], &stream).clone();
    let message_scope = scope(
        &route,
        Some((
            serde_json::from_value(channel["space"].clone()).unwrap(),
            serde_json::from_value(stream.clone()).unwrap(),
        )),
    )
    .unwrap();
    // The recipient process can remain closed during upload and notification retries.
    recipient.close().await.unwrap();
    sender.operate(json!({"op":"send","space":channel["space"],"stream":stream,"text":"Only ciphertext may leave the sender","created_at":"2026-09-12T12:00:00Z"})).await.unwrap();
    assert!(
        !delivery
            .attempts
            .lock()
            .unwrap()
            .iter()
            .any(|a| a["scope"] == message_scope)
    );
    sender.operate(json!({"op":"sync"})).await.unwrap();
    let first = delivery
        .attempts
        .lock()
        .unwrap()
        .iter()
        .find(|a| a["scope"] == message_scope)
        .cloned()
        .expect("stored message must attempt a wake");
    let view = sender.view().await.unwrap();
    let record = chat(&view, &stream)["rows"][0]["id"].clone();
    let wire = first.to_string();
    for private in [
        "Only ciphertext may leave the sender",
        "Private notification test",
        stream.as_str().unwrap(),
        record.as_str().unwrap(),
        view["identity"].as_str().unwrap(),
    ] {
        assert!(!wire.contains(private));
    }
    sender.close().await.unwrap();
    delivery.fail.store(false, Ordering::SeqCst);
    // Exercise the persisted real retry deadline, without modifying a live database.
    tokio::time::sleep(Duration::from_secs(31)).await;
    let mut sender = ClientApp::open(temp.path().join("Sender"), PASSWORD.into(), true)
        .await
        .unwrap();
    sender.configure_push(&url, true).unwrap();
    sender.operate(json!({"op":"sync"})).await.unwrap();
    let attempts: Vec<Value> = delivery
        .attempts
        .lock()
        .unwrap()
        .iter()
        .filter(|a| a["scope"] == message_scope)
        .cloned()
        .collect();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts[0]["event"], attempts[1]["event"],
        "relay can deduplicate a repeated handoff"
    );
    sender.operate(json!({"op":"sync"})).await.unwrap();
    assert_eq!(
        delivery
            .attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a["scope"] == message_scope)
            .count(),
        2
    );
    let mut recipient = ClientApp::open(temp.path().join("Recipient"), PASSWORD.into(), true)
        .await
        .unwrap();
    recipient.configure_push(&url, true).unwrap();
    let opened = recipient
        .open_notification(attempts[1]["target"].as_str().unwrap())
        .unwrap();
    assert_eq!(opened["record"], record);
    assert_eq!(opened["stream"], stream);
    assert_eq!(opened["identity"], json!(recipient.identity_id()));
    recipient.operate(json!({"op":"sync"})).await.unwrap();
    let received = recipient.view().await.unwrap();
    assert_eq!(chat(&received, &stream)["rows"][0]["id"], record);
    assert_eq!(
        chat(&received, &stream)["unread_count"],
        1,
        "opening a target is not a read receipt"
    );
    sender.close().await.unwrap();
    recipient.close().await.unwrap();
    wake_server.abort();
    replica_server.abort();
}

async fn replica_server(root: &Path, apps: &mut [&mut ClientApp]) -> tokio::task::JoinHandle<()> {
    let replica = ReplicaStore::open(root.join("replica")).await.unwrap();
    let mailbox = replica.create_mailbox(32 * 1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let descriptor = json!({"url":format!("http://{}",listener.local_addr().unwrap()),"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
    let path = root.join("peer.json");
    vault::write_private(&path, &serde_json::to_vec(&descriptor).unwrap(), false).unwrap();
    for app in apps {
        app.operate(json!({"op":"add_peer","path":path}))
            .await
            .unwrap();
    }
    tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, elo_core::http::router(replica, &origin))
        }
        .await
        .unwrap()
    })
}

#[tokio::test]
async fn membership_invitation_wakes_a_closed_recipient_and_clears_the_matching_alert() {
    for trusted_sender in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let delivery = Arc::new(Delivery::default());
        *delivery.expected_key.lock().unwrap() = "b".repeat(64);
        let router = Router::new()
            .route("/v1/routes/{id}/wake", post(receive))
            .with_state(delivery.clone());
        let wake_server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut sender = profile(temp.path(), "Sender").await;
        let mut recipient = profile(temp.path(), "Recipient").await;
        let mut third = profile(temp.path(), "Third").await;
        for app in [&mut sender, &mut recipient] {
            app.configure_push(&url, true).unwrap();
        }
        let route = Route {
            endpoint: url.clone(),
            id: "a".repeat(32),
            notify_key: "b".repeat(64),
            scope_key: "c".repeat(64),
            since: 1,
        };
        recipient.advertise_wake_route(Some(route.clone())).unwrap();
        contact(&mut sender, &mut recipient).await;
        contact(&mut sender, &mut third).await;
        if trusted_sender {
            contact(&mut recipient, &mut sender).await;
        }
        let replica_server =
            replica_server(temp.path(), &mut [&mut sender, &mut recipient, &mut third]).await;
        let recipient_id = recipient.identity_id();
        let third_id = third.identity_id();
        recipient.close().await.unwrap();
        let created = sender.operate(json!({"op":"contact_create_chat","request_id":"19".repeat(16),"name":"New chat invitation","chat_kind":"chat","people":[recipient_id]})).await.unwrap();
        let stream = created["stream"].clone();
        let channel = chat(&created["view"], &stream).clone();
        sender.close().await.unwrap();
        let mut sender = ClientApp::open(temp.path().join("Sender"), PASSWORD.into(), true)
            .await
            .unwrap();
        sender.configure_push(&url, true).unwrap();
        sender.operate(json!({"op":"sync"})).await.unwrap();
        let attempts = delivery.attempts.lock().unwrap().clone();
        assert_eq!(
            attempts.len(),
            1,
            "a persisted membership invitation must wake the offline recipient once"
        );
        let wake = &attempts[0];
        assert_eq!(wake["category"], "invitation");
        assert_eq!(wake["scope"], scope(&route, None).unwrap());
        let wire = wake.to_string();
        for private in [
            "New chat invitation",
            stream.as_str().unwrap(),
            &recipient_id.to_string(),
        ] {
            assert!(
                !wire.contains(private),
                "invitation details remain encrypted"
            );
        }
        let mut recipient = ClientApp::open(temp.path().join("Recipient"), PASSWORD.into(), true)
            .await
            .unwrap();
        recipient.configure_push(&url, true).unwrap();
        let target = recipient
            .open_notification(wake["target"].as_str().unwrap())
            .unwrap();
        assert_eq!(target["chat"]["stream"], stream);
        assert_eq!(target["chat"]["space"], channel["space"]);
        let seen = json!({"op":"invitation_activity_seen","ids":[format!("invitation:{}", target["chat"]["invitation"].as_str().unwrap())]});
        recipient.operate(seen.clone()).await.unwrap();
        assert!(
            recipient
                .notification_read_receipts(&route, &seen)
                .unwrap()
                .is_empty(),
            "unverified push data cannot produce a receipt"
        );
        recipient
            .operate(
                json!({"op":"invitation_sync","force":true,"foreground":true,"receive_only":true}),
            )
            .await
            .unwrap();
        let activity = recipient
            .operate(json!({"op":"invitation_activity"}))
            .await
            .unwrap();
        if trusted_sender {
            assert!(activity["received"].as_array().unwrap().is_empty());
            assert_eq!(
                chat(&recipient.view().await.unwrap(), &stream)["can_post"],
                true
            );
        } else {
            let entries = activity["received"].as_array().unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0]["id"], target["chat"]["invitation"]);
            assert!(
                !recipient.view().await.unwrap()["streams"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|s| s["stream"] == stream),
                "opening a push does not accept the invitation"
            );
        }
        recipient.operate(seen.clone()).await.unwrap();
        let receipts = recipient.notification_read_receipts(&route, &seen).unwrap();
        assert_eq!(
            receipts,
            vec![json!({"scope":wake["scope"],"event":wake["event"]})]
        );
        assert_eq!(recipient.view().await.unwrap()["invitations"]["unseen"], 0);
        if !trusted_sender {
            assert_eq!(
                recipient.view().await.unwrap()["invitations"]["actionable"],
                1,
                "clearing the alert must leave the invitation awaiting a decision"
            );
            recipient.close().await.unwrap();
            recipient = ClientApp::open(temp.path().join("Recipient"), PASSWORD.into(), true)
                .await
                .unwrap();
            recipient.configure_push(&url, true).unwrap();
            let reopened = recipient
                .open_notification(wake["target"].as_str().unwrap())
                .unwrap();
            assert_eq!(reopened, target);
            let activity = recipient
                .operate(json!({"op":"invitation_activity"}))
                .await
                .unwrap();
            let entries = activity["received"].as_array().unwrap();
            assert_eq!(entries.len(), 1, "a seen invitation survives restart");
            assert_eq!(entries[0]["id"], target["chat"]["invitation"]);
            let link = entries[0]["link"].clone();
            let preview = recipient
                .operate(json!({"op":"invitation_preview","link":link}))
                .await
                .unwrap();
            let join = json!({"op":"invitation_join","link":link,"trusted":true,"confirmed_reference":preview["id"]});
            for invalid in [
                json!({"trusted":false,"confirmed_reference":preview["id"]}),
                json!({"trusted":true,"confirmed_reference":"00".repeat(32)}),
            ] {
                let mut request = join.clone();
                request["trusted"] = invalid["trusted"].clone();
                request["confirmed_reference"] = invalid["confirmed_reference"].clone();
                assert!(recipient.operate(request).await.is_err());
            }
            assert!(
                !recipient.view().await.unwrap()["streams"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|s| s["stream"] == stream),
                "preview and invalid confirmation must not grant chat access"
            );
            recipient.operate(join).await.unwrap();
            let joined = recipient.view().await.unwrap();
            assert_eq!(chat(&joined, &stream)["can_post"], true);
            assert_eq!(joined["invitations"]["actionable"], 0);
            assert!(
                recipient
                    .operate(json!({"op":"invitation_activity"}))
                    .await
                    .unwrap()["received"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "acceptance removes the pending invitation"
            );
        }
        // A later member addition silently updates this existing recipient.
        sender.operate(json!({"op":"contact_add_members","request_id":"20".repeat(16),"space":channel["space"],"stream":stream,"people":[third_id]})).await.unwrap();
        sender.operate(json!({"op":"sync"})).await.unwrap();
        assert_eq!(
            delivery.attempts.lock().unwrap().len(),
            1,
            "existing members must not receive a new invitation alert"
        );
        sender.close().await.unwrap();
        recipient.close().await.unwrap();
        third.close().await.unwrap();
        wake_server.abort();
        replica_server.abort();
    }
}

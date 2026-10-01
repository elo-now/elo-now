use super::*;
use elo_core::realtime::{ClientFrame, ServerFrame};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn send(socket: &mut Socket, frame: ClientFrame) {
    socket
        .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
        .await
        .unwrap();
}

async fn receive(socket: &mut Socket) -> ServerFrame {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
            frame => panic!("Unexpected realtime frame: {frame:?}"),
        }
    }
}

#[tokio::test]
async fn hosted_realtime_accepts_native_targets_and_rejects_unavailable_reservations() {
    let temp = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let config: HostConfig = serde_json::from_value(json!({
        "root":temp.path().join("host"), "public_url":origin,
        "max_spaces_per_identity":2, "mailbox_quota_bytes":32 * 1024 * 1024,
    }))
    .unwrap();
    let host = Host::open(config, true).await.unwrap();
    let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
    let mut owner = tests::profile(&temp.path().join("owner")).await;
    let created = owner
        .operate(json!({
            "op":"space_create", "contact_email":"owner@example.test",
            "host":format!("{origin}/spaces/v1/create"),
            "message_lifetime_seconds":86400, "name":"Live delivery",
        }))
        .await
        .unwrap();
    owner
        .operate(json!({"op":"space_setup_done"}))
        .await
        .unwrap();
    owner.operate(json!({"op":"sync"})).await.unwrap();
    let context = created["view"]["active_space"].as_str().unwrap();
    let target = owner
        .realtime_snapshot()
        .targets()
        .into_iter()
        .find(|target| target.space_context == context)
        .unwrap();
    let websocket = reqwest::Url::parse(&target.url).unwrap();
    assert_eq!(websocket.path(), elo_core::realtime::HOST_PATH);
    let native = target.subscribe().unwrap();
    let ClientFrame::Subscribe { request, .. } = &native else {
        panic!("Expected subscription");
    };
    assert!(request.replica.starts_with("/spaces/"));
    assert!(request.replica.ends_with("/replica/"));
    let (mut socket, _) = tokio_tungstenite::connect_async(&target.url).await.unwrap();
    send(&mut socket, native).await;
    assert!(
        matches!(receive(&mut socket).await, ServerFrame::Subscribed { id } if id == target.id)
    );
    assert!(matches!(receive(&mut socket).await, ServerFrame::Changed { id } if id == target.id));

    // Exercise the hosted durable upload path, not a manually injected bus event.
    let view = owner.view().await.unwrap();
    let chat = view["streams"][0].clone();
    owner
        .operate(json!({
            "op":"send", "space":chat["space"], "stream":chat["stream"],
            "text":"Hosted realtime catch-up", "created_at":"2026-10-01T12:00:00Z",
        }))
        .await
        .unwrap();
    let synced = owner.operate(json!({"op":"sync_live"})).await.unwrap();
    assert!(synced["result"]["stored"].as_u64().unwrap_or(0) > 0);
    assert!(matches!(receive(&mut socket).await, ServerFrame::Changed { id } if id == target.id));

    let (reservation, space) = host
        .spaces
        .read()
        .await
        .iter()
        .find(|(_, space)| space.mailbox == target.mailbox())
        .map(|(id, space)| (id.clone(), space.clone()))
        .unwrap();
    *space.serving.write().await = false;
    let (mut stopped, _) = tokio_tungstenite::connect_async(&target.url).await.unwrap();
    send(&mut stopped, target.subscribe().unwrap()).await;
    assert!(
        matches!(receive(&mut stopped).await, ServerFrame::Error { code } if code == "unauthorized")
    );
    drop(stopped);

    *space.serving.write().await = true;
    host.spaces.write().await.remove(&reservation);
    let (mut removed, _) = tokio_tungstenite::connect_async(&target.url).await.unwrap();
    send(&mut removed, target.subscribe().unwrap()).await;
    assert!(
        matches!(receive(&mut removed).await, ServerFrame::Error { code } if code == "unauthorized")
    );
    drop(removed);

    let _ = socket.close(None).await;
    drop(socket);
    host.spaces.write().await.insert(reservation, space);
    owner.close().await.unwrap();
    task.abort();
    let _ = task.await;
    tests::close_host(host).await;
}

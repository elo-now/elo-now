mod support;
use elo_call_service::{
    engine::Engine,
    registry::Limits,
    server::{self, Admission, AdmissionFuture, Service},
};
use elo_core::{
    calls::{CallKind, InitialMedia, Operation},
    ids::{IdentityId, SpaceId},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{AUDIENCE, Fixture};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
struct Gate(AtomicBool);
impl Admission for Gate {
    fn allowed(&self, _: SpaceId, _: IdentityId) -> AdmissionFuture<'_> {
        Box::pin(async move { Ok(self.0.load(Ordering::SeqCst)) })
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
async fn receive(socket: &mut Socket, kind: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let value: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            if value["type"] == kind {
                return value;
            }
        }
    })
    .await
    .unwrap()
}
async fn submit(socket: &mut Socket, request: elo_call_service::engine::Request) {
    socket
        .send(Message::Text(
            serde_json::to_string(&request).unwrap().into(),
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn simultaneous_starts_share_a_room_signals_are_targeted_and_host_revocation_stops_admission()
{
    let f = Fixture::new(false);
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        &directory.path().join("state.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
    )
    .unwrap();
    let gate = Arc::new(Gate(AtomicBool::new(true)));
    let service = Service::new(engine, gate.clone(), 8);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/calls/v1/connect", listener.local_addr().unwrap());
    let task = tokio::spawn(axum::serve(listener, server::app(service)).into_future());
    let (mut owner, _) = connect_async(&url).await.unwrap();
    owner
        .send(Message::Ping(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), owner.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Message::Pong(_)
    ));
    let (mut peer, _) = connect_async(&url).await.unwrap();
    let op = || Operation::Start {
        kind: CallKind::Group,
        initial_media: InitialMedia::Audio,
    };
    tokio::join!(
        submit(&mut owner, f.request(&f.owner, op(), now(), true)),
        submit(&mut peer, f.request(&f.peer, op(), now(), true))
    );
    let first = receive(&mut owner, "result").await;
    let second = receive(&mut peer, "result").await;
    assert_eq!(first["call"]["call_id"], second["call"]["call_id"]);
    let id = first["call"]["call_id"].as_str().unwrap().to_owned();
    let (mut observer, _) = connect_async(&url).await.unwrap();
    submit(
        &mut observer,
        f.request(&f.third, Operation::Subscribe, now(), true),
    )
    .await;
    receive(&mut observer, "result").await;
    // Drain the observer's own presence before verifying private delivery.
    receive(&mut observer, "presence").await;
    submit(
        &mut owner,
        f.request(
            &f.owner,
            Operation::Signal {
                call_id: id.clone(),
                to: f.peer.credential().id(),
                ciphertext: "aGVsbG8=".into(),
            },
            now(),
            false,
        ),
    )
    .await;
    receive(&mut owner, "result").await;
    let signal = receive(&mut peer, "signal").await;
    assert_eq!(signal["to"], f.peer.credential().id().to_string());
    assert_eq!(signal["ciphertext"], "aGVsbG8=");
    assert!(
        tokio::time::timeout(Duration::from_millis(150), observer.next())
            .await
            .is_err()
    );
    gate.0.store(false, Ordering::SeqCst);
    submit(
        &mut owner,
        f.request(&f.owner, Operation::Heartbeat { call_id: id }, now(), false),
    )
    .await;
    assert_eq!(receive(&mut owner, "error").await["code"], "unauthorized");
    receive(&mut peer, "ended").await;
    owner.close(None).await.unwrap();
    peer.close(None).await.unwrap();
    observer.close(None).await.unwrap();
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn signed_stream_membership_does_not_bypass_hosting_denial() {
    let f = Fixture::new(false);
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        &directory.path().join("state.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
    )
    .unwrap();
    let service = Service::new(engine, Arc::new(Gate(AtomicBool::new(false))), 2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/calls/v1/connect", listener.local_addr().unwrap());
    let task = tokio::spawn(axum::serve(listener, server::app(service)).into_future());
    let (mut socket, _) = connect_async(url).await.unwrap();
    submit(
        &mut socket,
        f.request(
            &f.owner,
            Operation::Start {
                kind: CallKind::Group,
                initial_media: InitialMedia::Audio,
            },
            now(),
            true,
        ),
    )
    .await;
    let reply = receive(&mut socket, "error").await;
    assert_eq!(reply["code"], "unauthorized");
    assert!(reply.get("call").is_none());
    socket.close(None).await.unwrap();
    task.abort();
    let _ = task.await;
}

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
async fn native_state_read_requires_signed_subscribe_and_current_admission_without_joining() {
    let f = Fixture::new(false);
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(
        &directory.path().join("state.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
    )
    .unwrap();
    let start = f.request(
        &f.owner,
        Operation::Start {
            kind: CallKind::Group,
            initial_media: InitialMedia::Audio,
        },
        now(),
        true,
    );
    let prepared = engine.prepare(start, None, now()).unwrap();
    let call_id = engine
        .execute(prepared, now())
        .unwrap()
        .call
        .unwrap()
        .call_id;
    let media = f.request(
        &f.owner,
        Operation::Media {
            call_id: call_id.clone(),
            state: elo_core::calls::MediaState::default(),
        },
        now(),
        false,
    );
    let prepared = engine.prepare(media, None, now()).unwrap();
    engine.execute(prepared, now()).unwrap();
    let gate = Arc::new(Gate(AtomicBool::new(true)));
    let service = Service::new(engine, gate.clone(), 8);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = format!("http://{}", listener.local_addr().unwrap());
    let ws = format!("ws://{}/calls/v1/connect", listener.local_addr().unwrap());
    let task = tokio::spawn(axum::serve(listener, server::app(service)).into_future());
    let client = reqwest::Client::new();
    let endpoint = format!("{host}/calls/v1/state");
    let read = || f.request(&f.peer, Operation::Subscribe, now(), true);
    let response: Value = client
        .post(&endpoint)
        .json(&read())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["call"]["call_id"], call_id);
    assert_eq!(response["call"]["ready"], true);
    assert_eq!(
        response["call"]["participants"].as_object().unwrap().len(),
        1,
        "a state read never joins the recipient"
    );
    let join = f.request(
        &f.peer,
        Operation::Join {
            call_id: call_id.clone(),
            invitation_id: None,
        },
        now(),
        true,
    );
    assert_eq!(
        client
            .post(&endpoint)
            .json(&join)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let mut forged = read();
    forged.command.push('A');
    assert_eq!(
        client
            .post(&endpoint)
            .json(&forged)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    gate.0.store(false, Ordering::SeqCst);
    assert_eq!(
        client
            .post(&endpoint)
            .json(&read())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    gate.0.store(true, Ordering::SeqCst);
    let (mut owner, _) = connect_async(ws).await.unwrap();
    submit(
        &mut owner,
        f.request(&f.owner, Operation::Leave { call_id }, now(), true),
    )
    .await;
    receive(&mut owner, "result").await;
    let response: Value = client
        .post(endpoint)
        .json(&read())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        response["call"].is_null(),
        "ended calls cannot authorize a session-start hint"
    );
    task.abort();
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
                epoch: 2,
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

#[tokio::test]
async fn later_subscriptions_receive_calls_but_staggering_never_bypasses_admission() {
    use elo_core::{authority::Authority, ids::StreamId};
    struct RecipientGate {
        recipient: IdentityId,
        enabled: AtomicBool,
    }
    impl Admission for RecipientGate {
        fn allowed(&self, _: SpaceId, identity: IdentityId) -> AdmissionFuture<'_> {
            Box::pin(async move {
                Ok(identity != self.recipient || self.enabled.load(Ordering::SeqCst))
            })
        }
    }
    let mut f = Fixture::new(false);
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        &directory.path().join("state.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
    )
    .unwrap();
    let gate = Arc::new(RecipientGate {
        recipient: f.peer.identity_id(),
        enabled: AtomicBool::new(true),
    });
    let service = Service::new(engine, gate.clone(), 4);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/calls/v1/connect", listener.local_addr().unwrap());
    let task = tokio::spawn(axum::serve(listener, server::app(service)).into_future());
    let (mut peer, _) = connect_async(&url).await.unwrap();
    let original = f.authority.clone();
    let root_hex = f.owner.credential().record().body()["root_public_key"]
        .as_str()
        .unwrap();
    let root_bytes =
        std::array::from_fn(|i| u8::from_str_radix(&root_hex[i * 2..i * 2 + 2], 16).unwrap());
    let root = ed25519_dalek::VerifyingKey::from_bytes(&root_bytes).unwrap();
    for n in 1..=66 {
        let stream = StreamId::from_bytes([n; 16]);
        let mut authority = Authority::new(
            original.genesis().bytes(),
            original.space(),
            &root,
            f.owner.credential().clone(),
            stream,
        )
        .unwrap();
        let mut config = original.head().unwrap().clone();
        for id in config
            .members
            .iter()
            .flat_map(|member| &member.credential_ids)
        {
            authority.add_credential(original.credential(*id).unwrap().clone());
        }
        config.stream_id = stream;
        authority
            .apply_config(config.sign(f.owner.signing_key()).unwrap())
            .unwrap();
        f.authority = authority;
        submit(
            &mut peer,
            f.request(&f.peer, Operation::Subscribe, now(), true),
        )
        .await;
        assert!(receive(&mut peer, "result").await["call"].is_null());
    }
    let (mut owner, _) = connect_async(&url).await.unwrap();
    submit(
        &mut owner,
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
    let call = receive(&mut owner, "result").await["call"].clone();
    assert_eq!(
        receive(&mut peer, "presence").await["call"]["call_id"],
        call["call_id"]
    );
    gate.enabled.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(6)).await;
    submit(
        &mut owner,
        f.request(
            &f.owner,
            Operation::Media {
                call_id: call["call_id"].as_str().unwrap().into(),
                state: elo_core::calls::MediaState {
                    audio_muted: false,
                    video_published: true,
                    screen_published: false,
                },
            },
            now(),
            false,
        ),
    )
    .await;
    receive(&mut owner, "result").await;
    // The last chat is outside the first maintenance batch. Its next event
    // must still recheck hosting before disclosing presence or signalling.
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let value: Value =
                serde_json::from_str(peer.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_ne!(value["type"], "presence");
            assert_ne!(value["type"], "signal");
            if value["type"] == "access_revoked"
                && value["scope"]["conversation"]["stream_id"] == f.authority.stream().to_string()
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn direct_ring_answer_and_decline_reach_every_signed_device_subscription() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use elo_core::calls::delegation::CallDelegate;
    let f = Fixture::new(true);
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        &directory.path().join("state.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
    )
    .unwrap();
    let service = Service::new(engine, Arc::new(Gate(AtomicBool::new(true))), 8);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/calls/v1/connect", listener.local_addr().unwrap());
    let task = tokio::spawn(axum::serve(listener, server::app(service)).into_future());
    let (mut owner, _) = connect_async(&url).await.unwrap();
    let (mut peer, _) = connect_async(&url).await.unwrap();
    let (mut sibling, _) = connect_async(&url).await.unwrap();
    submit(
        &mut peer,
        f.request(&f.peer, Operation::Subscribe, now(), true),
    )
    .await;
    receive(&mut peer, "result").await;
    submit(
        &mut sibling,
        f.request(&f.peer_device, Operation::Subscribe, now(), true),
    )
    .await;
    receive(&mut sibling, "result").await;
    submit(
        &mut owner,
        f.request(
            &f.owner,
            Operation::Start {
                kind: CallKind::Direct,
                initial_media: InitialMedia::Audio,
            },
            now(),
            true,
        ),
    )
    .await;
    let first = receive(&mut owner, "result").await;
    let id = first["call"]["call_id"].as_str().unwrap().to_owned();
    let invitation =
        first["call"]["invitations"][f.peer.identity_id().to_string()]["invitation_id"]
            .as_str()
            .unwrap()
            .to_owned();
    for socket in [&mut peer, &mut sibling] {
        let event = receive(socket, "presence").await;
        assert_eq!(event["call"]["phase"], "ringing");
        assert_eq!(event["call"]["call_id"], id);
    }
    submit(
        &mut sibling,
        f.request(
            &f.peer_device,
            Operation::Decline {
                call_id: id.clone(),
                invitation_id: invitation,
            },
            now(),
            false,
        ),
    )
    .await;
    receive(&mut sibling, "result").await;
    for socket in [&mut owner, &mut peer, &mut sibling] {
        let event = receive(socket, "ended").await;
        assert_eq!(event["call_id"], id);
        assert_eq!(event["reason"], "declined");
    }
    submit(
        &mut owner,
        f.request(
            &f.owner,
            Operation::Start {
                kind: CallKind::Direct,
                initial_media: InitialMedia::Video,
            },
            now(),
            false,
        ),
    )
    .await;
    let second = receive(&mut owner, "result").await;
    receive(&mut owner, "presence").await;
    let id = second["call"]["call_id"].as_str().unwrap().to_owned();
    let invitation =
        second["call"]["invitations"][f.peer.identity_id().to_string()]["invitation_id"]
            .as_str()
            .unwrap()
            .to_owned();
    receive(&mut peer, "presence").await;
    receive(&mut sibling, "presence").await;
    let delegate =
        CallDelegate::create(&f.authority, &f.peer, f.authority.space(), AUDIENCE, now()).unwrap();
    submit(
        &mut peer,
        elo_call_service::engine::Request {
            command: STANDARD.encode(
                delegate
                    .sign_command(
                        &f.authority,
                        Operation::Join {
                            call_id: id.clone(),
                            invitation_id: Some(invitation.clone()),
                        },
                        now(),
                    )
                    .unwrap()
                    .bytes(),
            ),
            delegation: Some(STANDARD.encode(delegate.certificate().bytes())),
            proof: None,
        },
    )
    .await;
    let answered = receive(&mut peer, "result").await;
    assert_eq!(answered["call"]["phase"], "active");
    assert!(
        answered["call"]["invitations"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        answered["call"]["participants"][f.peer.identity_id().to_string()]["delegation"],
        STANDARD.encode(delegate.certificate().bytes())
    );
    for socket in [&mut owner, &mut sibling] {
        let event = receive(socket, "presence").await;
        assert_eq!(event["call"]["phase"], "active");
    }
    // Another device's late decline must not terminate the answered attempt.
    submit(
        &mut sibling,
        f.request(
            &f.peer_device,
            Operation::Decline {
                call_id: id.clone(),
                invitation_id: invitation,
            },
            now(),
            false,
        ),
    )
    .await;
    assert_eq!(receive(&mut sibling, "error").await["code"], "invalid");
    submit(
        &mut owner,
        f.request(
            &f.owner,
            Operation::End {
                call_id: id.clone(),
            },
            now(),
            false,
        ),
    )
    .await;
    receive(&mut owner, "result").await;
    for socket in [&mut owner, &mut peer, &mut sibling] {
        let event = receive(socket, "ended").await;
        assert_eq!(event["call_id"], id);
        assert_eq!(event["reason"], "ended");
    }
    task.abort();
}

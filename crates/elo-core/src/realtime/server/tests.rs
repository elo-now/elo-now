use super::*;
use crate::{
    identity::DeviceRevocation, ids::ObjectId, replica::MailboxDescriptor, vault::Session,
};
use futures_util::FutureExt;

fn proof(
    session: &Session,
    store: &ReplicaStore,
    request: &SubscriptionRequest,
    path: &str,
) -> String {
    access::Signer::new(session)
        .proof(&access::RequestContext {
            origin: "https://realtime.example",
            replica: store.key(),
            method: "SUBSCRIBE",
            path,
            body: &serde_json::to_vec(request).unwrap(),
            transfer: "",
            retention: "",
        })
        .unwrap()
}

async fn fixture() -> (
    tempfile::TempDir,
    ReplicaStore,
    MailboxDescriptor,
    Session,
    Arc<Server>,
    SubscriptionRequest,
) {
    let temp = tempfile::tempdir().unwrap();
    let store = ReplicaStore::open(temp.path().join("replica"))
        .await
        .unwrap();
    let mailbox = store.create_mailbox(1024 * 1024).await.unwrap();
    let (session, _) = Session::create().unwrap();
    store
        .set_space_members(mailbox.mailbox_id, vec![session.identity_id()])
        .await
        .unwrap();
    let server = Server::new(
        "https://realtime.example",
        PATH,
        Arc::new(crate::realtime::Standalone(store.clone())),
    );
    let request = SubscriptionRequest {
        id: "messages".into(),
        replica: "/".into(),
        mailbox: mailbox.mailbox_id,
        read_token: mailbox.read_token.clone(),
    };
    (temp, store, mailbox, session, server, request)
}

fn listener(
    id: &str,
    mailbox: MailboxId,
    identity: IdentityId,
    sender: mpsc::Sender<Notice>,
) -> Listener {
    Listener {
        id: id.into(),
        mailbox,
        identity,
        sender,
        changed: Arc::new(Notify::new()),
        hint_pending: Arc::new(AtomicBool::new(false)),
        queued_bytes: Arc::new(AtomicUsize::new(0)),
    }
}

#[tokio::test]
async fn subscription_proofs_bind_request_endpoint_and_consume_replay_nonce() {
    let (_temp, store, _mailbox, session, server, request) = fixture().await;
    let signed = proof(&session, &store, &request, PATH);
    let mut altered = request.clone();
    altered.id = "different-slot".into();
    assert!(server.subscribe(&altered, signed.clone()).await.is_err());
    assert!(
        server
            .subscribe(&request, proof(&session, &store, &request, HOST_PATH))
            .await
            .is_err()
    );
    let mut token = request.clone();
    token.read_token = "0".repeat(64);
    assert!(
        server
            .subscribe(&token, proof(&session, &store, &token, PATH))
            .await
            .is_err()
    );
    assert!(server.subscribe(&request, signed.clone()).await.is_ok());
    assert!(server.subscribe(&request, signed).await.is_err());
    let (stranger, _) = Session::create().unwrap();
    assert!(
        server
            .subscribe(&request, proof(&stranger, &store, &request, PATH))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn live_subscriptions_lose_access_after_membership_removal_and_device_revocation() {
    let (_temp, store, mailbox, session, server, request) = fixture().await;
    let (_, actor, companion) = server
        .subscribe(&request, proof(&session, &store, &request, PATH))
        .await
        .unwrap();
    let (sender, _receiver) = mpsc::channel(QUEUE);
    let entry = listener(&request.id, request.mailbox, actor.identity, sender);
    let hint_pending = entry.hint_pending.clone();
    let registration = store.realtime.subscribe(entry);
    let subscription = Subscription {
        request: request.clone(),
        actor,
        companion,
        store: store.clone(),
        hint_pending,
        _registration: registration,
    };
    assert!(server.authorized(&subscription).await.is_ok());
    store
        .set_space_members(mailbox.mailbox_id, vec![])
        .await
        .unwrap();
    assert!(server.authorized(&subscription).await.is_err());
    store
        .set_space_members(mailbox.mailbox_id, vec![session.identity_id()])
        .await
        .unwrap();
    assert!(server.authorized(&subscription).await.is_ok());
    let companion = session.linked_companion().unwrap();
    let revocation = DeviceRevocation::issue_from_device(
        companion.credential(),
        companion.signing_key(),
        session.credential(),
    )
    .unwrap();
    store.revocations().insert(&revocation).unwrap();
    assert!(server.authorized(&subscription).await.is_err());
    assert!(
        server
            .subscribe(&request, proof(&session, &store, &request, PATH))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_committed_upload_emits_one_coalesced_hint_and_duplicate_uploads_emit_none() {
    let (_temp, store, mailbox, session, _server, request) = fixture().await;
    let (sender, mut receiver) = mpsc::channel(QUEUE);
    let entry = listener("slot", request.mailbox, session.identity_id(), sender);
    let pending = entry.hint_pending.clone();
    let changed = entry.changed.clone();
    let _registration = store.realtime.subscribe(entry);
    let bytes = b"synthetic opaque ciphertext".to_vec();
    let object = ObjectId::of_ciphertext(&bytes);
    store
        .post(
            mailbox.mailbox_id,
            mailbox.write_token.clone(),
            object,
            bytes.clone(),
            crate::replica::TransferHint::Eager,
        )
        .await
        .unwrap();
    assert!(changed.notified().now_or_never().is_some());
    assert!(pending.load(Ordering::Acquire));
    assert!(receiver.try_recv().is_err());
    assert_eq!(
        store
            .get(mailbox.mailbox_id, mailbox.read_token.clone(), object)
            .await
            .unwrap(),
        bytes
    );
    pending.store(false, Ordering::Release);
    store
        .post(
            mailbox.mailbox_id,
            mailbox.write_token.clone(),
            object,
            bytes,
            crate::replica::TransferHint::Eager,
        )
        .await
        .unwrap();
    assert!(receiver.try_recv().is_err());
    assert!(changed.notified().now_or_never().is_none());
    for _ in 0..1000 {
        store.realtime.changed(request.mailbox);
    }
    assert!(pending.swap(false, Ordering::AcqRel));
    assert!(changed.notified().now_or_never().is_some());
    assert!(changed.notified().now_or_never().is_none());
    assert!(receiver.try_recv().is_err());
    // A change during authorization/sending schedules another wakeup instead
    // of being cleared by completion of the previous hint.
    store.realtime.changed(request.mailbox);
    assert!(pending.load(Ordering::Acquire));
    assert!(changed.notified().now_or_never().is_some());
}

#[tokio::test]
async fn ephemeral_fanout_drops_over_budget_data_without_blocking_durable_hints() {
    let bus = Arc::new(Events::default());
    let (session, _) = Session::create().unwrap();
    let (other, _) = Session::create().unwrap();
    let mailbox = MailboxId::from_bytes([1; 32]);
    let (sender, mut receiver) = mpsc::channel(QUEUE);
    let noisy = listener("noisy", mailbox, session.identity_id(), sender);
    let noisy_pending = noisy.hint_pending.clone();
    let noisy_changed = noisy.changed.clone();
    let queued_bytes = noisy.queued_bytes.clone();
    let _noisy = bus.subscribe(noisy);
    let (sender, mut quiet_receiver) = mpsc::channel(QUEUE);
    let quiet = listener("quiet", mailbox, other.identity_id(), sender);
    let quiet_pending = quiet.hint_pending.clone();
    let quiet_changed = quiet.changed.clone();
    let _quiet = bus.subscribe(quiet);
    let recipients = BTreeSet::from([session.identity_id()]);
    for _ in 0..5 {
        bus.publish(
            mailbox,
            session.credential().into(),
            false,
            &recipients,
            &"x".repeat(MAX_ENVELOPE),
        );
    }
    assert_eq!(queued_bytes.load(Ordering::Acquire), MAX_QUEUED_BYTES);
    assert!(quiet_receiver.try_recv().is_err());
    // Both recipients still get their durable sync wakeup, including the one
    // whose transient-byte budget is completely occupied.
    bus.changed(mailbox);
    for (pending, changed) in [
        (&noisy_pending, &noisy_changed),
        (&quiet_pending, &quiet_changed),
    ] {
        assert!(pending.swap(false, Ordering::AcqRel));
        assert!(changed.notified().now_or_never().is_some());
    }
    for _ in 0..4 {
        let notice = receiver.try_recv().unwrap();
        queued_bytes.fetch_sub(notice.envelope.len(), Ordering::AcqRel);
    }
    assert!(receiver.try_recv().is_err());
    assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
    bus.publish(
        mailbox,
        session.credential().into(),
        false,
        &recipients,
        "recovered",
    );
    assert_eq!(&*receiver.try_recv().unwrap().envelope, "recovered");
}

#[tokio::test]
async fn a_full_or_closed_ephemeral_queue_returns_its_byte_reservation() {
    let bus = Arc::new(Events::default());
    let (session, _) = Session::create().unwrap();
    let mailbox = MailboxId::from_bytes([1; 32]);
    let (sender, mut receiver) = mpsc::channel(1);
    let entry = listener("slot", mailbox, session.identity_id(), sender);
    let queued_bytes = entry.queued_bytes.clone();
    let pending = entry.hint_pending.clone();
    let changed = entry.changed.clone();
    let _registration = bus.subscribe(entry);
    let recipients = BTreeSet::from([session.identity_id()]);
    for _ in 0..1000 {
        bus.publish(
            mailbox,
            session.credential().into(),
            false,
            &recipients,
            "queued",
        );
    }
    assert_eq!(queued_bytes.load(Ordering::Acquire), "queued".len());
    bus.changed(mailbox);
    assert!(pending.swap(false, Ordering::AcqRel));
    assert!(changed.notified().now_or_never().is_some());
    let notice = receiver.try_recv().unwrap();
    queued_bytes.fetch_sub(notice.envelope.len(), Ordering::AcqRel);
    drop(receiver);
    bus.publish(
        mailbox,
        session.credential().into(),
        false,
        &recipients,
        "closed",
    );
    assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
}

#[test]
fn connection_caps_are_per_identity_and_device_and_release_on_disconnect() {
    let (session, _) = Session::create().unwrap();
    let actor = session.credential().into();
    let mut connections = Connections::default();
    assert!(connections.admit(1, actor));
    assert!(connections.admit(1, actor));
    assert!(connections.admit(2, actor));
    assert!(!connections.admit(3, actor));
    connections.remove(1);
    assert!(connections.admit(3, actor));
    for id in 4..=9 {
        assert!(connections.admit(
            id,
            Actor {
                identity: session.identity_id(),
                credential: RecordId::from_bytes([id as u8; 32])
            }
        ));
    }
    assert!(!connections.admit(
        10,
        Actor {
            identity: session.identity_id(),
            credential: RecordId::from_bytes([10; 32])
        }
    ));
}

#[test]
fn full_handshake_and_maximum_publication_rate_fit_the_frame_budget() {
    let started = tokio::time::Instant::now();
    let mut frames = RateBudget::new(started, FRAMES_PER_TEN_SECONDS, Duration::from_secs(10));
    let mut publications =
        RateBudget::new(started, PUBLICATIONS_PER_SECOND, Duration::from_secs(1));
    for _ in 0..MAX_SUBSCRIPTIONS {
        assert!(frames.admit(started));
    }
    for second in 0..10 {
        let now = started + Duration::from_secs(second);
        for _ in 0..PUBLICATIONS_PER_SECOND {
            assert!(publications.admit(now));
            assert!(frames.admit(now));
        }
        assert!(
            !publications.admit(now),
            "the eleventh publication must be rejected"
        );
    }
    // Normal Ping/Pong and small control traffic still fit, but the total is bounded.
    for _ in 0..FRAMES_PER_TEN_SECONDS - MAX_SUBSCRIPTIONS - 10 * PUBLICATIONS_PER_SECOND {
        assert!(frames.admit(started + Duration::from_secs(9)));
    }
    assert!(!frames.admit(started + Duration::from_secs(9)));
    assert!(frames.admit(started + Duration::from_secs(10)));
}

type TestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn wire_send(socket: &mut TestSocket, frame: ClientFrame) {
    use futures_util::SinkExt;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&frame).unwrap().into(),
        ))
        .await
        .unwrap();
}
async fn wire_receive(socket: &mut TestSocket) -> ServerFrame {
    use futures_util::StreamExt;
    loop {
        let message = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(text) = message {
            return serde_json::from_str(&text).unwrap();
        }
    }
}

#[tokio::test]
async fn websocket_multiplexes_slots_and_delivers_only_explicit_recipient_events() {
    let (_temp, store, mailbox, alice, server, mut first) = fixture().await;
    let (bob, _) = Session::create().unwrap();
    store
        .set_space_members(
            mailbox.mailbox_id,
            vec![alice.identity_id(), bob.identity_id()],
        )
        .await
        .unwrap();
    first.id = "alice".into();
    let mut second = first.clone();
    second.id = "bob".into();
    let second_mailbox = store.create_mailbox(1024 * 1024).await.unwrap();
    store
        .set_space_members(second_mailbox.mailbox_id, vec![bob.identity_id()])
        .await
        .unwrap();
    let third = SubscriptionRequest {
        id: "other-mailbox".into(),
        mailbox: second_mailbox.mailbox_id,
        read_token: second_mailbox.read_token,
        ..second.clone()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = server.router();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}{PATH}"))
        .await
        .unwrap();
    for (session, request) in [(&alice, &first), (&bob, &second), (&bob, &third)] {
        wire_send(
            &mut socket,
            ClientFrame::Subscribe {
                request: request.clone(),
                proof: proof(session, &store, request, PATH),
            },
        )
        .await;
        assert!(
            matches!(wire_receive(&mut socket).await, ServerFrame::Subscribed { id } if id == request.id)
        );
        assert!(
            matches!(wire_receive(&mut socket).await, ServerFrame::Changed { id } if id == request.id)
        );
    }
    // A different slot name cannot multiply recipient work for the same
    // authenticated device and mailbox, even when its proof is fresh.
    let duplicate = SubscriptionRequest {
        id: "alice-again".into(),
        ..first.clone()
    };
    wire_send(
        &mut socket,
        ClientFrame::Subscribe {
            request: duplicate.clone(),
            proof: proof(&alice, &store, &duplicate, PATH),
        },
    )
    .await;
    assert!(
        matches!(wire_receive(&mut socket).await, ServerFrame::Error { code } if code == "duplicate_subscription")
    );
    // The existing Alice/Bob slots continue to work after rejecting the duplicate.
    wire_send(
        &mut socket,
        ClientFrame::Publish {
            request: PublicationRequest {
                subscription: first.id.clone(),
                recipients: vec![bob.identity_id()],
                envelope: "opaque signed ciphertext".into(),
            },
        },
    )
    .await;
    assert!(
        matches!(wire_receive(&mut socket).await, ServerFrame::Ephemeral { id, identity, credential, .. }
        if id == second.id && identity == alice.identity_id() && credential == alice.credential().id())
    );
    // Removing the addressed member invalidates its live slot before new data is forwarded.
    store
        .set_space_members(mailbox.mailbox_id, vec![alice.identity_id()])
        .await
        .unwrap();
    store.realtime.changed(mailbox.mailbox_id);
    let first_event = wire_receive(&mut socket).await;
    let second_event = wire_receive(&mut socket).await;
    assert!(
        matches!((&first_event, &second_event), (ServerFrame::Changed { id: a }, ServerFrame::Revoked { id: b }) if a == "alice" && b == "bob")
    );
    drop(socket);
    task.abort();
}

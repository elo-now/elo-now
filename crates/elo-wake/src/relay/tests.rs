use super::*;
#[derive(Default)]
struct Fake {
    sent: Mutex<Vec<Notice>>,
    failure: Mutex<bool>,
}
impl Provider for Fake {
    fn send(
        &self,
        _token: String,
        notice: Notice,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), fcm::Error>> + Send + '_>> {
        Box::pin(async move {
            if *self.failure.lock().unwrap() {
                return Err(fcm::Error::Delivery);
            }
            self.sent.lock().unwrap().push(notice);
            Ok(())
        })
    }
}
fn headers(key: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("authorization", format!("Bearer {key}").parse().unwrap());
    h
}
fn wake_input(n: u8, scope: &str) -> Wake {
    Wake {
        sender: None,
        event: format!("{n:064x}"),
        scope: scope.into(),
        target: URL_SAFE_NO_PAD.encode([7u8; 100]),
    }
}
async fn setup(relay: &Arc<Relay>, provider: &Fake) -> (String, String, String, String) {
    let (id, owner, key, scope) = (
        "a".repeat(32),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
    );
    let session = elo_core::vault::Session::create().unwrap().0;
    let binding = route_binding(&session, &relay.endpoint, &id, "synthetic-device-token");
    assert!(
        !register(
            State(relay.clone()),
            Path(id.clone()),
            headers(&owner),
            Json(Registration {
                token: "synthetic-device-token".into(),
                notify_key: key.clone(),
                binding,
            })
        )
        .await
        .unwrap()
        .0["active"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(wake_input(1, &scope))
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    let challenge = match &provider.sent.lock().unwrap()[0] {
        Notice::Challenge { challenge, .. } => challenge.clone(),
        _ => panic!("challenge missing"),
    };
    assert_eq!(
        confirm(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(Confirmation {
                challenge: challenge.clone()
            })
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    let _ = confirm(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        Json(Confirmation { challenge }),
    )
    .await
    .unwrap();
    (id, owner, key, scope)
}

fn route_binding(
    session: &elo_core::vault::Session,
    endpoint: &str,
    id: &str,
    token: &str,
) -> elo_core::app::account_deletion::Request {
    use base64::engine::general_purpose::STANDARD;
    let value = json!({"v":1,"kind":"account.route","endpoint":endpoint,"route":id,"token":elo_core::ids::ObjectId::of_ciphertext(token.as_bytes()),"issued":now().unwrap() as u64 * 1000});
    elo_core::app::account_deletion::Request {
        record: STANDARD.encode(
            elo_core::record::SignedRecord::sign(
                &serde_json::to_vec(&value).unwrap(),
                session.signing_key(),
            )
            .unwrap()
            .bytes(),
        ),
        credential: STANDARD.encode(session.credential().record().bytes()),
    }
}

#[tokio::test]
async fn account_deletion_removes_all_device_routes_and_is_not_a_registration_proof() {
    use base64::engine::general_purpose::STANDARD;
    use elo_core::{
        app::account_deletion::{self as protocol, Action},
        record::SignedRecord,
        vault::Session,
    };
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let path = dir.path().join("relay.sqlite");
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let alice = Session::create().unwrap().0;
    let bob = Session::create().unwrap().0;
    for (n, session) in [(1, &alice), (2, &alice), (3, &bob)] {
        let id = format!("{n:032x}");
        let token = format!("synthetic-device-{n}-token");
        let _ = register(
            State(relay.clone()),
            Path(id.clone()),
            headers(&"b".repeat(64)),
            Json(Registration {
                binding: route_binding(session, &relay.endpoint, &id, &token),
                token,
                notify_key: "c".repeat(64),
            }),
        )
        .await
        .unwrap();
    }
    let bob_route = format!("{:032x}", 3);
    let tag = elo_core::app::push_sender::sender_tag(&bob_route, alice.identity_id());
    {
        let db = relay.database().unwrap();
        db.execute(
            "INSERT INTO events VALUES(?1,?2,?3)",
            params![bob_route, "synthetic-event", now().unwrap() + 100],
        )
        .unwrap();
        db.execute(
            "INSERT INTO attention VALUES(?1,?2,?3)",
            params![bob_route, "synthetic-scope", "synthetic-event"],
        )
        .unwrap();
        db.execute("INSERT INTO queue(route,scope,event,target,next,expires,sender) VALUES(?1,?2,?3,?4,0,?5,?6)",params![bob_route,"synthetic-scope","synthetic-event","opaque-target",now().unwrap()+100,tag]).unwrap();
    }
    let make = |action| {
        let command = protocol::Command {
            v: 1,
            kind: "account.deletion".into(),
            endpoint: format!("{}{}", relay.endpoint, protocol::WAKE_PATH),
            nonce: "ab".repeat(16),
            issued: now().unwrap() as u64 * 1000,
            action,
            confirmed: action == Action::Submit,
        };
        protocol::Request {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), alice.signing_key())
                    .unwrap()
                    .bytes(),
            ),
            credential: STANDARD.encode(alice.credential().record().bytes()),
        }
    };
    let _ = erase_account(State(relay.clone()), Json(make(Action::Inspect)))
        .await
        .unwrap();
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM routes", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    let deletion = make(Action::Submit);
    let mut forged = deletion.clone();
    forged.credential = STANDARD.encode(bob.credential().record().bytes());
    assert!(
        erase_account(State(relay.clone()), Json(forged))
            .await
            .is_err()
    );
    let _ = erase_account(State(relay.clone()), Json(deletion.clone()))
        .await
        .unwrap();
    let _ = erase_account(State(relay.clone()), Json(deletion))
        .await
        .unwrap();
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM routes", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM erased_accounts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT identity FROM route_accounts", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        bob.identity_id().to_string()
    );
    for table in ["queue", "events", "attention"] {
        assert_eq!(
            relay
                .database()
                .unwrap()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    let id = format!("{:032x}", 4);
    assert!(
        register(
            State(relay.clone()),
            Path(id.clone()),
            headers(&"b".repeat(64)),
            Json(Registration {
                binding: make(Action::Submit),
                token: "synthetic-device-token".into(),
                notify_key: "c".repeat(64)
            })
        )
        .await
        .is_err()
    );
    drop(relay);
    let relay = Relay::open(&path, provider).unwrap();
    assert_eq!(
        register(
            State(relay.clone()),
            Path(id.clone()),
            headers(&"b".repeat(64)),
            Json(Registration {
                binding: route_binding(&alice, &relay.endpoint, &id, "synthetic-device-token"),
                token: "synthetic-device-token".into(),
                notify_key: "c".repeat(64)
            })
        )
        .await
        .unwrap_err(),
        StatusCode::GONE
    );
}
async fn allow(
    relay: &Arc<Relay>,
    id: &str,
    owner: &str,
    scope: &str,
    revision: i64,
    enabled: bool,
) {
    policy(
        State(relay.clone()),
        Path(id.into()),
        headers(owner),
        Json(Policy {
            authenticated_senders: false,
            blocked_senders: Vec::new(),
            revision,
            introductions: true,
            scopes: vec![
                Scope {
                    scope: scope.into(),
                    enabled,
                    alert_once: true,
                },
                Scope {
                    scope: "f".repeat(64),
                    enabled: true,
                    alert_once: false,
                },
            ],
        }),
    )
    .await
    .unwrap();
}
fn due(relay: &Relay) {
    relay
        .database()
        .unwrap()
        .execute_batch("UPDATE queue SET next=0; UPDATE routes SET next_send=0;")
        .unwrap();
}
#[tokio::test]
async fn legacy_clients_keep_alerts_and_introductions_remain_repeatable() {
    let temp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&temp.path().join("db"), provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    let introduction = "f".repeat(64);
    for n in 1..=2 {
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(wake_input(n, &introduction)),
        )
        .await
        .unwrap();
        due(&relay);
        assert!(relay.deliver_due().await.unwrap());
    }
    // Downgrading replaces the capability declaration, including omitted scopes.
    // Old policy serialization must keep its digest so identical retries still work.
    let old = format!(
        r#"{{"revision":2,"introductions":true,"scopes":[{{"scope":"{scope}","enabled":true}}]}}"#
    );
    let legacy: Policy = serde_json::from_str(&old).unwrap();
    assert_eq!(serde_json::to_string(&legacy).unwrap(), old);
    policy(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        Json(legacy),
    )
    .await
    .unwrap();
    policy(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        Json(serde_json::from_str(&old).unwrap()),
    )
    .await
    .unwrap();
    for n in 3..=4 {
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(wake_input(n, &scope)),
        )
        .await
        .unwrap();
        due(&relay);
        assert!(relay.deliver_due().await.unwrap());
    }
    assert_eq!(
        provider
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|n| matches!(n, Notice::Wake { quiet: false, .. }))
            .count(),
        4
    );
}
#[tokio::test]
async fn a_hundred_unread_messages_alert_once_until_the_latest_is_read() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db");
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    for n in 1..=100 {
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(wake_input(n, &scope)),
        )
        .await
        .unwrap();
        due(&relay);
        assert!(relay.deliver_due().await.unwrap());
    }
    let audible = || {
        provider
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|n| matches!(n, Notice::Wake { quiet: false, .. }))
            .count()
    };
    assert_eq!(audible(), 1);
    drop(relay);
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let receipts = |n| {
        Json(ReadReceipts {
            events: vec![ReadReceipt {
                scope: scope.clone(),
                event: wake_input(n, &scope).event,
            }],
        })
    };
    assert_eq!(
        read(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            receipts(100)
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    // Reading an older notification cannot re-arm its newer unread replacement.
    read(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        receipts(1),
    )
    .await
    .unwrap();
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(101, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert_eq!(audible(), 1);
    read(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        receipts(101),
    )
    .await
    .unwrap();
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(102, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert_eq!(audible(), 2);
    // Retried acknowledgements cannot clear the new alert, even after restart.
    read(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        receipts(101),
    )
    .await
    .unwrap();
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(103, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert_eq!(audible(), 2);
    // Foreground reads can reach the service before a delayed sender's wake.
    read(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        receipts(104),
    )
    .await
    .unwrap();
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(104, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(!relay.deliver_due().await.unwrap());
    // Other conversations retain their independent first alert.
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(105, &"e".repeat(64))),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert_eq!(audible(), 3);
    // Reading an event that is still coalesced in the queue cancels it.
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(106, &scope)),
    )
    .await
    .unwrap();
    read(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        receipts(106),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(!relay.deliver_due().await.unwrap());
}
#[tokio::test]
async fn recipient_policy_cancels_queued_wakes_and_unknown_scopes_are_quiet() {
    let temp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&temp.path().join("db"), provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(1, &scope)),
    )
    .await
    .unwrap();
    assert!(!relay.deliver_due().await.unwrap());
    assert_eq!(
        policy(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(Policy {
                authenticated_senders: false,
                blocked_senders: Vec::new(),
                revision: 1,
                introductions: true,
                scopes: vec![]
            })
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    allow(&relay, &id, &owner, &scope, 1, true).await;
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(2, &scope)),
    )
    .await
    .unwrap();
    allow(&relay, &id, &owner, &scope, 2, false).await;
    due(&relay);
    assert!(!relay.deliver_due().await.unwrap());
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(3, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(!relay.deliver_due().await.unwrap());
    assert_eq!(
        policy(
            State(relay.clone()),
            Path(id.clone()),
            headers(&owner),
            Json(Policy {
                authenticated_senders: false,
                blocked_senders: Vec::new(),
                revision: 1,
                introductions: true,
                scopes: vec![Scope {
                    scope: scope.clone(),
                    enabled: true,
                    alert_once: true
                }]
            })
        )
        .await
        .unwrap_err(),
        StatusCode::CONFLICT
    );
    allow(&relay, &id, &owner, &scope, 3, true).await;
    // An acknowledged-but-muted event is not replayed by a client; new events work.
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(4, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert_eq!(provider.sent.lock().unwrap().len(), 2);
}
#[tokio::test]
async fn queue_retries_and_deduplicates_across_restart_and_coalesces_bursts() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db");
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    for n in [1, 2, 3, 1] {
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(wake_input(n, &scope)),
        )
        .await
        .unwrap();
    }
    *provider.failure.lock().unwrap() = true;
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    drop(relay);
    let relay = Relay::open(&path, provider.clone()).unwrap();
    *provider.failure.lock().unwrap() = false;
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert!(!relay.deliver_due().await.unwrap());
    assert_eq!(provider.sent.lock().unwrap().len(), 2);
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(3, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(!relay.deliver_due().await.unwrap());
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(4, &scope)),
    )
    .await
    .unwrap();
    assert_eq!(
        remove(State(relay.clone()), Path(id.clone()), headers(&key))
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    remove(State(relay.clone()), Path(id.clone()), headers(&owner))
        .await
        .unwrap();
    due(&relay);
    assert!(!relay.deliver_due().await.unwrap());
    assert_eq!(
        wake(
            State(relay.clone()),
            Path(id),
            headers(&key),
            Json(wake_input(5, &scope))
        )
        .await
        .unwrap_err(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn policy_retries_are_idempotent_and_removing_a_scope_keeps_it_muted() {
    let temp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&temp.path().join("db"), provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    assert_eq!(
        policy(
            State(relay.clone()),
            Path(id.clone()),
            headers(&owner),
            Json(Policy {
                authenticated_senders: false,
                blocked_senders: Vec::new(),
                revision: 1,
                introductions: true,
                scopes: vec![Scope {
                    scope: scope.clone(),
                    enabled: false,
                    alert_once: true
                }]
            })
        )
        .await
        .unwrap_err(),
        StatusCode::CONFLICT
    );
    policy(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        Json(Policy {
            authenticated_senders: false,
            blocked_senders: Vec::new(),
            revision: 2,
            introductions: true,
            scopes: vec![],
        }),
    )
    .await
    .unwrap();
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(11, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(!relay.deliver_due().await.unwrap());
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(12, &"e".repeat(64))),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert_eq!(provider.sent.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn blocked_identity_cannot_wake_through_new_scopes_or_devices_and_queued_alerts_are_removed()
{
    let tmp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&tmp.path().join("private/wake.sqlite"), provider.clone()).unwrap();
    let (route, owner, key, scope) = setup(&relay, &provider).await;
    let (sender, card) = elo_core::vault::Session::create().unwrap();
    let blocked = elo_core::app::push_sender::sender_tag(&route, sender.identity_id());
    let set_policy = |revision, tags| Policy {
        revision,
        introductions: true,
        scopes: vec![Scope {
            scope: scope.clone(),
            enabled: true,
            alert_once: true,
        }],
        authenticated_senders: true,
        blocked_senders: tags,
    };
    policy(
        State(relay.clone()),
        Path(route.clone()),
        headers(&owner),
        Json(set_policy(1, vec![])),
    )
    .await
    .unwrap();
    let signed = |session: &elo_core::vault::Session, n, scope: &str| {
        let mut body = serde_json::to_value(wake_input(n, scope)).unwrap();
        elo_core::app::push_sender::sign(session, &route, &mut body).unwrap();
        serde_json::from_value::<Wake>(body).unwrap()
    };
    wake(
        State(relay.clone()),
        Path(route.clone()),
        headers(&key),
        Json(signed(&sender, 20, &scope)),
    )
    .await
    .unwrap();
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM queue", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    policy(
        State(relay.clone()),
        Path(route.clone()),
        headers(&owner),
        Json(set_policy(2, vec![blocked.clone()])),
    )
    .await
    .unwrap();
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM queue", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let recovered = elo_core::vault::Session::recover(&card, sender.identity_id()).unwrap();
    for request in [
        signed(&sender, 21, &scope),
        signed(&recovered, 22, &"f".repeat(64)),
        wake_input(23, &scope),
    ] {
        assert_eq!(
            wake(
                State(relay.clone()),
                Path(route.clone()),
                headers(&key),
                Json(request)
            )
            .await
            .unwrap(),
            StatusCode::ACCEPTED
        );
    }
    let mut forged = signed(&sender, 24, &scope);
    forged.event = "e".repeat(64);
    assert_eq!(
        wake(
            State(relay.clone()),
            Path(route.clone()),
            headers(&key),
            Json(forged)
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM queue", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let allowed = elo_core::vault::Session::create().unwrap().0;
    wake(
        State(relay.clone()),
        Path(route.clone()),
        headers(&key),
        Json(signed(&allowed, 25, &scope)),
    )
    .await
    .unwrap();
    relay
        .database()
        .unwrap()
        .execute("UPDATE queue SET next=0", [])
        .unwrap();
    assert!(relay.deliver_due().await.unwrap());
    assert_eq!(
        provider
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|n| matches!(n, Notice::Wake { .. }))
            .count(),
        1
    );
    // Preferences survive process restarts and only recipient-owned policy can clear them.
    drop(relay);
    let relay = Relay::open(&tmp.path().join("private/wake.sqlite"), provider.clone()).unwrap();
    assert_eq!(
        policy(
            State(relay.clone()),
            Path(route.clone()),
            headers(&key),
            Json(set_policy(3, vec![]))
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    policy(
        State(relay.clone()),
        Path(route.clone()),
        headers(&owner),
        Json(set_policy(3, vec![])),
    )
    .await
    .unwrap();
    wake(
        State(relay.clone()),
        Path(route.clone()),
        headers(&key),
        Json(signed(&sender, 26, &scope)),
    )
    .await
    .unwrap();
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM queue", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn native_calls_require_current_recipient_policy_and_never_reappear_after_end() {
    use elo_core::{
        calls::wake::{Notice as Ring, Recipient},
        ids::RecordId,
    };
    let root = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let private_key = "e".repeat(64);
    let relay = Relay::open(&root.path().join("wake.sqlite"), provider.clone())
        .unwrap()
        .with_calls(zeroize::Zeroizing::new(private_key.clone()), None)
        .unwrap();
    let (route, owner, _, scope) = setup(&relay, &provider).await;
    allow(&relay, &route, &owner, &scope, 1, true).await;
    let identity = relay
        .database()
        .unwrap()
        .query_row(
            "SELECT identity FROM route_accounts WHERE route=?",
            [&route],
            |r| r.get::<_, String>(0),
        )
        .unwrap()
        .parse()
        .unwrap();
    let sender = elo_core::vault::Session::create().unwrap().0.identity_id();
    let credential = RecordId::from_bytes([1; 32]);
    let head = RecordId::from_bytes([2; 32]);
    let configure = |enabled, token: &str| calls::Registration {
        enabled,
        platform: "android".into(),
        token: token.into(),
        subscriptions: vec![calls::Subscription {
            call_scope: "3".repeat(64),
            notification_scope: scope.clone(),
            credential: credential.to_string(),
            head: head.to_string(),
            target: URL_SAFE_NO_PAD.encode([7u8; 100]),
        }],
    };
    assert_eq!(
        calls::register(
            State(relay.clone()),
            Path(route.clone()),
            headers(&owner),
            Json(configure(true, "different-device-token"))
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    calls::register(
        State(relay.clone()),
        Path(route.clone()),
        headers(&owner),
        Json(configure(true, "synthetic-device-token")),
    )
    .await
    .unwrap();
    let ring = |n| Ring::Ring {
        call_id: format!("{n:032x}"),
        scope: "3".repeat(64),
        head,
        caller: sender,
        recipients: vec![Recipient {
            identity,
            credential,
        }],
        expires: now().unwrap() as u64 + 45,
        video: true,
    };
    assert_eq!(
        calls::event(State(relay.clone()), headers(&owner), Json(ring(1)))
            .await
            .unwrap_err(),
        StatusCode::UNAUTHORIZED
    );
    calls::event(State(relay.clone()), headers(&private_key), Json(ring(1)))
        .await
        .unwrap();
    assert!(calls::deliver(&relay).await.unwrap());
    let sent = || {
        provider
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|n| matches!(n, Notice::Call { .. }))
            .count()
    };
    assert_eq!(sent(), 1);
    assert!(!calls::deliver(&relay).await.unwrap());
    calls::event(
        State(relay.clone()),
        headers(&private_key),
        Json(Ring::End {
            call_id: format!("{:032x}", 1),
        }),
    )
    .await
    .unwrap();
    calls::event(State(relay.clone()), headers(&private_key), Json(ring(1)))
        .await
        .unwrap();
    assert!(!calls::deliver(&relay).await.unwrap());
    // Muting after queueing prevents delivery, not just future subscriptions.
    calls::event(State(relay.clone()), headers(&private_key), Json(ring(2)))
        .await
        .unwrap();
    allow(&relay, &route, &owner, &scope, 2, false).await;
    calls::deliver(&relay).await.unwrap();
    assert_eq!(sent(), 1);
    allow(&relay, &route, &owner, &scope, 3, true).await;
    calls::event(State(relay.clone()), headers(&private_key), Json(ring(3)))
        .await
        .unwrap();
    let tag = elo_core::app::push_sender::sender_tag(&route, sender);
    relay
        .database()
        .unwrap()
        .execute(
            "INSERT INTO blocked_senders VALUES(?,?)",
            params![route, tag],
        )
        .unwrap();
    calls::deliver(&relay).await.unwrap();
    assert_eq!(sent(), 1);
    relay
        .database()
        .unwrap()
        .execute("DELETE FROM blocked_senders", [])
        .unwrap();
    calls::event(State(relay.clone()), headers(&private_key), Json(ring(4)))
        .await
        .unwrap();
    calls::register(
        State(relay.clone()),
        Path(route.clone()),
        headers(&owner),
        Json(configure(false, "")),
    )
    .await
    .unwrap();
    assert!(!calls::deliver(&relay).await.unwrap());
    assert_eq!(sent(), 1);
    calls::register(
        State(relay.clone()),
        Path(route.clone()),
        headers(&owner),
        Json(configure(true, "synthetic-device-token")),
    )
    .await
    .unwrap();
    calls::event(State(relay.clone()), headers(&private_key), Json(ring(5)))
        .await
        .unwrap();
    calls::deliver(&relay).await.unwrap();
    let ticket = provider
        .sent
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find_map(|n| {
            if let Notice::Call { ticket, .. } = n {
                Some(ticket.clone())
            } else {
                None
            }
        })
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = relay.clone().router();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let http = reqwest::Client::new();
    let url = format!("http://{address}/v1/routes/{route}/calls/{:032x}", 5);
    assert_eq!(
        http.delete(&url)
            .bearer_auth(&owner)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );
    assert_eq!(
        http.delete(&url)
            .bearer_auth(&ticket)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let status = calls::status(
        State(relay.clone()),
        Path((route.clone(), format!("{:032x}", 5))),
        headers(&ticket),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(status["ringing"], false);
    assert_eq!(
        calls::declined(State(relay.clone()), headers(&private_key))
            .await
            .unwrap()
            .0["declined"][0][1],
        identity.to_string()
    );
    assert_eq!(
        http.post(format!("http://{address}/internal/calls/event"))
            .bearer_auth(&private_key)
            .json(&ring(6))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
}

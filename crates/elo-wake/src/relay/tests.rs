use super::*;
mod authorization;
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
fn test_sender() -> &'static elo_core::vault::Session {
    static SENDER: std::sync::OnceLock<elo_core::vault::Session> = std::sync::OnceLock::new();
    SENDER.get_or_init(|| elo_core::vault::Session::create().unwrap().0)
}
fn test_sender_tag(route: &str) -> String {
    elo_core::app::push_sender::credential_tag(route, test_sender().credential().id())
}
fn signed_wake(sender: &elo_core::vault::Session, route: &str, n: u8, scope: &str) -> Wake {
    let mut body = json!({"event":format!("{n:064x}"),"scope":scope,"target":URL_SAFE_NO_PAD.encode([7u8; 100])});
    elo_core::app::push_sender::sign(sender, route, &mut body).unwrap();
    serde_json::from_value(body).unwrap()
}
fn wake_input(n: u8, scope: &str) -> Wake {
    signed_wake(test_sender(), &"a".repeat(32), n, scope)
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
            authenticated_senders: true,
            blocked_senders: Vec::new(),
            notify_key: None,
            revision,
            introductions: true,
            scopes: vec![
                Scope {
                    scope: scope.into(),
                    enabled,
                    alert_once: true,
                    senders: vec![test_sender_tag(&"a".repeat(32))],
                    allow_unknown: false,
                },
                Scope {
                    scope: "f".repeat(64),
                    enabled: true,
                    alert_once: false,
                    senders: vec![test_sender_tag(&"a".repeat(32))],
                    allow_unknown: true,
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
async fn introductions_remain_repeatable_and_unsigned_policy_downgrades_are_rejected() {
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
    let old = format!(
        r#"{{"revision":2,"introductions":true,"scopes":[{{"scope":"{scope}","enabled":true}}]}}"#
    );
    assert!(serde_json::from_str::<Policy>(&old).is_err());
    assert_eq!(
        provider
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|n| matches!(n, Notice::Wake { quiet: false, .. }))
            .count(),
        2
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
    // An undeclared scope can trigger a quiet sync, never an audible alert.
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
    assert_eq!(audible(), 2);
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
                authenticated_senders: true,
                blocked_senders: Vec::new(),
                notify_key: None,
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
                authenticated_senders: true,
                blocked_senders: Vec::new(),
                notify_key: None,
                revision: 1,
                introductions: true,
                scopes: vec![Scope {
                    scope: scope.clone(),
                    enabled: true,
                    alert_once: true,
                    senders: vec![test_sender_tag(&"a".repeat(32))],
                    allow_unknown: false,
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
                authenticated_senders: true,
                blocked_senders: Vec::new(),
                notify_key: None,
                revision: 1,
                introductions: true,
                scopes: vec![Scope {
                    scope: scope.clone(),
                    enabled: false,
                    alert_once: true,
                    senders: vec![test_sender_tag(&"a".repeat(32))],
                    allow_unknown: false,
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
            authenticated_senders: true,
            blocked_senders: Vec::new(),
            notify_key: None,
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
    let allowed = elo_core::vault::Session::create().unwrap().0;
    let blocked = elo_core::app::push_sender::sender_tag(&route, sender.identity_id());
    let set_policy = |revision, tags| Policy {
        revision,
        introductions: true,
        scopes: vec![Scope {
            scope: scope.clone(),
            enabled: true,
            alert_once: true,
            senders: vec![
                elo_core::app::push_sender::credential_tag(&route, sender.credential().id()),
                elo_core::app::push_sender::credential_tag(&route, allowed.credential().id()),
            ],
            allow_unknown: false,
        }],
        authenticated_senders: true,
        blocked_senders: tags,
        notify_key: None,
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
        Wake {
            sender: None,
            ..wake_input(23, &scope)
        },
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
async fn retiring_incoming_call_tokens_preserves_ordinary_notification_delivery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("wake.sqlite");
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let (route, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &route, &owner, &scope, 1, true).await;
    wake(
        State(relay.clone()),
        Path(route.clone()),
        headers(&key),
        Json(wake_input(2, &scope)),
    )
    .await
    .unwrap();
    let retired = [
        "call_queue",
        "call_subscriptions",
        "call_devices",
        "call_declines",
        "call_events",
        "voip_bindings",
        "voip_challenges",
        "voip_keys",
    ];
    {
        let db = relay.database().unwrap();
        for table in retired {
            db.execute_batch(&format!(
                "CREATE TABLE {table}(token TEXT); INSERT INTO {table} VALUES('synthetic-retired-token');"
            ))
            .unwrap();
        }
    }
    drop(relay);
    let relay = Relay::open(&path, provider.clone()).unwrap();
    {
        let db = relay.database().unwrap();
        for table in retired {
            assert!(
                !db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
            );
        }
        assert!(row(&db, &route).unwrap().unwrap().active);
        assert_eq!(
            db.query_row("SELECT count(*) FROM queue", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert!(provider.sent.lock().unwrap().iter().any(|notice| matches!(notice,
        Notice::Wake { registration, scope: delivered, .. } if registration == &route && delivered == &scope
    )));
}

#[tokio::test]
async fn retired_incoming_call_and_voip_endpoints_are_not_exposed() {
    use std::future::IntoFuture;
    let directory = tempfile::tempdir().unwrap();
    let relay = Relay::open(
        &directory.path().join("wake.sqlite"),
        Arc::new(Fake::default()),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(axum::serve(listener, relay.router()).into_future());
    let http = reqwest::Client::new();
    for (method, path) in [
        (reqwest::Method::PUT, "/v1/routes/retired/calls"),
        (reqwest::Method::GET, "/v1/routes/retired/calls/session"),
        (reqwest::Method::DELETE, "/v1/routes/retired/calls/session"),
        (reqwest::Method::POST, "/v1/routes/retired/voip/challenge"),
        (reqwest::Method::POST, "/v1/routes/retired/voip/proof"),
        (reqwest::Method::POST, "/internal/calls/event"),
        (reqwest::Method::POST, "/internal/calls/declined"),
    ] {
        assert_eq!(
            http.request(method, format!("{endpoint}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        http.get(format!("{endpoint}/wake/health"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    server.abort();
}

#[tokio::test]
async fn failed_registration_releases_capacity_and_does_not_take_delivery_gate() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    *provider.failure.lock().unwrap() = true;
    let relay = Relay::open(&dir.path().join("wake.sqlite"), provider).unwrap();
    let session = elo_core::vault::Session::create().unwrap().0;
    let id = "d".repeat(32);
    // A locked delivery worker must not hold up device possession checks.
    let _delivery = relay.delivery_gate.lock().await;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        register(
            State(relay.clone()),
            Path(id.clone()),
            headers(&"a".repeat(64)),
            Json(Registration {
                token: "synthetic-failed-token".into(),
                notify_key: "b".repeat(64),
                binding: route_binding(&session, &relay.endpoint, &id, "synthetic-failed-token"),
            }),
        ),
    )
    .await
    .expect("registration must not wait for unrelated delivery");
    assert_eq!(result.unwrap_err(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM routes", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn a_full_shared_ledger_preserves_other_routes_and_counters_survive_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wake.sqlite");
    let relay = Relay::open(&path, Arc::new(Fake::default())).unwrap();
    {
        let mut db = relay.database().unwrap();
        let tx = db.transaction().unwrap();
        for route in ["noisy", "quiet", "other-device"] {
            tx.execute(
                "INSERT INTO routes VALUES(?,x'01',x'02','test-token','',1,9999999999,NULL,0)",
                [route],
            )
            .unwrap();
        }
        tx.execute(
            "INSERT INTO route_accounts VALUES('quiet','owner'),('other-device','owner')",
            [],
        )
        .unwrap();
        // Simulate a full shared ledger without sending external notifications.
        tx.execute_batch(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<250000)
            INSERT INTO events SELECT 'noisy',printf('%064x',x),9999999999 FROM n;",
        )
        .unwrap();
        assert!(!event_capacity(&tx, "noisy").unwrap());
        assert!(event_capacity(&tx, "quiet").unwrap());
        for n in 0..64 {
            assert!(event_capacity(&tx, "quiet").unwrap());
            tx.execute(
                "INSERT INTO events VALUES('quiet',?,9999999999)",
                [format!("{n:064x}")],
            )
            .unwrap();
        }
        assert!(!event_capacity(&tx, "quiet").unwrap());
        assert!(event_capacity(&tx, "other-device").unwrap());
        tx.execute(
            "INSERT OR IGNORE INTO events VALUES('quiet',?,9999999999)",
            [format!("{:064x}", 0)],
        )
        .unwrap();
        assert_eq!(
            tx.query_row(
                "SELECT count FROM route_event_totals WHERE route='quiet'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            64
        );
        tx.execute("DELETE FROM routes WHERE id='noisy'", [])
            .unwrap();
        assert!(event_capacity(&tx, "quiet").unwrap());
        assert_eq!(
            tx.query_row("SELECT count FROM event_totals", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            64
        );
        tx.commit().unwrap();
    }
    drop(relay);
    let reopened = Relay::open(&path, Arc::new(Fake::default())).unwrap();
    let db = reopened.database().unwrap();
    assert_eq!(
        db.query_row("SELECT count FROM event_totals", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        64
    );
    assert!(event_capacity(&db, "quiet").unwrap());
    // Extra devices owned by the same identity do not multiply its quota.
    db.execute_batch(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<8128)
        INSERT INTO events SELECT 'other-device',printf('%064x',x),9999999999 FROM n;",
    )
    .unwrap();
    assert!(!event_capacity(&db, "quiet").unwrap());
}

#[tokio::test]
async fn invitation_category_is_signed_persisted_and_cannot_be_replaced_by_the_transport() {
    let temp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let path = temp.path().join("db");
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    let mut body = serde_json::to_value(signed_wake(test_sender(), &id, 101, &scope)).unwrap();
    body["category"] = json!("invitation");
    let forged: Wake = serde_json::from_value(body.clone()).unwrap();
    assert!(
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(forged)
        )
        .await
        .is_err()
    );
    elo_core::app::push_sender::sign(test_sender(), &id, &mut body).unwrap();
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(serde_json::from_value(body).unwrap()),
    )
    .await
    .unwrap();
    drop(relay);
    let relay = Relay::open(&path, provider.clone()).unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    let sent = provider.sent.lock().unwrap();
    let notice = sent.last().unwrap();
    assert!(
        matches!(notice, Notice::Wake { category, event, .. } if category == "invitation" && event == &format!("{:064x}",101))
    );
    let payload = crate::fcm::payload("synthetic", notice);
    assert_eq!(
        payload["message"]["apns"]["payload"]["aps"]["alert"]["body"],
        "New invitation"
    );
    assert_eq!(payload["message"]["apns"]["payload"]["aps"]["badge"], 1);
    assert!(payload["message"]["android"].get("collapse_key").is_none());
}

#[tokio::test]
async fn session_wakes_require_exact_authorized_scope_deduplicate_and_expire() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db");
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    let expires = now().unwrap() as u64 + 60;
    let session = |event: u8, scope: &str, expires: u64| {
        let mut body = json!({"event":format!("{event:064x}"),"scope":scope,"target":URL_SAFE_NO_PAD.encode([7u8;100]),"category":"session_start","expires":expires});
        elo_core::app::push_sender::sign(test_sender(), &id, &mut body).unwrap();
        serde_json::from_value::<Wake>(body).unwrap()
    };
    let send = |input| {
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(input),
        )
    };
    let mut tampered = session(201, &scope, expires);
    tampered.expires = Some(expires - 1);
    assert_eq!(send(tampered).await.unwrap_err(), StatusCode::FORBIDDEN);
    assert_eq!(
        send(session(201, &scope, expires + 10)).await.unwrap_err(),
        StatusCode::BAD_REQUEST
    );
    send(session(201, &"e".repeat(64), expires)).await.unwrap();
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM queue", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0,
        "introductions cannot authorize a session hint"
    );
    send(session(201, &scope, expires)).await.unwrap();
    send(session(201, &scope, expires)).await.unwrap();
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT expires FROM queue", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        expires as i64
    );
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    send(session(201, &scope, expires)).await.unwrap();
    due(&relay);
    assert!(
        !relay.deliver_due().await.unwrap(),
        "same session cannot alert twice after delivery"
    );
    send(session(202, &scope, expires)).await.unwrap();
    allow(&relay, &id, &owner, &scope, 2, false).await;
    due(&relay);
    assert!(
        !relay.deliver_due().await.unwrap(),
        "a mute also cancels already queued session hints"
    );
    allow(&relay, &id, &owner, &scope, 3, true).await;
    send(session(203, &scope, expires)).await.unwrap();
    relay
        .database()
        .unwrap()
        .execute("UPDATE queue SET expires=0", [])
        .unwrap();
    due(&relay);
    assert!(
        !relay.deliver_due().await.unwrap(),
        "an expired session hint is never submitted to the provider"
    );
    let sent = provider.sent.lock().unwrap();
    let Notice::Wake {
        category,
        expires: Some(actual),
        ..
    } = sent.last().unwrap()
    else {
        panic!("session hint missing")
    };
    assert_eq!(category, "session_start");
    assert_eq!(*actual, expires);
    let payload = crate::fcm::payload("synthetic", sent.last().unwrap());
    assert_eq!(
        payload["message"]["data"]["elo_expires"],
        expires.to_string()
    );
    assert_eq!(
        payload["message"]["apns"]["headers"]["apns-expiration"],
        expires.to_string()
    );
    assert!(
        payload["message"]["apns"]["payload"]["aps"]
            .get("badge")
            .is_none()
    );
    assert_eq!(
        payload["message"]["apns"]["payload"]["aps"]["alert"]["body"],
        "A chat session has started. Open elo.now to join."
    );
    assert!(!payload.to_string().contains("elo_call"));
}

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
    assert!(
        !register(
            State(relay.clone()),
            Path(id.clone()),
            headers(&owner),
            Json(Registration {
                token: "synthetic-device-token".into(),
                notify_key: key.clone()
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

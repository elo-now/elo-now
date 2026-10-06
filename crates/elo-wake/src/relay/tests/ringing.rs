use super::*;
use crate::relay::ringing::{self as incoming, Binding, Ring};

fn input(
    sender: &elo_core::vault::Session,
    route: &str,
    scope: &str,
    event: u8,
    expires: u64,
) -> Ring {
    let mut wake = json!({"event":format!("{event:064x}"),"scope":scope,
        "target":URL_SAFE_NO_PAD.encode([7u8;100]),"category":"call_ring","expires":expires});
    elo_core::app::push_sender::sign(sender, route, &mut wake).unwrap();
    serde_json::from_value(
        json!({"wake":wake,"call_id":"12".repeat(16),"invitation_id":"34".repeat(16)}),
    )
    .unwrap()
}
fn binding(provider: &str, token: Option<&str>) -> Binding {
    serde_json::from_value(json!({"provider":provider,"token":token})).unwrap()
}
fn rings(provider: &Fake) -> usize {
    provider
        .sent
        .lock()
        .unwrap()
        .iter()
        .filter(|notice| matches!(notice, Notice::Ring { .. }))
        .count()
}
async fn bind(relay: &Arc<Relay>, route: &str, owner: &str) {
    assert_eq!(
        incoming::bind(
            State(relay.clone()),
            Path(route.into()),
            headers(owner),
            Json(binding("fcm", None))
        )
        .await
        .unwrap(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn ring_binding_requires_the_proved_installation_owner_and_rejects_invalid_provider_tokens() {
    let temp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&temp.path().join("db"), provider.clone()).unwrap();
    let (id, owner, key, _) = setup(&relay, &provider).await;
    assert_eq!(
        incoming::bind(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(binding("fcm", None))
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    for bad in [
        binding("other", None),
        binding("fcm", Some("another-token")),
        binding("apns", None),
        binding("apns", Some("not-a-device-token")),
        serde_json::from_value(json!({"provider":"fcm","sandbox":true})).unwrap(),
        binding("apns_sandbox", Some(&"a".repeat(64))),
    ] {
        assert_eq!(
            incoming::bind(
                State(relay.clone()),
                Path(id.clone()),
                headers(&owner),
                Json(bad)
            )
            .await
            .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }
    bind(&relay, &id, &owner).await;
    assert_eq!(
        incoming::unbind(State(relay.clone()), Path(id.clone()), headers(&key))
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        incoming::unbind(State(relay.clone()), Path(id.clone()), headers(&owner))
            .await
            .unwrap(),
        StatusCode::NO_CONTENT
    );
    relay
        .database()
        .unwrap()
        .execute("UPDATE routes SET active=0", [])
        .unwrap();
    assert_eq!(
        incoming::bind(
            State(relay.clone()),
            Path(id),
            headers(&owner),
            Json(binding("fcm", None))
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn ringing_requires_exact_signed_sender_and_scope_and_deduplicates_one_attempt() {
    let temp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&temp.path().join("db"), provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    bind(&relay, &id, &owner).await;
    let expires = now().unwrap() as u64 + 50;
    let send = |body| {
        incoming::ring(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(body),
        )
    };
    let stranger = elo_core::vault::Session::create().unwrap().0;
    assert_eq!(
        send(input(&stranger, &id, &scope, 1, expires))
            .await
            .unwrap(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        send(input(test_sender(), &id, &"ef".repeat(32), 2, expires))
            .await
            .unwrap(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        rings(&provider),
        0,
        "introductions and another credential never authorize ringing"
    );
    let mut unsigned = json!({"event":"11".repeat(32),"scope":scope,"target":URL_SAFE_NO_PAD.encode([7u8;100]),"category":"call_ring","expires":expires});
    elo_core::app::push_sender::sign(test_sender(), &id, &mut unsigned).unwrap();
    unsigned["target"] = json!(URL_SAFE_NO_PAD.encode([8u8; 100]));
    let tampered = serde_json::from_value(
        json!({"wake":unsigned,"call_id":"12".repeat(16),"invitation_id":"34".repeat(16)}),
    )
    .unwrap();
    assert_eq!(send(tampered).await.unwrap_err(), StatusCode::FORBIDDEN);
    assert_eq!(
        incoming::ring(
            State(relay.clone()),
            Path(id.clone()),
            headers(&owner),
            Json(input(test_sender(), &id, &scope, 3, expires))
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    send(input(test_sender(), &id, &scope, 3, expires))
        .await
        .unwrap();
    send(input(test_sender(), &id, &scope, 3, expires))
        .await
        .unwrap();
    assert_eq!(
        rings(&provider),
        1,
        "replayed signed requests cannot ring twice"
    );
    assert!(matches!(
        provider.sent.lock().unwrap().last(),
        Some(Notice::Ring { voip: false, .. })
    ));
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM queue", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0,
        "call rings are never queued beyond their immediate expiry"
    );
}

#[tokio::test]
async fn ring_expiry_provider_failure_retry_and_opt_out_do_not_leave_delayed_alerts() {
    let temp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&temp.path().join("db"), provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    bind(&relay, &id, &owner).await;
    let expires = now().unwrap() as u64 + 50;
    let send = |body| {
        incoming::ring(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(body),
        )
    };
    for deadline in [now().unwrap() as u64, now().unwrap() as u64 + 120] {
        assert_eq!(
            send(input(test_sender(), &id, &scope, 1, deadline))
                .await
                .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }
    *provider.failure.lock().unwrap() = true;
    assert_eq!(
        send(input(test_sender(), &id, &scope, 2, expires))
            .await
            .unwrap_err(),
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(rings(&provider), 0);
    assert_eq!(
        relay
            .database()
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "failed provider delivery remains retryable"
    );
    *provider.failure.lock().unwrap() = false;
    relay
        .database()
        .unwrap()
        .execute("UPDATE incoming_bindings SET next_send=0", [])
        .unwrap();
    send(input(test_sender(), &id, &scope, 2, expires))
        .await
        .unwrap();
    send(input(test_sender(), &id, &scope, 2, expires))
        .await
        .unwrap();
    assert_eq!(rings(&provider), 1);
    allow(&relay, &id, &owner, &scope, 2, false).await;
    send(input(test_sender(), &id, &scope, 3, expires))
        .await
        .unwrap();
    assert_eq!(rings(&provider), 1, "muted scopes cannot ring");
    allow(&relay, &id, &owner, &scope, 3, true).await;
    relay
        .database()
        .unwrap()
        .execute("UPDATE incoming_bindings SET expires=0,next_send=0", [])
        .unwrap();
    send(input(test_sender(), &id, &scope, 4, expires))
        .await
        .unwrap();
    assert_eq!(rings(&provider), 1, "expired enrollment cannot ring");
    bind(&relay, &id, &owner).await;
    incoming::unbind(State(relay.clone()), Path(id.clone()), headers(&owner))
        .await
        .unwrap();
    send(input(test_sender(), &id, &scope, 5, expires))
        .await
        .unwrap();
    assert_eq!(rings(&provider), 1, "removing enrollment prevents delivery");
}

#[tokio::test]
async fn apns_environments_are_bound_per_installation_and_update_without_changing_global_provider()
{
    let temp = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&temp.path().join("db"), provider.clone()).unwrap();
    let owner = "b".repeat(64);
    let notify = "c".repeat(64);
    let scope = "d".repeat(64);
    let voip_token = "e".repeat(64);
    let expires = now().unwrap() as u64 + 50;
    for (index, sandbox) in [(1u8, false), (2, true)] {
        let route = format!("{index:032x}");
        let token = format!("synthetic-installation-{index}");
        let session = elo_core::vault::Session::create().unwrap().0;
        let _ = register(
            State(relay.clone()),
            Path(route.clone()),
            headers(&owner),
            Json(Registration {
                binding: route_binding(&session, &relay.endpoint, &route, &token),
                token,
                notify_key: notify.clone(),
            }),
        )
        .await
        .unwrap();
        let challenge = match provider.sent.lock().unwrap().last().unwrap() {
            Notice::Challenge { challenge, .. } => challenge.clone(),
            _ => panic!("expected installation challenge"),
        };
        let _ = confirm(
            State(relay.clone()),
            Path(route.clone()),
            headers(&owner),
            Json(Confirmation { challenge }),
        )
        .await
        .unwrap();
        policy(
            State(relay.clone()),
            Path(route.clone()),
            headers(&owner),
            Json(Policy {
                authenticated_senders: true,
                blocked_senders: vec![],
                notify_key: None,
                revision: 1,
                introductions: false,
                scopes: vec![Scope {
                    scope: scope.clone(),
                    enabled: true,
                    alert_once: true,
                    senders: vec![test_sender_tag(&route)],
                    allow_unknown: false,
                }],
            }),
        )
        .await
        .unwrap();
        let binding =
            serde_json::from_value(json!({"provider":"apns","token":voip_token,"sandbox":sandbox}))
                .unwrap();
        incoming::bind(
            State(relay.clone()),
            Path(route.clone()),
            headers(&owner),
            Json(binding),
        )
        .await
        .unwrap();
        let saved: String = relay
            .database()
            .unwrap()
            .query_row(
                "SELECT provider FROM incoming_bindings WHERE route=?",
                [&route],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved, if sandbox { "apns_sandbox" } else { "apns" });
        incoming::ring(
            State(relay.clone()),
            Path(route.clone()),
            headers(&notify),
            Json(input(test_sender(), &route, &scope, index, expires)),
        )
        .await
        .unwrap();
        assert!(
            matches!(provider.sent.lock().unwrap().last(), Some(Notice::Ring {voip:true,apns_sandbox,..}) if *apns_sandbox == sandbox)
        );
    }
    // Re-signing a development install must move its binding immediately, even
    // when the device happens to retain the same registration/token value.
    let route = format!("{:032x}", 1);
    incoming::bind(
        State(relay.clone()),
        Path(route.clone()),
        headers(&owner),
        Json(
            serde_json::from_value(json!({"provider":"apns","token":voip_token,"sandbox":true}))
                .unwrap(),
        ),
    )
    .await
    .unwrap();
    relay
        .database()
        .unwrap()
        .execute(
            "UPDATE incoming_bindings SET next_send=0 WHERE route=?",
            [&route],
        )
        .unwrap();
    incoming::ring(
        State(relay.clone()),
        Path(route.clone()),
        headers(&notify),
        Json(input(test_sender(), &route, &scope, 3, expires)),
    )
    .await
    .unwrap();
    assert!(matches!(
        provider.sent.lock().unwrap().last(),
        Some(Notice::Ring {
            voip: true,
            apns_sandbox: true,
            ..
        })
    ));
    assert_eq!(rings(&provider), 3);
    // Older clients omit the field, which has always meant production.
    incoming::bind(
        State(relay.clone()),
        Path(route.clone()),
        headers(&owner),
        Json(binding("apns", Some(&voip_token))),
    )
    .await
    .unwrap();
    let saved: String = relay
        .database()
        .unwrap()
        .query_row(
            "SELECT provider FROM incoming_bindings WHERE route=?",
            [&route],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(saved, "apns");
    assert!(
        serde_json::from_value::<Binding>(
            json!({"provider":"apns","token":voip_token,"sandbox":"true"})
        )
        .is_err()
    );
}

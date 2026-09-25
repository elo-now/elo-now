use super::*;
use elo_core::{app::push_sender::credential_tag, vault::Session};

fn count(relay: &Relay, table: &str) -> i64 {
    assert!(["queue", "events"].contains(&table));
    relay
        .database()
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn scope_permissions_and_rotated_keys_survive_retries_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wake.sqlite");
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let (id, owner, old_key, scope) = setup(&relay, &provider).await;
    let (sender, recovery) = Session::create().unwrap();
    let replacement = Session::recover(&recovery, sender.identity_id()).unwrap();
    let stranger = Session::create().unwrap().0;
    let key = "9".repeat(64);
    let other_scope = "8".repeat(64);
    let make_policy = |revision, removed: bool, rotate: bool| Policy {
        revision,
        introductions: true,
        authenticated_senders: true,
        blocked_senders: vec![],
        notify_key: rotate.then(|| key.clone()),
        scopes: vec![
            Scope {
                scope: scope.clone(),
                enabled: true,
                alert_once: true,
                allow_unknown: false,
                senders: if removed {
                    vec![]
                } else {
                    vec![credential_tag(&id, sender.credential().id())]
                },
            },
            Scope {
                scope: other_scope.clone(),
                enabled: true,
                alert_once: true,
                allow_unknown: false,
                senders: vec![credential_tag(&id, replacement.credential().id())],
            },
        ],
    };
    policy(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        Json(make_policy(1, false, false)),
    )
    .await
    .unwrap();
    // A new credential of the SAME identity is not membership in the old chat.
    for (n, who) in [(1, &replacement), (2, &stranger)] {
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&old_key),
            Json(signed_wake(who, &id, n, &scope)),
        )
        .await
        .unwrap();
    }
    assert_eq!(count(&relay, "queue"), 0);
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&old_key),
        Json(signed_wake(&sender, &id, 3, &scope)),
    )
    .await
    .unwrap();
    assert_eq!(count(&relay, "queue"), 1);
    policy(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        Json(make_policy(2, true, true)),
    )
    .await
    .unwrap();
    assert_eq!(count(&relay, "queue"), 0, "revocation removes queued work");
    // A lost acknowledgement retries the same revision and key; neither rolls back.
    policy(
        State(relay.clone()),
        Path(id.clone()),
        headers(&owner),
        Json(make_policy(2, true, true)),
    )
    .await
    .unwrap();
    assert_eq!(
        policy(
            State(relay.clone()),
            Path(id.clone()),
            headers(&owner),
            Json(make_policy(1, false, false))
        )
        .await
        .unwrap_err(),
        StatusCode::CONFLICT
    );
    drop(relay);
    let relay = Relay::open(&path, provider.clone()).unwrap();
    assert_eq!(
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&old_key),
            Json(signed_wake(&sender, &id, 4, &scope))
        )
        .await
        .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    // Even learning the fresh route key through another chat grants no access here.
    for (n, who, target) in [
        (5, &sender, &scope),
        (6, &replacement, &scope),
        (7, &sender, &other_scope),
    ] {
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(signed_wake(who, &id, n, target)),
        )
        .await
        .unwrap();
    }
    assert_eq!(count(&relay, "queue"), 0);
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(signed_wake(&replacement, &id, 8, &other_scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert!(matches!(
        provider.sent.lock().unwrap().last(),
        Some(Notice::Wake { quiet: false, .. })
    ));
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(signed_wake(&replacement, &id, 9, &other_scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert!(
        matches!(
            provider.sent.lock().unwrap().last(),
            Some(Notice::Wake { quiet: true, .. })
        ),
        "unread chats stay quiet without a repeatable introduction scope"
    );
}

#[tokio::test]
async fn unknown_identities_share_a_durable_quiet_budget_without_displacing_known_alerts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wake.sqlite");
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&path, provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    let intro = "f".repeat(64);
    let stranger = Session::create().unwrap().0;
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(1, &intro)),
    )
    .await
    .unwrap();
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(signed_wake(&stranger, &id, 2, &intro)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert!(matches!(
        provider.sent.lock().unwrap().last(),
        Some(Notice::Wake { quiet: false, .. })
    ));
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(signed_wake(&stranger, &id, 3, &intro)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
    assert!(matches!(
        provider.sent.lock().unwrap().last(),
        Some(Notice::Wake { quiet: true, .. })
    ));
    let before = count(&relay, "events");
    drop(relay);
    let relay = Relay::open(&path, provider.clone()).unwrap();
    for n in 4..12 {
        let attacker = Session::create().unwrap().0;
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(signed_wake(&attacker, &id, n, &format!("{n:064x}"))),
        )
        .await
        .unwrap();
    }
    assert_eq!(count(&relay, "events"), before);
    assert_eq!(count(&relay, "queue"), 0);
    // Only one unknown hint may occupy the queue, even across budget periods.
    for n in 12..15 {
        relay
            .database()
            .unwrap()
            .execute("UPDATE untrusted_wakes SET next=0", [])
            .unwrap();
        wake(
            State(relay.clone()),
            Path(id.clone()),
            headers(&key),
            Json(signed_wake(&stranger, &id, n, &format!("{n:064x}"))),
        )
        .await
        .unwrap();
        assert_eq!(count(&relay, "queue"), 1);
    }
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(15, &scope)),
    )
    .await
    .unwrap();
    assert_eq!(
        count(&relay, "queue"),
        2,
        "trusted work does not share the unknown-sender budget"
    );
}

#[tokio::test]
async fn invalid_policy_cannot_rotate_a_key_or_disable_authentication() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Fake::default());
    let relay = Relay::open(&dir.path().join("wake.sqlite"), provider.clone()).unwrap();
    let (id, owner, key, scope) = setup(&relay, &provider).await;
    allow(&relay, &id, &owner, &scope, 1, true).await;
    let policy_value = json!({"revision":2,"authenticated_senders":true,"scopes":[{"scope":scope,"enabled":true,"senders":[test_sender_tag(&id)]}],"notify_key":"9".repeat(64)});
    for (field, value) in [
        ("authenticated_senders", json!(false)),
        ("notify_key", json!("invalid")),
    ] {
        let mut v = policy_value.clone();
        v[field] = value;
        assert_eq!(
            policy(
                State(relay.clone()),
                Path(id.clone()),
                headers(&owner),
                Json(serde_json::from_value(v).unwrap())
            )
            .await
            .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }
    for senders in [json!(["invalid"]), json!(vec![test_sender_tag(&id); 8193])] {
        let mut v = policy_value.clone();
        v["scopes"][0]["senders"] = senders;
        assert_eq!(
            policy(
                State(relay.clone()),
                Path(id.clone()),
                headers(&owner),
                Json(serde_json::from_value(v).unwrap())
            )
            .await
            .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }
    wake(
        State(relay.clone()),
        Path(id.clone()),
        headers(&key),
        Json(wake_input(1, &scope)),
    )
    .await
    .unwrap();
    due(&relay);
    assert!(relay.deliver_due().await.unwrap());
}

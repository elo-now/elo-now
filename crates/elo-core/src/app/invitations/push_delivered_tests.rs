use super::*;

fn route() -> Route {
    Route {
        endpoint: "https://notifications.example/".into(),
        id: "a".repeat(32),
        notify_key: "b".repeat(64),
        scope_key: "c".repeat(64),
        since: 1,
    }
}

fn target(app: &ClientApp, record: RecordId) -> Target {
    Target {
        v: 1,
        identity: app.identity_id(),
        category: "message".into(),
        space: Some(app.pins[0].space),
        space_context: None,
        stream: Some(app.pins[0].stream),
        chat: None,
        record: Some(record),
        thread: None,
        call_id: None,
        expires: now().unwrap().as_millis() as u64 + 60_000,
    }
}

fn delivery(app: &ClientApp, route: &Route, target: &Target) -> Value {
    wake_request(
        route,
        target.space.zip(target.stream),
        &target.record.unwrap().to_string(),
        target,
        &app.session.credential().recipient(),
    )
    .unwrap()
}

async fn send(app: &mut ClientApp) -> RecordId {
    let pin = app.pins[0].clone();
    app.operate(json!({"op":"send", "space":pin.space, "stream":pin.stream,
        "text":"Synthetic late notification", "created_at":"2026-10-02T12:00:00Z"}))
        .await
        .unwrap()["sent"]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

async fn mark(app: &mut ClientApp, id: RecordId, op: &str) {
    let pin = app.pins[0].clone();
    app.operate(json!({"op":op,"space":pin.space,"stream":pin.stream,"records":[id]}))
        .await
        .unwrap();
}

#[tokio::test]
async fn delivered_late_read_receipts_preserve_new_and_manually_unread_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = crate::app::performance::profile(tmp.path().join("profile")).await;
    let id = send(&mut app).await;
    let route = route();
    let read = delivery(&app, &route, &target(&app, id));
    let new = delivery(&app, &route, &target(&app, RecordId::from_bytes([91; 32])));
    assert!(
        app.notification_delivered_read_receipts(&route, &[read.clone(), new.clone()])
            .await
            .unwrap()
            .is_empty()
    );
    mark(&mut app, id, "mark_read").await;
    let expected = vec![json!({"scope":read["scope"],"event":read["event"]})];
    assert_eq!(
        app.notification_delivered_read_receipts(&route, &[read.clone(), new])
            .await
            .unwrap(),
        expected
    );
    mark(&mut app, id, "mark_unread").await;
    assert!(
        app.notification_delivered_read_receipts(&route, std::slice::from_ref(&read))
            .await
            .unwrap()
            .is_empty()
    );
    mark(&mut app, id, "mark_read").await;
    // Connected Spaces use the same verified local read state after startup.
    app.enable_spaces().await.unwrap();
    assert_eq!(
        app.notification_delivered_read_receipts(&route, std::slice::from_ref(&read))
            .await
            .unwrap(),
        expected
    );
    let mut changed_route = route.clone();
    changed_route.scope_key = "d".repeat(64);
    assert!(
        app.notification_delivered_read_receipts(&changed_route, &[read])
            .await
            .unwrap()
            .is_empty()
    );
    let fresh = delivery(&app, &changed_route, &target(&app, id));
    assert_eq!(
        app.notification_delivered_read_receipts(&changed_route, &[fresh])
            .await
            .unwrap()
            .len(),
        1
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn private_read_state_clears_one_delivered_chat_while_another_stays_unread() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = crate::app::performance::profile(tmp.path().join("profile")).await;
    let first = send(&mut app).await;
    let route = route();
    let first_alert = delivery(&app, &route, &target(&app, first));
    let first_pin = app.pins[0].clone();
    app.operate(json!({"op":"create_chat","name":"Another conversation"}))
        .await
        .unwrap();
    let second_pin = app.pins.last().unwrap().clone();
    let sent = app
        .operate(
            json!({"op":"send","space":second_pin.space,"stream":second_pin.stream,
        "text":"Keep this unread","created_at":"2026-10-02T12:00:00Z"}),
        )
        .await
        .unwrap();
    let second: RecordId = sent["sent"]["id"].as_str().unwrap().parse().unwrap();
    let mut second_target = target(&app, second);
    second_target.space = Some(second_pin.space);
    second_target.stream = Some(second_pin.stream);
    let second_alert = delivery(&app, &route, &second_target);
    app.set_private_read_markers(first_pin.space, first_pin.stream, vec![first], true)
        .unwrap();
    app.set_private_read_markers(second_pin.space, second_pin.stream, vec![second], true)
        .unwrap();
    // The same encrypted projection updated by receive_private_settings must
    // clear a specific delivered receipt, not depend on a zero aggregate badge.
    app.set_private_read_markers(first_pin.space, first_pin.stream, vec![first], false)
        .unwrap();
    assert_eq!(
        app.notification_delivered_read_receipts(&route, &[first_alert.clone(), second_alert])
            .await
            .unwrap(),
        vec![json!({"scope":first_alert["scope"],"event":first_alert["event"]})]
    );
    assert_eq!(
        app.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .iter()
            .map(|stream| stream["unread_count"].as_u64().unwrap())
            .sum::<u64>(),
        1
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn delivered_receipts_require_exact_scope_event_recipient_and_bounded_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = crate::app::performance::profile(tmp.path().join("profile")).await;
    let id = send(&mut app).await;
    mark(&mut app, id, "mark_read").await;
    let route = route();
    let valid = delivery(&app, &route, &target(&app, id));
    let mut wrong_scope = valid.clone();
    wrong_scope["scope"] = json!("0".repeat(64));
    let mut wrong_event = valid.clone();
    wrong_event["event"] = json!("0".repeat(64));
    let mut wrong_identity = target(&app, id);
    wrong_identity.identity = IdentityId::from_bytes([92; 32]);
    let mut wrong_category = target(&app, id);
    wrong_category.category = "invitation".into();
    let mut future = target(&app, id);
    future.expires += 86_520_000;
    let mut malformed = valid.clone();
    malformed["target"] = json!("a".repeat(2049));
    let mut tampered = valid.clone();
    let mut cipher = URL_SAFE_NO_PAD
        .decode(valid["target"].as_str().unwrap())
        .unwrap();
    *cipher.last_mut().unwrap() ^= 1;
    tampered["target"] = json!(URL_SAFE_NO_PAD.encode(cipher));
    let wrong_key = age::x25519::Identity::generate();
    let wrong_recipient = wake_request(
        &route,
        Some((app.pins[0].space, app.pins[0].stream)),
        &id.to_string(),
        &target(&app, id),
        &wrong_key.to_public(),
    )
    .unwrap();
    let invalid = [
        wrong_scope,
        wrong_event,
        delivery(&app, &route, &wrong_identity),
        delivery(&app, &route, &wrong_category),
        delivery(&app, &route, &future),
        malformed,
        tampered,
        wrong_recipient,
        Value::Null,
    ];
    assert!(
        app.notification_delivered_read_receipts(&route, &invalid)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        app.notification_delivered_read_receipts(&route, &vec![valid; 65])
            .await
            .is_err()
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn delivered_deleted_messages_are_cleared_but_expired_unknown_targets_are_not() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = crate::app::performance::profile(tmp.path().join("profile")).await;
    let id = send(&mut app).await;
    let route = route();
    let mut expired = target(&app, id);
    expired.expires = 1;
    let alert = delivery(&app, &route, &expired);
    assert!(
        app.open_notification(alert["target"].as_str().unwrap())
            .is_err()
    );
    assert!(
        app.notification_delivered_read_receipts(&route, std::slice::from_ref(&alert))
            .await
            .unwrap()
            .is_empty()
    );
    let pin = app.pins[0].clone();
    app.operate(
        json!({"op":"message_action","space":pin.space,"stream":pin.stream,
        "created_at":"2026-10-02T12:00:00Z", "action":{"type":"delete","target":id}}),
    )
    .await
    .unwrap();
    assert_eq!(
        app.notification_delivered_read_receipts(&route, std::slice::from_ref(&alert))
            .await
            .unwrap(),
        vec![json!({"scope":alert["scope"],"event":alert["event"]})]
    );
    expired.record = Some(RecordId::from_bytes([93; 32]));
    let unknown = delivery(&app, &route, &expired);
    assert!(
        app.notification_delivered_read_receipts(&route, &[unknown])
            .await
            .unwrap()
            .is_empty()
    );
    app.close().await.unwrap();
}

#[tokio::test]
async fn delivered_signed_expired_message_is_cleared_without_marking_it_read() {
    let tmp = tempfile::tempdir().unwrap();
    let app = crate::app::performance::profile(tmp.path().join("profile")).await;
    let clock = now().unwrap().as_millis() as u64 - 7_200_000;
    let mut message = crate::app::performance::message(&app, 0, clock)
        .chat()
        .unwrap();
    message.payload.expires_at_ms = Some(clock + 3_600_000);
    let authority = &app.authorities.0[0];
    let record = authority
        .prepare_chat(message, app.session.signing_key())
        .unwrap();
    let recipients = record
        .chat()
        .unwrap()
        .recipient_credentials
        .iter()
        .map(|id| authority.credential(*id).unwrap().clone())
        .collect::<Vec<_>>();
    app.store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                record.id(),
                crypto::seal_chat(&record, &recipients).unwrap(),
                RecordMetadata::new(
                    "chat.message",
                    Some(authority.space()),
                    Some(authority.stream()),
                    authority.head_id(),
                )
                .unwrap(),
                vec![],
                LocalTime::from_millis(clock).unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let route = route();
    // Even a still-valid target cannot revive an already expired signed message.
    let alert = delivery(&app, &route, &target(&app, record.id()));
    assert!(
        app.read
            .seen
            .get(&authority.stream().to_string())
            .is_none_or(Vec::is_empty)
    );
    assert_eq!(
        app.notification_delivered_read_receipts(&route, std::slice::from_ref(&alert))
            .await
            .unwrap(),
        vec![json!({"scope":alert["scope"],"event":alert["event"]})]
    );
    assert!(
        app.read
            .seen
            .get(&authority.stream().to_string())
            .is_none_or(Vec::is_empty)
    );
    app.close().await.unwrap();
}

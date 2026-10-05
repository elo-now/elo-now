use super::*;
use serde_json::json;
fn target() -> Target {
    Target {
        identity: "owner".into(),
        space: "space".into(),
        stream: "stream".into(),
        space_context: Some("context".into()),
        record: Some("record".into()),
        call_id: None,
        category: Category::Message,
    }
}
fn view() -> Value {
    json!({"identity":"owner","credential":"device","active_space":"context","streams":[{"space":"space","stream":"stream","space_context":"context","muted":false,"forked":false,"members":[{"identity_id":"owner","capabilities":["READ"],"credential_ids":["device"]}],"rows":[{"id":"record","unread":true,"body":{"kind":"chat.message","issuer_identity":"other"}}]}]})
}
#[test]
fn target_requires_current_identity_membership_scope_and_unforked_history() {
    let target = target();
    assert!(valid_target(&view(), &target, true));
    for (path, value) in [
        ("/identity", json!("other")),
        ("/credential", json!("revoked-device")),
        ("/streams/0/members/0/capabilities", json!([])),
        ("/streams/0/forked", json!(true)),
        ("/streams/0/space_context", json!("other")),
        ("/streams/0/rows/0/body/kind", json!("deleted")),
    ] {
        let mut view = view();
        *view.pointer_mut(path).unwrap() = value;
        assert!(!valid_target(&view, &target, true), "{path}");
        assert!(!valid_target(&view, &target, false), "{path}");
    }
    assert!(!valid_target(&Value::Null, &target, false));
}
#[test]
fn arrival_suppresses_muted_read_and_own_messages_but_click_can_open_read_message() {
    for (path, value) in [
        ("/streams/0/muted", json!(true)),
        ("/streams/0/rows/0/unread", json!(false)),
        ("/streams/0/rows/0/body/issuer_identity", json!("owner")),
    ] {
        let mut view = view();
        *view.pointer_mut(path).unwrap() = value;
        assert!(!valid_target(&view, &target(), true));
        assert!(valid_target(&view, &target(), false));
    }
}
#[test]
fn session_target_only_opens_verified_conversation_and_cannot_smuggle_record() {
    let mut target = target();
    target.category = Category::Session;
    assert!(!valid_target(&view(), &target, true));
    target.record = None;
    target.call_id = Some("00".repeat(16));
    assert!(valid_target(&view(), &target, true));
    let mut v = view();
    v["streams"][0]["members"] = json!([]);
    assert!(!valid_target(&v, &target, false));
}
#[test]
fn registry_requires_opt_in_deduplicates_bursts_bounds_memory_and_expires_clicks() {
    let now = Instant::now();
    let mut state = Registry::default();
    assert!(state.insert(target(), now).is_none());
    state.enabled = true;
    let id = state.insert(target(), now).unwrap();
    assert_eq!(id.len(), 32);
    assert!(!id.contains("record"));
    assert!(
        state
            .insert(target(), now + Duration::from_secs(5))
            .is_none()
    );
    let mut other = target();
    other.record = Some("other".into());
    assert!(
        state
            .insert(other.clone(), now + Duration::from_secs(1))
            .is_none()
    );
    assert!(state.insert(other, now + Duration::from_secs(3)).is_some());
    state.opened = Some(id);
    state.prune(now + TTL + Duration::from_secs(4));
    assert!(state.entries.is_empty());
    assert!(state.opened.is_none());
    for n in 0..LIMIT {
        let mut target = target();
        target.record = Some(n.to_string());
        assert!(
            state
                .insert(target, now + TTL + Duration::from_secs(10 + n as u64 * 3))
                .is_some()
        );
    }
    assert!(
        state
            .insert(target(), now + TTL + Duration::from_secs(500))
            .is_some()
    );
}
#[test]
fn sound_and_target_wire_reject_arbitrary_paths_and_private_payloads() {
    assert!(serde_json::from_value::<Sound>(json!("/tmp/audio.wav")).is_err());
    assert_eq!(
        serde_json::from_value::<Sound>(json!("elo-male")).unwrap(),
        Sound::EloMale
    );
    let mut target = serde_json::to_value(target()).unwrap();
    target["body"] = json!("private text");
    assert!(serde_json::from_value::<Target>(target).is_err());
}

#[test]
fn session_and_message_bursts_use_separate_lanes() {
    let now = Instant::now();
    let mut state = Registry {
        enabled: true,
        ..Default::default()
    };
    assert!(state.insert(target(), now).is_some());
    let mut session = target();
    session.category = Category::Session;
    session.record = None;
    session.call_id = Some("01".repeat(16));
    assert!(state.insert(session.clone(), now).is_some());
    session.call_id = Some("02".repeat(16));
    assert!(
        state
            .insert(session.clone(), now + Duration::from_secs(1))
            .is_none()
    );
    assert!(
        state
            .insert(session, now + Duration::from_secs(3))
            .is_some()
    );
}
#[test]
fn capacity_evicts_oldest_but_preserves_pending_click_and_new_arrivals() {
    let now = Instant::now();
    let mut state = Registry {
        enabled: true,
        ..Default::default()
    };
    let first = state.insert(target(), now).unwrap();
    state.opened = Some(first.clone());
    let mut second = None;
    for n in 1..=LIMIT {
        let mut target = target();
        target.record = Some(n.to_string());
        let id = state
            .insert(target, now + Duration::from_secs(n as u64 * 3))
            .unwrap();
        if n == 1 {
            second = Some(id);
        }
    }
    assert_eq!(state.entries.len(), LIMIT);
    assert!(state.entries.contains_key(&first));
    assert!(!state.entries.contains_key(&second.unwrap()));
}
#[test]
fn history_page_never_crosses_identity_or_space_compartments() {
    let mut view = view();
    let original = view["streams"][0].clone();
    let mut other = original.clone();
    other["space_context"] = json!("other-context");
    other["rows"] = json!([]);
    view["all_streams"] = json!([other.clone(), original]);
    let page = json!({"history":{"identity":"owner","space":"space","stream":"stream",
        "space_context":"context","rows":[{"id":"new"}]}});
    for field in ["identity", "space", "stream", "space_context"] {
        let mut page = page.clone();
        page["history"][field] = json!("wrong");
        let before = view.clone();
        assert!(!apply_history_page(&mut view, &target(), &page));
        assert_eq!(before, view);
    }
    assert!(apply_history_page(&mut view, &target(), &page));
    assert_eq!(view["all_streams"][0], other);
    assert_eq!(view["all_streams"][1]["rows"], page["history"]["rows"]);
}

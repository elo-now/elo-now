use super::*;

fn entry(clock: u64, device: u8, active: bool) -> Entry {
    Entry {
        field: Field::Unread,
        space: SpaceId::from_bytes([11; 32]),
        stream: StreamId::from_bytes([12; 16]),
        record: RecordId::from_bytes([13; 32]),
        stamp: Stamp {
            clock,
            device: RecordId::from_bytes([device; 32]),
        },
        active,
    }
}

#[test]
fn concurrent_offline_read_markers_converge_under_duplicates_and_reordering() {
    let values = [
        entry(100, 1, false),
        entry(101, 1, true),
        entry(101, 2, false),
    ];
    let mut left = State::default();
    let mut right = State::default();
    for value in values.iter().chain(values.iter()) {
        left.merge(value.clone());
    }
    for value in values.iter().rev().chain(values.iter().rev()) {
        right.merge(value.clone());
    }
    assert_eq!(left.values, right.values);
    assert!(!left.values.values().next().unwrap().active);
    // Explicit unread after learning the remote read supersedes it.
    let key = values[0].key();
    left.local(
        Field::Unread,
        values[0].space,
        values[0].stream,
        values[0].record,
        true,
        values[0].stamp.device,
        101,
    )
    .unwrap();
    assert!(left.values[&key].stamp.clock > 101);
    right.merge(left.values[&key].clone());
    assert_eq!(left.values, right.values);
    assert!(right.values[&key].active);
}

#[test]
fn repeated_mark_read_does_not_generate_an_event_or_overwrite_manual_unread() {
    let value = entry(100, 1, false);
    let mut state = State::default();
    assert!(
        state
            .local(
                value.field,
                value.space,
                value.stream,
                value.record,
                false,
                value.stamp.device,
                100
            )
            .unwrap()
            .is_some()
    );
    state.pending.clear();
    assert!(
        state
            .local(
                value.field,
                value.space,
                value.stream,
                value.record,
                false,
                value.stamp.device,
                500
            )
            .unwrap()
            .is_none()
    );
    assert!(state.pending.is_empty());
    assert!(state.merge(entry(102, 2, true)));
    assert!(!state.merge(entry(100, 1, false)));
    assert!(state.values[&value.key()].active);
}

#[tokio::test]
async fn read_and_thread_pending_changes_survive_restart_in_encrypted_profile_state() {
    let temp = tempfile::tempdir().unwrap();
    let password = "synthetic private settings password";
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(
            temp.path().join("profile"),
            password.into(),
            "General",
            "Alex",
        )
        .await
        .unwrap();
    let pin = app.pins[0].clone();
    let id = RecordId::from_bytes([91; 32]);
    app.set_private_read_markers(pin.space, pin.stream, vec![id], false)
        .unwrap();
    app.set_private_thread_value(Field::Follow, pin.space, pin.stream, id, false)
        .unwrap();
    let path = app.directory.clone();
    let on_disk = vault::read_private(&path.join("read-state.age")).unwrap();
    assert!(
        !on_disk
            .windows(64)
            .any(|bytes| bytes == id.to_string().as_bytes())
    );
    let expected = app.read.private_settings.as_ref().unwrap().values.clone();
    app.close().await.unwrap();
    let app = ClientApp::open(path, password.into(), true).await.unwrap();
    let state = app.read.private_settings.as_ref().unwrap();
    assert_eq!(state.values, expected);
    assert_eq!(state.pending.len(), 2);
    assert!(app.read.seen[&pin.stream.to_string()].contains(&id.to_string()));
    assert_eq!(app.private_thread_follows(pin.stream, false), vec![id]);
    app.close().await.unwrap();
}

#[test]
fn fresh_changes_precede_a_large_checkpoint_and_coalesce_duplicates() {
    let mut state = State::default();
    for n in 0..200u8 {
        let mut old = entry(100, 1, false);
        old.record = RecordId::from_bytes([n; 32]);
        let key = old.key();
        state.merge(old);
        state.checkpoint.insert(key);
    }
    let fresh = RecordId::from_bytes([199; 32]);
    state
        .local(
            Field::Unread,
            SpaceId::from_bytes([11; 32]),
            StreamId::from_bytes([12; 16]),
            fresh,
            true,
            RecordId::from_bytes([1; 32]),
            200,
        )
        .unwrap();
    let keys = state.batch_keys();
    assert_eq!(keys.len(), MAX_BATCH);
    assert_eq!(state.values[&keys[0]].record, fresh);
    assert!(state.values[&keys[0]].active);
    assert_eq!(keys.iter().collect::<BTreeSet<_>>().len(), MAX_BATCH);
    let saved = serde_json::to_vec(&state).unwrap();
    let restored: State = serde_json::from_slice(&saved).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored.batch_keys(), keys);
    assert_eq!(restored.checkpoint.len(), 200);
}

#[tokio::test]
async fn legacy_markers_bootstrap_below_fresh_explicit_actions() {
    let temp = tempfile::tempdir().unwrap();
    let app = crate::app::performance::profile(temp.path().join("profile")).await;
    let pin = &app.pins[0];
    let seen = RecordId::from_bytes([91; 32]);
    let conflicting = RecordId::from_bytes([92; 32]);
    let unread = RecordId::from_bytes([93; 32]);
    let mut read = ReadState {
        v: 1,
        ..Default::default()
    };
    read.seen.insert(
        pin.stream.to_string(),
        vec![seen.to_string(), conflicting.to_string()],
    );
    read.unread
        .insert(pin.stream.to_string(), vec![unread.to_string()]);
    let mut state = State::default();
    let current = Entry {
        field: Field::Unread,
        space: pin.space,
        stream: pin.stream,
        record: conflicting,
        active: true,
        stamp: Stamp {
            clock: 100,
            device: app.session.credential().id(),
        },
    };
    state.merge(current.clone());
    read.private_settings = Some(state);
    assert!(app.bootstrap_private_settings(&mut read).unwrap());
    let state = read.private_settings.as_ref().unwrap();
    assert_eq!(state.values[&current.key()], current);
    assert_eq!(
        state
            .values
            .values()
            .find(|entry| entry.record == seen)
            .unwrap()
            .stamp
            .clock,
        0
    );
    let inherited_unread = state
        .values
        .values()
        .find(|entry| entry.record == unread)
        .unwrap();
    assert!(inherited_unread.active);
    assert_eq!(inherited_unread.stamp.clock, 1);
    assert_eq!(state.checkpoint.len(), 2);
    assert!(state.pending.is_empty());
    assert!(!app.bootstrap_private_settings(&mut read).unwrap());
    let mut peer = State::default();
    peer.merge(current.clone());
    for value in read
        .private_settings
        .as_ref()
        .unwrap()
        .values
        .values()
        .rev()
    {
        peer.merge(value.clone());
    }
    assert_eq!(peer.values[&current.key()], current);
    app.close().await.unwrap();
}

#[test]
fn compact_read_state_round_trips_one_hundred_thousand_markers_without_storage_regression() {
    let mut read = ReadState {
        v: 1,
        ..Default::default()
    };
    let stream = StreamId::from_bytes([12; 16]);
    let mut state = State {
        baseline_initialized: true,
        ..Default::default()
    };
    for index in 0..100_000u32 {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        let mut value = entry(u64::from(index) + 1, 1, index % 3 == 0);
        value.record = RecordId::from_bytes(bytes);
        let key = value.key();
        let records = if value.active {
            &mut read.unread
        } else {
            &mut read.seen
        };
        records
            .entry(stream.to_string())
            .or_default()
            .push(value.record.to_string());
        state.merge(value);
        if index % 2 == 0 {
            state.pending.insert(key.clone());
        }
        state.checkpoint.insert(key);
    }
    let before = serde_json::to_vec(&read).unwrap();
    read.private_settings = Some(state);
    read.validate().unwrap();
    let bytes = serde_json::to_vec(&read).unwrap();
    assert!(
        bytes.len() < before.len(),
        "compact {} must not exceed legacy {}",
        bytes.len(),
        before.len()
    );
    assert!(bytes.len() < MAX_READ_STATE);
    let reopened: ReadState = serde_json::from_slice(&bytes).unwrap();
    reopened.validate().unwrap();
    assert_eq!(reopened.seen, read.seen);
    assert_eq!(reopened.unread, read.unread);
    let expected = read.private_settings.as_ref().unwrap();
    let restored = reopened.private_settings.as_ref().unwrap();
    assert_eq!(restored.values, expected.values);
    assert_eq!(restored.pending, expected.pending);
    assert_eq!(restored.checkpoint, expected.checkpoint);
    assert_eq!(restored.clock, expected.clock);
    assert!(restored.baseline_initialized);
}

#[test]
fn compact_private_state_accepts_legacy_markers_and_first_local_state_format() {
    let value = entry(100, 1, true);
    let original_key = format!(
        "{:?}:{}:{}:{}",
        value.field, value.space, value.stream, value.record
    );
    let mut values = BTreeMap::new();
    values.insert(original_key.clone(), value.clone());
    let old = json!({"v":1,"clock":100,"values":values,"pending":[original_key],
        "cursor":12,"last_checkpoint_ms":50});
    let state: State = serde_json::from_value(old).unwrap();
    assert_eq!(state.values[&value.key()], value);
    assert!(state.pending.contains(&value.key()));
    assert_eq!(state.cursor(), 12);
    let old_read = json!({"v":1,"seen":{value.stream.to_string():[value.record]},"unread":{}});
    let read: ReadState = serde_json::from_value(old_read).unwrap();
    assert!(read.private_settings.is_none());
    assert_eq!(
        read.seen[&value.stream.to_string()],
        vec![value.record.to_string()]
    );
}

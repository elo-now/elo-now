mod support;
use elo_call_service::{
    engine::Engine,
    registry::{CallError, Event, Limits, Registry, Scope},
};
use elo_core::{
    calls::{CallKind, InitialMedia, MediaState, Operation},
    ids::SpaceId,
};
use support::{AUDIENCE, Fixture, NOW};

fn start(kind: CallKind) -> Operation {
    Operation::Start {
        kind,
        initial_media: InitialMedia::Audio,
    }
}

#[test]
fn concurrent_start_intents_share_one_call_and_identity_uses_only_one_device() {
    for direct in [true, false] {
        let f = Fixture::new(direct);
        let mut registry = Registry::new(Limits::default()).unwrap();
        let kind = if direct {
            CallKind::Direct
        } else {
            CallKind::Group
        };
        let command = f.command(&f.owner, start(kind), NOW);
        registry.apply(&f.authority, &command, NOW).unwrap();
        let scope = Scope::from(&command);
        let id = registry.presence(&scope).unwrap().call_id.clone();
        let peer_start = f.command(&f.peer, start(kind), NOW);
        registry.apply(&f.authority, &peer_start, NOW).unwrap();
        assert_eq!(registry.presence(&scope).unwrap().call_id, id);
        assert_eq!(registry.presence(&scope).unwrap().participants.len(), 2);
        assert!(!registry.presence(&scope).unwrap().ringing);
        registry.apply(&f.authority, &peer_start, NOW + 1).unwrap();
        let other_device = f.command(&f.peer_device, Operation::Join { call_id: id }, NOW);
        assert!(matches!(
            registry.apply(&f.authority, &other_device, NOW),
            Err(CallError::AlreadyJoined)
        ));
    }
}

#[test]
fn media_leases_participant_limits_and_timeouts_are_enforced() {
    let f = Fixture::new(false);
    let mut registry = Registry::new(Limits {
        participants: 2,
        cameras: 1,
        screens: 1,
        ..Limits::default()
    })
    .unwrap();
    let command = f.command(&f.owner, start(CallKind::Group), NOW);
    let scope = Scope::from(&command);
    registry.apply(&f.authority, &command, NOW).unwrap();
    let id = registry.presence(&scope).unwrap().call_id.clone();
    registry
        .apply(
            &f.authority,
            &f.command(
                &f.peer,
                Operation::Join {
                    call_id: id.clone(),
                },
                NOW,
            ),
            NOW,
        )
        .unwrap();
    assert!(matches!(
        registry.apply(
            &f.authority,
            &f.command(
                &f.third,
                Operation::Join {
                    call_id: id.clone()
                },
                NOW
            ),
            NOW
        ),
        Err(CallError::Full)
    ));
    let media = Operation::Media {
        call_id: id.clone(),
        state: MediaState {
            audio_muted: false,
            video_published: true,
            screen_published: true,
        },
    };
    registry
        .apply(&f.authority, &f.command(&f.owner, media.clone(), NOW), NOW)
        .unwrap();
    assert!(matches!(
        registry.apply(&f.authority, &f.command(&f.peer, media.clone(), NOW), NOW),
        Err(CallError::MediaLimit)
    ));
    registry
        .apply(
            &f.authority,
            &f.command(
                &f.owner,
                Operation::Leave {
                    call_id: id.clone(),
                },
                NOW + 1,
            ),
            NOW + 1,
        )
        .unwrap();
    registry
        .apply(&f.authority, &f.command(&f.peer, media, NOW + 1), NOW + 1)
        .unwrap();
    assert_eq!(registry.presence(&scope).unwrap().key_epoch, 3);
    registry.tick(NOW + 31);
    assert!(registry.presence(&scope).unwrap().participants.is_empty());
    registry.tick(NOW + 46);
    assert!(registry.presence(&scope).is_none());
}

#[test]
fn direct_decline_leave_and_ring_timeout_end_the_call() {
    for action in [0, 1, 2] {
        let f = Fixture::new(true);
        let mut registry = Registry::new(Limits::default()).unwrap();
        let command = f.command(&f.owner, start(CallKind::Direct), NOW);
        registry.apply(&f.authority, &command, NOW).unwrap();
        let scope = Scope::from(&command);
        let id = registry.presence(&scope).unwrap().call_id.clone();
        let events = match action {
            0 => registry
                .apply(
                    &f.authority,
                    &f.command(&f.peer, Operation::Decline { call_id: id }, NOW),
                    NOW,
                )
                .unwrap(),
            1 => registry
                .apply(
                    &f.authority,
                    &f.command(&f.owner, Operation::Leave { call_id: id }, NOW),
                    NOW,
                )
                .unwrap(),
            _ => registry.tick(NOW + 45),
        };
        assert!(matches!(events[0], Event::Ended { .. }));
        assert!(registry.presence(&scope).is_none());
    }
}

#[test]
fn last_explicit_group_leave_ends_the_call_immediately() {
    let f = Fixture::new(false);
    let mut registry = Registry::new(Limits::default()).unwrap();
    let command = f.command(&f.owner, start(CallKind::Group), NOW);
    registry.apply(&f.authority, &command, NOW).unwrap();
    let scope = Scope::from(&command);
    let id = registry.presence(&scope).unwrap().call_id.clone();

    let events = registry
        .apply(
            &f.authority,
            &f.command(&f.owner, Operation::Leave { call_id: id }, NOW + 1),
            NOW + 1,
        )
        .unwrap();

    assert!(matches!(events.as_slice(), [Event::Ended { .. }]));
    assert!(registry.presence(&scope).is_none());
}

#[test]
fn hosted_space_contexts_do_not_share_presence_or_signals() {
    let f = Fixture::new(false);
    let mut registry = Registry::new(Limits::default()).unwrap();
    let command = f.command(&f.owner, start(CallKind::Group), NOW);
    registry.apply(&f.authority, &command, NOW).unwrap();
    let scope = Scope::from(&command);
    let id = registry.presence(&scope).unwrap().call_id.clone();
    let mut other = f.command(&f.peer, Operation::Subscribe, NOW);
    other.hosting_space_id = SpaceId::from_bytes([8; 32]);
    assert!(
        registry
            .apply(&f.authority, &other, NOW)
            .unwrap()
            .is_empty()
    );
    other.operation = Operation::Join {
        call_id: id.clone(),
    };
    assert!(matches!(
        registry.apply(&f.authority, &other, NOW),
        Err(CallError::Ended)
    ));
    let outsider = f.command(
        &f.third,
        Operation::Signal {
            call_id: id,
            to: f.owner.credential().id(),
            ciphertext: "aGVsbG8=".into(),
        },
        NOW,
    );
    assert!(matches!(
        registry.apply(&f.authority, &outsider, NOW),
        Err(CallError::Unauthorized)
    ));
    assert!(registry.revoke_space(other.hosting_space_id).is_empty());
    assert_eq!(registry.revoke_space(command.hosting_space_id).len(), 1);
}

#[test]
fn one_device_cannot_join_two_calls_but_separate_devices_can_use_separate_calls() {
    let f = Fixture::new(false);
    let mut registry = Registry::new(Limits::default()).unwrap();
    let first = f.command(&f.peer, start(CallKind::Group), NOW);
    registry.apply(&f.authority, &first, NOW).unwrap();
    let mut second = f.command(&f.peer, start(CallKind::Group), NOW);
    second.hosting_space_id = SpaceId::from_bytes([8; 32]);
    assert!(matches!(
        registry.apply(&f.authority, &second, NOW),
        Err(CallError::AlreadyJoined)
    ));
    second.credential_id = f.peer_device.credential().id();
    registry.apply(&f.authority, &second, NOW).unwrap();
    assert_ne!(
        registry.presence(&Scope::from(&first)).unwrap().call_id,
        registry.presence(&Scope::from(&second)).unwrap().call_id
    );
}

#[test]
fn accepted_command_replay_is_idempotent_even_after_restart() {
    let f = Fixture::new(false);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.sqlite");
    let request = f.request(&f.owner, start(CallKind::Group), NOW, true);
    let encoded = serde_json::to_string(&request).unwrap();
    let mut engine = Engine::open(&path, AUDIENCE.into(), Limits::default()).unwrap();
    let prepared = engine.prepare(request, None, NOW).unwrap();
    let applied = engine.execute(prepared, NOW).unwrap();
    assert!(!applied.duplicate);
    let call = applied.call.unwrap().call_id;
    let replay = engine
        .prepare(serde_json::from_str(&encoded).unwrap(), None, NOW + 1)
        .unwrap();
    let applied = engine.execute(replay, NOW + 1).unwrap();
    assert!(applied.duplicate);
    assert!(applied.events.is_empty());
    assert_eq!(applied.call.unwrap().call_id, call);
    drop(engine);
    let mut engine = Engine::open(&path, AUDIENCE.into(), Limits::default()).unwrap();
    let replay = engine
        .prepare(serde_json::from_str(&encoded).unwrap(), None, NOW + 2)
        .unwrap();
    let applied = engine.execute(replay, NOW + 2).unwrap();
    assert!(applied.duplicate);
    assert!(applied.call.is_none());
}

#[test]
fn stale_membership_cannot_return_after_restart_and_a_new_head_ends_the_call() {
    let mut f = Fixture::new(false);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.sqlite");
    let mut engine = Engine::open(&path, AUDIENCE.into(), Limits::default()).unwrap();
    let prepared = engine
        .prepare(
            f.request(&f.owner, start(CallKind::Group), NOW, true),
            None,
            NOW,
        )
        .unwrap();
    let scope = engine.execute(prepared, NOW).unwrap().scope;
    let old = f.request(&f.peer, Operation::Subscribe, NOW, true);
    let stale = f.request(&f.owner, Operation::Subscribe, NOW, true);
    f.remove_peer();
    let prepared = engine
        .prepare(
            f.request(&f.owner, Operation::Subscribe, NOW, true),
            None,
            NOW,
        )
        .unwrap();
    engine.execute(prepared, NOW).unwrap();
    assert!(matches!(engine.take_events()[0], Event::Ended { .. }));
    assert!(!engine.authorized(scope, f.peer.credential().id()));
    drop(engine);
    let mut engine = Engine::open(&path, AUDIENCE.into(), Limits::default()).unwrap();
    let prepared = engine.prepare(old, None, NOW).unwrap();
    assert!(matches!(
        engine.execute(prepared, NOW),
        Err(CallError::Unauthorized)
    ));
    let prepared = engine.prepare(stale, None, NOW).unwrap();
    assert!(matches!(
        engine.execute(prepared, NOW),
        Err(CallError::Unauthorized)
    ));
    assert!(!engine.authorized(scope, f.peer.credential().id()));
}

#[test]
fn socket_cannot_change_device_and_signatures_or_audience_cannot_be_substituted() {
    let f = Fixture::new(false);
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        &directory.path().join("state.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
    )
    .unwrap();
    assert!(
        engine
            .prepare(
                f.request(&f.peer, Operation::Subscribe, NOW, true),
                Some(f.owner.credential().id()),
                NOW
            )
            .is_err()
    );
    assert!(
        engine
            .prepare(
                f.request(&f.owner, Operation::Subscribe, NOW, true),
                None,
                NOW + 60
            )
            .is_err()
    );
    let mut request = f.request(&f.owner, Operation::Subscribe, NOW, true);
    request.command.replace_range(100..101, "!");
    assert!(engine.prepare(request, None, NOW).is_err());
}

#[test]
fn configuration_forks_remain_blocked_after_service_restart() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use elo_call_service::engine::Request;
    use elo_core::{calls, record::random_hex};
    let mut f = Fixture::new(false);
    let mut branch = f
        .authority
        .call_proof()
        .unwrap()
        .verify(f.authority.space(), f.authority.stream())
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.sqlite");
    let mut engine = Engine::open(&path, AUDIENCE.into(), Limits::default()).unwrap();
    f.remove_peer();
    let request = f.request(&f.owner, start(CallKind::Group), NOW, true);
    let prepared = engine.prepare(request, None, NOW).unwrap();
    let scope = engine.execute(prepared, NOW).unwrap().scope;
    let mut configuration = branch.head().unwrap().clone();
    configuration.sequence += 1;
    configuration.previous_config_id = branch.head_id();
    configuration.nonce = random_hex::<16>().unwrap();
    configuration.action.operation = "replace".into();
    branch
        .apply_config(configuration.sign(f.owner.signing_key()).unwrap())
        .unwrap();
    let request = Request {
        command: STANDARD.encode(
            calls::sign_command(
                &branch,
                &f.owner,
                branch.space(),
                AUDIENCE,
                Operation::Subscribe,
                NOW,
            )
            .unwrap()
            .bytes(),
        ),
        proof: Some(branch.call_proof().unwrap()),
    };
    let prepared = engine.prepare(request, None, NOW).unwrap();
    assert!(matches!(
        engine.execute(prepared, NOW),
        Err(CallError::Unauthorized)
    ));
    assert!(engine.registry.presence(&scope).is_none());
    assert!(!engine.authorized(scope, f.owner.credential().id()));
    assert_eq!(engine.take_events().len(), 1);
    drop(engine);
    let engine = Engine::open(&path, AUDIENCE.into(), Limits::default()).unwrap();
    assert!(
        engine
            .prepare(
                f.request(&f.owner, Operation::Subscribe, NOW, true),
                None,
                NOW
            )
            .is_err()
    );
}

#[test]
fn only_one_process_owns_state_and_idle_proof_eviction_keeps_the_durable_fence() {
    let f = Fixture::new(false);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.sqlite");
    let mut engine = Engine::open(&path, AUDIENCE.into(), Limits::default()).unwrap();
    assert!(Engine::open(&path, AUDIENCE.into(), Limits::default()).is_err());
    let request = f.request(&f.owner, Operation::Subscribe, NOW, true);
    let prepared = engine.prepare(request, None, NOW).unwrap();
    let scope = engine.execute(prepared, NOW).unwrap().scope;
    assert!(engine.authorized(scope, f.owner.credential().id()));
    engine.maintain(NOW + 121).unwrap();
    assert!(!engine.authorized(scope, f.owner.credential().id()));
    assert!(
        engine
            .prepare(
                f.request(&f.owner, Operation::Subscribe, NOW + 121, false),
                None,
                NOW + 121
            )
            .is_err()
    );
    let prepared = engine
        .prepare(
            f.request(&f.owner, Operation::Subscribe, NOW + 121, true),
            None,
            NOW + 121,
        )
        .unwrap();
    engine.execute(prepared, NOW + 121).unwrap();
    assert!(engine.authorized(scope, f.owner.credential().id()));
    let db = rusqlite::Connection::open(&path).unwrap();
    let columns = db
        .prepare("SELECT name FROM pragma_table_info('fences')")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(columns, ["scope", "head", "sequence", "blocked"]);
}

#[test]
fn an_idle_live_subscription_retains_authority_until_the_subscriber_disconnects() {
    let f = Fixture::new(true);
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(
        &root.path().join("calls.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
    )
    .unwrap();
    let prepared = engine
        .prepare(
            f.request(&f.peer, Operation::Subscribe, NOW, true),
            None,
            NOW,
        )
        .unwrap();
    let scope = engine.execute(prepared, NOW).unwrap().scope;
    // A connected listener makes no call commands while waiting for a caller.
    // The server still checks its admission every five seconds.
    for elapsed in (5..=180).step_by(5) {
        assert!(
            engine
                .authorized_head(scope, f.peer.credential().id(), NOW + elapsed)
                .is_some()
        );
        engine.maintain(NOW + elapsed).unwrap();
        assert!(
            engine.authorized(scope, f.peer.credential().id()),
            "live subscription expired at {elapsed}s"
        );
    }
    let prepared = engine
        .prepare(
            f.request(&f.owner, start(CallKind::Direct), NOW + 181, true),
            None,
            NOW + 181,
        )
        .unwrap();
    let started = engine.execute(prepared, NOW + 181).unwrap();
    assert!(started.call.unwrap().ringing);
    assert!(engine.authorized(scope, f.peer.credential().id()));
    engine.maintain(NOW + 400).unwrap();
    assert!(!engine.authorized(scope, f.peer.credential().id()));
}

#[test]
fn background_decline_only_ends_a_current_ring_addressed_to_the_recipient() {
    let f = Fixture::new(true);
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(
        &root.path().join("calls.sqlite"),
        AUDIENCE.into(),
        Limits::default(),
    )
    .unwrap();
    let prepared = engine
        .prepare(
            f.request(&f.owner, start(CallKind::Direct), NOW, true),
            None,
            NOW,
        )
        .unwrap();
    let call = engine.execute(prepared, NOW).unwrap().call.unwrap();
    assert_eq!(engine.wake_recipients(&call).len(), 2);
    assert!(
        engine
            .background_decline(&call.call_id, f.owner.identity_id())
            .is_empty()
    );
    assert!(
        engine
            .background_decline(&call.call_id, f.third.identity_id())
            .is_empty()
    );
    assert_eq!(
        engine
            .background_decline(&call.call_id, f.peer.identity_id())
            .len(),
        1
    );
    assert!(engine.registry.presence(&call.scope).is_none());
    assert!(
        engine
            .background_decline(&call.call_id, f.peer.identity_id())
            .is_empty()
    );
}

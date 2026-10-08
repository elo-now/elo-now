use super::*;
use elo_core::record::SignedRecord;
use elo_core::{
    authority::{Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig},
    ids::{IdentityId, RecordId, SpaceId, StreamId},
    record::{encode_hex, random_hex},
    vault::Session,
};
const AUDIENCE: &str = "https://calls.example.test/calls/v1";

struct Fixture {
    owner: Session,
    peer: Session,
    authority: Authority,
    now: u64,
}
impl Fixture {
    fn new() -> Self {
        Self::with_witness(None)
    }
    fn with_witness(witness: Option<elo_core::authority::WitnessPin>) -> Self {
        let version = if witness.is_some() { 4 } else { 1 };
        let (owner, recovery) = Session::create().unwrap();
        let peer = Session::create().unwrap().0;
        let root = recovery.recover_root(owner.identity_id()).unwrap();
        let genesis = SpaceGenesis {
            witness,
            v: version,
            kind: "space.genesis".into(),
            nonce: random_hex::<16>().unwrap(),
            issuer_identity: owner.identity_id(),
            owners: vec![Owner {
                identity_id: owner.identity_id(),
                root_public_key: encode_hex(root.verifying_key().as_bytes()),
            }],
            controller_credential_id: owner.credential().id(),
        };
        let key = if version == 4 {
            owner.signing_key()
        } else {
            &root
        };
        let signed = SignedRecord::sign(&serde_json::to_vec(&genesis).unwrap(), key).unwrap();
        let mut authority = Authority::new(
            signed.bytes(),
            signed.id().to_string().parse().unwrap(),
            &root.verifying_key(),
            owner.credential().clone(),
            StreamId::from_bytes([7; 16]),
        )
        .unwrap();
        authority.add_credential(peer.credential().clone());
        let mut members = [&owner, &peer]
            .into_iter()
            .map(|person| Member {
                identity_id: person.identity_id(),
                identity_type: "HUMAN".into(),
                root_public_key: person.credential().record().body()["root_public_key"]
                    .as_str()
                    .unwrap()
                    .into(),
                capabilities: if person.identity_id() == owner.identity_id() {
                    vec![
                        Capability::Read,
                        Capability::Post,
                        Capability::ShareHistory,
                        Capability::Manage,
                    ]
                } else {
                    vec![Capability::Read, Capability::Post]
                },
                credential_ids: vec![person.credential().id()],
                external: false,
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.identity_id);
        let config = StreamConfig {
            witness_evidence: None,
            v: version,
            kind: "stream.config".into(),
            nonce: random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: owner.credential().id(),
            members,
            owner_credential_ids: vec![owner.credential().id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: owner.identity_id(),
                request_record_id: None,
            },
            chat_kind: Some(if version == 4 {
                ChatKind::Chat
            } else {
                ChatKind::Direct
            }),
            recovery: None,
        };
        authority
            .apply_config(config.sign(owner.signing_key()).unwrap())
            .unwrap();
        Self {
            owner,
            peer,
            authority,
            now: time(),
        }
    }
    fn binding(&self) -> CallDelegateBinding {
        let delegate = CallDelegate::create(
            &self.authority,
            &self.peer,
            self.authority.space(),
            AUDIENCE,
            self.now,
        )
        .unwrap();
        CallDelegateBinding {
            identity: self.peer.identity_id(),
            credential: self.peer.credential().id(),
            space_context: self.authority.space().to_string(),
            name: "Synthetic direct chat".into(),
            audience: AUDIENCE.into(),
            push_endpoint: Some("https://wake.example.test/".into()),
            hosting_space_id: self.authority.space(),
            scope: calls::CallScope {
                space_id: self.authority.space(),
                stream_id: self.authority.stream(),
            },
            config_id: self.authority.head_id().unwrap(),
            witness: self.authority.witness_pin().cloned(),
            proof: self
                .authority
                .call_proof_signed(self.peer.signing_key())
                .unwrap(),
            delegate: delegate.export().unwrap().to_vec(),
        }
    }
    fn target(&self) -> calls::ring::RingTarget {
        calls::ring::RingTarget {
            v: 1,
            hosting_space_id: self.authority.space(),
            scope: calls::CallScope {
                space_id: self.authority.space(),
                stream_id: self.authority.stream(),
            },
            recipient: self.peer.identity_id(),
            call_id: "11".repeat(16),
            invitation_id: "22".repeat(16),
            expires: self.now + 45,
        }
    }
    fn call(&self, target: &calls::ring::RingTarget) -> Value {
        json!({"call_id":target.call_id,"scope":{"hosting_space_id":self.authority.space(),"conversation":target.scope},"kind":"direct","phase":"ringing","ready":true,"key_epoch":1,"config_id":self.authority.head_id(),"started_by":self.owner.identity_id(),"invitations":{self.peer.identity_id().to_string():{"invitation_id":target.invitation_id,"invited_by":self.owner.identity_id(),"expires_at":target.expires}},"participants":{self.owner.identity_id().to_string():{"identity_id":self.owner.identity_id(),"credential_id":self.owner.credential().id(),"ready":true,"media":{"audio_muted":false,"video_published":false,"screen_published":false}}}})
    }
}

#[test]
fn protected_delegate_binding_rejects_expiry_and_swapped_identity_credential_scope_head_or_audience()
 {
    let fixture = Fixture::new();
    let binding = serde_json::to_value(fixture.binding()).unwrap();
    assert!(
        Prepared::load(
            serde_json::from_value(binding.clone()).unwrap(),
            fixture.now
        )
        .is_ok()
    );
    assert!(
        Prepared::load(
            serde_json::from_value(binding.clone()).unwrap(),
            fixture.now + calls::delegation::MAX_DELEGATION_TTL
        )
        .is_err()
    );
    for (field, value) in [
        ("identity", json!(fixture.owner.identity_id())),
        ("credential", json!(fixture.owner.credential().id())),
        ("config_id", json!(RecordId::from_bytes([88; 32]))),
        ("audience", json!("https://other.example.test/calls/v1")),
        ("hosting_space_id", json!(SpaceId::from_bytes([66; 32]))),
        (
            "scope",
            json!({"space_id":fixture.authority.space(),"stream_id":StreamId::from_bytes([99;16])}),
        ),
    ] {
        let mut modified = binding.clone();
        modified[field] = value;
        assert!(
            Prepared::load(serde_json::from_value(modified).unwrap(), fixture.now).is_err(),
            "accepted changed {field}"
        );
    }
    let mut modified = binding;
    modified["delegate"] = json!([1, 2, 3]);
    assert!(Prepared::load(serde_json::from_value(modified).unwrap(), fixture.now).is_err());
}

#[test]
fn incoming_live_state_rejects_unknown_members_wrong_kind_scope_and_swapped_delegations() {
    let fixture = Fixture::new();
    let prepared = Prepared::load(fixture.binding(), fixture.now).unwrap();
    let target = fixture.target();
    let call = fixture.call(&target);
    assert!(prepared.validate(&call, &target, true).is_ok());
    for (field, value) in [
        ("call_id", json!("33".repeat(16))),
        ("config_id", json!(RecordId::from_bytes([55; 32]))),
        ("kind", json!("group")),
        (
            "scope",
            json!({"hosting_space_id":fixture.authority.space(),"conversation":{"space_id":fixture.authority.space(),"stream_id":StreamId::from_bytes([88;16])}}),
        ),
    ] {
        let mut modified = call.clone();
        modified[field] = value;
        assert!(
            prepared.validate(&modified, &target, true).is_err(),
            "accepted changed {field}"
        );
    }
    let mut modified = call.clone();
    modified["participants"][fixture.owner.identity_id().to_string()]["credential_id"] =
        json!(RecordId::from_bytes([99; 32]));
    assert!(prepared.validate(&modified, &target, true).is_err());
    let peer_delegate = CallDelegate::create(
        &fixture.authority,
        &fixture.peer,
        fixture.authority.space(),
        AUDIENCE,
        fixture.now,
    )
    .unwrap();
    let mut modified = call.clone();
    modified["participants"][fixture.owner.identity_id().to_string()]["delegation"] =
        json!(STANDARD.encode(peer_delegate.certificate().bytes()));
    assert!(
        prepared.validate(&modified, &target, true).is_err(),
        "a peer certificate cannot replace the caller's certificate"
    );
    let mut modified = call;
    modified["invitations"][fixture.peer.identity_id().to_string()]["invitation_id"] =
        json!("44".repeat(16));
    assert!(prepared.validate(&modified, &target, true).is_err());
}

#[test]
fn incoming_target_is_bound_to_the_recipient_and_complete_hosting_scope() {
    let fixture = Fixture::new();
    let prepared = Prepared::load(fixture.binding(), fixture.now).unwrap();
    let target = fixture.target();
    let call = fixture.call(&target);
    for field in ["recipient", "hosting", "space", "stream"] {
        let mut modified = target.clone();
        match field {
            "recipient" => modified.recipient = IdentityId::from_bytes([88; 32]),
            "hosting" => modified.hosting_space_id = SpaceId::from_bytes([88; 32]),
            "space" => modified.scope.space_id = SpaceId::from_bytes([88; 32]),
            "stream" => modified.scope.stream_id = StreamId::from_bytes([88; 16]),
            _ => unreachable!(),
        }
        assert!(
            prepared.validate(&call, &modified, true).is_err(),
            "accepted mismatched target {field}"
        );
    }
}

#[test]
fn native_delegate_signs_only_call_commands_and_keeps_parent_credential_admission() {
    let fixture = Fixture::new();
    let prepared = Prepared::load(fixture.binding(), fixture.now).unwrap();
    assert!(
        prepared
            .signed(
                Operation::Start {
                    kind: calls::CallKind::Direct,
                    initial_media: calls::InitialMedia::Audio
                },
                fixture.now
            )
            .is_err()
    );
    let request = prepared.signed(Operation::Subscribe, fixture.now).unwrap();
    let signed = SignedRecord::parse(
        &STANDARD
            .decode(request["command"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let cert =
        calls::delegation::decode_certificate(request["delegation"].as_str().unwrap()).unwrap();
    let command = calls::delegation::verify_command(
        &fixture.authority,
        &signed,
        &cert,
        AUDIENCE,
        fixture.now,
    )
    .unwrap();
    assert_eq!(command.credential_id, fixture.peer.credential().id());
    assert!(calls::verify_command(&fixture.authority, &signed, AUDIENCE, fixture.now).is_err());
}

#[test]
fn cold_action_lookup_requires_the_saved_route_and_exact_encrypted_target() {
    let fixture = Fixture::new();
    let route = elo_core::app::push::Route {
        endpoint: "https://wake.example.test/".into(),
        id: "55".repeat(16),
        notify_key: "66".repeat(32),
        scope_key: "77".repeat(32),
        since: fixture.now,
    };
    let target = fixture.target();
    let encoded = calls::ring::seal(&route.scope_key, &route.id, &target, fixture.now).unwrap();
    let enrollment = serde_json::to_value(Enrollment {
        bindings: vec![fixture.binding()],
        routes: vec![route.clone().into()],
        ..Enrollment::default()
    })
    .unwrap();
    let event = json!({"action":"decline","registration":route.id,"target":encoded,
        "callId":target.call_id,"invitationId":target.invitation_id,"expires":target.expires});
    let lookup = |saved: Value, event: &Value, now: u64| {
        super::transport::lookup(serde_json::from_value(saved).unwrap(), event, now)
    };
    let (prepared, restored) = lookup(enrollment.clone(), &event, fixture.now).unwrap();
    assert_eq!(restored.invitation_id, target.invitation_id);
    assert_eq!(prepared.binding.audience, AUDIENCE);
    assert_eq!(
        super::transport::socket_url(&prepared).unwrap(),
        "wss://calls.example.test/calls/v1/connect"
    );
    for (field, value) in [
        ("registration", json!("88".repeat(16))),
        ("callId", json!("88".repeat(16))),
        ("invitationId", json!("88".repeat(16))),
        ("expires", json!(target.expires + 1)),
        ("target", json!("A".repeat(encoded.len()))),
    ] {
        let mut changed = event.clone();
        changed[field] = value;
        assert!(
            lookup(enrollment.clone(), &changed, fixture.now).is_err(),
            "accepted changed {field}"
        );
    }
    assert!(lookup(enrollment.clone(), &event, target.expires).is_err());
    for (field, value) in [
        ("endpoint", json!("https://other-wake.example.test/")),
        ("endpoint", json!("http://wake.example.test/")),
        ("endpoint", json!("https://wake.example.test/other")),
        ("scope_key", json!("88".repeat(32))),
    ] {
        let mut changed = enrollment.clone();
        changed["routes"][0][field] = value;
        assert!(lookup(changed, &event, fixture.now).is_err());
    }
    let mut changed = enrollment;
    changed["bindings"][0]["push_endpoint"] = Value::Null;
    assert!(lookup(changed, &event, fixture.now).is_err());
}

#[tokio::test]
async fn cold_decline_rejects_other_actions_and_unknown_routes_before_network_access() {
    assert!(!super::transport::decline(Enrollment::default(), json!({"action":"answer"})).await);
    assert!(!super::transport::decline(Enrollment::default(), json!({"action":"decline"})).await);
}

#[test]
fn native_ui_ownership_uses_only_live_locally_verified_exact_identity_hints() {
    let fixture = Fixture::new();
    let route = elo_core::app::push::Route {
        endpoint: "https://wake.example.test/".into(),
        id: "55".repeat(16),
        notify_key: "66".repeat(32),
        scope_key: "77".repeat(32),
        since: fixture.now,
    };
    let target = fixture.target();
    let encoded = calls::ring::seal(&route.scope_key, &route.id, &target, fixture.now).unwrap();
    let bytes = serde_json::to_vec(&Enrollment {
        bindings: vec![fixture.binding()],
        routes: vec![route.clone().into()],
        ..Enrollment::default()
    })
    .unwrap();
    let hint = json!({"registration":route.id,"target":encoded,"callId":target.call_id,
        "invitationId":target.invitation_id,"expires":target.expires});
    let identity = fixture.peer.identity_id().to_string();
    let read =
        |snapshot: Value, who: &str, now| presentation::verified_hints(&bytes, &snapshot, who, now);
    assert_eq!(
        read(json!({"presentationHints":[hint]}), &identity, fixture.now),
        vec![json!({"call_id":target.call_id,"invitation_id":target.invitation_id})]
    );
    assert!(
        read(
            json!({"presentationHints":[hint]}),
            &fixture.owner.identity_id().to_string(),
            fixture.now
        )
        .is_empty()
    );
    // A queued incoming event is not evidence that native UI is still showing.
    assert!(
        read(
            json!({"presentationHints":[],"pending":[hint]}),
            &identity,
            fixture.now
        )
        .is_empty()
    );
    assert!(
        read(
            json!({"presentationHints":[hint]}),
            &identity,
            target.expires
        )
        .is_empty()
    );
    for field in ["callId", "invitationId", "registration", "target"] {
        let mut swapped = hint.clone();
        swapped[field] = "99".repeat(16).into();
        assert!(
            read(
                json!({"presentationHints":[swapped]}),
                &identity,
                fixture.now
            )
            .is_empty(),
            "{field}"
        );
    }
    let mut fence = presentation::Fence::default();
    let mut ended = hint.clone();
    ended["action"] = "decline".into();
    fence.observe(&ended, fixture.now);
    let dismissed = fence.dismissed(fixture.now);
    assert_eq!(
        read(
            json!({"presentationHints":dismissed}),
            &identity,
            fixture.now
        )
        .len(),
        1
    );
    assert!(
        read(
            json!({"presentationHints":dismissed}),
            &fixture.owner.identity_id().to_string(),
            fixture.now
        )
        .is_empty()
    );
    assert!(fence.dismissed(target.expires).is_empty());
}

#[test]
fn native_terminal_fence_blocks_delayed_admission_but_allows_the_explicit_decline() {
    let mut fence = presentation::Fence::default();
    let now = 1_000;
    let mut event = json!({"callId":"11".repeat(16),"invitationId":"22".repeat(16),"expires":now+45,"action":"incoming"});
    let incoming = fence.observe(&event, now).unwrap();
    assert!(fence.ringing(&incoming, now));
    event["action"] = "answer".into();
    let answer = fence.observe(&event, now + 1).unwrap();
    assert!(!fence.ringing(&incoming, now + 1));
    assert!(fence.permits(&answer, now + 1));
    event["action"] = "decline".into();
    let decline = fence.observe(&event, now + 2).unwrap();
    assert!(!fence.permits(&incoming, now + 2));
    assert!(!fence.permits(&answer, now + 2));
    assert!(fence.current(&decline, now + 2));
    event["action"] = "incoming".into();
    let delayed = fence.observe(&event, now + 3).unwrap();
    assert!(!fence.permits(&delayed, now + 3));
    event["invitationId"] = "33".repeat(16).into();
    let other = fence.observe(&event, now + 3).unwrap();
    assert!(fence.permits(&other, now + 3));
    assert!(!fence.current(&decline, now + 45));
}

#[test]
fn native_logout_fences_inflight_prepare_status_and_stale_enrollment() {
    let mut fence = presentation::Fence::default();
    let event = json!({"callId":"11".repeat(16),"invitationId":"22".repeat(16),"expires":1045,"action":"incoming"});
    let old = fence.observe(&event, 1000).unwrap();
    let old_epoch = fence.epoch();
    let old_snapshot = fence.snapshot();
    fence.suspend();
    assert!(!fence.permits(&old, 1000));
    assert_ne!(fence.snapshot(), old_snapshot);
    fence.resume(old_epoch);
    assert!(fence.snapshot().is_none());
    fence.resume(fence.epoch());
    assert!(fence.snapshot().is_some());
    assert!(!fence.permits(&old, 1000));
    let fresh = fence.observe(&event, 1000).unwrap();
    assert!(fence.permits(&fresh, 1000));
}

#[test]
fn native_failure_releases_ui_ownership_but_user_dismissal_is_stable_on_event_replay() {
    let now = 1_000;
    let base = json!({"callId":"11".repeat(16),"invitationId":"22".repeat(16),
        "registration":"33".repeat(16),"target":"x".repeat(100),"expires":now+45});
    for (action, reason) in [
        ("ended", None),
        ("decline", Some("unavailable")),
        ("decline", Some("busy")),
        ("end", Some("disabled")),
        ("end", Some("process_restarted")),
    ] {
        let mut fence = presentation::Fence::default();
        let mut event = base.clone();
        event["action"] = action.into();
        event["reason"] = reason.into();
        let ticket = fence.observe(&event, now).unwrap();
        assert!(!fence.permits(&ticket, now));
        assert!(fence.dismissed(now).is_empty(), "{action}: {reason:?}");
    }
    for (action, reason) in [
        ("decline", None),
        ("decline", Some("declined")),
        ("end", None),
        ("end", Some("local")),
    ] {
        let mut fence = presentation::Fence::default();
        let mut event = base.clone();
        event["action"] = action.into();
        event["reason"] = reason.into();
        fence.observe(&event, now);
        let snapshot = fence.snapshot();
        let dismissed = fence.dismissed(now);
        assert_eq!(dismissed.len(), 1);
        fence.observe(&event, now + 1);
        assert_eq!(fence.snapshot(), snapshot);
        assert_eq!(fence.dismissed(now + 1), dismissed);
        // The subsequent native teardown does not undo an explicit rejection.
        event["action"] = "ended".into();
        fence.observe(&event, now + 2);
        assert_eq!(fence.snapshot(), snapshot);
        assert_eq!(fence.dismissed(now + 2), dismissed);
        assert!(fence.dismissed(now + 45).is_empty());
    }
}

#[test]
fn protected_routes_keep_only_receive_capability_and_discard_legacy_send_keys() {
    let old = json!({"endpoint":"https://wake.example.test/","id":"55".repeat(16),
        "scope_key":"77".repeat(32),"notify_key":"66".repeat(32),"since":123});
    let received: RingRoute = serde_json::from_value(old.clone()).unwrap();
    let saved = serde_json::to_value(&received).unwrap();
    assert_eq!(saved.as_object().unwrap().len(), 3);
    assert_eq!(saved["scope_key"], old["scope_key"]);
    assert!(saved.get("notify_key").is_none());
    assert!(saved.get("since").is_none());
    let current: RingRoute = serde_json::from_value(saved.clone()).unwrap();
    assert_eq!(serde_json::to_value(&current).unwrap(), saved);
    let mut unknown = old;
    unknown["private_key"] = json!("must not be silently accepted");
    assert!(serde_json::from_value::<RingRoute>(unknown).is_err());
}

#[test]
fn uncertain_leave_survives_restart_and_blocks_only_its_call_and_credential_until_expiry() {
    let now = 10_000;
    let credential = RecordId::from_bytes([3; 32]);
    let mut saved = Enrollment::default();
    saved
        .begin_leave(
            PendingLeave {
                call_id: "11".repeat(16),
                credential,
                request_id: "22".repeat(16),
                until: now + calls::COMMAND_TTL,
            },
            now,
        )
        .unwrap();
    let restored: Enrollment =
        serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
    assert!(restored.leave_pending(&"11".repeat(16), credential, now + 8));
    assert!(!restored.leave_pending(&"33".repeat(16), credential, now + 8));
    assert!(!restored.leave_pending(&"11".repeat(16), RecordId::from_bytes([4; 32]), now + 8));
    assert!(!restored.leave_pending(&"11".repeat(16), credential, now + calls::COMMAND_TTL));
    let legacy: Enrollment = serde_json::from_value(json!({"bindings":[],"routes":[]})).unwrap();
    assert!(legacy.pending_leaves.is_empty());
}

#[test]
fn leave_fence_requires_exact_ack_and_does_not_replace_an_uncertain_command() {
    let credential = RecordId::from_bytes([3; 32]);
    let mut saved = Enrollment::default();
    let leave = |request: &str| PendingLeave {
        call_id: "11".repeat(16),
        credential,
        request_id: request.into(),
        until: 160,
    };
    saved.begin_leave(leave("first"), 100).unwrap();
    assert!(saved.begin_leave(leave("second"), 100).is_err());
    saved.acknowledge_leave("second");
    assert!(saved.leave_pending(&"11".repeat(16), credential, 101));
    saved.acknowledge_leave("first");
    assert!(!saved.leave_pending(&"11".repeat(16), credential, 101));
}

#[test]
fn leave_fences_are_bounded_without_evicting_live_guards_and_prune_passively() {
    let credential = RecordId::from_bytes([3; 32]);
    let mut saved = Enrollment::default();
    let leave = |index: u64, until: u64| PendingLeave {
        call_id: format!("{index:032x}"),
        credential,
        request_id: format!("{index:032x}"),
        until,
    };
    for index in 0..32 {
        saved.begin_leave(leave(index, 160), 100).unwrap();
    }
    assert!(saved.begin_leave(leave(32, 160), 100).is_err());
    assert_eq!(saved.pending_leaves.len(), 32);
    assert!(saved.leave_pending(&format!("{:032x}", 0), credential, 159));
    assert!(saved.begin_leave(leave(33, 221), 160).is_err());
    saved.begin_leave(leave(33, 220), 160).unwrap();
    assert_eq!(saved.pending_leaves.len(), 1);
}

#[test]
fn protected_general_binding_requires_its_separately_pinned_witness() {
    let pin = elo_core::authority::WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
        key_generation: 1,
    };
    let f = Fixture::with_witness(Some(pin));
    let encoded = serde_json::to_vec(&f.binding()).unwrap();
    let restored = serde_json::from_slice(&encoded).unwrap();
    assert!(Prepared::load(restored, f.now).is_ok());
    let mut missing = f.binding();
    missing.witness = None;
    assert!(Prepared::load(missing, f.now).is_err());
    let mut changed = f.binding();
    changed.witness.as_mut().unwrap().key_generation += 1;
    assert!(Prepared::load(changed, f.now).is_err());
}

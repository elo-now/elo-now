use super::*;

const NOW: u64 = 1_800_000_000_000;

struct Fixture {
    owner: Session,
    companion: Session,
    peer: Session,
    outsider: Session,
    authority: Authority,
}

impl Fixture {
    fn new() -> Self {
        let (owner, recovery) = Session::create().unwrap();
        let companion = owner.linked_companion().unwrap();
        let peer = Session::create().unwrap().0;
        let outsider = Session::create().unwrap().0;
        let root = recovery.recover_root(owner.identity_id()).unwrap();
        let genesis = SpaceGenesis {
            v: 1,
            kind: "space.genesis".into(),
            nonce: record::random_hex::<16>().unwrap(),
            issuer_identity: owner.identity_id(),
            owners: vec![Owner {
                identity_id: owner.identity_id(),
                root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            }],
            controller_credential_id: owner.credential().id(),
        };
        let signed = SignedRecord::sign(&serde_json::to_vec(&genesis).unwrap(), &root).unwrap();
        let mut authority = Authority::new(
            signed.bytes(),
            signed.id().to_string().parse().unwrap(),
            &root.verifying_key(),
            owner.credential().clone(),
            StreamId::from_bytes([7; 16]),
        )
        .unwrap();
        for session in [&companion, &peer, &outsider] {
            authority.add_credential(session.credential().clone());
        }
        let mut members = [&owner, &peer]
            .into_iter()
            .map(|session| Member {
                identity_id: session.identity_id(),
                identity_type: "HUMAN".into(),
                root_public_key: session.credential().record().body()["root_public_key"]
                    .as_str()
                    .unwrap()
                    .into(),
                capabilities: if session.identity_id() == owner.identity_id() {
                    vec![
                        Capability::Read,
                        Capability::Post,
                        Capability::ShareHistory,
                        Capability::Manage,
                    ]
                } else {
                    vec![Capability::Read, Capability::Post]
                },
                credential_ids: if session.identity_id() == owner.identity_id() {
                    let mut ids = vec![owner.credential().id(), companion.credential().id()];
                    ids.sort();
                    ids
                } else {
                    vec![peer.credential().id()]
                },
                external: false,
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.identity_id);
        let mut owners = vec![owner.credential().id(), companion.credential().id()];
        owners.sort();
        authority
            .apply_config(
                StreamConfig {
                    v: 1,
                    kind: "stream.config".into(),
                    nonce: record::random_hex::<16>().unwrap(),
                    space_id: authority.space(),
                    stream_id: authority.stream(),
                    sequence: 1,
                    previous_config_id: None,
                    controller_credential_id: owner.credential().id(),
                    members,
                    owner_credential_ids: owners,
                    action: ConfigAction {
                        operation: "create".into(),
                        actor_identity: owner.identity_id(),
                        request_record_id: None,
                    },
                    chat_kind: Some(ChatKind::Chat),
                    recovery: None,
                }
                .sign(owner.signing_key())
                .unwrap(),
            )
            .unwrap();
        Self {
            owner,
            companion,
            peer,
            outsider,
            authority,
        }
    }

    fn scope(&self) -> Scope {
        Scope {
            space_context: self.authority.space().to_string(),
            space: self.authority.space(),
            stream: self.authority.stream(),
        }
    }

    fn snapshot(&self, session: &Session) -> Snapshot {
        let scope = self.scope();
        Snapshot {
            identity: session.identity_id(),
            active_space: Some(scope.space_context.clone()),
            contexts: BTreeMap::from([(
                scope.space_context,
                Context {
                    identity: session.identity_id(),
                    credential: session.credential().id(),
                    signing: session.signing_key().clone(),
                    signer: crate::sync::access::Signer::new(session),
                    age: session.age_identity().clone(),
                    authorities: Authorities(vec![self.authority.clone()].into()),
                    blocked: blocking::Blocked::default(),
                    membership: membership::MembershipSnapshot::default(),
                    peers: vec![],
                    allow_loopback: false,
                },
            )]),
        }
    }

    fn body(&self, session: &Session, payload: Payload) -> SignedEvent {
        SignedEvent {
            v: 1,
            kind: "chat.ephemeral".into(),
            context: self.scope().space_context,
            space: self.authority.space(),
            stream: self.authority.stream(),
            config: self.authority.head_id().unwrap(),
            issuer_identity: session.identity_id(),
            issuer_credential: session.credential().id(),
            created_at_ms: NOW,
            expires_at_ms: NOW + payload.lifetime(),
            nonce: record::random_hex::<16>().unwrap(),
            payload,
        }
    }

    fn update(&mut self, change: impl FnOnce(&mut StreamConfig)) {
        let mut config = self.authority.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = self.authority.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.action.operation = "replace".into();
        change(&mut config);
        self.authority
            .apply_config(config.sign(self.owner.signing_key()).unwrap())
            .unwrap();
    }
}

// Bypass the sender API to test correctly signed, encrypted hostile payloads at
// the receive boundary. Merely testing seal() would miss receiver regressions.
fn signed_envelope(body: &SignedEvent, signer: &Session, recipient: &Session) -> String {
    let signed =
        SignedRecord::sign(&serde_json::to_vec(body).unwrap(), signer.signing_key()).unwrap();
    STANDARD.encode(crypto::seal_record(&signed, &[recipient.credential().recipient()]).unwrap())
}

fn upload(status: UploadStatus) -> Payload {
    Payload::Upload {
        attachment_id: AttachmentId::from_bytes([9; 16]),
        name: "Synthetic private photo.jpg".into(),
        size: 1024,
        status,
        record: (status == UploadStatus::Ready).then_some(RecordId::from_bytes([10; 32])),
    }
}

#[test]
fn signed_envelopes_reach_authorized_companions_but_not_known_outsiders() {
    let f = Fixture::new();
    let scope = f.scope();
    assert_ne!(f.owner.credential().id(), f.companion.credential().id());
    assert_eq!(f.owner.identity_id(), f.companion.identity_id());
    assert!(f.companion.credential().authorizing_device().is_some());
    for sender in [&f.owner, &f.companion, &f.peer] {
        let payload = upload(UploadStatus::Ready);
        let (audience, envelope) = f
            .snapshot(sender)
            .seal(&scope, payload.clone(), NOW)
            .unwrap();
        assert_eq!(
            audience.len(),
            2,
            "delivery fanout uses identities, not devices"
        );
        assert!(audience.contains(&f.owner.identity_id()));
        assert!(audience.contains(&f.peer.identity_id()));
        assert!(!envelope.contains("Synthetic private photo"));
        let ciphertext = STANDARD.decode(&envelope).unwrap();
        assert!(crypto::open_record(&ciphertext, f.outsider.age_identity()).is_err());
        assert!(
            f.snapshot(&f.outsider)
                .open(
                    &scope.space_context,
                    &envelope,
                    sender.identity_id(),
                    sender.credential().id(),
                    NOW
                )
                .is_err()
        );
        for reader in [&f.owner, &f.companion, &f.peer] {
            let snapshot = f.snapshot(reader);
            let event = snapshot
                .open(
                    &scope.space_context,
                    &envelope,
                    sender.identity_id(),
                    sender.credential().id(),
                    NOW,
                )
                .unwrap();
            assert_eq!(event.payload, payload);
            assert_eq!(event.scope(), scope);
            assert!(snapshot.allows_event(&event));
            assert!(
                serde_json::to_value(&event)
                    .unwrap()
                    .get("config")
                    .is_none()
            );
        }
    }
}

#[test]
fn receiver_binds_outer_sender_scope_current_config_and_signature() {
    let f = Fixture::new();
    let scope = f.scope();
    let snapshot = f.snapshot(&f.peer);
    let (_, envelope) = f
        .snapshot(&f.owner)
        .seal(&scope, Payload::Typing { active: true }, NOW)
        .unwrap();
    for (sender, credential) in [
        (f.peer.identity_id(), f.owner.credential().id()),
        (f.owner.identity_id(), f.companion.credential().id()),
        (f.outsider.identity_id(), f.outsider.credential().id()),
    ] {
        assert!(
            snapshot
                .open(&scope.space_context, &envelope, sender, credential, NOW)
                .is_err()
        );
    }
    assert!(
        snapshot
            .open(
                "another-space",
                &envelope,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_err()
    );
    let body = f.body(&f.owner, Payload::Typing { active: true });
    let mut variants = Vec::new();
    let mut wrong = body.clone();
    wrong.context = "another-space".into();
    variants.push(wrong);
    let mut wrong = body.clone();
    wrong.space = SpaceId::from_bytes([20; 32]);
    variants.push(wrong);
    let mut wrong = body.clone();
    wrong.stream = StreamId::from_bytes([21; 16]);
    variants.push(wrong);
    let mut wrong = body.clone();
    wrong.config = RecordId::from_bytes([22; 32]);
    variants.push(wrong);
    let mut wrong = body.clone();
    wrong.nonce = "not-a-nonce".into();
    variants.push(wrong);
    let mut wrong = body.clone();
    wrong.kind = "chat.message".into();
    variants.push(wrong);
    for wrong in variants {
        assert!(
            snapshot
                .open(
                    &scope.space_context,
                    &signed_envelope(&wrong, &f.owner, &f.peer),
                    f.owner.identity_id(),
                    f.owner.credential().id(),
                    NOW
                )
                .is_err()
        );
    }
    let forged_signature = signed_envelope(&body, &f.peer, &f.peer);
    assert!(
        snapshot
            .open(
                &scope.space_context,
                &forged_signature,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_err()
    );
}

#[test]
fn refreshed_snapshots_reject_retired_devices_and_remove_previously_opened_hints() {
    let mut f = Fixture::new();
    let scope = f.scope();
    let (_, envelope) = f
        .snapshot(&f.companion)
        .seal(&scope, Payload::Typing { active: true }, NOW)
        .unwrap();
    let before = f.snapshot(&f.peer);
    let event = before
        .open(
            &scope.space_context,
            &envelope,
            f.companion.identity_id(),
            f.companion.credential().id(),
            NOW,
        )
        .unwrap();
    let retired = f.companion.credential().id();
    f.update(|config| {
        for member in &mut config.members {
            member.credential_ids.retain(|id| *id != retired);
        }
        config.owner_credential_ids.retain(|id| *id != retired);
    });
    let refreshed = f.snapshot(&f.peer);
    assert!(!refreshed.allows_event(&event));
    assert!(
        refreshed
            .open(
                &scope.space_context,
                &envelope,
                f.companion.identity_id(),
                retired,
                NOW
            )
            .is_err()
    );
    assert!(!f.snapshot(&f.companion).permits(&scope));
    assert!(
        f.snapshot(&f.companion)
            .seal(&scope, Payload::Presence { active: true }, NOW)
            .is_err()
    );
    // A retired key can still sign, but referring to the fresh config cannot
    // restore its membership, even when the remaining identity may still post.
    let fresh_claim = f.body(&f.companion, Payload::Typing { active: true });
    assert!(
        refreshed
            .open(
                &scope.space_context,
                &signed_envelope(&fresh_claim, &f.companion, &f.peer),
                f.companion.identity_id(),
                retired,
                NOW
            )
            .is_err()
    );
    let (_, current) = f
        .snapshot(&f.owner)
        .seal(&scope, Payload::Presence { active: true }, NOW)
        .unwrap();
    assert!(
        refreshed
            .open(
                &scope.space_context,
                &current,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_ok()
    );
    let removed = f.peer.identity_id();
    f.update(|config| {
        config
            .members
            .retain(|member| member.identity_id != removed)
    });
    assert!(!f.snapshot(&f.peer).permits(&scope));
    assert!(!f.snapshot(&f.peer).allows_event(&event));
    assert!(
        f.snapshot(&f.peer)
            .open(
                &scope.space_context,
                &current,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_err()
    );
}

#[test]
fn conflicting_signed_configs_disable_live_hints_until_permissions_are_resolved() {
    let mut f = Fixture::new();
    let scope = f.scope();
    let (_, envelope) = f
        .snapshot(&f.owner)
        .seal(&scope, Payload::Typing { active: true }, NOW)
        .unwrap();
    let event = f
        .snapshot(&f.peer)
        .open(
            &scope.space_context,
            &envelope,
            f.owner.identity_id(),
            f.owner.credential().id(),
            NOW,
        )
        .unwrap();
    let mut conflicting = f.authority.head().unwrap().clone();
    conflicting.nonce = record::random_hex::<16>().unwrap();
    let signed = conflicting.sign(f.owner.signing_key()).unwrap();
    f.authority.apply_config(signed).unwrap();
    assert!(f.authority.is_forked());
    let snapshot = f.snapshot(&f.peer);
    assert!(!snapshot.permits(&scope));
    assert!(!snapshot.allows_event(&event));
    assert!(
        snapshot
            .open(
                &scope.space_context,
                &envelope,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_err()
    );
    assert!(
        f.snapshot(&f.owner)
            .seal(&scope, Payload::Typing { active: true }, NOW)
            .is_err()
    );
}

#[test]
fn receiver_rejects_expired_future_and_overlong_lifetimes() {
    let f = Fixture::new();
    let snapshot = f.snapshot(&f.peer);
    let body = f.body(&f.owner, Payload::Typing { active: true });
    for (created, expires) in [
        (NOW - 8_000, NOW),
        (NOW + 2_001, NOW + 10_001),
        (NOW, NOW),
        (NOW, NOW + 8_001),
        (NOW, record::MAX_INTEGER),
    ] {
        let mut wrong = body.clone();
        wrong.created_at_ms = created;
        wrong.expires_at_ms = expires;
        assert!(
            snapshot
                .open(
                    &f.scope().space_context,
                    &signed_envelope(&wrong, &f.owner, &f.peer),
                    f.owner.identity_id(),
                    f.owner.credential().id(),
                    NOW
                )
                .is_err()
        );
    }
    let mut tolerated = body;
    tolerated.created_at_ms = NOW + 2_000;
    tolerated.expires_at_ms = tolerated.created_at_ms + 8_000;
    assert!(
        snapshot
            .open(
                &f.scope().space_context,
                &signed_envelope(&tolerated, &f.owner, &f.peer),
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_ok()
    );
}

#[test]
fn both_boundaries_reject_unsafe_attachment_metadata_and_inconsistent_terminal_state() {
    let f = Fixture::new();
    let mut invalid = Vec::new();
    for name in [
        "".into(),
        ".".into(),
        "..".into(),
        "../private.jpg".into(),
        "folder\\private.jpg".into(),
        "line\nbreak.jpg".into(),
        "photo\u{202e}gpj.exe".into(),
        "hidden\u{200b}.jpg".into(),
        "x".repeat(256),
    ] {
        let mut payload = upload(UploadStatus::Uploading);
        if let Payload::Upload { name: value, .. } = &mut payload {
            *value = name;
        }
        invalid.push(payload);
    }
    let mut oversized = upload(UploadStatus::Uploading);
    if let Payload::Upload { size, .. } = &mut oversized {
        *size = crate::attachments::MAX_ATTACHMENT_FILE_SIZE + 1;
    }
    invalid.push(oversized);
    for status in [
        UploadStatus::Uploading,
        UploadStatus::Interrupted,
        UploadStatus::Cancelled,
        UploadStatus::Ready,
    ] {
        let mut payload = upload(status);
        if let Payload::Upload { record, .. } = &mut payload {
            *record = if status == UploadStatus::Ready {
                None
            } else {
                Some(RecordId::from_bytes([10; 32]))
            };
        }
        invalid.push(payload);
    }
    for payload in invalid {
        assert!(
            f.snapshot(&f.owner)
                .seal(&f.scope(), payload.clone(), NOW)
                .is_err()
        );
        let body = f.body(&f.owner, payload);
        assert!(
            f.snapshot(&f.peer)
                .open(
                    &f.scope().space_context,
                    &signed_envelope(&body, &f.owner, &f.peer),
                    f.owner.identity_id(),
                    f.owner.credential().id(),
                    NOW
                )
                .is_err()
        );
    }
}

#[test]
fn read_only_members_can_publish_presence_but_cannot_publish_typing_or_uploads() {
    let mut f = Fixture::new();
    let reader = f.peer.identity_id();
    f.update(|config| {
        config
            .members
            .iter_mut()
            .find(|member| member.identity_id == reader)
            .unwrap()
            .capabilities = vec![Capability::Read]
    });
    let snapshot = f.snapshot(&f.peer);
    assert!(
        snapshot
            .seal(&f.scope(), Payload::Presence { active: true }, NOW)
            .is_ok()
    );
    for payload in [
        Payload::Typing { active: true },
        upload(UploadStatus::Uploading),
    ] {
        assert!(snapshot.seal(&f.scope(), payload.clone(), NOW).is_err());
        let body = f.body(&f.peer, payload);
        assert!(
            f.snapshot(&f.owner)
                .open(
                    &f.scope().space_context,
                    &signed_envelope(&body, &f.peer, &f.owner),
                    f.peer.identity_id(),
                    f.peer.credential().id(),
                    NOW
                )
                .is_err()
        );
    }
}

fn blocked(session: &Session, identity: IdentityId) -> blocking::Blocked {
    let directory = tempfile::tempdir().unwrap();
    let entries = BTreeMap::from([(identity, "Synthetic blocked peer")]);
    let bytes = crypto::seal_bytes(
        &serde_json::to_vec(&entries).unwrap(),
        &[session.age_identity().to_public()],
        1024 * 1024,
    )
    .unwrap();
    vault::write_private(&directory.path().join("blocked.age"), &bytes, false).unwrap();
    blocking::Blocked::open(directory.path(), session.age_identity()).unwrap()
}

#[test]
fn blocking_excludes_encryption_recipients_and_discards_existing_received_hints() {
    let f = Fixture::new();
    let scope = f.scope();
    let mut sender = f.snapshot(&f.owner);
    sender
        .contexts
        .get_mut(&scope.space_context)
        .unwrap()
        .blocked = blocked(&f.owner, f.peer.identity_id());
    let (audience, envelope) = sender
        .seal(&scope, Payload::Presence { active: true }, NOW)
        .unwrap();
    assert_eq!(audience, vec![f.owner.identity_id()]);
    assert!(
        crypto::open_record(&STANDARD.decode(&envelope).unwrap(), f.peer.age_identity()).is_err()
    );
    assert!(
        f.snapshot(&f.companion)
            .open(
                &scope.space_context,
                &envelope,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_ok()
    );
    let (_, incoming) = f
        .snapshot(&f.peer)
        .seal(&scope, Payload::Typing { active: true }, NOW)
        .unwrap();
    let mut receiver = f.snapshot(&f.owner);
    let event = receiver
        .open(
            &scope.space_context,
            &incoming,
            f.peer.identity_id(),
            f.peer.credential().id(),
            NOW,
        )
        .unwrap();
    receiver
        .contexts
        .get_mut(&scope.space_context)
        .unwrap()
        .blocked = blocked(&f.owner, f.peer.identity_id());
    assert!(!receiver.allows_event(&event));
    assert!(
        receiver
            .open(
                &scope.space_context,
                &incoming,
                f.peer.identity_id(),
                f.peer.credential().id(),
                NOW
            )
            .is_err()
    );
}

#[test]
fn targets_use_canonical_urls_and_subscription_proofs_bind_every_routing_field() {
    use crate::sync::access::{RequestContext, verify};
    let f = Fixture::new();
    let scope = f.scope();
    let replica = SigningKey::from_bytes(&[81; 32]);
    let descriptor = PeerDescriptor {
        url: "https://replica.example.test/".into(),
        signing_public_key: record::encode_hex(replica.verifying_key().as_bytes()),
        mailbox_id: MailboxId::from_bytes([82; 32]),
        read_token: Some("synthetic-read-token".into()),
        write_token: Some("synthetic-write-token".into()),
    };
    let hosted = PeerDescriptor {
        url: format!(
            "https://host.example.test/spaces/{}/replica/",
            "83".repeat(32)
        ),
        ..descriptor.clone()
    };
    let mut snapshot = f.snapshot(&f.companion);
    snapshot
        .contexts
        .get_mut(&scope.space_context)
        .unwrap()
        .peers = vec![descriptor.clone(), hosted];
    let targets = snapshot.targets();
    assert_eq!(targets.len(), 2);
    assert_eq!(
        targets[0].url,
        format!("wss://replica.example.test{}", crate::realtime::PATH)
    );
    assert_eq!(
        targets[1].url,
        format!("wss://host.example.test{}", crate::realtime::HOST_PATH)
    );
    assert_eq!(targets[0].mailbox(), targets[1].mailbox());
    assert_ne!(
        targets[0].id, targets[1].id,
        "mailbox IDs are local to each Replica"
    );
    for target in &targets {
        let ClientFrame::Subscribe { request, proof } = target.subscribe().unwrap() else {
            panic!("expected subscription");
        };
        let base = reqwest::Url::parse(&target.descriptor.url).unwrap();
        let socket = reqwest::Url::parse(&target.url).unwrap();
        let origin = base.origin().ascii_serialization();
        let key = replica.verifying_key();
        let body = serde_json::to_vec(&request).unwrap();
        let context = RequestContext {
            origin: &origin,
            replica: &key,
            method: "SUBSCRIBE",
            path: socket.path(),
            body: &body,
            transfer: "",
            retention: "",
        };
        let actor = verify(&proof, &context).unwrap();
        assert_eq!(actor.identity, f.companion.identity_id());
        assert_eq!(actor.credential, f.companion.credential().id());
        assert!(actor.companion);
        assert_eq!(request.id, target.id);
        assert_eq!(request.replica, base.path());
        assert_eq!(request.mailbox, target.mailbox());
        assert!(
            verify(
                &proof,
                &RequestContext {
                    origin: "https://wrong.example.test",
                    ..context
                }
            )
            .is_err()
        );
        assert!(
            verify(
                &proof,
                &RequestContext {
                    path: "/wrong/realtime",
                    ..context
                }
            )
            .is_err()
        );
        let mut changed = request.clone();
        changed.mailbox = MailboxId::from_bytes([99; 32]);
        let changed_body = serde_json::to_vec(&changed).unwrap();
        assert!(
            verify(
                &proof,
                &RequestContext {
                    body: &changed_body,
                    ..context
                }
            )
            .is_err()
        );
        let mut wrong_scope = scope.clone();
        wrong_scope.space_context = "another-space".into();
        assert!(
            snapshot
                .publication(
                    target,
                    &wrong_scope,
                    Payload::Presence { active: true },
                    NOW
                )
                .is_err()
        );
        let ClientFrame::Publish { request } = snapshot
            .publication(target, &scope, Payload::Typing { active: true }, NOW)
            .unwrap()
        else {
            panic!("expected publication");
        };
        assert!(
            f.snapshot(&f.peer)
                .open(
                    &scope.space_context,
                    &request.envelope,
                    f.companion.identity_id(),
                    f.companion.credential().id(),
                    NOW
                )
                .is_ok()
        );
    }
    let previous = targets[0].signature();
    snapshot
        .contexts
        .get_mut(&scope.space_context)
        .unwrap()
        .peers[0]
        .read_token = Some("rotated-token".into());
    assert_ne!(snapshot.targets()[0].signature(), previous);
    assert_eq!(
        snapshot.targets()[0].id,
        targets[0].id,
        "token rotation preserves the subscription namespace"
    );
    for url in [
        "http://replica.example.test/",
        "https://user@replica.example.test/",
        "https://replica.example.test/?token=secret",
        "https://replica.example.test/#secret",
        "https://replica.example.test/arbitrary/",
    ] {
        snapshot
            .contexts
            .get_mut(&scope.space_context)
            .unwrap()
            .peers = vec![PeerDescriptor {
            url: url.into(),
            ..descriptor.clone()
        }];
        assert!(snapshot.targets().is_empty(), "rejected target {url}");
    }
    let context = snapshot.contexts.get_mut(&scope.space_context).unwrap();
    context.peers = vec![PeerDescriptor {
        url: "http://127.0.0.1:9999/".into(),
        ..descriptor
    }];
    assert!(snapshot.targets().is_empty());
    snapshot
        .contexts
        .get_mut(&scope.space_context)
        .unwrap()
        .allow_loopback = true;
    assert_eq!(
        snapshot.targets()[0].url,
        format!("ws://127.0.0.1:9999{}", crate::realtime::PATH)
    );
    snapshot
        .contexts
        .get_mut(&scope.space_context)
        .unwrap()
        .peers[0]
        .read_token = None;
    assert!(snapshot.targets().is_empty());
}

#[test]
fn subscription_ids_separate_replica_paths_pinned_keys_and_space_contexts() {
    let f = Fixture::new();
    let scope = f.scope();
    let replica = SigningKey::from_bytes(&[85; 32]);
    let rotated = SigningKey::from_bytes(&[86; 32]);
    let first = PeerDescriptor {
        url: format!(
            "https://host.example.test/spaces/{}/replica/",
            "87".repeat(32)
        ),
        signing_public_key: record::encode_hex(replica.verifying_key().as_bytes()),
        mailbox_id: MailboxId::from_bytes([88; 32]),
        read_token: Some("synthetic-read-token".into()),
        write_token: None,
    };
    let other_path = PeerDescriptor {
        url: format!(
            "https://host.example.test/spaces/{}/replica/",
            "89".repeat(32)
        ),
        ..first.clone()
    };
    let other_key = PeerDescriptor {
        signing_public_key: record::encode_hex(rotated.verifying_key().as_bytes()),
        ..first.clone()
    };
    let mut snapshot = f.snapshot(&f.owner);
    snapshot
        .contexts
        .get_mut(&scope.space_context)
        .unwrap()
        .peers = vec![first.clone(), other_path, other_key];
    let mut another = f
        .snapshot(&f.owner)
        .contexts
        .remove(&scope.space_context)
        .unwrap();
    another.peers = vec![first.clone()];
    snapshot.contexts.insert("another-space".into(), another);
    let targets = snapshot.targets();
    assert_eq!(targets.len(), 4);
    assert_eq!(
        targets
            .iter()
            .map(|target| &target.id)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        targets
            .iter()
            .map(|target| &target.url)
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "distinct replicas share one hosted websocket endpoint without collapsing subscriptions"
    );

    let context = snapshot.contexts.get_mut(&scope.space_context).unwrap();
    context.peers = vec![
        PeerDescriptor {
            url: "https://HOST.example.test:443".into(),
            ..first.clone()
        },
        PeerDescriptor {
            url: "https://host.example.test/".into(),
            ..first.clone()
        },
    ];
    snapshot.contexts.remove("another-space");
    let canonical = snapshot.targets();
    assert_eq!(canonical.len(), 2);
    assert_eq!(
        canonical[0].id, canonical[1].id,
        "equivalent URLs refer to the same Replica namespace"
    );
    for key in ["not-a-key".into(), "00".repeat(32)] {
        snapshot
            .contexts
            .get_mut(&scope.space_context)
            .unwrap()
            .peers = vec![PeerDescriptor {
            signing_public_key: key,
            ..first.clone()
        }];
        assert!(
            snapshot.targets().is_empty(),
            "invalid or weak pinned keys cannot become websocket targets"
        );
    }
}

type LiveTestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn live_send(socket: &mut LiveTestSocket, frame: ClientFrame) {
    use futures_util::SinkExt;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&frame).unwrap().into(),
        ))
        .await
        .unwrap();
}

async fn live_receive(socket: &mut LiveTestSocket) -> crate::realtime::ServerFrame {
    use futures_util::{SinkExt, StreamExt};
    loop {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match frame {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                return serde_json::from_str(&text).unwrap();
            }
            tokio_tungstenite::tungstenite::Message::Ping(payload) => {
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Pong(payload))
                    .await
                    .unwrap();
            }
            other => panic!("unexpected websocket frame: {other:?}"),
        }
    }
}

#[tokio::test]
async fn native_targets_interoperate_with_loopback_relay_and_durable_catchup() {
    use crate::{
        ids::ObjectId,
        realtime::ServerFrame,
        replica::{ReplicaStore, TransferHint},
    };
    let f = Fixture::new();
    let scope = f.scope();
    let temp = tempfile::tempdir().unwrap();
    let store = ReplicaStore::open(temp.path().join("replica"))
        .await
        .unwrap();
    let mailbox = store.create_mailbox(1024 * 1024).await.unwrap();
    store
        .set_space_members(
            mailbox.mailbox_id,
            vec![f.owner.identity_id(), f.peer.identity_id()],
        )
        .await
        .unwrap();
    store
        .set_admitted_devices(vec![
            f.owner.credential().id(),
            f.companion.credential().id(),
            f.peer.credential().id(),
        ])
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let descriptor = PeerDescriptor {
        url: origin.clone(),
        signing_public_key: record::encode_hex(store.key().as_bytes()),
        mailbox_id: mailbox.mailbox_id,
        read_token: Some(mailbox.read_token.clone()),
        write_token: Some(mailbox.write_token.clone()),
    };
    let router = crate::http::router(store.clone(), &origin);
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let snapshot = |session: &Session| {
        let mut snapshot = f.snapshot(session);
        let context = snapshot.contexts.get_mut(&scope.space_context).unwrap();
        context.peers = vec![descriptor.clone()];
        context.allow_loopback = true;
        snapshot
    };
    let owner = snapshot(&f.owner);
    let peer = snapshot(&f.peer);
    let companion = snapshot(&f.companion);
    let outsider = snapshot(&f.outsider);
    let owner_target = owner.targets().remove(0);
    let peer_target = peer.targets().remove(0);
    let companion_target = companion.targets().remove(0);
    let outsider_target = outsider.targets().remove(0);
    let (mut owner_socket, _) = tokio_tungstenite::connect_async(&owner_target.url)
        .await
        .unwrap();
    let (mut peer_socket, _) = tokio_tungstenite::connect_async(&peer_target.url)
        .await
        .unwrap();
    let (mut companion_socket, _) = tokio_tungstenite::connect_async(&companion_target.url)
        .await
        .unwrap();
    for (socket, target) in [
        (&mut owner_socket, &owner_target),
        (&mut peer_socket, &peer_target),
        (&mut companion_socket, &companion_target),
    ] {
        // This uses the exact native subscription builder, not a test proof.
        live_send(socket, target.subscribe().unwrap()).await;
        assert!(
            matches!(live_receive(socket).await, ServerFrame::Subscribed { id } if id == target.id)
        );
        assert!(
            matches!(live_receive(socket).await, ServerFrame::Changed { id } if id == target.id)
        );
    }
    let (mut outsider_socket, _) = tokio_tungstenite::connect_async(&outsider_target.url)
        .await
        .unwrap();
    live_send(&mut outsider_socket, outsider_target.subscribe().unwrap()).await;
    assert!(
        matches!(live_receive(&mut outsider_socket).await, ServerFrame::Error { code } if code == "unauthorized")
    );
    drop(outsider_socket);

    let time = now().unwrap().as_millis() as u64;
    let payload = upload(UploadStatus::Uploading);
    live_send(
        &mut owner_socket,
        owner
            .publication(&owner_target, &scope, payload.clone(), time)
            .unwrap(),
    )
    .await;
    for (socket, snapshot, target) in [
        (&mut owner_socket, &owner, &owner_target),
        (&mut peer_socket, &peer, &peer_target),
        (&mut companion_socket, &companion, &companion_target),
    ] {
        let ServerFrame::Ephemeral {
            id,
            envelope,
            identity,
            credential,
        } = live_receive(socket).await
        else {
            panic!("expected encrypted upload activity");
        };
        assert_eq!(id, target.id);
        assert_eq!(identity, f.owner.identity_id());
        assert_eq!(credential, f.owner.credential().id());
        assert!(!envelope.contains("Synthetic private photo"));
        let opened = snapshot
            .open(&target.space_context, &envelope, identity, credential, time)
            .unwrap();
        assert_eq!(opened.payload, payload);
        assert!(snapshot.allows_event(&opened));
        assert!(
            outsider
                .open(&target.space_context, &envelope, identity, credential, time)
                .is_err()
        );
    }
    live_send(
        &mut companion_socket,
        companion
            .publication(
                &companion_target,
                &scope,
                Payload::Typing { active: true },
                time,
            )
            .unwrap(),
    )
    .await;
    for (socket, snapshot) in [
        (&mut owner_socket, &owner),
        (&mut peer_socket, &peer),
        (&mut companion_socket, &companion),
    ] {
        let ServerFrame::Ephemeral {
            envelope,
            identity,
            credential,
            ..
        } = live_receive(socket).await
        else {
            panic!("expected companion typing activity");
        };
        assert_eq!(identity, f.owner.identity_id());
        assert_eq!(credential, f.companion.credential().id());
        assert_eq!(
            snapshot
                .open(&scope.space_context, &envelope, identity, credential, time)
                .unwrap()
                .payload,
            Payload::Typing { active: true }
        );
    }
    let writer = Peer::new(descriptor.clone(), true)
        .unwrap()
        .with_identity(&f.owner);
    let reader = Peer::new(descriptor.clone(), true)
        .unwrap()
        .with_identity(&f.peer);
    assert!(
        reader.inventory(0).await.unwrap().entries.is_empty(),
        "ephemeral activity never enters durable history"
    );
    let message = f
        .authority
        .prepare_chat(
            ChatMessage {
                v: 1,
                kind: "chat.message".into(),
                nonce: record::random_hex::<16>().unwrap(),
                space_id: scope.space,
                stream_id: scope.stream,
                issuer_identity: f.owner.identity_id(),
                issuer_credential: f.owner.credential().id(),
                config_id: f.authority.head_id().unwrap(),
                audience: vec![],
                recipient_credentials: vec![],
                logical_time: time,
                created_at: "2026-10-01T12:00:00Z".into(),
                parents: vec![],
                payload: TextPayload {
                    text: "Durable message after a live hint".into(),
                    expires_at_ms: None,
                    sender_name: None,
                    thread_root: None,
                    action: None,
                },
                locator: None,
                access: None,
            },
            f.owner.signing_key(),
        )
        .unwrap();
    let ciphertext = crypto::seal_record(
        &message,
        &[
            f.owner.credential().recipient(),
            f.peer.credential().recipient(),
            f.companion.credential().recipient(),
        ],
    )
    .unwrap();
    let object = ObjectId::of_ciphertext(&ciphertext);
    writer
        .post(object, ciphertext.clone(), TransferHint::Eager)
        .await
        .unwrap();
    for socket in [&mut owner_socket, &mut peer_socket, &mut companion_socket] {
        assert!(
            matches!(live_receive(socket).await, ServerFrame::Changed { id } if id == peer_target.id)
        );
    }
    // A Changed hint triggers the ordinary authenticated inventory/get path.
    let inventory = reader.inventory(0).await.unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.entries[0].object_id, object);
    let received = reader
        .get(object, inventory.entries[0].size_bytes)
        .await
        .unwrap();
    let opened = crypto::open_record(&received, f.peer.age_identity()).unwrap();
    assert_eq!(opened.id(), message.id());
    assert_eq!(
        f.authority.verify_historical(&opened).unwrap().payload.text,
        "Durable message after a live hint"
    );

    drop((owner_socket, peer_socket, companion_socket));
    server.abort();
    let _ = server.await;
}

#[test]
fn small_wire_frames_cannot_expand_past_the_live_plaintext_budget() {
    use std::io::Write;
    let f = Fixture::new();
    let snapshot = f.snapshot(&f.peer);
    let body = f.body(&f.owner, Payload::Typing { active: true });
    // Whitespace inside the JSON object preserves the valid schema and signature.
    // A generic record opener accepts it, exercising the dedicated live budget.
    let padded = |padding: usize| {
        let mut bytes = serde_json::to_vec(&body).unwrap();
        assert_eq!(bytes.pop(), Some(b'}'));
        bytes.extend(std::iter::repeat_n(b' ', padding));
        bytes.push(b'}');
        SignedRecord::sign(&bytes, f.owner.signing_key()).unwrap()
    };
    let raw = padded(MAX_PLAINTEXT);
    let ciphertext = crypto::seal_record(&raw, &[f.peer.credential().recipient()]).unwrap();
    let envelope = STANDARD.encode(&ciphertext);
    assert!(envelope.len() < MAX_ENVELOPE);
    assert_eq!(
        crypto::open_record(&ciphertext, f.peer.age_identity())
            .unwrap()
            .id(),
        raw.id()
    );
    assert!(
        snapshot
            .open(
                &f.scope().space_context,
                &envelope,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_err()
    );

    let large = padded(512 * 1024);
    let mut compressor =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    compressor.write_all(large.bytes()).unwrap();
    let mut packed = b"elo-packed-record-v1\n".to_vec();
    let size_at = packed.len();
    packed.extend_from_slice(&(large.bytes().len() as u32).to_be_bytes());
    packed.extend_from_slice(&compressor.finish().unwrap());
    assert!(packed.len() < MAX_PLAINTEXT);
    let ciphertext =
        crypto::seal_bytes(&packed, &[f.peer.credential().recipient()], MAX_PLAINTEXT).unwrap();
    let envelope = STANDARD.encode(&ciphertext);
    assert!(envelope.len() < MAX_ENVELOPE);
    assert_eq!(
        crypto::open_record(&ciphertext, f.peer.age_identity())
            .unwrap()
            .id(),
        large.id()
    );
    assert!(matches!(
        crypto::open_record_bounded(&ciphertext, f.peer.age_identity(), MAX_PLAINTEXT),
        Err(crypto::CryptoError::InvalidInput)
    ));
    assert!(
        snapshot
            .open(
                &f.scope().space_context,
                &envelope,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_err()
    );
    // A forged expansion size must not bypass the same allocation limit.
    packed[size_at..size_at + 4].copy_from_slice(&(MAX_PLAINTEXT as u32).to_be_bytes());
    let forged =
        crypto::seal_bytes(&packed, &[f.peer.credential().recipient()], MAX_PLAINTEXT).unwrap();
    assert!(crypto::open_record_bounded(&forged, f.peer.age_identity(), MAX_PLAINTEXT).is_err());

    let valid =
        SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), f.owner.signing_key()).unwrap();
    let ciphertext = crypto::seal_record(&valid, &[f.peer.credential().recipient()]).unwrap();
    assert_eq!(
        crypto::open_record_bounded(&ciphertext, f.peer.age_identity(), MAX_PLAINTEXT)
            .unwrap()
            .id(),
        valid.id()
    );
    for end in [0, 20, ciphertext.len() - 17, ciphertext.len() - 1] {
        assert!(
            crypto::open_record_bounded(&ciphertext[..end], f.peer.age_identity(), MAX_PLAINTEXT)
                .is_err()
        );
    }
    let mut corrupted = ciphertext.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(crypto::open_record_bounded(&corrupted, f.peer.age_identity(), MAX_PLAINTEXT).is_err());
    let mut appended = ciphertext;
    appended.push(0);
    assert!(crypto::open_record_bounded(&appended, f.peer.age_identity(), MAX_PLAINTEXT).is_err());
}

#[test]
fn outgoing_limits_count_encryption_keys_separately_from_recipient_identities() {
    let mut f = Fixture::new();
    let extras = (0..255)
        .map(|_| Session::create().unwrap().0)
        .collect::<Vec<_>>();
    for session in &extras {
        f.authority.add_credential(session.credential().clone());
    }
    let member = |session: &Session| Member {
        identity_id: session.identity_id(),
        identity_type: "HUMAN".into(),
        root_public_key: session.credential().record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into(),
        capabilities: vec![Capability::Read],
        credential_ids: vec![session.credential().id()],
        external: false,
    };
    f.update(|config| {
        config.members.extend(extras[..253].iter().map(member));
        config.members.sort_by_key(|member| member.identity_id);
    });
    let recipients = f
        .authority
        .expected_recipients(f.authority.head_id().unwrap(), f.owner.credential().id())
        .unwrap();
    assert_eq!(recipients.0.len(), 255);
    assert_eq!(recipients.1.len(), MAX_RECIPIENTS);
    let (audience, envelope) = f
        .snapshot(&f.owner)
        .seal(&f.scope(), upload(UploadStatus::Uploading), NOW)
        .unwrap();
    assert_eq!(audience.len(), 255);
    assert!(envelope.len() <= MAX_ENVELOPE);
    assert!(
        f.snapshot(&f.companion)
            .open(
                &f.scope().space_context,
                &envelope,
                f.owner.identity_id(),
                f.owner.credential().id(),
                NOW
            )
            .is_ok()
    );
    f.update(|config| {
        config.members.push(member(&extras[253]));
        config.members.sort_by_key(|member| member.identity_id);
    });
    let recipients = f
        .authority
        .expected_recipients(f.authority.head_id().unwrap(), f.owner.credential().id())
        .unwrap();
    assert_eq!(recipients.0.len(), MAX_RECIPIENTS);
    assert_eq!(recipients.1.len(), MAX_RECIPIENTS + 1);
    assert!(
        f.snapshot(&f.owner)
            .seal(&f.scope(), Payload::Typing { active: true }, NOW)
            .is_err()
    );
    f.update(|config| {
        config.members.push(member(&extras[254]));
        config.members.sort_by_key(|member| member.identity_id);
    });
    assert_eq!(
        f.authority.head().unwrap().members.len(),
        MAX_RECIPIENTS + 1
    );
    assert!(
        f.snapshot(&f.owner)
            .seal(&f.scope(), Payload::Presence { active: true }, NOW)
            .is_err()
    );
    assert!(
        !fits_envelope(MAX_PLAINTEXT, MAX_RECIPIENTS),
        "frame budgeting includes age headers and base64 expansion"
    );
}

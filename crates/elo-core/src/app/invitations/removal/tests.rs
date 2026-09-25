use super::*;
use std::time::Duration;
const PASSWORD: &str = "synthetic removal security password";
async fn profile(root: &Path, name: &str) -> ClientApp {
    ProfileDraft::new()
        .unwrap()
        .save_named(root.join(name), PASSWORD.into(), "General", name)
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    ClientApp::open(root.join(name), PASSWORD.into(), true)
        .await
        .unwrap()
}
async fn contact(owner: &mut ClientApp, other: &mut ClientApp) {
    let card = other
        .operate(json!({"op":"contact_create","name":"Contact"}))
        .await
        .unwrap();
    let preview = owner
        .operate(json!({"op":"contact_preview","link":card["link"]}))
        .await
        .unwrap();
    owner.operate(json!({"op":"contact_add","link":card["link"],"trusted":true,"confirmed_contact":preview["id"]})).await.unwrap();
}
fn packet_for(app: &ClientApp, recipient: &ClientApp, prefix: &str) -> Packet {
    app.invitation_state()
        .unwrap()
        .jobs
        .iter()
        .filter(|(id, _)| id.starts_with(prefix))
        .find_map(|(_, job)| {
            let serialized = serde_json::to_value(job).unwrap();
            let bytes = STANDARD
                .decode(serialized["ciphertext"].as_str().unwrap())
                .unwrap();
            crypto::open_bytes(&bytes, recipient.session.age_identity(), MAX_PACKET)
                .ok()
                .and_then(|plain| serde_json::from_slice(&plain).ok())
        })
        .expect("recipient-bound packet")
}

#[tokio::test]
async fn removal_proofs_are_restricted_monotonic_and_resumable_after_commit() {
    let dir = tempfile::tempdir().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    let mut sam = profile(dir.path(), "Sam").await;
    contact(&mut alex, &mut maya).await;
    contact(&mut maya, &mut alex).await;
    contact(&mut alex, &mut sam).await;
    contact(&mut sam, &mut alex).await;
    let replica = crate::replica::ReplicaStore::open(dir.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
    let path = dir.path().join("peer.json");
    vault::write_private(&path,&serde_json::to_vec(&json!({"url":"http://127.0.0.1:9","signing_public_key":record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token})).unwrap(),false).unwrap();
    alex.operate(json!({"op":"add_peer","path":path}))
        .await
        .unwrap();
    let base = alex.authorities.0[0].clone();
    alex.operate(json!({"op":"contact_add_members","request_id":"91".repeat(16),"space":base.space(),"stream":base.stream(),"people":[maya.session.identity_id(),sam.session.identity_id()]})).await.unwrap();
    let sam_addition = packet_for(&alex, &sam, "members:");
    let before = alex.authorities.0[0].clone();
    alex.operate(json!({"op":"remove_member","space":base.space(),"stream":base.stream(),"fingerprint":sam.session.identity_id()})).await.unwrap();
    let committed = alex.authorities.0[0].clone();
    let maya_packet = packet_for(&alex, &maya, "removal:");
    let sam_packet = packet_for(&alex, &sam, "removal:");
    // Both clients receive the removal before the original addition. The remaining
    // client can post; the removed client retains only a revoked membership proof.
    maya.verify_removal(&maya_packet).unwrap();
    sam.verify_removal(&sam_packet).unwrap();
    let Packet::MembershipChange { bundle, .. } = &maya_packet else {
        panic!("membership change");
    };
    let mut forged = before.clone();
    let mut changed = committed.head().unwrap().clone();
    changed
        .members
        .iter_mut()
        .find(|member| member.identity_id == maya.session.identity_id())
        .unwrap()
        .capabilities
        .push(Capability::ShareHistory);
    forged
        .apply_config(changed.sign(alex.session.signing_key()).unwrap())
        .unwrap();
    let forged_packet = Packet::MembershipChange {
        bundle: bundle.clone(),
        ciphertext: STANDARD.encode(
            forged
                .seal_snapshot(&maya.session.credential().recipient())
                .unwrap(),
        ),
    };
    assert!(
        maya.verify_removal(&forged_packet).is_err(),
        "a controller signature must not smuggle a permission change into a removal"
    );
    let mut wrong = bundle.clone();
    wrong.stream = StreamId::from_bytes([42; 16]);
    let Packet::MembershipChange { ciphertext, .. } = &maya_packet else {
        unreachable!()
    };
    assert!(
        maya.verify_removal(&Packet::MembershipChange {
            bundle: wrong,
            ciphertext: ciphertext.clone()
        })
        .is_err()
    );
    assert!(
        sam.verify_removal(&maya_packet).is_err(),
        "encrypted snapshots stay recipient-bound"
    );
    assert!(maya.receive_removal(&maya_packet).await.unwrap());
    assert!(sam.receive_removal(&sam_packet).await.unwrap());
    assert!(
        !maya.receive_removal(&maya_packet).await.unwrap(),
        "duplicate delivery is idempotent"
    );
    assert!(
        sam.membership_preview(&sam_addition).is_err(),
        "an older addition cannot restore access"
    );
    let current = maya
        .authorities
        .0
        .iter()
        .find(|a| a.space() == base.space())
        .unwrap();
    assert!(
        current
            .head()
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_id == maya.session.identity_id())
    );
    assert!(
        !current
            .head()
            .unwrap()
            .members
            .iter()
            .any(|m| m.identity_id == sam.session.identity_id())
    );
    let mut state = alex.invitation_state().unwrap();
    let expected = serde_json::to_value(&state.jobs).unwrap();
    let job_ids: Vec<_> = state
        .jobs
        .keys()
        .filter(|id| id.starts_with("removal:"))
        .cloned()
        .collect();
    let jobs = job_ids
        .into_iter()
        .map(|id| {
            let job = state.jobs.remove(&id).unwrap();
            (id, job)
        })
        .collect();
    let draft = state.removals.values_mut().next().unwrap();
    draft.jobs = jobs;
    draft.snapshot = Some(
        STANDARD.encode(
            committed
                .seal_snapshot(&alex.session.age_identity().to_public())
                .unwrap(),
        ),
    );
    alex.save_invitations(&state).unwrap();
    alex.authorities.0[0] = before;
    alex.resume_committed_removals(&mut state).unwrap();
    assert!(
        !state.jobs.keys().any(|id| id.starts_with("removal:")),
        "uncommitted reductions cannot be sent"
    );
    alex.authorities.0[0] = committed;
    alex.close().await.unwrap();
    alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
        .await
        .unwrap();
    let mut restored = alex.invitation_state().unwrap();
    alex.resume_committed_removals(&mut restored).unwrap();
    assert_eq!(
        serde_json::to_value(&restored.jobs).unwrap(),
        expected,
        "restart must activate byte-identical jobs"
    );
    alex.resume_committed_removals(&mut restored).unwrap();
    assert_eq!(serde_json::to_value(&restored.jobs).unwrap(), expected);
    // Re-adding the person creates a newer legitimate configuration. Replaying
    // the earlier removal must not roll it back on a remaining participant.
    alex.operate(json!({"op":"contact_add_members","request_id":"92".repeat(16),"space":base.space(),"stream":base.stream(),"people":[sam.session.identity_id()]})).await.unwrap();
    let newest = alex.authorities.0[0].clone();
    let i = maya
        .authorities
        .0
        .iter()
        .position(|a| a.space() == base.space())
        .unwrap();
    maya.authorities.0[i] = newest
        .merge_into_store(
            Some(&maya.authorities.0[i]),
            &maya.store,
            maya.session.age_identity(),
            now().unwrap(),
        )
        .await
        .unwrap();
    assert!(!maya.receive_removal(&maya_packet).await.unwrap());
    assert_eq!(maya.authorities.0[i].head_id(), newest.head_id());
    alex.close().await.unwrap();
    maya.close().await.unwrap();
    sam.close().await.unwrap();
}

#[tokio::test]
async fn recovered_device_repairs_imported_seed_without_hiding_ordinary_general() {
    let dir = tempfile::tempdir().unwrap();
    let draft = ProfileDraft::new().unwrap();
    let mut owner = draft
        .save(dir.path().join("owner"), PASSWORD.into(), "General")
        .await
        .unwrap();
    owner.allow_loopback = true;
    let mut restored =
        ProfileDraft::recover(&draft.card().phrase, &draft.card().identity_id.to_string())
            .unwrap()
            .save(dir.path().join("restored"), PASSWORD.into(), "General")
            .await
            .unwrap();
    restored.allow_loopback = true;
    owner
        .create_chat("General", None, ChatKind::Chat)
        .await
        .unwrap();
    owner
        .create_chat("Server General", None, ChatKind::Chat)
        .await
        .unwrap();
    // The hosting roster has admitted the freshly recovered credential. Each
    // existing conversation receives the normal signed device update.
    for authority in owner.authorities.0.iter_mut() {
        authority.add_credential(restored.session.credential().clone());
        let mut config = authority.head().unwrap().clone();
        config.members[0]
            .credential_ids
            .push(restored.session.credential().id());
        config.members[0].credential_ids.sort();
        config.owner_credential_ids = config.members[0].credential_ids.clone();
        config.sequence += 1;
        config.previous_config_id = authority.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.action.operation = "device.updated".into();
        authority
            .commit_update(
                &owner.store,
                config.sign(owner.session.signing_key()).unwrap(),
                owner.session.age_identity(),
                now().unwrap(),
            )
            .await
            .unwrap();
    }
    let general = &owner.authorities.0[2];
    let pin = &owner.pins[2];
    let ciphertext = general
        .seal_snapshot_signed(
            &restored.session.credential().recipient(),
            owner.session.signing_key(),
        )
        .unwrap();
    restored.operate(json!({"op":"import_stream","space":pin.space,"stream":pin.stream,"root":pin.root,"name":"General","ciphertext":STANDARD.encode(ciphertext)})).await.unwrap();
    let scope = team::TeamScope {
        space: pin.space,
        stream: pin.stream,
        root: pin.root.clone(),
        controller: general.controller().id(),
    };
    let descriptor = team::TeamDescriptor {
        v: 1,
        url: "http://127.0.0.1:9/team/v1/enroll".into(),
        token: "ab".repeat(32),
        scope: scope.clone(),
        message_lifetime_seconds: 86400,
    };
    let address = super::super::super::space_service::SpaceAddress {
        url: "http://127.0.0.1:9".into(),
        scope,
        message_lifetime_seconds: 86400,
    };
    for app in [&mut owner, &mut restored] {
        app.configure_team(descriptor.clone()).unwrap();
        app.call_host = Some(address.clone());
    }
    let replica = crate::replica::ReplicaStore::open(dir.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
    let listener = crate::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let peer = PeerDescriptor {
        url: url.clone(),
        signing_public_key: record::encode_hex(replica.key().as_bytes()),
        mailbox_id: mailbox.mailbox_id,
        read_token: Some(mailbox.read_token.clone()),
        write_token: Some(mailbox.write_token.clone()),
    };
    let transport = Peer::new(peer.clone(), true).unwrap();
    for app in [&mut owner, &mut restored] {
        app.ensure_peer(peer.clone()).unwrap();
    }
    let http_replica = replica.clone();
    let http = tokio::spawn(async move {
        axum::serve(listener, crate::http::router(http_replica, &url))
            .await
            .unwrap();
    });
    // Reproduce old clients delivering both the setup seed and a real empty
    // General without signed presentation metadata.
    for index in [0, 1] {
        let authority = &owner.authorities.0[index];
        let mut bundle = owner
            .offer_bundle(index, &json!({"post":true,"reusable":false}), 86_400_000)
            .unwrap();
        let mut body = decode_record(&bundle.invitation).unwrap().body().clone();
        body.as_object_mut().unwrap().remove("personal_seed");
        body["base_config_id"] = json!(authority.head().unwrap().previous_config_id);
        bundle.invitation = STANDARD.encode(
            SignedRecord::sign(
                &serde_json::to_vec(&body).unwrap(),
                owner.session.signing_key(),
            )
            .unwrap()
            .bytes(),
        );
        let packet = Packet::MembershipChange {
            bundle,
            ciphertext: STANDARD.encode(
                authority
                    .seal_snapshot_signed(
                        &restored.session.credential().recipient(),
                        owner.session.signing_key(),
                    )
                    .unwrap(),
            ),
        };
        assert!(restored.receive_removal(&packet).await.unwrap());
    }
    let seed = owner.pins[0].clone();
    let ordinary = owner.pins[1].clone();
    let visible = restored.view().await.unwrap();
    assert_eq!(
        visible["streams"].as_array().unwrap().len(),
        3,
        "the old packet exposes the duplicate seed"
    );
    let head = owner.authorities.0[0].head_id();
    owner.refresh_chat_devices().await.unwrap();
    assert_eq!(
        owner.authorities.0[0].head_id(),
        head,
        "metadata repair does not change permissions"
    );
    let packet = packet_for(&owner, &restored, "seed-metadata:");
    // The sender has delivered the repair once. An older recipient rejects the
    // new signed field, but still advances its saved inventory cursor past it.
    for (id, job) in &owner.invitation_state().unwrap().jobs {
        if !id.starts_with("seed-metadata:") {
            continue;
        }
        let job = serde_json::to_value(job).unwrap();
        let bytes = STANDARD
            .decode(job["ciphertext"].as_str().unwrap())
            .unwrap();
        replica
            .post(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                crate::ids::ObjectId::of_ciphertext(&bytes),
                bytes,
                crate::replica::TransferHint::Lazy,
            )
            .await
            .unwrap();
    }
    let inventory = transport.inventory(0).await.unwrap();
    assert!(inventory.head > 0);
    let key = format!("{}:{}", transport.id(), transport.mailbox());
    let mut state = restored.invitation_state().unwrap();
    state.seen_notices.push("already-dismissed-notice".into());
    let mut cursor = serde_json::to_value(direct::Cursor::default()).unwrap();
    cursor["after"] = json!(inventory.head);
    cursor["generation"] = json!(inventory.storage_generation);
    state
        .discovery
        .insert(key.clone(), serde_json::from_value(cursor).unwrap());
    let report = restored
        .discover_offers(
            &mut state,
            true,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(
        report.received, 0,
        "pull to refresh alone does not rewind discovery"
    );
    assert_eq!(
        restored.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    // Persist the exact pre-upgrade format rather than re-delivering the packet
    // directly to the receiver. Reopening must replay the stored server object.
    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy["discovery"][&key]
        .as_object_mut()
        .unwrap()
        .remove("format");
    let sealed = crypto::seal_bytes(
        &serde_json::to_vec(&legacy).unwrap(),
        &[restored.session.age_identity().to_public()],
        MAX_STATE,
    )
    .unwrap();
    vault::write_private(&restored.directory.join("invitations.age"), &sealed, true).unwrap();
    restored.close().await.unwrap();
    let mut restored = ClientApp::open(dir.path().join("restored"), PASSWORD.into(), true)
        .await
        .unwrap();
    restored.configure_team(descriptor.clone()).unwrap();
    let mut state = restored.invitation_state().unwrap();
    let report = restored
        .discover_offers(
            &mut state,
            true,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(report.retry, 0);
    assert_eq!(
        report.received, 1,
        "upgrade must revisit the previously skipped repair"
    );
    assert_eq!(state.seen_notices, ["already-dismissed-notice"]);
    let saved = restored.invitation_state().unwrap();
    assert_eq!(
        serde_json::to_value(&saved.discovery).unwrap(),
        serde_json::to_value(&state.discovery).unwrap(),
        "cursor migration runs only once"
    );
    let report = restored
        .discover_offers(
            &mut state,
            true,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(
        report.received, 0,
        "ordinary refresh does not replay old packets"
    );
    assert!(
        !restored.receive_removal(&packet).await.unwrap(),
        "replay is idempotent"
    );
    let queued = serde_json::to_vec(&owner.invitation_state().unwrap().jobs).unwrap();
    owner.refresh_chat_devices().await.unwrap();
    assert_eq!(
        serde_json::to_vec(&owner.invitation_state().unwrap().jobs).unwrap(),
        queued,
        "sync does not queue the same repair again"
    );
    for paged in [false, true] {
        if paged {
            restored.enable_paged_views();
        }
        let view = restored.view().await.unwrap();
        let streams = view["streams"].as_array().unwrap();
        assert_eq!(streams.len(), 2);
        assert!(!streams.iter().any(|s| s["stream"] == json!(seed.stream)));
        assert!(
            streams
                .iter()
                .any(|s| s["stream"] == json!(ordinary.stream)),
            "ordinary General stays visible"
        );
    }
    // The marker is inside the signature; changing it on a normal chat cannot
    // make that conversation disappear.
    let Packet::MembershipChange {
        mut bundle,
        ciphertext,
    } = packet.clone()
    else {
        unreachable!()
    };
    let signed = decode_record(&bundle.invitation).unwrap();
    let mut tampered = signed.bytes().to_vec();
    let offset = tampered.windows(4).position(|b| b == b"true").unwrap();
    tampered[offset..offset + 4].copy_from_slice(b"null");
    bundle.invitation = STANDARD.encode(tampered);
    assert!(
        restored
            .receive_removal(&Packet::MembershipChange { bundle, ciphertext })
            .await
            .is_err()
    );
    restored.close().await.unwrap();
    let mut restored = ClientApp::open(dir.path().join("restored"), PASSWORD.into(), true)
        .await
        .unwrap();
    restored.configure_team(descriptor.clone()).unwrap();
    assert_eq!(
        restored.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "classification survives restart"
    );
    let index = restored
        .pins
        .iter()
        .position(|p| p.stream == seed.stream)
        .unwrap();
    // Real messages remain readable even in an old internal stream.
    restored.call_host = None;
    restored.operate(json!({"op":"send","space":seed.space,"stream":seed.stream,"text":"Existing history must remain accessible","created_at":"2026-09-25T10:00:00Z"})).await.unwrap();
    assert_eq!(restored.authorities.0[index].head_id(), head);
    assert_eq!(
        restored.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    owner.close().await.unwrap();
    let mut owner = ClientApp::open(dir.path().join("owner"), PASSWORD.into(), true)
        .await
        .unwrap();
    owner.configure_team(descriptor).unwrap();
    owner.share_personal_seed_metadata(0).await.unwrap();
    assert_eq!(
        serde_json::to_vec(&owner.invitation_state().unwrap().jobs).unwrap(),
        queued,
        "restart does not queue another repair"
    );
    owner.close().await.unwrap();
    restored.close().await.unwrap();
    http.abort();
}

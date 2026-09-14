use super::*;
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

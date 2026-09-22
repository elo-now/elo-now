use super::*;

async fn profile(root: &Path, name: &str) -> ClientApp {
    ProfileDraft::new()
        .unwrap()
        .save_named(
            root.join(name),
            "synthetic membership proof password".into(),
            "General",
            name,
        )
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    ClientApp::open(
        root.join(name),
        "synthetic membership proof password".into(),
        true,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn signed_contact_updates_reject_permission_edits_wrong_proofs_and_removed_recipient_replays()
{
    let dir = tempfile::tempdir().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    let card = maya
        .operate(json!({"op":"contact_create","name":"Maya"}))
        .await
        .unwrap();
    let preview = alex
        .operate(json!({"op":"contact_preview","link":card["link"]}))
        .await
        .unwrap();
    alex.operate(json!({"op":"contact_add","link":card["link"],"trusted":true,"confirmed_contact":preview["id"]})).await.unwrap();
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
    let request = json!({"op":"contact_add_members","space":base.space(),"stream":base.stream(),"request_id":"41".repeat(16),"people":[maya.session.identity_id()]});
    alex.operate(request).await.unwrap();
    let mut state = alex.invitation_state().unwrap();
    let committed = alex.authorities.0[0].clone();
    let expected_jobs = serde_json::to_value(&state.jobs).unwrap();
    let draft = state.additions.values_mut().next().unwrap();
    draft.snapshot = Some(
        STANDARD.encode(
            committed
                .seal_snapshot(&alex.session.age_identity().to_public())
                .unwrap(),
        ),
    );
    draft.jobs = std::mem::take(&mut state.jobs);
    // Persist the state of a crash just before the delivery journal is activated.
    alex.save_invitations(&state).unwrap();
    alex.authorities.0[0] = base.clone();
    alex.resume_committed_additions(&mut state).unwrap();
    assert!(
        state.jobs.is_empty(),
        "uncommitted drafts must stay private"
    );
    assert!(state.additions.values().next().unwrap().snapshot.is_some());
    alex.authorities.0[0] = committed;
    alex.close().await.unwrap();
    alex = ClientApp::open(
        dir.path().join("Alex"),
        "synthetic membership proof password".into(),
        true,
    )
    .await
    .unwrap();
    let mut state = alex.invitation_state().unwrap();
    assert!(state.jobs.is_empty());
    alex.resume_committed_additions(&mut state).unwrap();
    assert_eq!(serde_json::to_value(&state.jobs).unwrap(), expected_jobs);
    assert!(state.additions.values().next().unwrap().snapshot.is_none());
    alex.resume_committed_additions(&mut state).unwrap();
    assert_eq!(
        serde_json::to_value(&alex.invitation_state().unwrap().jobs).unwrap(),
        expected_jobs
    );
    let job = state.jobs.values().next().unwrap();
    let serialized = serde_json::to_value(job).unwrap();
    let encrypted = STANDARD
        .decode(serialized["ciphertext"].as_str().unwrap())
        .unwrap();
    let clear = crypto::open_bytes(&encrypted, maya.session.age_identity(), MAX_PACKET).unwrap();
    let packet: Packet = serde_json::from_slice(&clear).unwrap();
    let (valid, _, _) = maya.verified_membership(&packet).unwrap();
    let Packet::Members { bundle, .. } = &packet else {
        panic!("expected membership packet")
    };
    for change_old_member in [false, true] {
        let mut forged = base.clone();
        forged.add_credential(maya.session.credential().clone());
        let mut config = valid.head().unwrap().clone();
        let identity = if change_old_member {
            alex.session.identity_id()
        } else {
            maya.session.identity_id()
        };
        let member = config
            .members
            .iter_mut()
            .find(|m| m.identity_id == identity)
            .unwrap();
        if change_old_member {
            member.capabilities.push(Capability::Replicate);
        } else {
            member.capabilities.push(Capability::ShareHistory);
        }
        forged
            .apply_config(config.sign(alex.session.signing_key()).unwrap())
            .unwrap();
        let packet = Packet::Members {
            bundle: bundle.clone(),
            ciphertext: STANDARD.encode(
                forged
                    .seal_snapshot(&maya.session.credential().recipient())
                    .unwrap(),
            ),
        };
        assert!(
            maya.verified_membership(&packet).is_err(),
            "a valid controller signature cannot bypass the addition-only rule"
        );
    }
    let mut wrong = bundle.clone();
    let mut offer: shared::Offer = decode_record(&wrong.invitation).unwrap().decode().unwrap();
    offer.invitees.clear();
    wrong.invitation = STANDARD.encode(
        SignedRecord::sign(
            &serde_json::to_vec(&offer).unwrap(),
            alex.session.signing_key(),
        )
        .unwrap()
        .bytes(),
    );
    let Packet::Members { ciphertext, .. } = &packet else {
        unreachable!()
    };
    assert!(
        maya.verified_membership(&Packet::Members {
            bundle: wrong,
            ciphertext: ciphertext.clone()
        })
        .is_err()
    );
    let mut inbox = maya.invitation_state().unwrap();
    maya.receive_membership(packet.clone(), &mut inbox)
        .await
        .unwrap();
    assert_eq!(maya.view().await.unwrap()["invitations"]["actionable"], 1);
    let ignored = maya
        .operate(json!({"op":"invitation_notifications_seen","ids":[]}))
        .await
        .unwrap();
    assert_eq!(
        ignored["view"]["invitations"]["actionable"], 1,
        "reading notifications is not acceptance"
    );
    maya.import_membership(&packet).await.unwrap();
    assert_eq!(maya.view().await.unwrap()["invitations"]["actionable"], 0);
    alex.operate(json!({"op":"remove_member","space":base.space(),"stream":base.stream(),"fingerprint":maya.session.identity_id()})).await.unwrap();
    let i = maya
        .authorities
        .0
        .iter()
        .position(|a| a.space() == base.space() && a.stream() == base.stream())
        .unwrap();
    // Model the recipient having already learned the signed removal.
    maya.authorities.0[i] = alex.authorities.0[0].clone();
    assert!(
        maya.verified_membership(&packet).is_err(),
        "old delivery cannot restore removed membership"
    );
    alex.close().await.unwrap();
    maya.close().await.unwrap();
}

use super::*;

async fn profile(path: &Path, name: &str) -> ClientApp {
    ProfileDraft::new()
        .unwrap()
        .save_named(
            path.join(name),
            "synthetic personal DM password".into(),
            "General",
            name,
        )
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    ClientApp::open(
        path.join(name),
        "synthetic personal DM password".into(),
        true,
    )
    .await
    .unwrap()
}

fn packet(draft: &PersonalDraft, authority: &Authority, recipient: &VerifiedCredential) -> Packet {
    Packet::Direct {
        bundle: draft.bundle.clone().unwrap(),
        contact: Box::new(draft.contact.clone().unwrap()),
        ciphertext: STANDARD.encode(authority.seal_snapshot(&recipient.recipient()).unwrap()),
    }
}

fn update(
    a: &mut Authority,
    key: &ed25519_dalek::SigningKey,
    change: impl FnOnce(&mut StreamConfig),
) {
    let mut next = a.head().unwrap().clone();
    next.sequence += 1;
    next.previous_config_id = a.head_id();
    next.nonce = record::random_hex::<16>().unwrap();
    next.action = ConfigAction {
        operation: "replace".into(),
        actor_identity: a.controller().identity(),
        request_record_id: None,
    };
    change(&mut next);
    a.apply_config(next.sign(key).unwrap()).unwrap();
}

#[tokio::test]
async fn personal_bootstrap_rejects_signed_expansion_permission_changes_and_replays_after_removal()
{
    let temp = tempfile::tempdir().unwrap();
    let mut alex = profile(temp.path(), "Alex").await;
    let mut maya = profile(temp.path(), "Maya").await;
    let sam = profile(temp.path(), "Sam").await;
    let card = maya
        .operate(json!({"op":"contact_create","name":"Maya"}))
        .await
        .unwrap();
    let preview = alex
        .operate(json!({"op":"contact_preview","link":card["link"]}))
        .await
        .unwrap();
    alex.operate(json!({"op":"contact_add","link":card["link"],"trusted":true,"confirmed_contact":preview["id"]})).await.unwrap();
    let created = alex
        .operate(json!({"op":"contact_open","identity":maya.session.identity_id(),"name":"Maya"}))
        .await
        .unwrap();
    // Legacy demo/imported DMs can have a combined local title without any
    // saved card or signed sender name available to the view projection.
    let mut names = alex.invitation_state().unwrap();
    names.contacts.clear();
    alex.save_invitations(&names).unwrap();
    let index = alex
        .pins
        .iter()
        .position(|p| json!(p.stream) == created["stream"])
        .unwrap();
    alex.pins[index].name = "Alex, Maya".into();
    let reopened = alex
        .operate(json!({"op":"contact_open","identity":maya.session.identity_id(),"name":"Maya"}))
        .await
        .unwrap();
    assert_eq!(
        reopened["view"]["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stream"] == created["stream"])
            .unwrap()["name"],
        "Maya"
    );
    let state = alex.invitation_state().unwrap();
    let draft = &state.personal[&maya.session.identity_id().to_string()];
    let a = alex
        .authorities
        .0
        .iter()
        .find(|a| json!(a.stream()) == created["stream"])
        .unwrap();
    let valid = packet(draft, a, maya.session.credential());
    assert!(maya.verify_personal(&valid).is_ok());
    let mut expanded = a.clone();
    expanded.add_credential(sam.session.credential().clone());
    update(&mut expanded, alex.session.signing_key(), |c| {
        c.members.push(Member {
            identity_id: sam.session.identity_id(),
            identity_type: "HUMAN".into(),
            root_public_key: sam.session.credential().record().body()["root_public_key"]
                .as_str()
                .unwrap()
                .into(),
            capabilities: vec![Capability::Read, Capability::Post],
            credential_ids: vec![sam.session.credential().id()],
            external: true,
        });
        c.members.sort_by_key(|m| m.identity_id);
    });
    assert!(
        maya.verify_personal(&packet(draft, &expanded, maya.session.credential()))
            .is_err(),
        "even a correctly signed group config is not a personal DM bootstrap"
    );
    let mut elevated = a.clone();
    update(&mut elevated, alex.session.signing_key(), |c| {
        c.members
            .iter_mut()
            .find(|m| m.identity_id == maya.session.identity_id())
            .unwrap()
            .capabilities
            .push(Capability::ShareHistory)
    });
    assert!(
        maya.verify_personal(&packet(draft, &elevated, maya.session.credential()))
            .is_err()
    );
    let mut altered = valid.clone();
    if let Packet::Direct { bundle, .. } = &mut altered {
        bundle.stream = record::random_hex::<16>().unwrap().parse().unwrap();
    }
    assert!(
        maya.verify_personal(&altered).is_err(),
        "unsigned scope changes fail"
    );
    maya.import_personal(&valid).await.unwrap();
    let mut removed = a.clone();
    update(&mut removed, alex.session.signing_key(), |c| {
        c.members
            .retain(|m| m.identity_id != maya.session.identity_id())
    });
    let index = maya
        .authorities
        .0
        .iter()
        .position(|a| a.stream() == draft.stream)
        .unwrap();
    let removed_head = removed.head_id();
    maya.authorities.0[index] = removed;
    maya.import_personal(&valid).await.unwrap();
    assert_eq!(
        maya.authorities.0[index].head_id(),
        removed_head,
        "replay cannot roll back a removal"
    );
    assert_eq!(maya.authorities.0[index].head().unwrap().members.len(), 1);
    alex.close().await.unwrap();
    maya.close().await.unwrap();
    sam.close().await.unwrap();
}

#[tokio::test]
async fn personal_block_suppresses_new_dms_history_reactions_and_survives_restart() {
    let temp = tempfile::tempdir().unwrap();
    let mut alex = profile(temp.path(), "Alex").await;
    let mut maya = profile(temp.path(), "Maya").await;
    let card = maya
        .operate(json!({"op":"contact_create","name":"Maya"}))
        .await
        .unwrap();
    let preview = alex
        .operate(json!({"op":"contact_preview","link":card["link"]}))
        .await
        .unwrap();
    alex.operate(json!({"op":"contact_add","link":card["link"],"trusted":true,"confirmed_contact":preview["id"]})).await.unwrap();
    let created = alex
        .operate(json!({"op":"contact_open","identity":maya.identity_id(),"name":"Maya"}))
        .await
        .unwrap();
    let state = alex.invitation_state().unwrap();
    let draft = &state.personal[&maya.identity_id().to_string()];
    let index = alex
        .pins
        .iter()
        .position(|p| json!(p.stream) == created["stream"])
        .unwrap();
    let valid = packet(draft, &alex.authorities.0[index], maya.session.credential());
    let blocked_identity = alex.identity_id();
    let change = |app: &ClientApp, blocked| json!({"op":"set_user_blocked","expected_identity":app.identity_id(),"identity":blocked_identity,"name":"Alex","blocked":blocked});
    maya.operate(change(&maya, true)).await.unwrap();
    assert!(
        !maya
            .receive_personal(valid.clone(), &mut maya.invitation_state().unwrap())
            .await
            .unwrap()
    );
    assert!(maya.import_personal(&valid).await.is_err());
    assert!(
        maya.operate(json!({"op":"contact_open","identity":alex.identity_id(),"name":"Renamed"}))
            .await
            .is_err()
    );
    maya.operate(change(&maya, false)).await.unwrap();
    maya.import_personal(&valid).await.unwrap();
    let a = &alex.authorities.0[index];
    let space = a.space();
    let stream = a.stream();
    alex.operate(json!({"op":"send","space":space,"stream":stream,"text":"Visible before blocking","created_at":"2026-09-15T01:00:00Z"})).await.unwrap();
    let a = &alex.authorities.0[index];
    async fn deliver(
        source: &ClientApp,
        recipient: &ClientApp,
        a: &Authority,
        kind: &str,
    ) -> SignedRecord {
        let signed = source
            .originals(a)
            .await
            .unwrap()
            .into_iter()
            .find(|(r, _)| {
                r.body()["kind"] == kind
                    && r.body()["issuer_identity"] == json!(source.identity_id())
            })
            .unwrap()
            .0;
        let recipients = signed
            .chat()
            .unwrap()
            .recipient_credentials
            .iter()
            .map(|id| a.credential(*id).unwrap().clone())
            .collect::<Vec<_>>();
        recipient
            .store
            .commit_local_record_with_outbox(
                PreparedLocalRecord::new(
                    signed.id(),
                    crypto::seal_chat(&signed, &recipients).unwrap(),
                    RecordMetadata::new(kind, Some(a.space()), Some(a.stream()), a.head_id())
                        .unwrap(),
                    vec![],
                    now().unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        signed
    }
    deliver(&alex, &maya, a, "chat.message").await;
    maya.operate(json!({"op":"send","space":space,"stream":stream,"text":"My message stays visible","created_at":"2026-09-15T01:00:02Z"})).await.unwrap();
    let maya_authority = maya
        .authorities
        .0
        .iter()
        .find(|a| a.stream() == stream)
        .unwrap();
    let own_message = deliver(&maya, &alex, maya_authority, "chat.message").await;
    alex.operate(json!({"op":"message_action","created_at":"2026-09-15T01:00:03Z","space":space,"stream":stream,"action":{"type":"reaction","target":own_message.id(),"emoji":"👍","active":true}})).await.unwrap();
    deliver(&alex, &maya, &alex.authorities.0[index], "chat.action").await;
    maya.enable_paged_views();
    let request = json!({"op":"history_page","expected_identity":maya.identity_id(),"space":space,"stream":stream});
    let snapshot = maya.history_snapshot();
    let before = snapshot.history_page(&request).await.unwrap();
    let rows = before["history"]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .find(|r| r["id"] == json!(own_message.id()))
            .unwrap()["reactions"][0]["count"],
        1
    );
    maya.operate(change(&maya, true)).await.unwrap();
    let after = snapshot.history_page(&request).await.unwrap();
    let rows = after["history"]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], json!(own_message.id()));
    assert!(rows[0]["reactions"].as_array().unwrap().is_empty());
    let archive = maya
        .export_profile("synthetic backup password".into())
        .await
        .unwrap();
    let plain =
        super::super::super::profile_backup::decrypt(&archive, "synthetic backup password".into())
            .unwrap();
    let backup: Value =
        serde_json::from_reader(flate2::read::GzDecoder::new(plain.as_slice())).unwrap();
    assert!(
        backup["files"]["blocked.age"].is_string(),
        "safety preferences are included in the encrypted backup"
    );
    let restored = ClientApp::restore_profile(
        temp.path().join("restored-blocks"),
        &archive,
        "synthetic backup password".into(),
        maya.identity_id(),
        "synthetic restored password".into(),
        true,
    )
    .await
    .unwrap();
    assert!(restored.blocked.contains(alex.identity_id()));
    assert_eq!(
        restored
            .history_snapshot()
            .history_page(&request)
            .await
            .unwrap()["history"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    restored.close().await.unwrap();
    let view = maya.view().await.unwrap();
    let dm = view["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stream"] == json!(stream))
        .unwrap();
    assert_eq!(dm["unread_count"], 0);
    assert_eq!(dm["can_post"], false);
    assert_eq!(
        view["blocked_users"][0]["identity"],
        json!(alex.identity_id())
    );
    assert!(maya.operate(json!({"op":"send","space":space,"stream":stream,"text":"must not send","created_at":"2026-09-15T01:00:01Z"})).await.is_err());
    assert!(maya.operate(json!({"op":"set_user_blocked","expected_identity":maya.identity_id(),"identity":maya.identity_id(),"name":"Maya","blocked":true})).await.is_err());
    let records = maya.store.stats().await.unwrap().records;
    drop(snapshot);
    maya.close().await.unwrap();
    let encrypted = std::fs::read(temp.path().join("Maya/blocked.age")).unwrap();
    assert!(!encrypted.windows(4).any(|bytes| bytes == b"Alex"));
    let mut maya = ClientApp::open(
        temp.path().join("Maya"),
        "synthetic personal DM password".into(),
        true,
    )
    .await
    .unwrap();
    assert!(maya.blocked.contains(alex.identity_id()));
    assert_eq!(
        maya.store.stats().await.unwrap().records,
        records,
        "blocking preserves signed history"
    );
    maya.operate(change(&maya, false)).await.unwrap();
    assert_eq!(
        maya.operate(request).await.unwrap()["history"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    maya.close().await.unwrap();
    alex.close().await.unwrap();
}

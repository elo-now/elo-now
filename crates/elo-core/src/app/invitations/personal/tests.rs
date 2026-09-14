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

use super::*;
const PASSWORD: &str = "synthetic management recovery password";

pub(in crate::app) async fn fixture(
    base: &Path,
) -> (ProfileDraft, ClientApp, ClientApp, ClientApp) {
    let draft = ProfileDraft::new().unwrap();
    let mut owner = draft
        .save(base.join("owner"), PASSWORD.into(), "Managed chat")
        .await
        .unwrap();
    let mut helper = ProfileDraft::new()
        .unwrap()
        .save(base.join("helper"), PASSWORD.into(), "Own chat")
        .await
        .unwrap();
    let restored =
        ProfileDraft::recover(&draft.card().phrase, &draft.card().identity_id.to_string())
            .unwrap()
            .save(base.join("restored"), PASSWORD.into(), "New chat")
            .await
            .unwrap();
    let a = &mut owner.authorities.0[0];
    a.add_credential(helper.session.credential().clone());
    let mut c = a.head().unwrap().clone();
    c.sequence += 1;
    c.previous_config_id = a.head_id();
    c.nonce = record::random_hex::<16>().unwrap();
    c.action.operation = "replace".into();
    c.chat_kind = Some(ChatKind::Chat);
    c.members.push(Member {
        identity_id: helper.session.identity_id(),
        identity_type: "HUMAN".into(),
        root_public_key: helper.session.credential().record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into(),
        capabilities: vec![Capability::Read, Capability::Post],
        credential_ids: vec![helper.session.credential().id()],
        external: false,
    });
    c.members.sort_by_key(|m| m.identity_id);
    a.commit_update(
        &owner.store,
        c.sign(owner.session.signing_key()).unwrap(),
        owner.session.age_identity(),
        now().unwrap(),
    )
    .await
    .unwrap();
    let pin = &owner.pins[0];
    let cipher = a
        .seal_snapshot_signed(
            &helper.session.credential().recipient(),
            owner.session.signing_key(),
        )
        .unwrap();
    helper.operate(json!({"op":"import_stream","space":pin.space,"stream":pin.stream,"root":pin.root,"name":pin.name,"ciphertext":STANDARD.encode(cipher)})).await.unwrap();
    (draft, owner, helper, restored)
}

#[tokio::test]
async fn recovery_exchange_is_bound_reviewed_retriable_and_adopted_after_restart() {
    let temp = tempfile::tempdir().unwrap();
    let (draft, mut owner, mut helper, mut restored) = fixture(temp.path()).await;
    let a = &owner.authorities.0[0];
    let (space, stream) = (a.space(), a.stream());
    let request = restored.control_recovery_request();
    let device = restored.control_recovery_device();
    assert_eq!(
        helper.control_recovery_choices(&request).await.unwrap()["chats"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        helper
            .control_recovery_export(&request, space, stream, owner.control_recovery_device())
            .await
            .is_err()
    );
    let package = helper
        .control_recovery_export(&request, space, stream, device)
        .await
        .unwrap();
    assert!(
        owner.control_recovery_preview(&package).await.is_err(),
        "only the requested new device decrypts the file"
    );
    let mut preview = restored.control_recovery_preview(&package).await.unwrap();
    assert_eq!(preview["members"].as_array().unwrap().len(), 2);
    let owner_row = preview["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["identity_id"] == json!(owner.session.identity_id()))
        .unwrap();
    assert_eq!(owner_row["credential_ids"], json!([device]));
    assert!(
        restored
            .control_recovery_confirm(&package, &preview, &draft.card().phrase)
            .await
            .is_err()
    );
    preview["confirmed"] = true.into();
    let mut tampered = package.clone();
    tampered["name"] = "Substituted label".into();
    assert!(
        restored
            .control_recovery_confirm(&tampered, &preview, &draft.card().phrase)
            .await
            .is_err()
    );
    assert!(
        restored
            .control_recovery_confirm(&package, &preview, "incorrect words")
            .await
            .is_err()
    );
    let mut hosted = package.clone();
    hosted["hosting_space"] = json!(SpaceId::from_bytes([9; 32]));
    assert!(
        restored
            .control_recovery_preview(&hosted)
            .await
            .unwrap_err()
            .to_string()
            .contains("original Space")
    );
    restored
        .control_recovery_confirm(&package, &preview, &draft.card().phrase)
        .await
        .unwrap();
    let index = restored
        .authority_index(&json!({"space":space,"stream":stream}))
        .unwrap();
    let head = restored.authorities.0[index].head_id();
    restored
        .control_recovery_confirm(&package, &preview, &draft.card().phrase)
        .await
        .unwrap();
    assert_eq!(restored.authorities.0[index].head_id(), head);
    restored.close().await.unwrap();
    let mut restored = ClientApp::open(temp.path().join("restored"), PASSWORD.into(), false)
        .await
        .unwrap();
    restored
        .control_recovery_confirm(&package, &preview, &draft.card().phrase)
        .await
        .unwrap();
    let notice = restored.control_recovery_share(space, stream).unwrap();
    assert!(owner.control_recovery_share(space, stream).is_err());
    assert!(
        owner
            .control_recovery_export(
                &helper.control_recovery_request(),
                space,
                stream,
                helper.control_recovery_device()
            )
            .await
            .is_err()
    );
    // The removed device cannot decrypt the adoption file.
    let bytes = STANDARD
        .decode(notice["ciphertext"].as_str().unwrap())
        .unwrap();
    assert!(
        Authority::open_snapshot(
            &bytes,
            owner.session.age_identity(),
            space,
            &root_key(&owner.pins[0].root).unwrap(),
            stream
        )
        .is_err()
    );
    let mut adoption = helper.control_recovery_preview(&notice).await.unwrap();
    assert_eq!(adoption["controller"], json!(device));
    adoption["confirmed"] = true.into();
    helper
        .control_recovery_confirm(&notice, &adoption, "")
        .await
        .unwrap();
    helper.close().await.unwrap();
    let helper = ClientApp::open(temp.path().join("helper"), PASSWORD.into(), false)
        .await
        .unwrap();
    let index = helper
        .authority_index(&json!({"space":space,"stream":stream}))
        .unwrap();
    let adopted = &helper.authorities.0[index];
    assert_eq!(adopted.controller().id(), device);
    assert_eq!(adopted.head_id(), head);
    assert!(
        helper.require_controller(adopted).is_err(),
        "import never promotes a regular member"
    );
    assert_eq!(
        adopted.call_proof().unwrap().v,
        2,
        "checkpoint survives encrypted local persistence"
    );
    assert_eq!(
        adopted
            .head()
            .unwrap()
            .members
            .iter()
            .find(|m| m.identity_id == helper.session.identity_id())
            .unwrap()
            .capabilities,
        vec![Capability::Read, Capability::Post]
    );
}

#[test]
fn recovery_file_parser_rejects_duplicate_fields_and_oversized_input() {
    assert!(parse_package(br#"{"v":1,"v":2}"#).is_err());
    assert!(parse_package(&vec![b' '; MAX_CONTROL_PACKAGE + 1]).is_err());
}

#[tokio::test]
async fn management_recovery_after_rejoining_and_receiving_device_roster_update() {
    let temp = tempfile::tempdir().unwrap();
    let (draft, mut owner, mut helper, mut restored) = fixture(temp.path()).await;
    let pin = owner.pins[0].clone();
    let authority = &mut owner.authorities.0[0];
    // Rejoining the hosted Space registers the recovered device before the
    // owner requests management recovery. Chat roster sync propagates it too.
    authority.add_credential(restored.session.credential().clone());
    let mut config = authority.head().unwrap().clone();
    let member = config
        .members
        .iter_mut()
        .find(|m| m.identity_id == restored.identity_id())
        .unwrap();
    member
        .credential_ids
        .push(restored.control_recovery_device());
    member.credential_ids.sort();
    config.owner_credential_ids = member.credential_ids.clone();
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
    for app in [&mut helper, &mut restored] {
        let ciphertext = authority
            .seal_snapshot_signed(
                &app.session.credential().recipient(),
                owner.session.signing_key(),
            )
            .unwrap();
        app.operate(json!({"op":"import_stream", "space":pin.space,
            "stream":pin.stream, "root":pin.root, "name":pin.name,
            "ciphertext":STANDARD.encode(ciphertext)}))
            .await
            .unwrap();
    }
    let package = helper
        .control_recovery_export(
            &restored.control_recovery_request(),
            pin.space,
            pin.stream,
            restored.control_recovery_device(),
        )
        .await
        .unwrap();
    let mut preview = restored.control_recovery_preview(&package).await.unwrap();
    assert_eq!(preview["known_chat"], true);
    preview["confirmed"] = true.into();
    restored
        .control_recovery_confirm(&package, &preview, &draft.card().phrase)
        .await
        .expect("a recovered device already admitted by roster sync can recover management");
    let notice = restored
        .control_recovery_share(pin.space, pin.stream)
        .unwrap();
    let mut adoption = helper.control_recovery_preview(&notice).await.unwrap();
    adoption["confirmed"] = true.into();
    helper
        .control_recovery_confirm(&notice, &adoption, "")
        .await
        .unwrap();
    let i = helper
        .authority_index(&json!({"space":pin.space,"stream":pin.stream}))
        .unwrap();
    assert_eq!(
        helper.authorities.0[i].controller().id(),
        restored.control_recovery_device()
    );
    assert!(
        !helper.authorities.0[i]
            .head()
            .unwrap()
            .owner_credential_ids
            .contains(&owner.control_recovery_device())
    );
    owner.close().await.unwrap();
    helper.close().await.unwrap();
    restored.close().await.unwrap();
}

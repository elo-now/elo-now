use super::*;
use tempfile::TempDir;

const PASSWORD: &str = "public synthetic group persistence password";

#[test]
fn legacy_workspace_and_group_references_are_validated() {
    let old = json!({"v":1,"pins":[{
        "name":"Legacy", "space":"11".repeat(32), "stream":"22".repeat(16),
        "root":"33".repeat(32)
    }]});
    let mut workspace: Workspace = serde_json::from_value(old).unwrap();
    workspace.validate().unwrap();
    assert!(workspace.groups.is_empty());
    assert!(workspace.pins[0].group.is_none());
    assert_eq!(workspace.pins[0].created_at, 0);
    workspace.v = 2;
    workspace.groups.push(ChatGroup {
        id: "44".repeat(16),
        name: "Friends".into(),
    });
    workspace.pins[0].group = Some(workspace.groups[0].id.clone());
    workspace.validate().unwrap();
    let mut invalid = workspace.clone();
    invalid.pins[0].group = Some("55".repeat(16));
    assert!(invalid.validate().is_err());
    invalid = workspace.clone();
    invalid.groups.push(invalid.groups[0].clone());
    assert!(invalid.validate().is_err());
    invalid = workspace.clone();
    invalid.v = 3;
    assert!(invalid.validate().is_err());
    invalid.pins[0].chat_kind = Some(ChatKind::Direct);
    invalid.validate().unwrap();
    invalid.v = 4;
    assert!(invalid.validate().is_err());
    workspace.pins[0].created_at = -1;
    assert!(workspace.validate().is_err());
}

#[tokio::test]
async fn groups_survive_upgrade_and_restart_without_changing_authority_or_vault() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("profile");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(path.clone(), PASSWORD.into(), "General")
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    let old = &before["streams"][0];
    app.operate(
        json!({"op":"send", "space":old["space"], "stream":old["stream"],
        "text":"Preserved across group migration", "created_at":"2026-09-09T12:00:00Z"}),
    )
    .await
    .unwrap();
    let old = app.view().await.unwrap()["streams"][0].clone();
    let vault_before = std::fs::read(path.join("vault.age")).unwrap();
    // Save the original workspace v1 envelope, without any new metadata fields.
    let legacy = json!({"v":1,"pins":[{"name":old["name"], "space":old["space"],
        "stream":old["stream"], "root":app.pins[0].root}]});
    let encrypted = crypto::seal_bytes(
        &serde_json::to_vec(&legacy).unwrap(),
        &[app.session.age_identity().to_public()],
        1024 * 1024,
    )
    .unwrap();
    app.close().await.unwrap();
    vault::write_private(&path.join("workspace.age"), &encrypted, true).unwrap();
    let mut app = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert!(app.groups.is_empty());
    assert!(app.pins[0].group.is_none());
    app.operate(json!({"op":"create_group", "name":"  Weekend friends  "}))
        .await
        .unwrap();
    let first = app.groups[0].id.clone();
    for name in [
        "",
        " \t",
        "line\nbreak",
        &"a".repeat(81),
        "weekend FRIENDS",
        "DMs",
    ] {
        assert!(
            app.operate(json!({"op":"create_group", "name":name}))
                .await
                .is_err()
        );
    }
    assert_eq!(app.groups.len(), 1);
    // The first system view is now an icon; Yo is an ordinary available name.
    app.create_group("Yo").unwrap();
    assert_eq!(app.groups.len(), 2);
    assert_eq!(app.groups[1].name, "Yo");
    app.operate(
        json!({"op":"set_chat_group", "space":old["space"], "stream":old["stream"], "group":first}),
    )
    .await
    .unwrap();
    let grouped = app.view().await.unwrap()["streams"][0].clone();
    for key in [
        "head",
        "controller",
        "members",
        "owners",
        "rows",
        "can_post",
    ] {
        assert_eq!(grouped[key], old[key]);
    }
    assert!(
        app.operate(json!({"op":"create_chat", "name":"Invalid group", "group":"missing"}))
            .await
            .is_err()
    );
    assert!(app.operate(json!({"op":"set_chat_group", "space":old["space"], "stream":old["stream"], "group":false})).await.is_err());
    assert_eq!(app.pins.len(), 1);
    app.operate(json!({"op":"create_chat", "name":"Trip", "group":first}))
        .await
        .unwrap();
    assert_eq!(app.pins[1].group.as_deref(), Some(first.as_str()));
    app.create_group("Work").unwrap();
    let second = app
        .groups
        .iter()
        .find(|g| g.name == "Work")
        .unwrap()
        .id
        .clone();
    app.operate(json!({"op":"set_chat_group", "space":app.pins[1].space, "stream":app.pins[1].stream, "group":second})).await.unwrap();
    app.operate(
        json!({"op":"set_chat_group", "space":old["space"], "stream":old["stream"], "group":""}),
    )
    .await
    .unwrap();
    let expected = app.view().await.unwrap();
    assert_eq!(std::fs::read(path.join("vault.age")).unwrap(), vault_before);
    let bytes = std::fs::read(path.join("workspace.age")).unwrap();
    assert!(
        !bytes
            .windows(b"Weekend friends".len())
            .any(|w| w == b"Weekend friends")
    );
    // A failed local metadata write must not publish success in memory.
    std::fs::rename(path.join("workspace.age"), path.join("saved.age")).unwrap();
    std::fs::create_dir(path.join("workspace.age")).unwrap();
    assert!(app.create_group("Must not appear").is_err());
    assert!(app.operate(json!({"op":"set_chat_group", "space":old["space"], "stream":old["stream"], "group":first})).await.is_err());
    assert_eq!(app.view().await.unwrap(), expected);
    std::fs::remove_dir(path.join("workspace.age")).unwrap();
    std::fs::rename(path.join("saved.age"), path.join("workspace.age")).unwrap();
    app.close().await.unwrap();
    let app = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(app.view().await.unwrap(), expected);
    assert!(app.pins[0].group.is_none());
    assert_eq!(app.pins[1].group.as_deref(), Some(second.as_str()));
    assert_eq!(app.groups[0].name, "Weekend friends");
    assert_eq!(std::fs::read(path.join("vault.age")).unwrap(), vault_before);
    app.close().await.unwrap();
}

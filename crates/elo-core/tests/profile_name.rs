use elo_core::app::{ClientApp, ProfileDraft};
use serde_json::json;
use tempfile::TempDir;

const PASSWORD: &str = "public synthetic profile name test password";

#[tokio::test]
async fn queued_operations_cannot_act_on_a_different_open_profile() {
    let temp = TempDir::new().unwrap();
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(
            temp.path().join("profile"),
            PASSWORD.into(),
            "General",
            "Alex",
        )
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    for op in ["sync_live", "invitation_sync", "set_profile_name"] {
        assert!(
            app.operate(json!({"op":op,"expected_identity":"another profile","name":"Wrong"}))
                .await
                .is_err()
        );
    }
    assert_eq!(app.view().await.unwrap(), before);
    let result = app
        .operate(json!({"op":"sync_live","expected_identity":before["identity"]}))
        .await
        .unwrap();
    assert!(
        result["view"].is_null(),
        "unchanged polls do not decrypt or redraw the UI"
    );
    assert_eq!(app.view().await.unwrap(), before);
    assert_eq!(result["result"]["received_messages"], json!([]));
    app.close().await.unwrap();
}

#[tokio::test]
async fn message_names_update_per_chat_without_rewriting_signed_history() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("named");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), PASSWORD.into(), "General", "Alex")
        .await
        .unwrap();
    let initial = app.view().await.unwrap();
    let send = |text: &str| {
        json!({"op":"send", "space":initial["streams"][0]["space"],
        "stream":initial["streams"][0]["stream"], "text":text, "created_at":"2026-09-10T18:00:00Z"})
    };
    let first = app.operate(send("First")).await.unwrap()["view"].clone();
    let original = first["streams"][0]["rows"][0].clone();
    app.operate(json!({"op":"set_profile_name", "name":"Alex River"}))
        .await
        .unwrap();
    let after = app.operate(send("Second")).await.unwrap()["view"].clone();
    let identity = initial["identity"].as_str().unwrap();
    assert_eq!(after["streams"][0]["member_names"][identity], "Alex River");
    assert_eq!(after["streams"][0]["rows"][0], original);
    assert_eq!(original["body"]["payload"]["sender_name"], "Alex");
    assert_eq!(
        after["streams"][0]["rows"][1]["body"]["payload"]["sender_name"],
        "Alex River"
    );
    app.close().await.unwrap();
    let reopened = ClientApp::open(path, PASSWORD.into(), false).await.unwrap();
    assert_eq!(reopened.view().await.unwrap(), after);
    reopened.close().await.unwrap();
}

fn photo(width: u32, height: u32) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let pixels = image::RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
    });
    let mut bytes = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, 85)
        .encode_image(&pixels)
        .unwrap();
    // A valid JPEG comment must not survive avatar normalization.
    let comment = b"Synthetic private location metadata";
    let mut segment = vec![0xff, 0xfe];
    segment.extend_from_slice(&((comment.len() + 2) as u16).to_be_bytes());
    segment.extend_from_slice(comment);
    bytes.splice(2..2, segment);
    format!("data:image/jpeg;base64,{}", STANDARD.encode(bytes))
}

#[tokio::test]
async fn avatar_is_private_persistent_removable_and_preserved_by_name_edits() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("profile");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), PASSWORD.into(), "General", "Alex")
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    let input = photo(64, 64);
    let view = app
        .operate(json!({"op":"set_profile_details", "name":"Alex", "avatar":input}))
        .await
        .unwrap()["view"]
        .clone();
    let avatar = view["avatar"].as_str().unwrap().to_owned();
    assert_ne!(avatar, input);
    let decoded = STANDARD
        .decode(avatar.strip_prefix("data:image/jpeg;base64,").unwrap())
        .unwrap();
    assert!(
        !decoded
            .windows(34)
            .any(|part| part == b"Synthetic private location metadata")
    );
    assert_eq!(
        image::load_from_memory_with_format(&decoded, image::ImageFormat::Jpeg)
            .unwrap()
            .width(),
        64
    );
    for key in ["identity", "credential", "streams", "groups"] {
        assert_eq!(view[key], before[key]);
    }
    app.operate(json!({"op":"set_profile_name", "name":"Alex River"}))
        .await
        .unwrap();
    assert_eq!(app.view().await.unwrap()["avatar"], avatar);
    // Saving an unchanged photo must not repeatedly recompress it.
    app.operate(json!({"op":"set_profile_details", "name":"Alex River", "avatar":avatar}))
        .await
        .unwrap();
    assert_eq!(app.view().await.unwrap()["avatar"], avatar);
    app.close().await.unwrap();
    let encrypted = std::fs::read(path.join("profile-details.age")).unwrap();
    assert!(
        !encrypted
            .windows(avatar.len())
            .any(|part| part == avatar.as_bytes())
    );
    let mut app = ClientApp::open(path.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(app.view().await.unwrap()["avatar"], avatar);
    assert_eq!(app.view().await.unwrap()["name"], "Alex River");
    app.operate(json!({"op":"set_profile_details", "name":"Alex River", "avatar":null}))
        .await
        .unwrap();
    app.close().await.unwrap();
    let app = ClientApp::open(path, PASSWORD.into(), false).await.unwrap();
    assert!(app.view().await.unwrap()["avatar"].is_null());
    assert_eq!(app.view().await.unwrap()["streams"], before["streams"]);
    app.close().await.unwrap();
}

#[tokio::test]
async fn malformed_photos_and_failed_writes_leave_both_name_and_avatar_unchanged() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("profile");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), PASSWORD.into(), "General", "Alex")
        .await
        .unwrap();
    app.operate(json!({"op":"set_profile_details", "name":"Alex", "avatar":photo(32,32)}))
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    let encrypted = std::fs::read(path.join("profile-details.age")).unwrap();
    for avatar in [
        json!("https://example.com/photo.jpg"),
        json!("data:image/svg+xml;base64,PHN2Zz4="),
        json!("data:image/jpeg;base64,/9g="),
        json!("data:image/jpeg;base64,?"),
        json!(format!("data:image/jpeg;base64,{}", "A".repeat(256 * 1024))),
        json!(photo(385, 1)),
        json!(false),
        json!({}),
    ] {
        assert!(
            app.operate(json!({"op":"set_profile_details", "name":"Changed", "avatar":avatar}))
                .await
                .is_err()
        );
        assert_eq!(app.view().await.unwrap(), before);
        assert_eq!(
            std::fs::read(path.join("profile-details.age")).unwrap(),
            encrypted
        );
    }
    for request in [
        json!({"op":"set_profile_details", "name":"Changed"}),
        json!({"op":"set_profile_details", "name":"", "avatar":null}),
    ] {
        assert!(app.operate(request).await.is_err());
        assert_eq!(app.view().await.unwrap(), before);
    }
    let saved = path.join("saved.age");
    std::fs::rename(path.join("profile-details.age"), &saved).unwrap();
    std::fs::create_dir(path.join("profile-details.age")).unwrap();
    assert!(
        app.operate(json!({"op":"set_profile_details", "name":"Changed", "avatar":null}))
            .await
            .is_err()
    );
    assert_eq!(app.view().await.unwrap(), before);
    std::fs::remove_dir(path.join("profile-details.age")).unwrap();
    std::fs::rename(saved, path.join("profile-details.age")).unwrap();
    app.close().await.unwrap();
}

#[tokio::test]
async fn name_is_encrypted_persistent_and_independent_of_signed_identity() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("profile");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), PASSWORD.into(), "General", "  Zoë Nowak  ")
        .await
        .unwrap();
    let before = app.view().await.unwrap();
    assert_eq!(before["name"], "Zoë Nowak");
    let vault = std::fs::read(path.join("vault.age")).unwrap();
    let code = app
        .operate(json!({"op":"contact_create", "name":"Zoë Nowak"}))
        .await
        .unwrap();
    // Reopening a personal QR must not exhaust the 128 outgoing-item limit.
    for _ in 0..130 {
        assert_eq!(
            app.operate(json!({"op":"contact_create", "name":"Zoë Nowak"}))
                .await
                .unwrap(),
            code
        );
    }
    let changed = app
        .operate(json!({"op":"set_profile_name", "name":"  李 小龍  "}))
        .await
        .unwrap()["view"]
        .clone();
    assert_eq!(changed["name"], "李 小龍");
    for key in ["identity", "credential", "streams", "groups"] {
        assert_eq!(changed[key], before[key]);
    }
    let renamed_code = app
        .operate(json!({"op":"contact_create", "name":"李 小龍"}))
        .await
        .unwrap();
    assert_ne!(renamed_code, code);
    assert_eq!(
        app.operate(json!({"op":"contact_create", "name":"Zoë Nowak"}))
            .await
            .unwrap(),
        code
    );
    app.operate(json!({"op":"create_group", "name":"Friends"}))
        .await
        .unwrap();
    app.close().await.unwrap();
    for file in [
        "profile.json",
        "profile-details.age",
        "workspace.age",
        "vault.age",
    ] {
        let bytes = std::fs::read(path.join(file)).unwrap();
        assert!(
            !bytes
                .windows("李 小龍".len())
                .any(|window| window == "李 小龍".as_bytes())
        );
    }
    assert_eq!(std::fs::read(path.join("vault.age")).unwrap(), vault);
    let reopened = ClientApp::open(path, PASSWORD.into(), false).await.unwrap();
    let view = reopened.view().await.unwrap();
    assert_eq!(view["name"], "李 小龍");
    assert_eq!(view["groups"][0]["name"], "Friends");
    assert_eq!(view["streams"], before["streams"]);
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn legacy_profiles_accept_names_and_failed_edits_leave_the_previous_name() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("legacy");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(path.clone(), PASSWORD.into(), "General")
        .await
        .unwrap();
    assert!(app.view().await.unwrap()["name"].is_null());
    assert!(!path.join("profile-details.age").exists());
    app.operate(json!({"op":"set_profile_name", "name":"Alex"}))
        .await
        .unwrap();
    let original = std::fs::read(path.join("profile-details.age")).unwrap();
    for name in [
        "",
        "   ",
        "two\nlines",
        "tab\there",
        &"x".repeat(121),
        &"🌿".repeat(31),
    ] {
        assert!(
            app.operate(json!({"op":"set_profile_name", "name":name}))
                .await
                .is_err()
        );
        assert_eq!(app.view().await.unwrap()["name"], "Alex");
        assert_eq!(
            std::fs::read(path.join("profile-details.age")).unwrap(),
            original
        );
    }
    let saved = path.join("saved.age");
    std::fs::rename(path.join("profile-details.age"), &saved).unwrap();
    std::fs::create_dir(path.join("profile-details.age")).unwrap();
    assert!(
        app.operate(json!({"op":"set_profile_name", "name":"New name"}))
            .await
            .is_err()
    );
    assert_eq!(app.view().await.unwrap()["name"], "Alex");
    std::fs::remove_dir(path.join("profile-details.age")).unwrap();
    std::fs::rename(saved, path.join("profile-details.age")).unwrap();
    app.close().await.unwrap();
    let reopened = ClientApp::open(path, PASSWORD.into(), false).await.unwrap();
    assert_eq!(reopened.view().await.unwrap()["name"], "Alex");
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn invalid_registration_name_creates_nothing_and_foreign_metadata_is_rejected() {
    let temp = TempDir::new().unwrap();
    let draft = ProfileDraft::new().unwrap();
    let invalid = temp.path().join("invalid");
    assert!(
        draft
            .save_named(invalid.clone(), PASSWORD.into(), "General", " ")
            .await
            .is_err()
    );
    assert!(!invalid.exists());
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    draft
        .save_named(first.clone(), PASSWORD.into(), "General", "First")
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    ProfileDraft::new()
        .unwrap()
        .save_named(second.clone(), PASSWORD.into(), "General", "Second")
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    let foreign = std::fs::read(second.join("profile-details.age")).unwrap();
    elo_core::vault::write_private(&first.join("profile-details.age"), &foreign, true).unwrap();
    assert!(
        ClientApp::open(first, PASSWORD.into(), false)
            .await
            .is_err()
    );
}

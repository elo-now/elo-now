use elo_core::{
    app::{ClientApp, ProfileDraft},
    replica::ReplicaStore,
    vault,
};
use serde_json::{Value, json};
use std::path::Path;
const PASSWORD: &str = "synthetic contact membership password";
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
    let code = other
        .operate(json!({"op":"contact_create","name":other.view().await.unwrap()["name"]}))
        .await
        .unwrap();
    let preview = owner
        .operate(json!({"op":"contact_preview","link":code["link"]}))
        .await
        .unwrap();
    owner.operate(json!({"op":"contact_add","link":code["link"],"trusted":true,"confirmed_contact":preview["id"]})).await.unwrap();
}
fn chat<'a>(view: &'a Value, stream: &Value) -> &'a Value {
    view["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["stream"] == *stream)
        .unwrap()
}
async fn server(root: &Path, apps: &mut [&mut ClientApp]) -> tokio::task::JoinHandle<()> {
    let replica = ReplicaStore::open(root.join("replica")).await.unwrap();
    let mailbox = replica.create_mailbox(64 * 1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let descriptor = json!({"url":format!("http://{}",listener.local_addr().unwrap()),"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
    let path = root.join("peer.json");
    vault::write_private(&path, &serde_json::to_vec(&descriptor).unwrap(), false).unwrap();
    for app in apps {
        app.operate(json!({"op":"add_peer","path":path}))
            .await
            .unwrap();
    }
    tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, elo_core::http::router(replica, &origin))
        }
        .await
        .unwrap();
    })
}
async fn sync(app: &mut ClientApp) {
    app.operate(json!({"op":"sync"})).await.unwrap();
}
async fn send(app: &mut ClientApp, c: &Value, text: &str) {
    app.operate(json!({"op":"send","space":c["space"],"stream":c["stream"],"text":text,"created_at":"2026-09-11T18:00:00Z"})).await.unwrap();
}

#[tokio::test]
async fn contact_additions_reach_existing_and_new_members_without_sender_or_old_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    let mut sam = profile(dir.path(), "Sam").await;
    contact(&mut alex, &mut maya).await;
    contact(&mut maya, &mut alex).await;
    contact(&mut alex, &mut sam).await;
    contact(&mut sam, &mut alex).await;
    let server = server(dir.path(), &mut [&mut alex, &mut maya, &mut sam]).await;
    let create = json!({"op":"contact_create_chat","request_id":"01".repeat(16),"name":"Team","chat_kind":"chat","people":[maya.view().await.unwrap()["identity"]]});
    let created = alex.operate(create.clone()).await.unwrap();
    let stream = created["stream"].clone();
    let c = chat(&created["view"], &stream).clone();
    assert_eq!(c["members"].as_array().unwrap().len(), 2);
    assert_eq!(c["can_post"], true);
    send(&mut alex, &c, "Before Sam joined").await;
    sync(&mut alex).await;
    sync(&mut maya).await;
    assert_eq!(
        chat(&maya.view().await.unwrap(), &stream)["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let add = json!({"op":"contact_add_members","request_id":"02".repeat(16),"space":c["space"],"stream":stream,"people":[sam.view().await.unwrap()["identity"]]});
    let added = alex.operate(add.clone()).await.unwrap();
    let head = chat(&added["view"], &stream)["head"].clone();
    assert_eq!(
        chat(&added["view"], &stream)["members"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    send(&mut alex, &c, "After Sam joined").await;
    sync(&mut alex).await;
    alex.close().await.unwrap();
    sync(&mut sam).await;
    sync(&mut maya).await;
    for person in [&maya, &sam] {
        let view = person.view().await.unwrap();
        let c = chat(&view, &stream);
        assert_eq!(c["members"].as_array().unwrap().len(), 3);
        assert_eq!(c["head"], head);
        assert_eq!(c["can_post"], true);
    }
    let sam_view = sam.view().await.unwrap();
    let received = chat(&sam_view, &stream);
    assert_eq!(
        received["rows"].as_array().unwrap().len(),
        1,
        "adding a contact does not share earlier ciphertext"
    );
    assert_eq!(
        received["rows"][0]["body"]["payload"]["text"],
        "After Sam joined"
    );
    assert_eq!(
        chat(&maya.view().await.unwrap(), &stream)["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    send(&mut sam, &c, "Sam can reply").await;
    sync(&mut sam).await;
    sync(&mut maya).await;
    assert_eq!(
        chat(&maya.view().await.unwrap(), &stream)["rows"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let mut alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(alex.operate(create).await.unwrap()["stream"], stream);
    let repeat = alex.operate(add).await.unwrap();
    assert_eq!(
        chat(&repeat["view"], &stream)["head"],
        head,
        "retry does not append another configuration"
    );
    assert_eq!(repeat["view"]["streams"].as_array().unwrap().len(), 2);
    alex.close().await.unwrap();
    maya.close().await.unwrap();
    sam.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn contact_additions_reject_invalid_scope_selection_and_unauthorized_controller() {
    let dir = tempfile::tempdir().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    contact(&mut alex, &mut maya).await;
    contact(&mut maya, &mut alex).await;
    let server = server(dir.path(), &mut [&mut alex, &mut maya]).await;
    let original = alex.view().await.unwrap();
    let c = original["streams"][0].clone();
    let person = maya.view().await.unwrap()["identity"].clone();
    for people in [
        json!([]),
        json!([original["identity"]]),
        json!([person, person]),
        json!(["ff".repeat(32)]),
        json!([person, "ff".repeat(32)]),
    ] {
        assert!(alex.operate(json!({"op":"contact_add_members","request_id":"10".repeat(16),"space":c["space"],"stream":c["stream"],"people":people})).await.is_err());
        assert_eq!(alex.view().await.unwrap()["streams"][0]["head"], c["head"]);
    }
    let good = json!({"op":"contact_add_members","request_id":"20".repeat(16),"space":c["space"],"stream":c["stream"],"people":[person]});
    alex.operate(good.clone()).await.unwrap();
    sync(&mut alex).await;
    sync(&mut maya).await;
    assert!(maya.operate(json!({"op":"contact_add_members","request_id":"21".repeat(16),"space":c["space"],"stream":c["stream"],"people":[original["identity"]]})).await.is_err());
    let mut changed = good.clone();
    changed["stream"] = json!("aa".repeat(16));
    assert!(alex.operate(changed).await.is_err());
    alex.operate(
        json!({"op":"remove_member","space":c["space"],"stream":c["stream"],"fingerprint":person}),
    )
    .await
    .unwrap();
    assert!(
        alex.operate(good).await.is_err(),
        "retry must not restore a removed member"
    );
    assert_eq!(
        alex.view().await.unwrap()["streams"][0]["members"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    alex.close().await.unwrap();
    maya.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn unknown_sender_requires_global_review_and_the_configuration_is_recipient_bound() {
    let dir = tempfile::tempdir().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    let mut outsider = profile(dir.path(), "Other").await;
    contact(&mut alex, &mut maya).await;
    let server = server(dir.path(), &mut [&mut alex, &mut maya, &mut outsider]).await;
    let created=alex.operate(json!({"op":"contact_create_chat","request_id":"31".repeat(16),"name":"Trip","chat_kind":"chat","people":[maya.view().await.unwrap()["identity"]]})).await.unwrap();
    sync(&mut alex).await;
    alex.close().await.unwrap();
    sync(&mut maya).await;
    sync(&mut outsider).await;
    assert_eq!(
        maya.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let activity = maya
        .operate(json!({"op":"invitation_activity"}))
        .await
        .unwrap();
    assert_eq!(activity["received"].as_array().unwrap().len(), 1);
    assert!(
        outsider
            .operate(json!({"op":"invitation_activity"}))
            .await
            .unwrap()["received"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let link = &activity["received"][0]["link"];
    assert!(
        outsider
            .operate(json!({"op":"invitation_preview","link":link}))
            .await
            .is_err()
    );
    let preview = maya
        .operate(json!({"op":"invitation_preview","link":link}))
        .await
        .unwrap();
    assert!(maya.operate(json!({"op":"invitation_join","link":link,"trusted":false,"confirmed_reference":preview["id"]})).await.is_err());
    maya.operate(json!({"op":"invitation_join","link":link,"trusted":true,"confirmed_reference":preview["id"]})).await.unwrap();
    assert_eq!(
        chat(&maya.view().await.unwrap(), &created["stream"])["can_post"],
        true
    );
    maya.close().await.unwrap();
    outsider.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn removals_reach_offline_chat_and_dm_members_and_exclude_their_message_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    let mut sam = profile(dir.path(), "Sam").await;
    contact(&mut alex, &mut maya).await;
    contact(&mut maya, &mut alex).await;
    contact(&mut alex, &mut sam).await;
    contact(&mut sam, &mut alex).await;
    let server = server(dir.path(), &mut [&mut alex, &mut maya, &mut sam]).await;
    let sam_id = sam.view().await.unwrap()["identity"].clone();
    let sam_keys = vault::Session::open(
        &std::fs::read(dir.path().join("Sam/vault.age")).unwrap(),
        PASSWORD.into(),
        sam_id.as_str().unwrap().parse().unwrap(),
    )
    .unwrap();
    for (nonce, kind) in [("81", "chat"), ("82", "direct")] {
        let created = alex.operate(json!({"op":"contact_create_chat","request_id":nonce.repeat(16),"name":"Alex, Maya, Sam","chat_kind":kind,"people":[maya.view().await.unwrap()["identity"],sam_id]})).await.unwrap();
        let stream = created["stream"].clone();
        let c = chat(&created["view"], &stream).clone();
        send(&mut alex, &c, "A message Sam already has").await;
        sync(&mut alex).await;
        sync(&mut maya).await;
        sync(&mut sam).await;
        assert_eq!(
            chat(&sam.view().await.unwrap(), &stream)["rows"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        sam.close().await.unwrap();
        send(&mut maya, &c, "Old audience, still queued").await;
        let remove =
            json!({"op":"remove_member","space":c["space"],"stream":stream,"fingerprint":sam_id});
        let removed = alex.operate(remove.clone()).await.unwrap();
        let head = chat(&removed["view"], &stream)["head"].clone();
        assert_eq!(
            chat(&alex.operate(remove).await.unwrap()["view"], &stream)["head"],
            head
        );
        alex.close().await.unwrap();
        alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
            .await
            .unwrap();
        sync(&mut alex).await;
        alex.close().await.unwrap();
        // The controller is offline. Maya must apply the reduction before uploading
        // her previously queued ciphertext for the old audience.
        sync(&mut maya).await;
        let updated = maya.view().await.unwrap();
        assert_eq!(chat(&updated, &stream)["head"], head);
        assert_eq!(
            chat(&updated, &stream)["members"].as_array().unwrap().len(),
            2
        );
        assert!(updated["counts"]["held"].as_u64().unwrap() > 0);
        send(&mut maya, &c, "Private after removal").await;
        sync(&mut maya).await;
        let latest = maya.view().await.unwrap();
        let message = chat(&latest, &stream)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["body"]["payload"]["text"] == "Private after removal")
            .unwrap();
        let db = rusqlite::Connection::open(dir.path().join("Maya/client.sqlite")).unwrap();
        let ciphertext: Vec<u8> = db.query_row("SELECT o.ciphertext FROM objects o JOIN record_sources s USING(object_id) WHERE s.record_id=?1",
            [message["id"].as_str().unwrap()], |row| row.get(0)).unwrap();
        assert!(
            elo_core::crypto::open_record(&ciphertext, sam_keys.age_identity()).is_err(),
            "even a copied ciphertext cannot be opened with the removed member's key"
        );
        sam = ClientApp::open(dir.path().join("Sam"), PASSWORD.into(), true)
            .await
            .unwrap();
        sync(&mut sam).await;
        let updated = sam.view().await.unwrap();
        let removed_chat = chat(&updated, &stream);
        assert_eq!(removed_chat["head"], head);
        assert_eq!(removed_chat["can_post"], false);
        assert!(updated["invitations"]["notifications"].as_u64().unwrap() > 0);
        let activity = sam
            .operate(json!({"op":"invitation_activity"}))
            .await
            .unwrap();
        let notices = activity["notices"].as_array().unwrap();
        assert!(
            notices
                .iter()
                .any(|entry| entry["stream"] == stream && entry["seen"] == false)
        );
        let ids: Vec<_> = notices.iter().map(|entry| entry["id"].clone()).collect();
        let read = sam
            .operate(json!({"op":"invitation_notifications_seen","ids":ids}))
            .await
            .unwrap();
        assert_eq!(read["view"]["invitations"]["notifications"], 0);

        assert_eq!(
            removed_chat["rows"].as_array().unwrap().len(),
            1,
            "previously received history remains, new ciphertext is excluded"
        );
        assert!(sam.operate(json!({"op":"send","space":c["space"],"stream":stream,"text":"Should not post","created_at":"2026-09-11T19:00:00Z"})).await.is_err());
        sam.close().await.unwrap();
        sam = ClientApp::open(dir.path().join("Sam"), PASSWORD.into(), true)
            .await
            .unwrap();
        assert_eq!(chat(&sam.view().await.unwrap(), &stream)["head"], head);
        alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
            .await
            .unwrap();
    }
    alex.close().await.unwrap();
    maya.close().await.unwrap();
    sam.close().await.unwrap();
    server.abort();
}

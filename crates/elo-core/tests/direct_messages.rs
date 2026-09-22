use elo_core::{
    app::{ClientApp, ProfileDraft},
    replica::ReplicaStore,
    vault,
};
use serde_json::{Value, json};
use tempfile::TempDir;
const PASSWORD: &str = "synthetic direct-message test password";
fn scope(chat: &Value, op: &str) -> Value {
    json!({"op":op,"space":chat["space"],"stream":chat["stream"]})
}
fn chat<'a>(view: &'a Value, stream: &Value) -> &'a Value {
    view["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|chat| chat["stream"] == *stream)
        .unwrap()
}
async fn profile(root: &std::path::Path, name: &str) -> ClientApp {
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
async fn request(app: &mut ClientApp, link: &Value) -> Value {
    let preview = app
        .operate(json!({"op":"invitation_preview","link":link}))
        .await
        .unwrap();
    let name = app.view().await.unwrap()["name"].clone();
    app.operate(json!({"op":"invitation_request","link":link,"trusted":true,"confirmed_invitation":preview["id"],"name":name})).await.unwrap()
}
async fn approve(app: &mut ClientApp, id: &Value, identity: &Value) -> Value {
    app.operate(json!({"op":"invitation_approve","id":id,"confirmed":true,"confirmed_identity":identity,"post":true})).await.unwrap()
}
async fn join(app: &mut ClientApp, link: &Value) {
    let preview = app
        .operate(json!({"op":"invitation_preview","link":link}))
        .await
        .unwrap();
    app.operate(json!({"op":"invitation_join","link":link,"trusted":true,"confirmed_reference":preview["id"]})).await.unwrap();
}
async fn make_known(owner: &mut ClientApp, person: &mut ClientApp) {
    let mut create = scope(
        &owner.view().await.unwrap()["streams"][0],
        "invitation_create",
    );
    create["automatic"] = json!(false);
    create["post"] = json!(true);
    let offer = owner.operate(create).await.unwrap();
    let request = request(person, &offer["link"]).await;
    let incoming = owner
        .operate(json!({"op":"invitation_receive","link":request["link"]}))
        .await
        .unwrap();
    let grant = approve(
        owner,
        &incoming["id"],
        &person.view().await.unwrap()["identity"],
    )
    .await;
    join(person, &grant["link"]).await;
}
async fn sync(app: &mut ClientApp) -> Value {
    app.operate(json!({"op":"invitation_sync","force":true}))
        .await
        .unwrap()
}
async fn activity(app: &mut ClientApp) -> Value {
    app.operate(json!({"op":"invitation_activity"}))
        .await
        .unwrap()
}

#[tokio::test]
async fn selected_dm_invites_are_private_durable_and_complete_group_membership_in_any_join_order() {
    let dir = TempDir::new().unwrap();
    let mut owner = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    let mut sam = profile(dir.path(), "Sam").await;
    let mut outsider = profile(dir.path(), "Other").await;
    make_known(&mut owner, &mut maya).await;
    make_known(&mut owner, &mut sam).await;
    make_known(&mut owner, &mut outsider).await;
    let replica = ReplicaStore::open(dir.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(64 * 1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let descriptor = json!({"url":format!("http://{}",listener.local_addr().unwrap()),"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
    let path = dir.path().join("peer.json");
    vault::write_private(&path, &serde_json::to_vec(&descriptor).unwrap(), false).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, elo_core::http::router(replica))
            .await
            .unwrap()
    });
    for app in [&mut owner, &mut maya, &mut sam, &mut outsider] {
        app.operate(json!({"op":"add_peer","path":path}))
            .await
            .unwrap();
    }
    let maya_id = maya.view().await.unwrap()["identity"].clone();
    let sam_id = sam.view().await.unwrap()["identity"].clone();
    let create = json!({"op":"create_dm","request_id":"1234567890abcdef1234567890abcdef","people":[maya_id,sam_id],"name":"Alex, Maya, Sam"});
    let created = owner.operate(create.clone()).await.unwrap();
    let stream = created["stream"].clone();
    let channel = chat(&created["view"], &stream);
    assert_eq!(channel["chat_kind"], "direct");
    assert_eq!(
        channel["members"].as_array().unwrap().len(),
        1,
        "selection is not membership approval"
    );
    assert_eq!(
        channel["direct_invitation"]["pending"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let link = channel["direct_invitation"]["link"].clone();
    let retried = owner.operate(create.clone()).await.unwrap();
    assert_eq!(retried["stream"], stream);
    assert_eq!(
        chat(&retried["view"], &stream)["direct_invitation"]["link"],
        link
    );
    assert!(
        outsider
            .operate(json!({"op":"invitation_preview","link":link}))
            .await
            .is_err()
    );
    // Bypass the UI with a genuinely signed request from an unselected person.
    // Invitation identity binding is enforced by the native receiver as well.
    {
        use base64::{
            Engine,
            engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        };
        use std::io::{Read, Write};
        let bytes = URL_SAFE_NO_PAD
            .decode(link.as_str().unwrap().split('#').nth(1).unwrap())
            .unwrap();
        let mut plain = Vec::new();
        flate2::read::ZlibDecoder::new(bytes.as_slice())
            .read_to_end(&mut plain)
            .unwrap();
        let packet: Value = serde_json::from_slice(&plain).unwrap();
        let invitation = elo_core::record::SignedRecord::parse(
            &STANDARD
                .decode(packet["bundle"]["invitation"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let identity = outsider.view().await.unwrap()["identity"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let session = vault::Session::open(
            &vault::read_private(&dir.path().join("Other/vault.age")).unwrap(),
            PASSWORD.into(),
            identity,
        )
        .unwrap();
        let request = elo_core::invite::shared::Request {
            wake: None,
            v: 1,
            kind: "space.join.shared".into(),
            nonce: "abcdefabcdefabcdefabcdefabcdefab".into(),
            invite_id: invitation.id(),
            issuer_identity: session.identity_id(),
            issuer_credential: session.credential().id(),
            name: "Other".into(),
            delivery: None,
        };
        let signed = elo_core::record::SignedRecord::sign(
            &serde_json::to_vec(&request).unwrap(),
            session.signing_key(),
        )
        .unwrap();
        let forged = json!({"kind":"Request","bundle":packet["bundle"],"request":STANDARD.encode(signed.bytes()),"credential":STANDARD.encode(session.credential().record().bytes())});
        let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zip.write_all(&serde_json::to_vec(&forged).unwrap())
            .unwrap();
        let link = format!(
            "elo://exchange/v1#{}",
            URL_SAFE_NO_PAD.encode(zip.finish().unwrap())
        );
        assert!(
            owner
                .operate(json!({"op":"invitation_receive","link":link}))
                .await
                .is_err()
        );
        assert_eq!(
            chat(&owner.view().await.unwrap(), &stream)["members"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    sync(&mut owner).await;
    owner.close().await.unwrap();
    for app in [&mut maya, &mut sam, &mut outsider] {
        sync(app).await;
    }
    let received = activity(&mut maya).await;
    assert_eq!(received["received"].as_array().unwrap().len(), 1);
    assert_eq!(
        activity(&mut outsider).await["received"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "other shared-mailbox users cannot see an addressed offer"
    );
    assert_eq!(
        maya.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "delivery does not join"
    );
    request(&mut maya, &received["received"][0]["link"]).await;
    sync(&mut maya).await;
    let mut owner = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(owner.operate(create).await.unwrap()["stream"], stream);
    sync(&mut owner).await;
    let incoming = activity(&mut owner).await;
    let grant = approve(&mut owner, &incoming["incoming"][0]["id"], &maya_id).await;
    sync(&mut owner).await;
    sync(&mut maya).await;
    assert_eq!(
        activity(&mut maya).await["outgoing"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["stream"] == stream && entry["status"] == "approved")
            .count(),
        1
    );
    join(&mut maya, &grant["link"]).await;
    assert_eq!(
        chat(&maya.view().await.unwrap(), &stream)["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let received = activity(&mut sam).await;
    request(&mut sam, &received["received"][0]["link"]).await;
    sync(&mut sam).await;
    sync(&mut owner).await;
    let incoming = activity(&mut owner).await;
    let id = incoming["incoming"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["stream"] == stream)
        .unwrap()["id"]
        .clone();
    approve(&mut owner, &id, &sam_id).await;
    sync(&mut owner).await;
    sync(&mut maya).await;
    sync(&mut sam).await;
    assert_eq!(
        chat(&maya.view().await.unwrap(), &stream)["members"]
            .as_array()
            .unwrap()
            .len(),
        3,
        "earlier Join receives the remaining originally selected member"
    );
    let outgoing = activity(&mut sam).await;
    let grant = outgoing["outgoing"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["stream"] == stream)
        .unwrap()["link"]
        .clone();
    join(&mut sam, &grant).await;
    let dm = chat(&maya.view().await.unwrap(), &stream).clone();
    let mut send = scope(&dm, "send");
    send["text"] = json!("Private group DM test");
    send["created_at"] = json!("2026-09-10T20:00:00Z");
    maya.operate(send).await.unwrap();
    maya.operate(json!({"op":"sync"})).await.unwrap();
    maya.close().await.unwrap();
    sam.operate(json!({"op":"sync"})).await.unwrap();
    let received = chat(&sam.view().await.unwrap(), &stream).clone();
    assert_eq!(
        received["rows"][0]["body"]["payload"]["text"],
        "Private group DM test"
    );
    sam.close().await.unwrap();
    let sam = ClientApp::open(dir.path().join("Sam"), PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(
        chat(&sam.view().await.unwrap(), &stream)["rows"],
        received["rows"]
    );
    for filename in ["invitations.age", "workspace.age"] {
        let raw = std::fs::read(dir.path().join("Alex").join(filename)).unwrap();
        assert!(!raw.windows(15).any(|window| window == b"Alex, Maya, Sam"));
    }
    sam.close().await.unwrap();
    owner.close().await.unwrap();
    outsider.close().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn dm_rejects_unverified_people_self_duplicates_and_changed_retry_before_creating_a_chat() {
    let dir = TempDir::new().unwrap();
    let mut owner = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    let own = owner.view().await.unwrap()["identity"].clone();
    let other = maya.view().await.unwrap()["identity"].clone();
    let mut create = json!({"op":"create_dm","request_id":"234567890abcdef1234567890abcdef1","people":[],"name":"Alex, Maya"});
    for people in [
        json!([]),
        json!([own]),
        json!([other]),
        json!([other, other]),
    ] {
        create["people"] = people;
        assert!(owner.operate(create.clone()).await.is_err());
        assert_eq!(
            owner.view().await.unwrap()["streams"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    make_known(&mut owner, &mut maya).await;
    create["people"] = json!([other]);
    let result = owner.operate(create.clone()).await.unwrap();
    assert_eq!(
        chat(&result["view"], &result["stream"])["direct_invitation"]["automatic"],
        false
    );
    create["name"] = json!("Changed retry");
    assert!(owner.operate(create).await.is_err());
    assert_eq!(
        owner.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    owner.close().await.unwrap();
    maya.close().await.unwrap();
}

#[tokio::test]
async fn named_chats_use_the_same_selected_people_flow_and_preserve_group_on_retry() {
    let dir = TempDir::new().unwrap();
    let mut owner = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    make_known(&mut owner, &mut maya).await;
    let group = owner
        .operate(json!({"op":"create_group","name":"Work"}))
        .await
        .unwrap()["view"]["groups"][0]["id"]
        .clone();
    let create = json!({"op":"create_dm","request_id":"ab34567890abcdef1234567890abcdef","people":[maya.view().await.unwrap()["identity"]],"name":"Design","chat_kind":"chat","group":group});
    let result = owner.operate(create.clone()).await.unwrap();
    let created = chat(&result["view"], &result["stream"]);
    assert_eq!(created["name"], "Design");
    assert_eq!(created["chat_kind"], "chat");
    assert_eq!(created["group"], group);
    assert_eq!(created["members"].as_array().unwrap().len(), 1);
    let request = request(&mut maya, &created["direct_invitation"]["link"]).await;
    let incoming = owner
        .operate(json!({"op":"invitation_receive","link":request["link"]}))
        .await
        .unwrap();
    let grant = approve(
        &mut owner,
        &incoming["id"],
        &maya.view().await.unwrap()["identity"],
    )
    .await;
    join(&mut maya, &grant["link"]).await;
    assert_eq!(
        chat(&maya.view().await.unwrap(), &result["stream"])["chat_kind"],
        "chat"
    );
    assert_eq!(
        chat(&maya.view().await.unwrap(), &result["stream"])["group"],
        Value::Null,
        "groups are personal"
    );
    owner.close().await.unwrap();
    let mut owner = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(
        owner.operate(create.clone()).await.unwrap()["stream"],
        result["stream"]
    );
    let mut changed = create;
    changed["chat_kind"] = json!("direct");
    changed["group"] = json!("");
    assert!(owner.operate(changed).await.is_err());
    owner.close().await.unwrap();
    maya.close().await.unwrap();
}

#[tokio::test]
async fn actions_cross_a_real_replica_without_the_author_online_and_private_markers_survive_restart()
 {
    let dir = TempDir::new().unwrap();
    let mut owner = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    make_known(&mut owner, &mut maya).await;
    let replica = ReplicaStore::open(dir.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(64 * 1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let descriptor = json!({"url":format!("http://{}",listener.local_addr().unwrap()),"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
    let peer = dir.path().join("peer.json");
    vault::write_private(&peer, &serde_json::to_vec(&descriptor).unwrap(), false).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, elo_core::http::router(replica))
            .await
            .unwrap()
    });
    for app in [&mut owner, &mut maya] {
        app.operate(json!({"op":"add_peer","path":peer}))
            .await
            .unwrap();
    }
    let channel = owner.view().await.unwrap()["streams"][0].clone();
    let mut send = scope(&channel, "send");
    send["text"] = json!("Synthetic private pinned text");
    send["created_at"] = json!("2026-09-11T23:00:00Z");
    let sent = owner.operate(send).await.unwrap();
    let row = chat(&sent["view"], &channel["stream"])["rows"][0].clone();
    let mut event = scope(&channel, "message_action");
    event["created_at"] = json!("2026-09-11T23:01:00Z");
    event["action"] = json!({"type":"reaction","target":row["id"],"emoji":"👍","active":true});
    owner.operate(event.clone()).await.unwrap();
    let mut pin = event.clone();
    pin["action"] = json!({"type":"pin","target":row["id"],"active":true});
    owner.operate(pin.clone()).await.unwrap();
    owner.operate(json!({"op":"sync"})).await.unwrap();
    owner.close().await.unwrap();
    let sync = maya.operate(json!({"op":"sync"})).await.unwrap();
    assert_eq!(
        sync["result"]["received_messages"],
        json!([row["id"]]),
        "reactions and pins never produce message alerts"
    );
    let received = maya.view().await.unwrap();
    let rows = &chat(&received, &channel["stream"])["rows"];
    assert_eq!(
        rows.as_array().unwrap().len(),
        1,
        "actions are not messages"
    );
    assert_eq!(rows[0]["reactions"][0]["count"], 1);
    assert_eq!(rows[0]["pinned"], true);
    assert_eq!(chat(&received, &channel["stream"])["unread_count"], 1);
    maya.operate(event.clone()).await.unwrap();
    let repeated = maya.operate(event.clone()).await.unwrap();
    assert_eq!(
        chat(&repeated["view"], &channel["stream"])["rows"][0]["reactions"][0]["count"],
        2,
        "one reaction per identity, not per event"
    );
    event["action"]["active"] = json!(false);
    maya.operate(event.clone()).await.unwrap();
    pin["action"]["active"] = json!(false);
    maya.operate(pin).await.unwrap();
    let mut mark = scope(&channel, "mark_read");
    mark["records"] = json!([row["id"]]);
    maya.operate(mark.clone()).await.unwrap();
    mark["op"] = json!("mark_unread");
    maya.operate(mark.clone()).await.unwrap();
    let due = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + 60_000;
    let mut remind = scope(&channel, "remind");
    remind["record"] = row["id"].clone();
    remind["due_at"] = json!(due);
    let initial = maya.operate(remind.clone()).await.unwrap();
    assert_eq!(
        initial["view"]["reminders"][0]["system_notification"],
        false
    );
    remind["system_notification"] = json!(true);
    maya.operate(remind.clone()).await.unwrap();
    let mut bad = remind.clone();
    bad["due_at"] = json!(1);
    assert!(maya.operate(bad).await.is_err());
    let mut bad = event.clone();
    bad["action"]["target"] = json!("00".repeat(32));
    assert!(maya.operate(bad).await.is_err());
    let mut bad = event;
    bad["action"]["emoji"] = json!("<script>");
    assert!(maya.operate(bad).await.is_err());
    maya.operate(json!({"op":"sync"})).await.unwrap();
    maya.close().await.unwrap();
    let mut owner = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
        .await
        .unwrap();
    owner.operate(json!({"op":"sync"})).await.unwrap();
    let owner_view = owner.view().await.unwrap();
    let own_row = &chat(&owner_view, &channel["stream"])["rows"][0];
    assert_eq!(own_row["reactions"][0]["count"], 1);
    assert_eq!(own_row["reactions"][0]["mine"], true);
    assert_eq!(own_row["pinned"], false);
    assert!(
        owner_view["reminders"].as_array().unwrap().is_empty(),
        "personal reminder must not travel through the replica"
    );
    let own_unread = owner.operate(mark.clone()).await.unwrap();
    assert_eq!(
        chat(&own_unread["view"], &channel["stream"])["rows"][0]["unread"],
        true,
        "own messages can be marked unread"
    );
    let mut maya = ClientApp::open(dir.path().join("Maya"), PASSWORD.into(), true)
        .await
        .unwrap();
    let restarted = maya.view().await.unwrap();
    assert_eq!(restarted["reminders"][0]["record"], row["id"]);
    assert_eq!(restarted["reminders"][0]["due_at"], due);
    assert_eq!(restarted["reminders"][0]["system_notification"], true);
    assert_eq!(
        chat(&restarted, &channel["stream"])["rows"][0]["unread"],
        true
    );
    mark["op"] = json!("mark_read");
    assert_eq!(
        chat(
            &maya.operate(mark).await.unwrap()["view"],
            &channel["stream"]
        )["unread_count"],
        0
    );
    remind["op"] = json!("reminder_remove");
    assert!(
        maya.operate(remind).await.unwrap()["view"]["reminders"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    owner.close().await.unwrap();
    maya.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn saved_contacts_require_review_survive_restart_and_start_dm_without_shared_membership() {
    let dir = TempDir::new().unwrap();
    let mut owner = profile(dir.path(), "Alex").await;
    let mut person = profile(dir.path(), "Maya").await;
    let card = person
        .operate(json!({"op":"contact_create","name":"Maya"}))
        .await
        .unwrap();
    let preview = owner
        .operate(json!({"op":"contact_preview","link":card["link"]}))
        .await
        .unwrap();
    assert_eq!(preview["kind"], "contact");
    let incoming_link = owner
        .operate(json!({"op":"invitation_preview","link":card["link"]}))
        .await
        .unwrap();
    assert_eq!(
        incoming_link, preview,
        "a contact link opened outside a chat must not invite into the selected chat"
    );
    assert!(
        owner.view().await.unwrap()["contacts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for (trusted, confirmed) in [(false, preview["id"].clone()), (true, json!("wrong"))] {
        assert!(owner.operate(json!({"op":"contact_add","link":card["link"],"trusted":trusted,"confirmed_contact":confirmed})).await.is_err());
    }
    assert!(
        person
            .operate(json!({"op":"contact_preview","link":card["link"]}))
            .await
            .is_err()
    );
    let add = json!({"op":"contact_add","link":card["link"],"trusted":true,"confirmed_contact":preview["id"]});
    owner.operate(add.clone()).await.unwrap();
    owner.operate(add).await.unwrap();
    let saved = owner.view().await.unwrap();
    assert_eq!(saved["contacts"].as_array().unwrap().len(), 1);
    assert_eq!(saved["contacts"][0]["name"], "Maya");
    assert_eq!(saved["streams"][0]["members"].as_array().unwrap().len(), 1);
    owner.close().await.unwrap();
    let mut owner = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(owner.view().await.unwrap()["contacts"], saved["contacts"]);
    let created = owner.operate(json!({"op":"create_dm","request_id":"55555555555555555555555555555555","people":[preview["identity"]],"name":"Alex, Maya"})).await.unwrap();
    let dm = chat(&created["view"], &created["stream"]);
    assert_eq!(dm["members"].as_array().unwrap().len(), 1);
    let link = dm["direct_invitation"]["link"].clone();
    assert!(
        owner
            .operate(json!({"op":"contact_preview","link":link}))
            .await
            .is_err()
    );
    let request = request(&mut person, &link).await;
    let received = owner
        .operate(json!({"op":"invitation_receive","link":request["link"]}))
        .await
        .unwrap();
    let grant = approve(&mut owner, &received["id"], &preview["identity"]).await;
    assert_eq!(
        person.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "Contact exchange must not silently join a chat"
    );
    join(&mut person, &grant["link"]).await;
    assert_eq!(
        chat(&person.view().await.unwrap(), &created["stream"])["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    owner.close().await.unwrap();
    person.close().await.unwrap();
}

async fn save_contact(owner: &mut ClientApp, person: &mut ClientApp) {
    let name = person.view().await.unwrap()["name"].clone();
    let code = person
        .operate(json!({"op":"contact_create","name":name}))
        .await
        .unwrap();
    let preview = owner
        .operate(json!({"op":"contact_preview","link":code["link"]}))
        .await
        .unwrap();
    owner.operate(json!({"op":"contact_add","link":code["link"],"trusted":true,"confirmed_contact":preview["id"]})).await.unwrap();
}

#[tokio::test]
async fn contact_tap_reuses_one_to_one_upgrades_only_its_pending_dm_and_sends_immediately() {
    let dir = TempDir::new().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    save_contact(&mut alex, &mut maya).await;
    let id = maya.view().await.unwrap()["identity"].clone();
    let legacy = alex.operate(json!({"op":"create_dm","request_id":"66666666666666666666666666666666","people":[id],"name":"Alex, Maya"})).await.unwrap();
    let open = json!({"op":"contact_open","identity":id,"name":"Maya"});
    let result = alex.operate(open.clone()).await.unwrap();
    assert_eq!(result["stream"], legacy["stream"]);
    let dm = chat(&result["view"], &result["stream"]);
    assert_eq!(dm["name"], "Maya");
    assert_eq!(dm["members"].as_array().unwrap().len(), 2);
    assert_eq!(dm["can_post"], true);
    let mut send = scope(dm, "send");
    send["text"] = json!("Ready before any network connection");
    send["created_at"] = json!("2026-09-11T10:00:00Z");
    alex.operate(send).await.unwrap();
    alex.close().await.unwrap();
    let mut alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
        .await
        .unwrap();
    let repeated = alex.operate(open).await.unwrap();
    assert_eq!(repeated["stream"], result["stream"]);
    assert_eq!(repeated["view"]["streams"].as_array().unwrap().len(), 2);
    assert_eq!(
        chat(&repeated["view"], &result["stream"])["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let unknown = "77".repeat(32);
    assert!(
        alex.operate(json!({"op":"contact_open","identity":unknown,"name":"Unknown"}))
            .await
            .is_err()
    );
    alex.close().await.unwrap();
    maya.close().await.unwrap();
}

#[tokio::test]
async fn personal_dm_bootstrap_and_message_survive_sender_offline_with_explicit_stranger_review() {
    let dir = TempDir::new().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    let mut sam = profile(dir.path(), "Sam").await;
    save_contact(&mut alex, &mut maya).await;
    save_contact(&mut alex, &mut sam).await;
    save_contact(&mut maya, &mut alex).await;
    let replica = ReplicaStore::open(dir.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(64 * 1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let descriptor = json!({"url":format!("http://{}",listener.local_addr().unwrap()),"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
    let path = dir.path().join("peer.json");
    vault::write_private(&path, &serde_json::to_vec(&descriptor).unwrap(), false).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, elo_core::http::router(replica))
            .await
            .unwrap()
    });
    for app in [&mut alex, &mut maya, &mut sam] {
        app.operate(json!({"op":"add_peer","path":path}))
            .await
            .unwrap();
    }
    let mut streams = Vec::new();
    for person in [&maya, &sam] {
        let view = person.view().await.unwrap();
        let created = alex
            .operate(json!({"op":"contact_open","identity":view["identity"],"name":view["name"]}))
            .await
            .unwrap();
        let dm = chat(&created["view"], &created["stream"]);
        let mut send = scope(dm, "send");
        send["text"] = json!("Sent before the other person opened this DM");
        send["created_at"] = json!("2026-09-11T10:01:00Z");
        alex.operate(send).await.unwrap();
        streams.push(created["stream"].clone());
    }
    alex.operate(json!({"op":"sync"})).await.unwrap();
    alex.close().await.unwrap();
    maya.operate(json!({"op":"sync"})).await.unwrap();
    let received = maya.view().await.unwrap();
    let dm = chat(&received, &streams[0]);
    assert_eq!(dm["name"], "Alex");
    assert_eq!(dm["can_post"], true);
    assert_eq!(dm["rows"].as_array().unwrap().len(), 1);
    assert_eq!(
        received["streams"].as_array().unwrap().len(),
        2,
        "known contact imports only their own DM"
    );
    let opened = maya
        .operate(
            json!({"op":"contact_open","identity":received["contacts"][0]["id"],"name":"Alex"}),
        )
        .await
        .unwrap();
    assert_eq!(
        opened["stream"], streams[0],
        "opening from the other side reuses the same DM"
    );
    sam.operate(json!({"op":"sync"})).await.unwrap();
    assert_eq!(
        sam.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "an unknown sender cannot silently join a profile"
    );
    let pending = activity(&mut sam).await;
    assert_eq!(pending["received"].as_array().unwrap().len(), 1);
    let link = pending["received"][0]["link"].clone();
    let preview = sam
        .operate(json!({"op":"invitation_preview","link":link}))
        .await
        .unwrap();
    assert!(sam.operate(json!({"op":"invitation_join","link":link,"trusted":false,"confirmed_reference":preview["id"]})).await.is_err());
    assert!(
        maya.operate(json!({"op":"invitation_preview","link":link}))
            .await
            .is_err(),
        "another recipient cannot use this bootstrap"
    );
    join(&mut sam, &link).await;
    sam.operate(json!({"op":"sync"})).await.unwrap();
    assert_eq!(
        chat(&sam.view().await.unwrap(), &streams[1])["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    maya.close().await.unwrap();
    sam.close().await.unwrap();
    let maya = ClientApp::open(dir.path().join("Maya"), PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(
        chat(&maya.view().await.unwrap(), &streams[0])["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    maya.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn discovery_backlog_resumes_without_poll_delay_and_delivers_a_new_dm_once() {
    use axum::response::IntoResponse;
    use elo_core::{ids::ObjectId, replica::TransferHint};
    let dir = TempDir::new().unwrap();
    let mut alex = profile(dir.path(), "Alex").await;
    let mut maya = profile(dir.path(), "Maya").await;
    save_contact(&mut alex, &mut maya).await;
    save_contact(&mut maya, &mut alex).await;
    let replica = ReplicaStore::open(dir.path().join("replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(64 * 1024 * 1024).await.unwrap();
    // Older unrelated envelopes must not impose a 30-second pause per batch.
    for n in 0..25u8 {
        let bytes = vec![n; 256];
        replica
            .post(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                ObjectId::of_ciphertext(&bytes),
                bytes,
                TransferHint::Lazy,
            )
            .await
            .unwrap();
    }
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let descriptor = json!({"url":format!("http://{}",listener.local_addr().unwrap()),"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
    let path = dir.path().join("peer.json");
    vault::write_private(&path, &serde_json::to_vec(&descriptor).unwrap(), false).unwrap();
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let armed = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let fail_armed = armed.clone();
    let fail_reads = reads.clone();
    let router = elo_core::http::router(replica).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let armed = fail_armed.clone();
            let reads = fail_reads.clone();
            async move {
                if armed.load(Ordering::SeqCst)
                    && request.method() == axum::http::Method::GET
                    && request.uri().path().contains("/objects/")
                    && reads.fetch_add(1, Ordering::SeqCst) == 9
                {
                    return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                next.run(request).await
            }
        },
    ));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    for app in [&mut alex, &mut maya] {
        app.operate(json!({"op":"add_peer","path":path}))
            .await
            .unwrap();
    }
    let created = alex
        .operate(json!({"op":"contact_open","identity":maya.identity_id(),"name":"Maya"}))
        .await
        .unwrap();
    let mut send = scope(chat(&created["view"], &created["stream"]), "send");
    send["text"] = json!("After the old discovery backlog");
    send["created_at"] = json!("2026-09-13T18:00:00Z");
    alex.operate(send).await.unwrap();
    alex.operate(json!({"op":"sync"})).await.unwrap();
    alex.close().await.unwrap();
    armed.store(true, Ordering::SeqCst);
    maya.enable_spaces().await.unwrap();
    let first = maya
        .operate(json!({"op":"invitation_sync","foreground":true}))
        .await
        .unwrap();
    assert_eq!(first["delivery"]["more"], true);
    assert_eq!(first["delivery"]["retry"], 0);
    maya.close().await.unwrap();
    let mut maya = ClientApp::open(dir.path().join("Maya"), PASSWORD.into(), true)
        .await
        .unwrap();
    maya.enable_spaces().await.unwrap();
    let mut drained = false;
    let mut partial_failure = false;
    for _ in 0..8 {
        // No force flag and no sleep: persisted backlog remains immediately due.
        let report = maya
            .operate(json!({"op":"invitation_sync","foreground":true}))
            .await
            .unwrap();
        if report["delivery"]["retry"] == 1 {
            assert_eq!(report["delivery"]["progressed"], true);
            assert_eq!(report["delivery"]["more"], true);
            partial_failure = true;
        } else {
            assert_eq!(report["delivery"]["retry"], 0);
        }
        if report["delivery"]["more"] == false {
            drained = true;
            break;
        }
    }
    assert!(drained, "bounded discovery pages must reach idle");
    assert!(
        partial_failure,
        "the injected failure must preserve committed progress"
    );
    let view = maya.view().await.unwrap();
    assert_eq!(chat(&view, &created["stream"])["name"], "Alex");
    maya.operate(json!({"op":"sync_live"})).await.unwrap();
    let view = maya.view().await.unwrap();
    let rows = chat(&view, &created["stream"])["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["body"]["payload"]["text"],
        "After the old discovery backlog"
    );
    maya.operate(json!({"op":"invitation_sync","force":true,"foreground":true}))
        .await
        .unwrap();
    maya.operate(json!({"op":"sync_live"})).await.unwrap();
    assert_eq!(
        chat(&maya.view().await.unwrap(), &created["stream"])["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    maya.close().await.unwrap();
    server.abort();
}

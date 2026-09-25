use elo_core::{
    app::ClientApp,
    replica::ReplicaStore,
    store::ClientStore,
    vault::{self, Session},
};
use serde_json::{Value, json};
use tempfile::TempDir;
const PASSWORD: &str = "synthetic desktop integration passphrase";
async fn profile(path: &std::path::Path, recovery: &std::path::Path) -> Value {
    let (session, card) = Session::create().unwrap();
    let store = ClientStore::open(path).await.unwrap();
    let public =
        json!({"identity_id":session.identity_id(),"credential_id":session.credential().id()});
    vault::write_private(
        &path.join("profile.json"),
        &serde_json::to_vec(&public).unwrap(),
        false,
    )
    .unwrap();
    vault::write_private(
        &path.join("vault.age"),
        &session.seal(PASSWORD.into()).unwrap(),
        false,
    )
    .unwrap();
    vault::write_private(recovery, &serde_json::to_vec(&card).unwrap(), false).unwrap();
    store.close().await.unwrap();
    public
}
fn scope(view: &Value, op: &str) -> Value {
    let s = &view["streams"][0];
    json!({"op":op,"space":s["space"],"stream":s["stream"]})
}
async fn send(app: &mut ClientApp, text: &str) -> Value {
    let view = app.view().await.unwrap();
    let mut v = scope(&view, "send");
    v["text"] = json!(text);
    v["created_at"] = json!("2026-09-09T12:00:00Z");
    app.operate(v).await.unwrap()["view"].clone()
}
#[tokio::test]
async fn real_profiles_join_sync_explicit_history_files_revoke_and_restart() {
    let d = TempDir::new().unwrap();
    let owner_dir = d.path().join("owner");
    let reader_dir = d.path().join("reader");
    let card = d.path().join("owner-recovery.json");
    let owner_public = profile(&owner_dir, &card).await;
    let reader_public = profile(&reader_dir, &d.path().join("reader-recovery.json")).await;
    let replica = ReplicaStore::open(d.path().join("replica")).await.unwrap();
    let mailbox = replica.create_mailbox(64 * 1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let descriptor = json!({"url":url,"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
    let peer = d.path().join("peer.json");
    vault::write_private(&peer, &serde_json::to_vec(&descriptor).unwrap(), false).unwrap();
    let server = tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, elo_core::http::router(replica, &origin))
        }
        .await
        .unwrap()
    });
    let mut owner = ClientApp::open(owner_dir.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    let first = owner
        .operate(json!({"op":"create_space","name":"Test channel","recovery_card":card}))
        .await
        .unwrap()["view"]
        .clone();
    owner
        .operate(json!({"op":"add_peer","path":peer}))
        .await
        .unwrap();
    let before = send(
        &mut owner,
        "PUBLIC BEFORE JOIN — not present in reader plaintext",
    )
    .await;
    assert_eq!(before["streams"][0]["rows"][0]["state"], "QUEUED");
    owner.operate(json!({"op":"sync"})).await.unwrap();
    assert_eq!(
        owner.view().await.unwrap()["streams"][0]["rows"][0]["state"],
        "STORED"
    );
    let invite = d.path().join("invite.json");
    let mut v = scope(&first, "invite_create");
    v["output"] = json!(invite);
    owner.operate(v).await.unwrap();
    let exchange: Value = serde_json::from_slice(&std::fs::read(&invite).unwrap()).unwrap();
    let mut reader = ClientApp::open(reader_dir.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    let join = d.path().join("join.json");
    reader.operate(json!({"op":"invite_request","path":invite,"space":exchange["space"],"root":exchange["root"],"output":join})).await.unwrap();
    let config = d.path().join("reader-config.age");
    let mut approve = scope(&first, "invite_approve");
    approve["path"] = json!(join);
    approve["fingerprint"] = owner_public["identity_id"].clone();
    approve["output"] = json!(config);
    assert!(owner.operate(approve.clone()).await.is_err());
    assert!(!config.exists());
    approve["fingerprint"] = reader_public["identity_id"].clone();
    approve["post"] = json!(true);
    owner.operate(approve).await.unwrap();
    reader.operate(json!({"op":"import_stream","path":config,"space":exchange["space"],"stream":exchange["stream"],"root":exchange["root"],"name":"Joined channel"})).await.unwrap();
    // An unavailable first peer must not prevent the surviving second peer.
    let dead = d.path().join("dead-peer.json");
    let mut dead_descriptor = descriptor.clone();
    dead_descriptor["url"] = json!("http://127.0.0.1:9/");
    dead_descriptor["signing_public_key"] = json!(elo_core::record::encode_hex(
        ed25519_dalek::SigningKey::from_bytes(&[101; 32])
            .verifying_key()
            .as_bytes()
    ));
    dead_descriptor["write_token"] = Value::Null;
    vault::write_private(&dead, &serde_json::to_vec(&dead_descriptor).unwrap(), false).unwrap();
    reader
        .operate(json!({"op":"add_peer","path":dead}))
        .await
        .unwrap();
    reader
        .operate(json!({"op":"add_peer","path":peer}))
        .await
        .unwrap();
    reader.operate(json!({"op":"sync"})).await.unwrap();
    assert_eq!(
        reader.view().await.unwrap()["streams"][0]["rows"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    owner
        .operate(json!({"op":"set_profile_name", "name":"Alex River"}))
        .await
        .unwrap();
    send(&mut owner, "PUBLIC AFTER JOIN").await;
    owner.operate(json!({"op":"sync"})).await.unwrap();
    reader.operate(json!({"op":"sync"})).await.unwrap();
    let received = reader.view().await.unwrap();
    let owner_id = owner_public["identity_id"].as_str().unwrap();
    assert_eq!(
        received["streams"][0]["member_names"][owner_id],
        "Alex River"
    );
    assert_eq!(
        received["streams"][0]["rows"][0]["body"]["payload"]["sender_name"],
        "Alex River"
    );
    assert_eq!(received["streams"][0]["rows"].as_array().unwrap().len(), 1);
    assert_eq!(received["streams"][0]["unread_count"], 1);
    assert_eq!(received["streams"][0]["rows"][0]["unread"], true);
    assert_eq!(
        received["streams"][0]["rows"][0]["body"]["payload"]["text"],
        "PUBLIC AFTER JOIN"
    );
    let mut mark_read = scope(&received, "mark_read");
    mark_read["records"] = json!([received["streams"][0]["rows"][0]["id"]]);
    let read = reader.operate(mark_read).await.unwrap();
    assert_eq!(read["view"]["streams"][0]["unread_count"], 0);
    assert_eq!(read["view"]["streams"][0]["rows"][0]["unread"], false);
    assert_eq!(
        received["streams"][0]["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["identity_id"] == reader_public["identity_id"])
            .unwrap()["external"],
        true
    );
    let request = d.path().join("history.request");
    let mut v = scope(&received, "history_request");
    v["count"] = json!(20);
    v["output"] = json!(request);
    reader.operate(v).await.unwrap();
    let mut v = scope(&first, "history_preview");
    v["path"] = json!(request);
    let preview = owner.operate(v.clone()).await.unwrap();
    assert_eq!(preview["selection"].as_array().unwrap().len(), 2);
    let bundle = d.path().join("history.age");
    v["op"] = json!("history_approve");
    v["expected_request"] = preview["request_id"].clone();
    v["output"] = json!(bundle);
    v["selection"] = json!([preview["selection"][0]["id"]]);
    let mut changed_request = v.clone();
    changed_request["expected_request"] = json!("00".repeat(32));
    assert!(owner.operate(changed_request).await.is_err());
    assert!(!bundle.exists());
    owner.operate(v).await.unwrap();
    let mut v = scope(&received, "history_import");
    v["request"] = json!(request);
    v["path"] = json!(bundle);
    reader.operate(v.clone()).await.unwrap();
    reader.operate(v).await.unwrap();
    let imported = reader.view().await.unwrap();
    assert_eq!(imported["streams"][0]["rows"].as_array().unwrap().len(), 2);
    let input = d.path().join("public-file.txt");
    std::fs::write(&input, b"PUBLIC FILE BYTES").unwrap();
    let mut v = scope(&first, "file_share");
    v["path"] = json!(input);
    owner.operate(v).await.unwrap();
    owner.operate(json!({"op":"sync"})).await.unwrap();
    reader.operate(json!({"op":"sync"})).await.unwrap();
    let fileview = reader.view().await.unwrap();
    let file = fileview["streams"][0]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["body"]["kind"] == "file.shared")
        .unwrap();
    assert_eq!(fileview["inbox"]["DEFERRED"], 1);
    let file_object = file["body"]["object_id"].as_str().unwrap();
    let cache = rusqlite::Connection::open(reader_dir.join("client.sqlite")).unwrap();
    assert_eq!(
        cache
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM objects WHERE object_id=?1",
                [file_object],
                |r| r.get(0)
            )
            .unwrap(),
        0
    );
    let output = d.path().join("downloaded.txt");
    let mut v = scope(&received, "file_download");
    v["record"] = file["id"].clone();
    v["output"] = json!(output);
    reader.operate(v).await.unwrap();
    assert_eq!(std::fs::read(output).unwrap(), b"PUBLIC FILE BYTES");
    let ciphertext = cache
        .query_row::<Vec<u8>, _, _>(
            "SELECT ciphertext FROM objects WHERE object_id=?1",
            [file_object],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        elo_core::ids::ObjectId::of_ciphertext(&ciphertext).to_string(),
        file_object
    );
    assert_ne!(ciphertext, b"PUBLIC FILE BYTES");
    send(&mut owner, "PUBLIC HELD BEFORE CONFIG CHANGE").await;
    let mut v = scope(&first, "remove_member");
    v["fingerprint"] = reader_public["identity_id"].clone();
    owner.operate(v).await.unwrap();
    assert!(
        owner.view().await.unwrap()["counts"]["held"]
            .as_u64()
            .unwrap()
            > 0
    );
    // A stale snapshot cannot roll back a known head or resurrect removed membership.
    assert!(owner.operate(json!({"op":"import_stream","path":config,"space":exchange["space"],"stream":exchange["stream"],"root":exchange["root"],"name":"Rollback"})).await.is_err());
    owner.close().await.unwrap();
    reader.close().await.unwrap();
    let reopened = ClientApp::open(reader_dir, PASSWORD.into(), true)
        .await
        .unwrap();
    assert_eq!(
        reopened.view().await.unwrap()["streams"][0]["rows"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    reopened.close().await.unwrap();
    let db = std::fs::read(owner_dir.join("client.sqlite")).unwrap();
    assert!(
        !db.windows(b"PUBLIC AFTER JOIN".len())
            .any(|x| x == b"PUBLIC AFTER JOIN")
    );
    server.abort();
}

#[tokio::test]
async fn automatic_peer_enrollment_preserves_profiles_and_existing_mailboxes() {
    use elo_core::{app::ProfileDraft, sync::PeerDescriptor};
    let d = TempDir::new().unwrap();
    let path = d.path().join("profile");
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(path.clone(), PASSWORD.into(), "General", "Alex")
        .await
        .unwrap();
    send(&mut app, "A preserved local message").await;
    let before = app.view().await.unwrap();
    let descriptor = |mailbox: &str| -> PeerDescriptor {
        serde_json::from_value(json!({
            "url":"https://replica.example/", "signing_public_key":elo_core::record::encode_hex(
                ed25519_dalek::SigningKey::from_bytes(&[76;32]).verifying_key().as_bytes()),
            "mailbox_id":mailbox.repeat(32), "read_token":"synthetic-read", "write_token":"synthetic-write"
        })).unwrap()
    };
    let owner = descriptor("ab");
    let team = descriptor("cd");
    assert!(app.ensure_peer(owner.clone()).unwrap());
    assert!(app.ensure_peer(team.clone()).unwrap());
    let vault_before_retry = std::fs::read(path.join("vault.age")).unwrap();
    assert!(!app.ensure_peer(team.clone()).unwrap());
    let mut conflict = owner.clone();
    conflict.read_token = Some("never-replace-owner".into());
    assert!(!app.ensure_peer(conflict).unwrap());
    assert_eq!(
        std::fs::read(path.join("vault.age")).unwrap(),
        vault_before_retry
    );
    let session = Session::open(
        &vault_before_retry,
        PASSWORD.into(),
        serde_json::from_value(before["identity"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(session.peers()[0].read_token, owner.read_token);
    assert_eq!(session.peers().len(), 2);
    let after = app.view().await.unwrap();
    for key in [
        "identity",
        "credential",
        "name",
        "streams",
        "groups",
        "counts",
    ] {
        assert_eq!(before[key], after[key]);
    }
    assert_eq!(after["replicas"].as_array().unwrap().len(), 2);
    assert_eq!(after["replicas"][0]["id"], after["replicas"][1]["id"]);
    assert_ne!(
        after["replicas"][0]["mailbox"],
        after["replicas"][1]["mailbox"]
    );
    // A failed encrypted vault commit must not leave a half-added in-memory peer.
    let saved = path.join("saved-vault.age");
    std::fs::rename(path.join("vault.age"), &saved).unwrap();
    std::fs::create_dir(path.join("vault.age")).unwrap();
    assert!(app.ensure_peer(descriptor("ef")).is_err());
    assert_eq!(app.view().await.unwrap()["replicas"], after["replicas"]);
    std::fs::remove_dir(path.join("vault.age")).unwrap();
    std::fs::rename(saved, path.join("vault.age")).unwrap();
    app.close().await.unwrap();
    let mut reopened = ClientApp::open(path, PASSWORD.into(), false).await.unwrap();
    assert!(!reopened.ensure_peer(team).unwrap());
    assert_eq!(reopened.view().await.unwrap(), after);
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn controller_loss_recovery_review_restart_and_old_device_retirement() {
    let d = TempDir::new().unwrap();
    let owner_dir = d.path().join("lost-owner");
    let reader_dir = d.path().join("surviving-reader");
    let fresh_dir = d.path().join("recovered-owner");
    let card_path = d.path().join("owner-recovery.json");
    let owner_public = profile(&owner_dir, &card_path).await;
    let reader_card = d.path().join("reader-recovery.json");
    let reader_public = profile(&reader_dir, &reader_card).await;
    let mut owner = ClientApp::open(owner_dir.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    let initial = owner
        .operate(json!({"op":"create_space","name":"Survives loss","recovery_card":card_path}))
        .await
        .unwrap()["view"]
        .clone();
    send(&mut owner, "PUBLIC ORIGINAL KEPT ON LOST DEVICE").await;
    let invitation = d.path().join("invite.json");
    let mut v = scope(&initial, "invite_create");
    v["output"] = json!(invitation);
    owner.operate(v).await.unwrap();
    let exchange: Value = serde_json::from_slice(&std::fs::read(&invitation).unwrap()).unwrap();
    let mut reader = ClientApp::open(reader_dir.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    let join = d.path().join("join.json");
    reader.operate(json!({"op":"invite_request","path":invitation,"space":exchange["space"],"root":exchange["root"],"output":join})).await.unwrap();
    let old_config = d.path().join("reader-before.age");
    let mut approve = scope(&initial, "invite_approve");
    approve["path"] = json!(join);
    approve["fingerprint"] = reader_public["identity_id"].clone();
    approve["output"] = json!(old_config);
    approve["post"] = json!(true);
    owner.operate(approve).await.unwrap();
    let import = json!({"op":"import_stream","path":old_config,"space":exchange["space"],"stream":exchange["stream"],"root":exchange["root"],"name":"Survives loss"});
    reader.operate(import.clone()).await.unwrap();
    owner.close().await.unwrap(); // No transfer/retire call or old device secret is used to recover.

    let card: vault::RecoveryCard =
        serde_json::from_slice(&vault::read_private(&card_path).unwrap()).unwrap();
    let fresh = Session::recover(
        &card,
        serde_json::from_value(owner_public["identity_id"].clone()).unwrap(),
    )
    .unwrap();
    let fresh_store = ClientStore::open(&fresh_dir).await.unwrap();
    vault::write_private(
        &fresh_dir.join("profile.json"),
        &serde_json::to_vec(
            &json!({"identity_id":fresh.identity_id(),"credential_id":fresh.credential().id()}),
        )
        .unwrap(),
        false,
    )
    .unwrap();
    vault::write_private(
        &fresh_dir.join("vault.age"),
        &fresh.seal(PASSWORD.into()).unwrap(),
        false,
    )
    .unwrap();
    fresh_store.close().await.unwrap();
    let mut recovered = ClientApp::open(fresh_dir.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    let device = d.path().join("new-device.record");
    recovered
        .operate(json!({"op":"device_export","output":device}))
        .await
        .unwrap();
    let proof = d.path().join("recovery-proof.age");
    let mut export = scope(&initial, "recovery_export");
    export["path"] = json!(device);
    export["output"] = json!(proof);
    export["credential"] = reader_public["credential_id"].clone();
    assert!(reader.operate(export.clone()).await.is_err());
    assert!(!proof.exists());
    export["credential"] = json!(fresh.credential().id());
    reader.operate(export).await.unwrap();
    let mut request = json!({"op":"recovery_preview","path":proof,"space":exchange["space"],"stream":exchange["stream"],"root":exchange["root"],"name":"Recovered channel","recovery_card":card_path});
    let preview = recovered.operate(request.clone()).await.unwrap();
    assert_eq!(preview["members"].as_array().unwrap().len(), 2);
    request["op"] = json!("controller_recover");
    assert!(recovered.operate(request.clone()).await.is_err());
    for field in ["expected_proof", "expected_config", "expected_recovery"] {
        request[field] = preview[field].clone();
    }
    request["confirmed_recovery"] = json!(true);
    let mut bad = request.clone();
    bad["expected_proof"] = json!("00".repeat(32));
    assert!(recovered.operate(bad).await.is_err());
    let mut bad = request.clone();
    bad["recovery_card"] = json!(reader_card);
    assert!(recovered.operate(bad).await.is_err());
    // Fail after the SQLite commit but before workspace/vault activation.
    std::fs::create_dir(fresh_dir.join("workspace.age")).unwrap();
    assert!(recovered.operate(request.clone()).await.is_err());
    recovered.close().await.unwrap();
    std::fs::remove_dir(fresh_dir.join("workspace.age")).unwrap();
    let store = ClientStore::open(&fresh_dir).await.unwrap();
    let space = serde_json::from_value(exchange["space"].clone()).unwrap();
    let stream = serde_json::from_value(exchange["stream"].clone()).unwrap();
    let saved = store
        .authority_snapshot(space, stream)
        .await
        .unwrap()
        .unwrap();
    let root = card
        .recover_root(fresh.identity_id())
        .unwrap()
        .verifying_key();
    let a = elo_core::authority::Authority::open_snapshot(
        &saved,
        fresh.age_identity(),
        space,
        &root,
        stream,
    )
    .unwrap();
    let committed_head = a.head_id();
    store.close().await.unwrap();
    let mut recovered = ClientApp::open(fresh_dir.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    let result = recovered.operate(request.clone()).await.unwrap();
    assert_eq!(result["view"]["streams"][0]["head"], json!(committed_head));
    let result = recovered.operate(request).await.unwrap();
    assert_eq!(result["view"]["streams"][0]["head"], json!(committed_head));
    assert_eq!(
        result["view"]["streams"][0]["rows"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let reader_after = d.path().join("reader-after.age");
    let mut export = scope(&initial, "export_config");
    export["credential"] = reader_public["credential_id"].clone();
    export["output"] = json!(reader_after);
    recovered.operate(export).await.unwrap();
    let mut adopt = import.clone();
    adopt["path"] = json!(reader_after);
    assert!(reader.operate(adopt.clone()).await.is_err());
    let mut review = adopt.clone();
    review["op"] = json!("config_preview");
    let reviewed = reader.operate(review).await.unwrap();
    for field in ["expected_proof", "expected_config", "expected_recovery"] {
        adopt[field] = reviewed[field].clone();
    }
    adopt["confirmed_recovery"] = json!(true);
    reader.operate(adopt).await.unwrap();
    reader.operate(import.clone()).await.unwrap();
    assert_eq!(
        reader.view().await.unwrap()["streams"][0]["head"],
        json!(committed_head)
    );
    send(&mut recovered, "PUBLIC AFTER EMERGENCY RECOVERY").await;
    // Post-recovery invitations carry a root controller chain, without exposing members.
    let invitation = d.path().join("after-recovery-invite.json");
    let mut v = scope(&initial, "invite_create");
    v["output"] = json!(invitation);
    recovered.operate(v).await.unwrap();
    reader.operate(json!({"op":"invite_request","path":invitation,"space":exchange["space"],"root":exchange["root"],"output":d.path().join("after-recovery-request.json")})).await.unwrap();
    recovered.close().await.unwrap();
    let reopened = ClientApp::open(fresh_dir.clone(), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(
        reopened.view().await.unwrap()["streams"][0]["controller"],
        json!(fresh.credential().id())
    );
    reopened.close().await.unwrap();

    // A returning old device may learn the signed configuration from another
    // participant. Its existing messages survive, but its device loses POST/MANAGE.
    let lost = Session::open(
        &vault::read_private(&owner_dir.join("vault.age")).unwrap(),
        PASSWORD.into(),
        fresh.identity_id(),
    )
    .unwrap();
    let notice = d.path().join("returning-old-device.age");
    std::fs::write(
        &notice,
        a.seal_snapshot(&lost.age_identity().to_public()).unwrap(),
    )
    .unwrap();
    let mut returned = ClientApp::open(owner_dir, PASSWORD.into(), false)
        .await
        .unwrap();
    let mut adopt = import;
    adopt["path"] = json!(notice);
    adopt["op"] = json!("config_preview");
    let review = returned.operate(adopt.clone()).await.unwrap();
    adopt["op"] = json!("import_stream");
    adopt["confirmed_recovery"] = json!(true);
    for field in ["expected_proof", "expected_config", "expected_recovery"] {
        adopt[field] = review[field].clone();
    }
    returned.operate(adopt).await.unwrap();
    let view = returned.view().await.unwrap();
    assert_eq!(view["streams"][0]["can_post"], false);
    assert_eq!(view["streams"][0]["rows"].as_array().unwrap().len(), 1);
    let mut v = scope(&initial, "invite_create");
    v["output"] = json!(d.path().join("must-not-exist.json"));
    assert!(returned.operate(v).await.is_err());
    returned.close().await.unwrap();
    reader.close().await.unwrap();
}

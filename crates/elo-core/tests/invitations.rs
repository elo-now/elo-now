use elo_core::{app::ClientApp, app::ProfileDraft};
use serde_json::{Value, json};
use tempfile::TempDir;
const PASSWORD: &str = "public invitation test password";
async fn profile(root: &std::path::Path, name: &str) -> ClientApp {
    ProfileDraft::new()
        .unwrap()
        .save(root.join(name), PASSWORD.into(), "General")
        .await
        .unwrap()
}
fn scope(view: &Value, op: &str) -> Value {
    let s = &view["streams"][0];
    json!({"op":op,"space":s["space"],"stream":s["stream"]})
}
async fn offer(owner: &mut ClientApp, reusable: bool) -> String {
    let mut v = scope(&owner.view().await.unwrap(), "invitation_create");
    v["reusable"] = json!(reusable);
    v["post"] = json!(true);
    owner.operate(v).await.unwrap()["link"]
        .as_str()
        .unwrap()
        .into()
}
async fn request(candidate: &mut ClientApp, link: &str, name: &str) -> String {
    let p = candidate
        .operate(json!({"op":"invitation_preview","link":link}))
        .await
        .unwrap();
    candidate.operate(json!({"op":"invitation_request","link":link,"confirmed_invitation":p["id"],"trusted":true,"name":name})).await.unwrap()["link"].as_str().unwrap().into()
}
#[tokio::test]
async fn shared_invitation_two_people_approval_restart_and_private_state() {
    let d = TempDir::new().unwrap();
    let mut owner = profile(d.path(), "owner").await;
    let mut alice = profile(d.path(), "alice").await;
    let mut bob = profile(d.path(), "bob").await;
    let link = offer(&mut owner, true).await;
    assert!(!link.contains(PASSWORD));
    let alice_request = request(&mut alice, &link, "Alice").await;
    let bob_request = request(&mut bob, &link, "Bob").await;
    assert_eq!(request(&mut alice, &link, "Alice").await, alice_request);
    for (candidate, req, name) in [
        (&mut alice, alice_request, "Alice"),
        (&mut bob, bob_request, "Bob"),
    ] {
        let incoming = owner
            .operate(json!({"op":"invitation_receive","link":req}))
            .await
            .unwrap();
        let before = owner.view().await.unwrap();
        let mut approve = json!({"op":"invitation_approve","id":incoming["id"],"confirmed":true,"confirmed_identity":before["identity"],"post":true});
        assert!(owner.operate(approve.clone()).await.is_err());
        approve["confirmed_identity"] = candidate.view().await.unwrap()["identity"].clone();
        approve["share_history"] = json!(true);
        assert!(owner.operate(approve.clone()).await.is_err());
        approve["share_history"] = json!(false);
        let grant = owner.operate(approve.clone()).await.unwrap();
        assert_eq!(owner.operate(approve).await.unwrap()["link"], grant["link"]);
        let preview = candidate
            .operate(json!({"op":"invitation_preview","link":grant["link"]}))
            .await
            .unwrap();
        assert_eq!(preview["kind"], "grant");
        assert_eq!(preview["capabilities"], json!(["READ", "POST"]));
        candidate.operate(json!({"op":"invitation_join","link":grant["link"],"confirmed_reference":preview["id"],"trusted":true})).await.unwrap();
        let joined = candidate.view().await.unwrap();
        assert_eq!(joined["streams"].as_array().unwrap().len(), 2, "{name}");
        assert!(joined["streams"][1]["rows"].as_array().unwrap().is_empty());
    }
    let scope_before = scope(&owner.view().await.unwrap(), "invitation_list");
    let old = owner.operate(scope_before.clone()).await.unwrap();
    assert_eq!(old["requests"].as_array().unwrap().len(), 2);
    let raw = std::fs::read(d.path().join("owner/invitations.age")).unwrap();
    assert!(!raw.windows(5).any(|s| s == b"Alice"));
    assert!(!raw.windows(link.len()).any(|s| s == link.as_bytes()));
    owner.close().await.unwrap();
    let mut reopened = ClientApp::open(d.path().join("owner"), PASSWORD.into(), false)
        .await
        .unwrap();
    assert_eq!(reopened.operate(scope_before).await.unwrap(), old);
}
#[tokio::test]
async fn shared_invitation_revocation_decline_and_contact_scan() {
    let d = TempDir::new().unwrap();
    let mut owner = profile(d.path(), "owner").await;
    let mut alice = profile(d.path(), "alice").await;
    let link = offer(&mut owner, true).await;
    let request = request(&mut alice, &link, "Alice").await;
    let incoming = owner
        .operate(json!({"op":"invitation_receive","link":request}))
        .await
        .unwrap();
    owner
        .operate(json!({"op":"invitation_decline","id":incoming["id"]}))
        .await
        .unwrap();
    assert!(owner.operate(json!({"op":"invitation_approve","id":incoming["id"],"confirmed":true,"confirmed_identity":alice.view().await.unwrap()["identity"]})).await.is_err());
    let listing = owner
        .operate(scope(&owner.view().await.unwrap(), "invitation_list"))
        .await
        .unwrap();
    let mut disable = scope(&owner.view().await.unwrap(), "invitation_disable");
    disable["id"] = listing["offers"][0]["id"].clone();
    owner.operate(disable).await.unwrap();
    assert!(
        owner
            .operate(json!({"op":"invitation_receive","link":request}))
            .await
            .is_err()
    );
    let contact = alice
        .operate(json!({"op":"contact_create","name":"Alice"}))
        .await
        .unwrap();
    let mut receive = scope(&owner.view().await.unwrap(), "invitation_receive");
    receive["link"] = contact["link"].clone();
    let incoming = owner.operate(receive).await.unwrap();
    let grant=owner.operate(json!({"op":"invitation_approve","id":incoming["id"],"confirmed":true,"confirmed_identity":alice.view().await.unwrap()["identity"],"post":false})).await.unwrap();
    let preview = alice
        .operate(json!({"op":"invitation_preview","link":grant["link"]}))
        .await
        .unwrap();
    assert_eq!(preview["capabilities"], json!(["READ"]));
    alice.operate(json!({"op":"invitation_join","link":grant["link"],"confirmed_reference":preview["id"],"trusted":true})).await.unwrap();
    let view = alice.view().await.unwrap();
    assert_eq!(view["streams"][1]["can_post"], false);
}

fn rewrite_packet(link: &str, mutate: impl FnOnce(&mut Value)) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::io::{Read, Write};
    let bytes = URL_SAFE_NO_PAD
        .decode(link.strip_prefix("elo://exchange/v1#").unwrap())
        .unwrap();
    let mut text = Vec::new();
    flate2::read::ZlibDecoder::new(bytes.as_slice())
        .read_to_end(&mut text)
        .unwrap();
    let mut packet: Value = serde_json::from_slice(&text).unwrap();
    mutate(&mut packet);
    let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zip.write_all(&serde_json::to_vec(&packet).unwrap())
        .unwrap();
    format!(
        "elo://exchange/v1#{}",
        URL_SAFE_NO_PAD.encode(zip.finish().unwrap())
    )
}
#[tokio::test]
async fn one_person_limit_tampering_and_untrusted_links_fail_closed() {
    let d = TempDir::new().unwrap();
    let mut owner = profile(d.path(), "owner").await;
    let mut alice = profile(d.path(), "alice").await;
    let mut bob = profile(d.path(), "bob").await;
    let link = offer(&mut owner, false).await;
    let p = alice
        .operate(json!({"op":"invitation_preview","link":link}))
        .await
        .unwrap();
    assert!(alice.operate(json!({"op":"invitation_request","link":link,"name":"Alice","confirmed_invitation":p["id"],"trusted":false})).await.is_err());
    let tampered = rewrite_packet(&link, |p| p["bundle"]["root"] = json!("00".repeat(32)));
    assert!(
        alice
            .operate(json!({"op":"invitation_preview","link":tampered}))
            .await
            .is_err()
    );
    let tampered = rewrite_packet(&link, |p| {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let mut signed = STANDARD
            .decode(p["bundle"]["invitation"].as_str().unwrap())
            .unwrap();
        let last = signed.len() - 1;
        signed[last] ^= 1;
        p["bundle"]["invitation"] = json!(STANDARD.encode(signed));
    });
    assert!(
        alice
            .operate(json!({"op":"invitation_preview","link":tampered}))
            .await
            .is_err()
    );
    let ar = request(&mut alice, &link, "Alice").await;
    let br = request(&mut bob, &link, "Bob").await;
    let a = owner
        .operate(json!({"op":"invitation_receive","link":ar}))
        .await
        .unwrap();
    let b = owner
        .operate(json!({"op":"invitation_receive","link":br}))
        .await
        .unwrap();
    let grant=owner.operate(json!({"op":"invitation_approve","id":a["id"],"confirmed":true,"confirmed_identity":alice.view().await.unwrap()["identity"],"post":true})).await.unwrap();
    assert!(owner.operate(json!({"op":"invitation_approve","id":b["id"],"confirmed":true,"confirmed_identity":bob.view().await.unwrap()["identity"],"post":true})).await.is_err());
    assert_eq!(
        owner.view().await.unwrap()["streams"][0]["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        bob.operate(json!({"op":"invitation_preview","link":grant["link"]}))
            .await
            .is_err()
    );
    let tampered = rewrite_packet(grant["link"].as_str().unwrap(), |p| {
        p["stream"] = json!("00".repeat(16))
    });
    assert!(
        alice
            .operate(json!({"op":"invitation_preview","link":tampered}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn invitation_parser_bounds_decompression_and_rejects_foreign_schemes() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::io::Write;
    let d = TempDir::new().unwrap();
    let mut app = profile(d.path(), "owner").await;
    let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zip.write_all(&vec![b'a'; 1024 * 1024 + 1]).unwrap();
    let bomb = format!(
        "elo://exchange/v1#{}",
        URL_SAFE_NO_PAD.encode(zip.finish().unwrap())
    );
    for link in [
        bomb,
        "https://elo.now.invalid/invite".into(),
        "elo://exchange/v2#AAAA".into(),
        "elo://exchange/v1#not-base64!".into(),
    ] {
        assert!(
            app.operate(json!({"op":"invitation_preview","link":link}))
                .await
                .is_err()
        );
    }
    assert!(!d.path().join("owner/invitations.age").exists());
}

fn packet_value(link: &str) -> Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::io::Read;
    let bytes = URL_SAFE_NO_PAD
        .decode(link.strip_prefix("elo://exchange/v1#").unwrap())
        .unwrap();
    let mut plain = Vec::new();
    flate2::read::ZlibDecoder::new(bytes.as_slice())
        .read_to_end(&mut plain)
        .unwrap();
    serde_json::from_slice(&plain).unwrap()
}
fn signed_body(encoded: &Value) -> Value {
    use base64::{Engine, engine::general_purpose::STANDARD};
    elo_core::record::SignedRecord::parse(&STANDARD.decode(encoded.as_str().unwrap()).unwrap())
        .unwrap()
        .body()
        .clone()
}
async fn reopen(app: ClientApp, path: std::path::PathBuf) -> ClientApp {
    app.close().await.unwrap();
    ClientApp::open(path, PASSWORD.into(), true).await.unwrap()
}
async fn delivery(app: &mut ClientApp) -> Value {
    app.operate(json!({"op":"invitation_sync","force":true}))
        .await
        .unwrap()
}

#[tokio::test]
async fn replica_delivery_survives_lost_ack_restart_and_keeps_approval_explicit() {
    use axum::{
        extract::Request,
        http::{Method, StatusCode},
        middleware::{self, Next},
        response::IntoResponse,
    };
    use elo_core::{record::encode_hex, replica::ReplicaStore};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let d = TempDir::new().unwrap();
    let store = ReplicaStore::open(d.path().join("replica")).await.unwrap();
    let mailbox = store.create_mailbox(64 * 1024 * 1024).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}");
    let lose_ack = Arc::new(AtomicBool::new(true));
    let flag = lose_ack.clone();
    let router = elo_core::http::router(store.clone(), &url).layer(middleware::from_fn(
        move |request: Request, next: Next| {
            let flag = flag.clone();
            async move {
                let upload =
                    request.method() == Method::POST && request.uri().path().contains("/objects/");
                let response = next.run(request).await;
                if upload && response.status().is_success() && flag.swap(false, Ordering::SeqCst) {
                    StatusCode::SERVICE_UNAVAILABLE.into_response()
                } else {
                    response
                }
            }
        },
    ));
    let mut server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let owner = profile(d.path(), "owner-network").await;
    let mut owner = reopen(owner, d.path().join("owner-network")).await;
    let mut alice = profile(d.path(), "alice-network").await;
    let descriptor = d.path().join("peer.json");
    elo_core::vault::write_private(&descriptor,&serde_json::to_vec(&json!({"url":url,"signing_public_key":encode_hex(store.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":null,"write_token":mailbox.write_token})).unwrap(),false).unwrap();
    owner
        .operate(json!({"op":"add_peer","path":descriptor}))
        .await
        .unwrap();
    // A century-long offer remains usable without advertising an expiring inbox.
    let mut long_create = scope(&owner.view().await.unwrap(), "invitation_create");
    long_create["lifetime"] = json!("100y");
    let long = owner.operate(long_create).await.unwrap();
    let long_preview = alice
        .operate(json!({"op":"invitation_preview", "link":long["link"]}))
        .await
        .unwrap();
    assert_eq!(long_preview["automatic"], false);
    assert!(signed_body(&packet_value(long["link"].as_str().unwrap())["bundle"]["invitation"])["delivery"].is_null());
    assert_eq!(delivery(&mut owner).await["delivery"]["retry"], 0);
    let link = offer(&mut owner, true).await;
    let offer_packet = packet_value(&link);
    let offer_body = signed_body(&offer_packet["bundle"]["invitation"]);
    assert!(offer_body["delivery"]["read_token"].is_null());
    assert_ne!(
        offer_body["delivery"]["write_token"],
        json!(mailbox.write_token)
    );
    // A scanned link never enables insecure HTTP for a normal client.
    let p = alice
        .operate(json!({"op":"invitation_preview","link":link}))
        .await
        .unwrap();
    assert!(alice.operate(json!({"op":"invitation_request","link":link,"confirmed_invitation":p["id"],"trusted":true,"name":"Alice"})).await.is_err());
    alice = reopen(alice, d.path().join("alice-network")).await;
    assert_eq!(delivery(&mut owner).await["delivery"]["retry"], 0);
    let request_link = request(&mut alice, &link, "Alice").await;
    let request_body = signed_body(&packet_value(&request_link)["request"]);
    assert!(request_body["delivery"]["read_token"].is_null());
    assert_ne!(
        request_body["delivery"]["mailbox_id"],
        offer_body["delivery"]["mailbox_id"]
    );
    alice = reopen(alice, d.path().join("alice-network")).await;
    assert_eq!(request(&mut alice, &link, "Alice").await, request_link);
    assert_eq!(delivery(&mut alice).await["delivery"]["retry"], 1);
    let db = rusqlite::Connection::open(d.path().join("replica/replica.sqlite")).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM deliveries", [], |r| r.get(0))
            .unwrap(),
        1
    );
    server.abort();
    let _ = (&mut server).await;
    assert!(
        delivery(&mut alice).await["delivery"]["retry"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        alice
            .operate(json!({"op":"invitation_activity"}))
            .await
            .unwrap()["outgoing"][0]["status"],
        "queued"
    );
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let router = elo_core::http::router(store.clone(), &url);
    server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    assert_eq!(delivery(&mut alice).await["delivery"]["stored"], 1);
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM deliveries", [], |r| r.get(0))
            .unwrap(),
        1
    );
    let ciphertext: Vec<u8> = db
        .query_row("SELECT ciphertext FROM objects", [], |r| r.get(0))
        .unwrap();
    assert!(!ciphertext.windows(5).any(|w| w == b"Alice"));
    // Malformed and oversized ciphertext shares a mailbox with a valid request.
    // Neither may poison the cursor or create an actionable Activity entry.
    for bytes in [vec![7; 123], vec![8; 1024 * 1024 + 64 * 1024 + 1]] {
        store
            .post(
                offer_body["delivery"]["mailbox_id"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
                offer_body["delivery"]["write_token"]
                    .as_str()
                    .unwrap()
                    .into(),
                elo_core::ids::ObjectId::of_ciphertext(&bytes),
                bytes,
                elo_core::replica::TransferHint::Eager,
            )
            .await
            .unwrap();
    }
    let received = delivery(&mut owner).await;
    assert_eq!(received["delivery"]["rejected"], 2);
    assert_eq!(received["delivery"]["received"], 1);
    assert_eq!(delivery(&mut owner).await["delivery"]["rejected"], 0);

    let activity = owner
        .operate(json!({"op":"invitation_activity"}))
        .await
        .unwrap();
    let id = activity["incoming"][0]["id"].clone();
    assert_eq!(activity["incoming"][0]["name"], "Alice");
    assert_eq!(
        owner.view().await.unwrap()["streams"][0]["members"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let mut approval = json!({"op":"invitation_approve","id":id,"confirmed_identity":alice.view().await.unwrap()["identity"],"confirmed":false,"post":false});
    assert!(owner.operate(approval.clone()).await.is_err());
    approval["confirmed"] = json!(true);
    let approved = owner.operate(approval).await.unwrap();
    assert_eq!(approved["automatic"], true);
    owner = reopen(owner, d.path().join("owner-network")).await;
    assert_eq!(delivery(&mut owner).await["delivery"]["stored"], 1);
    assert_eq!(delivery(&mut alice).await["delivery"]["received"], 1);
    assert_eq!(
        alice.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let activity = alice
        .operate(json!({"op":"invitation_activity"}))
        .await
        .unwrap();
    assert_eq!(activity["outgoing"][0]["status"], "approved");
    assert_eq!(activity["outgoing"][0]["link"], approved["link"]);
    let preview = alice
        .operate(json!({"op":"invitation_preview","link":approved["link"]}))
        .await
        .unwrap();
    assert_eq!(preview["capabilities"], json!(["READ"]));
    alice.operate(json!({"op":"invitation_join","link":approved["link"],"confirmed_reference":preview["id"],"trusted":true})).await.unwrap();
    assert_eq!(alice.view().await.unwrap()["invitations"]["responses"], 0);
    assert_eq!(alice.view().await.unwrap()["streams"][1]["can_post"], false);
    assert_eq!(delivery(&mut alice).await["delivery"]["received"], 0);

    // A second chat exercises a signed refusal without sending another QR/link.
    owner
        .operate(json!({"op":"create_chat","name":"Other chat"}))
        .await
        .unwrap();
    let view = owner.view().await.unwrap();
    let second=owner.operate(json!({"op":"invitation_create","space":view["streams"][1]["space"],"stream":view["streams"][1]["stream"],"post":true})).await.unwrap();
    delivery(&mut owner).await;
    request(&mut alice, second["link"].as_str().unwrap(), "Alice").await;
    delivery(&mut alice).await;
    assert_eq!(delivery(&mut owner).await["delivery"]["received"], 1);
    let pending = owner
        .operate(json!({"op":"invitation_activity"}))
        .await
        .unwrap();
    owner
        .operate(json!({"op":"invitation_decline","id":pending["incoming"][0]["id"]}))
        .await
        .unwrap();
    assert_eq!(delivery(&mut owner).await["delivery"]["stored"], 1);
    assert_eq!(delivery(&mut alice).await["delivery"]["received"], 1);
    let activity = alice
        .operate(json!({"op":"invitation_activity"}))
        .await
        .unwrap();
    let refused = activity["outgoing"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["status"] == "declined")
        .unwrap();
    let preview = alice
        .operate(json!({"op":"invitation_preview","link":refused["link"]}))
        .await
        .unwrap();
    assert_eq!(preview["kind"], "declined");
    alice
        .operate(json!({"op":"invitation_dismiss","id":preview["id"]}))
        .await
        .unwrap();
    assert_eq!(alice.view().await.unwrap()["invitations"]["responses"], 0);
    assert_eq!(
        alice.view().await.unwrap()["streams"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // Stored packets remain opaque, and network failure leaves all local results intact.
    server.abort();
    owner.close().await.unwrap();
    alice.close().await.unwrap();
}

#[tokio::test]
async fn typed_chats_and_group_dms_keep_their_category_through_invitation_join_and_restart() {
    let d = TempDir::new().unwrap();
    let mut owner = profile(d.path(), "owner").await;
    let mut alice = profile(d.path(), "alice").await;
    let mut bob = profile(d.path(), "bob").await;
    for kind in ["direct", "chat"] {
        let result = owner
            .operate(json!({"op":"create_chat", "name":"Type preservation", "chat_kind":kind}))
            .await
            .unwrap();
        let created = result["view"]["streams"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert_eq!(created["chat_kind"], kind);
        let offer = owner
            .operate(json!({"op":"invitation_create", "space":created["space"],
            "stream":created["stream"], "post":true, "reusable":true}))
            .await
            .unwrap();
        let link = offer["link"].as_str().unwrap();
        for (candidate, name) in [(&mut alice, "Alice"), (&mut bob, "Bob")] {
            let req = request(candidate, link, name).await;
            let received = owner
                .operate(json!({"op":"invitation_receive", "link":req}))
                .await
                .unwrap();
            let identity = candidate.view().await.unwrap()["identity"].clone();
            let approved = owner
                .operate(json!({"op":"invitation_approve", "id":received["id"],
                "confirmed":true, "confirmed_identity":identity, "post":true}))
                .await
                .unwrap();
            let preview = candidate
                .operate(json!({"op":"invitation_preview", "link":approved["link"]}))
                .await
                .unwrap();
            // Untrusted envelope metadata cannot relabel the signed chat category.
            let tampered = rewrite_packet(approved["link"].as_str().unwrap(), |packet| {
                packet["chat_kind"] = json!(if kind == "direct" { "chat" } else { "direct" });
            });
            assert!(
                candidate
                    .operate(json!({"op":"invitation_preview", "link":tampered}))
                    .await
                    .is_err()
            );
            candidate
                .operate(json!({"op":"invitation_join", "link":approved["link"],
                "trusted":true, "confirmed_reference":preview["id"]}))
                .await
                .unwrap();
            let view = candidate.view().await.unwrap();
            let joined = view["streams"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["stream"] == created["stream"])
                .unwrap();
            assert_eq!(joined["chat_kind"], kind);
            assert!(joined["rows"].as_array().unwrap().is_empty());
            assert_eq!(joined["can_manage_members"], false);
            assert_eq!(joined["can_post"], true);
        }
        let current = owner.view().await.unwrap();
        let current = current["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stream"] == created["stream"])
            .unwrap();
        assert_eq!(current["members"].as_array().unwrap().len(), 3);
        assert_eq!(current["chat_kind"], kind);
        // Explicit config exchange updates the first participant to three members.
        let output = d.path().join(format!("{kind}-alice.age"));
        let alice_credential = alice.view().await.unwrap()["credential"].clone();
        owner
            .operate(
                json!({"op":"export_config", "space":created["space"], "stream":created["stream"],
            "credential":alice_credential, "output":output}),
            )
            .await
            .unwrap();
        let owner_identity = owner.view().await.unwrap()["identity"].clone();
        let root = current["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["identity_id"] == owner_identity)
            .unwrap()["root_public_key"]
            .clone();
        alice
            .operate(
                json!({"op":"import_stream", "space":created["space"], "stream":created["stream"],
            "root":root, "path":output, "name":"Type preservation"}),
            )
            .await
            .unwrap();
        let alice_view = alice.view().await.unwrap();
        let updated = alice_view["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stream"] == created["stream"])
            .unwrap();
        assert_eq!(updated["members"].as_array().unwrap().len(), 3);
        assert_eq!(updated["chat_kind"], kind);
    }
    for (app, name) in [(owner, "owner"), (alice, "alice"), (bob, "bob")] {
        let expected = app.view().await.unwrap();
        app.close().await.unwrap();
        let reopened = ClientApp::open(d.path().join(name), PASSWORD.into(), false)
            .await
            .unwrap();
        assert_eq!(reopened.view().await.unwrap(), expected);
        reopened.close().await.unwrap();
    }
}

#[tokio::test]
async fn invitation_duration_is_signed_defaults_to_24_hours_and_rejects_invalid_values() {
    let d = TempDir::new().unwrap();
    let mut owner = profile(d.path(), "owner").await;
    let mut candidate = profile(d.path(), "candidate").await;
    let view = owner.view().await.unwrap();
    for (field, value, minutes) in [
        ("unused", json!(null), 1_440u64),
        ("lifetime", json!("1m"), 1),
        ("lifetime", json!("10m"), 10),
        ("lifetime", json!("30m"), 30),
        ("lifetime", json!("1h"), 60),
        ("lifetime", json!("24h"), 1_440),
        ("lifetime", json!("100y"), 36_525 * 1_440),
        ("days", json!(1), 1_440),
        ("days", json!(7), 7 * 1_440),
        ("days", json!(30), 30 * 1_440),
    ] {
        let mut create = scope(&view, "invitation_create");
        if field != "unused" {
            create[field] = value;
        }
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let offer = owner.operate(create).await.unwrap();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Preview validates the signed offer on another identity, not only the owner's listing.
        let preview = candidate
            .operate(json!({"op":"invitation_preview", "link":offer["link"]}))
            .await
            .unwrap();
        let expires = preview["expires_at"].as_u64().unwrap();
        assert!((before + minutes * 60_000..=after + minutes * 60_000).contains(&expires));
        let listing = owner
            .operate(scope(&view, "invitation_list"))
            .await
            .unwrap();
        let saved = listing["offers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == offer["id"])
            .unwrap();
        assert_eq!(saved["expires_at"], expires);
    }
    let before = owner
        .operate(scope(&view, "invitation_list"))
        .await
        .unwrap();
    let original_view = owner.view().await.unwrap();
    for invalid in [
        json!({"lifetime":0}),
        json!({"lifetime":-1}),
        json!({"lifetime":1.5}),
        json!({"lifetime":"1"}),
        json!({"lifetime":null}),
        json!({"lifetime":true}),
        json!({"lifetime":"unlimited"}),
        json!({"lifetime":"7d"}),
        json!({"days":0}),
        json!({"days":2}),
        json!({"days":null}),
        json!({"days":"1"}),
        json!({"lifetime":"1h","days":1}),
    ] {
        let mut create = scope(&view, "invitation_create");
        create
            .as_object_mut()
            .unwrap()
            .extend(invalid.as_object().unwrap().clone());
        assert!(
            owner
                .operate(create)
                .await
                .unwrap_err()
                .to_string()
                .contains("invalid invitation duration")
        );
        assert_eq!(
            owner
                .operate(scope(&view, "invitation_list"))
                .await
                .unwrap(),
            before
        );
        assert_eq!(owner.view().await.unwrap(), original_view);
    }
}

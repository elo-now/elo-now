use super::tests::{close_host, profile};
use super::*;
use elo_core::app::pairing::{PairSource, PairTarget};

#[tokio::test]
async fn foreground_discovery_completes_open_admission_without_approving_manual_requests() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let directory = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let host = Host::open(
        HostConfig {
            root: directory.path().join("host"),
            public_url: base.clone(),
            max_spaces_per_identity: 3,
            max_spaces: default_max_spaces(),
            max_space_creations_per_day: default_daily_creations(),
            mailbox_quota_bytes: 150_000_000,
            allowed_message_retentions:
                elo_core::message_retention::MessageRetention::public_policies(),
            allowed_creators: None,
            operator_snapshot: None,
            backup_access_key: None,
            call_admission_key: None,
            attachment_storage: None,
            recovery_recipient: None,
            client_policy: Default::default(),
            witness: None,
        },
        true,
    )
    .await
    .unwrap();
    let authority_requests = Arc::new(AtomicUsize::new(0));
    let requests = authority_requests.clone();
    let router = app(host.clone()).layer(axum::middleware::from_fn(
        move |request: Request, next: axum::middleware::Next| {
            let requests = requests.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = axum::body::to_bytes(body, 8 * 1024 * 1024).await.unwrap();
                if let Ok(request) = serde_json::from_slice::<SpaceRequest>(&bytes)
                    && let Some(encoded) = request.record
                    && let Ok(bytes) = STANDARD.decode(encoded)
                    && let Ok(signed) = record::SignedRecord::parse(&bytes)
                    && matches!(
                        signed.body()["action"].as_str(),
                        Some("authority" | "authority_publish")
                    )
                {
                    requests.fetch_add(1, Ordering::SeqCst);
                }
                next.run(Request::from_parts(parts, Body::from(bytes)))
                    .await
            }
        },
    ));
    let task = tokio::spawn(axum::serve(listener, router).into_future());
    let mut owner = profile(&directory.path().join("owner")).await;
    let mut guest = profile(&directory.path().join("guest")).await;
    let mut manual = profile(&directory.path().join("manual")).await;
    let created = owner.operate(json!({"op":"space_create","host":format!("{base}/spaces/v1/create"),"name":"Open admission","contact_email":"owner@example.test","message_lifetime_seconds":86400,"require_approval":false})).await.unwrap();
    let space = created["view"]["active_space"].clone();
    let invitation = created["view"]["space_creation"]["invitation"].clone();
    owner
        .operate(json!({"op":"space_setup_done"}))
        .await
        .unwrap();
    let pending = guest
        .operate(json!({"op":"space_join","link":invitation}))
        .await
        .unwrap();
    assert_eq!(pending["view"]["spaces"][0]["status"], "pending");
    assert_eq!(pending["view"]["spaces"][0]["pending_reason"], "owner_sync");
    let foreground = json!({"op":"invitation_sync","foreground":true});
    let before_owner = guest.operate(foreground.clone()).await.unwrap();
    assert_eq!(
        before_owner["view"]["spaces"][0]["pending_reason"],
        "owner_sync"
    );
    assert_eq!(authority_requests.load(Ordering::SeqCst), 0);

    // Opening a notification stays read-only; it must not hold navigation for
    // the owner maintenance pass or silently authorize a waiting device.
    owner
        .operate(json!({"op":"invitation_sync","foreground":true,"target_space":space}))
        .await
        .unwrap();
    assert_eq!(authority_requests.load(Ordering::SeqCst), 0);
    owner.operate(foreground.clone()).await.unwrap();
    assert_eq!(authority_requests.load(Ordering::SeqCst), 2);
    let joined = guest.operate(foreground.clone()).await.unwrap();
    assert_eq!(joined["view"]["spaces"][0]["status"], "joined");
    assert!(joined["view"]["spaces"][0]["pending_reason"].is_null());
    assert_eq!(joined["view"]["spaces"][0]["owner"], false);

    let settled = authority_requests.load(Ordering::SeqCst);
    owner.operate(foreground.clone()).await.unwrap();
    owner
        .operate(json!({"op":"sync_live","foreground":true}))
        .await
        .unwrap();
    assert_eq!(
        authority_requests.load(Ordering::SeqCst),
        settled,
        "idle discovery and message synchronization must add no authority requests"
    );

    let invite = owner.operate(json!({"op":"space_invite","id":space,"body":{"lifetime":86400,"require_approval":true}})).await.unwrap();
    let pending = manual
        .operate(json!({"op":"space_join","link":invite["result"]["link"]}))
        .await
        .unwrap();
    assert_eq!(pending["view"]["spaces"][0]["pending_reason"], "approval");
    owner.operate(foreground.clone()).await.unwrap();
    let pending = manual.operate(foreground.clone()).await.unwrap();
    assert_eq!(pending["view"]["spaces"][0]["status"], "pending");
    assert_eq!(pending["view"]["spaces"][0]["pending_reason"], "approval");
    assert!(
        !host
            .spaces
            .read()
            .await
            .values()
            .next()
            .unwrap()
            .client
            .lock()
            .await
            .as_ref()
            .unwrap()
            .space_access_members()
            .unwrap()
            .contains(&manual.identity_id())
    );

    let manage = owner
        .operate(json!({"op":"space_manage","id":space}))
        .await
        .unwrap();
    let request = manage["result"]["requests"][0]["id"].clone();
    owner
        .operate(json!({"op":"space_decide","id":space,"body":{"id":request,"approve":true}}))
        .await
        .unwrap();
    let joined = manual.operate(foreground).await.unwrap();
    assert_eq!(joined["view"]["spaces"][0]["status"], "joined");
    assert!(joined["view"]["spaces"][0]["pending_reason"].is_null());
    owner.close().await.unwrap();
    guest.close().await.unwrap();
    manual.close().await.unwrap();
    task.abort();
    let _ = task.await;
    close_host(host).await;
}

#[tokio::test]
async fn owner_managed_general_uses_public_hosting_and_linked_owner_after_original_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let host = Host::open(
        HostConfig {
            root: directory.path().join("host"),
            public_url: base.clone(),
            max_spaces_per_identity: 3,
            max_spaces: default_max_spaces(),
            max_space_creations_per_day: default_daily_creations(),
            mailbox_quota_bytes: 150_000_000,
            allowed_message_retentions:
                elo_core::message_retention::MessageRetention::public_policies(),
            allowed_creators: None,
            operator_snapshot: None,
            backup_access_key: None,
            call_admission_key: None,
            attachment_storage: None,
            recovery_recipient: None,
            client_policy: Default::default(),
            witness: None,
        },
        true,
    )
    .await
    .unwrap();
    let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
    let mut owner = profile(&directory.path().join("owner")).await;
    let mut guest = profile(&directory.path().join("guest")).await;
    let created = owner.operate(json!({"op":"space_create","host":format!("{base}/spaces/v1/create"),"name":"Owner managed","contact_email":"owner@example.test","message_lifetime_seconds":86400})).await.unwrap();
    let space = created["view"]["active_space"].clone();
    owner
        .operate(json!({"op":"space_setup_done"}))
        .await
        .unwrap();
    let hosted = host.spaces.read().await.values().next().unwrap().clone();
    let disk = host.config.root.join("spaces").join(&hosted.id);
    assert!(
        !disk.join("profile").exists(),
        "new hosting must not create a private General profile"
    );
    assert!(!disk.join("service-recovery.age").exists());
    let reservation: Value =
        serde_json::from_slice(&vault::read_private(&disk.join("reservation.json")).unwrap())
            .unwrap();
    assert!(reservation.get("password").is_none());
    assert!(matches!(
        hosted.client.lock().await.as_ref(),
        Some(HostedService::Public(_))
    ));

    owner
        .operate(json!({"op":"create_chat","name":"Private after General","chat_kind":"chat"}))
        .await
        .expect("a new General owner can create a private chat");
    let mut source = PairSource::new(&owner).await.unwrap();
    let mut target = PairTarget::new(&source.link().unwrap(), "Second owner device", true).unwrap();
    target.send().await.unwrap();
    let pending = source.poll().await.unwrap();
    source
        .accept(&mut owner, pending["requests"][0]["id"].as_str().unwrap())
        .await
        .unwrap();
    target.poll().await.unwrap();
    let mut companion = target
        .finish_linked(directory.path().join("companion"))
        .await
        .unwrap();
    companion.enable_spaces().await.unwrap();
    assert!(companion.can_link_device());
    let private = companion
        .operate(
            json!({"op":"create_chat", "name":"Linked owner private chat", "chat_kind":"chat"}),
        )
        .await
        .expect("the live linked owner can publish an independent private authority to the host");
    let private = private["view"]["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stream| stream["name"] == "Linked owner private chat")
        .unwrap();
    assert_eq!(private["is_general"], false);
    assert_eq!(private["owner_managed"], false);
    assert_eq!(private["can_manage_members"], true);
    assert_eq!(private["members"].as_array().unwrap().len(), 1);

    let invite = companion.operate(json!({"op":"space_invite","id":space,"body":{"lifetime":86400,"require_approval":true}})).await.unwrap();
    let joined = guest
        .operate(json!({"op":"space_join","link":invite["result"]["link"]}))
        .await
        .unwrap();
    assert!(
        !hosted
            .client
            .lock()
            .await
            .as_ref()
            .unwrap()
            .space_access_members()
            .unwrap()
            .contains(&guest.identity_id())
    );
    assert!(
        !joined["view"]["streams"]
            .as_array()
            .is_some_and(|streams| streams.iter().any(|stream| stream["is_general"] == true))
    );
    let management = companion
        .operate(json!({"op":"space_manage","id":space}))
        .await
        .unwrap();
    let request = management["result"]["requests"]
        .as_array()
        .unwrap()
        .first()
        .unwrap();
    companion
        .operate(json!({"op":"space_decide","id":space,"body":{"id":request["id"],"approve":true}}))
        .await
        .unwrap();
    guest.operate(json!({"op":"space_refresh"})).await.unwrap();
    assert!(
        hosted
            .client
            .lock()
            .await
            .as_ref()
            .unwrap()
            .space_access_members()
            .unwrap()
            .contains(&guest.identity_id())
    );

    let devices = companion.linked_devices().await.unwrap();
    let original = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|device| device["current"] != true)
        .unwrap()
        .clone();
    let retired = companion
        .revoke_linked_device(original["credential"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(retired["pending"], 0);
    companion
        .operate(json!({"op":"space_refresh"}))
        .await
        .unwrap();
    let original_id: elo_core::ids::RecordId = original["id"].as_str().unwrap().parse().unwrap();
    assert!(
        !hosted
            .client
            .lock()
            .await
            .as_ref()
            .unwrap()
            .space_access_devices()
            .unwrap()
            .contains(&original_id)
    );
    assert!(companion.can_link_device());
    companion.operate(json!({"op":"space_invite","id":space,"body":{"lifetime":86400,"require_approval":true}})).await.unwrap();
    companion
        .operate(json!({"op":"create_chat", "name":"Private after original retirement", "chat_kind":"chat"}))
        .await
        .expect("retiring the original device must not retire the linked owner's private authority");

    let mut nested_source = PairSource::new(&companion).await.unwrap();
    let mut nested_target =
        PairTarget::new(&nested_source.link().unwrap(), "Third owner device", true).unwrap();
    nested_target.send().await.unwrap();
    let pending = nested_source.poll().await.unwrap();
    nested_source
        .accept(
            &mut companion,
            pending["requests"][0]["id"].as_str().unwrap(),
        )
        .await
        .unwrap();
    nested_target.poll().await.unwrap();
    let nested = nested_target
        .finish_linked(directory.path().join("nested"))
        .await
        .unwrap();
    assert!(nested.can_link_device());
    nested.close().await.unwrap();
    drop(hosted);
    guest.close().await.unwrap();
    companion.close().await.unwrap();
    owner.close().await.unwrap();
    task.abort();
    let _ = task.await;
    close_host(host).await;
}

#[tokio::test]
async fn legacy_creation_is_rejected_before_reserving_capacity_or_private_keys() {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let directory = tempfile::tempdir().unwrap();
    let host = Host::open(
        serde_json::from_value(json!({
            "root":directory.path().join("host"),
            "public_url":"https://host.example.test",
            "max_spaces_per_identity":2,
            "max_spaces":0,
            "mailbox_quota_bytes":150_000_000
        }))
        .unwrap(),
        false,
    )
    .await
    .unwrap();
    let (owner, _) = vault::Session::create().unwrap();
    let mut command = CreateCommand {
        v: 1,
        kind: "space.create".into(),
        host: "https://host.example.test/spaces/v1/create".into(),
        request_id: "12".repeat(16),
        issued: current().unwrap(),
        name: "Legacy request".into(),
        contact_email: "owner@example.test".into(),
        message_lifetime_seconds: elo_core::message_retention::MessageRetention::Hours24,
        require_approval: true,
        authority: None,
    };
    let mut request = CreateRequest {
        record: STANDARD.encode(
            record::SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), owner.signing_key())
                .unwrap()
                .bytes(),
        ),
        credential: STANDARD.encode(owner.credential().record().bytes()),
        work: 0,
    };
    // Pay the real legacy proof of work so the route reaches the version policy.
    let mut prefix = Sha256::new();
    prefix.update(b"elo.space.create.work.v1\0");
    prefix.update(Sha256::digest(request.record.as_bytes()));
    prefix.update(Sha256::digest(request.credential.as_bytes()));
    request.work = (0u64..64 * (1 << 20))
        .find(|nonce| {
            let mut hash = prefix.clone();
            hash.update(nonce.to_be_bytes());
            let digest = hash.finalize();
            u32::from_be_bytes(digest[..4].try_into().unwrap()).leading_zeros() >= 20
        })
        .expect("legacy proof of work");
    space_host::verify_create(&request, &command.host, current().unwrap()).unwrap();
    let response = app(host.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/spaces/v1/create")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);

    // Internal provisioning cannot bypass the same policy or consume a slot.
    for version in [1, 2] {
        command.v = version;
        assert_eq!(
            host.provision(&command, owner.identity_id())
                .await
                .err()
                .unwrap()
                .to_string(),
            "Owner-managed Space creation requires an updated app."
        );
    }
    assert!(host.spaces.read().await.is_empty());
    assert!(host.allocations.lock().unwrap().is_empty());
    assert_eq!(
        std::fs::read_dir(host.config.root.join("spaces"))
            .unwrap()
            .count(),
        0
    );
    assert!(!host.config.root.join("creation-budget.json").exists());
    assert!(!host.config.root.join("reservation-stage").exists());
    close_host(host).await;
}

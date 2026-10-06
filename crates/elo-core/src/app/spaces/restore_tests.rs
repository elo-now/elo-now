use super::*;
const PASSWORD: &str = "synthetic private restore test password";

async fn profile(base: &Path, name: &str) -> ClientApp {
    let mut app = ProfileDraft::new()
        .unwrap()
        .save_named(base.join(name), PASSWORD.into(), "General", name)
        .await
        .unwrap();
    app.allow_loopback = true;
    app
}

#[tokio::test]
async fn joining_an_existing_space_is_not_restricted_by_the_new_creation_offer() {
    let temp = tempfile::tempdir().unwrap();
    let owner = profile(temp.path(), "offer owner").await;
    let mut hosting = hosting_services::test_profile(71);
    hosting.message_lifetimes = vec![crate::message_retention::MessageRetention::Hours48];
    hosting.default_message_lifetime = crate::message_retention::MessageRetention::Hours48;
    hosting.validate().unwrap();
    let mut address = SpaceAddress {
        url: "https://api71.example.test/team/v1/spaces".into(),
        scope: owner.team_scope().unwrap(),
        message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
        service_credential: None,
    };
    require_hosting_address(&hosting, &address).unwrap();
    address.url = "https://unapproved.example.test/team/v1/spaces".into();
    assert!(require_hosting_address(&hosting, &address).is_err());
    owner.close().await.unwrap();
}

#[tokio::test]
async fn primary_transfer_is_rejected_before_looking_up_or_contacting_a_host() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = profile(temp.path(), "immutable primary").await;
    owner.enable_spaces().await.unwrap();
    let error = owner
        .operate(json!({
            "op":"space_role_change", "id":"unavailable-space",
            "body":{"kind":"transfer_primary","target":owner.identity_id(),"revision":1}
        }))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Primary ownership cannot be transferred."
    );
    owner.close().await.unwrap();
}

async fn witnessed_restore_fixture(
    base: &Path,
    origin: &str,
    bound: bool,
) -> (
    ClientApp,
    SpaceAddress,
    Authority,
    Value,
    ed25519_dalek::SigningKey,
) {
    let mut user = profile(base, "restore source").await;
    user.enable_spaces().await.unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[102; 32]);
    let mut hosting = hosting_services::test_profile(101);
    hosting.create_url = format!("{origin}/spaces/v1/create");
    if bound {
        hosting.witness.url = format!("{origin}/witness/v1");
    }
    hosting.storage = None;
    user.configure_witness_pin(Some(hosting.witness.clone()))
        .unwrap();
    user.configure_invitation_host(&hosting.create_url).unwrap();
    let proof = user.owner_general_creation(&"a7".repeat(16)).unwrap();
    let genesis = decode_record(&proof.genesis).unwrap();
    let scope = team::TeamScope {
        space: genesis.id().to_string().parse().unwrap(),
        stream: "a7".repeat(16).parse().unwrap(),
        controller: user.session.credential().id(),
        root: field(user.session.credential().record().body(), "root_public_key")
            .unwrap()
            .into(),
    };
    let authority = proof
        .verify_witnessed(scope.space, scope.stream, &hosting.witness)
        .unwrap();
    let address = SpaceAddress {
        url: format!("{origin}/team/v1/spaces"),
        scope,
        message_lifetime_seconds: Default::default(),
        service_credential: Some(STANDARD.encode(user.session.credential().record().bytes())),
    };
    let replica = crate::replica::ReplicaStore::open(base.join("restore replica"))
        .await
        .unwrap();
    let mailbox = replica.create_mailbox(1024 * 1024).await.unwrap();
    let peer = PeerDescriptor {
        url: "http://127.0.0.1:9/".into(),
        signing_public_key: record::encode_hex(replica.key().as_bytes()),
        mailbox_id: mailbox.mailbox_id,
        read_token: Some(mailbox.read_token),
        write_token: Some(mailbox.write_token),
    };
    let approved = json!({
        "status":"approved", "name":"Private restore", "owner":true,
        "general_head":authority.head_id(), "peer":peer,
        "enrollment":{"v":2,"packet":STANDARD.encode(serde_json::to_vec(&json!({"proof":proof,"contacts":[]})).unwrap())}
    });
    // Use an actual isolated child vault, with no usable personal/root entry.
    let mut spaces = user.spaces.take().unwrap();
    spaces.catalog.entries.clear();
    spaces.catalog.active = None;
    spaces.catalog.personal_genesis = None;
    if bound {
        user.configure_hosting_profile(hosting.clone()).unwrap();
        spaces
            .catalog
            .hosting_bindings
            .insert(address.scope.space.to_string(), hosting);
    }
    spaces
        .add_joined(&mut user, address.clone(), approved.clone())
        .await
        .unwrap();
    user.spaces = Some(spaces);
    let child = &user.spaces.as_ref().unwrap().children[&address.scope.space.to_string()];
    assert_eq!(child.identity_id(), user.identity_id());
    assert_eq!(child.authorities.0[0].head_id(), authority.head_id());
    (user, address, authority, approved, key)
}

async fn assert_witnessed_restore_quarantined(user: &mut ClientApp, address: &SpaceAddress) {
    user.enable_paged_views();
    let view = user.view().await.unwrap();
    assert_eq!(view["spaces"][0]["status"], "checking");
    assert_eq!(view["spaces"][0]["owner"], false);
    assert!(view["active_space"].is_null());
    assert_eq!(view["streams"], json!([]));
    assert_eq!(view["all_streams"], json!([]));
    assert!(user.spaces.as_ref().unwrap().children.is_empty());
    assert!(user.selected_space_client().is_err());
    assert!(
        user.operate(json!({"op":"space_select","id":address.scope.space}))
            .await
            .is_err()
    );
    assert!(user.operate(json!({"op":"send","space":address.scope.space,"stream":address.scope.stream,"text":"Must stay quarantined","created_at":"2026-10-05T12:00:00Z"})).await.is_err());
}

#[tokio::test]
async fn offline_private_non_root_backup_restore_reaches_ready_without_cached_privileges() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let temp = tempfile::tempdir().unwrap();
    // Reserve a local endpoint, then close it: no DNS or external service is involved.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    drop(listener);
    let (source, address, _, _, _) = witnessed_restore_fixture(temp.path(), &origin, true).await;
    let expected = source.identity_id();
    let hosting = source.spaces.as_ref().unwrap().catalog.hosting_bindings
        [&address.scope.space.to_string()]
        .clone();
    let backup = source.export_profile(PASSWORD.into()).await.unwrap();
    source.close().await.unwrap();
    let ready = Arc::new(AtomicBool::new(false));
    let reported = ready.clone();
    let progress = super::super::profile_backup::RestoreProgress::new(move |stage, _, _| {
        if stage == super::super::profile_backup::RestoreStage::Ready {
            reported.store(true, Ordering::SeqCst);
        }
        true
    });
    let path = temp.path().join("restored private");
    let mut restored = super::super::profile_backup::restore(
        super::super::profile_backup::RestoreRequest {
            directory: path.clone(),
            bytes: &backup,
            secret: PASSWORD.into(),
            expected,
            password: PASSWORD.into(),
            allow_loopback: true,
            resume: false,
            paged: true,
        },
        &progress,
    )
    .await
    .unwrap();
    assert!(ready.load(Ordering::SeqCst));
    assert!(!path.join(".initializing").exists());
    assert_eq!(
        restored.hosting_profile_for_id(&hosting.id()),
        Some(&hosting)
    );
    assert_witnessed_restore_quarantined(&mut restored, &address).await;
    restored.close().await.unwrap();
}

#[tokio::test]
async fn restored_witnessed_child_requires_valid_fresh_head_before_becoming_usable() {
    use crate::witness::{Command, Freshness, HeadRequest, Operation, Position, Request, Response};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let temp = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (source, address, authority, approved, key) =
        witnessed_restore_fixture(temp.path(), &origin, false).await;
    let path = source.directory.clone();
    let credential = STANDARD.encode(source.session.credential().record().bytes());
    let host_key = source.session.signing_key().clone();
    let pin = authority.witness_pin().unwrap().clone();
    source.quarantine_restored_spaces().unwrap();
    source.close().await.unwrap();
    let mut reopened = ClientApp::open(path, PASSWORD.into(), true).await.unwrap();
    reopened.configure_witness_pin(Some(pin.clone())).unwrap();
    reopened
        .configure_invitation_host(&format!("{origin}/spaces/v1/create"))
        .unwrap();
    reopened.witness_test_url = Some(origin);
    reopened.enable_spaces().await.unwrap();
    assert_witnessed_restore_quarantined(&mut reopened, &address).await;
    let mode = Arc::new(AtomicUsize::new(0)); // 0 unavailable, 1 wrong signer, 2 valid.
    let commands = mode.clone();
    let heads = mode.clone();
    let reads = Arc::new(AtomicUsize::new(0));
    let read_count = reads.clone();
    let syncs = Arc::new(AtomicUsize::new(0));
    let sync_count = syncs.clone();
    let proof = authority.call_proof().unwrap();
    let head = authority.head_id().unwrap();
    let space = authority.space();
    let router = axum::Router::new()
        .route("/command", axum::routing::post(move |axum::Json(request):axum::Json<Request>| {
            let command:Command = decode_record(&request.command).unwrap().decode().unwrap();
            assert!(matches!(command.operation, Operation::Read));
            read_count.fetch_add(1, Ordering::SeqCst);
            let status = if commands.load(Ordering::SeqCst) == 0 { axum::http::StatusCode::SERVICE_UNAVAILABLE } else { axum::http::StatusCode::OK };
            let response = Response { receipt:None, proof:Some(proof.clone()), challenge:None };
            async move { (status, axum::Json(response)) }
        }))
        .route("/head", axum::routing::post(move |axum::Json(request):axum::Json<HeadRequest>| {
            let time = now().unwrap().as_millis() as u64;
            let freshness = Freshness { v:1,kind:"witness.freshness".into(),audience:pin.url.clone(),nonce:request.nonce,
                space_id:request.space_id,stream_id:request.stream_id,authority_head:head,
                position:Position {sequence:1,record_id:Some(RecordId::from_bytes([103;32]))},
                issued_at_ms:time,expires_at_ms:time+30_000,witness_key_generation:1 };
            let signer = if heads.load(Ordering::SeqCst) == 1 { ed25519_dalek::SigningKey::from_bytes(&[104;32]) } else { key.clone() };
            let signed = SignedRecord::sign(&serde_json::to_vec(&freshness).unwrap(), &signer).unwrap();
            let response = json!({"freshness":STANDARD.encode(signed.bytes())});
            async move { axum::Json(response) }
        }))
        .route("/team/v1/spaces", axum::routing::post(move |axum::Json(request):axum::Json<super::super::space_service::Request>| {
            let command = decode_record(request.record.as_deref().unwrap()).unwrap();
            command.verify_signature(&host_key.verifying_key()).unwrap();
            assert_eq!(command.body()["action"], "witness_sync");
            sync_count.fetch_add(1, Ordering::SeqCst);
            let answer = json!({"v":1,"kind":"space.response","space":space,"nonce":request.nonce,"body":approved,"ciphertext_hash":null});
            let signed = SignedRecord::sign(&serde_json::to_vec(&answer).unwrap(), &host_key).unwrap();
            let response = super::super::space_service::Response {record:STANDARD.encode(signed.bytes()),credential:credential.clone(),ciphertext:None};
            async move { axum::Json(response) }
        }));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    for (state, should_error) in [(0, false), (1, true)] {
        mode.store(state, Ordering::SeqCst);
        let mut spaces = reopened.spaces.take().unwrap();
        let entry = spaces.catalog.entries[0].clone();
        let result = spaces
            .poll_entry(&mut reopened, entry, PollMode::Regular)
            .await;
        reopened.spaces = Some(spaces);
        assert_eq!(
            result.is_err(),
            should_error,
            "only transport unavailability may be deferred"
        );
        assert_witnessed_restore_quarantined(&mut reopened, &address).await;
        assert_eq!(
            syncs.load(Ordering::SeqCst),
            0,
            "unverified witness answers must not reach the host"
        );
    }
    mode.store(2, Ordering::SeqCst);
    let mut spaces = reopened.spaces.take().unwrap();
    let entry = spaces.catalog.entries[0].clone();
    spaces
        .poll_entry(&mut reopened, entry, PollMode::Regular)
        .await
        .unwrap();
    assert_eq!(spaces.catalog.entries[0].status, "joined");
    assert!(!spaces.catalog.entries[0].root);
    assert_eq!(
        spaces.catalog.active.as_deref(),
        Some(address.scope.space.to_string().as_str())
    );
    assert!(
        spaces
            .children
            .contains_key(&address.scope.space.to_string())
    );
    reopened.spaces = Some(spaces);
    assert!(reopened.selected_space_client().is_ok());
    assert_eq!(reads.load(Ordering::SeqCst), 3);
    assert_eq!(syncs.load(Ordering::SeqCst), 1);
    reopened.close().await.unwrap();
    server.abort();
}

#[derive(Clone, Copy)]
enum DeferredOwnerCase {
    Paired,
    PairedAfterRestart,
    Backup,
    Revoked,
    Retired,
}

async fn deferred_owner_grant(case: DeferredOwnerCase) {
    use crate::witness::{Command, Freshness, HeadRequest, Operation, Position, Request, Response};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let temp = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (mut source, address, mut authority, mut approved, key) =
        witnessed_restore_fixture(temp.path(), &origin, false).await;
    let path = source.directory.clone();
    let space = address.scope.space;
    let id = space.to_string();
    let pin = authority.witness_pin().unwrap().clone();
    let credential = STANDARD.encode(source.session.credential().record().bytes());
    let host_key = source.session.signing_key().clone();
    if matches!(case, DeferredOwnerCase::Revoked) {
        let replacement = source.session.linked_companion().unwrap();
        authority.add_credential(replacement.credential().clone());
        let mut next = authority.head().unwrap().clone();
        next.sequence += 1;
        next.previous_config_id = authority.head_id();
        next.nonce = record::random_hex::<16>().unwrap();
        next.witness_evidence = None;
        next.members[0].credential_ids = vec![replacement.credential().id()];
        next.owner_credential_ids = vec![replacement.credential().id()];
        next.action.operation = "device.updated".into();
        next.action.request_record_id = None;
        let signed = authority
            .prepare_witness_owner_config(&next.sign(&host_key).unwrap(), &key)
            .unwrap();
        authority.apply_config(signed).unwrap();
        approved["general_head"] = json!(authority.head_id());
        approved["enrollment"]["packet"] = json!(
            STANDARD.encode(
                serde_json::to_vec(&json!({"proof":authority.call_proof().unwrap(),"contacts":[]}))
                    .unwrap()
            )
        );
    }
    // Apply the actual backup restore provenance reset to both vaults. The
    // separate archive tests cover decoding; here the host stays unavailable
    // until the authenticated live-pairing completion has run.
    source.session = Session::restore_backup(
        &vault::read_private(&path.join("vault.age")).unwrap(),
        PASSWORD.into(),
        source.identity_id(),
    )
    .unwrap();
    source.persist_vault().unwrap();
    let child = source
        .spaces
        .as_mut()
        .unwrap()
        .children
        .get_mut(&id)
        .unwrap();
    child.session = Session::restore_backup(
        &vault::read_private(&child.directory.join("vault.age")).unwrap(),
        PASSWORD.into(),
        child.identity_id(),
    )
    .unwrap();
    if matches!(case, DeferredOwnerCase::Retired) {
        child.session.retire_controller();
    }
    child.persist_vault().unwrap();
    source.quarantine_restored_spaces().unwrap();
    source.close().await.unwrap();

    let mut restored = ClientApp::open(path.clone(), PASSWORD.into(), true)
        .await
        .unwrap();
    restored.configure_witness_pin(Some(pin.clone())).unwrap();
    restored
        .configure_invitation_host(&format!("{origin}/spaces/v1/create"))
        .unwrap();
    restored.witness_test_url = Some(origin.clone());
    restored.enable_spaces().await.unwrap();
    assert!(!restored.session.owner_grant_eligible);
    assert_witnessed_restore_quarantined(&mut restored, &address).await;
    if !matches!(case, DeferredOwnerCase::Backup) {
        // This is the production hook called only after authenticated live pairing.
        restored.activate_linked_owner_controls().unwrap();
        assert!(restored.session.owner_grant_eligible);
    }
    if matches!(case, DeferredOwnerCase::PairedAfterRestart) {
        restored.close().await.unwrap();
        restored = ClientApp::open(path, PASSWORD.into(), true).await.unwrap();
        restored.configure_witness_pin(Some(pin.clone())).unwrap();
        restored
            .configure_invitation_host(&format!("{origin}/spaces/v1/create"))
            .unwrap();
        restored.witness_test_url = Some(origin);
        restored.enable_spaces().await.unwrap();
        assert!(restored.session.owner_grant_eligible);
    }
    let mode = Arc::new(AtomicUsize::new(0)); // unavailable, forged head, valid head.
    let commands = mode.clone();
    let heads = mode.clone();
    let syncs = Arc::new(AtomicUsize::new(0));
    let sync_count = syncs.clone();
    let proof = authority.call_proof().unwrap();
    let head = authority.head_id().unwrap();
    let router = axum::Router::new()
        .route("/command", axum::routing::post(move |axum::Json(request):axum::Json<Request>| {
            let command:Command = decode_record(&request.command).unwrap().decode().unwrap();
            assert!(matches!(command.operation, Operation::Read));
            let status = if commands.load(Ordering::SeqCst) == 0 { axum::http::StatusCode::SERVICE_UNAVAILABLE } else { axum::http::StatusCode::OK };
            let response = Response { receipt:None, proof:Some(proof.clone()), challenge:None };
            async move { (status, axum::Json(response)) }
        }))
        .route("/head", axum::routing::post(move |axum::Json(request):axum::Json<HeadRequest>| {
            let time = now().unwrap().as_millis() as u64;
            let freshness = Freshness { v:1,kind:"witness.freshness".into(),audience:pin.url.clone(),nonce:request.nonce,
                space_id:request.space_id,stream_id:request.stream_id,authority_head:head,
                position:Position {sequence:1,record_id:Some(RecordId::from_bytes([113;32]))},
                issued_at_ms:time,expires_at_ms:time+30_000,witness_key_generation:1 };
            let signer = if heads.load(Ordering::SeqCst) == 1 { ed25519_dalek::SigningKey::from_bytes(&[114;32]) } else { key.clone() };
            let signed = SignedRecord::sign(&serde_json::to_vec(&freshness).unwrap(), &signer).unwrap();
            async move { axum::Json(json!({"freshness":STANDARD.encode(signed.bytes())})) }
        }))
        .route("/team/v1/spaces", axum::routing::post(move |axum::Json(request):axum::Json<super::super::space_service::Request>| {
            let command = decode_record(request.record.as_deref().unwrap()).unwrap();
            command.verify_signature(&host_key.verifying_key()).unwrap();
            assert_eq!(command.body()["action"], "witness_sync");
            sync_count.fetch_add(1, Ordering::SeqCst);
            let answer = json!({"v":1,"kind":"space.response","space":space,"nonce":request.nonce,"body":approved,"ciphertext_hash":null});
            let signed = SignedRecord::sign(&serde_json::to_vec(&answer).unwrap(), &host_key).unwrap();
            let response = super::super::space_service::Response {record:STANDARD.encode(signed.bytes()),credential:credential.clone(),ciphertext:None};
            async move { axum::Json(response) }
        }));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    for state in 0..=2 {
        mode.store(state, Ordering::SeqCst);
        let mut spaces = restored.spaces.take().unwrap();
        let entry = spaces.catalog.entries[0].clone();
        let result = spaces
            .poll_entry(&mut restored, entry, PollMode::Regular)
            .await;
        restored.spaces = Some(spaces);
        let denied = matches!(case, DeferredOwnerCase::Revoked);
        if state < 2 || denied {
            assert_eq!(result.is_err(), state != 0);
            assert_witnessed_restore_quarantined(&mut restored, &address).await;
            let child = restored
                .open_space_child(child_path(&restored, &id).unwrap(), space)
                .await
                .unwrap();
            assert!(!child.session.can_control(space));
            child.close().await.unwrap();
            assert_eq!(
                syncs.load(Ordering::SeqCst),
                usize::from(state == 2 && denied)
            );
            continue;
        }
        result.unwrap();
        let child = &restored.spaces.as_ref().unwrap().children[&id];
        let eligible = matches!(
            case,
            DeferredOwnerCase::Paired | DeferredOwnerCase::PairedAfterRestart
        );
        assert_eq!(child.session.owner_grant_eligible, eligible);
        assert_eq!(child.session.can_control(space), eligible);
        assert_eq!(syncs.load(Ordering::SeqCst), 1);
        // A cache or process restart must not change the authenticated outcome.
        restored.close().await.unwrap();
        restored = ClientApp::open(temp.path().join("restore source"), PASSWORD.into(), true)
            .await
            .unwrap();
        restored
            .configure_witness_pin(Some(authority.witness_pin().unwrap().clone()))
            .unwrap();
        restored.enable_spaces().await.unwrap();
        assert_eq!(
            restored.spaces.as_ref().unwrap().children[&id]
                .session
                .can_control(space),
            eligible
        );
    }
    restored.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn deferred_live_pairing_owner_grants_activate_when_hosting_returns() {
    deferred_owner_grant(DeferredOwnerCase::Paired).await;
}

#[tokio::test]
async fn deferred_live_pairing_owner_grants_survive_restart_before_hosting_returns() {
    deferred_owner_grant(DeferredOwnerCase::PairedAfterRestart).await;
}

#[tokio::test]
async fn deferred_live_pairing_does_not_promote_an_ordinary_backup() {
    deferred_owner_grant(DeferredOwnerCase::Backup).await;
}

#[tokio::test]
async fn deferred_live_pairing_owner_grants_cannot_restore_a_revoked_device() {
    deferred_owner_grant(DeferredOwnerCase::Revoked).await;
}

#[tokio::test]
async fn deferred_live_pairing_owner_grants_do_not_reactivate_a_retired_compartment() {
    deferred_owner_grant(DeferredOwnerCase::Retired).await;
}

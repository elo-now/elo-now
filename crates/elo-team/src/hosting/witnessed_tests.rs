use super::*;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use elo_core::{
    app::{team::EnrollmentRequest, witness_durable_admission::DurableAdmissionRequest},
    authority::*,
    ids::{RecordId, StreamId},
    record::SignedRecord,
    vault::Session,
    witness::{Freshness, HeadRequest, Position},
};
use std::{
    io::{Read, Write},
    sync::Mutex as StdMutex,
};

fn signed<T: Serialize>(body: &T, session: &Session) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(body).unwrap(), session.signing_key()).unwrap()
}
fn encoded(signed: &SignedRecord) -> String {
    STANDARD.encode(signed.bytes())
}
fn fixture() -> (Session, Session, WitnessPin, Authority) {
    let (signer, _) = Session::create().unwrap();
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(signer.signing_key().verifying_key().as_bytes()),
        key_generation: 1,
    };
    let (owner, recovery) = Session::create().unwrap();
    let root = owner.credential().record().body()["root_public_key"]
        .as_str()
        .unwrap()
        .to_string();
    let genesis = SignedRecord::sign(
        &serde_json::to_vec(&SpaceGenesis {
            v: 4,
            kind: "space.genesis".into(),
            nonce: "ab".repeat(16),
            issuer_identity: owner.identity_id(),
            owners: vec![Owner {
                identity_id: owner.identity_id(),
                root_public_key: root.clone(),
            }],
            controller_credential_id: owner.credential().id(),
            witness: Some(pin.clone()),
        })
        .unwrap(),
        owner.signing_key(),
    )
    .unwrap();
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &recovery
            .recover_root(owner.identity_id())
            .unwrap()
            .verifying_key(),
        owner.credential().clone(),
        StreamId::from_bytes([0xab; 16]),
    )
    .unwrap();
    authority
        .apply_config(
            StreamConfig {
                v: 4,
                kind: "stream.config".into(),
                nonce: "ab".repeat(16),
                space_id: authority.space(),
                stream_id: authority.stream(),
                sequence: 1,
                previous_config_id: None,
                controller_credential_id: owner.credential().id(),
                members: vec![Member {
                    identity_id: owner.identity_id(),
                    identity_type: "HUMAN".into(),
                    root_public_key: root,
                    capabilities: vec![
                        Capability::Read,
                        Capability::Post,
                        Capability::ShareHistory,
                        Capability::Manage,
                    ],
                    credential_ids: vec![owner.credential().id()],
                    external: false,
                }],
                owner_credential_ids: vec![owner.credential().id()],
                action: ConfigAction {
                    operation: "create".into(),
                    actor_identity: owner.identity_id(),
                    request_record_id: None,
                },
                chat_kind: Some(ChatKind::Chat),
                recovery: None,
                witness_evidence: None,
            }
            .sign(owner.signing_key())
            .unwrap(),
        )
        .unwrap();
    (owner, signer, pin, authority)
}

fn enrollment(session: &Session, authority: &Authority) -> EnrollmentRequest {
    let contact = elo_core::invite::shared::contact(
        session.credential(),
        session.signing_key(),
        "Test member",
        current().unwrap() + 3_600_000,
    )
    .unwrap();
    let packet = json!({"kind":"Contact","card":encoded(&contact),"credential":encoded(session.credential().record())});
    let mut compressed =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    compressed
        .write_all(&serde_json::to_vec(&packet).unwrap())
        .unwrap();
    EnrollmentRequest {
        v: 1,
        contact: format!(
            "elo://exchange/v1#{}",
            URL_SAFE_NO_PAD.encode(compressed.finish().unwrap())
        ),
        proof: encoded(&signed(
            &json!({"v":1,"kind":"team.join","space":authority.space(),"stream":authority.stream(),"controller":authority.initial_controller().id(),"contact":contact.id()}),
            session,
        )),
    }
}
fn request(session: &Session, authority: &Authority, action: &str, body: Value) -> SpaceRequest {
    let nonce = record::random_hex::<16>().unwrap();
    SpaceRequest {
        nonce: nonce.clone(),
        invitation: None,
        credential: Some(encoded(session.credential().record())),
        record: Some(encoded(&signed(
            &json!({"v":1,"kind":"space.command","space":authority.space(),"nonce":nonce,"issued":current().unwrap(),"action":action,"body":body}),
            session,
        ))),
    }
}
async fn post(router: &Router, path: &str, body: &impl Serialize) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
fn plaintext(response: Value, session: &Session) -> Value {
    use elo_core::crypto::DecryptionIdentity;
    let bytes = STANDARD
        .decode(response["ciphertext"].as_str().unwrap())
        .unwrap();
    let decryptor = age::Decryptor::new(bytes.as_slice()).unwrap();
    let mut reader = decryptor
        .decrypt(session.age_identity().identities().into_iter())
        .unwrap();
    let mut plain = Vec::new();
    reader.read_to_end(&mut plain).unwrap();
    serde_json::from_slice(&plain).unwrap()
}
fn policy(authority: &Authority, owner: &Session, invitation: &Session) -> SignedRecord {
    signed(
        &WitnessInvitationPolicy {
            v: 1,
            kind: "witness.invitation".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            authority_head: authority.head_id().unwrap(),
            issuer_credential_id: owner.credential().id(),
            invitation_public_key: record::encode_hex(
                invitation.signing_key().verifying_key().as_bytes(),
            ),
            not_before_ms: current().unwrap() - 1000,
            expires_at_ms: current().unwrap() + 3_600_000,
            require_approval: true,
            max_uses: 5,
            witness_key_generation: 1,
        },
        owner,
    )
}
fn pending(
    authority: &Authority,
    owner: &Session,
    guest: &Session,
    invitation: &Session,
    address: &SpaceAddress,
) -> DurableAdmissionRequest {
    let policy = policy(authority, owner, invitation);
    let now = current().unwrap();
    let contact = elo_core::invite::shared::contact(
        guest.credential(),
        guest.signing_key(),
        "Candidate",
        now / 1000 + 3600,
    )
    .unwrap();
    let body = WitnessJoinRequest {
        v: 1,
        kind: "witness.join_request".into(),
        nonce: record::random_hex::<32>().unwrap(),
        space_id: authority.space(),
        stream_id: authority.stream(),
        policy_id: policy.id(),
        credential_id: guest.credential().id(),
        contact_id: contact.id(),
        issued_at_ms: now,
        expires_at_ms: now + 1_800_000,
        witness_key_generation: 1,
    };
    let device = signed(&body, guest);
    DurableAdmissionRequest {
        request_id: device.id(),
        name: "Witnessed test".into(),
        address: address.clone(),
        credential: encoded(guest.credential().record()),
        request: WitnessJoinRequestEvidence {
            policy: encoded(&policy),
            device_request: encoded(&device),
            invitation_request: encoded(&signed(&body, invitation)),
            contact: encoded(&contact),
        },
        expires_at_ms: body.expires_at_ms,
    }
}
fn advance(
    authority: &mut Authority,
    owner: &Session,
    witness: &Session,
    guest: &Session,
    add: bool,
) {
    authority.add_credential(guest.credential().clone());
    let mut proposal = authority.head().unwrap().clone();
    proposal.sequence += 1;
    proposal.previous_config_id = authority.head_id();
    proposal.nonce = record::random_hex::<16>().unwrap();
    proposal.witness_evidence = None;
    proposal.action.operation = if add { "replace" } else { "member.removed" }.into();
    proposal
        .members
        .retain(|m| m.identity_id != guest.identity_id());
    if add {
        proposal.members.push(Member {
            identity_id: guest.identity_id(),
            identity_type: "HUMAN".into(),
            root_public_key: guest.credential().record().body()["root_public_key"]
                .as_str()
                .unwrap()
                .into(),
            capabilities: vec![Capability::Read, Capability::Post, Capability::ShareHistory],
            credential_ids: vec![guest.credential().id()],
            external: false,
        });
        proposal.members.sort_by_key(|m| m.identity_id);
    }
    let next = authority
        .prepare_witness_owner_config(
            &proposal.sign(owner.signing_key()).unwrap(),
            witness.signing_key(),
        )
        .unwrap();
    authority.apply_config(next).unwrap();
}

#[tokio::test]
async fn witnessed_routes_create_import_relay_ciphertext_restart_and_deny_stale_membership() {
    let directory = tempfile::tempdir().unwrap();
    let (owner, witness, pin, mut authority) = fixture();
    let witness = Arc::new(witness);
    let head = Arc::new(StdMutex::new((authority.head_id().unwrap(), 1u64)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/head", listener.local_addr().unwrap());
    let server_head = head.clone();
    let server_witness = witness.clone();
    let server_pin = pin.clone();
    let witness_task = tokio::spawn(axum::serve(listener,Router::new().route("/head",axum::routing::post(move |Json(request):Json<HeadRequest>| {
        let head = server_head.clone(); let signer=server_witness.clone(); let pin=server_pin.clone(); async move {
            let (head,sequence)=*head.lock().unwrap();let now=current().unwrap();
            Json(json!({"freshness":encoded(&signed(&Freshness {v:1,kind:"witness.freshness".into(),audience:pin.url,nonce:request.nonce,space_id:request.space_id,stream_id:request.stream_id,authority_head:head,position:Position {sequence,record_id:Some(RecordId::from_bytes([sequence as u8;32]))},issued_at_ms:now,expires_at_ms:now+30_000,witness_key_generation:1},&signer))}))
        }
    }))).into_future());
    let config = HostConfig {
        root: directory.path().join("host"),
        public_url: "https://api.example.test".into(),
        max_spaces_per_identity: 3,
        max_spaces: 128,
        max_space_creations_per_day: 32,
        mailbox_quota_bytes: 150_000_000,
        operator_snapshot: None,
        backup_access_key: None,
        call_admission_key: None,
        attachment_storage: None,
        recovery_recipient: None,
        client_policy: Default::default(),
        witness: Some(pin),
    };
    let mut host = Host::open(config.clone(), false).await.unwrap();
    Arc::get_mut(&mut host)
        .unwrap()
        .witness
        .as_mut()
        .unwrap()
        .test_endpoint(endpoint.clone());
    let command = CreateCommand {
        v: 2,
        kind: "space.create".into(),
        host: format!("{}/spaces/v1/create", config.public_url),
        request_id: "ab".repeat(16),
        issued: current().unwrap(),
        name: "Witnessed test".into(),
        contact_email: "owner@example.test".into(),
        message_lifetime_seconds: 86400,
        require_approval: true,
        authority: Some(authority.call_proof().unwrap()),
    };
    let mut creation = CreateRequest {
        record: encoded(&signed(&command, &owner)),
        credential: encoded(owner.credential().record()),
        work: 0,
    };
    let mut prefix = Sha256::new();
    prefix.update(b"elo.space.create.work.v1\0");
    prefix.update(Sha256::digest(creation.record.as_bytes()));
    prefix.update(Sha256::digest(creation.credential.as_bytes()));
    for nonce in 0u64..64 * (1 << 20) {
        let mut h = prefix.clone();
        h.update(nonce.to_be_bytes());
        let digest = h.finalize();
        if u32::from_be_bytes(digest[..4].try_into().unwrap()).leading_zeros() >= 20 {
            creation.work = nonce;
            break;
        }
    }
    let router = app(host.clone());
    let (status, reply) = post(&router, "/spaces/v1/create", &creation).await;
    assert_eq!(status, StatusCode::OK);
    let reply = plaintext(reply, &owner);
    assert_eq!(reply["kind"], "space.created.witnessed");
    assert!(reply.get("invitation").is_none());
    let address: SpaceAddress = serde_json::from_value(reply["address"].clone()).unwrap();
    let path = reqwest::Url::parse(&address.url).unwrap().path().to_owned();
    let id = reservation_id(owner.identity_id(), &command.request_id);
    let persisted: Value = serde_json::from_slice(
        &vault::read_private(
            &config
                .root
                .join("spaces")
                .join(&id)
                .join("reservation.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(persisted["invitation"].is_null());
    let sync = request(
        &owner,
        &authority,
        "witness_sync",
        json!({"proof":authority.call_proof().unwrap(),"enrollment":enrollment(&owner,&authority)}),
    );
    let (status, reply) = post(&router, &path, &sync).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(plaintext(reply, &owner)["status"], "approved");
    assert_eq!(
        post(
            &router,
            &path,
            &request(&owner, &authority, "authority_publish", json!({}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (guest, _) = Session::create().unwrap();
    let (invitation, _) = Session::create().unwrap();
    let packet = pending(&authority, &owner, &guest, &invitation, &address);
    let submit = request(
        &guest,
        &authority,
        "witness_request",
        json!({"request":packet}),
    );
    assert_eq!(post(&router, &path, &submit).await.0, StatusCode::OK);
    assert_eq!(post(&router, &path, &submit).await.0, StatusCode::OK);
    let (status, reply) = post(
        &router,
        &path,
        &request(
            &owner,
            &authority,
            "witness_pending",
            json!({"request_id":packet.request_id}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        plaintext(reply, &owner)["request"]["request_id"],
        json!(packet.request_id)
    );
    let approval = signed(
        &WitnessApprovalV2 {
            v: 2,
            kind: "witness.approval".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            authority_head: authority.head_id().unwrap(),
            issuer_credential_id: owner.credential().id(),
            request_id: packet.request_id,
            readmission: false,
            expires_at_ms: packet.expires_at_ms,
        },
        &owner,
    );
    assert_eq!(
        post(
            &router,
            &path,
            &request(
                &guest,
                &authority,
                "witness_approve",
                json!({"request_id":packet.request_id,"approval":encoded(&approval)})
            )
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let approve = request(
        &owner,
        &authority,
        "witness_approve",
        json!({"request_id":packet.request_id,"approval":encoded(&approval)}),
    );
    assert_eq!(post(&router, &path, &approve).await.0, StatusCode::OK);
    assert_eq!(post(&router, &path, &approve).await.0, StatusCode::OK);
    let policy = policy(&authority, &owner, &invitation);
    let bytes = vec![1u8; 113];
    let digest = ObjectId::from_bytes(Sha256::digest(&bytes).into());
    let now = current().unwrap();
    let upload_path = format!("/spaces/{id}/invitations/v1");
    let upload_command = invitation_descriptors::UploadCommand {
        v: 1,
        kind: "invitation.descriptor.put".into(),
        nonce: record::random_hex::<32>().unwrap(),
        audience: format!("{}{upload_path}", config.public_url),
        space_id: authority.space(),
        stream_id: authority.stream(),
        authority_head: authority.head_id().unwrap(),
        credential_id: owner.credential().id(),
        policy_id: policy.id(),
        ciphertext_id: digest,
        ciphertext_size: bytes.len() as u64,
        ciphertext_expires_at_ms: now + 600_000,
        issued_at_ms: now,
        expires_at_ms: now + 60_000,
    };
    let upload = invitation_descriptors::UploadRequest {
        command: encoded(&signed(&upload_command, &owner)),
        policy: encoded(&policy),
        ciphertext: STANDARD.encode(&bytes),
    };
    assert_eq!(
        post(&router, &upload_path, &upload).await.0,
        StatusCode::CREATED
    );
    assert_eq!(post(&router, &upload_path, &upload).await.0, StatusCode::OK);
    let get_path = format!("/invitations/v1/{digest}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&get_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()[..],
        bytes
    );
    let mut spoof = upload_command.clone();
    spoof.credential_id = guest.credential().id();
    let spoof = invitation_descriptors::UploadRequest {
        command: encoded(&signed(&spoof, &guest)),
        policy: encoded(&policy),
        ciphertext: STANDARD.encode(&bytes),
    };
    assert_eq!(
        post(&router, &upload_path, &spoof).await.0,
        StatusCode::FORBIDDEN
    );
    drop(router);
    super::tests::close_host(host).await;
    let mut host = Host::open(config.clone(), false).await.unwrap();
    Arc::get_mut(&mut host)
        .unwrap()
        .witness
        .as_mut()
        .unwrap()
        .test_endpoint(endpoint);
    let router = app(host.clone());
    let (_, reply) = post(
        &router,
        &path,
        &request(
            &guest,
            &authority,
            "witness_pending",
            json!({"request_id":packet.request_id}),
        ),
    )
    .await;
    assert_eq!(plaintext(reply, &guest)["approval"], encoded(&approval));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(get_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let old = authority.clone();
    advance(&mut authority, &owner, &witness, &guest, true);
    *head.lock().unwrap() = (authority.head_id().unwrap(), 2);
    host.witness.as_ref().unwrap().clear_test_cache();
    // Old head cannot service reads or upload once the independent witness advances.
    assert_eq!(
        post(
            &router,
            &path,
            &request(
                &owner,
                &old,
                "status",
                json!({"enrollment":enrollment(&owner,&old)})
            )
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let guest_sync = request(
        &guest,
        &authority,
        "witness_sync",
        json!({"proof":authority.call_proof().unwrap(),"enrollment":enrollment(&guest,&authority)}),
    );
    let (status, reply) = post(&router, &path, &guest_sync).await;
    assert_eq!(status, StatusCode::OK);
    let reply = plaintext(reply, &guest);
    assert_eq!(reply["general_head"], json!(authority.head_id()));
    assert_eq!(reply["status"], "approved");
    let space = host.spaces.read().await.get(&id).unwrap().clone();
    assert!(
        space
            .client
            .lock()
            .await
            .as_ref()
            .unwrap()
            .space_access_devices()
            .unwrap()
            .contains(&guest.credential().id())
    );
    advance(&mut authority, &owner, &witness, &guest, false);
    *head.lock().unwrap() = (authority.head_id().unwrap(), 3);
    host.witness.as_ref().unwrap().clear_test_cache();
    assert!(host.require_current_replica(&space).await.is_err());
    let sync = request(
        &owner,
        &authority,
        "witness_sync",
        json!({"proof":authority.call_proof().unwrap(),"enrollment":enrollment(&owner,&authority)}),
    );
    assert_eq!(post(&router, &path, &sync).await.0, StatusCode::OK);
    assert_eq!(
        post(&router, &path, &guest_sync).await.0,
        StatusCode::FORBIDDEN
    );
    assert!(
        !space
            .client
            .lock()
            .await
            .as_ref()
            .unwrap()
            .space_access_devices()
            .unwrap()
            .contains(&guest.credential().id())
    );
    assert!(host.require_current_replica(&space).await.is_ok());
    drop(space);
    drop(router);
    super::tests::close_host(host).await;
    witness_task.abort();
}

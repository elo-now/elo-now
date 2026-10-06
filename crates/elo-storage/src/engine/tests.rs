use super::*;
use ed25519_dalek::VerifyingKey;
use elo_core::{
    authority::{Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig},
    ids::StreamId,
    vault::Session,
};
const NOW: u64 = 1_800_000_000;

#[test]
fn managed_configuration_never_accepts_missing_server_credentials_and_keeps_replay_fence() {
    let (_dir, mut engine, owner, a) = configured();
    let request = prepared(
        &a,
        &owner,
        Operation::ConfigureManaged {
            expected_revision: 1,
            retention_hours: 12,
        },
    );
    let ip = "127.0.0.1".parse().unwrap();
    assert!(engine.apply(&request, ip, NOW).is_err());
    assert_eq!(engine.status(a.space()).unwrap().revision, 1);
    engine
        .apply_with_managed(&request, ip, NOW, Some(&provider()))
        .unwrap();
    assert_eq!(engine.status(a.space()).unwrap().revision, 2);
    assert_eq!(engine.status(a.space()).unwrap().retention_hours, Some(12));
    engine
        .apply_with_managed(&request, ip, NOW, Some(&provider()))
        .unwrap();
    assert_eq!(engine.status(a.space()).unwrap().revision, 2);
}
pub(crate) const AUDIENCE: &str = "https://storage.example.test/storage/v1";
fn authority(owner: &Session) -> Authority {
    authority_with_pin(owner, None)
}
fn authority_with_pin(owner: &Session, pin: Option<WitnessPin>) -> Authority {
    let nonce = record::random_hex::<16>().unwrap();
    let root = owner.credential().record().body()["root_public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let genesis = SpaceGenesis {
        v: if pin.is_some() { 4 } else { 2 },
        witness: pin.clone(),
        kind: "space.genesis".into(),
        nonce: nonce.clone(),
        issuer_identity: owner.identity_id(),
        owners: vec![Owner {
            identity_id: owner.identity_id(),
            root_public_key: root.clone(),
        }],
        controller_credential_id: owner.credential().id(),
    };
    let signed =
        SignedRecord::sign(&serde_json::to_vec(&genesis).unwrap(), owner.signing_key()).unwrap();
    let mut a = Authority::new(
        signed.bytes(),
        signed.id().to_string().parse().unwrap(),
        &VerifyingKey::from_bytes(
            root.parse::<elo_core::ids::IdentityId>()
                .unwrap()
                .as_bytes(),
        )
        .unwrap(),
        owner.credential().clone(),
        nonce.parse::<StreamId>().unwrap(),
    )
    .unwrap();
    let config = StreamConfig {
        witness_evidence: None,
        v: if pin.is_some() { 4 } else { 2 },
        kind: "stream.config".into(),
        nonce,
        space_id: a.space(),
        stream_id: a.stream(),
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
    };
    a.apply_config(config.sign(owner.signing_key()).unwrap())
        .unwrap();
    a
}
fn provider() -> ProviderConfig {
    ProviderConfig::S3Compatible {
        endpoint: "https://s3.example.test".into(),
        region: "test-1".into(),
        bucket: "bucket".into(),
        access_key: "limited-key".into(),
        secret_key: "never-store-this-secret-in-plaintext".into(),
    }
}
fn prepared(a: &Authority, owner: &Session, operation: Operation) -> Verified {
    let signed = broker::sign_command(a, owner, AUDIENCE, Operation::Status, NOW).unwrap();
    let mut command: Command = signed.decode().unwrap();
    command.operation = operation;
    Verified {
        command,
        authority: a.clone(),
        request_id: signed.id(),
    }
}
fn configured() -> (tempfile::TempDir, Engine, Session, Authority) {
    configured_with_pin(None)
}
pub(crate) fn configured_with_pin(
    pin: Option<WitnessPin>,
) -> (tempfile::TempDir, Engine, Session, Authority) {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key");
    std::fs::write(&key, [71u8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut engine = Engine::open(&dir.path().join("data"), &key, AUDIENCE.into(), 128).unwrap();
    let owner = Session::create().unwrap().0;
    let a = authority_with_pin(&owner, pin);
    let request = prepared(
        &a,
        &owner,
        Operation::Configure {
            expected_revision: 0,
            provider: provider(),
            retention_hours: 1,
        },
    );
    engine
        .apply(&request, "127.0.0.1".parse().unwrap(), NOW)
        .unwrap();
    (dir, engine, owner, a)
}
#[test]
fn encrypted_credentials_cas_and_exact_idempotency_survive_restart() {
    let (dir, mut engine, owner, a) = configured();
    let request = prepared(
        &a,
        &owner,
        Operation::Configure {
            expected_revision: 1,
            provider: provider(),
            retention_hours: 1,
        },
    );
    let response = engine
        .apply(&request, "127.0.0.1".parse().unwrap(), NOW)
        .unwrap();
    let replay = engine
        .apply(&request, "127.0.0.1".parse().unwrap(), NOW)
        .unwrap();
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        serde_json::to_value(replay).unwrap()
    );
    let stale = prepared(
        &a,
        &owner,
        Operation::Disable {
            expected_revision: 1,
        },
    );
    assert!(matches!(
        engine.apply(&stale, "127.0.0.1".parse().unwrap(), NOW),
        Err(Error::Conflict)
    ));
    assert_eq!(engine.status(a.space()).unwrap().revision, 2);
    let secret: Vec<u8> = engine
        .db
        .query_row("SELECT secret FROM providers LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert!(!String::from_utf8_lossy(&secret).contains("never-store-this-secret"));
    drop(engine);
    let reopened = Engine::open(
        &dir.path().join("data"),
        &dir.path().join("key"),
        AUDIENCE.into(),
        128,
    )
    .unwrap();
    assert_eq!(reopened.status(a.space()).unwrap().revision, 2);
    assert_eq!(
        reopened.provider(&a.space().to_string(), 2).unwrap().name(),
        "s3_compatible"
    );
}
#[test]
fn denied_operation_does_not_advance_fence_and_old_head_cannot_return() {
    let (_dir, mut engine, owner, old) = configured();
    let mut latest = old.clone();
    let mut config = latest.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = latest.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.action.operation = "replace".into();
    latest
        .apply_config(config.sign(owner.signing_key()).unwrap())
        .unwrap();
    let denied = prepared(
        &latest,
        &owner,
        Operation::Disable {
            expected_revision: 999,
        },
    );
    assert!(matches!(
        engine.apply(&denied, "127.0.0.1".parse().unwrap(), NOW),
        Err(Error::Conflict)
    ));
    let old_status = prepared(&old, &owner, Operation::Status);
    assert!(
        engine
            .apply(&old_status, "127.0.0.1".parse().unwrap(), NOW)
            .is_ok()
    );
    let new_status = prepared(&latest, &owner, Operation::Status);
    engine
        .apply(&new_status, "127.0.0.1".parse().unwrap(), NOW)
        .unwrap();
    assert!(matches!(
        engine.apply(&old_status, "127.0.0.1".parse().unwrap(), NOW),
        Err(Error::Unauthorized)
    ));
}
#[test]
fn tokens_are_hashed_scoped_single_use_and_objects_keep_their_provider_version() {
    let (_dir, mut engine, owner, a) = configured();
    let ip = "127.0.0.1".parse().unwrap();
    let id = AttachmentObjectId::from_bytes([4; 16]);
    let reserve = prepared(
        &a,
        &owner,
        Operation::Reserve {
            object_id: id,
            encrypted_size: 100,
            ciphertext_sha256: "00".repeat(32),
        },
    );
    let Response::Transfer { token, .. } = engine.apply(&reserve, ip, NOW).unwrap() else {
        panic!("transfer expected")
    };
    let saved: String = engine
        .db
        .query_row("SELECT hash FROM tokens", [], |r| r.get(0))
        .unwrap();
    assert_ne!(saved, token);
    assert!(
        engine
            .claim(
                AttachmentObjectId::from_bytes([5; 16]),
                &token,
                "upload",
                NOW
            )
            .is_err()
    );
    assert!(engine.claim(id, &token, "download", NOW).is_err());
    let object = engine.claim(id, &token, "upload", NOW).unwrap();
    assert!(engine.claim(id, &token, "upload", NOW).is_err());
    assert!(matches!(
        engine.apply(
            &prepared(&a, &owner, Operation::Download { object_id: id }),
            ip,
            NOW
        ),
        Err(Error::Missing)
    ));
    engine.uploaded(&object, true).unwrap();
    engine
        .apply(
            &prepared(&a, &owner, Operation::Complete { object_id: id }),
            ip,
            NOW,
        )
        .unwrap();
    engine
        .apply(
            &prepared(
                &a,
                &owner,
                Operation::Configure {
                    expected_revision: 1,
                    provider: provider(),
                    retention_hours: 1,
                },
            ),
            ip,
            NOW,
        )
        .unwrap();
    engine.prune(NOW).unwrap();
    assert!(engine.provider(&object.space, 1).is_ok());
    engine
        .apply(
            &prepared(
                &a,
                &owner,
                Operation::Disable {
                    expected_revision: 2,
                },
            ),
            ip,
            NOW,
        )
        .unwrap();
    assert!(
        engine
            .apply(
                &prepared(&a, &owner, Operation::Download { object_id: id }),
                ip,
                NOW
            )
            .is_ok()
    );
    assert!(engine.garbage(NOW + 3599).unwrap().is_empty());
    assert_eq!(engine.garbage(NOW + 3600).unwrap().len(), 1);
}
#[test]
fn signature_audience_general_and_work_are_verified_before_engine() {
    let owner = Session::create().unwrap().0;
    let a = authority(&owner);
    let signed = broker::sign_command(&a, &owner, AUDIENCE, Operation::Status, NOW).unwrap();
    let req = || Request {
        command: STANDARD.encode(signed.bytes()),
        proof: a.call_proof().unwrap(),
    };
    assert!(Verified::new_test(req(), AUDIENCE, NOW).is_ok());
    assert!(Verified::new_test(req(), "https://wrong.test/storage/v1", NOW).is_err());
    assert!(Verified::new_test(req(), AUDIENCE, NOW + broker::COMMAND_TTL).is_err());
    let mut command: Command = signed.decode().unwrap();
    command.operation = Operation::Configure {
        expected_revision: 0,
        provider: provider(),
        retention_hours: 1,
    };
    let signed =
        SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), owner.signing_key()).unwrap();
    assert!(
        Verified::new_test(
            Request {
                command: STANDARD.encode(signed.bytes()),
                proof: a.call_proof().unwrap()
            },
            AUDIENCE,
            NOW
        )
        .is_err()
    );
}

#[tokio::test]
async fn direct_http_upload_complete_and_download_verify_ciphertext_and_token_scope() {
    use crate::{
        server::{self, Service},
        storage::LocalStorage,
    };
    use std::sync::Arc;
    let (dir, engine, owner, a) = configured();
    let store = LocalStorage::open(&dir.path().join("objects"))
        .await
        .unwrap();
    let service = Service::new_test(engine, AUDIENCE.into()).with_test_storage(Arc::new(store));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            server::router(service).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::new();
    let request = |operation| Request {
        command: STANDARD.encode(
            broker::sign_command(&a, &owner, AUDIENCE, operation, crate::now())
                .unwrap()
                .bytes(),
        ),
        proof: a.call_proof().unwrap(),
    };
    let id = AttachmentObjectId::from_bytes([7; 16]);
    let data = b"encrypted body example";
    let response = client
        .post(format!("{url}/storage/v1/command"))
        .json(&request(Operation::Reserve {
            object_id: id,
            encrypted_size: data.len() as u64,
            ciphertext_sha256: record::encode_hex(&Sha256::digest(data)),
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let Response::Transfer { token, .. } = response.json::<Response>().await.unwrap() else {
        panic!("transfer")
    };
    let response = client
        .put(format!("{url}/storage/v1/objects/{id}"))
        .bearer_auth(&token)
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    let response = client
        .post(format!("{url}/storage/v1/command"))
        .json(&request(Operation::Download { object_id: id }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    let response = client
        .post(format!("{url}/storage/v1/command"))
        .json(&request(Operation::Complete { object_id: id }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response = client
        .post(format!("{url}/storage/v1/command"))
        .json(&request(Operation::Download { object_id: id }))
        .send()
        .await
        .unwrap();
    let Response::Transfer { token, .. } = response.json::<Response>().await.unwrap() else {
        panic!("transfer")
    };
    let wrong = AttachmentObjectId::from_bytes([8; 16]);
    assert_eq!(
        client
            .get(format!("{url}/storage/v1/objects/{wrong}"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let downloaded = client
        .get(format!("{url}/storage/v1/objects/{id}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(downloaded.status(), reqwest::StatusCode::OK);
    assert_eq!(downloaded.bytes().await.unwrap().as_ref(), data);
    assert_eq!(
        client
            .get(format!("{url}/storage/v1/objects/{id}"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    server.abort();
}

#[test]
fn quota_includes_pending_objects_and_expired_tokens_do_not_claim() {
    let (_dir, mut engine, owner, a) = configured();
    let ip = "127.0.0.1".parse().unwrap();
    let mut token = String::new();
    for i in 0..9 {
        let response = engine
            .apply(
                &prepared(
                    &a,
                    &owner,
                    Operation::Reserve {
                        object_id: AttachmentObjectId::from_bytes([i; 16]),
                        encrypted_size: 5 * 1024 * 1024,
                        ciphertext_sha256: "00".repeat(32),
                    },
                ),
                ip,
                NOW,
            )
            .unwrap();
        if let Response::Transfer { token: t, .. } = response {
            token = t;
        }
    }
    assert!(matches!(
        engine.apply(
            &prepared(
                &a,
                &owner,
                Operation::Reserve {
                    object_id: AttachmentObjectId::from_bytes([9; 16]),
                    encrypted_size: 5 * 1024 * 1024,
                    ciphertext_sha256: "00".repeat(32),
                }
            ),
            ip,
            NOW
        ),
        Err(Error::Limit)
    ));
    assert!(
        engine
            .claim(
                AttachmentObjectId::from_bytes([8; 16]),
                &token,
                "upload",
                NOW + broker::TRANSFER_TTL
            )
            .is_err()
    );
}

#[test]
fn registration_work_is_bound_to_the_signed_provider_configuration() {
    let owner = Session::create().unwrap().0;
    let a = authority(&owner);
    let signed = broker::sign_command(
        &a,
        &owner,
        AUDIENCE,
        Operation::Configure {
            expected_revision: 0,
            provider: provider(),
            retention_hours: 1,
        },
        NOW,
    )
    .unwrap();
    assert!(
        Verified::new_test(
            Request {
                command: STANDARD.encode(signed.bytes()),
                proof: a.call_proof().unwrap()
            },
            AUDIENCE,
            NOW
        )
        .is_ok()
    );
    let mut rejected = false;
    for n in 0..4 {
        let mut command: Command = signed.decode().unwrap();
        if let Operation::Configure {
            provider: ProviderConfig::S3Compatible { bucket, .. },
            ..
        } = &mut command.operation
        {
            *bucket = format!("another-bucket-{n}");
        }
        let changed =
            SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), owner.signing_key())
                .unwrap();
        if Verified::new_test(
            Request {
                command: STANDARD.encode(changed.bytes()),
                proof: a.call_proof().unwrap(),
            },
            AUDIENCE,
            NOW,
        )
        .is_err()
        {
            rejected = true;
            break;
        }
    }
    assert!(
        rejected,
        "A registration work nonce must be bound to the exact provider configuration"
    );
}

#[test]
fn interrupted_upload_cleanup_waits_for_the_persisted_provider_lease() {
    let (_dir, mut engine, owner, a) = configured();
    let ip = "127.0.0.1".parse().unwrap();
    let id = AttachmentObjectId::from_bytes([9; 16]);
    let response = engine
        .apply(
            &prepared(
                &a,
                &owner,
                Operation::Reserve {
                    object_id: id,
                    encrypted_size: 100,
                    ciphertext_sha256: "00".repeat(32),
                },
            ),
            ip,
            NOW,
        )
        .unwrap();
    let Response::Transfer { token, .. } = response else {
        panic!("transfer")
    };
    let object = engine.claim(id, &token, "upload", NOW).unwrap();
    engine.uploaded(&object, false).unwrap();
    assert!(engine.garbage(NOW + 99).unwrap().is_empty());
    assert_eq!(engine.garbage(NOW + 100).unwrap().len(), 1);
}

fn add_posting_member(a: &Authority, owner: &Session, peer: &Session) -> Authority {
    let mut next = a.clone();
    next.add_credential(peer.credential().clone());
    let mut config = next.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = next.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.action.operation = "replace".into();
    config.members.push(Member {
        identity_id: peer.identity_id(),
        identity_type: "HUMAN".into(),
        root_public_key: peer.credential().record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into(),
        capabilities: vec![Capability::Read, Capability::Post],
        credential_ids: vec![peer.credential().id()],
        external: false,
    });
    config.members.sort_by_key(|member| member.identity_id);
    next.apply_config(config.sign(owner.signing_key()).unwrap())
        .unwrap();
    next
}
fn reserve(id: u8) -> Operation {
    Operation::Reserve {
        object_id: AttachmentObjectId::from_bytes([id; 16]),
        encrypted_size: 100,
        ciphertext_sha256: "00".repeat(32),
    }
}
fn object_deadline(response: Response) -> u64 {
    let Response::Transfer {
        object_expires_at_ms,
        ..
    } = response
    else {
        panic!("transfer expected")
    };
    object_expires_at_ms
}

#[test]
fn owner_policy_is_signed_cas_guarded_and_cannot_be_changed_by_a_member() {
    let (_dir, mut engine, owner, a) = configured();
    let ip = "127.0.0.1".parse().unwrap();
    let peer = Session::create().unwrap().0;
    let a = add_posting_member(&a, &owner, &peer);
    let operation = Operation::Policy {
        expected_revision: 1,
        retention_hours: 12,
    };
    let signed = broker::sign_command(&a, &peer, AUDIENCE, operation, NOW).unwrap();
    assert!(
        Verified::new_test(
            Request {
                command: STANDARD.encode(signed.bytes()),
                proof: a.call_proof().unwrap()
            },
            AUDIENCE,
            NOW
        )
        .is_err()
    );
    let request = prepared(
        &a,
        &owner,
        Operation::Policy {
            expected_revision: 1,
            retention_hours: 12,
        },
    );
    let accepted = engine.apply(&request, ip, NOW).unwrap();
    assert_eq!(
        serde_json::to_value(&accepted).unwrap(),
        serde_json::to_value(engine.apply(&request, ip, NOW + 5).unwrap()).unwrap()
    );
    assert_eq!(engine.status(a.space()).unwrap().retention_hours, Some(12));
    assert_eq!(engine.status(a.space()).unwrap().revision, 2);
    assert!(matches!(
        engine.apply(
            &prepared(
                &a,
                &owner,
                Operation::Policy {
                    expected_revision: 1,
                    retention_hours: 24
                }
            ),
            ip,
            NOW
        ),
        Err(Error::Conflict)
    ));
    for hours in [0, 2, 25, u32::MAX] {
        assert!(
            broker::sign_command(
                &a,
                &owner,
                AUDIENCE,
                Operation::Policy {
                    expected_revision: 2,
                    retention_hours: hours
                },
                NOW
            )
            .is_err()
        );
    }
    assert_eq!(engine.status(a.space()).unwrap().retention_hours, Some(12));
    // The new head does not allow a member to smuggle a provider replacement
    // with a different policy either.
    let signed = broker::sign_command(
        &a,
        &peer,
        AUDIENCE,
        Operation::Configure {
            expected_revision: 2,
            provider: provider(),
            retention_hours: 24,
        },
        NOW,
    )
    .unwrap();
    assert!(
        Verified::new_test(
            Request {
                command: STANDARD.encode(signed.bytes()),
                proof: a.call_proof().unwrap()
            },
            AUDIENCE,
            NOW
        )
        .is_err()
    );
}

#[test]
fn reserve_uses_broker_time_and_rejects_a_client_supplied_deadline() {
    let (_dir, mut engine, owner, a) = configured();
    let ip = "127.0.0.1".parse().unwrap();
    let request = prepared(&a, &owner, reserve(41));
    let deadline = object_deadline(engine.apply(&request, ip, NOW + 15).unwrap());
    assert_eq!(deadline, (NOW + 15 + 3600) * 1000);
    // A network retry returns the original deadline, not another hour from retry.
    assert_eq!(
        object_deadline(engine.apply(&request, ip, NOW + 30).unwrap()),
        deadline
    );
    let signed = broker::sign_command(&a, &owner, AUDIENCE, reserve(42), NOW).unwrap();
    let mut forged = serde_json::to_value(signed.decode::<Command>().unwrap()).unwrap();
    forged["operation"]["expires_at_ms"] = serde_json::json!((NOW + 24 * 3600) * 1000);
    let signed =
        SignedRecord::sign(&serde_json::to_vec(&forged).unwrap(), owner.signing_key()).unwrap();
    assert!(
        Verified::new_test(
            Request {
                command: STANDARD.encode(signed.bytes()),
                proof: a.call_proof().unwrap()
            },
            AUDIENCE,
            NOW
        )
        .is_err()
    );
}

#[test]
fn policy_changes_affect_only_new_objects_and_preserve_provider_generation() {
    let (_dir, mut engine, owner, a) = configured();
    let ip = "127.0.0.1".parse().unwrap();
    let first = object_deadline(
        engine
            .apply(&prepared(&a, &owner, reserve(51)), ip, NOW)
            .unwrap(),
    );
    engine
        .apply(
            &prepared(
                &a,
                &owner,
                Operation::Policy {
                    expected_revision: 1,
                    retention_hours: 24,
                },
            ),
            ip,
            NOW,
        )
        .unwrap();
    let second = object_deadline(
        engine
            .apply(&prepared(&a, &owner, reserve(52)), ip, NOW)
            .unwrap(),
    );
    engine
        .apply(
            &prepared(
                &a,
                &owner,
                Operation::Policy {
                    expected_revision: 2,
                    retention_hours: 12,
                },
            ),
            ip,
            NOW,
        )
        .unwrap();
    let third = object_deadline(
        engine
            .apply(&prepared(&a, &owner, reserve(53)), ip, NOW)
            .unwrap(),
    );
    assert_eq!(
        (first, second, third),
        (
            (NOW + 3600) * 1000,
            (NOW + 24 * 3600) * 1000,
            (NOW + 12 * 3600) * 1000
        )
    );
    for (id, expires) in [(51, first), (52, second), (53, third)] {
        let stored = read_object(
            &engine.db,
            &a.space().to_string(),
            &AttachmentObjectId::from_bytes([id; 16]).to_string(),
        )
        .unwrap();
        assert_eq!(stored.expires, expires);
        assert_eq!(stored.revision, 1);
    }
    engine.prune(NOW).unwrap();
    assert!(engine.provider(&a.space().to_string(), 1).is_ok());
    assert_eq!(engine.garbage(NOW + 3600).unwrap().len(), 1);
    assert_eq!(engine.garbage(NOW + 12 * 3600).unwrap().len(), 2);
    assert_eq!(engine.garbage(NOW + 24 * 3600).unwrap().len(), 3);
}

#[test]
fn old_staging_configurations_block_reservations_until_an_owner_signs_policy() {
    let (dir, mut engine, owner, a) = configured();
    let ip = "127.0.0.1".parse().unwrap();
    let deadline = object_deadline(
        engine
            .apply(&prepared(&a, &owner, reserve(61)), ip, NOW)
            .unwrap(),
    );
    engine.db.execute_batch("ALTER TABLE settings DROP COLUMN retention_hours; ALTER TABLE settings DROP COLUMN provider_revision;").unwrap();
    drop(engine);
    let mut engine = Engine::open(
        &dir.path().join("data"),
        &dir.path().join("key"),
        AUDIENCE.into(),
        128,
    )
    .unwrap();
    let status = engine.status(a.space()).unwrap();
    assert!(status.configured);
    assert!(!status.enabled);
    assert_eq!(status.retention_hours, None);
    assert!(matches!(
        engine.apply(&prepared(&a, &owner, reserve(62)), ip, NOW),
        Err(Error::NotConfigured)
    ));
    engine
        .apply(
            &prepared(
                &a,
                &owner,
                Operation::Policy {
                    expected_revision: 1,
                    retention_hours: 12,
                },
            ),
            ip,
            NOW,
        )
        .unwrap();
    assert!(engine.status(a.space()).unwrap().enabled);
    assert_eq!(
        object_deadline(
            engine
                .apply(&prepared(&a, &owner, reserve(62)), ip, NOW)
                .unwrap()
        ),
        (NOW + 12 * 3600) * 1000
    );
    let old = read_object(
        &engine.db,
        &a.space().to_string(),
        &AttachmentObjectId::from_bytes([61; 16]).to_string(),
    )
    .unwrap();
    assert_eq!(old.expires, deadline);
    assert_eq!(old.revision, 1);
}

#[test]
fn witnessed_proof_is_required_and_global_position_survives_restart() {
    use ed25519_dalek::SigningKey;
    use elo_core::witness::{Freshness, HeadRequest, Position, verify_freshness};
    let key = SigningKey::from_bytes(&[41; 32]);
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(key.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let (dir, engine, owner, authority) = configured();
    let request = Request {
        command: STANDARD.encode(
            broker::sign_command(&authority, &owner, AUDIENCE, Operation::Status, NOW)
                .unwrap()
                .bytes(),
        ),
        proof: authority.call_proof().unwrap(),
    };
    assert!(Verified::new(request, AUDIENCE, NOW, &pin).is_err());
    engine.pin_witness(&pin).unwrap();
    let lease = |sequence, record_id| {
        let request = HeadRequest {
            space_id: authority.space(),
            stream_id: authority.stream(),
            nonce: record::random_hex::<32>().unwrap(),
        };
        let body = Freshness {
            v: 1,
            kind: "witness.freshness".into(),
            audience: pin.url.clone(),
            nonce: request.nonce.clone(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            authority_head: authority.head_id().unwrap(),
            position: Position {
                sequence,
                record_id: Some(RecordId::from_bytes([record_id; 32])),
            },
            issued_at_ms: NOW * 1000,
            expires_at_ms: NOW * 1000 + 30_000,
            witness_key_generation: 1,
        };
        let encoded = STANDARD.encode(
            SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &key)
                .unwrap()
                .bytes(),
        );
        verify_freshness(
            &pin,
            &request,
            &encoded,
            std::time::Instant::now(),
            NOW * 1000,
            None,
        )
        .unwrap()
    };
    engine.observe_witness(&lease(5, 5), NOW * 1000).unwrap();
    drop(engine);
    let engine = Engine::open(
        &dir.path().join("data"),
        &dir.path().join("key"),
        AUDIENCE.into(),
        128,
    )
    .unwrap();
    assert_eq!(engine.witness_position().unwrap().unwrap().sequence, 5);
    assert!(engine.observe_witness(&lease(4, 4), NOW * 1000).is_err());
    assert!(engine.observe_witness(&lease(5, 6), NOW * 1000).is_err());
    engine.observe_witness(&lease(6, 6), NOW * 1000).unwrap();
    assert!(
        engine
            .check_witness(&lease(6, 6), NOW * 1000 + 30_000)
            .is_err()
    );
    let mut another_pin = pin.clone();
    another_pin.key_generation = 2;
    assert!(matches!(
        engine.pin_witness(&another_pin),
        Err(Error::Conflict)
    ));
    engine.pin_witness(&pin).unwrap();
}

/// Requires an independently downloaded and checksum-verified S3 server executable,
/// bound only to loopback with an ephemeral TLS CA and private test credentials.
/// The JSON file named by ELO_S3_TEST_CONFIG must be a 0600 regular file.
#[tokio::test]
#[ignore = "Requires an isolated real S3 TLS service; see ELO_S3_TEST_CONFIG"]
async fn real_s3_sigv4_provider_rotation_and_signed_retention_lifecycle() {
    use crate::storage::{AttachmentStorage, S3CompatibleStorage};
    use axum::body::Body;
    use futures_util::StreamExt;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        endpoint: String,
        root_pem: std::path::PathBuf,
        access_key: String,
        secret_key: String,
    }
    let path = std::env::var("ELO_S3_TEST_CONFIG").expect("private S3 fixture path");
    let fixture: Fixture = serde_json::from_slice(&Zeroizing::new(
        elo_core::vault::read_private(Path::new(&path)).unwrap(),
    ))
    .unwrap();
    let pem = std::fs::read(&fixture.root_pem).unwrap();
    let suffix = record::random_hex::<8>().unwrap();
    let first_bucket = format!("elo-test-a-{suffix}");
    let second_bucket = format!("elo-test-b-{suffix}");
    let open = |bucket: &str, secret: &str| {
        S3CompatibleStorage::loopback_tls_fixture(
            &fixture.endpoint,
            bucket,
            &fixture.access_key,
            secret,
            &pem,
        )
        .unwrap()
    };
    let first = open(&first_bucket, &fixture.secret_key);
    let second = open(&second_bucket, &fixture.secret_key);
    first.fixture_bucket(true).await.unwrap();
    second.fixture_bucket(true).await.unwrap();
    let (_dir, mut engine, owner, a) = configured();
    let ip = "127.0.0.1".parse().unwrap();
    let config = |bucket: &str| ProviderConfig::S3Compatible {
        endpoint: fixture.endpoint.clone(),
        region: "us-east-1".into(),
        bucket: bucket.into(),
        access_key: fixture.access_key.clone(),
        secret_key: fixture.secret_key.clone(),
    };
    engine
        .apply(
            &prepared(
                &a,
                &owner,
                Operation::Configure {
                    expected_revision: 1,
                    provider: config(&first_bucket),
                    retention_hours: 1,
                },
            ),
            ip,
            NOW,
        )
        .unwrap();
    let body = b"real S3 verifies SigV4 and stores this bounded ciphertext";
    let make_reserve = |id: u8| Operation::Reserve {
        object_id: AttachmentObjectId::from_bytes([id; 16]),
        encrypted_size: body.len() as u64,
        ciphertext_sha256: record::encode_hex(&Sha256::digest(body)),
    };
    let result = async {
        let response = engine
            .apply(&prepared(&a, &owner, make_reserve(71)), ip, NOW)
            .unwrap();
        let Response::Transfer {
            object_id,
            token,
            object_expires_at_ms,
            ..
        } = response
        else {
            panic!("transfer")
        };
        assert_eq!(object_expires_at_ms, (NOW + 3600) * 1000);
        let old = engine.claim(object_id, &token, "upload", NOW).unwrap();
        first
            .put(
                &old.space,
                &old.object,
                Body::from(body.as_slice()),
                old.size,
            )
            .await
            .unwrap();
        engine.uploaded(&old, true).unwrap();
        engine
            .apply(
                &prepared(&a, &owner, Operation::Complete { object_id }),
                ip,
                NOW,
            )
            .unwrap();
        // A deliberately wrong signature must fail on the independent S3 server.
        let wrong = open(&first_bucket, "invalid-test-signing-secret");
        assert!(wrong.get(&old.space, &old.object).await.is_err());
        let mut fetched = first.get(&old.space, &old.object).await.unwrap();
        let mut bytes = Vec::new();
        while let Some(chunk) = fetched.body.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(record::encode_hex(&Sha256::digest(&bytes)), old.hash);
        // Rotate actual buckets. Old object IDs must continue to use generation2.
        engine
            .apply(
                &prepared(
                    &a,
                    &owner,
                    Operation::Configure {
                        expected_revision: 2,
                        provider: config(&second_bucket),
                        retention_hours: 12,
                    },
                ),
                ip,
                NOW,
            )
            .unwrap();
        assert!(matches!(
            engine.apply(
                &prepared(
                    &a,
                    &owner,
                    Operation::Configure {
                        expected_revision: 2,
                        provider: config(&first_bucket),
                        retention_hours: 24
                    }
                ),
                ip,
                NOW
            ),
            Err(Error::Conflict)
        ));
        engine
            .apply(
                &prepared(
                    &a,
                    &owner,
                    Operation::Policy {
                        expected_revision: 3,
                        retention_hours: 24,
                    },
                ),
                ip,
                NOW,
            )
            .unwrap();
        let response = engine
            .apply(&prepared(&a, &owner, make_reserve(72)), ip, NOW)
            .unwrap();
        let Response::Transfer {
            object_id,
            token,
            object_expires_at_ms,
            ..
        } = response
        else {
            panic!("transfer")
        };
        assert_eq!(object_expires_at_ms, (NOW + 24 * 3600) * 1000);
        let new = engine.claim(object_id, &token, "upload", NOW).unwrap();
        assert_eq!((old.revision, new.revision), (2, 3));
        second
            .put(
                &new.space,
                &new.object,
                Body::from(body.as_slice()),
                new.size,
            )
            .await
            .unwrap();
        engine.uploaded(&new, true).unwrap();
        engine
            .apply(
                &prepared(&a, &owner, Operation::Complete { object_id }),
                ip,
                NOW,
            )
            .unwrap();
        assert!(second.get(&old.space, &old.object).await.is_err());
        assert!(first.get(&new.space, &new.object).await.is_err());
        let due = engine.garbage(NOW + 3600).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].object, old.object);
        first.delete(&old.space, &old.object).await.unwrap();
        engine.deleted(&old).unwrap();
        engine.prune(NOW + 3600).unwrap();
        assert!(first.get(&old.space, &old.object).await.is_err());
        assert!(second.get(&new.space, &new.object).await.is_ok());
        let due = engine.garbage(NOW + 24 * 3600).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].object, new.object);
        second.delete(&new.space, &new.object).await.unwrap();
        engine.deleted(&new).unwrap();
        assert!(second.get(&new.space, &new.object).await.is_err());
        assert_eq!(engine.status(a.space()).unwrap().used_bytes, 0);
    };
    // Explicit cleanup of only the two randomly named buckets created above.
    // The process supervisor also removes the private S3 server data directory.
    result.await;
    first.fixture_bucket(false).await.unwrap();
    second.fixture_bucket(false).await.unwrap();
}

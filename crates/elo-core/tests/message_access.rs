#[allow(dead_code)]
mod common;
use elo_core::{
    crypto,
    erasure::{self, RetentionClaim},
    identity::DeviceRevocation,
    ids::{MailboxId, ObjectId, RecordId},
    record::{self, ChatMessage, MessageAccess, MessageLocator, SignedRecord},
    replica::{MailboxDescriptor, ReplicaError, ReplicaStore, TransferHint},
    retention_access::{Context, Operation, Proof, public_key},
    store::{ClientStore, LocalTime},
    sync::{FixedDemoAuthority, SyncClient},
    vault::{RecoveryCard, Session},
};
use rusqlite::Connection;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
struct Fixture {
    dir: tempfile::TempDir,
    replica: ReplicaStore,
    mailbox: MailboxDescriptor,
    alice: Session,
    bob: Session,
    bob_card: RecoveryCard,
    outsider: Session,
    message: SignedRecord,
    locator: SignedRecord,
    body: Vec<u8>,
    locator_bytes: Vec<u8>,
    request_seed: String,
    accept_seed: String,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let replica = ReplicaStore::open(dir.path()).await.unwrap();
        let mailbox = replica.create_mailbox(200_000).await.unwrap();
        let alice = Session::create().unwrap().0;
        let (bob, bob_card) = Session::create().unwrap();
        let outsider = Session::create().unwrap().0;
        replica
            .set_space_members(
                mailbox.mailbox_id,
                vec![
                    alice.identity_id(),
                    bob.identity_id(),
                    outsider.identity_id(),
                ],
            )
            .await
            .unwrap();
        let request_seed = record::random_hex::<32>().unwrap();
        let accept_seed = record::random_hex::<32>().unwrap();
        let mut chat: ChatMessage = SignedRecord::parse(include_bytes!(
            "../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap()
        .chat()
        .unwrap();
        chat.issuer_identity = alice.identity_id();
        chat.issuer_credential = alice.credential().id();
        chat.audience = vec![alice.identity_id(), bob.identity_id()];
        chat.audience.sort();
        let mut recipients = vec![alice.credential().clone(), bob.credential().clone()];
        recipients.sort_by_key(|c| c.id());
        chat.recipient_credentials = recipients.iter().map(|c| c.id()).collect();
        chat.access = Some(MessageAccess {
            request_key: public_key(&request_seed).unwrap(),
            accept_secret: Some(accept_seed.clone()),
        });
        let message = chat.sign(alice.signing_key()).unwrap();
        let body = erasure::wrap_subjects_with_retention(
            crypto::seal_chat(&message, &recipients).unwrap(),
            alice.credential(),
            alice.signing_key(),
            vec![],
            Some(RetentionClaim::MessageBody {
                locator_nonce: chat.nonce.clone(),
                record_id: message.id(),
                lifetime_seconds: 21_600,
                direct_peer: Some(bob.identity_id()),
                request_key: public_key(&request_seed).unwrap(),
                accept_key: Some(public_key(&accept_seed).unwrap()),
            }),
        )
        .unwrap();
        chat.kind = "chat.locator".into();
        chat.payload.text.clear();
        chat.payload.sender_name = None;
        chat.access = None;
        chat.locator = Some(MessageLocator {
            message_record_id: message.id(),
            body_object_id: ObjectId::of_ciphertext(&body),
            locator_nonce: chat.nonce.clone(),
            request_secret: request_seed.clone(),
        });
        let locator = chat.sign(alice.signing_key()).unwrap();
        let locator_bytes = erasure::wrap_subjects_with_retention(
            crypto::seal_chat(&locator, &recipients).unwrap(),
            alice.credential(),
            alice.signing_key(),
            vec![],
            Some(RetentionClaim::MessageLocator {
                locator_nonce: chat.nonce.clone(),
                record_id: message.id(),
                body_object_id: ObjectId::of_ciphertext(&body),
                lifetime_seconds: 21_600,
                request_key: public_key(&request_seed).unwrap(),
            }),
        )
        .unwrap();
        let result = Self {
            dir,
            replica,
            mailbox,
            alice,
            bob,
            bob_card,
            outsider,
            message,
            locator,
            body,
            locator_bytes,
            request_seed,
            accept_seed,
        };
        for bytes in [&result.locator_bytes, &result.body] {
            result.upload(&result.alice, bytes.clone()).await.unwrap();
        }
        result
    }
    fn object(&self) -> ObjectId {
        ObjectId::of_ciphertext(&self.body)
    }
    fn db(&self) -> Connection {
        Connection::open(self.dir.path().join("replica.sqlite")).unwrap()
    }
    fn context(&self, session: &Session, operation: Operation) -> Context {
        Context {
            operation,
            replica: self.replica.peer_id(),
            mailbox: self.mailbox.mailbox_id,
            object: self.object(),
            record: self.message.id(),
            actor: session.credential().into(),
        }
    }
    fn proof(&self, session: &Session, operation: Operation, seed: &str) -> Proof {
        Proof::issue(seed, &self.context(session, operation), now()).unwrap()
    }
    async fn upload(
        &self,
        session: &Session,
        bytes: Vec<u8>,
    ) -> Result<(bool, Vec<u8>), ReplicaError> {
        self.replica
            .post_authenticated(
                self.mailbox.mailbox_id,
                self.mailbox.write_token.clone(),
                ObjectId::of_ciphertext(&bytes),
                bytes,
                TransferHint::Eager,
                true,
                Some(session.credential().into()),
            )
            .await
    }
    async fn expire(&self) {
        self.db()
            .execute(
                "UPDATE message_bodies SET expires_local_ms=received_local_ms",
                [],
            )
            .unwrap();
        self.replica.maintain_message_lifetime().await.unwrap();
    }
    async fn request(&self, session: &Session, proof: Proof) -> Result<(), ReplicaError> {
        self.replica
            .request_message(
                self.mailbox.mailbox_id,
                session.credential().into(),
                self.object(),
                self.message.id(),
                proof,
            )
            .await
    }
    async fn accept(&self, session: &Session, proof: Proof) -> Result<(), ReplicaError> {
        self.replica
            .accept_message(
                self.mailbox.mailbox_id,
                session.credential().into(),
                self.object(),
                self.message.id(),
                proof,
            )
            .await
    }
    async fn get_body(&self) -> Result<Vec<u8>, ReplicaError> {
        self.replica
            .get(
                self.mailbox.mailbox_id,
                self.mailbox.read_token.clone(),
                self.object(),
            )
            .await
    }
}

#[tokio::test]
async fn encrypted_locator_and_body_carry_separate_capabilities_and_authenticated_metadata() {
    let f = Fixture::new().await;
    let locator = crypto::open_record(&f.locator_bytes, f.bob.age_identity())
        .unwrap()
        .chat()
        .unwrap();
    assert_eq!(locator.locator.unwrap().request_secret, f.request_seed);
    assert!(locator.access.is_none());
    assert_eq!(
        crypto::open_record(&f.body, f.bob.age_identity())
            .unwrap()
            .chat()
            .unwrap()
            .access
            .unwrap()
            .accept_secret,
        Some(f.accept_seed.clone())
    );
    assert!(crypto::open_record(&f.body, f.outsider.age_identity()).is_err());
    assert!(crypto::open_record(&f.locator_bytes, f.outsider.age_identity()).is_err());
    for bytes in [&f.body, &f.locator_bytes] {
        let visible = String::from_utf8_lossy(bytes);
        assert!(!visible.contains(&f.request_seed));
        assert!(!visible.contains(&f.accept_seed));
    }
    let content = erasure::inspect(&f.body).unwrap().unwrap();
    for field in ["record", "peer", "key", "nonce"] {
        let mut claim = content.retention.clone().unwrap();
        if let RetentionClaim::MessageBody {
            record_id,
            direct_peer,
            request_key,
            locator_nonce,
            ..
        } = &mut claim
        {
            match field {
                "record" => *record_id = f.locator.id(),
                "peer" => *direct_peer = Some(f.outsider.identity_id()),
                "key" => *request_key = public_key(&record::random_hex::<32>().unwrap()).unwrap(),
                _ => *locator_nonce = record::random_hex::<16>().unwrap(),
            }
        }
        let forged = erasure::wrap_subjects_with_retention(
            content.ciphertext.to_vec(),
            f.alice.credential(),
            f.alice.signing_key(),
            vec![],
            Some(claim),
        )
        .unwrap();
        assert!(
            crypto::open_record(&forged, f.bob.age_identity()).is_err(),
            "{field}"
        );
    }
    assert!(
        f.accept(&f.bob, f.proof(&f.bob, Operation::Accept, &f.request_seed))
            .await
            .is_err()
    );
    assert_eq!(f.get_body().await.unwrap(), f.body);
}

#[tokio::test]
async fn proof_is_bound_to_operation_replica_mailbox_object_record_identity_and_device() {
    let f = Fixture::new().await;
    let context = f.context(&f.bob, Operation::Request);
    let proof = Proof::issue(&f.request_seed, &context, 1_000_000).unwrap();
    let key = public_key(&f.request_seed).unwrap();
    proof.verify(&key, &context, 1_000_001).unwrap();
    assert!(proof.verify(&key, &context, proof.expires_ms).is_err());
    assert!(proof.verify(&key, &context, 1).is_err());
    for field in 0..7 {
        let mut changed = f.context(&f.bob, Operation::Request);
        match field {
            0 => changed.operation = Operation::Accept,
            1 => changed.replica = elo_core::ids::PeerId::from_bytes([9; 32]),
            2 => changed.mailbox = MailboxId::from_bytes([9; 32]),
            3 => changed.object = ObjectId::from_bytes([9; 32]),
            4 => changed.record = RecordId::from_bytes([9; 32]),
            5 => changed.actor.identity = f.outsider.identity_id(),
            _ => changed.actor.credential = f.outsider.credential().id(),
        }
        assert!(
            proof.verify(&key, &changed, 1_000_001).is_err(),
            "field {field}"
        );
    }
}

#[tokio::test]
async fn restart_preserves_the_first_deadline_and_quota_includes_request_metadata() {
    let mut f = Fixture::new().await;
    f.expire().await;
    let proof = f.proof(&f.bob, Operation::Request, &f.request_seed);
    let db = f.db();
    let stored: i64 = db
        .query_row(
            "SELECT COALESCE(sum(wire_size_bytes),0) FROM objects",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // Body and locator reserve two metadata rows; leave no room for a request.
    db.execute("UPDATE mailboxes SET quota_bytes=?1", [stored + 2048])
        .unwrap();
    assert!(matches!(
        f.request(&f.bob, proof.clone()).await,
        Err(ReplicaError::Quota)
    ));
    db.execute("UPDATE mailboxes SET quota_bytes=200000", [])
        .unwrap();
    f.request(&f.bob, proof.clone()).await.unwrap();
    let deadline: i64 = db
        .query_row("SELECT expires_local_ms FROM message_requests", [], |r| {
            r.get(0)
        })
        .unwrap();
    drop(db);
    let other = tempfile::tempdir().unwrap();
    let placeholder = ReplicaStore::open(other.path()).await.unwrap();
    drop(std::mem::replace(&mut f.replica, placeholder));
    f.replica = ReplicaStore::open(f.dir.path()).await.unwrap();
    f.request(&f.bob, proof).await.unwrap();
    let after: i64 = f
        .db()
        .query_row("SELECT expires_local_ms FROM message_requests", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(after, deadline);
    f.upload(&f.alice, f.body.clone()).await.unwrap();
    let body_expiry: i64 = f
        .db()
        .query_row("SELECT expires_local_ms FROM message_bodies", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(body_expiry, deadline);
}

#[tokio::test]
async fn request_retries_and_old_acceptance_cannot_extend_or_delete_a_new_refill() {
    let f = Fixture::new().await;
    let acceptance = f.proof(&f.bob, Operation::Accept, &f.accept_seed);
    f.accept(&f.bob, acceptance.clone()).await.unwrap();
    let request = f.proof(&f.bob, Operation::Request, &f.request_seed);
    f.request(&f.bob, request.clone()).await.unwrap();
    let expiry = || {
        f.db()
            .query_row("SELECT expires_local_ms FROM message_requests", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
    };
    let deadline = expiry();
    f.request(&f.bob, request.clone()).await.unwrap();
    f.request(&f.bob, f.proof(&f.bob, Operation::Request, &f.request_seed))
        .await
        .unwrap();
    assert_eq!(expiry(), deadline);
    f.upload(&f.alice, f.body.clone()).await.unwrap();
    f.accept(&f.bob, acceptance.clone()).await.unwrap();
    assert_eq!(f.get_body().await.unwrap(), f.body);
    let body_expiry: i64 = f
        .db()
        .query_row("SELECT expires_local_ms FROM message_bodies", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(body_expiry, deadline);
    f.expire().await;
    f.db()
        .execute(
            "UPDATE message_requests SET expires_local_ms=requested_local_ms",
            [],
        )
        .unwrap();
    let expired_deadline = expiry();
    f.request(&f.bob, request).await.unwrap();
    assert_eq!(expiry(), expired_deadline);
    assert!(matches!(
        f.upload(&f.alice, f.body.clone()).await,
        Err(ReplicaError::Expired)
    ));
    let stale = Proof::issue(
        &f.request_seed,
        &f.context(&f.bob, Operation::Request),
        now() - 400_000,
    )
    .unwrap();
    assert!(matches!(
        f.request(&f.bob, stale).await,
        Err(ReplicaError::Unauthorized)
    ));
    let request = f.proof(&f.bob, Operation::Request, &f.request_seed);
    f.request(&f.bob, request.clone()).await.unwrap();
    f.upload(&f.alice, f.body.clone()).await.unwrap();
    f.accept(&f.bob, f.proof(&f.bob, Operation::Accept, &f.accept_seed))
        .await
        .unwrap();
    f.request(&f.bob, request).await.unwrap();
    assert!(matches!(
        f.upload(&f.alice, f.body.clone()).await,
        Err(ReplicaError::Expired)
    ));
    f.request(&f.bob, f.proof(&f.bob, Operation::Request, &f.request_seed))
        .await
        .unwrap();
    f.upload(&f.alice, f.body.clone()).await.unwrap();
    f.accept(&f.bob, acceptance).await.unwrap();
    assert_eq!(
        f.get_body().await.unwrap(),
        f.body,
        "an older acceptance is harmless even after the last nonce changed"
    );
}

#[tokio::test]
async fn removal_revocation_and_space_deletion_block_even_a_retained_secret() {
    let f = Fixture::new().await;
    f.expire().await;
    f.request(&f.bob, f.proof(&f.bob, Operation::Request, &f.request_seed))
        .await
        .unwrap();
    let revoked = DeviceRevocation::issue(
        &f.bob_card.recover_root(f.bob.identity_id()).unwrap(),
        f.bob.credential(),
    )
    .unwrap();
    f.replica.revocations().insert(&revoked).unwrap();
    assert!(matches!(
        f.request(&f.bob, f.proof(&f.bob, Operation::Request, &f.request_seed))
            .await,
        Err(ReplicaError::Unauthorized)
    ));
    assert!(matches!(
        f.upload(&f.bob, f.body.clone()).await,
        Err(ReplicaError::Unauthorized)
    ));
    assert!(
        matches!(
            f.upload(&f.alice, f.body.clone()).await,
            Err(ReplicaError::Expired)
        ),
        "revoking the requester invalidates its outstanding window"
    );
    let replacement = Session::recover(&f.bob_card, f.bob.identity_id()).unwrap();
    assert!(
        f.request(
            &replacement,
            f.proof(&f.bob, Operation::Request, &f.request_seed)
        )
        .await
        .is_err()
    );
    f.request(
        &replacement,
        f.proof(&replacement, Operation::Request, &f.request_seed),
    )
    .await
    .unwrap();
    f.replica
        .set_space_members(f.mailbox.mailbox_id, vec![f.alice.identity_id()])
        .await
        .unwrap();
    assert!(matches!(
        f.request(
            &replacement,
            f.proof(&replacement, Operation::Request, &f.request_seed)
        )
        .await,
        Err(ReplicaError::Unauthorized)
    ));
    assert!(matches!(
        f.upload(&f.alice, f.body.clone()).await,
        Err(ReplicaError::Expired)
    ));
    f.replica
        .delete_mailbox_tree(f.mailbox.mailbox_id)
        .await
        .unwrap();
    assert!(matches!(
        f.request(
            &f.alice,
            f.proof(&f.alice, Operation::Request, &f.request_seed)
        )
        .await,
        Err(ReplicaError::Unauthorized)
    ));
}

#[tokio::test]
async fn http_recipient_can_refill_but_a_space_member_without_history_cannot() {
    let f = Fixture::new().await;
    let (url, server) = common::server(f.replica.clone()).await;
    let bob = common::peer(&url, &f.replica, &f.mailbox, true, true).with_identity(&f.bob);
    let outsider =
        common::peer(&url, &f.replica, &f.mailbox, true, true).with_identity(&f.outsider);
    f.expire().await;
    assert!(
        outsider
            .request_message(
                f.object(),
                f.message.id(),
                &record::random_hex::<32>().unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        bob.request_message(f.object(), f.locator.id(), &f.request_seed)
            .await
            .is_err()
    );
    let locator = crypto::open_record(&f.locator_bytes, f.bob.age_identity())
        .unwrap()
        .chat()
        .unwrap()
        .locator
        .unwrap();
    bob.request_message(f.object(), f.message.id(), &locator.request_secret)
        .await
        .unwrap();
    assert!(
        matches!(
            f.replica
                .post_classified(
                    f.mailbox.mailbox_id,
                    f.mailbox.write_token.clone(),
                    f.object(),
                    f.body.clone(),
                    TransferHint::Eager,
                    true
                )
                .await,
            Err(ReplicaError::Unauthorized)
        ),
        "an active request does not authorize an anonymous uploader"
    );
    f.upload(&f.alice, f.body.clone()).await.unwrap();
    assert_eq!(
        bob.get(f.object(), f.body.len() as u64).await.unwrap(),
        f.body
    );
    assert!(
        bob.accept_message(f.object(), f.message.id(), &locator.request_secret)
            .await
            .is_err()
    );
    let chat = crypto::open_record(&f.body, f.bob.age_identity())
        .unwrap()
        .chat()
        .unwrap();
    bob.accept_message(
        f.object(),
        f.message.id(),
        chat.access.unwrap().accept_secret.as_deref().unwrap(),
    )
    .await
    .unwrap();
    assert!(matches!(f.get_body().await, Err(ReplicaError::NotFound)));
    server.abort();
}

#[tokio::test]
async fn sync_acknowledges_only_after_authority_verification_and_durable_acceptance() {
    let f = Fixture::new().await;
    let (url, server) = common::server(f.replica.clone()).await;
    let peers = [common::peer(&url, &f.replica, &f.mailbox, true, true).with_identity(&f.bob)];
    let chat = f.message.chat().unwrap();
    let mut authority = FixedDemoAuthority {
        space: chat.space_id,
        stream: chat.stream_id,
        config: chat.config_id,
        readers: chat.audience.into_iter().collect(),
        posters: Default::default(),
        credentials: [f.alice.credential().clone(), f.bob.credential().clone()]
            .into_iter()
            .map(|c| (c.id(), c))
            .collect(),
    };
    let rejected_dir = tempfile::tempdir().unwrap();
    let rejected = ClientStore::open(rejected_dir.path()).await.unwrap();
    let sync = SyncClient {
        store: &rejected,
        identity: f.bob.age_identity(),
        credential: f.bob.credential().id(),
        authority: &authority,
        peers: &peers,
    };
    assert!(
        sync.once(LocalTime::from_millis(now()).unwrap())
            .await
            .unwrap()
            .rejected
            > 0
    );
    assert_eq!(f.get_body().await.unwrap(), f.body);
    authority.posters.insert(f.alice.identity_id());
    let accepted_dir = tempfile::tempdir().unwrap();
    let accepted = ClientStore::open(accepted_dir.path()).await.unwrap();
    let sync = SyncClient {
        store: &accepted,
        identity: f.bob.age_identity(),
        credential: f.bob.credential().id(),
        authority: &authority,
        peers: &peers,
    };
    assert_eq!(
        sync.once(LocalTime::from_millis(now()).unwrap())
            .await
            .unwrap()
            .accepted,
        2
    );
    assert!(accepted.previously_accepted(f.message.id()).await.unwrap());
    assert_eq!(
        accepted.get_object(f.object()).await.unwrap(),
        Some(f.body.clone())
    );
    assert!(matches!(f.get_body().await, Err(ReplicaError::NotFound)));
    accepted.close().await.unwrap();
    let reopened = ClientStore::open(accepted_dir.path()).await.unwrap();
    assert!(reopened.previously_accepted(f.message.id()).await.unwrap());
    assert_eq!(reopened.get_object(f.object()).await.unwrap(), Some(f.body));
    reopened.close().await.unwrap();
    rejected.close().await.unwrap();
    server.abort();
}

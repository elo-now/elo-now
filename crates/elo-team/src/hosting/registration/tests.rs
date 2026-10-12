use super::*;
use crate::hosting::witnessed_tests::{fixture, post, solve_creation_work};
use elo_core::{
    authority::{Authority, SpaceGenesis},
    identity::DeviceRevocation,
    ids::StreamId,
    record::SignedRecord,
    vault::Session,
};

fn request(owner: &Session, template: &Authority, nonce: u8) -> CreateRequest {
    let id = record::encode_hex(&[nonce; 16]);
    let mut genesis: SpaceGenesis = template.genesis().decode().unwrap();
    genesis.nonce = id.clone();
    genesis.issuer_identity = owner.identity_id();
    genesis.controller_credential_id = owner.credential().id();
    genesis.owners[0].identity_id = owner.identity_id();
    genesis.owners[0].root_public_key = owner.credential().record().body()["root_public_key"]
        .as_str()
        .unwrap()
        .into();
    let genesis =
        SignedRecord::sign(&serde_json::to_vec(&genesis).unwrap(), owner.signing_key()).unwrap();
    let root: elo_core::ids::RecordId = owner.credential().record().body()["root_public_key"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &ed25519_dalek::VerifyingKey::from_bytes(root.as_bytes()).unwrap(),
        owner.credential().clone(),
        StreamId::from_bytes([nonce; 16]),
    )
    .unwrap();
    let mut initial = template.head().unwrap().clone();
    initial.nonce = id.clone();
    initial.space_id = authority.space();
    initial.stream_id = authority.stream();
    initial.controller_credential_id = owner.credential().id();
    initial.owner_credential_ids = vec![owner.credential().id()];
    initial.members[0].identity_id = owner.identity_id();
    initial.members[0].root_public_key = root.to_string();
    initial.members[0].credential_ids = vec![owner.credential().id()];
    initial.action.actor_identity = owner.identity_id();
    authority
        .apply_config(initial.sign(owner.signing_key()).unwrap())
        .unwrap();
    let command = CreateCommand {
        v: 2,
        kind: "space.create".into(),
        host: "https://api.example.test/spaces/v1/create".into(),
        request_id: id,
        issued: current().unwrap(),
        name: "Prepared Space".into(),
        contact_email: "owner@example.test".into(),
        message_lifetime_seconds: Default::default(),
        require_approval: true,
        authority: Some(authority.call_proof().unwrap()),
    };
    let mut request = CreateRequest {
        record: STANDARD.encode(
            SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), owner.signing_key())
                .unwrap()
                .bytes(),
        ),
        credential: STANDARD.encode(owner.credential().record().bytes()),
        work: 0,
    };
    solve_creation_work(&mut request);
    request
}

fn config(directory: &FilePath, pin: &elo_core::authority::WitnessPin) -> HostConfig {
    let key = directory.join("registration-key.bin");
    vault::write_private(&key, &[97; 32], false).unwrap();
    serde_json::from_value(json!({
        "root":directory.join("host"),"public_url":"https://api.example.test",
        "max_spaces_per_identity":2,"max_spaces":2,"max_space_creations_per_day":2,
        "mailbox_quota_bytes":150_000_000,"witness":pin,"registration_signing_key":key,
    }))
    .unwrap()
}

#[tokio::test]
async fn preparation_is_public_bounded_durable_and_binds_the_exact_creation() {
    let directory = tempfile::tempdir().unwrap();
    let (owner, _, pin, template) = fixture();
    let mut config = config(directory.path(), &pin);
    config.max_spaces = 1;
    let host = Host::open(config.clone(), false).await.unwrap();
    let request = request(&owner, &template, 71);
    let command: CreateCommand = SignedRecord::parse(&STANDARD.decode(&request.record).unwrap())
        .unwrap()
        .decode()
        .unwrap();
    let router = app(host.clone());
    let (status, value) = post(&router, "/spaces/v1/prepare", &request).await;
    assert_eq!(status, StatusCode::OK);
    let (ticket, signed) =
        RegistrationTicket::parse(value["registration_ticket"].as_str().unwrap()).unwrap();
    signed
        .verify_signature(&ed25519_dalek::SigningKey::from_bytes(&[97; 32]).verifying_key())
        .unwrap();
    let authority = space_host::verify_creation_authority_with_witness(
        &command,
        owner.credential(),
        Some(&pin),
    )
    .unwrap()
    .unwrap();
    assert_eq!(ticket.space_id, authority.space());
    assert_eq!(ticket.authority_head, authority.head_id().unwrap());
    assert_eq!(ticket.creator_identity, owner.identity_id());
    assert_eq!(ticket.credential_id, owner.credential().id());
    assert_eq!(ticket.audience, pin.url);
    assert_eq!(ticket.host, command.host);
    assert_eq!(host.allocations.lock().unwrap().len(), 1);
    assert!(
        host.spaces.read().await.is_empty(),
        "preparation must not open storage or contact the witness"
    );
    let allocated = config.root.join("spaces").join(&ticket.reservation_id);
    assert!(allocated.join("reservation.json").exists());
    assert!(!allocated.join("config.json").exists());
    assert!(!allocated.join("replica").exists());
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &request).await.0,
        StatusCode::OK
    );
    drop(router);
    crate::hosting::tests::close_host(host).await;
    let host = Host::open(config.clone(), false).await.unwrap();
    let router = app(host.clone());
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &request).await.0,
        StatusCode::OK
    );
    let second = self::request(&owner, &template, 72);
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &second).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let budget: CreationBudget = serde_json::from_slice(
        &vault::read_private(&config.root.join("creation-budget.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        budget.count, 1,
        "idempotent retries must not consume another allocation"
    );
    let mut changed = command;
    changed.name = "Changed immutable reservation".into();
    let mut changed_request = request.clone();
    changed_request.record = STANDARD.encode(
        SignedRecord::sign(&serde_json::to_vec(&changed).unwrap(), owner.signing_key())
            .unwrap()
            .bytes(),
    );
    solve_creation_work(&mut changed_request);
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &changed_request)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    drop(router);
    crate::hosting::tests::close_host(host).await;
}

#[tokio::test]
async fn preparation_denies_bad_work_retired_devices_and_restricted_creators_without_allocating() {
    let directory = tempfile::tempdir().unwrap();
    let (_, _, pin, authority) = fixture();
    let (owner, recovery) = Session::create().unwrap();
    let mut config = config(directory.path(), &pin);
    let request = request(&owner, &authority, 73);
    config.allowed_creators = Some(vec![]);
    let host = Host::open(config.clone(), false).await.unwrap();
    let router = app(host.clone());
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &request).await.0,
        StatusCode::FORBIDDEN
    );
    assert!(host.allocations.lock().unwrap().is_empty());
    drop(router);
    crate::hosting::tests::close_host(host).await;
    config.allowed_creators = None;
    let host = Host::open(config, false).await.unwrap();
    let router = app(host.clone());
    let mut invalid = request.clone();
    invalid.record.push('x');
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &invalid).await.0,
        StatusCode::BAD_REQUEST
    );
    host.revocations
        .insert(
            &DeviceRevocation::issue(
                &recovery.recover_root(owner.identity_id()).unwrap(),
                owner.credential(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &request).await.0,
        StatusCode::FORBIDDEN
    );
    assert!(host.allocations.lock().unwrap().is_empty());
    assert!(!host.config.root.join("creation-budget.json").exists());
    drop(router);
    crate::hosting::tests::close_host(host).await;
}

#[tokio::test]
async fn registration_key_is_explicit_and_deletion_or_gc_cannot_reset_ticket_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let (owner, _, pin, authority) = fixture();
    let mut config = config(directory.path(), &pin);
    let key = config.registration_signing_key.take();
    let request = request(&owner, &authority, 74);
    let host = Host::open(config.clone(), false).await.unwrap();
    let router = app(host.clone());
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &request).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(host.allocations.lock().unwrap().is_empty());
    drop(router);
    crate::hosting::tests::close_host(host).await;
    config.registration_signing_key = key;
    config.max_spaces = 1;
    let host = Host::open(config, false).await.unwrap();
    let router = app(host.clone());
    let (status, value) = post(&router, "/spaces/v1/prepare", &request).await;
    assert_eq!(status, StatusCode::OK);
    let (ticket, _) =
        RegistrationTicket::parse(value["registration_ticket"].as_str().unwrap()).unwrap();
    let path = host
        .config
        .root
        .join("spaces")
        .join(ticket.reservation_id)
        .join("reservation.json");
    let mut reserved: Reservation =
        serde_json::from_slice(&vault::read_private(&path).unwrap()).unwrap();
    reserved.reserved_at = current().unwrap() - 86_400_001;
    save(&path, &reserved).unwrap();
    host.expire_unpublished_reservations().await.unwrap();
    assert!(
        path.exists(),
        "issued tickets may have registered at the witness even without final create"
    );
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &request).await.0,
        StatusCode::OK
    );
    assert_eq!(registration_budget(&host).unwrap().issued, 1);
    let accounts = host.accounts.write().await;
    host.erase_unprovisioned_account_reservations(owner.identity_id())
        .await
        .unwrap();
    drop(accounts);
    assert!(
        !path.exists(),
        "account deletion removes the unfinished private setup"
    );
    let next = self::request(&owner, &authority, 75);
    assert_eq!(
        post(&router, "/spaces/v1/prepare", &next).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(host.allocations.lock().unwrap().is_empty());
    assert_eq!(registration_budget(&host).unwrap().issued, 1);
    drop(router);
    crate::hosting::tests::close_host(host).await;
}

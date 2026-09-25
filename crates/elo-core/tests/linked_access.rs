//! A valid companion signature alone must not bypass host enrollment or revocation.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use elo_core::{
    identity::{DeviceCredential, DeviceRevocation, generate_signing_key},
    record::{self, SignedRecord},
    replica::ReplicaStore,
    vault::Session,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn companion_transport_requires_admission_and_stays_independently_revocable() {
    let directory = tempfile::tempdir().unwrap();
    let store = ReplicaStore::open(directory.path()).await.unwrap();
    let mailbox = store.create_mailbox(1_000_000).await.unwrap();
    let (original, card) = Session::create().unwrap();
    store
        .set_space_members(mailbox.mailbox_id, vec![original.identity_id()])
        .await
        .unwrap();
    let key = generate_signing_key().unwrap();
    let child = DeviceCredential::issue_companion(
        original.credential(),
        original.signing_key(),
        &key.verifying_key(),
        &age::x25519::Identity::generate().to_public(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = elo_core::http::router(store.clone(), &origin);
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let path = format!(
        "/v1/mailboxes/{}/inventory?after=0&limit=1",
        mailbox.mailbox_id
    );
    let request = || {
        let issued = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let body = json!({"v":1,"kind":"replica.access.v2","origin":origin,"replica":record::encode_hex(store.key().as_bytes()),"method":"GET","path":path,"body_hash":record::encode_hex(&Sha256::digest(b"")),"transfer":"","retention":"","issued":issued,"nonce":record::random_hex::<32>().unwrap()});
        let signed = SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &key).unwrap();
        let proof = json!({"credential":URL_SAFE_NO_PAD.encode(child.record().bytes()),"record":URL_SAFE_NO_PAD.encode(signed.bytes()),"grant":null});
        reqwest::Client::new()
            .get(format!("{origin}{path}"))
            .bearer_auth(&mailbox.read_token)
            .header(
                "x-elo-identity",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&proof).unwrap()),
            )
    };
    assert_eq!(
        request().send().await.unwrap().status(),
        403,
        "unadmitted companion must not inherit transport by identity"
    );
    store.set_admitted_devices(vec![child.id()]).unwrap();
    assert_eq!(request().send().await.unwrap().status(), 200);
    let root = card.recover_root(original.identity_id()).unwrap();
    store
        .revocations()
        .insert(&DeviceRevocation::issue(&root, original.credential()).unwrap())
        .unwrap();
    assert_eq!(
        request().send().await.unwrap().status(),
        200,
        "an admitted child survives retirement of its original device"
    );
    store.set_admitted_devices(vec![]).unwrap();
    assert_eq!(
        request().send().await.unwrap().status(),
        403,
        "a new child of a revoked parent cannot authorize itself"
    );
    store.set_admitted_devices(vec![child.id()]).unwrap();
    store
        .revocations()
        .insert(&DeviceRevocation::issue(&root, &child).unwrap())
        .unwrap();
    assert_eq!(
        request().send().await.unwrap().status(),
        403,
        "individual revocation overrides cached admission"
    );
    server.abort();
}

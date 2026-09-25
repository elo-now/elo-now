//! Server-, payload- and nonce-bound mailbox request authorization.
use crate::{
    identity::{VerifiedCredential, generate_signing_key},
    ids::{IdentityId, RecordId},
    record::{self, SignedRecord},
    vault::Session,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const REQUEST_WINDOW: u64 = 120_000;
const GRANT_WINDOW: u64 = 600_000;

#[derive(Clone)]
pub(super) struct Signer {
    pub actor: crate::retention_access::Actor,
    key: SigningKey,
    credential: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    credential: String,
    record: String,
    grant: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    v: u8,
    kind: String,
    origin: String,
    replica: String,
    prefix: String,
    key: String,
    issued: u64,
    expires: u64,
    nonce: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    credential: String,
    grant: String,
    seed: String,
}
impl Drop for Delegation {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    v: u8,
    kind: String,
    origin: String,
    replica: String,
    method: String,
    path: String,
    body_hash: String,
    transfer: String,
    retention: String,
    issued: u64,
    nonce: String,
}

pub(crate) struct RequestContext<'a> {
    pub origin: &'a str,
    pub replica: &'a VerifyingKey,
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub transfer: &'a str,
    pub retention: &'a str,
}
pub(crate) struct VerifiedAccess {
    pub identity: IdentityId,
    pub credential: RecordId,
    pub companion: bool,
    pub nonce: String,
    pub expires: u64,
}
fn time() -> Result<u64, ()> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_millis() as u64)
}
fn encode<T: Serialize>(value: &T) -> Result<String, ()> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).map_err(|_| ())?))
}
fn decode_record(value: &str) -> Result<SignedRecord, ()> {
    SignedRecord::parse(&URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?).map_err(|_| ())
}
fn sign(
    key: &SigningKey,
    credential: String,
    grant: Option<String>,
    context: &RequestContext<'_>,
) -> Result<String, ()> {
    let access = Access {
        v: 1,
        kind: "replica.access.v2".into(),
        origin: context.origin.into(),
        replica: record::encode_hex(context.replica.as_bytes()),
        method: context.method.into(),
        path: context.path.into(),
        body_hash: record::encode_hex(&Sha256::digest(context.body)),
        transfer: context.transfer.into(),
        retention: context.retention.into(),
        issued: time()?,
        nonce: record::random_hex::<32>().map_err(|_| ())?,
    };
    let signed =
        SignedRecord::sign(&serde_json::to_vec(&access).map_err(|_| ())?, key).map_err(|_| ())?;
    encode(&Proof {
        credential,
        record: URL_SAFE_NO_PAD.encode(signed.bytes()),
        grant,
    })
}
impl Signer {
    pub fn new(session: &Session) -> Self {
        Self {
            actor: session.credential().into(),
            key: session.signing_key().clone(),
            credential: URL_SAFE_NO_PAD.encode(session.credential().record().bytes()),
        }
    }
    pub fn proof(&self, context: &RequestContext<'_>) -> Result<String, ()> {
        sign(&self.key, self.credential.clone(), None, context)
    }
    pub fn delegate(
        &self,
        origin: &str,
        replica: &VerifyingKey,
        prefix: &str,
    ) -> Result<String, ()> {
        if !super::endpoint::mailbox_prefix(prefix) {
            return Err(());
        }
        let key = generate_signing_key().map_err(|_| ())?;
        let issued = time()?;
        let body = Grant {
            v: 1,
            kind: "replica.pairing-grant.v2".into(),
            origin: origin.into(),
            replica: record::encode_hex(replica.as_bytes()),
            prefix: prefix.into(),
            key: record::encode_hex(key.verifying_key().as_bytes()),
            issued,
            expires: issued + GRANT_WINDOW,
            nonce: record::random_hex::<32>().map_err(|_| ())?,
        };
        let signed = SignedRecord::sign(&serde_json::to_vec(&body).map_err(|_| ())?, &self.key)
            .map_err(|_| ())?;
        encode(&Delegation {
            credential: self.credential.clone(),
            grant: URL_SAFE_NO_PAD.encode(signed.bytes()),
            seed: record::encode_hex(&key.to_bytes()),
        })
    }
}
pub(super) fn delegated_proof(encoded: &str, context: &RequestContext<'_>) -> Result<String, ()> {
    if encoded.len() > 12_288 {
        return Err(());
    }
    let delegation: Delegation =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?)
            .map_err(|_| ())?;
    let seed = zeroize::Zeroizing::new(record::hex(&delegation.seed).map_err(|_| ())?);
    let key = SigningKey::from_bytes(&seed);
    sign(
        &key,
        delegation.credential.clone(),
        Some(delegation.grant.clone()),
        context,
    )
}
pub(crate) fn verify(encoded: &str, context: &RequestContext<'_>) -> Result<VerifiedAccess, ()> {
    if encoded.len() > 16_384 {
        return Err(());
    }
    let proof: Proof = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?)
        .map_err(|_| ())?;
    let credential = decode_record(&proof.credential)?;
    let root = credential.body()["root_public_key"].as_str().ok_or(())?;
    let root = VerifyingKey::from_bytes(&record::hex(root).map_err(|_| ())?).map_err(|_| ())?;
    let credential = VerifiedCredential::verify(credential.bytes(), &root).map_err(|_| ())?;
    let now = time()?;
    let mut key = *credential.key();
    let mut grant_expiry = u64::MAX;
    if let Some(grant) = proof.grant {
        let signed = decode_record(&grant)?;
        signed.verify_signature(credential.key()).map_err(|_| ())?;
        let grant: Grant = signed.decode().map_err(|_| ())?;
        let suffix = context.path.strip_prefix(&grant.prefix).ok_or(())?;
        let object = suffix
            .strip_prefix("objects/")
            .is_some_and(|id| record::hex::<32>(id).is_ok());
        let permitted = (context.method == "GET" && (object || suffix.starts_with("inventory?")))
            || (context.method == "POST" && object);
        if grant.v != 1
            || grant.kind != "replica.pairing-grant.v2"
            || grant.origin != context.origin
            || grant.replica != record::encode_hex(context.replica.as_bytes())
            || !super::endpoint::mailbox_prefix(&grant.prefix)
            || !permitted
            || grant.issued > now + REQUEST_WINDOW
            || grant.expires <= now
            || grant.expires <= grant.issued
            || grant.expires - grant.issued > GRANT_WINDOW
        {
            return Err(());
        }
        record::hex::<32>(&grant.nonce).map_err(|_| ())?;
        key =
            VerifyingKey::from_bytes(&record::hex(&grant.key).map_err(|_| ())?).map_err(|_| ())?;
        if key.is_weak() {
            return Err(());
        }
        grant_expiry = grant.expires;
    }
    let signed = decode_record(&proof.record)?;
    signed.verify_signature(&key).map_err(|_| ())?;
    let access: Access = signed.decode().map_err(|_| ())?;
    record::hex::<32>(&access.nonce).map_err(|_| ())?;
    if access.v != 1
        || access.kind != "replica.access.v2"
        || access.origin != context.origin
        || access.replica != record::encode_hex(context.replica.as_bytes())
        || access.method != context.method
        || access.path != context.path
        || access.body_hash != record::encode_hex(&Sha256::digest(context.body))
        || access.transfer != context.transfer
        || access.retention != context.retention
        || now.abs_diff(access.issued) > REQUEST_WINDOW
    {
        return Err(());
    }
    Ok(VerifiedAccess {
        identity: credential.identity(),
        credential: credential.id(),
        companion: credential.authorizing_device().is_some(),
        nonce: access.nonce,
        expires: (access.issued + REQUEST_WINDOW).min(grant_expiry),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_proofs_bind_server_body_headers_method_and_path() {
        let (session, _) = Session::create().unwrap();
        let signer = Signer::new(&session);
        let replica = generate_signing_key().unwrap().verifying_key();
        let other = generate_signing_key().unwrap().verifying_key();
        let mut context = RequestContext {
            origin: "https://replica.example",
            replica: &replica,
            method: "POST",
            path: "/v1/mailboxes/one/children",
            body: b"request",
            transfer: "",
            retention: "",
        };
        let proof = signer.proof(&context).unwrap();
        assert_eq!(
            verify(&proof, &context).unwrap().identity,
            session.identity_id()
        );
        context.origin = "https://attacker.example";
        assert!(verify(&proof, &context).is_err());
        context.origin = "https://replica.example";
        context.replica = &other;
        assert!(verify(&proof, &context).is_err());
        context.replica = &replica;
        context.body = b"changed";
        assert!(verify(&proof, &context).is_err());
        context.body = b"request";
        context.transfer = "lazy";
        assert!(verify(&proof, &context).is_err());
        context.transfer = "";
        context.retention = "message";
        assert!(verify(&proof, &context).is_err());
        context.retention = "";
        context.method = "GET";
        assert!(verify(&proof, &context).is_err());
        context.method = "POST";
        context.path = "/v1/mailboxes/two/children";
        assert!(verify(&proof, &context).is_err());
    }
    #[tokio::test]
    async fn consumed_proofs_stay_consumed_after_replica_restart() {
        let temp = tempfile::tempdir().unwrap();
        let store = crate::replica::ReplicaStore::open(temp.path())
            .await
            .unwrap();
        let (session, _) = Session::create().unwrap();
        let key = *store.key();
        let context = RequestContext {
            origin: "https://replica.example",
            replica: &key,
            method: "GET",
            path: "/v1/mailboxes/one/inventory",
            body: &[],
            transfer: "",
            retention: "",
        };
        let encoded = Signer::new(&session).proof(&context).unwrap();
        store
            .consume_access(verify(&encoded, &context).unwrap())
            .await
            .unwrap();
        assert!(
            store
                .consume_access(verify(&encoded, &context).unwrap())
                .await
                .is_err()
        );
        drop(store);
        let reopened = crate::replica::ReplicaStore::open(temp.path())
            .await
            .unwrap();
        assert!(
            reopened
                .consume_access(verify(&encoded, &context).unwrap())
                .await
                .is_err()
        );
        let fresh = Signer::new(&session).proof(&context).unwrap();
        reopened
            .consume_access(verify(&fresh, &context).unwrap())
            .await
            .unwrap();
    }
    #[test]
    fn expired_future_and_legacy_proofs_are_rejected() {
        let (session, _) = Session::create().unwrap();
        let key = generate_signing_key().unwrap().verifying_key();
        let context = RequestContext {
            origin: "https://replica.example",
            replica: &key,
            method: "GET",
            path: "/v1/mailboxes/one/inventory",
            body: &[],
            transfer: "",
            retention: "",
        };
        let signer = Signer::new(&session);
        let encoded = signer.proof(&context).unwrap();
        for (issued, kind) in [
            (
                time().unwrap() - REQUEST_WINDOW - 1_000,
                "replica.access.v2",
            ),
            (
                time().unwrap() + REQUEST_WINDOW + 1_000,
                "replica.access.v2",
            ),
            (time().unwrap(), "replica.access"),
        ] {
            let mut proof: Proof =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap();
            let mut body: Access = decode_record(&proof.record).unwrap().decode().unwrap();
            body.issued = issued;
            body.kind = kind.into();
            proof.record = URL_SAFE_NO_PAD.encode(
                SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), session.signing_key())
                    .unwrap()
                    .bytes(),
            );
            assert!(verify(&encode(&proof).unwrap(), &context).is_err());
        }
    }

    #[tokio::test]
    async fn concurrent_replay_has_exactly_one_winner() {
        let temp = tempfile::tempdir().unwrap();
        let store = crate::replica::ReplicaStore::open(temp.path())
            .await
            .unwrap();
        let (session, _) = Session::create().unwrap();
        let key = *store.key();
        let context = RequestContext {
            origin: "https://replica.example",
            replica: &key,
            method: "GET",
            path: "/v1/mailboxes/one/inventory",
            body: &[],
            transfer: "",
            retention: "",
        };
        let encoded = Signer::new(&session).proof(&context).unwrap();
        let (first, second) = tokio::join!(
            store.consume_access(verify(&encoded, &context).unwrap()),
            store.consume_access(verify(&encoded, &context).unwrap())
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    }
}

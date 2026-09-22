//! Request proofs bind mailbox capabilities to a current Space identity.
use crate::{
    identity::VerifiedCredential,
    ids::IdentityId,
    record::{self, SignedRecord},
    vault::Session,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub(super) struct Signer {
    key: SigningKey,
    credential: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    credential: String,
    record: String,
}
fn time() -> Result<u64, ()> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_millis() as u64)
}
impl Signer {
    pub fn new(session: &Session) -> Self {
        Self {
            key: session.signing_key().clone(),
            credential: URL_SAFE_NO_PAD.encode(session.credential().record().bytes()),
        }
    }
    pub fn proof(&self, method: &str, path: &str, delegated: bool) -> Result<String, ()> {
        let body = serde_json::json!({"v":1,"kind":"replica.access","method":method,"path":path,"issued":time()?,"delegated":delegated});
        let record = SignedRecord::sign(&serde_json::to_vec(&body).map_err(|_| ())?, &self.key)
            .map_err(|_| ())?;
        Ok(URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Proof {
                credential: self.credential.clone(),
                record: URL_SAFE_NO_PAD.encode(record.bytes()),
            })
            .map_err(|_| ())?,
        ))
    }
}
pub(crate) fn verify(encoded: &str, method: &str, path: &str) -> Result<IdentityId, ()> {
    if encoded.len() > 8192 {
        return Err(());
    }
    let proof: Proof = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?)
        .map_err(|_| ())?;
    let credential =
        SignedRecord::parse(&URL_SAFE_NO_PAD.decode(proof.credential).map_err(|_| ())?)
            .map_err(|_| ())?;
    let root = credential.body()["root_public_key"].as_str().ok_or(())?;
    let key = VerifyingKey::from_bytes(&record::hex(root).map_err(|_| ())?).map_err(|_| ())?;
    let credential = VerifiedCredential::verify(credential.bytes(), &key).map_err(|_| ())?;
    let signed = SignedRecord::parse(&URL_SAFE_NO_PAD.decode(proof.record).map_err(|_| ())?)
        .map_err(|_| ())?;
    signed.verify_signature(credential.key()).map_err(|_| ())?;
    let body = signed.body();
    let delegated = body["delegated"] == true;
    let expected = body["path"].as_str().ok_or(())?;
    let matches = if delegated {
        // A device-link QR delegates only its short-lived child mailbox.
        super::endpoint::mailbox_prefix(expected) && path.starts_with(expected)
    } else {
        expected == path && body["method"] == method
    };
    if body["v"] != 1
        || body["kind"] != "replica.access"
        || !matches
        || time()?.abs_diff(body["issued"].as_u64().ok_or(())?)
            > if delegated { 600_000 } else { 120_000 }
    {
        return Err(());
    }
    Ok(credential.identity())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proofs_bind_requests_and_pairing_delegations_to_one_mailbox() {
        let (session, _) = Session::create().unwrap();
        let signer = Signer::new(&session);
        let proof = signer
            .proof("GET", "/v1/mailboxes/one/inventory?after=0", false)
            .unwrap();
        assert_eq!(
            verify(&proof, "GET", "/v1/mailboxes/one/inventory?after=0").unwrap(),
            session.identity_id()
        );
        assert!(verify(&proof, "POST", "/v1/mailboxes/one/inventory?after=0").is_err());
        assert!(verify(&proof, "GET", "/v1/mailboxes/two/inventory?after=0").is_err());
        let child = "01".repeat(32);
        let prefix = format!("/v1/mailboxes/{child}/");
        let grant = signer.proof("*", &prefix, true).unwrap();
        assert!(verify(&grant, "POST", &format!("{prefix}objects/one")).is_ok());
        assert!(verify(&grant, "GET", "/v1/mailboxes/parent/inventory").is_err());
        assert!(verify(&grant, "GET", "/v1/mailboxes/child-other/inventory").is_err());
        let mut altered: Proof =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&grant).unwrap()).unwrap();
        let (other, _) = Session::create().unwrap();
        altered.credential = URL_SAFE_NO_PAD.encode(other.credential().record().bytes());
        let altered = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&altered).unwrap());
        assert!(verify(&altered, "GET", &format!("{prefix}inventory")).is_err());
    }
}

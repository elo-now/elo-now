//! Signed attribution of encrypted content, without exposing message plaintext.
//! The outer signature is part of the object hash: reattribution makes a different
//! object and cannot authorize deletion of somebody else's existing ciphertext.
use crate::{
    crypto,
    identity::VerifiedCredential,
    ids::{IdentityId, ObjectId, RecordId},
    record::{self, SignedRecord},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8] = b"elo-owned-object-v1\n";
const MAX_PROOF: usize = 128 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    v: u8,
    kind: String,
    credential: String,
    ciphertext: ObjectId,
    subjects: Vec<IdentityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retention: Option<RetentionClaim>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetentionClaim {
    MessageBody {
        locator_nonce: String,
        record_id: RecordId,
        lifetime_seconds: u64,
        direct_peer: Option<IdentityId>,
    },
    MessageLocator {
        locator_nonce: String,
        body_object_id: ObjectId,
        record_id: RecordId,
        lifetime_seconds: u64,
    },
}
pub struct Content<'a> {
    pub credential: VerifiedCredential,
    pub ciphertext: &'a [u8],
    pub subjects: Vec<IdentityId>,
    pub retention: Option<RetentionClaim>,
}
pub fn wrap(
    ciphertext: Vec<u8>,
    credential: &VerifiedCredential,
    key: &SigningKey,
) -> crypto::Result<Vec<u8>> {
    wrap_subjects(ciphertext, credential, key, vec![credential.identity()])
}
pub fn wrap_subjects(
    ciphertext: Vec<u8>,
    credential: &VerifiedCredential,
    key: &SigningKey,
    subjects: Vec<IdentityId>,
) -> crypto::Result<Vec<u8>> {
    wrap_subjects_with_retention(ciphertext, credential, key, subjects, None)
}
pub fn wrap_subjects_with_retention(
    ciphertext: Vec<u8>,
    credential: &VerifiedCredential,
    key: &SigningKey,
    mut subjects: Vec<IdentityId>,
    retention: Option<RetentionClaim>,
) -> crypto::Result<Vec<u8>> {
    subjects.push(credential.identity());
    subjects.sort();
    subjects.dedup();
    if subjects.len() > 1002 {
        return Err(crypto::CryptoError::InvalidInput);
    }
    if key.verifying_key() != *credential.key() || ciphertext.starts_with(MAGIC) {
        return Err(crypto::CryptoError::InvalidInput);
    }
    let claim = Claim {
        v: 1,
        kind: "object.owner".into(),
        credential: STANDARD.encode(credential.record().bytes()),
        ciphertext: ObjectId::of_ciphertext(&ciphertext),
        subjects,
        retention,
    };
    let record = SignedRecord::sign(
        &serde_json::to_vec(&claim).map_err(|_| crypto::CryptoError::Encrypt)?,
        key,
    )
    .map_err(|_| crypto::CryptoError::Encrypt)?;
    if record.bytes().len() > MAX_PROOF
        || MAGIC.len() + 4 + record.bytes().len() + ciphertext.len() > crypto::MAX_CIPHERTEXT
    {
        return Err(crypto::CryptoError::InvalidInput);
    }
    let mut bytes = Vec::with_capacity(MAGIC.len() + 4 + record.bytes().len() + ciphertext.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(record.bytes().len() as u32).to_be_bytes());
    bytes.extend_from_slice(record.bytes());
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}
pub fn inspect(bytes: &[u8]) -> crypto::Result<Option<Content<'_>>> {
    if !bytes.starts_with(MAGIC) {
        return Ok(None);
    }
    let invalid = || crypto::CryptoError::Decrypt;
    if bytes.len() > crypto::MAX_CIPHERTEXT {
        return Err(invalid());
    }
    let size = u32::from_be_bytes(
        bytes
            .get(MAGIC.len()..MAGIC.len() + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ) as usize;
    if size == 0 || size > MAX_PROOF {
        return Err(invalid());
    }
    let start = MAGIC.len() + 4;
    let proof = SignedRecord::parse(bytes.get(start..start + size).ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let claim: Claim = proof.decode().map_err(|_| invalid())?;
    let raw = SignedRecord::parse(&STANDARD.decode(&claim.credential).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let root: [u8; 32] = record::hex(raw.body()["root_public_key"].as_str().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let root = VerifyingKey::from_bytes(&root).map_err(|_| invalid())?;
    let credential = VerifiedCredential::verify(raw.bytes(), &root).map_err(|_| invalid())?;
    proof
        .verify_signature(credential.key())
        .map_err(|_| invalid())?;
    let ciphertext = bytes
        .get(start + size..)
        .filter(|v| !v.is_empty())
        .ok_or_else(invalid)?;
    if claim.v != 1
        || claim.kind != "object.owner"
        || claim.ciphertext != ObjectId::of_ciphertext(ciphertext)
        || ciphertext.starts_with(MAGIC)
        || !record::sorted_unique(&claim.subjects, 1, 1002)
        || !claim.subjects.contains(&credential.identity())
        || !valid_retention(&claim.retention, credential.identity(), &claim.subjects)
    {
        return Err(invalid());
    }
    Ok(Some(Content {
        credential,
        ciphertext,
        subjects: claim.subjects,
        retention: claim.retention,
    }))
}

fn valid_retention(
    retention: &Option<RetentionClaim>,
    issuer: IdentityId,
    subjects: &[IdentityId],
) -> bool {
    let valid_common = |nonce: &str, lifetime: u64| {
        record::hex::<16>(nonce).is_ok() && matches!(lifetime, 21_600 | 43_200 | 86_400)
    };
    match retention {
        None => true,
        Some(RetentionClaim::MessageBody {
            locator_nonce,
            lifetime_seconds,
            direct_peer,
            ..
        }) => {
            valid_common(locator_nonce, *lifetime_seconds)
                && direct_peer.is_none_or(|peer| peer != issuer && subjects.contains(&issuer))
        }
        Some(RetentionClaim::MessageLocator {
            locator_nonce,
            lifetime_seconds,
            ..
        }) => valid_common(locator_nonce, *lifetime_seconds),
    }
}
pub fn owner(bytes: &[u8]) -> crypto::Result<Option<IdentityId>> {
    Ok(inspect(bytes)?.map(|v| v.credential.identity()))
}
/// Attribution is also checked against the authenticated original after decryption.
pub fn verify_original(bytes: &[u8], original: &SignedRecord) -> crypto::Result<()> {
    if let Some(content) = inspect(bytes)? {
        if original.body()["issuer_identity"] != serde_json::json!(content.credential.identity())
            || original.body()["issuer_credential"] != serde_json::json!(content.credential.id())
        {
            return Err(crypto::CryptoError::Decrypt);
        }
        original
            .verify_signature(content.credential.key())
            .map_err(|_| crypto::CryptoError::Decrypt)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Session;
    #[test]
    fn encrypted_attribution_is_authenticated_and_cannot_reattribute_existing_bytes() {
        let alice = Session::create().unwrap().0;
        let bob = Session::create().unwrap().0;
        let original = SignedRecord::sign(&serde_json::to_vec(&serde_json::json!({"v":1,"kind":"test","issuer_identity":alice.identity_id(),"issuer_credential":alice.credential().id()})).unwrap(),alice.signing_key()).unwrap();
        let cipher = crypto::seal_record(&original, &[alice.age_identity().to_public()]).unwrap();
        let bytes = wrap(cipher.clone(), alice.credential(), alice.signing_key()).unwrap();
        assert_eq!(
            crypto::open_record(&bytes, alice.age_identity())
                .unwrap()
                .id(),
            original.id()
        );
        assert_eq!(
            inspect(&bytes).unwrap().unwrap().subjects,
            vec![alice.identity_id()]
        );
        assert!(wrap(cipher.clone(), alice.credential(), bob.signing_key()).is_err());
        let forged = wrap(cipher, bob.credential(), bob.signing_key()).unwrap();
        assert_ne!(
            ObjectId::of_ciphertext(&forged),
            ObjectId::of_ciphertext(&bytes)
        );
        assert!(crypto::open_record(&forged, alice.age_identity()).is_err());
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(inspect(&corrupt).is_err());
        assert!(inspect(&bytes[..MAGIC.len() + 3]).is_err());
        assert!(wrap(bytes, alice.credential(), alice.signing_key()).is_err());
    }
}

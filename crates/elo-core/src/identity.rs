//! Root-signed device credentials. Enrollment does not grant Stream membership.
use crate::{
    ids::{IdentityId, RecordId},
    record::{self, RecordError, Result, SignedRecord},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCredential {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub identity_id: IdentityId,
    pub root_public_key: String,
    pub signing_public_key: String,
    pub age_recipient: String,
}
#[derive(Clone, Debug)]
pub struct VerifiedCredential {
    record: SignedRecord,
    body: DeviceCredential,
    key: VerifyingKey,
}
impl VerifiedCredential {
    /// `trusted_root` is an out-of-band anchor, never inferred from this record.
    pub fn verify(bytes: &[u8], trusted_root: &VerifyingKey) -> Result<Self> {
        let record = SignedRecord::parse(bytes)?;
        let body: DeviceCredential = record.decode()?;
        if body.v != 1 || body.kind != "device.credential" {
            return Err(RecordError::Unsupported);
        }
        record::hex::<16>(&body.nonce)?;
        if body.identity_id != IdentityId::of_root_key(trusted_root.as_bytes())
            || record::hex::<32>(&body.root_public_key)? != *trusted_root.as_bytes()
        {
            return Err(RecordError::Authority);
        }
        record.verify_signature(trusted_root)?;
        let key = VerifyingKey::from_bytes(&record::hex(&body.signing_public_key)?)
            .map_err(|_| RecordError::Signature)?;
        if key.is_weak() {
            return Err(RecordError::Signature);
        }
        let recipient: age::x25519::Recipient =
            body.age_recipient.parse().map_err(|_| RecordError::Json)?;
        if recipient.to_string() != body.age_recipient {
            return Err(RecordError::Json);
        }
        Ok(Self { record, body, key })
    }
    pub fn id(&self) -> RecordId {
        self.record.id()
    }
    pub fn identity(&self) -> IdentityId {
        self.body.identity_id
    }
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }
    pub fn recipient(&self) -> age::x25519::Recipient {
        self.body
            .age_recipient
            .parse()
            .expect("validated immutable credential")
    }
    pub fn record(&self) -> &SignedRecord {
        &self.record
    }
    /// Proves device authorship only. Config/capability/audience admission is separate.
    pub fn verify_chat(&self, record: &SignedRecord) -> Result<record::ChatMessage> {
        let chat = record.chat()?;
        if chat.issuer_credential != self.id() || chat.issuer_identity != self.identity() {
            return Err(RecordError::Authority);
        }
        record.verify_signature(&self.key)?;
        Ok(chat)
    }
}
impl DeviceCredential {
    pub fn issue(
        root: &SigningKey,
        signing_key: &VerifyingKey,
        recipient: &age::x25519::Recipient,
    ) -> Result<VerifiedCredential> {
        let body = Self {
            v: 1,
            kind: "device.credential".into(),
            nonce: record::random_hex::<16>()?,
            identity_id: IdentityId::of_root_key(root.verifying_key().as_bytes()),
            root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            signing_public_key: record::encode_hex(signing_key.as_bytes()),
            age_recipient: recipient.to_string(),
        };
        let record = SignedRecord::sign(
            &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
            root,
        )?;
        VerifiedCredential::verify(record.bytes(), &root.verifying_key())
    }
}
pub fn generate_signing_key() -> Result<SigningKey> {
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    getrandom::fill(&mut *seed).map_err(|_| RecordError::Random)?;
    let key = SigningKey::from_bytes(&seed);
    Ok(key)
}

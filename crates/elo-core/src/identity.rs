//! Root-anchored device credentials. Enrollment does not grant Stream membership.
use crate::{
    ids::{IdentityId, RecordId},
    record::{self, RecordError, Result, SignedRecord},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
pub mod revocations;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorizing_device: Option<String>,
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
        if !matches!(body.v, 1 | 2) || body.kind != "device.credential" {
            return Err(RecordError::Unsupported);
        }
        record::hex::<16>(&body.nonce)?;
        if body.identity_id != IdentityId::of_root_key(trusted_root.as_bytes())
            || record::hex::<32>(&body.root_public_key)? != *trusted_root.as_bytes()
        {
            return Err(RecordError::Authority);
        }
        match (body.v, &body.authorizing_device) {
            (1, None) => record.verify_signature(trusted_root)?,
            (2, Some(encoded)) => {
                use base64::Engine;
                if encoded.len() > 4096 {
                    return Err(RecordError::Framing);
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| RecordError::Json)?;
                let parent = SignedRecord::parse(&bytes)?;
                let parent_body: DeviceCredential = parent.decode()?;
                // One level only: a companion cannot create another device.
                // Reject before recursion, including oversized/cyclic chains.
                if parent_body.v != 1 || parent_body.authorizing_device.is_some() {
                    return Err(RecordError::Authority);
                }
                let parent = Self::verify(&bytes, trusted_root)?;
                record.verify_signature(parent.key())?;
            }
            _ => return Err(RecordError::Unsupported),
        }
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
    pub fn authorizing_device(&self) -> Option<RecordId> {
        use base64::Engine;
        self.body.authorizing_device.as_ref().map(|encoded| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("validated immutable device authorization");
            SignedRecord::parse(&bytes)
                .expect("validated immutable device authorization")
                .id()
        })
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
            authorizing_device: None,
        };
        let record = SignedRecord::sign(
            &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
            root,
        )?;
        VerifiedCredential::verify(record.bytes(), &root.verifying_key())
    }
    /// The already unlocked original device authorizes distinct companion keys.
    /// Hosts must check the authorizer is still admitted before new enrollment.
    pub fn issue_companion(
        authorizer: &VerifiedCredential,
        authorizing_key: &SigningKey,
        signing_key: &VerifyingKey,
        recipient: &age::x25519::Recipient,
    ) -> Result<VerifiedCredential> {
        use base64::Engine;
        if authorizer.authorizing_device().is_some()
            || authorizer.key() != &authorizing_key.verifying_key()
        {
            return Err(RecordError::Authority);
        }
        let root = VerifyingKey::from_bytes(&record::hex(&authorizer.body.root_public_key)?)
            .map_err(|_| RecordError::Signature)?;
        let body = Self {
            v: 2,
            kind: "device.credential".into(),
            nonce: record::random_hex::<16>()?,
            identity_id: authorizer.identity(),
            root_public_key: authorizer.body.root_public_key.clone(),
            signing_public_key: record::encode_hex(signing_key.as_bytes()),
            age_recipient: recipient.to_string(),
            authorizing_device: Some(
                base64::engine::general_purpose::STANDARD.encode(authorizer.record.bytes()),
            ),
        };
        let record = SignedRecord::sign(
            &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
            authorizing_key,
        )?;
        VerifiedCredential::verify(record.bytes(), &root)
    }
}
pub fn generate_signing_key() -> Result<SigningKey> {
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    getrandom::fill(&mut *seed).map_err(|_| RecordError::Random)?;
    let key = SigningKey::from_bytes(&seed);
    Ok(key)
}

/// Permanent authorization to retire one credential. Device-signed requests
/// also require current admission of the signer at the accepting host.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevocation {
    v: u64,
    kind: String,
    nonce: String,
    credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorizing_device: Option<String>,
}
impl DeviceRevocation {
    pub fn issue(root: &SigningKey, credential: &VerifiedCredential) -> Result<SignedRecord> {
        use base64::Engine;
        if credential.identity() != IdentityId::of_root_key(root.verifying_key().as_bytes()) {
            return Err(RecordError::Authority);
        }
        let body = Self {
            v: 1,
            kind: "device.revoked".into(),
            nonce: record::random_hex::<16>()?,
            credential: base64::engine::general_purpose::STANDARD
                .encode(credential.record().bytes()),
            authorizing_device: None,
        };
        SignedRecord::sign(
            &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
            root,
        )
    }
    pub fn issue_from_device(
        authorizer: &VerifiedCredential,
        key: &SigningKey,
        target: &VerifiedCredential,
    ) -> Result<SignedRecord> {
        use base64::Engine;
        if authorizer.identity() != target.identity()
            || authorizer.id() == target.id()
            || authorizer.key() != &key.verifying_key()
        {
            return Err(RecordError::Authority);
        }
        let body = Self {
            v: 2,
            kind: "device.revoked".into(),
            nonce: record::random_hex::<16>()?,
            credential: base64::engine::general_purpose::STANDARD.encode(target.record().bytes()),
            authorizing_device: Some(
                base64::engine::general_purpose::STANDARD.encode(authorizer.record().bytes()),
            ),
        };
        SignedRecord::sign(
            &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
            key,
        )
    }

    /// Cryptographic verification alone does not authorize a new tombstone.
    /// The host must authenticate the requester and check current admission.
    pub fn verify(signed: &SignedRecord) -> Result<VerifiedCredential> {
        Self::verify_inner(signed, None)
    }

    pub fn verify_request(
        signed: &SignedRecord,
        requester: &VerifiedCredential,
    ) -> Result<VerifiedCredential> {
        Self::verify_inner(signed, Some(requester))
    }

    fn verify_inner(
        signed: &SignedRecord,
        requester: Option<&VerifiedCredential>,
    ) -> Result<VerifiedCredential> {
        use base64::Engine;
        let body: Self = signed.decode()?;
        if !matches!(body.v, 1 | 2) || body.kind != "device.revoked" {
            return Err(RecordError::Unsupported);
        }
        record::hex::<16>(&body.nonce)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body.credential)
            .map_err(|_| RecordError::Json)?;
        let candidate = SignedRecord::parse(&bytes)?;
        let credential: DeviceCredential = candidate.decode()?;
        let root = VerifyingKey::from_bytes(&record::hex(&credential.root_public_key)?)
            .map_err(|_| RecordError::Signature)?;
        let credential = VerifiedCredential::verify(&bytes, &root)?;
        match (body.v, body.authorizing_device) {
            (1, None) => signed.verify_signature(&root)?,
            (2, Some(encoded)) => {
                if encoded.len() > 8192 {
                    return Err(RecordError::Framing);
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| RecordError::Json)?;
                let authorizer = VerifiedCredential::verify(&bytes, &root)?;
                if authorizer.id() == credential.id()
                    || requester.is_some_and(|requester| requester.id() != authorizer.id())
                {
                    return Err(RecordError::Authority);
                }
                signed.verify_signature(authorizer.key())?;
            }
            _ => return Err(RecordError::Unsupported),
        }
        if requester.is_some_and(|requester| {
            requester.identity() != credential.identity() || requester.id() == credential.id()
        }) {
            return Err(RecordError::Authority);
        }
        Ok(credential)
    }
}

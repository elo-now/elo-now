//! Short invitation capabilities. Public storage receives only bounded ciphertext;
//! the URL fragment carries the seed needed to decrypt it and prove admission.
//!
//! Opening a descriptor verifies authorship and deployment pins. It does not
//! establish current membership or invitation use/revocation state: admission
//! must still obtain a fresh challenge from the independently pinned witness.
//! Signed descriptors, including framing and proofs, are capped at 1 MiB. Larger
//! proofs return `LinkError::DescriptorTooLarge` and need a future bounded
//! checkpoint format; the codec never falls back to an unverified invitation.
use crate::{
    app::space_service::SpaceAddress,
    authority::{Authority, CallAuthorityProof, WitnessInvitationPolicy, WitnessPin},
    record::{self, RecordError, SignedRecord},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("Invitation descriptor exceeds the 1 MiB limit.")]
    DescriptorTooLarge,
    #[error(transparent)]
    InvalidRecord(#[from] RecordError),
}

pub type Result<T> = std::result::Result<T, LinkError>;

pub const PREFIX: &str = "https://elo.now/join#";
pub const FRAGMENT_LENGTH: usize = 87;
pub const MAX_CIPHERTEXT_BYTES: usize = record::MAX_RECORD + 1 + 24 + 16;
const VERSION: u8 = 1;
const SALT: &[u8] = b"elo.now/witness-invitation/seed/v1";
const ENCRYPTION_INFO: &[u8] = b"elo.now/witness-invitation/descriptor-key/v1";
const SIGNING_INFO: &[u8] = b"elo.now/witness-invitation/admission-key/v1";
const AAD: &[u8] = b"elo.now/witness-invitation/descriptor-ciphertext/v1";

/// Secret material deliberately has no Debug, Display or serde implementation.
pub struct InvitationSeed(Zeroizing<[u8; 32]>);

impl InvitationSeed {
    pub fn generate() -> Result<Self> {
        let mut value = Zeroizing::new([0; 32]);
        getrandom::fill(value.as_mut()).map_err(|_| RecordError::Random)?;
        Ok(Self(value))
    }

    fn derive(&self, info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(SALT), self.0.as_ref())
            .expand(info, key.as_mut())
            .map_err(|_| RecordError::Signature)?;
        Ok(key)
    }

    fn signing_key(&self) -> Result<SigningKey> {
        Ok(SigningKey::from_bytes(&*self.derive(SIGNING_INFO)?))
    }

    pub fn invitation_public_key(&self) -> Result<VerifyingKey> {
        Ok(self.signing_key()?.verifying_key())
    }
}

/// Parse the fixed official origin without accepting alternate URL encodings.
/// Only `ciphertext_id` may be sent to public storage. Never send the whole link.
pub struct InvitationLink {
    ciphertext_id: [u8; 32],
    seed: InvitationSeed,
    hosting_id: Option<String>,
}

impl InvitationLink {
    pub fn parse(value: &str) -> Result<Self> {
        let fragment = value.strip_prefix(PREFIX).ok_or(RecordError::Framing)?;
        if !matches!(fragment.len(), FRAGMENT_LENGTH | 130) {
            return Err(RecordError::Framing.into());
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(fragment)
                .map_err(|_| RecordError::Framing)?,
        );
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
        if canonical.as_str() != fragment {
            return Err(RecordError::Framing.into());
        }
        if !matches!((bytes.first(), bytes.len()), (Some(1), 65) | (Some(2), 97)) {
            return Err(RecordError::Unsupported.into());
        }
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&bytes[33..65]);
        Ok(Self {
            ciphertext_id: bytes[1..33].try_into().map_err(|_| RecordError::Framing)?,
            seed: InvitationSeed(seed),
            hosting_id: (bytes.len() == 97).then(|| record::encode_hex(&bytes[65..])),
        })
    }

    pub fn ciphertext_id(&self) -> String {
        record::encode_hex(&self.ciphertext_id)
    }
    /// A selector for a previously approved local hosting profile, never a URL
    /// or a new trust anchor. Unknown IDs must fail before any network request.
    pub fn hosting_id(&self) -> Option<&str> {
        self.hosting_id.as_deref()
    }

    pub fn with_hosting(mut self, id: &str) -> Result<Self> {
        record::hex::<32>(id)?;
        self.hosting_id = Some(id.to_owned());
        Ok(self)
    }

    /// Explicit secret export for sharing or QR rendering; never use in logs.
    pub fn to_url(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new(vec![0; if self.hosting_id.is_some() { 97 } else { 65 }]);
        bytes[0] = if self.hosting_id.is_some() {
            2
        } else {
            VERSION
        };
        bytes[1..33].copy_from_slice(&self.ciphertext_id);
        bytes[33..65].copy_from_slice(self.seed.0.as_ref());
        if let Some(id) = &self.hosting_id {
            bytes[65..].copy_from_slice(&record::hex::<32>(id).expect("validated hosting ID"));
        }
        let mut url = Zeroizing::new(String::from(PREFIX));
        URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut url);
        url
    }

    /// No descriptor data or admission key is returned before every check passes.
    pub fn open(
        &self,
        ciphertext: &[u8],
        configured_api_origin: &str,
        configured_witness: &WitnessPin,
        now_ms: u64,
    ) -> Result<VerifiedDescriptor> {
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(LinkError::DescriptorTooLarge);
        }
        if ciphertext.len() < 113
            || ciphertext[0] != VERSION
            || <[u8; 32]>::from(Sha256::digest(ciphertext)) != self.ciphertext_id
        {
            return Err(RecordError::Framing.into());
        }
        let key = self.seed.derive(ENCRYPTION_INFO)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| RecordError::Signature)?;
        let nonce = XNonce::try_from(&ciphertext[1..25]).map_err(|_| RecordError::Framing)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ciphertext[25..],
                        aad: AAD,
                    },
                )
                .map_err(|_| RecordError::Signature)?,
        );
        let signed = SignedRecord::parse(&plain)?;
        verify_descriptor(
            &signed,
            &self.seed,
            configured_api_origin,
            configured_witness,
            now_ms,
        )
    }
}

/// The owner's outer signature binds the API address and witness pin as well as
/// the public admission policy. Possession of the URL seed cannot rewrite them.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub v: u8,
    pub kind: String,
    pub name: String,
    pub address: SpaceAddress,
    pub witness: WitnessPin,
    pub proof: CallAuthorityProof,
    pub policy: String,
    pub invitation_public_key: String,
}

pub struct VerifiedDescriptor {
    signed: SignedRecord,
    descriptor: Descriptor,
    authority: Authority,
    policy: WitnessInvitationPolicy,
    invitation_signing_key: SigningKey,
}

impl VerifiedDescriptor {
    pub(crate) fn signed_record(&self) -> &SignedRecord {
        &self.signed
    }

    /// Restore only from the native encrypted pending store. The original owner
    /// signature and deployment pins are checked again; no seed is exported.
    pub(crate) fn restore_for_admission(
        signed: &SignedRecord,
        invitation_signing_key: SigningKey,
        configured_api_origin: &str,
        configured_witness: &WitnessPin,
        at_ms: u64,
    ) -> Result<Self> {
        verify_descriptor_with_key(
            signed,
            invitation_signing_key,
            configured_api_origin,
            configured_witness,
            at_ms,
        )
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
    pub fn policy(&self) -> &WitnessInvitationPolicy {
        &self.policy
    }
    pub fn invitation_signing_key(&self) -> &SigningKey {
        &self.invitation_signing_key
    }
}

/// Keep these fields separate: only ciphertext belongs in public storage.
pub struct EncryptedInvitation {
    pub link: InvitationLink,
    pub ciphertext: Vec<u8>,
}

pub fn seal(
    descriptor: &Descriptor,
    owner_key: &SigningKey,
    seed: InvitationSeed,
    configured_api_origin: &str,
    configured_witness: &WitnessPin,
    now_ms: u64,
) -> Result<EncryptedInvitation> {
    let body = serde_json::to_vec(descriptor).map_err(|_| RecordError::Json)?;
    if body.len() > record::MAX_RECORD - 72 {
        return Err(LinkError::DescriptorTooLarge);
    }
    let signed = SignedRecord::sign(&body, owner_key)?;
    verify_descriptor(
        &signed,
        &seed,
        configured_api_origin,
        configured_witness,
        now_ms,
    )?;
    encrypt_signed(&signed, seed)
}

fn encrypt_signed(signed: &SignedRecord, seed: InvitationSeed) -> Result<EncryptedInvitation> {
    let key = seed.derive(ENCRYPTION_INFO)?;
    let mut nonce_bytes = [0; 24];
    getrandom::fill(&mut nonce_bytes).map_err(|_| RecordError::Random)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| RecordError::Signature)?;
    let encrypted = cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: signed.bytes(),
                aad: AAD,
            },
        )
        .map_err(|_| RecordError::Signature)?;
    let mut ciphertext = Vec::with_capacity(25 + encrypted.len());
    ciphertext.push(VERSION);
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext.extend_from_slice(&encrypted);
    let ciphertext_id = Sha256::digest(&ciphertext).into();
    Ok(EncryptedInvitation {
        link: InvitationLink {
            ciphertext_id,
            seed,
            hosting_id: None,
        },
        ciphertext,
    })
}

fn verify_descriptor(
    signed: &SignedRecord,
    seed: &InvitationSeed,
    configured_api_origin: &str,
    configured_witness: &WitnessPin,
    now_ms: u64,
) -> Result<VerifiedDescriptor> {
    verify_descriptor_with_key(
        signed,
        seed.signing_key()?,
        configured_api_origin,
        configured_witness,
        now_ms,
    )
}

fn verify_descriptor_with_key(
    signed: &SignedRecord,
    invitation_signing_key: SigningKey,
    configured_api_origin: &str,
    configured_witness: &WitnessPin,
    now_ms: u64,
) -> Result<VerifiedDescriptor> {
    let descriptor: Descriptor = signed.decode()?;
    if descriptor.v != VERSION
        || descriptor.kind != "witness.invitation.descriptor"
        || !record::valid_display_name(&descriptor.name)
        || &descriptor.witness != configured_witness
    {
        return Err(RecordError::Authority.into());
    }
    descriptor
        .address
        .validate(false)
        .map_err(|_| RecordError::Authority)?;
    let address =
        reqwest::Url::parse(&descriptor.address.url).map_err(|_| RecordError::Authority)?;
    let api = reqwest::Url::parse(configured_api_origin).map_err(|_| RecordError::Authority)?;
    if api.scheme() != "https"
        || api.host_str().is_none()
        || api.path() != "/"
        || api.query().is_some()
        || api.fragment().is_some()
        || !api.username().is_empty()
        || api.password().is_some()
        || configured_api_origin.trim() != configured_api_origin
        || configured_api_origin.chars().any(char::is_control)
        || address.as_str() != descriptor.address.url
        || address.origin() != api.origin()
    {
        return Err(RecordError::Authority.into());
    }
    let scope = &descriptor.address.scope;
    let hosted = address
        .path()
        .strip_prefix("/spaces/")
        .and_then(|path| path.strip_suffix("/team/v1/spaces"))
        .is_some_and(|id| record::hex::<32>(id).is_ok());
    // Hosting allocation IDs differ from the cryptographic Space ID. The
    // owner's outer signature binds this canonical path to the verified scope.
    if address.path() != "/team/v1/spaces" && !hosted {
        return Err(RecordError::Authority.into());
    }
    let authority =
        descriptor
            .proof
            .verify_witnessed(scope.space, scope.stream, configured_witness)?;
    let initial = authority.initial_controller();
    if initial.id() != scope.controller
        || initial.record().body()["root_public_key"].as_str() != Some(scope.root.as_str())
        || descriptor.policy.len() > record::MAX_RECORD.div_ceil(3) * 4
    {
        return Err(RecordError::Authority.into());
    }
    let policy_record = SignedRecord::parse(
        &STANDARD
            .decode(&descriptor.policy)
            .map_err(|_| RecordError::Json)?,
    )?;
    let policy = authority.verify_witness_invitation(&policy_record, now_ms)?;
    let public_key = record::encode_hex(invitation_signing_key.verifying_key().as_bytes());
    if descriptor.invitation_public_key != public_key || policy.invitation_public_key != public_key
    {
        return Err(RecordError::Authority.into());
    }
    signed.verify_signature(authority.credential(policy.issuer_credential_id)?.key())?;
    Ok(VerifiedDescriptor {
        signed: signed.clone(),
        descriptor,
        authority,
        policy,
        invitation_signing_key,
    })
}

#[cfg(test)]
mod tests;

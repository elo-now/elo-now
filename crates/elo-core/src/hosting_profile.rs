//! Explicitly imported, signed hosting configuration. A valid signature proves
//! consistency, not trust: the native client must obtain the user's approval.
use crate::{
    authority::WitnessPin,
    message_retention::MessageRetention,
    record::{self, RecordError, SignedRecord},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub const PREFIX: &str = "elo://hosting/v1#";
pub const MAX_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedStorage {
    pub provider: String,
    pub retention_hours: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub url: String,
    pub managed: Option<ManagedStorage>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostingProfile {
    pub v: u8,
    pub kind: String,
    pub revision: u64,
    pub name: String,
    pub signing_public_key: String,
    pub create_url: String,
    pub witness: WitnessPin,
    pub storage: Option<Storage>,
    pub push_url: Option<String>,
    #[serde(default)]
    pub call_url: Option<String>,
    pub message_lifetimes: Vec<MessageRetention>,
    pub default_message_lifetime: MessageRetention,
}

/// Canonical URLs keep origin comparisons and displayed trust decisions equal.
pub fn endpoint(value: &str, path: &str) -> record::Result<()> {
    let url = reqwest::Url::parse(value).map_err(|_| RecordError::Json)?;
    if value.len() > 2048
        || url.as_str() != value
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != path
    {
        return Err(RecordError::Json);
    }
    Ok(())
}
impl HostingProfile {
    pub fn validate(&self) -> record::Result<()> {
        if self.v != 1
            || self.kind != "hosting.configuration"
            || self.revision == 0
            || self.revision > record::MAX_INTEGER
            || !record::valid_display_name(&self.name)
            || self.name.len() > 96
            || self.name.trim() != self.name
            || !MessageRetention::validate_allowed(&self.message_lifetimes)
            || !self
                .message_lifetimes
                .contains(&self.default_message_lifetime)
        {
            return Err(RecordError::Json);
        }
        VerifyingKey::from_bytes(&record::hex::<32>(&self.signing_public_key)?)
            .map_err(|_| RecordError::Signature)?;
        endpoint(&self.create_url, "/spaces/v1/create")?;
        self.witness.validate()?;
        endpoint(&self.witness.url, "/witness/v1")?;
        if let Some(storage) = &self.storage {
            endpoint(&storage.url, "/storage/v1")?;
            if let Some(managed) = &storage.managed
                && (!matches!(managed.provider.as_str(), "mega" | "s3")
                    || !matches!(managed.retention_hours, 1 | 12 | 24))
            {
                return Err(RecordError::Json);
            }
        }
        if let Some(url) = &self.push_url {
            endpoint(url, "/")?;
        }
        if let Some(url) = &self.call_url {
            endpoint(url, "/calls/v1")?;
        }
        Ok(())
    }
    pub fn id(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"elo.now/hosting-configuration/id/v1\0");
        hash.update(self.signing_public_key.as_bytes());
        record::encode_hex(&hash.finalize())
    }
    /// Updates may change advertised policy/name, never an approved trust anchor.
    pub fn accepts_update(&self, next: &Self) -> bool {
        self.id() == next.id()
            && next.revision > self.revision
            && self.create_url == next.create_url
            && self.witness == next.witness
            && self.storage.as_ref().map(|s| &s.url) == next.storage.as_ref().map(|s| &s.url)
            && self.push_url == next.push_url
            && self.call_url == next.call_url
    }
    pub fn sign(&self, key: &SigningKey) -> record::Result<SignedRecord> {
        self.validate()?;
        if self.signing_public_key != record::encode_hex(key.verifying_key().as_bytes()) {
            return Err(RecordError::Signature);
        }
        SignedRecord::sign_bounded(
            &serde_json::to_vec(self).map_err(|_| RecordError::Json)?,
            key,
            MAX_BYTES,
        )
    }
    pub fn from_record(bytes: &[u8]) -> record::Result<Self> {
        let record = SignedRecord::parse_bounded(bytes, MAX_BYTES)?;
        let profile: Self = record.decode()?;
        profile.validate()?;
        let key = VerifyingKey::from_bytes(&record::hex::<32>(&profile.signing_public_key)?)
            .map_err(|_| RecordError::Signature)?;
        record.verify_signature(&key)?;
        Ok(profile)
    }
    pub fn parse_link(link: &str) -> record::Result<(Self, Vec<u8>)> {
        let encoded = link
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(RecordError::Framing)?;
        if encoded.len() > MAX_BYTES * 2 {
            return Err(RecordError::Framing);
        }
        let compressed = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| RecordError::Framing)?;
        if URL_SAFE_NO_PAD.encode(&compressed) != encoded {
            return Err(RecordError::Framing);
        }
        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        let mut bytes = Vec::new();
        (&mut decoder)
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RecordError::Framing)?;
        if bytes.len() > MAX_BYTES || decoder.total_in() != compressed.len() as u64 {
            return Err(RecordError::Framing);
        }
        Ok((Self::from_record(&bytes)?, bytes))
    }
    pub fn link(record: &SignedRecord) -> record::Result<String> {
        Self::from_record(record.bytes())?;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(record.bytes())
            .map_err(|_| RecordError::Framing)?;
        Ok(format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(encoder.finish().map_err(|_| RecordError::Framing)?)
        ))
    }
    pub fn export(body: &[u8], key: &[u8; 32]) -> record::Result<serde_json::Value> {
        let value = record::strict_json(body, MAX_BYTES)?;
        let profile: Self = serde_json::from_value(value).map_err(|_| RecordError::Json)?;
        let signed = profile.sign(&SigningKey::from_bytes(key))?;
        Ok(
            serde_json::json!({"record":STANDARD.encode(signed.bytes()),"link":Self::link(&signed)?}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile(key: &SigningKey) -> HostingProfile {
        HostingProfile {
            v: 1,
            kind: "hosting.configuration".into(),
            revision: 1,
            name: "Private hosting".into(),
            signing_public_key: record::encode_hex(key.verifying_key().as_bytes()),
            create_url: "https://api.example/spaces/v1/create".into(),
            witness: WitnessPin {
                url: "https://witness.example/witness/v1".into(),
                public_key: record::encode_hex(
                    SigningKey::from_bytes(&[8; 32]).verifying_key().as_bytes(),
                ),
                key_generation: 1,
            },
            storage: None,
            push_url: None,
            call_url: None,
            message_lifetimes: vec![MessageRetention::Hours24, MessageRetention::NoExpiry],
            default_message_lifetime: MessageRetention::Hours24,
        }
    }
    #[test]
    fn imported_configuration_is_signed_bounded_and_canonical() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let p = profile(&key);
        let r = p.sign(&key).unwrap();
        let link = HostingProfile::link(&r).unwrap();
        assert_eq!(HostingProfile::parse_link(&link).unwrap().0, p);
        let mut bad = r.bytes().to_vec();
        bad[25] ^= 1;
        assert!(HostingProfile::from_record(&bad).is_err());
        assert!(HostingProfile::parse_link(&(link + "=")).is_err());
        let mut huge = ZlibEncoder::new(Vec::new(), Compression::best());
        huge.write_all(&vec![0; MAX_BYTES * 100]).unwrap();
        assert!(
            HostingProfile::parse_link(&format!(
                "{PREFIX}{}",
                URL_SAFE_NO_PAD.encode(huge.finish().unwrap())
            ))
            .is_err()
        );
        let mut bad = p.clone();
        bad.create_url = "http://api.example/spaces/v1/create".into();
        assert!(bad.validate().is_err());
        bad = p.clone();
        bad.message_lifetimes.push(MessageRetention::Hours24);
        assert!(bad.validate().is_err());
        for invalid in [
            "http://push.example/",
            "https://push.example/token",
            "https://push.example/?token=secret",
            "https://user@push.example/",
        ] {
            bad = p.clone();
            bad.push_url = Some(invalid.into());
            assert!(bad.validate().is_err());
        }
    }
    #[test]
    fn revision_updates_cannot_replace_trust_pins() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let p = profile(&key);
        let mut next = p.clone();
        assert!(!p.accepts_update(&next));
        next.revision = 2;
        next.name = "Renamed".into();
        assert!(p.accepts_update(&next));
        next.witness.public_key =
            record::encode_hex(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes());
        assert!(!p.accepts_update(&next));
    }
    #[test]
    fn optional_services_are_signed_and_cannot_change_after_approval() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut p = profile(&key);
        p.push_url = Some("https://push.example/".into());
        p.call_url = Some("https://calls.example/calls/v1".into());
        assert_eq!(
            HostingProfile::from_record(p.sign(&key).unwrap().bytes()).unwrap(),
            p
        );
        let mut next = p.clone();
        next.revision += 1;
        assert!(p.accepts_update(&next));
        next.call_url = Some("https://other.example/calls/v1".into());
        assert!(!p.accepts_update(&next));
        next.call_url = p.call_url.clone();
        next.push_url = None;
        assert!(!p.accepts_update(&next));
        for invalid in [
            "http://calls.example/calls/v1",
            "https://calls.example/",
            "https://calls.example/calls/v1?token=secret",
            "https://user@calls.example/calls/v1",
        ] {
            next.call_url = Some(invalid.into());
            assert!(next.validate().is_err());
        }
    }
}

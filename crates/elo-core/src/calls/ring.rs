//! Short encrypted wake hints, independent of the locked profile's age key.
//! Possession only permits routing to a cached call-only delegation. Admission
//! still requires a current signed call state and membership on the call server.
use super::CallScope;
use crate::{
    ids::{IdentityId, SpaceId},
    record::{self, RecordError, Result},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"elo.now/call-ring-target/v1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingTarget {
    pub v: u8,
    pub hosting_space_id: SpaceId,
    pub scope: CallScope,
    pub recipient: IdentityId,
    pub call_id: String,
    pub invitation_id: String,
    pub expires: u64,
}

fn cipher(scope_key: &str, route: &str) -> Result<XChaCha20Poly1305> {
    record::hex::<16>(route)?;
    let secret = Zeroizing::new(record::hex::<32>(scope_key)?);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(DOMAIN), secret.as_ref())
        .expand(route.as_bytes(), key.as_mut())
        .map_err(|_| RecordError::Json)?;
    Ok(XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| RecordError::Json)?)
}
fn validate(target: &RingTarget, now: u64) -> Result<()> {
    record::hex::<16>(&target.call_id)?;
    record::hex::<16>(&target.invitation_id)?;
    if target.v != 1 || target.expires <= now || target.expires > now.saturating_add(75) {
        return Err(RecordError::Authority);
    }
    Ok(())
}
pub fn seal(scope_key: &str, route: &str, target: &RingTarget, now: u64) -> Result<String> {
    validate(target, now)?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| RecordError::Json)?;
    let plain = Zeroizing::new(serde_json::to_vec(target).map_err(|_| RecordError::Json)?);
    let encrypted = cipher(scope_key, route)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: DOMAIN,
            },
        )
        .map_err(|_| RecordError::Json)?;
    Ok(URL_SAFE_NO_PAD.encode([nonce.as_slice(), &encrypted].concat()))
}
pub fn open(scope_key: &str, route: &str, encoded: &str, now: u64) -> Result<RingTarget> {
    if !(64..=2048).contains(&encoded.len()) {
        return Err(RecordError::Framing);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RecordError::Json)?;
    if bytes.len() < 40 {
        return Err(RecordError::Framing);
    }
    let nonce: [u8; 24] = bytes[..24].try_into().map_err(|_| RecordError::Framing)?;
    let plain = Zeroizing::new(
        cipher(scope_key, route)?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[24..],
                    aad: DOMAIN,
                },
            )
            .map_err(|_| RecordError::Signature)?,
    );
    let target: RingTarget = serde_json::from_slice(&plain).map_err(|_| RecordError::Json)?;
    validate(&target, now)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_target_is_route_bound_authenticated_and_expiring() {
        let key = "ab".repeat(32);
        let route = "cd".repeat(16);
        let target = RingTarget {
            v: 1,
            hosting_space_id: SpaceId::from_bytes([1; 32]),
            scope: CallScope {
                space_id: SpaceId::from_bytes([2; 32]),
                stream_id: crate::ids::StreamId::from_bytes([3; 16]),
            },
            recipient: IdentityId::from_bytes([4; 32]),
            call_id: "11".repeat(16),
            invitation_id: "22".repeat(16),
            expires: 1060,
        };
        let first = seal(&key, &route, &target, 1000).unwrap();
        assert_ne!(first, seal(&key, &route, &target, 1000).unwrap());
        assert_eq!(
            open(&key, &route, &first, 1000).unwrap().call_id,
            target.call_id
        );
        assert!(open(&key, &"ef".repeat(16), &first, 1000).is_err());
        assert!(open(&"00".repeat(32), &route, &first, 1000).is_err());
        assert!(open(&key, &route, &first, 1060).is_err());
        let mut corrupted = URL_SAFE_NO_PAD.decode(&first).unwrap();
        corrupted[30] ^= 1;
        assert!(open(&key, &route, &URL_SAFE_NO_PAD.encode(corrupted), 1000).is_err());
    }
}

use super::*;
use crate::{
    identity::{DeviceCredential, VerifiedCredential},
    invite::shared,
};
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use serde_json::json;

fn fixture(delegated: bool, wake: bool) -> (SignedRecord, VerifiedCredential) {
    let root = SigningKey::from_bytes(&[1; 32]);
    let device = SigningKey::from_bytes(&[2; 32]);
    let age = age::x25519::Identity::generate();
    let parent = DeviceCredential::issue(&root, &device.verifying_key(), &age.to_public()).unwrap();
    let child = SigningKey::from_bytes(&[3; 32]);
    let (credential, key) = if delegated {
        (
            DeviceCredential::issue_companion(
                &parent,
                &device,
                &child.verifying_key(),
                &age.to_public(),
            )
            .unwrap(),
            child,
        )
    } else {
        (parent, device)
    };
    let card = shared::contact(&credential, &key, "Zoë 🦊", 86_400_000).unwrap();
    let mut body = card.body().clone();
    if wake {
        body["wake"] = json!({
            "endpoint":"https://wake.example.invalid/wake/v1",
            "id":crate::record::random_hex::<32>().unwrap(),
            "notify_key":crate::record::random_hex::<32>().unwrap(),
            "scope_key":crate::record::random_hex::<32>().unwrap(), "since":1,
        });
    }
    let card = SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &key).unwrap();
    (card, credential)
}

fn legacy(card: &SignedRecord, credential: &SignedRecord) -> String {
    let packet = json!({"kind":"Contact","card":STANDARD.encode(card.bytes()),"credential":STANDARD.encode(credential.bytes())});
    let mut zip = ZlibEncoder::new(Vec::new(), Compression::default());
    zip.write_all(&serde_json::to_vec(&packet).unwrap())
        .unwrap();
    format!(
        "elo://exchange/v1#{}",
        URL_SAFE_NO_PAD.encode(zip.finish().unwrap())
    )
}

fn envelope(bytes: &[u8]) -> String {
    let mut zip = ZlibEncoder::new(Vec::new(), Compression::best());
    zip.write_all(bytes).unwrap();
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(zip.finish().unwrap()))
}

#[test]
fn compact_contact_preserves_signed_bytes_and_shortens_root_and_companion_cards() {
    for delegated in [false, true] {
        for wake in [false, true] {
            let (card, credential) = fixture(delegated, wake);
            let link = encode(&card, credential.record()).unwrap();
            let old = legacy(&card, credential.record());
            let (decoded_card, decoded_credential) = decode(&link).unwrap();
            assert_eq!(decoded_card.bytes(), card.bytes());
            assert_eq!(decoded_card.id(), card.id());
            assert_eq!(decoded_credential.bytes(), credential.record().bytes());
            assert_eq!(decoded_credential.id(), credential.id());
            let root = SigningKey::from_bytes(&[1; 32]);
            let verified =
                VerifiedCredential::verify(decoded_credential.bytes(), &root.verifying_key())
                    .unwrap();
            assert_eq!(
                shared::verify_contact(&decoded_card, &verified, 1)
                    .unwrap()
                    .name,
                "Zoë 🦊"
            );
            assert!(shared::verify_contact(&decoded_card, &verified, 86_400_000).is_err());
            assert!(
                link.len() < old.len(),
                "compact={} legacy={}",
                link.len(),
                old.len()
            );
            println!(
                "delegated={delegated} wake={wake}: legacy={} compact={} saved={}%, offline byte-exact roundtrip",
                old.len(),
                link.len(),
                100 * (old.len() - link.len()) / old.len()
            );
        }
    }
}

#[test]
fn compact_contact_rejects_invalid_framing_versions_and_compression() {
    let (card, credential) = fixture(false, true);
    let link = encode(&card, credential.record()).unwrap();
    let bytes = URL_SAFE_NO_PAD
        .decode(link.strip_prefix(PREFIX).unwrap())
        .unwrap();
    for end in 0..bytes.len() {
        assert!(
            decode(&format!(
                "{PREFIX}{}",
                URL_SAFE_NO_PAD.encode(&bytes[..end])
            ))
            .is_err(),
            "truncation at {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(&bytes);
    assert!(decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(trailing))).is_err());
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(corrupt))).is_err());
    for invalid in [
        String::new(),
        PREFIX.into(),
        format!("{link}="),
        link.replace("/v1#", "/v2#"),
        format!("{PREFIX}!"),
        format!("{PREFIX}{}", "A".repeat(MAX_ENCODED + 1)),
        envelope(&[0; 148]),
        envelope(&[0; 147]),
        envelope(&vec![0; MAX_PLAIN + 1]),
    ] {
        assert!(decode(&invalid).is_err());
    }
    let mut plain = Vec::new();
    plain.extend_from_slice(&u32::MAX.to_be_bytes());
    plain.extend_from_slice(card.bytes());
    plain.extend_from_slice(credential.record().bytes());
    assert!(decode(&envelope(&plain)).is_err());
    plain[..4].copy_from_slice(&(card.bytes().len() as u32).to_be_bytes());
    plain.push(0);
    assert!(decode(&envelope(&plain)).is_err());
    assert!(encode(credential.record(), &card).is_err());
}

#[test]
fn compact_contact_does_not_bypass_signature_or_credential_binding() {
    let (card, credential) = fixture(false, false);
    let mut modified = card.bytes().to_vec();
    *modified.last_mut().unwrap() ^= 1;
    let modified = SignedRecord::parse(&modified).unwrap();
    let link = encode(&modified, credential.record()).unwrap();
    let (modified, _) = decode(&link).unwrap();
    assert!(shared::verify_contact(&modified, &credential, 1).is_err());
    let (_, other) = fixture(true, false);
    let link = encode(&card, other.record()).unwrap();
    let (decoded, _) = decode(&link).unwrap();
    assert!(shared::verify_contact(&decoded, &other, 1).is_err());
}

#[test]
fn compact_contact_preserves_noncanonical_signed_json() {
    let (card, credential) = fixture(false, true);
    let card = SignedRecord::sign(
        &serde_json::to_vec_pretty(card.body()).unwrap(),
        &SigningKey::from_bytes(&[2; 32]),
    )
    .unwrap();
    let (decoded, _) = decode(&encode(&card, credential.record()).unwrap()).unwrap();
    assert_eq!(decoded.bytes(), card.bytes());
    assert_eq!(decoded.id(), card.id());
    shared::verify_contact(&decoded, &credential, 1).unwrap();
}

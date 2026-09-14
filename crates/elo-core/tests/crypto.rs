use ed25519_dalek::SigningKey;
use elo_core::{
    crypto::{open_record, seal_chat, seal_record},
    identity::DeviceCredential,
    record::SignedRecord,
};
const FIXTURE: &[u8] = include_bytes!("../../../protocol/fixtures/chat-message-v1.record.bin");
#[test]
fn multiple_readers_self_copy_and_outsider() {
    let alice = age::x25519::Identity::generate();
    let bob = age::x25519::Identity::generate();
    let replica = age::x25519::Identity::generate();
    let record = SignedRecord::parse(FIXTURE).unwrap();
    let c = seal_record(&record, &[alice.to_public(), bob.to_public()]).unwrap();
    for reader in [&alice, &bob] {
        assert_eq!(open_record(&c, reader).unwrap().bytes(), FIXTURE);
    }
    assert!(open_record(&c, &replica).is_err());
    let other = seal_record(&record, &[bob.to_public()]).unwrap();
    assert!(open_record(&other, &alice).is_err());
    assert_ne!(
        c,
        seal_record(&record, &[alice.to_public(), bob.to_public()]).unwrap()
    );
}
#[test]
fn truncation_corruption_and_trailing_bytes_never_return_a_prefix() {
    let identity = age::x25519::Identity::generate();
    let record = SignedRecord::parse(FIXTURE).unwrap();
    let c = seal_record(&record, &[identity.to_public()]).unwrap();
    for end in [0, 1, 20, 100, c.len() - 17, c.len() - 1] {
        assert!(open_record(&c[..end], &identity).is_err());
    }
    for pos in [0, 20, 100, c.len() - 17, c.len() - 1] {
        let mut b = c.clone();
        b[pos] ^= 1;
        assert!(open_record(&b, &identity).is_err());
    }
    let mut b = c;
    b.push(0);
    assert!(open_record(&b, &identity).is_err());
}
#[test]
fn invalid_recipient_sets_and_signed_set_mismatch_are_rejected() {
    let identity = age::x25519::Identity::generate();
    let record = SignedRecord::parse(FIXTURE).unwrap();
    assert!(seal_record(&record, &[]).is_err());
    assert!(seal_record(&record, &[identity.to_public(), identity.to_public()]).is_err());
    let many: Vec<_> = (0..=elo_core::record::MAX_CHAT_CREDENTIALS)
        .map(|_| age::x25519::Identity::generate().to_public())
        .collect();
    assert!(seal_record(&record, &many).is_err());
    let key = SigningKey::from_bytes(&[5; 32]);
    let credential =
        DeviceCredential::issue(&key, &key.verifying_key(), &identity.to_public()).unwrap();
    assert!(seal_chat(&record, std::slice::from_ref(&credential)).is_err());
    let mut chat = record.chat().unwrap();
    chat.recipient_credentials = vec![credential.id()];
    let signed = chat.sign(&key).unwrap();
    let c = seal_chat(&signed, &[credential]).unwrap();
    assert_eq!(open_record(&c, &identity).unwrap().bytes(), signed.bytes());
}
#[test]
fn oversized_plaintext_and_multichunk_truncation_are_rejected() {
    use std::io::Write;
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let mut c = Vec::new();
    let enc = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .unwrap();
    let mut w = enc.wrap_output(&mut c).unwrap();
    w.write_all(&vec![0; elo_core::record::MAX_RECORD + 1])
        .unwrap();
    w.finish().unwrap();
    assert!(open_record(&c, &identity).is_err());
    assert!(open_record(&c[..c.len() - 100], &identity).is_err());
}

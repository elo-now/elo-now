use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use elo_core::{
    identity::{DeviceCredential, VerifiedCredential},
    ids::{IdentityId, RecordId},
    record::{ChatMessage, MAX_RECORD, SignedRecord},
    store::{ClientStore, LocalTime, PreparedLocalRecord, RecordMetadata},
};
use serde_json::{Value, json};
const RECORD: &[u8] = include_bytes!("../../../protocol/fixtures/chat-message-v1.record.bin");
const BODY: &[u8] = include_bytes!("../../../protocol/fixtures/chat-message-v1.body.json");
fn key() -> SigningKey {
    SigningKey::from_bytes(&std::array::from_fn(|i| i as u8))
}
fn raw(body: &[u8]) -> Vec<u8> {
    let mut v = b"ELO1".to_vec();
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(body);
    let mut m = b"elo.now/signed-record/v1\0".to_vec();
    m.extend_from_slice(body);
    v.extend_from_slice(&key().sign(&m).to_bytes());
    v
}
fn valid(bytes: &[u8]) -> bool {
    SignedRecord::parse(bytes)
        .and_then(|r| {
            r.verify_signature(&key().verifying_key())?;
            r.chat()
        })
        .is_ok()
}
#[test]
fn python_fixture_matches_signature_bytes_and_all_ids() {
    let expected: Value = serde_json::from_slice(include_bytes!(
        "../../../protocol/fixtures/chat-message-v1.expected.json"
    ))
    .unwrap();
    let r = SignedRecord::parse(RECORD).unwrap();
    r.verify_signature(&key().verifying_key()).unwrap();
    r.chat().unwrap();
    assert_eq!(r.body_bytes(), BODY);
    assert_eq!(r.id().to_string(), expected["record_id"]);
    assert_eq!(
        IdentityId::of_root_key(key().verifying_key().as_bytes()).to_string(),
        expected["root_identity_id_for_same_test_public_key"]
    );
    assert_eq!(SignedRecord::sign(BODY, &key()).unwrap().bytes(), RECORD);
}
#[test]
fn sender_names_are_bounded_signed_and_optional_for_existing_records() {
    let legacy = SignedRecord::parse(RECORD).unwrap();
    assert!(legacy.chat().unwrap().payload.sender_name.is_none());
    assert_eq!(legacy.bytes(), RECORD);
    let mut body: Value = serde_json::from_slice(BODY).unwrap();
    for name in [
        json!("Alex River"),
        json!("李 小龍"),
        json!("x".repeat(120)),
    ] {
        body["payload"]["sender_name"] = name;
        let signed = raw(&serde_json::to_vec(&body).unwrap());
        assert!(valid(&signed));
    }
    for name in [
        json!(""),
        json!(" Alex"),
        json!("Alex "),
        json!("A\nB"),
        json!("x".repeat(121)),
        json!("🌿".repeat(31)),
        json!(7),
        json!([]),
    ] {
        body["payload"]["sender_name"] = name;
        assert!(!valid(&raw(&serde_json::to_vec(&body).unwrap())));
    }
    body["payload"]["sender_name"] = json!("Alex");
    let mut changed = raw(&serde_json::to_vec(&body).unwrap());
    let start = changed.windows(4).position(|part| part == b"Alex").unwrap();
    changed[start..start + 4].copy_from_slice(b"Maya");
    assert!(!valid(&changed));
}
#[test]
fn every_byte_is_bound_by_framing_or_signature() {
    for i in 0..RECORD.len() {
        let mut b = RECORD.to_vec();
        b[i] ^= 1;
        assert!(!valid(&b), "byte {i}");
    }
    for n in [0, 1, 4, 8, 71, RECORD.len() - 1] {
        assert!(!valid(&RECORD[..n]));
    }
    let mut b = RECORD.to_vec();
    b.push(0);
    assert!(!valid(&b));
    let mut b = RECORD.to_vec();
    b[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(!valid(&b));
    assert!(!valid(&vec![0; MAX_RECORD + 1]));
}
#[test]
fn strict_json_rejects_duplicate_keys_including_escaped_and_nested() {
    let s = std::str::from_utf8(BODY).unwrap();
    for body in [
        s.replacen("\"v\":1", "\"v\":1,\"v\":1", 1),
        s.replacen("\"v\":1", "\"v\":1,\"\\u0076\":1", 1),
        s.replacen("\"text\":", "\"text\":\"x\",\"text\":", 1),
    ] {
        assert!(!valid(&raw(body.as_bytes())));
    }
}
#[test]
fn strict_json_rejects_numeric_unicode_depth_and_outer_bytes() {
    let s = std::str::from_utf8(BODY).unwrap();
    for token in [
        "1.0",
        "1e0",
        "NaN",
        "Infinity",
        "-0",
        "-1",
        "9007199254740992",
        "true",
    ] {
        assert!(!valid(&raw(s
            .replace("\"logical_time\":1", &format!("\"logical_time\":{token}"))
            .as_bytes())));
    }
    for b in [
        format!(" {s}"),
        format!("{s}\n"),
        format!("\u{feff}{s}"),
        format!("{s}{{}}"),
        format!("{{\"v\":1,\"x\":{}0{}}}", "[".repeat(17), "]".repeat(17)),
        s.replacen("elo", "\\ud800", 1),
    ] {
        assert!(!valid(&raw(b.as_bytes())));
    }
    let mut b = BODY.to_vec();
    b[20] = 0xff;
    assert!(!valid(&raw(&b)));
}
#[test]
fn schema_rejects_unknown_fields_bad_dates_and_limits_even_when_signed() {
    let original: Value = serde_json::from_slice(BODY).unwrap();
    for (field, val) in [
        ("v", json!(2)),
        ("v", json!(true)),
        ("kind", json!("unknown")),
        ("surprise", json!(0)),
        ("nonce", json!("AB".repeat(16))),
        ("created_at", json!("2026-02-29T12:00:00Z")),
        ("created_at", json!("2026-09-08T24:00:00Z")),
        ("payload", json!({"text":""})),
        ("payload", json!({"text":"a".repeat(16385)})),
        ("payload", json!({"text":"x","extra":0})),
        ("audience", json!([])),
    ] {
        let mut v = original.clone();
        v[field] = val;
        assert!(!valid(&raw(&serde_json::to_vec(&v).unwrap())), "{field}");
    }
    for field in ["audience", "recipient_credentials"] {
        let mut v = original.clone();
        v[field].as_array_mut().unwrap().reverse();
        assert!(!valid(&raw(&serde_json::to_vec(&v).unwrap())));
        let mut v = original.clone();
        v[field] = json!([v[field][0], v[field][0]]);
        assert!(!valid(&raw(&serde_json::to_vec(&v).unwrap())));
    }
    let mut v = original;
    v["payload"]["text"] = json!("ą".repeat(8192));
    assert!(valid(&raw(&serde_json::to_vec(&v).unwrap())));
}
#[test]
fn whitespace_is_preserved_and_requires_new_signature() {
    let body = std::str::from_utf8(BODY).unwrap().replacen('{', "{ ", 1);
    let r = SignedRecord::parse(&raw(body.as_bytes())).unwrap();
    r.verify_signature(&key().verifying_key()).unwrap();
    assert_ne!(r.id(), SignedRecord::parse(RECORD).unwrap().id());
    let mut b = r.bytes().to_vec();
    let len = b.len();
    b[len - 64..].copy_from_slice(&RECORD[RECORD.len() - 64..]);
    assert!(!valid(&b));
}
#[test]
fn wrong_domain_key_and_noncanonical_signature_are_rejected() {
    let r = SignedRecord::parse(RECORD).unwrap();
    assert!(
        r.verify_signature(&SigningKey::from_bytes(&[99; 32]).verifying_key())
            .is_err()
    );
    let mut b = RECORD.to_vec();
    let len = b.len();
    b[len - 64..].copy_from_slice(&key().sign(BODY).to_bytes());
    assert!(!valid(&b));
    let mut b = RECORD.to_vec();
    b[len - 32..].fill(255);
    assert!(!valid(&b));
    let weak = VerifyingKey::from_bytes(&[0; 32]).unwrap();
    assert!(r.verify_signature(&weak).is_err());
}
#[test]
fn credential_requires_pinned_root_and_exact_device_binding() {
    let root = SigningKey::from_bytes(&[21; 32]);
    let device = key();
    let age = age::x25519::Identity::generate();
    let c = DeviceCredential::issue(&root, &device.verifying_key(), &age.to_public()).unwrap();
    assert!(VerifiedCredential::verify(c.record().bytes(), &device.verifying_key()).is_err());
    let mut chat: ChatMessage = SignedRecord::parse(RECORD).unwrap().chat().unwrap();
    chat.issuer_identity = c.identity();
    chat.issuer_credential = c.id();
    let r = chat.sign(&device).unwrap();
    c.verify_chat(&r).unwrap();
    chat.issuer_credential = RecordId::from_bytes([0; 32]);
    assert!(c.verify_chat(&chat.sign(&device).unwrap()).is_err());
    chat.issuer_credential = c.id();
    chat.issuer_identity = IdentityId::from_bytes([0; 32]);
    assert!(c.verify_chat(&chat.sign(&device).unwrap()).is_err());
    let mut body = c.record().body().clone();
    body["age_recipient"] = json!("age1invalid");
    let r = SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &root).unwrap();
    assert!(VerifiedCredential::verify(r.bytes(), &root.verifying_key()).is_err());
}
#[tokio::test]
async fn exact_record_bytes_survive_storage_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    // Public signature fixture only. T03 adds encrypted storage.
    let input = PreparedLocalRecord::new(
        RecordId::of_record_bytes(RECORD),
        RECORD.to_vec(),
        RecordMetadata::new("dev.signed_fixture", None, None, None).unwrap(),
        vec![],
        LocalTime::from_millis(1).unwrap(),
    )
    .unwrap();
    let result = store.commit_local_record_with_outbox(input).await.unwrap();
    store.close().await.unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let b = store.get_object(result.object_id).await.unwrap().unwrap();
    assert_eq!(b, RECORD);
    assert!(valid(&b));
    store.close().await.unwrap();
}

#[test]
fn thread_roots_are_optional_canonical_record_ids_bound_by_the_signature() {
    let legacy = SignedRecord::parse(RECORD).unwrap();
    assert!(legacy.chat().unwrap().payload.thread_root.is_none());
    let mut body: Value = serde_json::from_slice(BODY).unwrap();
    let root = "ab".repeat(32);
    body["payload"]["thread_root"] = json!(root);
    let signed = raw(&serde_json::to_vec(&body).unwrap());
    assert!(valid(&signed));
    assert_eq!(
        SignedRecord::parse(&signed)
            .unwrap()
            .chat()
            .unwrap()
            .payload
            .thread_root
            .unwrap()
            .to_string(),
        root
    );
    for invalid in [
        json!("missing"),
        json!(17),
        json!([]),
        json!("ab".repeat(31)),
        json!("ab".repeat(33)),
    ] {
        body["payload"]["thread_root"] = invalid;
        assert!(!valid(&raw(&serde_json::to_vec(&body).unwrap())));
    }
    let mut tampered = signed;
    let start = tampered
        .windows(root.len())
        .position(|part| part == root.as_bytes())
        .unwrap();
    tampered[start] = b'c';
    assert!(!valid(&tampered));
    assert_eq!(legacy.bytes(), RECORD);
}

#[test]
fn message_actions_are_strict_typed_signed_events_without_changing_legacy_bytes() {
    let legacy = SignedRecord::parse(RECORD).unwrap();
    assert!(legacy.chat().unwrap().payload.action.is_none());
    assert_eq!(legacy.bytes(), RECORD);
    let mut body: Value = serde_json::from_slice(BODY).unwrap();
    body["kind"] = json!("chat.action");
    body["payload"]["text"] = json!("");
    body["payload"]["action"] =
        json!({"type":"reaction","target":legacy.id(),"emoji":"👍","active":true});
    assert!(valid(&raw(&serde_json::to_vec(&body).unwrap())));
    let choices = elo_core::record::reaction_choices();
    assert!(choices.len() >= 200);
    let unique: std::collections::BTreeSet<_> = choices.iter().collect();
    assert_eq!(choices.len(), unique.len());
    for emoji in choices {
        body["payload"]["action"]["emoji"] = json!(emoji);
        assert!(valid(&raw(&serde_json::to_vec(&body).unwrap())), "{emoji}");
    }
    for (pointer, value) in [
        ("/payload/action/emoji", json!("x")),
        ("/payload/action/active", json!("true")),
        ("/payload/action/target", json!("bad")),
        ("/payload/text", json!("not a message")),
        ("/kind", json!("chat.message")),
    ] {
        let mut bad = body.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(!valid(&raw(&serde_json::to_vec(&bad).unwrap())));
    }
    let mut bad = body.clone();
    bad["payload"]["thread_root"] = json!(legacy.id());
    assert!(!valid(&raw(&serde_json::to_vec(&bad).unwrap())));
    let mut bad = body.clone();
    bad["payload"]["action"]["extra"] = json!("ignored?");
    assert!(!valid(&raw(&serde_json::to_vec(&bad).unwrap())));
    body["payload"]["action"] = json!({"type":"pin","target":legacy.id(),"active":false});
    let signed = raw(&serde_json::to_vec(&body).unwrap());
    assert!(valid(&signed));
    let mut changed = signed.clone();
    let offset = changed.windows(5).position(|p| p == b"false").unwrap();
    changed[offset..offset + 5].copy_from_slice(b"true ");
    assert!(!valid(&changed));
}

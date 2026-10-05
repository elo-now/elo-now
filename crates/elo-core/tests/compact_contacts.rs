use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use elo_core::{
    app::ProfileDraft,
    identity::DeviceCredential,
    invite::{contact_code, shared},
    record::SignedRecord,
};
use flate2::{Compression, write::ZlibEncoder};
use serde_json::json;
use std::io::Write;
use tempfile::TempDir;

fn legacy_contact(card: &SignedRecord, credential: &SignedRecord) -> String {
    let packet = json!({
        "kind": "Contact",
        "card": STANDARD.encode(card.bytes()),
        "credential": STANDARD.encode(credential.bytes()),
    });
    let mut zip = ZlibEncoder::new(Vec::new(), Compression::default());
    zip.write_all(&serde_json::to_vec(&packet).unwrap())
        .unwrap();
    format!(
        "elo://exchange/v1#{}",
        URL_SAFE_NO_PAD.encode(zip.finish().unwrap())
    )
}

#[tokio::test]
async fn compact_my_code_preserves_review_verification_and_legacy_contact_deduplication() {
    let dir = TempDir::new().unwrap();
    let password = "synthetic compact-contact test password";
    let mut recipient = ProfileDraft::new()
        .unwrap()
        .save_named(
            dir.path().join("recipient"),
            password.into(),
            "General",
            "Alex",
        )
        .await
        .unwrap();
    let mut person = ProfileDraft::new()
        .unwrap()
        .save_named(
            dir.path().join("person"),
            password.into(),
            "General",
            "Zoë 🦊",
        )
        .await
        .unwrap();
    let create = json!({"op": "contact_create", "name": "Zoë 🦊"});
    let code = person.operate(create.clone()).await.unwrap();
    let link = code["link"].as_str().unwrap();
    assert!(link.starts_with(contact_code::PREFIX));
    assert_eq!(person.operate(create).await.unwrap(), code);
    let (card, credential) = contact_code::decode(link).unwrap();
    let legacy = legacy_contact(&card, &credential);
    assert!(link.len() < legacy.len());

    // Valid framing must not bypass signature, credential binding or expiry.
    let mut forged = card.bytes().to_vec();
    *forged.last_mut().unwrap() ^= 1;
    let forged = SignedRecord::parse(&forged).unwrap();
    let root = SigningKey::from_bytes(&[71; 32]);
    let device = SigningKey::from_bytes(&[72; 32]);
    let age = age::x25519::Identity::generate();
    let other = DeviceCredential::issue(&root, &device.verifying_key(), &age.to_public()).unwrap();
    let expired = shared::contact(&other, &device, "Expired contact", 1).unwrap();
    for invalid in [
        contact_code::encode(&forged, &credential).unwrap(),
        contact_code::encode(&card, other.record()).unwrap(),
        contact_code::encode(&expired, other.record()).unwrap(),
    ] {
        assert!(
            recipient
                .operate(json!({"op": "contact_preview", "link": invalid}))
                .await
                .is_err()
        );
        assert!(
            recipient.view().await.unwrap()["contacts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    let preview = recipient
        .operate(json!({"op": "contact_preview", "link": link}))
        .await
        .unwrap();
    assert_eq!(preview["kind"], "contact");
    assert_eq!(preview["id"], json!(card.id()));
    assert_eq!(preview["name"], "Zoë 🦊");
    assert_eq!(
        recipient
            .operate(json!({"op": "contact_preview", "link": legacy}))
            .await
            .unwrap(),
        preview
    );
    assert_eq!(
        recipient
            .operate(json!({"op": "invitation_preview", "link": link}))
            .await
            .unwrap(),
        preview,
        "opening My code outside a chat must offer contact review, not chat admission"
    );
    for (trusted, confirmed) in [(false, preview["id"].clone()), (true, json!("wrong"))] {
        assert!(
            recipient
                .operate(json!({
                    "op": "contact_add", "link": link,
                    "trusted": trusted, "confirmed_contact": confirmed,
                }))
                .await
                .is_err()
        );
        assert!(
            recipient.view().await.unwrap()["contacts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    for accepted in [link, legacy.as_str()] {
        recipient
            .operate(json!({
                "op": "contact_add", "link": accepted,
                "trusted": true, "confirmed_contact": preview["id"],
            }))
            .await
            .unwrap();
    }
    let saved = recipient.view().await.unwrap();
    assert_eq!(saved["contacts"].as_array().unwrap().len(), 1);
    assert_eq!(saved["contacts"][0]["name"], "Zoë 🦊");
    assert_eq!(saved["contacts"][0]["id"], preview["identity"]);
    assert_eq!(saved["streams"].as_array().unwrap().len(), 1);
    assert_eq!(saved["streams"][0]["members"].as_array().unwrap().len(), 1);
    recipient.close().await.unwrap();
    person.close().await.unwrap();
}

//! A device proves its stable identity without revealing message plaintext.
//! Self-certification identifies a sender; it never grants Space membership.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    v: u8,
    kind: String,
    route: String,
    event: String,
    scope: String,
    target_hash: String,
    expires: u64,
}
pub fn sender_tag(route: &str, identity: IdentityId) -> String {
    let mut hash = Sha256::new();
    hash.update(b"elo.now/wake-sender/v1\0");
    hash.update(route.as_bytes());
    hash.update(identity.as_bytes());
    record::encode_hex(&hash.finalize())
}
pub fn verify(route: &str, request: &Value, time: u64) -> Result<String> {
    Ok(sender_tag(route, verify_identity(route, request, time)?))
}
pub fn verify_identity(route: &str, request: &Value, time: u64) -> Result<IdentityId> {
    let auth = &request["sender"];
    let decode = |field_name: &str| -> Result<Vec<u8>> {
        let encoded = field(auth, field_name)?;
        if encoded.len() > 4096 {
            return Err("Invalid notification sender.".into());
        }
        Ok(URL_SAFE_NO_PAD.decode(encoded)?)
    };
    let credential_bytes = decode("credential")?;
    let raw = SignedRecord::parse(&credential_bytes)?;
    // The root is not an authority anchor: its hash IS the sender identity.
    let credential = VerifiedCredential::verify(
        &credential_bytes,
        &root_key(field(raw.body(), "root_public_key")?)?,
    )?;
    let signed = SignedRecord::parse(&decode("proof")?)?;
    signed.verify_signature(credential.key())?;
    let body: Proof = signed.decode()?;
    if body.v != 1
        || body.kind != "notification.sender"
        || body.route != route
        || body.event != field(request, "event")?
        || body.scope != field(request, "scope")?
        || body.target_hash
            != record::encode_hex(&Sha256::digest(field(request, "target")?.as_bytes()))
        || body.expires < time
        || body.expires > time.saturating_add(120)
    {
        return Err("Invalid notification sender.".into());
    }
    Ok(credential.identity())
}
pub fn sign(session: &Session, route: &str, request: &mut Value) -> Result<()> {
    let proof = Proof {
        v: 1,
        kind: "notification.sender".into(),
        route: route.into(),
        event: field(request, "event")?.into(),
        scope: field(request, "scope")?.into(),
        target_hash: record::encode_hex(&Sha256::digest(field(request, "target")?.as_bytes())),
        expires: now()?.as_millis() as u64 / 1000 + 120,
    };
    let signed = SignedRecord::sign(&serde_json::to_vec(&proof)?, session.signing_key())?;
    request["sender"] = json!({"credential":URL_SAFE_NO_PAD.encode(session.credential().record().bytes()),"proof":URL_SAFE_NO_PAD.encode(signed.bytes())});
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sender_proof_binds_identity_route_target_and_expiry() {
        let (session, card) = Session::create().unwrap();
        let route = "a".repeat(32);
        let mut body =
            json!({"event":"b".repeat(64),"scope":"c".repeat(64),"target":"encrypted-only"});
        sign(&session, &route, &mut body).unwrap();
        let time = now().unwrap().as_millis() as u64 / 1000;
        let tag = verify(&route, &body, time).unwrap();
        assert_eq!(tag, sender_tag(&route, session.identity_id()));
        assert!(verify(&"d".repeat(32), &body, time).is_err());
        for field in ["event", "scope", "target"] {
            let mut forged = body.clone();
            forged[field] = json!("changed");
            assert!(verify(&route, &forged, time).is_err());
        }
        assert!(verify(&route, &body, time + 121).is_err());
        let other = Session::create().unwrap().0;
        let mut forged = body.clone();
        forged["sender"]["credential"] =
            json!(URL_SAFE_NO_PAD.encode(other.credential().record().bytes()));
        assert!(verify(&route, &forged, time).is_err());
        // Recovering the same identity with a new device cannot evade its block.
        let recovered = Session::recover(&card, session.identity_id()).unwrap();
        sign(&recovered, &route, &mut body).unwrap();
        assert_eq!(verify(&route, &body, time).unwrap(), tag);
    }
}

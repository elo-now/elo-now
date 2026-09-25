//! An App Attest assertion binds the native PushKit token to a proved route.
//! No verification push is sent: PushKit is reserved for actual incoming calls.
use super::*;
use base64::engine::general_purpose::STANDARD;
const ROOT: &[u8] = include_bytes!("Apple_App_Attestation_Root_CA.pem");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Token {
    token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    token: String,
    nonce: String,
    key_id: String,
    enrollment_nonce: String,
    attestation: String,
    assertion: String,
}

pub(super) fn schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS voip_challenges(route TEXT PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE, token TEXT NOT NULL, nonce TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS voip_keys(id TEXT PRIMARY KEY, identity TEXT NOT NULL, public_key BLOB NOT NULL, counter INTEGER NOT NULL, updated INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS voip_key_identity ON voip_keys(identity);
        CREATE TABLE IF NOT EXISTS voip_bindings(route TEXT PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE, token TEXT NOT NULL, key_id TEXT NOT NULL REFERENCES voip_keys(id));")
}
fn valid_token(token: &str) -> bool {
    (32..=512).contains(&token.len())
        && token.len() % 2 == 0
        && token
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub(super) fn verified(db: &Connection, route: &str, token: &str) -> Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM voip_bindings WHERE route=? AND token=?)",
        params![route, token],
        |r| r.get(0),
    )
    .map_err(db_error)
}
fn owner(db: &Connection, route: &str, headers: &HeaderMap, time: i64) -> Result<String> {
    let saved = row(db, route)?.ok_or(StatusCode::NOT_FOUND)?;
    if !saved.active || saved.expires <= time || !matches(&saved.owner, &auth(headers)?) {
        return Err(StatusCode::FORBIDDEN);
    }
    db.query_row(
        "SELECT identity FROM route_accounts WHERE route=?",
        [route],
        |r| r.get(0),
    )
    .map_err(|_| StatusCode::FORBIDDEN)
}
pub(super) async fn challenge(
    State(relay): State<Arc<Relay>>,
    Path(route): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Token>,
) -> Result<Json<Value>> {
    if !valid_token(&input.token) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if relay.apns.is_none() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let time = now()?;
    let mut db = relay.database()?;
    let identity = owner(&db, &route, &headers, time)?;
    let tx = db.transaction().map_err(db_error)?;
    tx.execute("DELETE FROM voip_keys WHERE updated<? AND NOT EXISTS(SELECT 1 FROM voip_bindings b WHERE b.key_id=voip_keys.id)", [time-90*86400]).map_err(db_error)?;
    if verified(&tx, &route, &input.token)? {
        tx.commit().map_err(db_error)?;
        return Ok(Json(json!({"verified":true})));
    }
    let previous: Option<(String, String, i64, i64)> = tx
        .query_row(
            "SELECT token,nonce,created,expires FROM voip_challenges WHERE route=?",
            [&route],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(db_error)?;
    if let Some((token, nonce, created, expires)) = previous {
        if created <= time && expires > time && token == input.token {
            tx.commit().map_err(db_error)?;
            return Ok(Json(json!({"nonce":nonce,"identity":identity})));
        }
        if time < created + 30 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let nonce = elo_core::record::encode_hex(&random);
    tx.execute("INSERT INTO voip_challenges VALUES(?,?,?,?,?) ON CONFLICT(route) DO UPDATE SET token=excluded.token,nonce=excluded.nonce,created=excluded.created,expires=excluded.expires",
        params![route,input.token,nonce,time,time+120]).map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(json!({"nonce":nonce,"identity":identity})))
}
fn enrollment(identity: &str, nonce: &str) -> String {
    format!("elo.now/voip-key/v1\n{identity}\n{nonce}")
}
fn binding(endpoint: &str, route: &str, identity: &str, proof: &Proof) -> String {
    format!(
        "elo.now/voip-ownership/v1\n{}\n{route}\n{identity}\n{}\n{}\n{}",
        endpoint.trim_end_matches('/'),
        proof.key_id,
        proof.token,
        proof.nonce
    )
}
// Parse the authenticated fields strictly before delegating certificate/signature
// verification. Reject duplicate keys, trailing bytes and indefinite containers.
fn assertion_counter(bytes: &[u8]) -> Result<u32> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let invalid = |_| StatusCode::BAD_REQUEST;
    if decoder.map().map_err(invalid)? != Some(2) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut auth = None;
    let mut signature = false;
    for _ in 0..2 {
        match decoder.str().map_err(invalid)? {
            "authenticatorData" if auth.is_none() => {
                auth = Some(decoder.bytes().map_err(invalid)?);
            }
            "signature" if !signature => {
                if !(64..=80).contains(&decoder.bytes().map_err(invalid)?.len()) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                signature = true;
            }
            _ => return Err(StatusCode::BAD_REQUEST),
        }
    }
    let auth = auth.ok_or(StatusCode::BAD_REQUEST)?;
    if !signature || auth.len() != 37 || decoder.position() != bytes.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(u32::from_be_bytes(
        auth[33..37]
            .try_into()
            .map_err(|_| StatusCode::BAD_REQUEST)?,
    ))
}
fn production_attestation(bytes: &[u8]) -> Result<()> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let invalid = |_| StatusCode::BAD_REQUEST;
    if decoder.map().map_err(invalid)? != Some(3) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..3 {
        let key = decoder.str().map_err(invalid)?;
        if !seen.insert(key) {
            return Err(StatusCode::BAD_REQUEST);
        }
        match key {
            "fmt" if decoder.str().map_err(invalid)? == "apple-appattest" => {}
            "authData" => {
                let auth = decoder.bytes().map_err(invalid)?;
                if auth.len() < 87 || &auth[37..53] != b"appattest\0\0\0\0\0\0\0" {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
            "attStmt" => {
                if decoder.map().map_err(invalid)? != Some(2) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let mut fields = std::collections::BTreeSet::new();
                for _ in 0..2 {
                    let field = decoder.str().map_err(invalid)?;
                    if !fields.insert(field) {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    match field {
                        "receipt" => {
                            decoder.bytes().map_err(invalid)?;
                        }
                        "x5c" => {
                            let count = decoder
                                .array()
                                .map_err(invalid)?
                                .ok_or(StatusCode::BAD_REQUEST)?;
                            if !(2..=3).contains(&count) {
                                return Err(StatusCode::BAD_REQUEST);
                            }
                            for _ in 0..count {
                                decoder.bytes().map_err(invalid)?;
                            }
                        }
                        _ => return Err(StatusCode::BAD_REQUEST),
                    }
                }
            }
            _ => return Err(StatusCode::BAD_REQUEST),
        }
    }
    if decoder.position() != bytes.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}
fn verify_attestation(proof: &Proof, identity: &str, app_id: &str, root: &[u8]) -> Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(&proof.attestation)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    production_attestation(&bytes)?;
    let (key, _) = appattest::attestation::Attestation::from_cbor_bytes(&bytes)
        .and_then(|a| {
            a.verify(
                &enrollment(identity, &proof.enrollment_nonce),
                app_id,
                &proof.key_id,
                root,
            )
        })
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(key.to_vec())
}
fn verify_assertion(
    proof: &Proof,
    payload: &str,
    app_id: &str,
    key: &[u8],
    previous: u32,
) -> Result<u32> {
    let bytes = STANDARD
        .decode(&proof.assertion)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let counter = assertion_counter(&bytes)?;
    appattest::assertion::Assertion::from_assertion(&bytes)
        .and_then(|a| {
            a.verify(
                Sha256::digest(payload.as_bytes()),
                &proof.nonce,
                app_id,
                key,
                previous,
                &proof.nonce,
            )
        })
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(counter)
}
pub(super) async fn prove(
    State(relay): State<Arc<Relay>>,
    Path(route): Path<String>,
    headers: HeaderMap,
    Json(proof): Json<Proof>,
) -> Result<StatusCode> {
    if !valid_token(&proof.token)
        || !hex(&proof.nonce, 32)
        || !hex(&proof.enrollment_nonce, 32)
        || proof.key_id.len() != 44
        || proof.attestation.len() > 24 * 1024
        || proof.assertion.len() > 1024
        || STANDARD
            .decode(&proof.key_id)
            .map_or(true, |b| b.len() != 32)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Bounded native cryptographic work; no server lock is held while verifying.
    let _permit = relay
        .registrations
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let time = now()?;
    let app_id = relay
        .apns
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .app_id();
    let (identity, known) = {
        let db = relay.database()?;
        let identity = owner(&db, &route, &headers, time)?;
        check_challenge(&db, &route, &proof, time)?;
        let known: Option<(String, Vec<u8>, u32)> = db
            .query_row(
                "SELECT identity,public_key,counter FROM voip_keys WHERE id=?",
                [&proof.key_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db_error)?;
        (identity, known)
    };
    let (key, previous) = if let Some((saved, key, counter)) = known {
        if saved != identity {
            return Err(StatusCode::FORBIDDEN);
        }
        (key, counter)
    } else {
        (verify_attestation(&proof, &identity, &app_id, ROOT)?, 0)
    };
    let counter = verify_assertion(
        &proof,
        &binding(&relay.endpoint, &route, &identity, &proof),
        &app_id,
        &key,
        previous,
    )?;
    let mut db = relay.database()?;
    let tx = db.transaction().map_err(db_error)?;
    if owner(&tx, &route, &headers, now()?)? != identity {
        return Err(StatusCode::FORBIDDEN);
    }
    check_challenge(&tx, &route, &proof, now()?)?;
    let count: i64 = tx
        .query_row(
            "SELECT count(*) FROM voip_keys WHERE identity=?",
            [&identity],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    let total: i64 = tx
        .query_row("SELECT count(*) FROM voip_keys", [], |r| r.get(0))
        .map_err(db_error)?;
    if previous == 0 && (count >= 32 || total >= 20000) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let changed = tx.execute("INSERT INTO voip_keys VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET counter=excluded.counter,updated=excluded.updated WHERE voip_keys.identity=excluded.identity AND voip_keys.counter<?6",
        params![proof.key_id,identity,key,counter,time,counter]).map_err(db_error)?;
    if changed != 1 {
        return Err(StatusCode::CONFLICT);
    }
    tx.execute("INSERT INTO voip_bindings VALUES(?,?,?) ON CONFLICT(route) DO UPDATE SET token=excluded.token,key_id=excluded.key_id", params![route,proof.token,proof.key_id]).map_err(db_error)?;
    tx.execute("DELETE FROM voip_challenges WHERE route=?", [&route])
        .map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}
fn check_challenge(db: &Connection, route: &str, proof: &Proof, time: i64) -> Result<()> {
    let valid: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM voip_challenges WHERE route=? AND token=? AND nonce=? AND created<=? AND expires>?)",
        params![route,proof.token,proof.nonce,time,time], |r|r.get(0)).map_err(db_error)?;
    if !valid {
        return Err(StatusCode::CONFLICT);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const APP: &str = "SYNTHETIC1.now.elo";
    fn proof() -> (Proof, Vec<u8>, appattest::testing::TestAttestation) {
        let nonce = "a".repeat(64);
        let enrollment_nonce = "b".repeat(64);
        let test = appattest::testing::build_test_attestation(
            &enrollment(&"c".repeat(64), &enrollment_nonce),
            APP,
        );
        let mut proof = Proof {
            token: "d".repeat(64),
            nonce,
            key_id: test.key_id.clone(),
            enrollment_nonce,
            attestation: STANDARD.encode(&test.cbor),
            assertion: String::new(),
        };
        let key = verify_attestation(
            &proof,
            &"c".repeat(64),
            APP,
            appattest::testing::TEST_ROOT_CA_CERT_PEM,
        )
        .unwrap();
        proof.assertion = STANDARD.encode(appattest::testing::build_test_assertion(
            APP,
            Sha256::digest(
                binding(
                    "https://example.test/",
                    &"e".repeat(32),
                    &"c".repeat(64),
                    &proof,
                )
                .as_bytes(),
            ),
            0,
            &test.device_key,
        ));
        (proof, key, test)
    }
    #[test]
    fn native_token_proof_binds_account_route_server_token_and_fresh_nonce() {
        let (mut proof, key, _) = proof();
        let payload = binding(
            "https://example.test/",
            &"e".repeat(32),
            &"c".repeat(64),
            &proof,
        );
        assert_eq!(verify_assertion(&proof, &payload, APP, &key, 0).unwrap(), 1);
        assert!(verify_assertion(&proof, &payload, APP, &key, 1).is_err());
        assert!(verify_assertion(&proof, &payload, "OTHER.now.elo", &key, 0).is_err());
        for changed in [
            payload.replace("example.test", "other.test"),
            payload.replace(&"e".repeat(32), &"f".repeat(32)),
            payload.replace(&"c".repeat(64), &"f".repeat(64)),
            payload.replace(&"d".repeat(64), &"f".repeat(64)),
            payload.replace(&"a".repeat(64), &"f".repeat(64)),
        ] {
            assert!(verify_assertion(&proof, &changed, APP, &key, 0).is_err());
        }
        let mut assertion = STANDARD.decode(&proof.assertion).unwrap();
        assertion.push(0);
        proof.assertion = STANDARD.encode(assertion);
        assert!(verify_assertion(&proof, &payload, APP, &key, 0).is_err());
    }
    #[test]
    fn a_non_apple_or_wrong_account_attestation_cannot_enroll() {
        let (proof, _, _) = proof();
        assert!(verify_attestation(&proof, &"c".repeat(64), APP, ROOT).is_err());
        assert!(
            verify_attestation(
                &proof,
                &"f".repeat(64),
                APP,
                appattest::testing::TEST_ROOT_CA_CERT_PEM
            )
            .is_err()
        );
        assert!(
            verify_attestation(
                &proof,
                &"c".repeat(64),
                "OTHER.now.elo",
                appattest::testing::TEST_ROOT_CA_CERT_PEM
            )
            .is_err()
        );
        let mut bytes = STANDARD.decode(&proof.attestation).unwrap();
        bytes.push(0);
        assert!(production_attestation(&bytes).is_err());
        let mut bytes = STANDARD.decode(&proof.attestation).unwrap();
        let offset = bytes
            .windows(16)
            .position(|v| v == b"appattest\0\0\0\0\0\0\0")
            .unwrap();
        bytes[offset..offset + 16].copy_from_slice(b"appattestdevelop");
        assert!(production_attestation(&bytes).is_err());
    }
    #[test]
    fn token_challenge_expires_and_is_bound_to_its_original_route() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE routes(id TEXT PRIMARY KEY); INSERT INTO routes VALUES('route');",
        )
        .unwrap();
        schema(&db).unwrap();
        let (proof, _, _) = proof();
        db.execute(
            "INSERT INTO voip_challenges VALUES('route',?,?,100,220)",
            params![proof.token, proof.nonce],
        )
        .unwrap();
        assert!(check_challenge(&db, "route", &proof, 120).is_ok());
        assert!(check_challenge(&db, "other", &proof, 120).is_err());
        assert!(check_challenge(&db, "route", &proof, 99).is_err());
        assert!(check_challenge(&db, "route", &proof, 220).is_err());
        db.execute("DELETE FROM voip_challenges WHERE route='route'", [])
            .unwrap();
        assert!(check_challenge(&db, "route", &proof, 120).is_err());
        assert!(!verified(&db, "route", &proof.token).unwrap());
    }
}

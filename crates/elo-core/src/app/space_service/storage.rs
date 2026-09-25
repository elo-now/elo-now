//! Atomic, individually encrypted state rows. Growth in one collection must not
//! exhaust the old 8 MiB envelope shared by every administrative operation.
use super::*;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

const MAPS: &[&str] = &[
    "offers",
    "applicants",
    "replies",
    "removals",
    "attachments",
    "attachment_access",
    "call_heads",
];
const MAX_ROWS: usize = 32_768;
type Rows = BTreeMap<(String, String), Vec<u8>>;

fn connection(path: &Path) -> Result<Connection> {
    use std::fs::OpenOptions;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("Unsafe Space state path.".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("Space state must be private.".into());
            }
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?;
    let db = Connection::open(path)?;
    db.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
        PRAGMA secure_delete=ON; PRAGMA max_page_count=65536;
        CREATE TABLE IF NOT EXISTS state (
            bucket TEXT NOT NULL, item TEXT NOT NULL, ciphertext BLOB NOT NULL,
            PRIMARY KEY(bucket,item)) WITHOUT ROWID;",
    )?;
    Ok(db)
}

fn cipher(app: &ClientApp) -> XChaCha20Poly1305 {
    let secret = Zeroizing::new(app.session.signing_key().to_bytes());
    let mut kdf = <Hmac<Sha256> as Mac>::new_from_slice(&*secret).expect("HMAC key");
    kdf.update(b"elo.space-service.storage.v1");
    let key = Zeroizing::new(<[u8; 32]>::from(kdf.finalize().into_bytes()));
    XChaCha20Poly1305::new_from_slice(&*key).expect("storage key")
}

fn crypt(
    cipher: &XChaCha20Poly1305,
    key: &(String, String),
    bytes: &[u8],
    seal: bool,
) -> Result<Vec<u8>> {
    let aad = serde_json::to_vec(key)?;
    if seal {
        if bytes.len() > LIMIT {
            return Err("Space state entry is too large.".into());
        }
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let mut output = nonce.to_vec();
        output.extend(
            cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: bytes,
                        aad: &aad,
                    },
                )
                .map_err(|_| "Cannot encrypt Space state.")?,
        );
        Ok(output)
    } else {
        if !(40..=LIMIT + 40).contains(&bytes.len()) {
            return Err("Invalid Space state entry.".into());
        }
        cipher
            .decrypt(
                XNonce::from_slice(&bytes[..24]),
                Payload {
                    msg: &bytes[24..],
                    aad: &aad,
                },
            )
            .map_err(|_| "Space state integrity check failed.".into())
    }
}

fn rows(db: &Connection, cipher: &XChaCha20Poly1305) -> Result<Rows> {
    let mut stmt = db.prepare("SELECT bucket,item,ciphertext FROM state")?;
    let mut query = stmt.query([])?;
    let mut result = Rows::new();
    while let Some(row) = query.next()? {
        if result.len() > MAX_ROWS {
            return Err("Too many Space state entries.".into());
        }
        let key = (row.get::<_, String>(0)?, row.get::<_, String>(1)?);
        let data: Vec<u8> = row.get(2)?;
        if key.0.len() > 64 || key.1.len() > 256 || data.len() > LIMIT + 40 {
            return Err("Invalid Space state entry.".into());
        }
        result.insert(key, data);
    }
    // Authentication of each row alone would not detect deletion of a revocation.
    let key = ("manifest".into(), String::new());
    let sealed = result.remove(&key).ok_or("Missing Space state manifest.")?;
    let expected: Vec<((String, String), String)> =
        serde_json::from_slice(&Zeroizing::new(crypt(cipher, &key, &sealed, false)?))?;
    if expected != manifest(&result) {
        return Err("Space state integrity check failed.".into());
    }
    Ok(result)
}

fn manifest(rows: &Rows) -> Vec<((String, String), String)> {
    rows.iter()
        .map(|(key, value)| (key.clone(), record::encode_hex(&Sha256::digest(value))))
        .collect()
}

pub(super) fn load(app: &ClientApp) -> Result<ServiceState> {
    let path = app.directory.join("space-service.sqlite");
    if !path.try_exists()? {
        let old = app.directory.join("space-service.age");
        return if old.try_exists()? {
            Ok(serde_json::from_slice(&Zeroizing::new(
                crypto::open_bytes(
                    &vault::read_private(&old)?,
                    app.session.age_identity(),
                    LIMIT,
                )?,
            ))?)
        } else {
            Ok(ServiceState::default())
        };
    }
    let db = connection(&path)?;
    let cipher = cipher(app);
    let mut value = serde_json::to_value(ServiceState::default())?;
    for (key, bytes) in rows(&db, &cipher)? {
        let decoded: Value =
            serde_json::from_slice(&Zeroizing::new(crypt(&cipher, &key, &bytes, false)?))?;
        if MAPS.contains(&key.0.as_str()) {
            value[&key.0]
                .as_object_mut()
                .ok_or("Invalid Space state bucket.")?
                .insert(key.1, decoded);
        } else if key.0 == "scalar" {
            value.as_object_mut().unwrap().insert(key.1, decoded);
        } else {
            return Err("Invalid Space state bucket.".into());
        }
    }
    Ok(serde_json::from_value(value)?)
}

pub(super) fn save(app: &ClientApp, state: &ServiceState) -> Result<()> {
    let path = app.directory.join("space-service.sqlite");
    let existed = path.try_exists()?;
    let initial = app.directory.join(".space-service.sqlite.new");
    if !existed && initial.try_exists()? {
        std::fs::remove_file(&initial)?;
    }
    let mut db = connection(if existed { &path } else { &initial })?;
    let cipher = cipher(app);
    let mut old = if existed {
        rows(&db, &cipher)?
    } else {
        Rows::new()
    };
    let Value::Object(fields) = serde_json::to_value(state)? else {
        unreachable!()
    };
    let mut plain = BTreeMap::new();
    for (bucket, value) in fields {
        if MAPS.contains(&bucket.as_str()) {
            let Value::Object(items) = value else {
                return Err("Invalid Space state map.".into());
            };
            for (item, value) in items {
                plain.insert((bucket.clone(), item), value);
            }
        } else {
            plain.insert(("scalar".into(), bucket), value);
        }
    }
    if plain.len() > MAX_ROWS {
        return Err("Space state capacity reached.".into());
    }
    let tx = db.transaction()?;
    let mut next = Rows::new();
    for (key, value) in plain {
        let bytes = Zeroizing::new(serde_json::to_vec(&value)?);
        let prior = old.remove(&key);
        let sealed = if let Some(prior) = prior.as_ref()
            && Zeroizing::new(crypt(&cipher, &key, prior, false)?).as_slice() == bytes.as_slice()
        {
            prior.clone()
        } else {
            let sealed = crypt(&cipher, &key, &bytes, true)?;
            tx.execute(
                "INSERT OR REPLACE INTO state VALUES (?1,?2,?3)",
                params![key.0, key.1, sealed],
            )?;
            sealed
        };
        next.insert(key, sealed);
    }
    for key in old.keys() {
        tx.execute(
            "DELETE FROM state WHERE bucket=?1 AND item=?2",
            params![key.0, key.1],
        )?;
    }
    let sealed = crypt(
        &cipher,
        &("manifest".into(), String::new()),
        &serde_json::to_vec(&manifest(&next))?,
        true,
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO state VALUES ('manifest','',?1)",
        [sealed],
    )?;
    tx.commit()?;
    drop(db);
    if !existed {
        std::fs::rename(&initial, &path)?;
        std::fs::File::open(&app.directory)?.sync_all()?;
    }
    let old = app.directory.join("space-service.age");
    if old.try_exists()? {
        std::fs::remove_file(old)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn large_state_survives_restart_and_only_changed_rows_are_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let app = ProfileDraft::new()
            .unwrap()
            .save_named(
                tmp.path().join("profile"),
                "test password".into(),
                "General",
                "Host",
            )
            .await
            .unwrap();
        let mut state = ServiceState::default();
        for index in 0..40 {
            state.replies.insert(
                index.to_string(),
                (1, "record".into(), json!("x".repeat(256 * 1024))),
            );
        }
        assert!(serde_json::to_vec(&state).unwrap().len() > LIMIT);
        save(&app, &state).unwrap();
        let path = app.directory.join("space-service.sqlite");
        let before = rows(&connection(&path).unwrap(), &cipher(&app)).unwrap();
        state.replies.remove("0");
        state.removals.insert(app.identity_id(), 1);
        save(&app, &state).unwrap();
        let after = rows(&connection(&path).unwrap(), &cipher(&app)).unwrap();
        assert_eq!(
            before[&("replies".into(), "1".into())],
            after[&("replies".into(), "1".into())]
        );
        assert!(!after.contains_key(&("replies".into(), "0".into())));
        let dir = app.directory.clone();
        app.close().await.unwrap();
        let app = ClientApp::open(dir, "test password".into(), false)
            .await
            .unwrap();
        assert_eq!(load(&app).unwrap().replies.len(), 39);
        // A failed write must not replace a committed revocation or destroy reads.
        state.replies.insert(
            "oversized".into(),
            (1, "record".into(), json!("x".repeat(LIMIT + 1))),
        );
        assert!(save(&app, &state).is_err());
        assert_eq!(load(&app).unwrap().removals[&app.identity_id()], 1);
        assert_eq!(load(&app).unwrap().replies.len(), 39);
        connection(&path)
            .unwrap()
            .execute("DELETE FROM state WHERE bucket='removals'", [])
            .unwrap();
        assert!(
            load(&app).is_err(),
            "removing a row must invalidate the manifest"
        );
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn legacy_state_is_imported_once_without_leaving_plaintext_or_old_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let app = ProfileDraft::new()
            .unwrap()
            .save_named(
                tmp.path().join("profile"),
                "test password".into(),
                "General",
                "Host",
            )
            .await
            .unwrap();
        let mut state = ServiceState::default();
        state.replies.insert(
            "example".into(),
            (1, "id".into(), json!("private-state-marker")),
        );
        let old = app.directory.join("space-service.age");
        vault::write_private(
            &old,
            &crypto::seal_bytes(
                &serde_json::to_vec(&state).unwrap(),
                &[app.session.age_identity().to_public()],
                LIMIT,
            )
            .unwrap(),
            false,
        )
        .unwrap();
        save(&app, &load(&app).unwrap()).unwrap();
        assert!(!old.exists());
        let bytes = std::fs::read(app.directory.join("space-service.sqlite")).unwrap();
        assert!(
            !bytes
                .windows(20)
                .any(|window| window == b"private-state-marker")
        );
        assert_eq!(load(&app).unwrap().replies.len(), 1);
        app.close().await.unwrap();
    }
}

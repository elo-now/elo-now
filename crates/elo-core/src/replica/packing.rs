//! Physical interning of the already-public credential in verified owner proofs.
//! Never rewrites signed bytes or touches the encrypted age payload.
use super::*;
use base64::engine::general_purpose::STANDARD;

pub(super) fn insert(
    tx: &rusqlite::Transaction<'_>,
    id: ObjectId,
    bytes: &[u8],
    content: Option<&crate::erasure::Content<'_>>,
    time: u64,
) -> Result<()> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM objects WHERE object_id=?1)",
        [id.to_string()],
        |r| r.get(0),
    )?;
    if exists {
        // The caller compares reconstructed bytes before adding a delivery.
        return Ok(());
    }
    let packed = content.and_then(|content| {
        let encoded = STANDARD.encode(content.credential.record().bytes());
        // Only the canonical literal public field can be interned. Other valid
        // JSON encodings fall back to storing the full original object.
        let field = format!("\"credential\":\"{encoded}\"");
        let proof = &bytes[..bytes.len() - content.ciphertext.len()];
        let offset = proof
            .windows(field.len())
            .position(|part| part == field.as_bytes())?
            + b"\"credential\":\"".len();
        Some((content.credential.id(), encoded.into_bytes(), offset))
    });
    if let Some((credential, encoded, offset)) = packed {
        let key = credential.as_bytes().as_slice();
        tx.execute(
            "INSERT OR IGNORE INTO object_credentials VALUES(?1,?2)",
            params![key, encoded],
        )?;
        let stored: Vec<u8> = tx.query_row(
            "SELECT encoded FROM object_credentials WHERE credential_id=?1",
            [key],
            |r| r.get(0),
        )?;
        if stored != encoded {
            return Err(ReplicaError::Conflict);
        }
        let mut compact = Vec::with_capacity(bytes.len() - encoded.len());
        compact.extend_from_slice(&bytes[..offset]);
        compact.extend_from_slice(&bytes[offset + encoded.len()..]);
        tx.execute("INSERT INTO objects(object_id,ciphertext,size_bytes,stored_local_ms,credential_id,credential_offset,wire_size_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(object_id) DO NOTHING",
            params![id.to_string(),compact,compact.len() as i64,time as i64,key,offset as i64,bytes.len() as i64])?;
    } else {
        tx.execute("INSERT INTO objects(object_id,ciphertext,size_bytes,stored_local_ms) VALUES(?1,?2,?3,?4) ON CONFLICT(object_id) DO NOTHING",
            params![id.to_string(),bytes,bytes.len() as i64,time as i64])?;
    }
    Ok(())
}

pub(super) fn load(c: &Connection, id: ObjectId) -> Result<Vec<u8>> {
    let (mut bytes, offset, credential, expected): (Vec<u8>, Option<i64>, Option<Vec<u8>>, i64) = c.query_row(
        "SELECT o.ciphertext,o.credential_offset,c.encoded,COALESCE(o.wire_size_bytes,o.size_bytes) FROM objects o LEFT JOIN object_credentials c USING(credential_id) WHERE object_id=?1",
        [id.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))
        .optional()?.ok_or(ReplicaError::NotFound)?;
    match (offset, credential) {
        (Some(offset), Some(credential))
            if offset >= 0
                && offset as usize <= bytes.len()
                && bytes.len() + credential.len() <= MAX_CIPHERTEXT =>
        {
            bytes.splice(offset as usize..offset as usize, credential);
        }
        (None, None) => {}
        _ => return Err(ReplicaError::Storage),
    }
    if bytes.len() as i64 != expected || ObjectId::of_ciphertext(&bytes) != id {
        return Err(ReplicaError::Storage);
    }
    Ok(bytes)
}

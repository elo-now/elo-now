use super::model::{ATTACHMENT_CHUNK_BYTES, MAX_ATTACHMENT_FILE_SIZE};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ELOATT01";
const HEADER_BYTES: u64 = 8 + 8 + 4;
const TAG_BYTES: u64 = 16;

#[derive(Clone, Debug)]
pub struct EncryptionPlan {
    pub key: Zeroizing<[u8; 32]>,
    pub nonce_prefix: [u8; 16],
    pub plaintext_size: u64,
}

#[derive(Clone, Debug)]
pub struct EncryptionResult {
    pub encrypted_size: u64,
    pub ciphertext_sha256: String,
}

pub fn encrypted_size(plaintext_size: u64) -> u64 {
    let chunks = plaintext_size.div_ceil(u64::from(ATTACHMENT_CHUNK_BYTES));
    HEADER_BYTES + plaintext_size + chunks * (4 + TAG_BYTES)
}

pub fn plan(plaintext_size: u64) -> Result<EncryptionPlan, &'static str> {
    if plaintext_size > MAX_ATTACHMENT_FILE_SIZE {
        return Err("Attachment files cannot exceed 5 MB.");
    }
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce_prefix = [0u8; 16];
    getrandom::fill(key.as_mut()).map_err(|_| "Could not create an attachment key.")?;
    getrandom::fill(&mut nonce_prefix).map_err(|_| "Could not create an attachment nonce.")?;
    Ok(EncryptionPlan {
        key,
        nonce_prefix,
        plaintext_size,
    })
}

fn nonce(prefix: &[u8; 16], index: u64) -> XNonce {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&index.to_be_bytes());
    nonce.into()
}

fn aad(index: u64, plaintext_size: u64) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&index.to_be_bytes());
    value[8..].copy_from_slice(&plaintext_size.to_be_bytes());
    value
}

pub fn encrypt_file(
    input: &Path,
    output: &Path,
    plan: &EncryptionPlan,
    mut progress: impl FnMut(u64),
) -> Result<EncryptionResult, Box<dyn std::error::Error + Send + Sync>> {
    let metadata = std::fs::symlink_metadata(input)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != plan.plaintext_size
        || metadata.len() > MAX_ATTACHMENT_FILE_SIZE
    {
        return Err("The selected attachment changed or is too large.".into());
    }
    let mut reader = File::open(input)?;
    let mut writer = File::create_new(output)?;
    let mut hasher = Sha256::new();
    let mut write_hashed = |bytes: &[u8]| -> std::io::Result<()> {
        writer.write_all(bytes)?;
        hasher.update(bytes);
        Ok(())
    };
    write_hashed(MAGIC)?;
    write_hashed(&plan.plaintext_size.to_be_bytes())?;
    write_hashed(&ATTACHMENT_CHUNK_BYTES.to_be_bytes())?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*plan.key)
        .map_err(|_| "Could not initialize attachment encryption.")?;
    let mut buffer = Zeroizing::new(vec![0u8; ATTACHMENT_CHUNK_BYTES as usize]);
    let mut done = 0u64;
    let mut index = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let mut encrypted = cipher
            .encrypt(
                &nonce(&plan.nonce_prefix, index),
                Payload {
                    msg: &buffer[..read],
                    aad: &aad(index, plan.plaintext_size),
                },
            )
            .map_err(|_| "Could not encrypt the attachment.")?;
        let length = u32::try_from(encrypted.len())?;
        write_hashed(&length.to_be_bytes())?;
        write_hashed(&encrypted)?;
        encrypted.zeroize();
        done += u64::try_from(read)?;
        progress(done);
        index += 1;
    }
    writer.sync_all()?;
    if done != plan.plaintext_size {
        return Err("The selected attachment changed while it was encrypted.".into());
    }
    Ok(EncryptionResult {
        encrypted_size: encrypted_size(plan.plaintext_size),
        ciphertext_sha256: crate::record::encode_hex(&hasher.finalize()),
    })
}

pub fn decrypt_file(
    input: &Path,
    output: &Path,
    key_b64: &str,
    nonce_prefix_b64: &str,
    expected_plaintext: u64,
    expected_ciphertext_hash: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut key = Zeroizing::new([0u8; 32]);
    let decoded = Zeroizing::new(STANDARD.decode(key_b64)?);
    let key_bytes: &[u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid attachment key.")?;
    key.copy_from_slice(key_bytes);
    let prefix: [u8; 16] = STANDARD
        .decode(nonce_prefix_b64)?
        .try_into()
        .map_err(|_| "Invalid attachment nonce.")?;
    let mut reader = File::open(input)?;
    let mut writer = File::create_new(output)?;
    let mut hasher = Sha256::new();
    let mut header = [0u8; HEADER_BYTES as usize];
    reader.read_exact(&mut header)?;
    hasher.update(header);
    if &header[..8] != MAGIC
        || u64::from_be_bytes(header[8..16].try_into()?) != expected_plaintext
        || u32::from_be_bytes(header[16..20].try_into()?) != ATTACHMENT_CHUNK_BYTES
    {
        return Err("Invalid attachment container.".into());
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| "Invalid attachment key.")?;
    let mut done = 0u64;
    let mut index = 0u64;
    loop {
        let mut length = [0u8; 4];
        match reader.read_exact(&mut length) {
            Ok(()) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::UnexpectedEof
                    && done == expected_plaintext =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
        hasher.update(length);
        let length = u32::from_be_bytes(length) as usize;
        if !(16..=ATTACHMENT_CHUNK_BYTES as usize + 16).contains(&length) {
            return Err("Invalid attachment chunk.".into());
        }
        let mut encrypted = Zeroizing::new(vec![0u8; length]);
        reader.read_exact(&mut encrypted)?;
        hasher.update(&*encrypted);
        let mut plain = cipher
            .decrypt(
                &nonce(&prefix, index),
                Payload {
                    msg: &encrypted,
                    aad: &aad(index, expected_plaintext),
                },
            )
            .map_err(|_| "Attachment authentication failed.")?;
        if done + u64::try_from(plain.len())? > expected_plaintext {
            plain.zeroize();
            return Err("Attachment size mismatch.".into());
        }
        writer.write_all(&plain)?;
        done += u64::try_from(plain.len())?;
        plain.zeroize();
        index += 1;
    }
    writer.sync_all()?;
    if done != expected_plaintext
        || crate::record::encode_hex(&hasher.finalize()) != expected_ciphertext_hash
    {
        return Err("Attachment integrity check failed.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_five_mebibytes_and_rejects_one_byte_more() {
        assert!(plan(MAX_ATTACHMENT_FILE_SIZE).is_ok());
        assert!(plan(MAX_ATTACHMENT_FILE_SIZE + 1).is_err());
    }

    #[test]
    fn rejects_invalid_key_lengths_before_opening_files() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("missing-input");
        let output = directory.path().join("output");
        for length in [0, 1, 31, 33, 64] {
            let error = decrypt_file(
                &input,
                &output,
                &STANDARD.encode(vec![0u8; length]),
                &STANDARD.encode([0u8; 16]),
                0,
                "",
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "Invalid attachment key.");
            assert!(!output.exists());
        }
    }

    #[test]
    fn chunked_round_trip_and_tamper_detection() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let output = directory.path().join("output");
        let bytes = vec![0x5a; ATTACHMENT_CHUNK_BYTES as usize + 113];
        std::fs::write(&input, &bytes).unwrap();
        let plan = plan(bytes.len() as u64).unwrap();
        let result = encrypt_file(&input, &encrypted, &plan, |_| {}).unwrap();
        assert_eq!(
            std::fs::metadata(&encrypted).unwrap().len(),
            result.encrypted_size
        );
        decrypt_file(
            &encrypted,
            &output,
            &STANDARD.encode(*plan.key),
            &STANDARD.encode(plan.nonce_prefix),
            plan.plaintext_size,
            &result.ciphertext_sha256,
        )
        .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        let mut damaged = std::fs::read(&encrypted).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        std::fs::write(&encrypted, damaged).unwrap();
        std::fs::remove_file(&output).unwrap();
        assert!(
            decrypt_file(
                &encrypted,
                &output,
                &STANDARD.encode(*plan.key),
                &STANDARD.encode(plan.nonce_prefix),
                plan.plaintext_size,
                &result.ciphertext_sha256,
            )
            .is_err()
        );
    }
}

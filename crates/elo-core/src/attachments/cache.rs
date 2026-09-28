//! A bounded local copy of attachment ciphertext, never plaintext or keys.
use super::{AttachmentDescriptor, MAX_ATTACHMENT_FILE_SIZE, crypto};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

const BUDGET: u64 = 128 * 1024 * 1024;

/// Validate the entire app-owned directory before profile/Space removal.
pub fn removable_files(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::other("Unsafe attachment cache."));
    }
    fs::read_dir(path)?
        .map(|entry| {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let extension = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || !stem.bytes().all(|b| b.is_ascii_hexdigit())
                || !matches!((stem.len(), extension), (64, "ciphertext") | (32, "tmp"))
            {
                return Err(std::io::Error::other("Unexpected attachment cache file."));
            }
            Ok(path)
        })
        .collect()
}

fn directory(root: &Path) -> std::io::Result<PathBuf> {
    let path = root.join("attachment-cache");
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::other("Unsafe attachment cache."));
    }
    Ok(path)
}

fn name(hash: &str) -> std::io::Result<String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(std::io::Error::other("Invalid attachment digest."));
    }
    Ok(format!("{hash}.ciphertext"))
}

pub(crate) fn store(root: &Path, source: &Path, hash: &str) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > crypto::encrypted_size(MAX_ATTACHMENT_FILE_SIZE)
    {
        return Err(std::io::Error::other("Unsafe attachment cache source."));
    }
    let bytes = fs::read(source)?;
    if bytes.len() as u64 > crypto::encrypted_size(MAX_ATTACHMENT_FILE_SIZE)
        || crate::record::encode_hex(&Sha256::digest(&bytes)) != hash
    {
        return Err(std::io::Error::other("Attachment integrity check failed."));
    }
    let directory = directory(root)?;
    let destination = directory.join(name(hash)?);
    let temporary = directory.join(format!(
        "{}.tmp",
        crate::record::random_hex::<16>().map_err(std::io::Error::other)?
    ));
    let result = (|| {
        use std::io::Write;
        let mut file = fs::File::create_new(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        // Evict least recently read ciphertext, keeping the newly added file.
        let mut entries = fs::read_dir(&directory)?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let metadata = fs::symlink_metadata(entry.path()).ok()?;
                (metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && entry.path().extension().is_some_and(|e| e == "ciphertext"))
                .then(|| {
                    (
                        metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                        metadata.len(),
                        entry.path(),
                    )
                })
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| e.0);
        let mut total: u64 = entries.iter().map(|e| e.1).sum();
        for (_, size, path) in entries {
            if total <= BUDGET {
                break;
            }
            if path != destination && fs::remove_file(path).is_ok() {
                total -= size;
            }
        }
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}

pub(crate) fn restore(root: &Path, descriptor: &AttachmentDescriptor, output: &Path) -> bool {
    if output.exists() {
        return false;
    }
    let Ok(filename) = name(&descriptor.encryption.ciphertext_sha256) else {
        return false;
    };
    // A cache miss must neither create a directory nor access the network.
    let directory = root.join("attachment-cache");
    let Ok(metadata) = fs::symlink_metadata(&directory) else {
        return false;
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    let path = directory.join(filename);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return false;
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != descriptor.encrypted_size
    {
        return false;
    }
    if crypto::decrypt_file(
        &path,
        output,
        &descriptor.encryption.key,
        &descriptor.encryption.nonce_prefix,
        descriptor.plaintext_size,
        &descriptor.encryption.ciphertext_sha256,
    )
    .is_err()
    {
        let _ = fs::remove_file(output);
        let _ = fs::remove_file(path);
        return false;
    }
    if let Ok(file) = fs::File::open(path) {
        let _ = file.set_times(fs::FileTimes::new().set_modified(SystemTime::now()));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[test]
    fn attachment_cache_keeps_ciphertext_and_rejects_tampering_and_other_spaces() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("original");
        let ciphertext = root.path().join("encrypted");
        let content = b"private image content for cache verification";
        fs::write(&source, content).unwrap();
        let plan = crypto::plan(content.len() as u64).unwrap();
        let encrypted = crypto::encrypt_file(&source, &ciphertext, &plan, |_| {}).unwrap();
        let descriptor = AttachmentDescriptor {
            id: "11".repeat(16).parse().unwrap(),
            object_id: "22".repeat(16).parse().unwrap(),
            name: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            plaintext_size: content.len() as u64,
            encrypted_size: encrypted.encrypted_size,
            created_at_ms: 1,
            expires_at_ms: Some(2),
            encryption: super::super::AttachmentEncryption {
                algorithm: "xchacha20-poly1305-chunks-v1".into(),
                key: STANDARD.encode(plan.key.as_slice()),
                nonce_prefix: STANDARD.encode(plan.nonce_prefix),
                chunk_bytes: super::super::ATTACHMENT_CHUNK_BYTES,
                ciphertext_sha256: encrypted.ciphertext_sha256.clone(),
            },
        };
        store(root.path(), &ciphertext, &encrypted.ciphertext_sha256).unwrap();
        fs::remove_file(source).unwrap();
        fs::remove_file(ciphertext).unwrap();
        let cached = root
            .path()
            .join("attachment-cache")
            .join(name(&encrypted.ciphertext_sha256).unwrap());
        let mut bytes = fs::read(&cached).unwrap();
        assert!(!bytes.windows(content.len()).any(|part| part == content));
        let output = root.path().join("restored");
        // No retained session/object state and no server, even after server expiry.
        assert!(restore(root.path(), &descriptor, &output));
        assert_eq!(fs::read(&output).unwrap(), content);
        fs::remove_file(&output).unwrap();
        let other = tempfile::tempdir().unwrap();
        assert!(!restore(other.path(), &descriptor, &output));
        assert!(!output.exists());
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&cached, bytes).unwrap();
        assert!(!restore(root.path(), &descriptor, &output));
        assert!(!output.exists());
        assert!(!cached.exists());
    }
}

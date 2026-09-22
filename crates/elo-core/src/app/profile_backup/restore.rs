//! Resumable, exclusively reserved backup import. A checkpoint is never a profile.
use super::*;
use crate::ids::ObjectId;
use ed25519_dalek::Signer;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestoreStage {
    Unlocking,
    Unpacking,
    Checking,
    Saving,
    Opening,
    Ready,
}
#[derive(Clone)]
pub struct RestoreProgress(Arc<dyn Fn(RestoreStage, usize, usize) -> bool + Send + Sync>);
impl Default for RestoreProgress {
    fn default() -> Self {
        Self::new(|_, _, _| true)
    }
}
impl RestoreProgress {
    /// Returning false requests a pause at a safe checkpoint, never mid-commit.
    pub fn new(
        callback: impl Fn(RestoreStage, usize, usize) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(callback))
    }
    fn report(&self, stage: RestoreStage, done: usize, total: usize) -> Result<()> {
        if (self.0)(stage, done, total) {
            Ok(())
        } else {
            Err("Recovery paused. Select the same backup to continue.".into())
        }
    }
}
pub struct RestoreRequest<'a> {
    pub directory: PathBuf,
    pub bytes: &'a [u8],
    pub secret: SecretString,
    pub expected: IdentityId,
    pub password: SecretString,
    pub allow_loopback: bool,
    pub resume: bool,
    pub paged: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    format: String,
    backup: ObjectId,
    opening: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedCheckpoint {
    checkpoint: Checkpoint,
    signature: String,
}
fn checkpoint_bytes(value: &Checkpoint) -> Result<Vec<u8>> {
    let mut bytes = b"elo.restore/checkpoint/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(value)?);
    Ok(bytes)
}
fn checkpoint(path: &Path, value: &Checkpoint, session: &Session, replace: bool) -> Result<()> {
    let signature = session.signing_key().sign(&checkpoint_bytes(value)?);
    let encoded = json!({"checkpoint":value,"signature":record::encode_hex(&signature.to_bytes())});
    vault::write_private(
        &path.join(".initializing"),
        &serde_json::to_vec(&encoded)?,
        replace,
    )?;
    Ok(())
}
fn temporary(name: &str) -> bool {
    name.strip_prefix(".elo-")
        .and_then(|s| s.strip_suffix(".tmp"))
        .is_some_and(|s| record::hex::<16>(s).is_ok())
}
fn clear_temporary(path: &Path) -> Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            clear_temporary(&entry.path())?;
        } else if temporary(&entry.file_name().to_string_lossy()) {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}
fn safe_tree(path: &Path, files: &BTreeMap<String, Zeroizing<Vec<u8>>>) -> Result<()> {
    fn visit(root: &Path, path: &Path, files: &BTreeMap<String, Zeroizing<Vec<u8>>>) -> Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("Unsafe recovery directory".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("Unsafe recovery directory".into());
            }
        }
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .ok_or("Invalid recovery path")?
                .to_owned();
            let kind = entry.file_type()?;
            if kind.is_dir()
                && files
                    .keys()
                    .any(|name| name.starts_with(&format!("{relative}/")))
            {
                visit(root, &entry.path(), files)?;
            } else if kind.is_file()
                && (files.contains_key(&relative)
                    // Opening may have prepared an optional encrypted cache
                    // before the Ready checkpoint was interrupted.
                    || relative.strip_suffix("space-vault-cache.age").is_some_and(|prefix| {
                        prefix.starts_with("spaces/")
                            && files.contains_key(&format!("{prefix}vault.age"))
                    })
                    || relative == ".initializing"
                    || relative
                        .strip_suffix(".elo-client.lock")
                        .is_some_and(|prefix| {
                            files.contains_key(&format!("{prefix}client.sqlite"))
                        })
                    || temporary(&entry.file_name().to_string_lossy())
                    || ["-wal", "-shm"].iter().any(|suffix| {
                        relative.strip_suffix(suffix).is_some_and(|name| {
                            name.ends_with("client.sqlite") && files.contains_key(name)
                        })
                    }))
            {
                let metadata = entry.metadata()?;
                if metadata.len() > (MAX_FILES * 2) as u64 {
                    return Err("Invalid recovery file size".into());
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
                        return Err("Unsafe recovery file".into());
                    }
                }
            } else {
                return Err("Unexpected file in recovery directory".into());
            }
        }
        Ok(())
    }
    visit(path, path, files)
}

fn matches_file(path: &Path, expected: &[u8]) -> Result<bool> {
    let mut file = std::fs::File::open(path)?;
    if file.metadata()?.len() != expected.len() as u64 {
        return Ok(false);
    }
    let mut buffer = [0u8; 16384];
    for chunk in expected.chunks(buffer.len()) {
        file.read_exact(&mut buffer[..chunk.len()])?;
        if &buffer[..chunk.len()] != chunk {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn restore(request: RestoreRequest<'_>, progress: &RestoreProgress) -> Result<ClientApp> {
    let RestoreRequest {
        directory,
        bytes,
        secret,
        expected,
        password,
        allow_loopback,
        resume,
        paged,
    } = request;
    progress.report(RestoreStage::Unlocking, 0, 0)?;
    let packed = decrypt(bytes, secret.clone())?;
    progress.report(RestoreStage::Unpacking, 0, 0)?;
    let mut json = Zeroizing::new(Vec::new());
    GzDecoder::new(packed.as_slice())
        .take(MAX_BACKUP as u64 + 1)
        .read_to_end(&mut json)
        .map_err(|_| "Invalid profile backup")?;
    if json.len() > MAX_BACKUP {
        return Err("Profile backup is too large".into());
    }
    let backup: Backup = serde_json::from_slice(&json).map_err(|_| "Invalid profile backup")?;
    if backup.format != "elo.now/profile-backup/v1"
        || backup.identity != expected
        || backup.files.len() > 17 * (FILES.len() + 2)
        || backup.files.keys().any(|k| !valid_backup_path(k))
    {
        return Err("This backup belongs to a different profile or is invalid".into());
    }
    drop(json);
    drop(packed);
    progress.report(RestoreStage::Checking, 0, 0)?;
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    for (name, encoded) in backup.files {
        let bytes = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| "Invalid profile backup")?,
        );
        total += bytes.len();
        if total > MAX_FILES {
            return Err("Profile backup is too large".into());
        }
        files.insert(name, bytes);
    }
    for required in ["vault.age", "client.sqlite", "profile.json"] {
        if !files.contains_key(required) {
            return Err("Incomplete profile backup".into());
        }
    }
    let session = Session::restore_backup(&files["vault.age"], secret.clone(), expected)?;
    let public: Value = serde_json::from_slice(&files["profile.json"])?;
    if public["identity_id"] != expected.to_string()
        || public["credential_id"] != session.credential().id().to_string()
    {
        return Err("Invalid profile backup identity".into());
    }
    // Validate the new password and vault before reserving any disk space.
    files.insert(
        "vault.age".into(),
        Zeroizing::new(session.seal(password.clone())?),
    );
    let space_ids = files
        .keys()
        .filter_map(|k| k.strip_prefix("spaces/").and_then(|s| s.split('/').next()))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if !space_ids.is_empty() && !files.contains_key("spaces.age") {
        return Err("Incomplete Space catalog".into());
    }
    for id in &space_ids {
        progress.report(RestoreStage::Checking, 0, 0)?;
        let prefix = format!("spaces/{id}/");
        for required in ["vault.age", "client.sqlite", "profile.json"] {
            if !files.contains_key(&format!("{prefix}{required}")) {
                return Err("Incomplete Space backup".into());
            }
        }
        let key = format!("{prefix}vault.age");
        let child = Session::restore_backup(&files[&key], secret.clone(), expected)?;
        let public: Value = serde_json::from_slice(&files[&format!("{prefix}profile.json")])?;
        if child.credential().id() != session.credential().id()
            || public["identity_id"] != expected.to_string()
            || public["credential_id"] != child.credential().id().to_string()
        {
            return Err("Invalid Space backup identity".into());
        }
        files.insert(key, Zeroizing::new(child.seal(password.clone())?));
    }
    let fingerprint = ObjectId::of_ciphertext(bytes);
    let mut journal = Checkpoint {
        format: "elo.restore/v1".into(),
        backup: fingerprint,
        opening: false,
    };
    let existing = std::fs::symlink_metadata(&directory).is_ok();
    if existing {
        if !resume {
            return Err("The profile directory already exists".into());
        }
        safe_tree(&directory, &files)?;
        let signed: SignedCheckpoint =
            serde_json::from_slice(&vault::read_private(&directory.join(".initializing"))?)
                .map_err(|_| "This directory is not a resumable recovery")?;
        session
            .signing_key()
            .verifying_key()
            .verify_strict(
                &checkpoint_bytes(&signed.checkpoint)?,
                &ed25519_dalek::Signature::from_bytes(&record::hex::<64>(&signed.signature)?),
            )
            .map_err(|_| "Invalid recovery checkpoint signature")?;
        journal = signed.checkpoint;
        if journal.format != "elo.restore/v1" || journal.backup != fingerprint {
            return Err("Select the same backup to continue recovery".into());
        }
        // The resumed vault was sealed with the password chosen on the
        // first attempt. Never replace it or revive controller authority.
        for name in files
            .keys()
            .filter(|name| name.ends_with("vault.age"))
            .cloned()
            .collect::<Vec<_>>()
        {
            let path = directory.join(&name);
            if path.exists() {
                let sealed = Zeroizing::new(vault::read_private(&path)?);
                let restored = Session::open(&sealed, password.clone(), expected)
                    .map_err(|_| "Use the password chosen when recovery started")?;
                if restored.credential().id() != session.credential().id()
                    || restored.controller_mode() != vault::ControllerMode::Follower
                {
                    return Err("Invalid recovery checkpoint".into());
                }
                files.insert(name, sealed);
            }
        }
        clear_temporary(&directory)?;
    } else {
        private_directory(&directory)?;
        checkpoint(&directory, &journal, &session, false)?;
    }
    let result: Result<ClientApp> = async {
        if !space_ids.is_empty() {
            for path in std::iter::once(directory.join("spaces"))
                .chain(space_ids.iter().map(|id| directory.join("spaces").join(id)))
            {
                if !path.exists() {
                    private_directory(&path)?;
                }
            }
        }
        let count = files.len();
        progress.report(RestoreStage::Saving, 0, count)?;
        for (index, (name, bytes)) in files.into_iter().enumerate() {
            let path = directory.join(&name);
            if path.exists() {
                // Opening may migrate SQLite and encrypted settings. That
                // phase resumes through normal authenticated profile open.
                if !journal.opening && !matches_file(&path, &bytes)? {
                    return Err("Recovery checkpoint does not match this backup".into());
                }
            } else if journal.opening {
                // A verified removal may have purged this compartment before
                // Ready was committed. Never recreate it from the old archive.
                if !super::super::spaces::restore_file_removed(&directory, &session, &name)? {
                    return Err("Incomplete recovery checkpoint".into());
                }
            } else {
                vault::write_private(&path, &bytes, false)?;
            }
            progress.report(RestoreStage::Saving, index + 1, count)?;
        }
        journal.opening = true;
        checkpoint(&directory, &journal, &session, true)?;
        progress.report(RestoreStage::Opening, 0, 0)?;
        let mut app =
            ClientApp::open_initialized(directory.clone(), password, allow_loopback).await?;
        if paged {
            app.enable_paged_views();
        }
        let verified: Result<()> = async {
            if app.has_spaces_catalog() {
                app.quarantine_restored_spaces()?;
                app.enable_spaces().await?;
            }
            app.view().await?;
            progress.report(RestoreStage::Ready, 1, 1)?;
            std::fs::remove_file(directory.join(".initializing"))?;
            #[cfg(unix)]
            std::fs::File::open(&directory)?.sync_all()?;
            Ok(())
        }
        .await;
        if let Err(error) = verified {
            app.close().await?;
            return Err(error);
        }
        Ok(app)
    }
    .await;
    if result.is_err() && !resume && !existing {
        // Only the legacy atomic call's exclusively created directory is
        // disposable. Resumable jobs preserve their private checkpoint.
        let _ = std::fs::remove_dir_all(directory);
    }
    result
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;

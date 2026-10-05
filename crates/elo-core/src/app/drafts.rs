//! Local drafts are sealed to the unlocked profile. Neither text, mention spans
//! nor staged attachment bytes are written in plaintext to the profile store.
use super::*;
use sha2::{Digest, Sha256};

const MAX_DRAFT: usize = 256 * 1024;
const MAX_FILE: usize = crate::attachments::MAX_ATTACHMENT_FILE_SIZE as usize;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DraftScope {
    pub identity: IdentityId,
    pub credential: RecordId,
    pub active_space: Option<String>,
    pub space: SpaceId,
    pub stream: StreamId,
    pub thread: Option<RecordId>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DraftMention {
    pub identity_id: IdentityId,
    pub label: String,
    pub start: usize,
    pub end: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DraftContent {
    pub text: String,
    pub expiry: Option<u8>,
    #[serde(default)]
    pub mentions: Vec<DraftMention>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAttachment {
    id: String,
    digest: String,
    name: String,
    size_bytes: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDraft {
    v: u8,
    scope: DraftScope,
    content: DraftContent,
    attachment: Option<StoredAttachment>,
}
pub struct LoadedDraft {
    pub content: DraftContent,
    pub attachment: Option<(String, Zeroizing<Vec<u8>>)>,
}
impl DraftContent {
    fn validate(&self) -> Result<()> {
        let text: Vec<u16> = self.text.encode_utf16().collect();
        if text.len() > 16384
            || self.expiry.is_some_and(|h| ![1, 12, 24].contains(&h))
            || self.mentions.len() > 128
        {
            return Err("Invalid conversation draft.".into());
        }
        let mut previous = 0;
        for mention in &self.mentions {
            if mention.start < previous
                || mention.start >= mention.end
                || mention.end > text.len()
                || mention.label.is_empty()
                || mention.label.chars().count() > 256
                || String::from_utf16(&text[mention.start..mention.end])
                    .ok()
                    .as_deref()
                    != Some(&format!("@{}", mention.label))
            {
                return Err("Invalid conversation draft mention.".into());
            }
            previous = mention.end;
        }
        Ok(())
    }
}
fn private_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
            return Err("Unsafe draft directory.".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
impl ClientApp {
    fn draft_client(&self, scope: &DraftScope) -> Result<&Self> {
        let client = self.draft_space_client(scope.active_space.as_deref())?;
        if scope.identity != self.session.identity_id()
            || scope.identity != client.session.identity_id()
            || scope.credential != client.session.credential().id()
            || !client.authorities.0.iter().any(|authority| {
                authority.space() == scope.space && authority.stream() == scope.stream
            })
        {
            return Err("The draft does not belong to this profile and chat.".into());
        }
        Ok(client)
    }
    fn draft_directory(&self) -> Result<PathBuf> {
        let directory = self.directory.join("drafts");
        private_dir(&directory)?;
        Ok(directory)
    }
    fn draft_path(directory: &Path, scope: &DraftScope) -> Result<PathBuf> {
        Ok(directory.join(format!(
            "{}.age",
            record::encode_hex(&Sha256::digest(serde_json::to_vec(scope)?))
        )))
    }
    fn read_draft(&self, scope: &DraftScope, path: &Path) -> Result<Option<StoredDraft>> {
        if !path.exists() {
            return Ok(None);
        }
        let cipher = read_exchange(path, MAX_DRAFT + 1024)?;
        let clear = Zeroizing::new(crypto::open_bytes(
            &cipher,
            self.session.age_identity(),
            MAX_DRAFT,
        )?);
        let draft: StoredDraft = serde_json::from_slice(&clear)?;
        if draft.v != 1 || draft.scope != *scope {
            return Err("Invalid conversation draft scope.".into());
        }
        draft.content.validate()?;
        Ok(Some(draft))
    }
    pub fn load_conversation_draft(&self, scope: &DraftScope) -> Result<LoadedDraft> {
        let client = self.draft_client(scope)?;
        let directory = client.draft_directory()?;
        let path = Self::draft_path(&directory, scope)?;
        let Some(draft) = client.read_draft(scope, &path)? else {
            return Ok(LoadedDraft {
                content: DraftContent::default(),
                attachment: None,
            });
        };
        let attachment = draft
            .attachment
            .map(|attachment| -> Result<_> {
                let _: [u8; 32] = record::hex(&attachment.id)?;
                if attachment.size_bytes > MAX_FILE {
                    return Err("Invalid draft attachment.".into());
                }
                let cipher = read_exchange(
                    &directory.join(format!("file-{}.age", attachment.id)),
                    MAX_FILE + 4096,
                )?;
                let clear = Zeroizing::new(crypto::open_bytes(
                    &cipher,
                    client.session.age_identity(),
                    MAX_FILE,
                )?);
                if clear.len() != attachment.size_bytes
                    || record::encode_hex(&Sha256::digest(&*clear)) != attachment.digest
                {
                    return Err("Invalid draft attachment.".into());
                }
                Ok((attachment.name, clear))
            })
            .transpose()?;
        Ok(LoadedDraft {
            content: draft.content,
            attachment,
        })
    }
    pub fn save_conversation_draft(
        &self,
        scope: &DraftScope,
        content: DraftContent,
        attachment: Option<(&Path, &str)>,
    ) -> Result<()> {
        self.save_conversation_draft_cached(scope, content, attachment, None)
            .map(|_| ())
    }
    /// The native caller may reuse only its own session-bound attachment cache.
    /// This cached value is never accepted from a renderer or network request.
    pub fn save_conversation_draft_cached(
        &self,
        scope: &DraftScope,
        content: DraftContent,
        attachment: Option<(&Path, &str)>,
        cached_attachment: Option<StoredAttachment>,
    ) -> Result<Option<StoredAttachment>> {
        content.validate()?;
        let client = self.draft_client(scope)?;
        let directory = client.draft_directory()?;
        let path = Self::draft_path(&directory, scope)?;
        let previous_attachment = client
            .read_draft(scope, &path)?
            .and_then(|draft| draft.attachment);
        let attachment = attachment
            .map(|(path, name)| -> Result<_> {
                if name.is_empty() || name.len() > 1024 {
                    return Err("Invalid draft attachment name.".into());
                }
                if let Some(cached) = cached_attachment {
                    record::hex::<32>(&cached.id)?;
                    let target = directory.join(format!("file-{}.age", cached.id));
                    if cached.name == name && target.is_file() {
                        return Ok(cached);
                    }
                }
                let clear = Zeroizing::new(read_exchange(path, MAX_FILE)?);
                let digest = record::encode_hex(&Sha256::digest(&*clear));
                // Filenames never reveal a public fingerprint of draft contents.
                let id = previous_attachment
                    .as_ref()
                    .filter(|file| file.digest == digest)
                    .map(|file| file.id.clone())
                    .unwrap_or(record::random_hex::<32>()?);
                let target = directory.join(format!("file-{id}.age"));
                if !target.exists() {
                    let cipher = crypto::seal_bytes(
                        &clear,
                        &[client.session.age_identity().to_public()],
                        MAX_FILE,
                    )?;
                    vault::write_private(&target, &cipher, false)?;
                }
                Ok(StoredAttachment {
                    id,
                    digest,
                    name: name.into(),
                    size_bytes: clear.len(),
                })
            })
            .transpose()?;
        let attachment_changed = previous_attachment.as_ref().map(|file| file.id.as_str())
            != attachment.as_ref().map(|file| file.id.as_str());
        if content.text.is_empty() && content.expiry.is_none() && attachment.is_none() {
            if path.exists() {
                std::fs::remove_file(path)?;
                #[cfg(unix)]
                std::fs::File::open(&directory)?.sync_all()?;
            }
        } else {
            let clear = Zeroizing::new(serde_json::to_vec(&StoredDraft {
                v: 1,
                scope: scope.clone(),
                content,
                attachment: attachment.clone(),
            })?);
            let cipher = crypto::seal_bytes(
                &clear,
                &[client.session.age_identity().to_public()],
                MAX_DRAFT,
            )?;
            vault::write_private(&path, &cipher, true)?;
        }
        if attachment_changed {
            client.collect_draft_files(&directory)?;
        }
        Ok(attachment)
    }
    fn collect_draft_files(&self, directory: &Path) -> Result<()> {
        let mut retained = BTreeSet::new();
        let entries = std::fs::read_dir(directory)?.collect::<std::result::Result<Vec<_>, _>>()?;
        for entry in &entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("file-") || !name.ends_with(".age") {
                continue;
            }
            let cipher = read_exchange(&entry.path(), MAX_DRAFT + 1024)?;
            let clear = Zeroizing::new(crypto::open_bytes(
                &cipher,
                self.session.age_identity(),
                MAX_DRAFT,
            )?);
            let stored: StoredDraft = serde_json::from_slice(&clear)?;
            if let Some(attachment) = stored.attachment {
                retained.insert(format!("file-{}.age", attachment.id));
            }
        }
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("file-") && name.ends_with(".age") && !retained.contains(&name) {
                std::fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;

/// Validate the complete directory before removing any local draft data.
pub(super) fn removable_files(directory: &Path) -> Result<Vec<PathBuf>> {
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Unsafe draft directory.".into());
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Unsafe draft file.")?;
        let hex = name.strip_suffix(".age").ok_or("Unsafe draft file.")?;
        let hex = hex.strip_prefix("file-").unwrap_or(hex);
        record::hex::<32>(hex)?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("Unsafe draft file.".into());
        }
        files.push(entry.path());
    }
    Ok(files)
}

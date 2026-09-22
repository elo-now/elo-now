//! Encrypted message backups and trusted device copies. Restoring never duplicates control.
use super::*;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
mod restore;
pub use restore::{RestoreProgress, RestoreRequest, RestoreStage, restore};

pub const MAX_BACKUP: usize = 96 * 1024 * 1024;
const MAX_FILES: usize = 64 * 1024 * 1024;
/// The report describes generated archive content, not whether a share sheet
/// ultimately saved it. It is not a new field in the v1 archive format.
pub struct RecoveryBackup {
    pub bytes: Vec<u8>,
    pub omitted_messages: usize,
    pub included_data_bytes: usize,
}

const FILES: &[&str] = &[
    "profile.json",
    "workspace.age",
    "profile-details.age",
    "read-state.age",
    "blocked.age",
    "invitations.age",
    "spaces.age",
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    format: String,
    identity: IdentityId,
    created_at: u64,
    files: BTreeMap<String, String>,
}

/// Standard age passphrase encryption; recovery words never go in the archive.
pub fn encrypt(bytes: &[u8], secret: SecretString) -> Result<Vec<u8>> {
    if bytes.is_empty()
        || bytes.len() > MAX_BACKUP
        || !(12..=1024).contains(&secret.expose_secret().len())
    {
        return Err("Invalid profile backup".into());
    }
    let encryptor = age::Encryptor::with_user_passphrase(secret);
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(bytes)?;
    writer.finish()?;
    if encrypted.len() > MAX_BACKUP {
        return Err("Profile backup is too large".into());
    }
    Ok(encrypted)
}

pub fn decrypt(bytes: &[u8], secret: SecretString) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() > MAX_BACKUP {
        return Err("Invalid profile backup".into());
    }
    let decryptor = crypto::bounded_decryptor(bytes).map_err(|_| "Invalid profile backup")?;
    if !decryptor.is_scrypt() {
        return Err("Invalid profile backup".into());
    }
    let mut identity = age::scrypt::Identity::new(secret);
    identity.set_max_work_factor(20);
    let mut out = Zeroizing::new(Vec::new());
    decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| "The backup could not be unlocked with this recovery key")?
        .take(MAX_BACKUP as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| "Invalid or incomplete profile backup")?;
    if out.len() > MAX_BACKUP {
        return Err("Profile backup is too large".into());
    }
    Ok(out)
}

fn valid_backup_path(path: &str) -> bool {
    let file = if let Some(rest) = path.strip_prefix("spaces/") {
        let Some((id, file)) = rest.split_once('/') else {
            return false;
        };
        if record::hex::<32>(id).is_err() || file == "spaces.age" {
            return false;
        }
        file
    } else {
        path
    };
    FILES.contains(&file) || ["vault.age", "client.sqlite"].contains(&file)
}

fn private_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

impl ClientApp {
    pub fn profile_path(&self) -> &Path {
        &self.directory
    }
    pub fn identity_id(&self) -> IdentityId {
        self.session.identity_id()
    }

    /// Transport configuration of this compartment only. Profile-wide features
    /// must resolve their connected Spaces instead of consulting this list.
    pub fn local_replica_descriptors(&self) -> &[PeerDescriptor] {
        self.session.peers()
    }

    /// Caller holds the application lock, so the SQLite image and metadata belong
    /// to the same application state. No plaintext database staging file exists.
    pub async fn export_profile(&self, secret: SecretString) -> Result<Vec<u8>> {
        Ok(self.export_profile_with_report(secret).await?.bytes)
    }

    pub async fn export_profile_with_report(&self, secret: SecretString) -> Result<RecoveryBackup> {
        self.export_snapshot(secret, false, MAX_FILES).await
    }

    pub(super) async fn export_device_copy(&self, secret: SecretString) -> Result<Vec<u8>> {
        Ok(self.export_snapshot(secret, true, MAX_FILES).await?.bytes)
    }

    async fn export_snapshot(
        &self,
        secret: SecretString,
        include_files: bool,
        maximum: usize,
    ) -> Result<RecoveryBackup> {
        if self
            .spaces
            .as_ref()
            .is_some_and(|spaces| spaces.awaiting_verification())
        {
            return Err(
                "Connect to verify your restored Spaces before creating a new backup.".into(),
            );
        }
        let mut profiles = vec![(String::new(), self)];
        if let Some(spaces) = &self.spaces {
            profiles.extend(
                spaces
                    .children()
                    .iter()
                    .map(|(id, child)| (format!("spaces/{id}/"), child)),
            );
        }
        // Reserve every compartment's vault/settings first. No Space can consume
        // the budget before another Space's identity and authority are preserved.
        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for (prefix, app) in &profiles {
            app.backup_metadata(prefix, &secret, &mut files, &mut total, maximum)?;
        }
        let stores: Vec<_> = profiles.iter().map(|(_, app)| *app).collect();
        let remaining = maximum.saturating_sub(total);
        let (images, omitted_messages) = if include_files {
            (database_images(&stores, remaining, None, true).await?, 0)
        } else {
            bounded_message_images(&stores, remaining).await?
        };
        for ((prefix, _), image) in profiles.iter().zip(images) {
            let image = Zeroizing::new(image);
            total += image.len();
            files.insert(format!("{prefix}client.sqlite"), STANDARD.encode(&*image));
        }
        let backup = Backup {
            format: "elo.now/profile-backup/v1".into(),
            identity: self.identity_id(),
            created_at: now()?.as_millis() as u64,
            files,
        };
        let json = Zeroizing::new(serde_json::to_vec(&backup)?);
        let mut compressor = GzEncoder::new(Vec::new(), Compression::fast());
        compressor.write_all(&json)?;
        let packed = Zeroizing::new(compressor.finish()?);
        Ok(RecoveryBackup {
            bytes: encrypt(&packed, secret)?,
            omitted_messages,
            included_data_bytes: total,
        })
    }

    fn backup_metadata(
        &self,
        prefix: &str,
        secret: &SecretString,
        files: &mut BTreeMap<String, String>,
        total: &mut usize,
        maximum: usize,
    ) -> Result<()> {
        let vault = self.session.seal(secret.clone())?;
        *total += vault.len();
        if *total > maximum {
            return Err("Profile settings and security data exceed the backup size limit.".into());
        }
        files.insert(format!("{prefix}vault.age"), STANDARD.encode(vault));
        for name in FILES {
            if !prefix.is_empty() && *name == "spaces.age" {
                continue;
            }
            let path = self.directory.join(name);
            match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
                Ok(_) => {}
            }
            let bytes = Zeroizing::new(read_exchange(&path, maximum.saturating_sub(*total))?);
            *total += bytes.len();
            if *total > maximum {
                return Err(
                    "Profile settings and security data exceed the backup size limit.".into(),
                );
            }
            files.insert(format!("{prefix}{name}"), STANDARD.encode(&*bytes));
        }
        Ok(())
    }

    async fn message_backup_plan(&self) -> Result<crate::store::MessageBackupPlan> {
        let mut targets = Vec::new();
        for authority in self.authorities.0.iter() {
            let sources = self
                .store
                .action_sources(authority.space(), authority.stream(), None)
                .await?;
            for (record, _) in self.open_sources(authority, sources).await? {
                if let Some(action) = record.chat()?.payload.action {
                    targets.push((record.id(), action.target()));
                }
            }
        }
        Ok(self.store.message_backup_plan(targets).await?)
    }

    pub async fn export_recovery_backup(&self, words: &str) -> Result<Vec<u8>> {
        Ok(self.export_recovery_backup_with_report(words).await?.bytes)
    }

    pub async fn export_recovery_backup_with_report(&self, words: &str) -> Result<RecoveryBackup> {
        let draft = ProfileDraft::recover(words, &self.identity_id().to_string())?;
        self.export_profile_with_report(draft.card().phrase.clone().into())
            .await
    }

    pub async fn restore_profile(
        directory: PathBuf,
        bytes: &[u8],
        secret: SecretString,
        expected: IdentityId,
        password: SecretString,
        allow_loopback: bool,
    ) -> Result<Self> {
        restore::restore(
            RestoreRequest {
                directory,
                bytes,
                secret,
                expected,
                password,
                allow_loopback,
                resume: false,
                paged: false,
            },
            &RestoreProgress::default(),
        )
        .await
    }
}

// All profiles share one uncompressed-data budget, regardless of gzip ratio.
async fn database_images(
    profiles: &[&ClientApp],
    maximum: usize,
    selections: Option<&[Vec<RecordId>]>,
    include_files: bool,
) -> std::result::Result<Vec<Vec<u8>>, crate::store::StoreError> {
    let mut remaining = maximum;
    let mut images = Vec::new();
    for (index, app) in profiles.iter().enumerate() {
        let image = if include_files {
            app.store.backup_image(remaining).await?
        } else {
            app.store
                .selected_message_backup_image(remaining, selections.map(|s| s[index].clone()))
                .await?
        };
        remaining -= image.len();
        images.push(image);
    }
    Ok(images)
}

async fn bounded_message_images(
    profiles: &[&ClientApp],
    maximum: usize,
) -> Result<(Vec<Vec<u8>>, usize)> {
    use crate::store::StoreError;
    match database_images(profiles, maximum, None, false).await {
        Ok(images) => return Ok((images, 0)),
        Err(StoreError::BackupTooLarge) => {}
        Err(error) => return Err(error.into()),
    }
    // Only oversized exports need a dependency plan or action decryption.
    let mut plans = Vec::new();
    for app in profiles {
        plans.push(app.message_backup_plan().await?);
    }
    let mut order = Vec::new();
    let mut messages = 0;
    for (profile, plan) in plans.iter().enumerate() {
        for (group, item) in plan.groups.iter().enumerate() {
            order.push((item.newest, profile, group));
            messages += item.messages;
        }
    }
    order.sort_unstable_by(|a, b| b.cmp(a));
    let selection = |count: usize| {
        let mut keep: Vec<_> = plans.iter().map(|p| p.required.clone()).collect();
        for (_, profile, group) in &order[..count] {
            keep[*profile].extend_from_slice(&plans[*profile].groups[*group].records);
        }
        keep
    };
    let mut images = match database_images(profiles, maximum, Some(&selection(0)), false).await {
        Ok(images) => images,
        Err(StoreError::BackupTooLarge) => {
            return Err("Profile settings and security data exceed the backup size limit.".into());
        }
        Err(error) => return Err(error.into()),
    };
    // Each probe writes a fresh bounded image; no deletion/free pages can leak
    // omitted content. Binary search limits retries even for a large history.
    let mut lower = 0;
    let mut upper = order.len();
    while lower < upper {
        let middle = lower + (upper - lower).div_ceil(2);
        match database_images(profiles, maximum, Some(&selection(middle)), false).await {
            Ok(candidate) => {
                images = candidate;
                lower = middle;
            }
            Err(StoreError::BackupTooLarge) => {
                upper = middle - 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let included: usize = order[..lower]
        .iter()
        .map(|(_, p, g)| plans[*p].groups[*g].messages)
        .sum();
    Ok((images, messages - included))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::MessageAction;

    pub(super) const PASSWORD: &str = "synthetic bounded backup password";

    pub(super) async fn profile(path: PathBuf) -> ClientApp {
        ProfileDraft::new()
            .unwrap()
            .save(path, PASSWORD.into(), "General")
            .await
            .unwrap()
    }

    pub(super) async fn message(
        app: &ClientApp,
        n: u64,
        root: Option<RecordId>,
        action: Option<MessageAction>,
    ) -> RecordId {
        let a = &app.authorities.0[0];
        let kind = if action.is_some() {
            "chat.action"
        } else {
            "chat.message"
        };
        let record = a
            .prepare_chat(
                ChatMessage {
                    v: 1,
                    kind: kind.into(),
                    nonce: record::random_hex::<16>().unwrap(),
                    space_id: a.space(),
                    stream_id: a.stream(),
                    issuer_identity: app.identity_id(),
                    issuer_credential: app.session.credential().id(),
                    config_id: a.head_id().unwrap(),
                    audience: vec![],
                    recipient_credentials: vec![],
                    logical_time: n,
                    created_at: "2026-09-13T12:00:00Z".into(),
                    parents: vec![],
                    payload: TextPayload {
                        text: if action.is_some() {
                            String::new()
                        } else {
                            // High-entropy synthetic text keeps this a budget
                            // overflow test after per-record compression.
                            use sha2::Digest;
                            let body: String = (0..128)
                                .map(|chunk| {
                                    record::encode_hex(&sha2::Sha256::digest(format!(
                                        "backup fixture {n}/{chunk}"
                                    )))
                                })
                                .collect();
                            format!("Message {n}: {body}")
                        },
                        sender_name: None,
                        thread_root: root,
                        action,
                    },
                    locator: None,
                },
                app.session.signing_key(),
            )
            .unwrap();
        let cipher = crypto::seal_chat(&record, &[app.session.credential().clone()]).unwrap();
        // Actions deliberately have older local timestamps than their target.
        let time = if kind == "chat.action" { 0 } else { n };
        app.store
            .commit_local_record_with_outbox(
                PreparedLocalRecord::new(
                    record.id(),
                    cipher,
                    RecordMetadata::new(kind, Some(a.space()), Some(a.stream()), a.head_id())
                        .unwrap(),
                    vec![],
                    LocalTime::from_millis(time).unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        record.id()
    }

    #[tokio::test]
    async fn bounded_backup_restores_newest_messages_actions_and_orphan_reply_without_changing_source()
     {
        let temp = tempfile::tempdir().unwrap();
        let app = profile(temp.path().join("source")).await;
        let mut ids = Vec::new();
        for n in 1..=120 {
            ids.push(message(&app, n, (n == 120).then(|| ids[0]), None).await);
        }
        let target = ids[119];
        for (n, action) in [
            (
                121,
                MessageAction::Reaction {
                    target,
                    emoji: "👍".into(),
                    active: true,
                },
            ),
            (
                122,
                MessageAction::Reaction {
                    target,
                    emoji: "👍".into(),
                    active: false,
                },
            ),
            (
                123,
                MessageAction::Pin {
                    target,
                    active: true,
                },
            ),
        ] {
            message(&app, n, None, Some(action)).await;
        }
        let original = app.store.backup_image(4 * 1024 * 1024).await.unwrap();
        // A reduced test budget exercises the exact production selection path.
        let maximum = 512 * 1024;
        let exported = app
            .export_snapshot(PASSWORD.into(), false, maximum)
            .await
            .unwrap();
        assert!(exported.included_data_bytes <= maximum);
        assert!(exported.omitted_messages > 0 && exported.omitted_messages < ids.len());
        let restored = ClientApp::restore_profile(
            temp.path().join("restored"),
            &exported.bytes,
            PASSWORD.into(),
            app.identity_id(),
            PASSWORD.into(),
            false,
        )
        .await
        .unwrap();
        let view = restored.view().await.unwrap();
        let rows = view["streams"][0]["rows"].as_array().unwrap();
        let expected = &ids[exported.omitted_messages..];
        assert_eq!(rows.len(), expected.len());
        for (row, id) in rows.iter().zip(expected) {
            assert_eq!(row["id"], id.to_string());
        }
        let last = rows.last().unwrap();
        assert_eq!(last["body"]["payload"]["thread_root"], ids[0].to_string());
        assert_eq!(last["pinned"], true);
        assert_eq!(last["reactions"], json!([]));
        assert_eq!(
            app.store.backup_image(4 * 1024 * 1024).await.unwrap(),
            original
        );
        // A settings/security overflow must fail, never emit an invalid archive.
        assert!(
            app.export_snapshot(PASSWORD.into(), false, 4096)
                .await
                .is_err()
        );
        let full = app
            .export_profile_with_report(PASSWORD.into())
            .await
            .unwrap();
        assert_eq!(full.omitted_messages, 0);
        assert!(full.included_data_bytes > maximum);
        restored.close().await.unwrap();
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn bounded_backup_uses_one_budget_and_global_recency_across_compartments() {
        let temp = tempfile::tempdir().unwrap();
        let early = profile(temp.path().join("early")).await;
        let late = profile(temp.path().join("late")).await;
        for n in 1..=120 {
            message(if n % 2 == 0 { &early } else { &late }, n, None, None).await;
        }
        let maximum = 640 * 1024;
        let (images, omitted) = bounded_message_images(&[&early, &late], maximum)
            .await
            .unwrap();
        assert!(images.iter().map(Vec::len).sum::<usize>() <= maximum);
        assert!(omitted > 0 && omitted < 120);
        let mut retained = Vec::new();
        for (i, image) in images.iter().enumerate() {
            let path = temp.path().join(format!("image-{i}"));
            std::fs::create_dir(&path).unwrap();
            vault::write_private(&path.join("client.sqlite"), image, false).unwrap();
            let store = ClientStore::open(&path).await.unwrap();
            store.close().await.unwrap();
            let db = rusqlite::Connection::open_with_flags(
                path.join("client.sqlite"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let mut q = db
                .prepare("SELECT first_seen_local_ms FROM records WHERE kind='chat.message'")
                .unwrap();
            let mut times = q
                .query_map([], |r| r.get::<_, i64>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert!(!times.is_empty());
            retained.append(&mut times);
        }
        retained.sort_unstable();
        assert_eq!(retained, ((omitted as i64 + 1)..=120).collect::<Vec<_>>());
        early.close().await.unwrap();
        late.close().await.unwrap();
    }
}

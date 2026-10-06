//! Local password rotation preserves device keys and commits the root vault last.
//! The encrypted journal repairs an interrupted multi-vault replacement on unlock.
use super::*;
use std::fs;

const JOURNAL: &str = ".password-change.age";
const MAX_JOURNAL: usize = 64 * 1024 * 1024;
const MAX_VAULTS: usize = 65;
const RECOVERY_REQUIRED: &str = "password_change_recovery_required";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    before: String,
    after: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    identity: IdentityId,
    entries: Vec<Entry>,
}

fn directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("password_change_unavailable".into());
    }
    Ok(())
}

fn destination(root: &Path, name: &str) -> Result<PathBuf> {
    directory(root)?;
    if name == "vault.age" {
        return Ok(root.join(name));
    }
    let parts: Vec<_> = name.split('/').collect();
    if parts.len() != 3 || parts[0] != "spaces" || parts[2] != "vault.age" {
        return Err("password_change_unavailable".into());
    }
    record::hex::<32>(parts[1])?;
    directory(&root.join("spaces"))?;
    directory(&root.join("spaces").join(parts[1]))?;
    Ok(root.join(name))
}

fn vault_paths(root: &Path) -> Result<Vec<String>> {
    let mut paths = vec!["vault.age".to_owned()];
    let spaces = root.join("spaces");
    match fs::symlink_metadata(&spaces) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
        Err(error) => return Err(error.into()),
        Ok(_) => directory(&spaces)?,
    }
    for entry in fs::read_dir(spaces)? {
        let entry = entry?;
        let id = entry
            .file_name()
            .into_string()
            .map_err(|_| "password_change_unavailable")?;
        let name = format!("spaces/{id}/vault.age");
        let path = destination(root, &name)?;
        if entry.path().join(".initializing").exists() {
            return Err("password_change_unavailable".into());
        }
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => paths.push(name),
        }
        if paths.len() > MAX_VAULTS {
            return Err("password_change_unavailable".into());
        }
    }
    paths[1..].sort();
    Ok(paths)
}

fn child_locks(root: &Path, paths: &[String], owned: &BTreeSet<PathBuf>) -> Result<Vec<fs::File>> {
    let mut locks = Vec::new();
    for name in paths.iter().filter(|name| name.as_str() != "vault.age") {
        let path = destination(root, name)?;
        let parent = path.parent().ok_or("password_change_unavailable")?;
        if !owned.contains(parent) {
            locks.push(crate::store::lock_profile(parent)?);
        }
    }
    Ok(locks)
}

impl Journal {
    fn prepare(app: &ClientApp, password: &SecretString, paths: Vec<String>) -> Result<Self> {
        let mut entries = Vec::new();
        for path in paths {
            let before = vault::read_private(&destination(&app.directory, &path)?)?;
            let session = Session::open(&before, app.password.clone(), app.identity_id())?;
            if session.credential().id() != app.session.credential().id() {
                return Err("password_change_unavailable".into());
            }
            let after = session.seal(password.clone())?;
            entries.push(Entry {
                path,
                before: STANDARD.encode(before),
                after: STANDARD.encode(after),
            });
        }
        Ok(Self {
            version: 1,
            identity: app.identity_id(),
            entries,
        })
    }

    fn validate(&self, root: &Path, session: &Session) -> Result<()> {
        if self.version != 1
            || self.identity != session.identity_id()
            || self.entries.is_empty()
            || self.entries.len() > MAX_VAULTS
            || self.entries[0].path != "vault.age"
        {
            return Err(RECOVERY_REQUIRED.into());
        }
        let mut paths = BTreeSet::new();
        for entry in &self.entries {
            if !paths.insert(&entry.path) {
                return Err(RECOVERY_REQUIRED.into());
            }
            let path = destination(root, &entry.path)?;
            let current = vault::read_private(&path)?;
            let before = STANDARD.decode(&entry.before)?;
            let after = STANDARD.decode(&entry.after)?;
            if current != before && current != after {
                return Err(RECOVERY_REQUIRED.into());
            }
        }
        Ok(())
    }

    fn save(&self, root: &Path, session: &Session) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(self)?);
        let bytes = crypto::seal_bytes(&plain, &[session.age_identity().to_public()], MAX_JOURNAL)?;
        vault::write_private(&root.join(JOURNAL), &bytes, false)?;
        Ok(())
    }

    // Children first, root last: a crash leaves an unambiguous old/new commit point.
    fn install(&self, root: &Path, forward: bool, fail_after: Option<usize>) -> Result<()> {
        for (index, entry) in self
            .entries
            .iter()
            .skip(1)
            .chain(self.entries.first())
            .enumerate()
        {
            if fail_after == Some(index) {
                return Err("synthetic password change interruption".into());
            }
            let path = destination(root, &entry.path)?;
            let bytes = STANDARD.decode(if forward { &entry.after } else { &entry.before })?;
            if vault::read_private(&path)? != bytes {
                vault::write_private(&path, &bytes, true)?;
            }
        }
        Ok(())
    }
}

fn remove_journal(root: &Path) -> Result<()> {
    fs::remove_file(root.join(JOURNAL))?;
    #[cfg(unix)]
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

pub(super) fn recover_interrupted_change(
    root: &Path,
    session: &Session,
    password: &SecretString,
) -> Result<()> {
    let path = root.join(JOURNAL);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let bytes = vault::read_private_bounded(&path, MAX_JOURNAL + 4096)?;
    let plain = Zeroizing::new(crypto::open_bytes(
        &bytes,
        session.age_identity(),
        MAX_JOURNAL,
    )?);
    let journal: Journal = serde_json::from_slice(&plain)?;
    let _child_locks = child_locks(
        root,
        &journal
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>(),
        &BTreeSet::new(),
    )?;
    journal.validate(root, session)?;
    let root_vault = vault::read_private(&root.join("vault.age"))?;
    let forward = root_vault == STANDARD.decode(&journal.entries[0].after)?;
    // Validate every selected vault before repairing any file. A journal cannot
    // redirect writes or install a vault for another identity or device.
    for entry in &journal.entries {
        let bytes = STANDARD.decode(if forward { &entry.after } else { &entry.before })?;
        let restored = Session::open(&bytes, password.clone(), session.identity_id())?;
        if restored.credential().id() != session.credential().id() {
            return Err(RECOVERY_REQUIRED.into());
        }
    }
    journal.install(root, forward, None)?;
    remove_journal(root)
}

impl ClientApp {
    /// Changes only this local profile's password; identity and device keys stay intact.
    /// A caller must lock this instance if `password_change_recovery_required` is returned.
    pub fn change_password(&mut self, current: SecretString, password: SecretString) -> Result<()> {
        self.change_password_inner(current, password, None)
    }

    fn change_password_inner(
        &mut self,
        current: SecretString,
        password: SecretString,
        fail_after: Option<usize>,
    ) -> Result<()> {
        if !self.password_matches(&current) {
            return Err("password_change_incorrect".into());
        }
        vault::validate_new_password(&password)?;
        if self.password_matches(&password) {
            return Err("password_change_unchanged".into());
        }
        // A live instance must never mutate files from an unfinished transaction.
        if fs::symlink_metadata(self.directory.join(JOURNAL)).is_ok() {
            return Err(RECOVERY_REQUIRED.into());
        }
        let paths = vault_paths(&self.directory)?;
        let owned = self
            .spaces
            .as_ref()
            .map(|spaces| {
                spaces
                    .children()
                    .values()
                    .map(|child| child.directory.clone())
                    .collect()
            })
            .unwrap_or_default();
        let _child_locks = child_locks(&self.directory, &paths, &owned)?;
        let journal = Journal::prepare(self, &password, paths)?;
        if let Err(error) = journal.save(&self.directory, &self.session) {
            if self.directory.join(JOURNAL).exists() && remove_journal(&self.directory).is_err() {
                return Err(RECOVERY_REQUIRED.into());
            }
            return Err(error);
        }
        let installed = journal
            .install(&self.directory, true, fail_after)
            .and_then(|()| remove_journal(&self.directory));
        if let Err(error) = installed {
            // The root may already have switched when directory sync failed.
            // Keep a durable journal until the complete rollback is finished.
            if !self.directory.join(JOURNAL).exists()
                && journal.save(&self.directory, &self.session).is_err()
            {
                return Err(RECOVERY_REQUIRED.into());
            }
            if journal.install(&self.directory, false, None).is_err()
                || remove_journal(&self.directory).is_err()
            {
                return Err(RECOVERY_REQUIRED.into());
            }
            return Err(error);
        }
        self.set_local_password(&password);
        Ok(())
    }

    fn set_local_password(&mut self, password: &SecretString) {
        self.password = password.clone();
        if let Some(spaces) = &mut self.spaces {
            for child in spaces.children_mut().values_mut() {
                child.set_local_password(password);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "meadow tungsten orbit marzipan";
    const NEW: &str = "saffron badger telescope orchard";

    async fn profile(path: PathBuf) -> ClientApp {
        ProfileDraft::new()
            .unwrap()
            .save(path, OLD.into(), "General")
            .await
            .unwrap()
    }

    fn child_vault(app: &ClientApp, id: u8) -> PathBuf {
        let path = app
            .directory
            .join("spaces")
            .join(record::encode_hex(&[id; 32]));
        fs::create_dir_all(&path).unwrap();
        let session = app.session.isolated_space();
        vault::write_private(
            &path.join("vault.age"),
            &session.seal(OLD.into()).unwrap(),
            false,
        )
        .unwrap();
        vault::write_private(
            &path.join("profile.json"),
            &serde_json::to_vec(&json!({
                "identity_id": session.identity_id(), "credential_id": session.credential().id()
            }))
            .unwrap(),
            false,
        )
        .unwrap();
        path
    }

    #[tokio::test]
    async fn validation_leaves_the_current_vault_and_password_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = profile(temp.path().join("profile")).await;
        let before = vault::read_private(&app.directory.join("vault.age")).unwrap();
        assert_eq!(
            app.change_password("incorrect current password".into(), NEW.into())
                .unwrap_err()
                .to_string(),
            "password_change_incorrect"
        );
        assert_eq!(
            app.change_password(OLD.into(), "short".into())
                .unwrap_err()
                .to_string(),
            "passphrase must contain 12..=1024 UTF-8 bytes"
        );
        assert_eq!(
            app.change_password(OLD.into(), "aaaaaaaaaaaa".into())
                .unwrap_err()
                .to_string(),
            "profile_password_weak"
        );
        assert_eq!(
            app.change_password(OLD.into(), OLD.into())
                .unwrap_err()
                .to_string(),
            "password_change_unchanged"
        );
        assert!(app.password_matches(&OLD.into()));
        assert_eq!(
            vault::read_private(&app.directory.join("vault.age")).unwrap(),
            before
        );
        assert!(!app.directory.join(JOURNAL).exists());
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn rotation_preserves_history_identity_controls_and_all_space_vaults() {
        let temp = tempfile::tempdir().unwrap();
        let draft = ProfileDraft::new().unwrap();
        let path = temp.path().join("profile");
        let mut app = draft
            .save(path.clone(), OLD.into(), "General")
            .await
            .unwrap();
        let other_path = temp.path().join("other-device");
        let other = draft
            .save(other_path.clone(), OLD.into(), "General")
            .await
            .unwrap();
        let other_vault = vault::read_private(&other_path.join("vault.age")).unwrap();
        let identity = app.identity_id();
        let credential = app.session.credential().id();
        let recipient = app.session.age_identity().to_public();
        let mode = app.session.controller_mode();
        let pin = app.pins[0].clone();
        app.operate(json!({"op":"send", "space":pin.space, "stream":pin.stream,
            "text":"Preserve this message across a local password change", "created_at":"2026-10-06T12:00:00Z"})).await.unwrap();
        let messages = app.originals(&app.authorities.0[0]).await.unwrap();
        assert!(!messages.is_empty());
        let workspace = vault::read_private(&path.join("workspace.age")).unwrap();
        let loaded_path = child_vault(&app, 11);
        let unopened_path = child_vault(&app, 12);
        let child = ClientApp::open(loaded_path.clone(), OLD.into(), false)
            .await
            .unwrap();
        app.enable_spaces().await.unwrap();
        app.spaces
            .as_mut()
            .unwrap()
            .children_mut()
            .insert(record::encode_hex(&[11; 32]), child);
        app.change_password(OLD.into(), NEW.into()).unwrap();
        assert!(app.password_matches(&NEW.into()));
        assert!(!app.password_matches(&OLD.into()));
        let child = &app.spaces.as_ref().unwrap().children()[&record::encode_hex(&[11; 32])];
        assert!(child.password_matches(&NEW.into()));
        // Later writes must not silently reintroduce the old password.
        child.persist_vault().unwrap();
        app.persist_vault().unwrap();
        assert_eq!(
            vault::read_private(&path.join("workspace.age")).unwrap(),
            workspace
        );
        assert_eq!(
            vault::read_private(&other_path.join("vault.age")).unwrap(),
            other_vault
        );
        assert!(other.password_matches(&OLD.into()));
        for child_path in [loaded_path, unopened_path] {
            let bytes = vault::read_private(&child_path.join("vault.age")).unwrap();
            assert!(Session::open(&bytes, OLD.into(), identity).is_err());
            assert_eq!(
                Session::open(&bytes, NEW.into(), identity)
                    .unwrap()
                    .credential()
                    .id(),
                credential
            );
        }
        app.close().await.unwrap();
        assert!(
            ClientApp::open(path.clone(), OLD.into(), false)
                .await
                .is_err()
        );
        let reopened = ClientApp::open(path, NEW.into(), false).await.unwrap();
        assert_eq!(reopened.identity_id(), identity);
        assert_eq!(reopened.session.credential().id(), credential);
        assert_eq!(reopened.session.age_identity().to_public(), recipient);
        assert!(reopened.session.controller_mode() == mode);
        let restored = reopened
            .originals(&reopened.authorities.0[0])
            .await
            .unwrap();
        assert_eq!(restored.len(), messages.len());
        assert_eq!(restored[0].0.bytes(), messages[0].0.bytes());
        reopened.close().await.unwrap();
        other.close().await.unwrap();
    }

    #[tokio::test]
    async fn a_failed_child_commit_rolls_back_every_vault() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = profile(temp.path().join("profile")).await;
        let child = child_vault(&app, 21);
        let root_before = vault::read_private(&app.directory.join("vault.age")).unwrap();
        let child_before = vault::read_private(&child.join("vault.age")).unwrap();
        assert!(
            app.change_password_inner(OLD.into(), NEW.into(), Some(1))
                .is_err()
        );
        assert_eq!(
            vault::read_private(&app.directory.join("vault.age")).unwrap(),
            root_before
        );
        assert_eq!(
            vault::read_private(&child.join("vault.age")).unwrap(),
            child_before
        );
        assert!(app.password_matches(&OLD.into()));
        assert!(!app.directory.join(JOURNAL).exists());
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn interrupted_replacement_recovers_using_the_root_commit_point() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profile");
        let app = profile(path.clone()).await;
        let child = child_vault(&app, 31);
        let journal = Journal::prepare(&app, &NEW.into(), vault_paths(&path).unwrap()).unwrap();
        journal.save(&path, &app.session).unwrap();
        assert!(journal.install(&path, true, Some(1)).is_err());
        app.close().await.unwrap();
        // Before the root commit, the old password repairs the changed child.
        let app = ClientApp::open(path.clone(), OLD.into(), false)
            .await
            .unwrap();
        assert_eq!(
            vault::read_private(&child.join("vault.age")).unwrap(),
            STANDARD.decode(&journal.entries[1].before).unwrap()
        );
        assert!(!path.join(JOURNAL).exists());
        journal.save(&path, &app.session).unwrap();
        journal.install(&path, true, None).unwrap();
        app.close().await.unwrap();
        assert!(
            ClientApp::open(path.clone(), OLD.into(), false)
                .await
                .is_err()
        );
        // After the root commit, the new password completes cleanup.
        let app = ClientApp::open(path.clone(), NEW.into(), false)
            .await
            .unwrap();
        assert_eq!(
            vault::read_private(&child.join("vault.age")).unwrap(),
            STANDARD.decode(&journal.entries[1].after).unwrap()
        );
        assert!(!path.join(JOURNAL).exists());
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn another_open_cannot_recover_a_live_password_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profile");
        let app = profile(path.clone()).await;
        let child = child_vault(&app, 35);
        let journal = Journal::prepare(&app, &NEW.into(), vault_paths(&path).unwrap()).unwrap();
        journal.save(&path, &app.session).unwrap();
        assert!(journal.install(&path, true, Some(1)).is_err());
        let changed_child = vault::read_private(&child.join("vault.age")).unwrap();
        let error = ClientApp::open(path.clone(), OLD.into(), false)
            .await
            .err()
            .unwrap();
        assert!(
            error
                .downcast_ref::<crate::store::StoreError>()
                .is_some_and(|error| matches!(error, crate::store::StoreError::AlreadyOpen))
        );
        assert!(path.join(JOURNAL).exists());
        assert_eq!(
            vault::read_private(&child.join("vault.age")).unwrap(),
            changed_child
        );
        app.close().await.unwrap();
        let reopened = ClientApp::open(path, OLD.into(), false).await.unwrap();
        reopened.close().await.unwrap();
    }

    #[tokio::test]
    async fn a_prepared_session_cannot_restore_an_obsolete_password() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profile");
        let mut app = profile(path.clone()).await;
        let encrypted = vault::read_private(&path.join("vault.age")).unwrap();
        let session = Session::open(&encrypted, OLD.into(), app.identity_id()).unwrap();
        app.change_password(OLD.into(), NEW.into()).unwrap();
        app.close().await.unwrap();
        let error = ClientApp::open_session(path.clone(), OLD.into(), false, session, encrypted)
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "profile_changed_while_opening");
        assert!(
            ClientApp::open(path.clone(), OLD.into(), false)
                .await
                .is_err()
        );
        let reopened = ClientApp::open(path, NEW.into(), false).await.unwrap();
        reopened.close().await.unwrap();
    }

    #[tokio::test]
    async fn an_independently_open_space_prevents_rotation_without_mutating_any_vault() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = profile(temp.path().join("profile")).await;
        let child_path = child_vault(&app, 36);
        let child = ClientApp::open(child_path.clone(), OLD.into(), false)
            .await
            .unwrap();
        let root_before = vault::read_private(&app.directory.join("vault.age")).unwrap();
        let child_before = vault::read_private(&child_path.join("vault.age")).unwrap();
        assert!(app.change_password(OLD.into(), NEW.into()).is_err());
        assert_eq!(
            vault::read_private(&app.directory.join("vault.age")).unwrap(),
            root_before
        );
        assert_eq!(
            vault::read_private(&child_path.join("vault.age")).unwrap(),
            child_before
        );
        assert!(!app.directory.join(JOURNAL).exists());
        child.close().await.unwrap();
        app.change_password(OLD.into(), NEW.into()).unwrap();
        app.close().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn space_symlinks_are_rejected_without_touching_external_vaults() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = profile(temp.path().join("profile")).await;
        let outside = profile(temp.path().join("outside")).await;
        let before = vault::read_private(&outside.directory.join("vault.age")).unwrap();
        fs::create_dir(app.directory.join("spaces")).unwrap();
        std::os::unix::fs::symlink(
            &outside.directory,
            app.directory
                .join("spaces")
                .join(record::encode_hex(&[41; 32])),
        )
        .unwrap();
        assert!(app.change_password(OLD.into(), NEW.into()).is_err());
        assert_eq!(
            vault::read_private(&outside.directory.join("vault.age")).unwrap(),
            before
        );
        assert!(app.password_matches(&OLD.into()));
        assert!(!app.directory.join(JOURNAL).exists());
        app.close().await.unwrap();
        outside.close().await.unwrap();
    }
}

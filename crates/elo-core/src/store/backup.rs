//! Message backups copy selected rows, never attachment pages or deleted remnants.
use super::*;
use std::collections::BTreeMap;

// Dependency order matters while foreign keys remain enabled. Retain signed
// file.shared messages; sent file.body objects and unindexed download caches
// are excluded. Keep transport observations only for included ciphertexts.
// For composite indexes, correlate the second membership check with EXISTS.
// Two IN loops can enumerate every kept record/object pair before checking the
// source index, making bounded exports quadratic in the retained history.
const TABLES: &[(&str, &str)] = &[
    (
        "objects",
        "WHERE object_id IN (SELECT object_id FROM main.record_sources WHERE record_id IN (SELECT record_id FROM elo_selection.keep))",
    ),
    (
        "records",
        "WHERE record_id IN (SELECT record_id FROM elo_selection.keep)",
    ),
    (
        "record_sources",
        "WHERE record_id IN (SELECT record_id FROM elo_backup.records) AND EXISTS (SELECT 1 FROM elo_backup.objects AS kept WHERE kept.object_id = main.record_sources.object_id)",
    ),
    (
        "outbox",
        "WHERE object_id IN (SELECT object_id FROM elo_backup.objects) AND EXISTS (SELECT 1 FROM elo_backup.records AS kept WHERE kept.record_id = main.outbox.record_id)",
    ),
    ("stream_heads", ""),
    ("peer_cursors", ""),
    (
        "inbox",
        "WHERE object_id IN (SELECT object_id FROM elo_backup.objects)",
    ),
    ("authority_snapshots", ""),
    ("used_invites", ""),
    ("replica_scans", ""),
    (
        "replica_copies",
        "WHERE object_id IN (SELECT object_id FROM elo_backup.objects)",
    ),
    ("message_audit_meta", ""),
    (
        "message_audit",
        "WHERE record_id IN (SELECT record_id FROM elo_backup.records)",
    ),
    (
        "notification_outbox",
        "WHERE record_id IN (SELECT record_id FROM elo_backup.records) AND EXISTS (SELECT 1 FROM elo_backup.objects AS kept WHERE kept.object_id = main.notification_outbox.object_id)",
    ),
];

impl ClientStore {
    /// A committed-WAL snapshot for recovery, without sent/received file bodies.
    /// The writer serializes access; the source database is never modified.
    pub async fn message_backup_image(&self, maximum: usize) -> Result<Vec<u8>> {
        self.selected_message_backup_image(maximum, None).await
    }

    pub(crate) async fn selected_message_backup_image(
        &self,
        maximum: usize,
        records: Option<Vec<RecordId>>,
    ) -> Result<Vec<u8>> {
        self.call(move |connection| {
            let schema = read_schema(connection)?;
            let tables = schema
                .iter()
                .filter(|entry| entry.0 == "table")
                .map(|entry| entry.1.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if tables != TABLES.iter().map(|entry| entry.0).collect() {
                // A new table needs an explicit backup policy before copying it.
                return Err(StoreError::UnrecognizedSchema);
            }
            if maximum < 4096 {
                return Err(StoreError::BackupTooLarge);
            }
            connection.execute("ATTACH DATABASE ':memory:' AS elo_selection", [])?;
            let result: Result<Vec<u8>> = (|| {
                connection.execute("CREATE TABLE elo_selection.keep(record_id TEXT PRIMARY KEY) WITHOUT ROWID", [])?;
                match records {
                    Some(records) => {
                        let transaction = connection.transaction()?;
                        {
                            let mut insert = transaction.prepare("INSERT OR IGNORE INTO elo_selection.keep VALUES(?1)")?;
                            for record in records { insert.execute([record.to_string()])?; }
                        }
                        transaction.commit()?;
                    }
                    None => { connection.execute("INSERT INTO elo_selection.keep SELECT record_id FROM records WHERE kind != 'file.body'", [])?; }
                }
                connection.execute("ATTACH DATABASE ':memory:' AS elo_backup", [])?;
                let result = copy_messages(connection, &schema, maximum);
                let detached = connection.execute("DETACH DATABASE elo_backup", []);
                let image = result?;
                detached?;
                Ok(image)
            })();
            // Detach on errors too, so a failed/oversized backup cannot leave a
            // second database attached to the live profile worker.
            let detached = connection.execute("DETACH DATABASE elo_selection", []);
            let image = result?;
            detached?;
            Ok(image)
        })
        .await
    }
}

fn copy_messages(
    connection: &mut Connection,
    schema: &[SchemaEntry],
    maximum: usize,
) -> Result<Vec<u8>> {
    connection.execute_batch(&format!(
        "PRAGMA elo_backup.page_size=4096; PRAGMA elo_backup.max_page_count={};",
        maximum / 4096
    ))?;
    let result = (|| {
        let transaction = connection.transaction()?;
        for kind in ["table", "index", "trigger"] {
            let prefix = format!("CREATE {} ", kind.to_uppercase());
            for entry in schema.iter().filter(|entry| entry.0 == kind) {
                let sql = entry.3.as_ref().ok_or(StoreError::UnrecognizedSchema)?;
                let definition = sql
                    .strip_prefix(&prefix)
                    .ok_or(StoreError::UnrecognizedSchema)?;
                // SQLite stores the original definition without the schema
                // qualifier, preserving exact-schema validation on restore.
                transaction.execute_batch(&format!("{prefix}elo_backup.{definition}"))?;
            }
        }
        for (table, filter) in TABLES {
            transaction.execute(
                &format!("INSERT INTO elo_backup.{table} SELECT * FROM main.{table} {filter}"),
                [],
            )?;
        }
        transaction.execute_batch(&format!("PRAGMA elo_backup.user_version={SCHEMA_VERSION}"))?;
        if transaction
            .prepare("PRAGMA elo_backup.foreign_key_check")?
            .query([])?
            .next()?
            .is_some()
        {
            return Err(StoreError::UnrecognizedSchema);
        }
        transaction.commit()?;
        let image = connection.serialize("elo_backup")?;
        if image.len() > maximum {
            return Err(StoreError::BackupTooLarge);
        }
        Ok(image.to_vec())
    })();
    match result {
        Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(error, _)))
            if error.code == rusqlite::ErrorCode::DiskFull =>
        {
            Err(StoreError::BackupTooLarge)
        }
        result => result,
    }
}

/// Ciphertexts and signed history grants are indivisible. Actions travel with
/// their target, so trimming cannot resurrect an old reaction or pin state.
pub(crate) struct MessageBackupGroup {
    pub records: Vec<RecordId>,
    pub newest: (i64, RecordId),
    pub messages: usize,
}

pub(crate) struct MessageBackupPlan {
    pub required: Vec<RecordId>,
    pub groups: Vec<MessageBackupGroup>,
}

impl ClientStore {
    /// Only identifiers/timestamps enter this transient plan. The caller has
    /// verified action targets using the profile keys; nothing is indexed on disk.
    pub(crate) async fn message_backup_plan(
        &self,
        action_targets: Vec<(RecordId, RecordId)>,
    ) -> Result<MessageBackupPlan> {
        self.call(move |connection| {
            let mut records = Vec::new();
            let mut indices = BTreeMap::new();
            let mut statement = connection.prepare(
                "SELECT record_id, kind, first_seen_local_ms FROM records WHERE kind != 'file.body' ORDER BY record_id",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let id = row.get::<_, String>(0)?.parse::<RecordId>()?;
                indices.insert(id, records.len());
                records.push((id, row.get::<_, String>(1)?, row.get::<_, i64>(2)?));
            }
            let mut parents: Vec<_> = (0..records.len()).collect();
            let mut previous_object = None;
            let mut statement = connection.prepare(
                "SELECT record_id, object_id FROM record_sources ORDER BY object_id, record_id",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let id = row.get::<_, String>(0)?.parse::<RecordId>()?;
                let Some(&index) = indices.get(&id) else { continue };
                let object: String = row.get(1)?;
                if let Some((previous, old_index)) = &previous_object
                    && *previous == object {
                    merge(&mut parents, *old_index, index);
                }
                previous_object = Some((object, index));
            }
            for (action, target) in action_targets {
                if let (Some(&a), Some(&b)) = (indices.get(&action), indices.get(&target)) {
                    merge(&mut parents, a, b);
                }
            }
            let mut groups: BTreeMap<usize, (MessageBackupGroup, bool)> = BTreeMap::new();
            for (index, (id, kind, time)) in records.into_iter().enumerate() {
                let is_message = matches!(kind.as_str(), "chat.message" | "file.shared");
                let required = !matches!(kind.as_str(), "chat.message" | "file.shared" | "chat.action" | "history.access.granted");
                let (group, essential) = groups.entry(root(&mut parents, index)).or_insert_with(|| (
                    MessageBackupGroup { records: Vec::new(), newest: (time, id), messages: 0 }, false,
                ));
                // Use the newest message's local receipt/creation time, never a
                // later reaction time, to rank an indivisible group. Local time
                // matches the history window and avoids trusting sender clocks.
                if is_message && group.messages == 0 {
                    group.newest = (time, id);
                } else if is_message || group.messages == 0 {
                    group.newest = group.newest.max((time, id));
                }
                group.messages += usize::from(is_message);
                group.records.push(id);
                *essential |= required;
            }
            let mut plan = MessageBackupPlan { required: Vec::new(), groups: Vec::new() };
            for (group, required) in groups.into_values() {
                if required { plan.required.extend(group.records); }
                else { plan.groups.push(group); }
            }
            Ok(plan)
        }).await
    }
}

fn root(parents: &mut [usize], mut index: usize) -> usize {
    while parents[index] != index {
        parents[index] = parents[parents[index]];
        index = parents[index];
    }
    index
}

fn merge(parents: &mut [usize], left: usize, right: usize) {
    let left = root(parents, left);
    let right = root(parents, right);
    // Stable representative and path compression keep overlapping grants cheap.
    parents[left.max(right)] = left.min(right);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn retention_plan_keeps_history_bundles_and_action_targets_together() {
        let temp = tempfile::tempdir().unwrap();
        let store = ClientStore::open(temp.path().join("source")).await.unwrap();
        let mut ids = Vec::new();
        let mut objects = Vec::new();
        for (n, (kind, time)) in [
            ("space.genesis", 0),
            ("chat.message", 100),
            ("chat.message", 300),
            ("chat.message", 50),
            ("chat.action", 1000),
            ("history.access.granted", 500),
            ("file.body", 600),
            ("file.shared", 400),
        ]
        .into_iter()
        .enumerate()
        {
            let id: RecordId = format!("{:064x}", n + 1).parse().unwrap();
            let cipher = vec![n as u8; 1024];
            objects.push(ObjectId::of_ciphertext(&cipher));
            ids.push(id);
            store
                .commit_local_record_with_outbox(
                    PreparedLocalRecord::new(
                        id,
                        cipher,
                        RecordMetadata::new(kind, None, None, None).unwrap(),
                        vec![],
                        LocalTime::from_millis(time).unwrap(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        let old = ids[1];
        let newer = ids[2];
        let grant = objects[5];
        store
            .call(move |connection| {
                connection.execute(
                    "INSERT INTO record_sources VALUES(?1,?2,0)",
                    params![old.to_string(), grant.to_string()],
                )?;
                connection.execute(
                    "INSERT INTO record_sources VALUES(?1,?2,1)",
                    params![newer.to_string(), grant.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let original = store.backup_image(1024 * 1024).await.unwrap();
        let plan = store
            .message_backup_plan(vec![(ids[4], ids[1])])
            .await
            .unwrap();
        assert_eq!(plan.required, vec![ids[0]]);
        assert_eq!(plan.groups.len(), 3);
        let bundle = plan
            .groups
            .iter()
            .find(|g| g.records.contains(&ids[5]))
            .unwrap();
        assert_eq!(bundle.records, vec![ids[1], ids[2], ids[4], ids[5]]);
        assert_eq!(bundle.newest, (300, ids[2]));
        assert_eq!(bundle.messages, 2);
        let mut keep = plan.required.clone();
        for group in plan.groups.iter().filter(|g| g.newest.0 >= 300) {
            keep.extend(&group.records);
        }
        let image = store
            .selected_message_backup_image(1024 * 1024, Some(keep))
            .await
            .unwrap();
        let path = temp.path().join("restored");
        std::fs::create_dir(&path).unwrap();
        private_file(&path.join("client.sqlite"))
            .unwrap()
            .write_all(&image)
            .unwrap();
        let restored = ClientStore::open(path).await.unwrap();
        assert_eq!(restored.stats().await.unwrap().records, 6);
        assert!(restored.get_object(objects[3]).await.unwrap().is_none());
        assert!(restored.get_object(objects[6]).await.unwrap().is_none());
        for i in [0, 1, 2, 4, 5, 7] {
            assert_eq!(
                restored.get_object(objects[i]).await.unwrap(),
                store.get_object(objects[i]).await.unwrap()
            );
        }
        assert_eq!(store.backup_image(1024 * 1024).await.unwrap(), original);
        restored.close().await.unwrap();
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn message_backup_omits_sent_bodies_and_download_cache_without_touching_source() {
        let temp = tempfile::tempdir().unwrap();
        let store = ClientStore::open(temp.path().join("source")).await.unwrap();
        let now = LocalTime::from_millis(1).unwrap();
        let target = DeliveryTarget {
            peer_id: "11".repeat(32).parse().unwrap(),
            mailbox_id: "22".repeat(32).parse().unwrap(),
        };
        let mut objects = Vec::new();
        for (i, (kind, size)) in [
            ("chat.message", 512),
            ("file.shared", 512),
            ("file.body", 2 * 1024 * 1024),
        ]
        .into_iter()
        .enumerate()
        {
            // Synthetic opaque bytes exercise storage/export, not signatures.
            let ciphertext = vec![b'A' + i as u8; size];
            let object = ObjectId::of_ciphertext(&ciphertext);
            store
                .commit_local_record_with_outbox(
                    PreparedLocalRecord::new(
                        format!("{:064x}", i + 1).parse().unwrap(),
                        ciphertext.clone(),
                        RecordMetadata::new(kind, None, None, None).unwrap(),
                        vec![target],
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            objects.push((object, ciphertext));
        }
        // Explicit incoming downloads are cached without a file.body record.
        let downloaded = vec![b'D'; 2 * 1024 * 1024];
        let download = ObjectId::of_ciphertext(&downloaded);
        store
            .cache_repair_object(download, downloaded.clone(), now)
            .await
            .unwrap();
        let original = store.backup_image(8 * 1024 * 1024).await.unwrap();
        assert!(store.backup_image(1024 * 1024).await.is_err());
        assert!(store.message_backup_image(4096).await.is_err());
        let image = store.message_backup_image(1024 * 1024).await.unwrap();
        assert!(image.len() < 1024 * 1024);
        for byte in *b"CD" {
            assert!(
                !image
                    .windows(1024)
                    .any(|window| window.iter().all(|b| *b == byte))
            );
        }
        assert_eq!(store.backup_image(8 * 1024 * 1024).await.unwrap(), original);
        assert_eq!(store.get_object(download).await.unwrap(), Some(downloaded));
        assert_eq!(
            store.get_object(objects[2].0).await.unwrap().as_ref(),
            Some(&objects[2].1)
        );
        let directory = temp.path().join("restored");
        std::fs::create_dir(&directory).unwrap();
        private_file(&directory.join("client.sqlite"))
            .unwrap()
            .write_all(&image)
            .unwrap();
        let restored = ClientStore::open(&directory).await.unwrap();
        assert_eq!(restored.stats().await.unwrap().records, 2);
        assert_eq!(restored.stats().await.unwrap().pending, 2);
        assert_eq!(
            restored.get_object(objects[0].0).await.unwrap().as_ref(),
            Some(&objects[0].1)
        );
        assert_eq!(
            restored.get_object(objects[1].0).await.unwrap().as_ref(),
            Some(&objects[1].1)
        );
        assert!(restored.get_object(objects[2].0).await.unwrap().is_none());
        assert!(restored.get_object(download).await.unwrap().is_none());
        restored.close().await.unwrap();
        store.close().await.unwrap();
    }
    #[test]
    fn backup_membership_filters_have_bounded_work_and_keep_only_matching_pairs() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("\
            CREATE TABLE record_sources(record_id TEXT, object_id TEXT, PRIMARY KEY(record_id,object_id));
            CREATE TABLE outbox(object_id TEXT PRIMARY KEY,record_id TEXT);
            CREATE TABLE notification_outbox(record_id TEXT PRIMARY KEY,object_id TEXT);
            ATTACH DATABASE ':memory:' AS elo_backup;
            CREATE TABLE elo_backup.records(record_id TEXT PRIMARY KEY);
            CREATE TABLE elo_backup.objects(object_id TEXT PRIMARY KEY);
            CREATE TABLE elo_backup.record_sources(record_id TEXT,object_id TEXT,PRIMARY KEY(record_id,object_id));
            CREATE TABLE elo_backup.outbox(object_id TEXT PRIMARY KEY,record_id TEXT);
            CREATE TABLE elo_backup.notification_outbox(record_id TEXT PRIMARY KEY,object_id TEXT);
            WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<1024)
              INSERT INTO record_sources SELECT printf('r%04d',v),printf('o%04d',v) FROM n;
            INSERT INTO outbox SELECT object_id,record_id FROM record_sources;
            INSERT INTO notification_outbox SELECT * FROM record_sources;
            INSERT INTO elo_backup.records SELECT record_id FROM record_sources WHERE CAST(substr(record_id,2) AS INTEGER)%2=0;
            INSERT INTO elo_backup.objects SELECT object_id FROM record_sources WHERE CAST(substr(record_id,2) AS INTEGER)%3=0;
        ").unwrap();
        for (table, filter) in TABLES.iter().filter(|(table, _)| {
            matches!(*table, "record_sources" | "outbox" | "notification_outbox")
        }) {
            let mut statement = connection
                .prepare(&format!(
                    "INSERT INTO elo_backup.{table} SELECT * FROM main.{table} {filter}"
                ))
                .unwrap();
            assert_eq!(statement.execute([]).unwrap(), 1024 / 6);
            // VM instructions are deterministic work, independent of host load.
            // The former two-IN composite-index plan exceeds this by enumerating
            // retained record/object combinations instead of source rows.
            assert!(
                statement.get_status(rusqlite::StatementStatus::VmStep) < 100_000,
                "{table} performs excessive backup work"
            );
            let invalid: i64=connection.query_row(&format!("SELECT count(*) FROM elo_backup.{table} WHERE CAST(substr(record_id,2) AS INTEGER)%6!=0"),[],|r|r.get(0)).unwrap();
            assert_eq!(invalid, 0);
        }
    }
}

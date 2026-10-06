//! Message backups copy selected rows, never attachment pages or deleted remnants.
use super::*;
use std::collections::BTreeMap;

// Dependency order matters while foreign keys remain enabled. Retain signed
// file.shared messages; sent file.body objects and unindexed download caches
// are excluded. Keep transport observations only for included ciphertexts.
// For composite indexes, correlate the second membership check with EXISTS.
// Two IN loops can enumerate every kept record/object pair before checking the
// source index, making bounded exports quadratic in the retained history.
// Applied private settings already live in the encrypted read-state snapshot.
// Unprocessed events and unfinished deliveries must survive a profile backup.
const REDUNDANT_PRIVATE_SETTINGS: &str = "kind='chat.private-settings'
    AND record_id IN (SELECT record_id FROM private_settings_inbox WHERE sequence<=?1)
    AND record_id NOT IN (SELECT record_id FROM outbox WHERE state!='STORED')";

const TABLES: &[(&str, &str)] = &[
    ("local_chat_deletions", "WHERE 0"),
    ("local_deleted_records", "WHERE 0"),
    ("local_deleted_targets", "WHERE 0"),
    ("local_deleted_objects", "WHERE 0"),
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
    (
        "private_settings_inbox",
        "WHERE record_id IN (SELECT record_id FROM elo_backup.records)",
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
    (
        "message_locators",
        "WHERE locator_record_id IN (SELECT record_id FROM elo_backup.records)",
    ),
];

impl ClientStore {
    /// A committed-WAL snapshot for recovery, without sent/received file bodies.
    /// The writer serializes access; the source database is never modified.
    pub async fn message_backup_image(&self, maximum: usize) -> Result<Vec<u8>> {
        self.selected_message_backup_image(maximum, None, 0).await
    }

    pub(crate) async fn selected_message_backup_image(
        &self,
        maximum: usize,
        records: Option<Vec<RecordId>>,
        private_settings_cursor: i64,
    ) -> Result<Vec<u8>> {
        self.transfer_image(maximum, records, private_settings_cursor, false)
            .await
    }

    pub(crate) async fn local_content_backup_image(&self, maximum: usize) -> Result<Vec<u8>> {
        self.transfer_image(maximum, None, 0, true).await
    }

    async fn transfer_image(
        &self,
        maximum: usize,
        records: Option<Vec<RecordId>>,
        private_settings_cursor: i64,
        include_files: bool,
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
                    None => { connection.execute("INSERT INTO elo_selection.keep SELECT record_id FROM records WHERE ?1 OR kind != 'file.body'", [include_files])?; }
                }
                connection.execute(
                    &format!("DELETE FROM elo_selection.keep WHERE record_id IN (SELECT record_id FROM records WHERE {REDUNDANT_PRIVATE_SETTINGS})"),
                    [private_settings_cursor],
                )?;
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
        for kind in ["table", "index"] {
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
        // The encrypted read-state cursor can exceed every retained inbox row.
        // Keep SQLite's high-water mark even when all applied events are omitted,
        // or newly received settings after restore would reuse consumed positions.
        transaction.execute("DELETE FROM elo_backup.sqlite_sequence", [])?;
        transaction.execute(
            "INSERT INTO elo_backup.sqlite_sequence SELECT * FROM main.sqlite_sequence",
            [],
        )?;
        // Install triggers after copying records: transport queue IDs in the
        // image must preserve their original sequence, not be regenerated.
        for entry in schema.iter().filter(|entry| entry.0 == "trigger") {
            let definition = entry
                .3
                .as_ref()
                .ok_or(StoreError::UnrecognizedSchema)?
                .strip_prefix("CREATE TRIGGER ")
                .ok_or(StoreError::UnrecognizedSchema)?;
            transaction.execute_batch(&format!("CREATE TRIGGER elo_backup.{definition}"))?;
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
        private_settings_cursor: i64,
    ) -> Result<MessageBackupPlan> {
        self.call(move |connection| {
            let mut records = Vec::new();
            let mut indices = BTreeMap::new();
            let mut statement = connection.prepare(
                &format!("SELECT record_id, kind, first_seen_local_ms FROM records WHERE kind != 'file.body' AND NOT ({REDUNDANT_PRIVATE_SETTINGS}) ORDER BY record_id"),
            )?;
            let mut rows = statement.query([private_settings_cursor])?;
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
            .message_backup_plan(vec![(ids[4], ids[1])], 0)
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
            .selected_message_backup_image(1024 * 1024, Some(keep), 0)
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
    async fn profile_backup_omits_applied_private_checkpoints_but_keeps_pending_and_cursor() {
        let temp = tempfile::tempdir().unwrap();
        let store = ClientStore::open(temp.path().join("source")).await.unwrap();
        let target = DeliveryTarget {
            peer_id: "11".repeat(32).parse().unwrap(),
            mailbox_id: "22".repeat(32).parse().unwrap(),
        };
        let ids: Vec<RecordId> = (1..=4)
            .map(|index| format!("{index:064x}").parse().unwrap())
            .collect();
        for (index, id) in ids.iter().enumerate() {
            // Opaque synthetic bytes exercise export retention, not signatures.
            let size = if index == 0 { 2 * 1024 * 1024 } else { 512 };
            store
                .commit_local_record_with_outbox(
                    PreparedLocalRecord::new(
                        *id,
                        vec![index as u8; size],
                        RecordMetadata::new("chat.private-settings", None, None, None).unwrap(),
                        if index < 3 { vec![target] } else { vec![] },
                        LocalTime::from_millis(index as u64).unwrap(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        let first = ids[0];
        let held = ids[2];
        store
            .call(move |connection| {
                connection.execute(
                    "UPDATE outbox SET state='STORED',receipt_record=X'01' WHERE record_id=?1",
                    [first.to_string()],
                )?;
                connection.execute(
                    "UPDATE outbox SET state='HELD_STALE_CONFIG' WHERE record_id=?1",
                    [held.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let original = store.backup_image(4 * 1024 * 1024).await.unwrap();
        assert!(store.message_backup_image(1024 * 1024).await.is_err());
        let plan = store.message_backup_plan(vec![], 3).await.unwrap();
        assert_eq!(plan.required, ids[1..]);
        assert!(plan.groups.is_empty());
        let image = store
            .selected_message_backup_image(1024 * 1024, None, 3)
            .await
            .unwrap();
        let directory = temp.path().join("with-pending");
        std::fs::create_dir(&directory).unwrap();
        private_file(&directory.join("client.sqlite"))
            .unwrap()
            .write_all(&image)
            .unwrap();
        let restored = ClientStore::open(&directory).await.unwrap();
        assert_eq!(restored.stats().await.unwrap().records, 3);
        let incoming = restored.private_settings_sources(3).await.unwrap();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].1.record, ids[3]);
        let retained: Vec<String> = restored
            .call(|connection| {
                Ok(connection
                    .prepare("SELECT state FROM outbox ORDER BY record_id")?
                    .query_map([], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?)
            })
            .await
            .unwrap();
        assert_eq!(retained, vec!["PENDING", "HELD_STALE_CONFIG"]);
        restored.close().await.unwrap();
        assert_eq!(store.backup_image(4 * 1024 * 1024).await.unwrap(), original);

        store
            .call(|connection| {
                connection.execute("UPDATE outbox SET state='STORED',receipt_record=X'01'", [])?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(
            store
                .message_backup_plan(vec![], 4)
                .await
                .unwrap()
                .required
                .is_empty()
        );
        let image = store
            .selected_message_backup_image(1024 * 1024, None, 4)
            .await
            .unwrap();
        let directory = temp.path().join("all-applied");
        std::fs::create_dir(&directory).unwrap();
        private_file(&directory.join("client.sqlite"))
            .unwrap()
            .write_all(&image)
            .unwrap();
        let restored = ClientStore::open(&directory).await.unwrap();
        assert_eq!(restored.stats().await.unwrap().records, 0);
        let next: RecordId = format!("{:064x}", 5).parse().unwrap();
        restored
            .commit_local_record_with_outbox(
                PreparedLocalRecord::new(
                    next,
                    vec![5; 512],
                    RecordMetadata::new("chat.private-settings", None, None, None).unwrap(),
                    vec![],
                    LocalTime::from_millis(5).unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let incoming = restored.private_settings_sources(4).await.unwrap();
        assert_eq!(
            incoming.len(),
            1,
            "new events must exceed the restored encrypted cursor"
        );
        assert_eq!(incoming[0].1.record, next);
        assert_eq!(incoming[0].0, 5);
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
    fn private_checkpoint_backup_filter_does_not_rescan_every_delivery_for_each_record() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("            CREATE TABLE records(record_id TEXT PRIMARY KEY,kind TEXT);
            CREATE TABLE private_settings_inbox(sequence INTEGER PRIMARY KEY,record_id TEXT UNIQUE);
            CREATE TABLE outbox(record_id TEXT,state TEXT);
            WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<1024)
              INSERT INTO records SELECT printf('r%04d',v),'chat.private-settings' FROM n;
            INSERT INTO private_settings_inbox SELECT CAST(substr(record_id,2) AS INTEGER),record_id FROM records;
            INSERT INTO outbox SELECT record_id,CASE WHEN CAST(substr(record_id,2) AS INTEGER)%2=0 THEN 'STORED' ELSE 'PENDING' END FROM records;
        ").unwrap();
        let mut statement = connection
            .prepare(&format!(
                "SELECT record_id FROM records WHERE {REDUNDANT_PRIVATE_SETTINGS}"
            ))
            .unwrap();
        let ids: Vec<String> = statement
            .query_map([512], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(ids.len(), 256);
        assert!(statement.get_status(rusqlite::StatementStatus::VmStep) < 100_000);
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

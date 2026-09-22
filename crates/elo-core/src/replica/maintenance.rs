use super::*;

/// Bound deletion-time work to 1024 free pages (normally 4 MiB). Live objects,
/// receipts and resurrection guards are never candidates for reclamation.
pub(super) fn reclaim(c: &Connection) -> Result<()> {
    let mut vacuum = c.prepare("PRAGMA incremental_vacuum(1024)")?;
    let mut rows = vacuum.query([])?;
    while rows.next()?.is_some() {}
    drop(rows);
    drop(vacuum);
    c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    Ok(())
}

impl ReplicaStore {
    /// Explicit local operator maintenance. The process lock prevents another
    /// service from opening this directory while the database is rebuilt.
    /// VACUUM may require up to twice the database size in additional free space.
    pub async fn compact_storage(&self) -> Result<()> {
        self.call(|db| {
            db.connection
                .pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
            db.connection
                .execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")?;
            Ok(())
        })
        .await
    }
}

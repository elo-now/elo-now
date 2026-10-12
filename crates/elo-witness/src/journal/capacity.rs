//! Durable per-Space reservations isolate growth without deleting signed history.
use super::*;

pub(crate) const MAX_SPACES: u64 = 128;
const NORMAL_EVENTS: u64 = 3_072;
const RESERVED_EVENTS: u64 = 4_096;
const NORMAL_BYTES: u64 = 3 * 1024 * 1024;
const RESERVED_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
struct Usage {
    events: u64,
    bytes: u64,
}

fn usage(db: &Connection, space: &str) -> Result<Usage> {
    // Count UTF-8 bytes, plus a conservative row/index charge. This is a logical
    // admission budget, not a claim about an exact SQLite file size. Half of the
    // database page ceiling remains outside the 128 Space reservations.
    let (events, bytes) = db.query_row(
        "SELECT count(*), COALESCE(sum(length(CAST(receipt AS BLOB)) + length(CAST(response AS BLOB)) + 1024),0) FROM events WHERE space=?1",
        [space], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let state = db.query_row(
        "SELECT COALESCE(sum(bytes),0) FROM (
           SELECT length(CAST(proof AS BLOB))+512 AS bytes FROM spaces WHERE space=?1
           UNION ALL SELECT length(CAST(record AS BLOB))+512 FROM policies WHERE space=?1
           UNION ALL SELECT length(CAST(record AS BLOB))+COALESCE(length(CAST(intent AS BLOB)),0)+512 FROM challenges WHERE space=?1
           UNION ALL SELECT 512 FROM tombstones WHERE space=?1
         )",
        [space], |row| row.get::<_, i64>(0),
    )?;
    Ok(Usage {
        events: u64::try_from(events).map_err(|_| Error::Unavailable)?,
        bytes: u64::try_from(bytes.saturating_add(state)).map_err(|_| Error::Unavailable)?,
    })
}

/// Called inside the mutation transaction, including its new receipt. A failed
/// budget check rolls the entire change back; no acknowledged history is pruned.
pub(crate) fn enforce(db: &Connection, space: SpaceId, security_reduction: bool) -> Result<()> {
    let usage = usage(db, &space.to_string())?;
    let (events, bytes) = if security_reduction {
        (RESERVED_EVENTS, RESERVED_BYTES)
    } else {
        (NORMAL_EVENTS, NORMAL_BYTES)
    };
    if usage.events > events || usage.bytes > bytes {
        return Err(Error::Limit);
    }
    Ok(())
}

/// Registration reserves a complete independent lifetime budget. Historical
/// oversized Spaces retain their data but count at their actual size, so a new
/// deployment cannot overbook the shared journal around grandfathered records.
pub(crate) fn reserve_space(db: &Connection) -> Result<()> {
    let mut statement = db.prepare("SELECT space FROM spaces")?;
    let spaces = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if spaces.len() as u64 >= MAX_SPACES {
        return Err(Error::Limit);
    }
    let mut events = RESERVED_EVENTS;
    let mut bytes = RESERVED_BYTES;
    for space in spaces {
        let usage = usage(db, &space)?;
        events = events.saturating_add(usage.events.max(RESERVED_EVENTS));
        bytes = bytes.saturating_add(usage.bytes.max(RESERVED_BYTES));
    }
    if events > MAX_EVENTS || bytes > MAX_SPACES * RESERVED_BYTES {
        return Err(Error::Limit);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

use super::*;
const NOW: u64 = DAY_MS + 1_000;
fn body(id: u64) -> Vec<u8> {
    let mut bytes = vec![7; 113];
    bytes[0] = 1;
    bytes[1..9].copy_from_slice(&id.to_be_bytes());
    bytes
}
fn binding(id: u64, space: u8, expires: u64) -> (Binding, Vec<u8>) {
    let bytes = body(id);
    (
        Binding {
            space: SpaceId::from_bytes([space; 32]),
            stream: StreamId::from_bytes([2; 16]),
            policy: RecordId::from_bytes([3; 32]),
            digest: ciphertext_id(&bytes),
            size: bytes.len() as u64,
            expires_at_ms: expires,
        },
        bytes,
    )
}

#[test]
fn immutable_bytes_and_metadata_survive_reopen_and_exact_retries() {
    let directory = private_test_directory();
    let mut store = Store::open(directory.path()).unwrap();
    let (entry, bytes) = binding(1, 1, NOW + 10_000);
    assert_eq!(store.put(&entry, &bytes, NOW), Ok(true));
    assert_eq!(store.put(&entry, &bytes, NOW + 1), Ok(false));
    for change in 0..5 {
        let mut replaced = entry.clone();
        match change {
            0 => replaced.space = SpaceId::from_bytes([99; 32]),
            1 => replaced.stream = StreamId::from_bytes([99; 16]),
            2 => replaced.policy = RecordId::from_bytes([99; 32]),
            3 => replaced.expires_at_ms += 1,
            _ => replaced.expires_at_ms -= 1,
        }
        assert_eq!(store.put(&replaced, &bytes, NOW + 2), Err(Error::Conflict));
    }
    drop(store);
    let mut store = Store::open(directory.path()).unwrap();
    assert_eq!(store.put(&entry, &bytes, NOW + 2), Ok(false));
    assert_eq!(store.get(entry.digest, NOW + 3).unwrap(), bytes);
    assert_eq!(
        store
            .db
            .query_row("SELECT count FROM budgets WHERE scope='*'", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
}

#[test]
fn expiry_is_enforced_before_cleanup_and_clock_rollback_cannot_restore_access() {
    let directory = private_test_directory();
    let mut store = Store::open(directory.path()).unwrap();
    let (entry, bytes) = binding(1, 1, NOW + 10);
    store.put(&entry, &bytes, NOW).unwrap();
    assert_eq!(store.get(entry.digest, NOW + 9).unwrap(), bytes);
    assert_eq!(store.get(entry.digest, NOW + 10), Err(Error::Missing));
    drop(store);
    let mut store = Store::open(directory.path()).unwrap();
    assert_eq!(store.get(entry.digest, NOW + 9), Err(Error::Unavailable));
    assert_eq!(store.cleanup(NOW + 10), Ok(1));
    assert_eq!(store.put(&entry, &bytes, NOW + 11), Err(Error::Invalid));
    assert_eq!(store.get(entry.digest, NOW + 11), Err(Error::Missing));
}

#[test]
fn size_hash_framing_and_finite_ttl_cannot_be_bypassed() {
    let directory = private_test_directory();
    let mut store = Store::open(directory.path()).unwrap();
    let (entry, bytes) = binding(1, 1, NOW + 10);
    let mut invalid = entry.clone();
    invalid.size += 1;
    assert_eq!(store.put(&invalid, &bytes, NOW), Err(Error::Invalid));
    let mut invalid = entry.clone();
    invalid.digest = ObjectId::from_bytes([0; 32]);
    assert_eq!(store.put(&invalid, &bytes, NOW), Err(Error::Invalid));
    let mut invalid = entry.clone();
    invalid.expires_at_ms = NOW + MAX_TTL_MS + 1;
    assert_eq!(store.put(&invalid, &bytes, NOW), Err(Error::Invalid));
    let mut bytes = vec![1; MAX_CIPHERTEXT_BYTES + 1];
    let mut invalid = entry.clone();
    invalid.size = bytes.len() as u64;
    invalid.digest = ciphertext_id(&bytes);
    assert_eq!(store.put(&invalid, &bytes, NOW), Err(Error::Invalid));
    bytes.pop();
    invalid.size -= 1;
    invalid.digest = ciphertext_id(&bytes);
    assert_eq!(store.put(&invalid, &bytes, NOW), Ok(true));
    assert_eq!(store.get(invalid.digest, NOW).unwrap(), bytes);
    let bytes = vec![2; 113];
    invalid.size = bytes.len() as u64;
    invalid.digest = ciphertext_id(&bytes);
    assert_eq!(store.put(&invalid, &bytes, NOW), Err(Error::Invalid));
}

#[test]
fn daily_space_budget_is_durable_and_expiring_bytes_do_not_reset_it() {
    let directory = private_test_directory();
    let mut store = Store::open(directory.path()).unwrap();
    for index in 0..DAILY_UPLOADS_PER_SPACE {
        let time = NOW + index * 10;
        let (entry, bytes) = binding(index, 1, time + 1);
        store.put(&entry, &bytes, time).unwrap();
        store.cleanup(time + 1).unwrap();
    }
    drop(store);
    let mut store = Store::open(directory.path()).unwrap();
    let (entry, bytes) = binding(999, 1, NOW + 1_000);
    assert_eq!(store.put(&entry, &bytes, NOW + 999), Err(Error::Limit));
    let (entry, bytes) = binding(999, 1, NOW + DAY_MS + 1);
    assert_eq!(store.put(&entry, &bytes, NOW + DAY_MS), Ok(true));
}

#[test]
fn space_capacity_and_global_daily_budget_are_independent() {
    let directory = private_test_directory();
    let mut store = Store::open(directory.path()).unwrap();
    for index in 0..MAX_OBJECTS_PER_SPACE {
        let (entry, bytes) = binding(index, 1, NOW + 10_000);
        store.put(&entry, &bytes, NOW).unwrap();
    }
    let (entry, bytes) = binding(999, 1, NOW + 10_000);
    assert_eq!(store.put(&entry, &bytes, NOW), Err(Error::Limit));
    for index in MAX_OBJECTS_PER_SPACE..DAILY_UPLOADS {
        let space = (index / MAX_OBJECTS_PER_SPACE + 1) as u8;
        let (entry, bytes) = binding(index, space, NOW + 10_000);
        store.put(&entry, &bytes, NOW).unwrap();
    }
    let (entry, bytes) = binding(999, 99, NOW + 10_000);
    assert_eq!(store.put(&entry, &bytes, NOW), Err(Error::Limit));
}

#[cfg(unix)]
#[test]
fn unsafe_storage_paths_are_rejected_without_following_links() {
    let directory = private_test_directory();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), directory.path().join("invitations.sqlite"))
        .unwrap();
    assert!(matches!(Store::open(directory.path()), Err(Error::Invalid)));
    assert_eq!(std::fs::metadata(outside.path()).unwrap().len(), 0);
}

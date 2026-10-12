use super::*;

fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE spaces(space TEXT,proof TEXT);
        CREATE TABLE events(space TEXT,receipt TEXT,response TEXT);
        CREATE TABLE policies(space TEXT,record TEXT);
        CREATE TABLE challenges(space TEXT,record TEXT,intent TEXT);
        CREATE TABLE tombstones(space TEXT);",
    )
    .unwrap();
    db
}

#[test]
fn space_byte_budget_preserves_security_reserve_and_other_spaces() {
    let db = database();
    let full = SpaceId::from_bytes([1; 32]);
    let other = SpaceId::from_bytes([2; 32]);
    db.execute(
        "INSERT INTO spaces VALUES(?1,?2)",
        params![full.to_string(), "x".repeat(NORMAL_BYTES as usize)],
    )
    .unwrap();
    assert!(matches!(enforce(&db, full, false), Err(Error::Limit)));
    enforce(&db, full, true).unwrap();
    enforce(&db, other, false).unwrap();
    db.execute(
        "UPDATE spaces SET proof=?1",
        ["x".repeat(RESERVED_BYTES as usize)],
    )
    .unwrap();
    assert!(matches!(enforce(&db, full, true), Err(Error::Limit)));
    enforce(&db, other, false).unwrap();
}

#[test]
fn event_budget_is_space_local_and_does_not_reset_when_state_shrinks() {
    let db = database();
    let full = SpaceId::from_bytes([1; 32]);
    let other = SpaceId::from_bytes([2; 32]);
    // Each event has a fixed overhead even if its textual fields are empty.
    db.execute("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?2) INSERT INTO events SELECT ?1,'','' FROM n", params![full.to_string(), (NORMAL_EVENTS + 1) as i64]).unwrap();
    assert!(matches!(enforce(&db, full, false), Err(Error::Limit)));
    enforce(&db, full, true).unwrap();
    enforce(&db, other, false).unwrap();
    db.execute("DELETE FROM policies", []).unwrap();
    assert!(matches!(enforce(&db, full, false), Err(Error::Limit)));
}

#[test]
fn new_registration_reserves_capacity_around_oversized_historical_spaces() {
    let db = database();
    for index in 0..MAX_SPACES - 1 {
        db.execute(
            "INSERT INTO spaces VALUES(?1,'')",
            [format!("{index:064x}")],
        )
        .unwrap();
    }
    reserve_space(&db).unwrap();
    db.execute(
        "UPDATE spaces SET proof=?1 WHERE space=?2",
        params!["x".repeat(RESERVED_BYTES as usize), format!("{:064x}", 0)],
    )
    .unwrap();
    assert!(matches!(reserve_space(&db), Err(Error::Limit)));
    // The limiter leaves existing bytes unchanged; it never reclaims history.
    assert_eq!(
        db.query_row(
            "SELECT length(proof) FROM spaces WHERE space=?1",
            [format!("{:064x}", 0)],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        RESERVED_BYTES as i64
    );
}

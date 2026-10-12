use super::*;

/// A bounded, opt-in benchmark of the real cache-hit integrity check. The opaque
/// policy/challenge rows are synthetic digest inputs, not protocol fixtures or
/// a production capacity claim. Keep this outside the normal correctness suite.
#[test]
#[ignore = "bounded synthetic witness head cost benchmark; run with --ignored --nocapture"]
fn cached_head_cost_with_growing_materialized_state() {
    for (rows, record_units) in [(0, 50), (64, 50), (256, 50), (512, 50), (512, 52)] {
        let (_directory, mut engine) = engine();
        let (_, authority) = authority(&engine);
        let opaque_record = "synthetic signed-record-sized digest input ".repeat(record_units);
        {
            let tx = engine.journal.db.transaction().unwrap();
            for index in 0..rows {
                let id = format!("{index:064x}");
                tx.execute(
                    "INSERT INTO policies(space,id,record,revoked,uses) VALUES(?1,?2,?3,1,1)",
                    rusqlite::params![authority.space().to_string(), id, opaque_record],
                )
                .unwrap();
                tx.execute("INSERT INTO challenges(id,space,policy,credential,record,expires,intent) VALUES(?1,?2,?1,?1,?3,?4,'consumed synthetic intent')",
                    rusqlite::params![id, authority.space().to_string(), opaque_record, NOW as i64]).unwrap();
                tx.execute(
                    "INSERT INTO tombstones(space,credential,identity) VALUES(?1,?2,?2)",
                    rusqlite::params![authority.space().to_string(), id],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        // Sign the snapshot after the synthetic rows are inserted, using the
        // normal journal path. Cache hits must still verify every row's digest.
        save_snapshot(&mut engine, &authority, 1);
        let startup = engine.journal.startup().unwrap();
        engine
            .journal
            .activate(
                Activation {
                    startup_nonce: startup.startup_nonce,
                    expected_position: startup.observed_position,
                    public_key: startup.public_key,
                    key_generation: startup.key_generation,
                    expires_at_ms: NOW + 60_000,
                },
                NOW,
            )
            .unwrap();
        let clock = Instant::now();
        let mut cache = HeadCache::new();
        cache
            .reply(&mut engine, head_request(&authority), NOW)
            .unwrap();
        let mut samples = Vec::new();
        for _ in 0..24 {
            let request = head_request(&authority);
            let started = Instant::now();
            cache
                .reply(
                    &mut engine,
                    request,
                    NOW + clock.elapsed().as_millis() as u64,
                )
                .unwrap();
            samples.push(started.elapsed().as_micros());
        }
        assert_eq!(cache.verifications, 1);
        samples.sort_unstable();
        let sql_bytes: i64 = engine.journal.db.query_row(
            "SELECT (SELECT sum(length(proof)) FROM spaces) + COALESCE((SELECT sum(length(record)) FROM policies),0) + COALESCE((SELECT sum(length(record)) FROM challenges),0)",
            [], |row| row.get(0)).unwrap();
        println!(
            "cached_head rows_per_table={rows} record_bytes={sql_bytes} median_us={} p95_us={} max_us={} debug_assertions={}",
            samples[12],
            samples[22],
            samples[23],
            cfg!(debug_assertions),
        );
        // Even after many cache hits, tampering without a new event must fail.
        engine
            .journal
            .db
            .execute("UPDATE spaces SET proof='{}'", [])
            .unwrap();
        assert!(matches!(
            cache.reply(
                &mut engine,
                head_request(&authority),
                NOW + clock.elapsed().as_millis() as u64,
            ),
            Err(Error::RecoveryRequired)
        ));
    }
}

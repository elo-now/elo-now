use elo_core::vault::write_private;
use std::sync::Barrier;

#[test]
fn concurrent_private_writers_publish_one_complete_file_without_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("export.age");
    let barrier = Barrier::new(8);
    let winners = std::thread::scope(|scope| {
        let handles: Vec<_> = (0u8..8)
            .map(|id| {
                let path = &path;
                let barrier = &barrier;
                scope.spawn(move || {
                    let bytes = vec![id; 64 * 1024];
                    barrier.wait();
                    write_private(path, &bytes, false).is_ok().then_some(id)
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(winners.len(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), vec![winners[0]; 64 * 1024]);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

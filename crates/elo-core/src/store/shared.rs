//! FIFO profile actors sharing a bounded budget for blocking SQLite work.
use super::*;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

static POOL: OnceLock<(usize, Arc<Semaphore>)> = OnceLock::new();

pub(super) fn configure(workers: usize) -> Result<()> {
    if !(1..=16).contains(&workers) {
        return Err(StoreError::InvalidInput(
            "SQLite workers must be between 1 and 16",
        ));
    }
    let (size, _) = POOL.get_or_init(|| (workers, Arc::new(Semaphore::new(workers))));
    if *size != workers {
        return Err(StoreError::InvalidInput(
            "SQLite worker budget is already configured",
        ));
    }
    Ok(())
}

pub(super) fn pool() -> Option<Arc<Semaphore>> {
    POOL.get().map(|(_, pool)| pool.clone())
}

pub(super) async fn run(
    path: PathBuf,
    mut receiver: mpsc::Receiver<Command>,
    ready: oneshot::Sender<Result<()>>,
    pool: Arc<Semaphore>,
) {
    let permit = pool
        .clone()
        .acquire_owned()
        .await
        .expect("permanent SQLite pool");
    let opened = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        open_connection(&path)
    })
    .await;
    let mut state = match opened {
        Ok(Ok(state)) => state,
        result => {
            let error = match result {
                Ok(Err(error)) => error,
                _ => StoreError::OutcomeUnknown,
            };
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        receiver.close();
    }
    loop {
        let command = receiver.recv().await;
        let permit = pool
            .clone()
            .acquire_owned()
            .await
            .expect("permanent SQLite pool");
        let next = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (connection, lock) = &mut state;
            match command {
                Some(Command::Run(operation)) => {
                    operation(connection);
                    Some((state, receiver))
                }
                Some(Command::Shutdown(reply)) => {
                    receiver.close();
                    // Preserve already accepted writes, even if awaiters cancel.
                    while let Some(queued) = receiver.blocking_recv() {
                        match queued {
                            Command::Run(operation) => operation(connection),
                            Command::Shutdown(other) => {
                                let _ = other.send(Err(StoreError::Closed));
                            }
                        }
                    }
                    let (connection, lock) = state;
                    let closed = connection
                        .close()
                        .map_err(|(_, error)| StoreError::Sqlite(error));
                    let unlocked = FileExt::unlock(&lock).map_err(StoreError::Io);
                    drop(lock);
                    let _ = reply.send(closed.and(unlocked));
                    None
                }
                None => {
                    // Checkpoint and release the file lock off the async runtime.
                    let _ = lock;
                    let (connection, lock) = state;
                    drop(connection);
                    drop(lock);
                    None
                }
            }
        })
        .await;
        match next {
            Ok(Some((next_state, next_receiver))) => {
                state = next_state;
                receiver = next_receiver;
            }
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn many_profiles_share_a_bounded_worker_budget_and_release_locks() {
        let temp = tempfile::tempdir().unwrap();
        let pool = Arc::new(Semaphore::new(2));
        let mut stores = Vec::new();
        for index in 0..24 {
            let path = temp.path().join(index.to_string());
            let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
            let (ready, result) = oneshot::channel();
            tokio::spawn(run(path, receiver, ready, pool.clone()));
            result.await.unwrap().unwrap();
            stores.push(ClientStore { sender });
        }
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut jobs = tokio::task::JoinSet::new();
        for store in &stores {
            let (store, active, peak) = (store.clone(), active.clone(), peak.clone());
            jobs.spawn(async move {
                store
                    .call(move |connection| {
                        let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(count, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(10));
                        let _: i64 = connection.query_row("SELECT 1", [], |r| r.get(0))?;
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = jobs.join_next().await {
            result.unwrap();
        }
        assert!((1..=2).contains(&peak.load(Ordering::SeqCst)));
        for (index, store) in stores.into_iter().enumerate() {
            store.close().await.unwrap();
            assert!(matches!(store.stats().await, Err(StoreError::Closed)));
            let reopened = ClientStore::open(temp.path().join(index.to_string()))
                .await
                .unwrap();
            reopened.close().await.unwrap();
        }
    }
}

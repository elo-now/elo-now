//! One bounded SQLite worker. Network tasks never acquire a blocking DB lock.
use super::{Result, StatusCode};
use rusqlite::Connection;
use std::sync::{Arc, Mutex, mpsc};
use tokio::sync::oneshot;

const QUEUE_CAPACITY: usize = 64;
type Job = Box<dyn FnOnce(&mut Connection) + Send>;

pub(super) struct Database {
    jobs: mpsc::SyncSender<Job>,
    #[cfg(test)]
    connection: Arc<Mutex<Connection>>,
}

impl Database {
    pub(super) fn new(connection: Connection) -> std::result::Result<Self, &'static str> {
        let connection = Arc::new(Mutex::new(connection));
        let worker_connection = connection.clone();
        let (jobs, receiver) = mpsc::sync_channel::<Job>(QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("elo-wake-sqlite".into())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    let Ok(mut db) = worker_connection.lock() else {
                        break;
                    };
                    job(&mut db);
                }
            })
            .map_err(|_| "Cannot start relay database worker")?;
        Ok(Self {
            jobs,
            #[cfg(test)]
            connection,
        })
    }

    pub(super) async fn call<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (sender, receiver) = oneshot::channel();
        self.jobs
            .try_send(Box::new(move |db| {
                // Cancelled, not-yet-started requests must not occupy SQLite.
                if !sender.is_closed() {
                    let _ = sender.send(operation(db));
                }
            }))
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        receiver
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    }

    #[cfg(test)]
    pub(super) fn inspect(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_sqlite_does_not_block_network_runtime_and_queue_is_bounded() {
        let database = Arc::new(Database::new(Connection::open_in_memory().unwrap()).unwrap());
        let (entered, started) = oneshot::channel();
        let (release, wait) = mpsc::channel();
        let worker = database.clone();
        let first = tokio::spawn(async move {
            worker
                .call(move |_| {
                    let _ = entered.send(());
                    wait.recv_timeout(Duration::from_secs(3)).unwrap();
                    Ok(())
                })
                .await
        });
        started.await.unwrap();
        // A timer on this single-thread runtime must still run while SQLite is busy.
        tokio::time::sleep(Duration::from_millis(10)).await;
        for _ in 0..QUEUE_CAPACITY {
            database.jobs.try_send(Box::new(|_| {})).unwrap();
        }
        assert_eq!(
            database.call(|_| Ok(())).await,
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
        release.send(()).unwrap();
        first.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_queued_write_is_skipped_and_shutdown_closes_worker() {
        let database = Arc::new(Database::new(Connection::open_in_memory().unwrap()).unwrap());
        let (entered, started) = oneshot::channel();
        let (release, wait) = mpsc::channel();
        database
            .jobs
            .try_send(Box::new(move |_| {
                let _ = entered.send(());
                wait.recv_timeout(Duration::from_secs(3)).unwrap();
            }))
            .unwrap();
        started.await.unwrap();
        let wrote = Arc::new(AtomicBool::new(false));
        let mark = wrote.clone();
        let worker = database.clone();
        let cancelled = tokio::spawn(async move {
            worker
                .call(move |_| {
                    mark.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await
        });
        tokio::task::yield_now().await;
        cancelled.abort();
        let _ = cancelled.await;
        release.send(()).unwrap();
        database
            .call(|db| {
                db.execute_batch("CREATE TABLE committed (id INTEGER)")
                    .map_err(super::super::db_error)?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(!wrote.load(Ordering::SeqCst));
        let connection = Arc::downgrade(&database.connection);
        drop(database);
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

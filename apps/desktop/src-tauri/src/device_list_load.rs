//! Supersede obsolete device-list reads when the user opens device linking.
//! Only read-only discovery is cancelled; approval and revocation keep running.
use std::future::Future;
use tokio::sync::watch;

pub(crate) struct DeviceListLoads(watch::Sender<()>);

impl Default for DeviceListLoads {
    fn default() -> Self {
        Self(watch::channel(()).0)
    }
}

impl DeviceListLoads {
    pub(crate) fn subscribe(&self) -> watch::Receiver<()> {
        self.0.subscribe()
    }

    pub(crate) fn interrupt(&self) {
        self.0.send_replace(());
    }
}

pub(crate) async fn load<F: Future>(
    mut interrupted: watch::Receiver<()>,
    work: F,
) -> Option<F::Output> {
    // A queued read may have been superseded before it acquired the runtime.
    if interrupted.has_changed().unwrap_or(true) {
        return None;
    }
    tokio::select! {
        biased;
        _ = interrupted.changed() => None,
        value = work => Some(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{task::Poll, time::Duration};

    #[tokio::test]
    async fn linking_releases_a_runtime_held_by_unreachable_device_discovery() {
        let loads = DeviceListLoads::default();
        let runtime = tokio::sync::Mutex::new(());
        let interrupted = loads.subscribe();
        let read = async {
            let _guard = runtime.lock().await;
            load(interrupted, std::future::pending::<()>()).await
        };
        tokio::pin!(read);
        std::future::poll_fn(|cx| {
            assert!(read.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(runtime.try_lock().is_err());
        loads.interrupt();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), read)
                .await
                .unwrap()
                .is_none()
        );
        assert!(runtime.try_lock().is_ok());
        assert_eq!(load(loads.subscribe(), async { 42 }).await, Some(42));
    }

    #[tokio::test]
    async fn a_superseded_queued_read_does_not_start_network_work() {
        let loads = DeviceListLoads::default();
        let interrupted = loads.subscribe();
        loads.interrupt();
        assert!(
            load(interrupted, async { panic!("obsolete read was started") })
                .await
                .is_none()
        );
    }
}

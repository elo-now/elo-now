//! Short-lived read snapshots for network-held runtime work. Locking the profile
//! or completing the pass invalidates any unfinished snapshot read.
use elo_core::app::HistorySnapshot;
use serde_json::Value;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
pub(crate) struct BackgroundHistory {
    inner: Arc<Mutex<Access>>,
    readers: Arc<tokio::sync::Semaphore>,
    pub(crate) changed: Arc<tokio::sync::Notify>,
}
#[derive(Default)]
struct Access {
    enabled: bool,
    current: Option<Arc<Pass>>,
}
struct Pass {
    snapshot: HistorySnapshot,
    revision: u64,
    valid: AtomicBool,
}
pub(crate) struct Guard {
    owner: BackgroundHistory,
    pass: Arc<Pass>,
}
impl Default for BackgroundHistory {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            readers: Arc::new(tokio::sync::Semaphore::new(2)),
            changed: Arc::default(),
        }
    }
}
impl BackgroundHistory {
    pub(crate) fn resume(&self) {
        self.inner.lock().expect("history access").enabled = true;
    }
    pub(crate) fn suspend(&self) {
        let mut access = self.inner.lock().expect("history access");
        access.enabled = false;
        self.changed.notify_waiters();
        if let Some(pass) = access.current.take() {
            pass.valid.store(false, Ordering::SeqCst);
        }
    }
    pub(crate) fn publish(&self, snapshot: HistorySnapshot, revision: u64) -> Option<Guard> {
        let mut access = self.inner.lock().expect("history access");
        if !access.enabled {
            return None;
        }
        let pass = Arc::new(Pass {
            snapshot,
            revision,
            valid: AtomicBool::new(true),
        });
        if let Some(old) = access.current.replace(pass.clone()) {
            old.valid.store(false, Ordering::SeqCst);
        }
        self.changed.notify_waiters();
        Some(Guard {
            owner: self.clone(),
            pass,
        })
    }
    pub(crate) async fn read(&self, request: &Value) -> Option<Value> {
        let pass = self.inner.lock().expect("history access").current.clone()?;
        // Bound simultaneous decryption/projection without holding the app mutex.
        let _permit = self.readers.acquire().await.ok()?;
        if !pass.valid.load(Ordering::SeqCst) {
            return None;
        }
        let mut result = pass.snapshot.history_page(request).await.ok()?;
        if !pass.valid.load(Ordering::SeqCst) {
            return None;
        }
        result["identity"] = serde_json::json!(pass.snapshot.identity_id());
        result["history"]["revision"] = serde_json::json!(pass.revision);
        Some(result)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.pass.valid.store(false, Ordering::SeqCst);
        self.owner.changed.notify_waiters();
        let mut access = self.owner.inner.lock().expect("history access");
        if access
            .current
            .as_ref()
            .is_some_and(|pass| Arc::ptr_eq(pass, &self.pass))
        {
            access.current = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elo_core::app::ProfileDraft;
    use serde_json::json;
    use std::{future::Future, task::Poll, time::Duration};

    #[tokio::test]
    async fn local_history_bypasses_busy_runtime_and_revokes_queued_readers() {
        let tmp = tempfile::tempdir().unwrap();
        let mut client = ProfileDraft::new()
            .unwrap()
            .save_named(
                tmp.path().join("profile"),
                "synthetic history password".into(),
                "History",
                "History fixture",
            )
            .await
            .unwrap();
        let view = client.view().await.unwrap();
        let chat = &view["streams"][0];
        client
            .operate(json!({"op":"send", "space":chat["space"],
            "stream":chat["stream"], "text":"Local while offline",
            "created_at":"2026-09-13T12:00:00Z"}))
            .await
            .unwrap();
        let request = json!({"op":"history_page", "expected_identity":client.identity_id(),
            "space":chat["space"], "stream":chat["stream"]});
        let expected = client.operate(request.clone()).await.unwrap()["history"].clone();
        let runtime = tokio::sync::Mutex::new(client);
        let busy = runtime.lock().await;
        let access = BackgroundHistory::default();
        assert!(access.publish(busy.history_snapshot(), 1).is_none());
        access.resume();
        // A read already waiting for the runtime must wake when a pass starts.
        let changed = access.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let old = access.publish(busy.history_snapshot(), 7).unwrap();
        tokio::time::timeout(Duration::from_secs(1), changed)
            .await
            .unwrap();
        let mut page = tokio::time::timeout(Duration::from_secs(2), access.read(&request))
            .await
            .expect("history waited for the held runtime mutex")
            .unwrap();
        assert_eq!(page["history"]["revision"], 7);
        page["history"].as_object_mut().unwrap().remove("revision");
        assert_eq!(page["history"], expected);
        let mut wrong = request.clone();
        wrong["expected_identity"] = json!("another profile");
        assert!(access.read(&wrong).await.is_none());

        // Hold both decryption slots and poll once to queue a reader on old.
        let slots = access.readers.acquire_many(2).await.unwrap();
        let pending = access.read(&request);
        tokio::pin!(pending);
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        access.suspend();
        assert!(access.publish(busy.history_snapshot(), 8).is_none());
        access.resume();
        let next = access.publish(busy.history_snapshot(), 9).unwrap();
        drop(old); // A finished old pass cannot revoke the replacement.
        drop(slots);
        assert!(pending.await.is_none(), "locked-profile result escaped");
        assert_eq!(
            access.read(&request).await.unwrap()["history"]["revision"],
            9
        );
        drop(next);
        assert!(access.read(&request).await.is_none());
        drop(busy);
        runtime.into_inner().close().await.unwrap();
    }
}

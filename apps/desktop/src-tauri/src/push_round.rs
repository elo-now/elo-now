//! Combine independent hosting results without discarding a verified notification tap.
use serde_json::{Value, json};

pub(super) struct Round {
    result: Value,
    succeeded: bool,
    error: Option<String>,
}

impl Round {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            result: json!({"available":true,"enabled":enabled,"pending":false,"wake":false,"opened":null}),
            succeeded: false,
            error: None,
        }
    }

    pub(super) fn snapshot(&mut self, value: Value) {
        for key in ["enabled", "pending", "wake"] {
            self.result[key] = json!(self.result[key] == true || value[key] == true);
        }
        if !value["opened"].is_null() {
            self.result["opened"] = value["opened"].clone();
        }
    }

    pub(super) fn accept(&mut self, value: Result<Value, String>) {
        match value {
            Ok(value) => {
                self.succeeded = true;
                self.snapshot(value);
            }
            Err(error) => {
                self.defer();
                self.error.get_or_insert(error);
            }
        }
    }

    pub(super) fn defer(&mut self) {
        self.result["pending"] = json!(true);
    }

    pub(super) fn finish(self) -> Result<Value, String> {
        if !self.succeeded
            && self.result["opened"].is_null()
            && let Some(error) = self.error
        {
            return Err(error);
        }
        Ok(self.result)
    }
}

/// Dropping an unfinished network operation leaves its saved revision/capability for retry.
pub(super) async fn until<F: std::future::Future>(
    deadline: tokio::time::Instant,
    operation: F,
) -> Option<F::Output> {
    tokio::time::timeout_at(deadline, operation).await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_host_does_not_hide_another_hosts_verified_tap_or_status() {
        for tap_first in [true, false] {
            let mut round = Round::new(true);
            let tap = json!({"opened":{"id":"verified","target":{"space":"private"}},"wake":true});
            if tap_first {
                round.snapshot(tap.clone());
            }
            round.accept(Err("offline".into()));
            if !tap_first {
                round.snapshot(tap);
            }
            let value = round.finish().unwrap();
            assert_eq!(value["opened"]["id"], "verified");
            assert_eq!(value["pending"], true);
        }
        let mut round = Round::new(true);
        round.accept(Err("offline".into()));
        round.accept(Ok(json!({"enabled":true})));
        assert_eq!(round.finish().unwrap()["pending"], true);
        let mut round = Round::new(true);
        round.accept(Err("offline".into()));
        assert_eq!(round.finish().unwrap_err(), "offline");
    }

    #[tokio::test]
    async fn exhausted_round_deadline_cancels_pending_network_work() {
        struct Pending(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Pending {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = Pending(cancelled.clone());
        let deadline = tokio::time::Instant::now();
        assert!(
            until(deadline, async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            })
            .await
            .is_none()
        );
        assert!(cancelled.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            until(deadline, std::future::pending::<()>())
                .await
                .is_none()
        );
    }
}

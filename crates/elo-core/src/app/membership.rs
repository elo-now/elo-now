//! Short, session-local permission leases. No background polling or disk cache.
use super::*;
use std::time::{Duration, Instant};

const LEASE: Duration = Duration::from_secs(30);
const FAILURE_BACKOFF: Duration = Duration::from_secs(5);
const MAX_ENTRIES: usize = 64;

#[derive(PartialEq, Eq)]
struct Key {
    address: String,
    credential: RecordId,
    space: SpaceId,
    stream: StreamId,
    head: RecordId,
    general_head: RecordId,
}

#[derive(Clone)]
struct Started {
    monotonic: Instant,
    wall: SystemTime,
}

impl Started {
    fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    fn fresh(&self, lifetime: Duration) -> bool {
        // Also expire across system sleep on platforms whose monotonic clock
        // pauses, and fail closed if the wall clock has moved backwards.
        self.monotonic.elapsed() < lifetime
            && self.wall.elapsed().is_ok_and(|elapsed| elapsed < lifetime)
    }
}

struct Entry {
    key: Key,
    started: Started,
    outcome: std::result::Result<(), String>,
}

impl Entry {
    fn fresh(&self) -> bool {
        self.started.fresh(if self.outcome.is_ok() {
            LEASE
        } else {
            FAILURE_BACKOFF
        })
    }
}

#[derive(Default)]
pub(super) struct MembershipChecks {
    // Sharing the lock across the request coalesces concurrent misses. The
    // native app already serializes mutations within one Space client.
    entries: tokio::sync::Mutex<Vec<Entry>>,
    generation: std::sync::atomic::AtomicU64,
}

pub(super) struct MembershipProbe {
    pub requests: Vec<Value>,
    keys: Vec<Key>,
    started: Started,
    generation: u64,
}

impl ClientApp {
    fn membership_key(&self, authority: &Authority) -> Result<Key> {
        let address = self.call_host.as_ref().ok_or("Space unavailable.")?;
        let head = authority
            .head_id()
            .ok_or("Chat permissions need to be refreshed.")?;
        let general_head = self
            .authorities
            .0
            .iter()
            .find(|a| a.space() == address.scope.space && a.stream() == address.scope.stream)
            .and_then(Authority::head_id)
            .ok_or("Chat permissions need to be refreshed.")?;
        Ok(Key {
            address: serde_json::to_string(address)?,
            credential: self.session.credential().id(),
            space: authority.space(),
            stream: authority.stream(),
            head,
            general_head,
        })
    }

    // Piggyback small head checks on the existing Space status sync. No extra
    // timer or HTTP request, and no repeated roster in these confirmations.
    pub(super) fn membership_probe(&self) -> Result<MembershipProbe> {
        let keys = self
            .authorities
            .0
            .iter()
            .take(MAX_ENTRIES)
            .map(|a| self.membership_key(a))
            .collect::<Result<Vec<_>>>()?;
        Ok(MembershipProbe {
            requests: keys
                .iter()
                .map(|k| json!({"space":k.space,"stream":k.stream,"head":k.head}))
                .collect(),
            keys,
            started: Started::now(),
            generation: self
                .membership_checks
                .generation
                .load(std::sync::atomic::Ordering::Acquire),
        })
    }

    pub(super) async fn accept_membership_probe(
        &self,
        probe: MembershipProbe,
        response: &Value,
    ) -> Result<()> {
        let Some(results) = response["chat_heads"].as_array() else {
            return Ok(());
        };
        if results.len() != probe.keys.len() || !probe.started.fresh(LEASE) {
            return Ok(());
        }
        let mut entries = self.membership_checks.entries.lock().await;
        if probe.generation
            != self
                .membership_checks
                .generation
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }
        for (key, result) in probe.keys.into_iter().zip(results) {
            let Some(authority) = self
                .authorities
                .0
                .iter()
                .find(|a| a.space() == key.space && a.stream() == key.stream)
            else {
                continue;
            };
            if self.membership_key(authority)? != key {
                continue;
            }
            if entries
                .iter()
                .any(|entry| entry.key == key && entry.started.monotonic > probe.started.monotonic)
            {
                continue;
            }
            entries.retain(|entry| entry.key != key && entry.fresh());
            let outcome = if result["head"] == json!(key.head) && result["error"].is_null() {
                Ok(())
            } else {
                Err(result["error"]
                    .as_str()
                    .unwrap_or("Chat permissions need to be refreshed.")
                    .to_owned())
            };
            if entries.len() == MAX_ENTRIES {
                entries.remove(0);
            }
            entries.push(Entry {
                key,
                started: probe.started.clone(),
                outcome,
            });
        }
        Ok(())
    }

    pub(super) async fn check_host_membership(&self, authority: &Authority) -> Result<()> {
        let Some(address) = &self.call_host else {
            return Ok(());
        };
        let key = self.membership_key(authority)?;
        let head = key.head;
        let mut entries = self.membership_checks.entries.lock().await;
        entries.retain(Entry::fresh);
        if let Some(entry) = entries.iter().find(|entry| entry.key == key) {
            return entry.outcome.clone().map_err(Into::into);
        }
        // Start the lease before sending: slow delivery cannot extend the
        // freshness of a valid signed answer. Cache hits never renew it.
        let started = Started::now();
        let outcome = match self
            .call_space(
                address,
                "chat_head_check",
                json!({
                    "space":authority.space(), "stream":authority.stream(), "head":head
                }),
            )
            .await
        {
            Ok(response) if response["head"] == json!(head) && started.fresh(LEASE) => Ok(()),
            Ok(_) => Err("Chat permissions need to be refreshed.".to_owned()),
            Err(error) => Err(error.to_string()),
        };
        let started = if outcome.is_ok() {
            started
        } else {
            Started::now()
        };
        if entries.len() == MAX_ENTRIES {
            entries.remove(0);
        }
        entries.push(Entry {
            key,
            started,
            outcome: outcome.clone(),
        });
        outcome.map_err(Into::into)
    }

    pub(super) async fn invalidate_membership_checks(&self) {
        let mut entries = self.membership_checks.entries.lock().await;
        self.membership_checks
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::space_service::{Request, Response, SpaceAddress};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    async fn fixture() -> (
        tempfile::TempDir,
        ClientApp,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic membership test password".into(),
                "General",
            )
            .await
            .unwrap();
        app.allow_loopback = true;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = &app.authorities.0[0];
        let head = authority.head_id().unwrap();
        let space = authority.space();
        app.call_host = Some(SpaceAddress {
            url: format!("http://{}/team/v1/spaces", listener.local_addr().unwrap()),
            scope: app.team_scope().unwrap(),
            message_lifetime_seconds: 86400,
        });
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let signer = app.session.signing_key().clone();
        let credential = STANDARD.encode(app.session.credential().record().bytes());
        let router = axum::Router::new().route(
            "/team/v1/spaces",
            axum::routing::post(move |axum::Json(request): axum::Json<Request>| {
                counter.fetch_add(1, Ordering::SeqCst);
                let answer = SignedRecord::sign(
                    &serde_json::to_vec(&json!({
                        "v":1,"kind":"space.response","space":space,"nonce":request.nonce,
                        "body":{"head":head}
                    }))
                    .unwrap(),
                    &signer,
                )
                .unwrap();
                let response = Response {
                    record: STANDARD.encode(answer.bytes()),
                    credential: credential.clone(),
                    ciphertext: None,
                };
                async move { axum::Json(response) }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (temp, app, hits, server)
    }

    async fn expire(app: &ClientApp) {
        for entry in app.membership_checks.entries.lock().await.iter_mut() {
            entry.started.monotonic = Instant::now() - LEASE;
        }
    }

    #[tokio::test]
    async fn a_message_burst_coalesces_checks_and_expiry_never_falls_back_offline() {
        let (_temp, app, hits, server) = fixture().await;
        let authority = &app.authorities.0[0];
        let start = Instant::now();
        let results = futures_util::future::join_all(
            (0..20).map(|_| app.require_fresh_membership(authority)),
        )
        .await;
        assert!(results.into_iter().all(|r| r.is_ok()));
        for _ in 0..80 {
            app.require_fresh_membership(authority).await.unwrap();
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "one hundred sends share one signed check"
        );
        eprintln!(
            "100 permission checks: {} HTTP request, {} ms including loopback",
            hits.load(Ordering::SeqCst),
            start.elapsed().as_millis()
        );
        let before = app.membership_checks.entries.lock().await[0]
            .started
            .monotonic;
        app.require_fresh_membership(authority).await.unwrap();
        assert_eq!(
            app.membership_checks.entries.lock().await[0]
                .started
                .monotonic,
            before,
            "cache hits must not renew the lease"
        );
        expire(&app).await;
        app.require_fresh_membership(authority).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        server.abort();
        let _ = server.await;
        expire(&app).await;
        assert!(app.require_fresh_membership(authority).await.is_err());
        let failed = app.membership_checks.entries.lock().await[0]
            .started
            .monotonic;
        for _ in 0..20 {
            assert!(app.require_fresh_membership(authority).await.is_err());
        }
        assert_eq!(
            app.membership_checks.entries.lock().await[0]
                .started
                .monotonic,
            failed,
            "failed taps share a backoff without granting access"
        );
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn ordinary_sync_confirmation_avoids_an_extra_request_and_local_changes_invalidate_it() {
        let (_temp, mut app, hits, server) = fixture().await;
        let proof = app.membership_probe().unwrap();
        let head = app.authorities.0[0].head_id().unwrap();
        app.accept_membership_probe(proof, &json!({"chat_heads":[{"head":head}]}))
            .await
            .unwrap();
        app.require_fresh_membership(&app.authorities.0[0])
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let stale = app.membership_probe().unwrap();
        // A denial arriving in normal sync overrides a still-live success.
        let proof = app.membership_probe().unwrap();
        app.accept_membership_probe(
            proof,
            &json!({"chat_heads":[{"error":"Chat permissions need to be refreshed."}]}),
        )
        .await
        .unwrap();
        assert!(
            app.require_fresh_membership(&app.authorities.0[0])
                .await
                .is_err()
        );
        app.accept_membership_probe(stale, &json!({"chat_heads":[{"head":head}]}))
            .await
            .unwrap();
        assert!(
            app.require_fresh_membership(&app.authorities.0[0])
                .await
                .is_err(),
            "a delayed older success cannot overwrite a newer denial"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let invalidated = app.membership_probe().unwrap();
        app.invalidate_membership_checks().await;
        app.accept_membership_probe(invalidated, &json!({"chat_heads":[{"head":head}]}))
            .await
            .unwrap();
        assert!(
            app.membership_checks.entries.lock().await.is_empty(),
            "a pending response cannot resurrect a locally invalidated lease"
        );
        app.require_fresh_membership(&app.authorities.0[0])
            .await
            .unwrap();
        let a = &app.authorities.0[0];
        let mut next = a.head().unwrap().clone();
        next.sequence += 1;
        next.previous_config_id = Some(head);
        next.nonce = record::random_hex::<16>().unwrap();
        next.action.operation = "device.updated".into();
        let record = next.sign(app.session.signing_key()).unwrap();
        app.authorities.0[0].apply_config(record).unwrap();
        assert!(
            app.require_fresh_membership(&app.authorities.0[0])
                .await
                .is_err(),
            "the mock host still confirms the old head"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        server.abort();
        let _ = server.await;
        app.close().await.unwrap();
    }

    #[test]
    fn leases_expire_on_sleep_clock_rollback_and_slow_responses() {
        let mut started = Started::now();
        assert!(started.fresh(LEASE));
        started.wall = SystemTime::now() - LEASE;
        assert!(
            !started.fresh(LEASE),
            "suspend time counts even if the monotonic clock paused"
        );
        started.wall = SystemTime::now() + Duration::from_secs(60);
        assert!(!started.fresh(LEASE));
        started.wall = SystemTime::now();
        started.monotonic = Instant::now() - LEASE;
        assert!(
            !started.fresh(LEASE),
            "slow responses do not restart the lease"
        );
    }
}

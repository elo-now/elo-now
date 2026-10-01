//! Short, session-local permission leases. No background polling or disk cache.
use super::*;
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const LEASE: Duration = Duration::from_secs(30);
const FAILURE_BACKOFF: Duration = Duration::from_secs(5);
const MAX_ENTRIES: usize = 64;

#[derive(Clone, PartialEq, Eq)]
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

type ScopeKeys = BTreeMap<(SpaceId, StreamId), Key>;

#[derive(Clone, Default)]
pub(super) struct MembershipChecks {
    // Sharing the lock across the request coalesces concurrent misses. The
    // native app already serializes mutations within one Space client.
    entries: Arc<tokio::sync::Mutex<Vec<Entry>>>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    snapshot_keys: Arc<RwLock<Option<ScopeKeys>>>,
    focused: Arc<RwLock<Option<(SpaceId, StreamId)>>>,
}

#[derive(Default)]
pub(super) struct MembershipSnapshot {
    checks: MembershipChecks,
    // None is exclusively a standalone client without a host. A hosted client
    // whose key cannot be captured has no matching key and fails closed.
    keys: Option<ScopeKeys>,
}

impl MembershipSnapshot {
    pub(super) fn allows(&self, space: SpaceId, stream: StreamId) -> bool {
        let Ok(current) = self.checks.snapshot_keys.try_read() else {
            return false;
        };
        let Some(keys) = &self.keys else {
            return current.is_none();
        };
        let Some(key) = keys.get(&(space, stream)) else {
            return false;
        };
        if current.as_ref().and_then(|keys| keys.get(&(space, stream))) != Some(key) {
            return false;
        }
        let Ok(entries) = self.checks.entries.try_lock() else {
            return false;
        };
        entries
            .iter()
            .any(|entry| entry.key == *key && entry.outcome.is_ok() && entry.started.fresh(LEASE))
    }

    pub(super) fn prioritize(&self, scope: Option<(SpaceId, StreamId)>) {
        if let Ok(mut focused) = self.checks.focused.try_write() {
            *focused = scope;
        }
    }
}

pub(super) struct MembershipProbe {
    pub requests: Vec<Value>,
    keys: Vec<Key>,
    started: Started,
    generation: u64,
}

impl ClientApp {
    pub(super) fn membership_snapshot(&self) -> MembershipSnapshot {
        let keys = self.call_host.as_ref().map(|_| {
            self.authorities
                .0
                .iter()
                .filter_map(|authority| {
                    self.membership_key(authority)
                        .ok()
                        .map(|key| ((key.space, key.stream), key))
                })
                .collect::<ScopeKeys>()
        });
        // Publishing new permission keys also invalidates older immutable live
        // snapshots, even while an old positive lease remains in the cache.
        if let Ok(mut current) = self.membership_checks.snapshot_keys.write() {
            *current = keys.clone();
        }
        MembershipSnapshot {
            checks: self.membership_checks.clone(),
            keys,
        }
    }

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
        let focused = self
            .membership_checks
            .focused
            .try_read()
            .ok()
            .and_then(|f| *f);
        let focus = self
            .authorities
            .0
            .iter()
            .find(|authority| focused == Some((authority.space(), authority.stream())));
        // The shared cache and existing status request remain bounded to 64
        // chats. Put the visible conversation first without adding traffic.
        let keys = self
            .authorities
            .0
            .iter()
            .filter(|authority| focused != Some((authority.space(), authority.stream())));
        let keys = focus
            .into_iter()
            .chain(keys)
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

    #[tokio::test]
    async fn live_snapshots_share_permission_expiry_invalidation_and_current_keys() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic live membership password".into(),
                "General",
            )
            .await
            .unwrap();
        let scope = realtime::Scope {
            space_context: String::new(),
            space: app.authorities.0[0].space(),
            stream: app.authorities.0[0].stream(),
        };
        let seal = |snapshot: &realtime::Snapshot| {
            snapshot.seal(&scope, realtime::Payload::Presence { active: true }, 1_000)
        };
        let standalone = app.realtime_snapshot();
        assert!(seal(&standalone).is_ok());
        app.call_host = Some(SpaceAddress {
            service_credential: None,
            // Every successful publication below uses only a seeded status
            // response. This unreachable host must never be contacted by seal.
            url: "https://unreachable.invalid/team/v1/spaces".into(),
            scope: app.team_scope().unwrap(),
            message_lifetime_seconds: 86400,
        });
        let captured = app.realtime_snapshot();
        assert!(
            seal(&captured).is_err(),
            "a hosted cache miss denies publication"
        );
        assert!(
            seal(&standalone).is_err(),
            "old standalone snapshots cannot bypass hosting"
        );
        let head = app.authorities.0[0].head_id().unwrap();
        app.accept_membership_probe(
            app.membership_probe().unwrap(),
            &json!({"chat_heads":[{"head":head}]}),
        )
        .await
        .unwrap();
        let (_, envelope) = seal(&captured).unwrap();
        let opened = captured
            .open(
                "",
                &envelope,
                app.identity_id(),
                app.session.credential().id(),
                1_000,
            )
            .unwrap();
        assert_eq!(
            opened.expires_at_ms, 61_000,
            "event TTL is independent of the publication lease"
        );
        {
            let _busy = app.membership_checks.entries.lock().await;
            assert!(
                seal(&captured).is_err(),
                "contention fails closed without waiting"
            );
        }
        let start = app.membership_checks.entries.lock().await[0]
            .started
            .monotonic;
        assert!(seal(&captured).is_ok());
        assert_eq!(
            app.membership_checks.entries.lock().await[0]
                .started
                .monotonic,
            start
        );
        expire(&app).await;
        assert!(
            seal(&captured).is_err(),
            "the previously captured snapshot observes expiry"
        );
        app.accept_membership_probe(
            app.membership_probe().unwrap(),
            &json!({"chat_heads":[{"head":head}]}),
        )
        .await
        .unwrap();
        assert!(
            seal(&captured).is_ok(),
            "an existing status sync renews the shared lease"
        );
        app.accept_membership_probe(
            app.membership_probe().unwrap(),
            &json!({"chat_heads":[{"error":"Access removed."}]}),
        )
        .await
        .unwrap();
        assert!(
            seal(&captured).is_err(),
            "a cached denial cannot authorize live content"
        );
        app.accept_membership_probe(
            app.membership_probe().unwrap(),
            &json!({"chat_heads":[{"head":head}]}),
        )
        .await
        .unwrap();
        app.invalidate_membership_checks().await;
        assert!(
            seal(&captured).is_err(),
            "invalidation reaches old snapshots immediately"
        );
        app.accept_membership_probe(
            app.membership_probe().unwrap(),
            &json!({"chat_heads":[{"head":head}]}),
        )
        .await
        .unwrap();
        assert!(seal(&captured).is_ok());

        let mut next = app.authorities.0[0].head().unwrap().clone();
        next.sequence += 1;
        next.previous_config_id = Some(head);
        next.nonce = record::random_hex::<16>().unwrap();
        next.action.operation = "device.updated".into();
        app.authorities.0[0]
            .apply_config(next.sign(app.session.signing_key()).unwrap())
            .unwrap();
        let updated = app.realtime_snapshot();
        assert!(
            seal(&captured).is_err(),
            "a new configuration invalidates the old captured key"
        );
        assert!(
            seal(&updated).is_err(),
            "the previous configuration's lease is not reusable"
        );
        app.accept_membership_probe(
            app.membership_probe().unwrap(),
            &json!({"chat_heads":[{"head":app.authorities.0[0].head_id()}]}),
        )
        .await
        .unwrap();
        assert!(seal(&updated).is_ok());
        assert!(seal(&captured).is_err());

        app.call_host.as_mut().unwrap().scope.stream = StreamId::from_bytes([255; 16]);
        let invalid_host = app.realtime_snapshot();
        assert!(
            seal(&invalid_host).is_err(),
            "an invalid hosted key must not become standalone"
        );
        assert!(seal(&updated).is_err());
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn live_focus_prioritizes_the_existing_sixty_four_chat_probe() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic focused membership password".into(),
                "General",
            )
            .await
            .unwrap();
        app.call_host = Some(SpaceAddress {
            service_credential: None,
            url: "https://unreachable.invalid/team/v1/spaces".into(),
            scope: app.team_scope().unwrap(),
            message_lifetime_seconds: 86400,
        });
        let general = app.authorities.0[0].clone();
        let root = root_key(
            general.genesis().body()["owners"][0]["root_public_key"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        for index in 1..=MAX_ENTRIES {
            let stream = StreamId::from_bytes([index as u8; 16]);
            let mut authority = Authority::new(
                general.genesis().bytes(),
                general.space(),
                &root,
                app.session.credential().clone(),
                stream,
            )
            .unwrap();
            let mut config = general.head().unwrap().clone();
            config.stream_id = stream;
            config.chat_kind = Some(ChatKind::Chat);
            config.nonce = record::random_hex::<16>().unwrap();
            authority
                .apply_config(config.sign(app.session.signing_key()).unwrap())
                .unwrap();
            app.authorities.0.push(authority);
        }
        let last = app.authorities.0.last().unwrap();
        let scope = realtime::Scope {
            space_context: String::new(),
            space: last.space(),
            stream: last.stream(),
        };
        let ordinary = app.membership_probe().unwrap();
        assert_eq!(ordinary.requests.len(), MAX_ENTRIES);
        assert!(
            ordinary
                .requests
                .iter()
                .all(|request| request["stream"] != json!(scope.stream))
        );
        let snapshot = app.realtime_snapshot();
        snapshot.prioritize_membership_focus(Some(&scope));
        let focused = app.membership_probe().unwrap();
        assert_eq!(focused.requests.len(), MAX_ENTRIES);
        assert_eq!(focused.requests[0]["stream"], json!(scope.stream));
        let response = json!({"chat_heads":focused.requests.iter().map(|request| json!({"head":request["head"]})).collect::<Vec<_>>()});
        app.accept_membership_probe(focused, &response)
            .await
            .unwrap();
        assert_eq!(
            app.membership_checks.entries.lock().await.len(),
            MAX_ENTRIES
        );
        assert!(
            snapshot
                .seal(&scope, realtime::Payload::Typing { active: true }, 1_000)
                .is_ok()
        );
        snapshot.prioritize_membership_focus(None);
        assert_eq!(app.membership_probe().unwrap().requests, ordinary.requests);
        app.close().await.unwrap();
    }

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
            service_credential: None,
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

//! Independently fetched, short-lived witness heads for hosted authority checks.
//! The durable global floor survives restarts; leases and caches never do.
use super::{Result, current, private_directory, save};
use elo_core::{
    authority::{Authority, WitnessPin},
    ids::{RecordId, SpaceId, StreamId},
    record, vault,
    witness::{HeadRequest, Position, VerifiedFreshness, verify_freshness},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

const RESPONSE_LIMIT: usize = 16_384;
const MAX_CACHE: usize = 128;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Floor {
    v: u8,
    pin: WitnessPin,
    position: Option<Position>,
}

struct State {
    floor: Floor,
    cache: BTreeMap<(SpaceId, StreamId), Arc<VerifiedFreshness>>,
    unavailable: bool,
}

pub(super) struct WitnessGate {
    pin: WitnessPin,
    endpoint: String,
    client: reqwest::Client,
    path: PathBuf,
    state: Mutex<State>,
    requests: Semaphore,
    // Exactly one process owns this floor. The lock file is never replaced.
    _lock: File,
}

impl WitnessGate {
    #[cfg(test)]
    pub(super) fn test_endpoint(&mut self, endpoint: String) {
        let url = reqwest::Url::parse(&endpoint).unwrap();
        assert!(
            url.host_str()
                .unwrap()
                .parse::<std::net::IpAddr>()
                .unwrap()
                .is_loopback()
        );
        self.endpoint = endpoint;
    }
    #[cfg(test)]
    pub(super) fn clear_test_cache(&self) {
        self.state.lock().unwrap().cache.clear();
    }

    pub(super) fn open(root: &Path, pin: WitnessPin) -> Result<Self> {
        pin.validate()?;
        private_directory(root)?;
        let path = root.join("floor.json");
        let lock_path = root.join("floor.lock");
        let initialized = lock_path.exists();
        if initialized {
            vault::read_private(&lock_path)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock()?;
        let floor = if path.exists() {
            let bytes = vault::read_private(&path)?;
            if bytes.len() > 4096 {
                return Err("Invalid hosting witness floor.".into());
            }
            let floor: Floor = serde_json::from_slice(&bytes)?;
            if floor.v != 1
                || floor.pin != pin
                || floor
                    .position
                    .as_ref()
                    .is_some_and(|position| position.sequence == 0 || position.record_id.is_none())
            {
                return Err("Hosting witness pin or floor mismatch.".into());
            }
            floor
        } else {
            // Losing the floor must not silently bootstrap trust again.
            if initialized {
                return Err("Missing hosting witness floor.".into());
            }
            let floor = Floor {
                v: 1,
                pin: pin.clone(),
                position: None,
            };
            save(&path, &floor)?;
            floor
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self {
            endpoint: format!("{}/head", pin.url.trim_end_matches('/')),
            pin,
            client,
            path,
            state: Mutex::new(State {
                floor,
                cache: BTreeMap::new(),
                unavailable: false,
            }),
            requests: Semaphore::new(8),
            _lock: lock,
        })
    }

    pub(super) async fn require(&self, authority: &Authority) -> Result<Arc<VerifiedFreshness>> {
        self.check_authority(authority)?;
        self.require_head(
            authority.space(),
            authority.stream(),
            authority.head_id().ok_or("Missing authority head.")?,
        )
        .await
    }

    /// Repeat immediately before committing an action after any asynchronous work.
    pub(super) fn check(&self, authority: &Authority, lease: &VerifiedFreshness) -> Result<()> {
        self.check_authority(authority)?;
        if lease.body().space_id != authority.space()
            || lease.body().stream_id != authority.stream()
            || Some(lease.body().authority_head) != authority.head_id()
        {
            return Err("Hosting witness authority is no longer current.".into());
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "Hosting witness unavailable.")?;
        if state.unavailable {
            return Err("Hosting witness floor could not be persisted.".into());
        }
        check_floor(&state.floor, lease, current()?)
    }

    fn check_authority(&self, authority: &Authority) -> Result<()> {
        if authority.is_forked() || authority.witness_pin() != Some(&self.pin) {
            return Err("Hosting witness authority mismatch.".into());
        }
        Ok(())
    }

    async fn require_head(
        &self,
        space: SpaceId,
        stream: StreamId,
        head: RecordId,
    ) -> Result<Arc<VerifiedFreshness>> {
        let floor = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Hosting witness unavailable.")?;
            if state.unavailable {
                return Err("Hosting witness floor could not be persisted.".into());
            }
            if let Some(lease) = state.cache.get(&(space, stream))
                && lease.body().authority_head == head
                && check_floor(&state.floor, lease, current()?).is_ok()
            {
                return Ok(lease.clone());
            }
            state.floor.position.clone()
        };
        let _slot = self.requests.try_acquire()?;
        let request = HeadRequest {
            space_id: space,
            stream_id: stream,
            nonce: record::random_hex::<32>()?,
        };
        let requested_at = Instant::now();
        let encoded = tokio::time::timeout(Duration::from_secs(5), self.fetch(&request)).await??;
        let lease = Arc::new(verify_freshness(
            &self.pin,
            &request,
            &encoded,
            requested_at,
            current()?,
            floor.as_ref(),
        )?);
        self.observe(lease.clone())?;
        if lease.body().authority_head != head {
            return Err("Hosting witness authority is no longer current.".into());
        }
        Ok(lease)
    }

    fn observe(&self, lease: Arc<VerifiedFreshness>) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Hosting witness unavailable.")?;
        if state.unavailable {
            return Err("Hosting witness floor could not be persisted.".into());
        }
        // Another Space may advance the global floor while this request is in flight.
        let now = current()?;
        check_floor(&state.floor, &lease, now)?;
        let next = Floor {
            v: 1,
            pin: self.pin.clone(),
            position: Some(lease.body().position.clone()),
        };
        if state.floor.position != next.position {
            if let Err(error) = save(&self.path, &next) {
                // We have observed a newer signed head. Older cached or borrowed
                // leases must not authorize anything after durability fails.
                state.unavailable = true;
                state.cache.clear();
                return Err(error);
            }
            state.floor = next;
        }
        state.cache.retain(|_, entry| entry.is_valid(now));
        let scope = (lease.body().space_id, lease.body().stream_id);
        if state.cache.len() >= MAX_CACHE && !state.cache.contains_key(&scope) {
            state.cache.pop_first();
        }
        state.cache.insert(scope, lease);
        Ok(())
    }

    async fn fetch(&self, request: &HeadRequest) -> Result<String> {
        let response = self
            .client
            .post(&self.endpoint)
            .json(request)
            .send()
            .await?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|size| size > RESPONSE_LIMIT as u64)
        {
            return Err("Hosting witness unavailable.".into());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > RESPONSE_LIMIT {
                return Err("Hosting witness response exceeds its limit.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            freshness: String,
        }
        Ok(serde_json::from_slice::<Reply>(&bytes)?.freshness)
    }
}

fn check_floor(floor: &Floor, lease: &VerifiedFreshness, now: u64) -> Result<()> {
    let body = lease.body();
    if !lease.is_valid(now)
        || body.audience != floor.pin.url
        || body.witness_key_generation != floor.pin.key_generation
        || floor.position.as_ref().is_some_and(|position| {
            body.position.sequence < position.sequence
                || (body.position.sequence == position.sequence
                    && body.position.record_id != position.record_id)
        })
    {
        return Err("Hosting witness lease is stale or conflicts with its floor.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;

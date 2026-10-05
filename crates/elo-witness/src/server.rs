use crate::{
    Error, Result,
    engine::Engine,
    journal::{self, Activation},
    wire::{Freshness, HeadRequest, Request},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Request as HttpRequest, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use elo_core::{
    ids::{RecordId, SpaceId, StreamId},
    record::SignedRecord,
};
use rusqlite::OptionalExtension;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const COMMAND_BYTES: usize = 9 * 1024 * 1024;
const HEAD_BYTES: usize = 1024;
const INGEST_SLOTS: usize = 4;

struct Budget {
    start: Instant,
    used: u32,
}
impl Budget {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            used: 0,
        }
    }
    fn take(&mut self, limit: u32) -> Result<()> {
        if self.start.elapsed() >= Duration::from_secs(1) {
            self.start = Instant::now();
            self.used = 0;
        }
        if self.used >= limit {
            return Err(Error::Limit);
        }
        self.used += 1;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct CachedHead {
    event: RecordId,
    head: RecordId,
}
struct HeadCache {
    entries: BTreeMap<(SpaceId, StreamId), CachedHead>,
    misses: Budget,
    #[cfg(test)]
    verifications: u64,
}
impl HeadCache {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            misses: Budget::new(),
            #[cfg(test)]
            verifications: 0,
        }
    }
    fn reply(&mut self, engine: &mut Engine, request: HeadRequest, now: u64) -> Result<String> {
        engine.journal.guard(now)?;
        request
            .nonce
            .parse::<RecordId>()
            .map_err(|_| Error::Invalid)?;
        // Keep the signed snapshot/digest check on every request, including hits.
        // An unchanged event ID alone is not evidence that SQLite rows are intact.
        let receipt = journal::verify_materialized_space(
            &engine.journal.db,
            request.space_id,
            &engine.journal.pin,
        )?;
        let event: String = engine
            .journal
            .db
            .query_row(
                "SELECT record_id FROM events WHERE space=?1 ORDER BY sequence DESC LIMIT 1",
                [request.space_id.to_string()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::Missing)?;
        let event: RecordId = event.parse().map_err(|_| Error::RecoveryRequired)?;
        let target = (request.space_id, request.stream_id);
        if let Some(cached) = self.entries.get(&target)
            && cached.event == event
            && cached.head == receipt.authority_head
        {
            // Only the verified authority head is cached. The signature, nonce,
            // time and global position are freshly produced for this request.
            let body = Freshness {
                v: 1,
                kind: "witness.freshness".into(),
                audience: engine.journal.pin.url.clone(),
                nonce: request.nonce,
                space_id: request.space_id,
                stream_id: request.stream_id,
                authority_head: cached.head,
                position: journal::position(&engine.journal.db)?,
                issued_at_ms: now,
                expires_at_ms: now.checked_add(30_000).ok_or(Error::Invalid)?,
                witness_key_generation: engine.journal.pin.key_generation,
            };
            return Ok(STANDARD.encode(
                SignedRecord::sign(
                    &serde_json::to_vec(&body).map_err(|_| Error::Invalid)?,
                    &engine.journal.key,
                )?
                .bytes(),
            ));
        }
        self.misses.take(8)?;
        #[cfg(test)]
        {
            self.verifications += 1;
        }
        let response = engine.head(request, now)?;
        let verified: Freshness = journal::decode(&response)?.decode()?;
        if self.entries.len() >= 128 && !self.entries.contains_key(&target) {
            self.entries.pop_first();
        }
        self.entries.insert(
            target,
            CachedHead {
                event,
                head: verified.authority_head,
            },
        );
        Ok(response)
    }
}

#[derive(Clone)]
pub struct Service {
    engine: Arc<Mutex<Engine>>,
    workers: Arc<Semaphore>,
    ingest: Arc<Semaphore>,
    rates: Arc<Mutex<BTreeMap<IpAddr, (Instant, u32)>>>,
    head_budget: Arc<Mutex<Budget>>,
    heads: Arc<Mutex<HeadCache>>,
    activation: PathBuf,
    proxy: bool,
}
impl Service {
    pub fn new(engine: Engine, activation: PathBuf, trusted_loopback_proxy: bool) -> Self {
        Self {
            engine: Arc::new(Mutex::new(engine)),
            workers: Arc::new(Semaphore::new(4)),
            ingest: Arc::new(Semaphore::new(INGEST_SLOTS)),
            rates: Arc::new(Mutex::new(BTreeMap::new())),
            head_budget: Arc::new(Mutex::new(Budget::new())),
            heads: Arc::new(Mutex::new(HeadCache::new())),
            activation,
            proxy: trusted_loopback_proxy,
        }
    }
    fn ip(&self, peer: SocketAddr, headers: &HeaderMap) -> Result<IpAddr> {
        if self.proxy {
            if !peer.ip().is_loopback() {
                return Err(Error::Unauthorized);
            }
            headers
                .get("x-real-ip")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.parse().ok())
                .ok_or(Error::Invalid)
        } else {
            Ok(peer.ip())
        }
    }
    fn rate(&self, ip: IpAddr) -> Result<()> {
        let mut rates = self.rates.lock().map_err(|_| Error::Unavailable)?;
        rates.retain(|_, (time, _)| time.elapsed() < Duration::from_secs(60));
        if rates.len() >= 4096 && !rates.contains_key(&ip) {
            return Err(Error::Limit);
        }
        let count = &mut rates.entry(ip).or_insert((Instant::now(), 0)).1;
        if *count >= 120 {
            return Err(Error::Limit);
        }
        *count += 1;
        Ok(())
    }
    async fn receive(
        &self,
        peer: SocketAddr,
        request: HttpRequest,
        head: bool,
    ) -> Result<(IpAddr, axum::body::Bytes, OwnedSemaphorePermit)> {
        let ip = self.ip(peer, request.headers())?;
        self.rate(ip)?;
        if head {
            self.head_budget
                .lock()
                .map_err(|_| Error::Unavailable)?
                .take(120)?;
        }
        // Admission precedes polling the body or parsing JSON. Keep this permit
        // through signature verification so queued decoded bodies stay bounded.
        let permit = self
            .ingest
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Limit)?;
        let limit = if head { HEAD_BYTES } else { COMMAND_BYTES };
        if request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.parse::<u64>().ok())
            .is_some_and(|n| n > limit as u64)
        {
            return Err(Error::Invalid);
        }
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split(';').next())
            .map(str::trim);
        if !content_type.is_some_and(|value| {
            value == "application/json"
                || (value.starts_with("application/") && value.ends_with("+json"))
        }) {
            return Err(Error::Invalid);
        }
        let timeout = if head {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(20)
        };
        let bytes = tokio::time::timeout(timeout, axum::body::to_bytes(request.into_body(), limit))
            .await
            .map_err(|_| Error::Invalid)?
            .map_err(|_| Error::Invalid)?;
        Ok((ip, bytes, permit))
    }
    async fn work<T: Send + 'static>(
        &self,
        task: impl FnOnce(&mut Engine, u64) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Limit)?;
        let engine = self.engine.clone();
        let activation = self.activation.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut engine = engine.lock().map_err(|_| Error::Unavailable)?;
            let now = crate::now_ms()?;
            // A runtime activation is consumed once and bound to this process.
            // There is deliberately no network administration endpoint.
            if activation.exists() {
                let result = (|| {
                    let bytes = elo_core::vault::read_private(&activation)
                        .map_err(|_| Error::Unavailable)?;
                    let body: Activation =
                        serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
                    engine.journal.activate(body, now)
                })();
                std::fs::remove_file(&activation).map_err(|_| Error::Unavailable)?;
                result?;
            }
            task(&mut engine, now)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}

pub fn router(service: Service) -> Router {
    Router::new()
        .route("/livez", get(|| async { StatusCode::OK }))
        .route("/readyz", get(ready))
        .route("/witness/v1/command", post(command))
        .route("/witness/v1/head", post(head))
        .with_state(service)
}
async fn ready(State(service): State<Service>) -> StatusCode {
    if service
        .work(|engine, now| Ok(engine.journal.ready(now)))
        .await
        .unwrap_or(false)
    {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn command(
    State(service): State<Service>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: HttpRequest,
) -> Result<Json<crate::wire::Response>> {
    let (ip, bytes, permit) = service.receive(peer, request, false).await?;
    Ok(Json(
        service
            .work(move |engine, now| {
                let _permit = permit;
                let request: Request =
                    serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
                engine.apply(request, ip, now)
            })
            .await?,
    ))
}
#[derive(Serialize)]
struct HeadReply {
    freshness: String,
}
async fn head(
    State(service): State<Service>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: HttpRequest,
) -> Result<Json<HeadReply>> {
    let (_, bytes, permit) = service.receive(peer, request, true).await?;
    let heads = service.heads.clone();
    Ok(Json(HeadReply {
        freshness: service
            .work(move |engine, now| {
                let _permit = permit;
                let request: HeadRequest =
                    serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
                heads
                    .lock()
                    .map_err(|_| Error::Unavailable)?
                    .reply(engine, request, now)
            })
            .await?,
    }))
}

#[cfg(test)]
mod tests;

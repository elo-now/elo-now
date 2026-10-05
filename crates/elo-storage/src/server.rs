use crate::{
    Error, Result,
    engine::{Engine, Object, Verified, private_dir},
    freshness::WitnessGate,
    now, now_ms,
    storage::{AttachmentStorage, S3CompatibleStorage},
};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use elo_core::{
    attachments::broker::{self, Operation, ProviderConfig, Request},
    authority::WitnessPin,
    ids::{AttachmentObjectId, RecordId, SpaceId, StreamId},
    record,
    witness::VerifiedFreshness,
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct Service {
    engine: Arc<Mutex<Engine>>,
    audience: String,
    trusted_loopback_proxy: bool,
    configs: Arc<Semaphore>,
    proofs: Arc<Semaphore>,
    transfers: Arc<Semaphore>,
    rate: Arc<Mutex<BTreeMap<IpAddr, (u64, u32)>>>,
    witness: Option<Arc<WitnessGate>>,
    #[cfg(test)]
    test_storage: Option<Arc<dyn AttachmentStorage>>,
}
impl Service {
    pub fn new(engine: Engine, audience: String, pin: WitnessPin) -> Result<Self> {
        let witness = Arc::new(WitnessGate::new(pin)?);
        engine.pin_witness(&witness.pin)?;
        Ok(Self::build(engine, audience, Some(witness)))
    }
    #[cfg(test)]
    pub(crate) fn new_test(engine: Engine, audience: String) -> Self {
        Self::build(engine, audience, None)
    }
    fn build(engine: Engine, audience: String, witness: Option<Arc<WitnessGate>>) -> Self {
        Self {
            engine: Arc::new(Mutex::new(engine)),
            audience,
            trusted_loopback_proxy: false,
            configs: Arc::new(Semaphore::new(1)),
            proofs: Arc::new(Semaphore::new(4)),
            transfers: Arc::new(Semaphore::new(8)),
            rate: Arc::new(Mutex::new(BTreeMap::new())),
            witness,
            #[cfg(test)]
            test_storage: None,
        }
    }
    pub fn trust_loopback_proxy(mut self, enabled: bool) -> Self {
        self.trusted_loopback_proxy = enabled;
        self
    }
    fn source_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> Result<IpAddr> {
        if self.trusted_loopback_proxy && peer.ip().is_loopback() {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .ok_or(Error::Invalid)
        } else {
            Ok(peer.ip())
        }
    }
    #[cfg(test)]
    pub(crate) fn with_test_storage(mut self, storage: Arc<dyn AttachmentStorage>) -> Self {
        self.test_storage = Some(storage);
        self
    }
    #[cfg(test)]
    pub(crate) fn with_test_witness_endpoint(
        mut self,
        pin: WitnessPin,
        endpoint: String,
    ) -> Result<Self> {
        self.lock()?.pin_witness(&pin)?;
        self.witness = Some(Arc::new(WitnessGate::new(pin)?.test_endpoint(endpoint)));
        Ok(self)
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Engine>> {
        self.engine.lock().map_err(|_| Error::Unavailable)
    }
    async fn fresh(
        &self,
        space: SpaceId,
        stream: StreamId,
        head: RecordId,
    ) -> Result<Option<Arc<VerifiedFreshness>>> {
        match &self.witness {
            Some(gate) => gate
                .require(&self.engine, space, stream, head)
                .await
                .map(Some),
            #[cfg(test)]
            None => Ok(None),
            #[cfg(not(test))]
            None => Err(Error::Unavailable),
        }
    }
    fn check_lease(&self, engine: &Engine, lease: &Option<Arc<VerifiedFreshness>>) -> Result<()> {
        match lease {
            Some(lease) => engine.check_witness(lease, now_ms()),
            #[cfg(test)]
            None if self.witness.is_none() => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }
    async fn claim(&self, object: AttachmentObjectId, token: &str, action: &str) -> Result<Object> {
        let target = self.lock()?.token_target(object, token, action, now())?;
        let lease = self.fresh(target.0, target.1, target.2).await?;
        let mut engine = self.lock()?;
        self.check_lease(&engine, &lease)?;
        if engine.token_target(object, token, action, now())? != target {
            return Err(Error::Unauthorized);
        }
        engine.claim(object, token, action, now())
    }
    fn rate(&self, ip: IpAddr) -> Result<()> {
        let now = now();
        let mut rates = self.rate.lock().map_err(|_| Error::Unavailable)?;
        rates.retain(|_, (start, _)| now.saturating_sub(*start) < 60);
        if rates.len() >= 4096 && !rates.contains_key(&ip) {
            return Err(Error::Limit);
        }
        let (_, count) = rates.entry(ip).or_insert((now, 0));
        if *count >= 120 {
            return Err(Error::Limit);
        }
        *count += 1;
        Ok(())
    }
    async fn open(
        &self,
        provider: &ProviderConfig,
        space: &str,
        revision: u64,
    ) -> Result<Arc<dyn AttachmentStorage>> {
        #[cfg(test)]
        if let Some(storage) = &self.test_storage {
            return Ok(storage.clone());
        }
        match provider {
            ProviderConfig::S3Compatible {
                endpoint,
                region,
                bucket,
                access_key,
                secret_key,
            } => S3CompatibleStorage::new(endpoint, region, bucket, access_key, secret_key)
                .await
                .map(|s| Arc::new(s) as Arc<dyn AttachmentStorage>)
                .map_err(|_| Error::Unavailable),
            ProviderConfig::MegaFolder {
                folder_link,
                write_auth,
            } => {
                let work: PathBuf = self
                    .lock()?
                    .data
                    .join("mega")
                    .join(space)
                    .join(revision.to_string());
                private_dir(&work)?;
                crate::mega::open(folder_link, write_auth, &work)
                    .await
                    .map_err(|_| Error::Unavailable)
            }
        }
    }
    async fn storage(&self, object: &Object) -> Result<Arc<dyn AttachmentStorage>> {
        let provider = self.lock()?.provider(&object.space, object.revision)?;
        self.open(&provider, &object.space, object.revision).await
    }
    pub async fn maintain(&self) {
        let objects = match self.lock().and_then(|e| e.garbage(now())) {
            Ok(objects) => objects,
            Err(_) => return,
        };
        for object in objects {
            let Ok(_slot) = self.transfers.clone().try_acquire_owned() else {
                break;
            };
            let result = async {
                let storage = self.storage(&object).await?;
                storage
                    .delete(&object.space, &object.object)
                    .await
                    .map_err(|_| Error::Unavailable)
            };
            if matches!(
                tokio::time::timeout(Duration::from_secs(90), result).await,
                Ok(Ok(()))
            ) {
                let _ = self.lock().and_then(|e| e.deleted(&object));
            }
        }
        let _ = self.lock().and_then(|e| e.prune(now()));
    }
}

#[cfg(test)]
mod tests;

pub fn router(service: Service) -> Router {
    // No bearer tokens in URLs: reverse-proxy access logs see only object IDs.
    Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/storage/v1/command",
            post(command).layer(DefaultBodyLimit::max(broker::MAX_REQUEST_BYTES)),
        )
        .route(
            "/storage/v1/objects/{object}",
            get(download).put(upload).layer(DefaultBodyLimit::disable()),
        )
        .with_state(service)
}

async fn command(
    State(service): State<Service>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> Result<axum::Json<broker::Response>> {
    let ip = service.source_ip(peer, request.headers())?;
    service.rate(ip)?;
    let slot = service
        .proofs
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Limit)?;
    let bytes = tokio::time::timeout(
        Duration::from_secs(20),
        axum::body::to_bytes(request.into_body(), broker::MAX_REQUEST_BYTES),
    )
    .await
    .map_err(|_| Error::Invalid)?
    .map_err(|_| Error::Invalid)?;
    let input: Request = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    let audience = service.audience.clone();
    let pin = service.witness.as_ref().map(|gate| gate.pin.clone());
    let (verified, _slot) = tokio::task::spawn_blocking(move || {
        let verified = match pin {
            Some(pin) => Verified::new(input, &audience, now(), &pin),
            #[cfg(test)]
            None => Verified::new_test(input, &audience, now()),
            #[cfg(not(test))]
            None => Err(Error::Unavailable),
        }?;
        Ok::<_, Error>((verified, slot))
    })
    .await
    .map_err(|_| Error::Unavailable)??;
    let scope = (
        verified.command.space_id,
        verified.command.stream_id,
        verified.command.config_id,
    );
    let lease = service.fresh(scope.0, scope.1, scope.2).await?;
    {
        let engine = service.lock()?;
        service.check_lease(&engine, &lease)?;
        if let Some(response) = engine.preflight(&verified, ip, now())? {
            return Ok(axum::Json(response));
        }
    }
    if let Operation::Configure {
        expected_revision,
        provider,
        ..
    } = &verified.command.operation
    {
        let _config_slot = service
            .configs
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Limit)?;
        if let ProviderConfig::MegaFolder {
            folder_link,
            write_auth,
        } = provider
        {
            tokio::time::timeout(
                Duration::from_secs(90),
                crate::mega::probe(folder_link, write_auth),
            )
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
        } else {
            // Verify access before activation. Probe objects are random and never
            // share an identifier with a user object. Cleanup touches only this probe.
            let store = service
                .open(
                    provider,
                    &verified.command.space_id.to_string(),
                    expected_revision + 1,
                )
                .await?;
            let probe = record::random_hex::<16>().map_err(|_| Error::Unavailable)?;
            let space = verified.command.space_id.to_string();
            let check = async {
                store
                    .put(&space, &probe, Body::from("elo-storage-probe-v1"), 20)
                    .await
                    .map_err(|_| Error::Unavailable)?;
                let mut got = store
                    .get(&space, &probe)
                    .await
                    .map_err(|_| Error::Unavailable)?;
                if got.size != 20 {
                    return Err(Error::Unavailable);
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = got.body.next().await {
                    bytes.extend_from_slice(&chunk.map_err(|_| Error::Unavailable)?);
                    if bytes.len() > 20 {
                        return Err(Error::Unavailable);
                    }
                }
                if bytes != b"elo-storage-probe-v1" {
                    return Err(Error::Unavailable);
                }
                Ok(())
            };
            let result = tokio::time::timeout(Duration::from_secs(90), check)
                .await
                .unwrap_or(Err(Error::Unavailable));
            let clean =
                tokio::time::timeout(Duration::from_secs(30), store.delete(&space, &probe)).await;
            result?;
            if !matches!(clean, Ok(Ok(()))) {
                return Err(Error::Unavailable);
            }
        }
    }
    // A provider probe may outlive the first lease. Revalidate immediately before
    // committing configuration, even when no newer proof has reached this broker.
    let lease = service.fresh(scope.0, scope.1, scope.2).await?;
    let mut engine = service.lock()?;
    service.check_lease(&engine, &lease)?;
    Ok(axum::Json(engine.apply(&verified, ip, now())?))
}
fn bearer(headers: &HeaderMap) -> Result<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)
}

struct UploadGuard {
    service: Service,
    object: Object,
    done: bool,
}
impl Drop for UploadGuard {
    fn drop(&mut self) {
        if !self.done {
            let _ = self
                .service
                .lock()
                .and_then(|e| e.uploaded(&self.object, false));
        }
    }
}
async fn upload(
    State(service): State<Service>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(object): Path<AttachmentObjectId>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode> {
    service.rate(service.source_ip(peer, &headers)?)?;
    let _slot = service
        .transfers
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Limit)?;
    let object = service.claim(object, bearer(&headers)?, "upload").await?;
    let mut guard = UploadGuard {
        service: service.clone(),
        object: object.clone(),
        done: false,
    };
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<u64>().ok())
        != Some(object.size)
    {
        return Err(Error::Invalid);
    }
    let storage = service.storage(&object).await?;
    let expected = object.size;
    let stats = Arc::new(Mutex::new((0u64, Sha256::new(), false)));
    let stats_stream = stats.clone();
    let body = Body::from_stream(body.into_data_stream().map(move |chunk| {
        let bytes = chunk.map_err(std::io::Error::other)?;
        let mut stats = stats_stream
            .lock()
            .map_err(|_| std::io::Error::other("Upload state unavailable."))?;
        stats.0 = stats.0.saturating_add(bytes.len() as u64);
        if stats.0 > expected {
            stats.2 = true;
            return Err(std::io::Error::other("Attachment size mismatch."));
        }
        stats.1.update(&bytes);
        Ok(bytes)
    }));
    let put = tokio::time::timeout(
        Duration::from_secs(90),
        storage.put(&object.space, &object.object, body, object.size),
    )
    .await;
    let valid = {
        let stats = stats.lock().map_err(|_| Error::Unavailable)?;
        !stats.2
            && stats.0 == object.size
            && record::encode_hex(&stats.1.clone().finalize()) == object.hash
    };
    if !matches!(put, Ok(Ok(()))) || !valid {
        return Err(Error::Invalid);
    }
    service.lock()?.uploaded(&object, true)?;
    guard.done = true;
    Ok(StatusCode::NO_CONTENT)
}

async fn download(
    State(service): State<Service>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(object): Path<AttachmentObjectId>,
    headers: HeaderMap,
) -> Result<Response> {
    service.rate(service.source_ip(peer, &headers)?)?;
    let slot = service
        .transfers
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Limit)?;
    let object = service.claim(object, bearer(&headers)?, "download").await?;
    let storage = service.storage(&object).await?;
    let stored = tokio::time::timeout(
        Duration::from_secs(90),
        storage.get(&object.space, &object.object),
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::Unavailable)?;
    if stored.size != object.size {
        return Err(Error::Unavailable);
    }
    let expected = object.size;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let stream = futures_util::stream::unfold(
        (stored.body, slot, 0u64),
        move |(mut stream, slot, seen)| async move {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    let next = seen.saturating_add(chunk.len() as u64);
                    if next > expected {
                        Some((
                            Err(std::io::Error::other("Attachment size mismatch.")),
                            (stream, slot, u64::MAX),
                        ))
                    } else {
                        Some((Ok(chunk), (stream, slot, next)))
                    }
                }
                Ok(None) if seen == expected => None,
                Ok(None) => Some((
                    Err(std::io::Error::other("Attachment ended early.")),
                    (stream, slot, expected),
                )),
                Ok(Some(Err(error))) => Some((Err(error), (stream, slot, expected))),
                Err(_) => Some((
                    Err(std::io::Error::other("Attachment download timed out.")),
                    (stream, slot, expected),
                )),
            }
        },
    );
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, object.size.to_string()),
            (header::CACHE_CONTROL, "no-store".into()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".into()),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

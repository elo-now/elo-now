//! Short witness leases are checked both for commands and token consumption.
//! The cache never extends a lease and is discarded on process restart.
use crate::{Error, Result, engine::Engine, now_ms};
use elo_core::{
    authority::WitnessPin,
    ids::{RecordId, SpaceId, StreamId},
    record,
    witness::{HeadRequest, VerifiedFreshness, verify_freshness},
};
use futures_util::StreamExt;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

pub(crate) struct WitnessGate {
    pub pin: WitnessPin,
    client: reqwest::Client,
    endpoint: String,
    cache: Mutex<BTreeMap<(SpaceId, StreamId), Arc<VerifiedFreshness>>>,
    requests: Semaphore,
}

impl WitnessGate {
    pub fn new(pin: WitnessPin) -> Result<Self> {
        pin.validate()?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            endpoint: format!("{}/head", pin.url.trim_end_matches('/')),
            pin,
            client,
            cache: Mutex::new(BTreeMap::new()),
            requests: Semaphore::new(8),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self
    }

    pub async fn require(
        &self,
        engine: &Arc<Mutex<Engine>>,
        space: SpaceId,
        stream: StreamId,
        head: RecordId,
    ) -> Result<Arc<VerifiedFreshness>> {
        let cached = self
            .cache
            .lock()
            .map_err(|_| Error::Unavailable)?
            .get(&(space, stream))
            .cloned();
        if let Some(cached) = cached
            && cached.body().authority_head == head
            && engine
                .lock()
                .map_err(|_| Error::Unavailable)?
                .check_witness(&cached, now_ms())
                .is_ok()
        {
            return Ok(cached);
        }
        let _request_slot = self.requests.try_acquire().map_err(|_| Error::Limit)?;
        let request = HeadRequest {
            space_id: space,
            stream_id: stream,
            nonce: record::random_hex::<32>()?,
        };
        let floor = engine
            .lock()
            .map_err(|_| Error::Unavailable)?
            .witness_position()?;
        let requested_at = Instant::now();
        let encoded = tokio::time::timeout(Duration::from_secs(5), async {
            let response = self
                .client
                .post(&self.endpoint)
                .json(&request)
                .send()
                .await
                .map_err(|_| Error::Unavailable)?;
            if !response.status().is_success()
                || response.content_length().is_some_and(|size| size > 16_384)
            {
                return Err(Error::Unavailable);
            }
            let mut stream = response.bytes_stream();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| Error::Unavailable)?;
                if bytes.len().saturating_add(chunk.len()) > 16_384 {
                    return Err(Error::Unavailable);
                }
                bytes.extend_from_slice(&chunk);
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Reply {
                freshness: String,
            }
            Ok(serde_json::from_slice::<Reply>(&bytes)
                .map_err(|_| Error::Unavailable)?
                .freshness)
        })
        .await
        .map_err(|_| Error::Unavailable)??;
        let lease = Arc::new(verify_freshness(
            &self.pin,
            &request,
            &encoded,
            requested_at,
            now_ms(),
            floor.as_ref(),
        )?);
        // Recheck the floor after network I/O: another request may have observed
        // a newer global journal position while this response was in flight.
        engine
            .lock()
            .map_err(|_| Error::Unavailable)?
            .observe_witness(&lease, now_ms())?;
        let mut cache = self.cache.lock().map_err(|_| Error::Unavailable)?;
        cache.retain(|_, value| value.is_valid(now_ms()));
        if cache.len() >= 128 && !cache.contains_key(&(space, stream)) {
            cache.pop_first();
        }
        cache.insert((space, stream), lease.clone());
        if lease.body().authority_head != head {
            return Err(Error::Unauthorized);
        }
        Ok(lease)
    }
}

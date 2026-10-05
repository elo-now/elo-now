use super::{Error, Result, UploadRequest};
use axum::{extract::Request, http::header};
use elo_core::ids::ObjectId;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const MAX_REQUEST_BYTES: usize = 3 * 1024 * 1024 / 2;

#[derive(Clone, Copy)]
struct Counter {
    started: Instant,
    used: u32,
}
impl Counter {
    fn take(&mut self, now: Instant, limit: u32) -> Result<()> {
        if now.saturating_duration_since(self.started) >= Duration::from_secs(60) {
            *self = Self {
                started: now,
                used: 0,
            };
        }
        if self.used >= limit {
            return Err(Error::Limit);
        }
        self.used += 1;
        Ok(())
    }
}
struct Budgets {
    global: Counter,
    networks: BTreeMap<[u8; 32], Counter>,
    spaces: BTreeMap<ObjectId, Counter>,
}

/// Admission is acquired before polling any request body. All maps and pending
/// operations are bounded even when an attacker rotates unauthenticated IPs.
pub(crate) struct Ingress {
    slots: Arc<Semaphore>,
    budgets: Mutex<Budgets>,
}
impl Ingress {
    pub fn new() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(4)),
            budgets: Mutex::new(Budgets {
                global: Counter {
                    started: Instant::now(),
                    used: 0,
                },
                networks: BTreeMap::new(),
                spaces: BTreeMap::new(),
            }),
        }
    }
    pub fn enter(
        &self,
        peer: IpAddr,
        space: Option<ObjectId>,
        now: Instant,
    ) -> Result<OwnedSemaphorePermit> {
        let mut budgets = self.budgets.lock().map_err(|_| Error::Unavailable)?;
        budgets.global.take(now, 240)?;
        budgets.networks.retain(|_, value| {
            now.saturating_duration_since(value.started) < Duration::from_secs(60)
        });
        budgets.spaces.retain(|_, value| {
            now.saturating_duration_since(value.started) < Duration::from_secs(60)
        });
        let network = network(peer);
        if budgets.networks.len() >= 1024 && !budgets.networks.contains_key(&network) {
            return Err(Error::Limit);
        }
        budgets
            .networks
            .entry(network)
            .or_insert(Counter {
                started: now,
                used: 0,
            })
            .take(now, 30)?;
        if let Some(space) = space {
            if budgets.spaces.len() >= 128 && !budgets.spaces.contains_key(&space) {
                return Err(Error::Limit);
            }
            budgets
                .spaces
                .entry(space)
                .or_insert(Counter {
                    started: now,
                    used: 0,
                })
                .take(now, 30)?;
        }
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Limit)
    }
}
fn network(ip: IpAddr) -> [u8; 32] {
    let prefix = match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.octets()[..8].to_vec(), |ip| ip.octets().to_vec()),
    };
    Sha256::digest(prefix).into()
}

impl Ingress {
    /// Keep the permit alive through signature checks, witness lookup and commit.
    pub async fn receive(
        &self,
        peer: IpAddr,
        hosted_space: ObjectId,
        request: Request,
    ) -> Result<(OwnedSemaphorePermit, UploadRequest)> {
        let permit = self.enter(peer, Some(hosted_space), Instant::now())?;
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if content_type.split(';').next().map(str::trim) != Some("application/json") {
            return Err(Error::Invalid);
        }
        if let Some(value) = request.headers().get(header::CONTENT_LENGTH) {
            let length: usize = value
                .to_str()
                .map_err(|_| Error::Invalid)?
                .parse()
                .map_err(|_| Error::Invalid)?;
            if length > MAX_REQUEST_BYTES {
                return Err(Error::Invalid);
            }
        }
        let body = tokio::time::timeout(
            Duration::from_secs(10),
            axum::body::to_bytes(request.into_body(), MAX_REQUEST_BYTES),
        )
        .await
        .map_err(|_| Error::Invalid)?
        .map_err(|_| Error::Invalid)?;
        let request = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
        Ok((permit, request))
    }
}

#[cfg(test)]
mod tests;

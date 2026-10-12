//! Bounded anonymous ingress, separate from CPU verification permits.
use crate::registry::CallError;
use axum::http::{HeaderMap, StatusCode};
use elo_core::ids::{IdentityId, RecordId};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// Mobile clients can overlap foreground control, native media, two incoming-call
// watchers, and a signed answer/mute command. Leave one slot for reconnection.
const DEVICE_CONNECTIONS: usize = 6;
const IDENTITY_CONNECTIONS: usize = 24;

pub(super) struct Ingress {
    slots: Arc<Semaphore>,
    sources: Mutex<BTreeMap<IpAddr, usize>>,
    source_limit: usize,
}
pub(super) struct Permit {
    ingress: Arc<Ingress>,
    source: IpAddr,
    _slot: OwnedSemaphorePermit,
}
impl Ingress {
    pub(super) fn new() -> Arc<Self> {
        Self::with_limits(4, 2)
    }
    pub(super) fn websocket() -> Arc<Self> {
        // A small same-network burst must accommodate several devices without
        // competing with slow HTTP state bodies for handshake capacity.
        Self::with_limits(8, 4)
    }
    fn with_limits(global: usize, per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(Semaphore::new(global)),
            sources: Mutex::new(BTreeMap::new()),
            source_limit: per_source,
        })
    }
    pub(super) fn acquire(self: &Arc<Self>, ip: IpAddr) -> Result<Permit, StatusCode> {
        let source = network(ip);
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if sources.get(&source).copied().unwrap_or(0) >= self.source_limit {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        *sources.entry(source).or_default() += 1;
        Ok(Permit {
            ingress: self.clone(),
            source,
            _slot: slot,
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut sources) = self.ingress.sources.lock()
            && let Some(count) = sources.get_mut(&self.source)
        {
            *count -= 1;
            if *count == 0 {
                sources.remove(&self.source);
            }
        }
    }
}
#[derive(Default)]
struct ConnectionCounts {
    identities: BTreeMap<IdentityId, usize>,
    devices: BTreeMap<RecordId, usize>,
}

#[derive(Default)]
pub(super) struct Connections {
    counts: Mutex<ConnectionCounts>,
}

pub(super) struct ConnectionPermit {
    connections: Arc<Connections>,
    identity: IdentityId,
    device: RecordId,
}

impl Connections {
    /// Only verified, currently admitted credentials enter this map. The global
    /// connection semaphore remains held for the same socket lifetime.
    pub(super) fn acquire(
        self: &Arc<Self>,
        identity: IdentityId,
        device: RecordId,
    ) -> Result<ConnectionPermit, CallError> {
        let mut counts = self.counts.lock().map_err(|_| CallError::Unavailable)?;
        if counts.devices.get(&device).copied().unwrap_or(0) >= DEVICE_CONNECTIONS
            || counts.identities.get(&identity).copied().unwrap_or(0) >= IDENTITY_CONNECTIONS
        {
            return Err(CallError::Unavailable);
        }
        *counts.devices.entry(device).or_default() += 1;
        *counts.identities.entry(identity).or_default() += 1;
        Ok(ConnectionPermit {
            connections: self.clone(),
            identity,
            device,
        })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.connections.counts.lock() {
            if let Some(count) = counts.devices.get_mut(&self.device) {
                *count -= 1;
                if *count == 0 {
                    counts.devices.remove(&self.device);
                }
            }
            if let Some(count) = counts.identities.get_mut(&self.identity) {
                *count -= 1;
                if *count == 0 {
                    counts.identities.remove(&self.identity);
                }
            }
        }
    }
}

fn network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => IpAddr::V4(ip),
            None => {
                let mut bytes = ip.octets();
                bytes[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
        },
    }
}
pub(super) fn source(peer: SocketAddr, headers: &HeaderMap) -> Result<IpAddr, StatusCode> {
    // The binary binds only to loopback. Caddy overwrites X-Real-IP; direct
    // non-loopback callers cannot choose their own quota bucket.
    if peer.ip().is_loopback() && headers.contains_key("x-real-ip") {
        if headers.get_all("x-real-ip").iter().count() != 1 {
            return Err(StatusCode::BAD_REQUEST);
        }
        return headers["x-real-ip"]
            .to_str()
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or(StatusCode::BAD_REQUEST);
    }
    Ok(peer.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_quota_normalizes_networks_and_releases_on_drop() {
        let gate = Ingress::new();
        let a = gate.acquire("192.0.2.1".parse().unwrap()).unwrap();
        let b = gate.acquire("::ffff:192.0.2.1".parse().unwrap()).unwrap();
        assert!(matches!(
            gate.acquire("192.0.2.1".parse().unwrap()),
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));
        let other = gate.acquire("192.0.2.2".parse().unwrap()).unwrap();
        drop(a);
        drop(b);
        drop(other);
        let a = gate.acquire("2001:db8::1".parse().unwrap()).unwrap();
        let b = gate.acquire("2001:db8::2".parse().unwrap()).unwrap();
        assert!(gate.acquire("2001:db8::ffff".parse().unwrap()).is_err());
        drop(a);
        drop(b);
        assert!(gate.sources.lock().unwrap().is_empty());
        assert_eq!(gate.slots.available_permits(), 4);
    }
    #[test]
    fn websocket_handshakes_allow_a_small_nat_burst_without_using_http_slots() {
        let websocket = Ingress::websocket();
        let http = Ingress::new();
        let source = "192.0.2.1".parse().unwrap();
        let http_permits: Vec<_> = (0..2).map(|_| http.acquire(source).unwrap()).collect();
        assert!(http.acquire(source).is_err());
        let websocket_permits: Vec<_> =
            (0..4).map(|_| websocket.acquire(source).unwrap()).collect();
        assert!(websocket.acquire(source).is_err());
        assert!(websocket.acquire("192.0.2.2".parse().unwrap()).is_ok());
        drop(http_permits);
        drop(websocket_permits);
        assert!(http.sources.lock().unwrap().is_empty());
        assert!(websocket.sources.lock().unwrap().is_empty());
    }

    #[test]
    fn authenticated_connection_quotas_allow_mobile_answer_handoff_and_reconnect() {
        let limits = Arc::new(Connections::default());
        let identity = IdentityId::from_bytes([1; 32]);
        let device = RecordId::from_bytes([2; 32]);
        let foreground = limits.acquire(identity, device).unwrap();
        let native_media = limits.acquire(identity, device).unwrap();
        let active_watch = limits.acquire(identity, device).unwrap();
        let waiting_watch = limits.acquire(identity, device).unwrap();
        let answer = limits.acquire(identity, device).unwrap();
        let reconnect = limits.acquire(identity, device).unwrap();
        assert!(limits.acquire(identity, device).is_err());
        drop(foreground);
        let replacement = limits.acquire(identity, device).unwrap();
        let mut linked = Vec::new();
        for index in 3..6 {
            for _ in 0..DEVICE_CONNECTIONS {
                linked.push(
                    limits
                        .acquire(identity, RecordId::from_bytes([index; 32]))
                        .unwrap(),
                );
            }
        }
        assert!(
            limits
                .acquire(identity, RecordId::from_bytes([9; 32]))
                .is_err()
        );
        assert!(
            !limits
                .counts
                .lock()
                .unwrap()
                .devices
                .contains_key(&RecordId::from_bytes([9; 32]))
        );
        let other = limits
            .acquire(
                IdentityId::from_bytes([10; 32]),
                RecordId::from_bytes([11; 32]),
            )
            .unwrap();
        drop(reconnect);
        drop(replacement);
        drop(native_media);
        drop(active_watch);
        drop(waiting_watch);
        drop(answer);
        drop(linked);
        drop(other);
        let counts = limits.counts.lock().unwrap();
        assert!(counts.devices.is_empty());
        assert!(counts.identities.is_empty());
    }

    #[test]
    fn public_sources_cannot_spoof_the_proxy_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.1".parse().unwrap());
        assert_eq!(
            source("192.0.2.1:90".parse().unwrap(), &headers).unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            source("127.0.0.1:90".parse().unwrap(), &headers).unwrap(),
            "198.51.100.1".parse::<IpAddr>().unwrap()
        );
    }
}

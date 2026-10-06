//! Native-pinned freshness. Hosting responses can never renew these leases.
use super::*;
use crate::{
    authority::{CallAuthorityProof, WitnessPin},
    witness::{self, HeadRequest, Position, VerifiedFreshness},
};
use std::time::{Duration, Instant};

const FLOOR_BYTES: usize = 32 * 1024;

/// An unavailable transport cannot verify a restored Space, but must not be
/// confused with a successfully received, invalid authorization proof.
#[derive(Debug, thiserror::Error)]
#[error("Chat permissions need to be refreshed.")]
pub(super) struct WitnessUnavailable;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Floors {
    entries: BTreeMap<String, Position>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadReply {
    freshness: String,
}

impl ClientApp {
    /// Native lifecycle hook. Existing live snapshots observe the invalidation.
    pub fn invalidate_permission_leases(&self) {
        self.membership_checks.clear_now();
        if let Some(spaces) = &self.spaces {
            for client in spaces.clients(self) {
                client.membership_checks.clear_now();
            }
        }
    }
    /// Supplied by the native build only. Never adopt a network or renderer pin.
    pub fn configure_witness_pin(&mut self, pin: Option<WitnessPin>) -> Result<()> {
        if let Some(pin) = &pin {
            pin.validate()?;
        }
        if self.witness_pin != pin {
            self.membership_checks.clear_now();
        }
        self.witness_pin = pin.clone();
        if let Some(spaces) = &mut self.spaces {
            spaces.configure_witness_pin(pin)?;
        }
        self.refresh_default_hosting_context();
        Ok(())
    }

    /// Full General proofs still require an independently configured anchor.
    pub(super) fn verify_general_proof(
        &self,
        proof: &CallAuthorityProof,
        space: SpaceId,
        stream: StreamId,
    ) -> Result<Authority> {
        if proof.genesis.len() > record::MAX_RECORD.div_ceil(3) * 4 {
            return Err("Chat permissions need to be refreshed.".into());
        }
        // The native deployment selects the protocol. An invitation cannot
        // downgrade a new General to authorization by the hosting service.
        Ok(match self.witness_pin.as_ref() {
            Some(pin) => proof.verify_witnessed(space, stream, pin)?,
            None => proof.verify(space, stream)?,
        })
    }

    pub(super) fn trusted_witness(&self, authority: &Authority) -> Result<&WitnessPin> {
        let pin = self
            .witness_pin
            .as_ref()
            .ok_or("Chat permissions need to be refreshed.")?;
        if authority.witness_pin().is_none() {
            return Err("This Space uses an unsupported access protocol.".into());
        }
        if authority.witness_pin() != Some(pin) || authority.is_forked() {
            return Err("Chat permissions need to be refreshed.".into());
        }
        Ok(pin)
    }

    fn witness_floors(&self) -> Result<Floors> {
        let path = self.directory.join("witness-floors.age");
        if !path.exists() {
            return Ok(Floors::default());
        }
        let encrypted = read_exchange(&path, FLOOR_BYTES * 2)?;
        let plain = Zeroizing::new(crypto::open_bytes(
            &encrypted,
            self.session.age_identity(),
            FLOOR_BYTES,
        )?);
        let floors: Floors = serde_json::from_slice(&plain)?;
        if floors.entries.len() > 32
            || floors.entries.iter().any(|(key, value)| {
                key.parse::<RecordId>().is_err()
                    || value.sequence == 0
                    || value.sequence > record::MAX_INTEGER
                    || value.record_id.is_none()
            })
        {
            return Err("Chat permissions need to be refreshed.".into());
        }
        Ok(floors)
    }

    fn persist_witness_floor(
        &self,
        mut floors: Floors,
        key: String,
        position: Position,
    ) -> Result<()> {
        if floors.entries.get(&key) == Some(&position) {
            return Ok(());
        }
        if floors.entries.len() >= 32 && !floors.entries.contains_key(&key) {
            return Err("Chat permissions need to be refreshed.".into());
        }
        floors.entries.insert(key, position);
        let plain = Zeroizing::new(serde_json::to_vec(&floors)?);
        let sealed = crypto::seal_bytes(
            &plain,
            &[self.session.age_identity().to_public()],
            FLOOR_BYTES,
        )?;
        vault::write_private(&self.directory.join("witness-floors.age"), &sealed, true)?;
        Ok(())
    }

    pub(super) fn witness_position(&self, pin: &WitnessPin) -> Result<Option<Position>> {
        let _guard = self
            .witness_floor_lock
            .lock()
            .map_err(|_| "Chat permissions need to be refreshed.")?;
        let key = RecordId::of_record_bytes(&serde_json::to_vec(pin)?).to_string();
        Ok(self.witness_floors()?.entries.get(&key).cloned())
    }

    /// Re-read under the same profile lock immediately before writing. Parallel
    /// valid replies must never replace a higher position with an older one.
    pub(super) fn record_witness_position(
        &self,
        pin: &WitnessPin,
        position: Position,
    ) -> Result<()> {
        self.store_witness_position(pin, position, None)
    }

    pub(super) fn record_witness_receipt_position(
        &self,
        pin: &WitnessPin,
        position: Position,
        previous: Option<RecordId>,
    ) -> Result<()> {
        self.store_witness_position(pin, position, Some(previous))
    }

    /// An acknowledged candidate admission is only an anchor for a subsequent
    /// full Read and fresh Head. A concurrent response may already have persisted
    /// a newer floor; preserve it without replaying the mutation. Known equal
    /// sequence or immediate-predecessor forks must still fail under this lock.
    pub(super) fn record_admission_receipt_position(
        &self,
        pin: &WitnessPin,
        position: Position,
        previous: Option<RecordId>,
    ) -> Result<()> {
        let _guard = self
            .witness_floor_lock
            .lock()
            .map_err(|_| "Chat permissions need to be refreshed.")?;
        let key = RecordId::of_record_bytes(&serde_json::to_vec(pin)?).to_string();
        let floors = self.witness_floors()?;
        if position.sequence == 0
            || position.sequence > record::MAX_INTEGER
            || position.record_id.is_none()
            || floors.entries.get(&key).is_some_and(|prior| {
                (position.sequence == prior.sequence && position.record_id != prior.record_id)
                    || (position.sequence == prior.sequence.saturating_add(1)
                        && previous != prior.record_id)
            })
        {
            return Err("Chat permissions need to be refreshed.".into());
        }
        if floors
            .entries
            .get(&key)
            .is_some_and(|prior| position.sequence <= prior.sequence)
        {
            return Ok(());
        }
        self.persist_witness_floor(floors, key, position)
    }

    fn store_witness_position(
        &self,
        pin: &WitnessPin,
        position: Position,
        receipt_previous: Option<Option<RecordId>>,
    ) -> Result<()> {
        let _guard = self
            .witness_floor_lock
            .lock()
            .map_err(|_| "Chat permissions need to be refreshed.")?;
        let key = RecordId::of_record_bytes(&serde_json::to_vec(pin)?).to_string();
        let floors = self.witness_floors()?;
        if position.sequence == 0
            || position.sequence > record::MAX_INTEGER
            || position.record_id.is_none()
            || floors.entries.get(&key).is_some_and(|prior| {
                position.sequence < prior.sequence
                    || (position.sequence == prior.sequence
                        && position.record_id != prior.record_id)
                    || (position.sequence == prior.sequence.saturating_add(1)
                        && receipt_previous.is_some_and(|previous| previous != prior.record_id))
            })
        {
            return Err("Chat permissions need to be refreshed.".into());
        }
        self.persist_witness_floor(floors, key, position)
    }

    pub(super) fn witness_endpoint(&self, pin: &WitnessPin, route: &str) -> Result<String> {
        let endpoint = format!("{}/{route}", pin.url.trim_end_matches('/'));
        #[cfg(test)]
        if let Some(test) = &self.witness_test_url {
            let mut url = reqwest::Url::parse(test)?;
            if url.scheme() != "http"
                || !url.host_str().is_some_and(|host| {
                    host.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                })
            {
                return Err("Invalid witness test endpoint.".into());
            }
            url.set_path(&format!("/{route}"));
            return Ok(url.to_string());
        }
        Ok(endpoint)
    }

    pub(super) async fn fetch_witness_freshness(
        &self,
        authority: &Authority,
        started: Instant,
    ) -> Result<VerifiedFreshness> {
        let pin = self.trusted_witness(authority)?;
        let floor = self.witness_position(pin)?;
        let request = HeadRequest {
            space_id: authority.space(),
            stream_id: authority.stream(),
            nonce: record::random_hex::<32>()?,
        };
        let endpoint = self.witness_endpoint(pin, "head")?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(10))
            .build()?;
        let response = client
            .post(endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|_| WitnessUnavailable)?;
        if response.status().is_server_error()
            || matches!(
                response.status(),
                reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::TOO_MANY_REQUESTS
            )
        {
            return Err(WitnessUnavailable.into());
        }
        if !response.status().is_success()
            || response.content_length().is_some_and(|size| size > 24_576)
        {
            return Err("Chat permissions need to be refreshed.".into());
        }
        use futures_util::StreamExt;
        let mut chunks = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|_| WitnessUnavailable)?;
            if bytes.len().saturating_add(chunk.len()) > 24_576 {
                return Err("Chat permissions need to be refreshed.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let reply: HeadReply = serde_json::from_slice(&bytes)?;
        let fresh = witness::verify_freshness(
            pin,
            &request,
            &reply.freshness,
            started,
            now()?.as_millis() as u64,
            floor.as_ref(),
        )?;
        // Persist even a newer head that needs importing. A failed refresh must
        // not let the next response move this profile's witness floor backwards.
        self.record_witness_position(pin, fresh.body().position.clone())?;
        if authority.head_id() != Some(fresh.body().authority_head) {
            return Err("Chat permissions need to be refreshed.".into());
        }
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests;

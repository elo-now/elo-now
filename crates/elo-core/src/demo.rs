//! Explicitly insecure, synthetic local demo input. Never a production vault.
use crate::{
    identity::VerifiedCredential,
    ids::{IdentityId, RecordId, SpaceId, StreamId},
    record::{RecordError, hex},
    sync::{FixedDemoAuthority, Peer, PeerDescriptor},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoCredential {
    pub root_public_key: String,
    pub signed_record_base64: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoConfig {
    pub v: u64,
    pub warning: String,
    pub own_credential: RecordId,
    pub age_identity: String,
    pub space: SpaceId,
    pub stream: StreamId,
    pub config: RecordId,
    pub readers: Vec<IdentityId>,
    pub posters: Vec<IdentityId>,
    pub credentials: Vec<DemoCredential>,
    pub peers: Vec<PeerDescriptor>,
}
pub struct LoadedDemo {
    pub own_credential: RecordId,
    pub identity: age::x25519::Identity,
    pub authority: FixedDemoAuthority,
    pub peers: Vec<Peer>,
}
impl DemoConfig {
    pub fn load(&self) -> Result<LoadedDemo, RecordError> {
        if self.v != 1
            || self.warning != "PUBLIC SYNTHETIC TEST ONLY; UNPROTECTED KEYS"
            || self.credentials.len() > 32
            || self.peers.len() > 8
        {
            return Err(RecordError::Authority);
        }
        let identity: age::x25519::Identity = self
            .age_identity
            .parse()
            .map_err(|_| RecordError::Authority)?;
        let mut credentials = std::collections::BTreeMap::new();
        for c in &self.credentials {
            let root = VerifyingKey::from_bytes(&hex(&c.root_public_key)?)
                .map_err(|_| RecordError::Signature)?;
            let bytes = STANDARD
                .decode(&c.signed_record_base64)
                .map_err(|_| RecordError::Json)?;
            let credential = VerifiedCredential::verify(&bytes, &root)?;
            if credentials.insert(credential.id(), credential).is_some() {
                return Err(RecordError::Authority);
            }
        }
        let own = credentials
            .get(&self.own_credential)
            .ok_or(RecordError::Authority)?;
        if own.recipient() != identity.to_public() {
            return Err(RecordError::Authority);
        }
        let authority = FixedDemoAuthority {
            space: self.space,
            stream: self.stream,
            config: self.config,
            readers: self.readers.iter().copied().collect(),
            posters: self.posters.iter().copied().collect(),
            credentials,
        };
        let peers = self
            .peers
            .iter()
            .map(|p| Peer::new(p.clone(), true).map_err(|_| RecordError::Authority))
            .collect::<Result<_, _>>()?;
        Ok(LoadedDemo {
            own_credential: self.own_credential,
            identity,
            authority,
            peers,
        })
    }
}

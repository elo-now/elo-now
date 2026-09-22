//! Explicitly public membership proofs for an authenticated call service.
//! These records disclose membership metadata, never profile or media secrets.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

pub const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallAuthorityProof {
    pub v: u8,
    pub genesis: String,
    pub credentials: Vec<String>,
    pub configs: Vec<String>,
}

impl Authority {
    pub fn call_proof(&self) -> Result<CallAuthorityProof> {
        if self.is_forked() {
            return Err(RecordError::Authority);
        }
        let mut configs = self.configs.values().collect::<Vec<_>>();
        configs.sort_by_key(|(record, config)| (config.sequence, record.id()));
        let proof = CallAuthorityProof {
            v: 1,
            genesis: STANDARD.encode(self.genesis.bytes()),
            credentials: self
                .credentials
                .values()
                .map(|c| STANDARD.encode(c.record().bytes()))
                .collect(),
            configs: configs
                .iter()
                .map(|(r, _)| STANDARD.encode(r.bytes()))
                .collect(),
        };
        proof.check_size()?;
        Ok(proof)
    }
}

impl CallAuthorityProof {
    fn check_size(&self) -> Result<()> {
        if self.v != 1
            || self.credentials.len() > 8192
            || self.configs.len() > 4096
            || self.configs.is_empty()
            || self.genesis.len().saturating_add(
                self.credentials
                    .iter()
                    .chain(&self.configs)
                    .map(String::len)
                    .sum::<usize>(),
            ) > MAX_PROOF_BYTES
        {
            return Err(RecordError::Authority);
        }
        Ok(())
    }

    /// The Space ID is content-addressed. This proves its chain, not admission
    /// to a deployment or freshness beyond the server's known configuration.
    pub fn verify(&self, space: SpaceId, stream: StreamId) -> Result<Authority> {
        self.check_size()?;
        let decode = |s: &str| STANDARD.decode(s).map_err(|_| RecordError::Json);
        let genesis = SignedRecord::parse(&decode(&self.genesis)?)?;
        let body: SpaceGenesis = genesis.decode()?;
        let root = body
            .owners
            .iter()
            .find(|owner| owner.identity_id == body.issuer_identity)
            .ok_or(RecordError::Authority)?;
        let root = VerifyingKey::from_bytes(&record::hex(&root.root_public_key)?)
            .map_err(|_| RecordError::Signature)?;
        let mut credentials = BTreeMap::new();
        for encoded in &self.credentials {
            let bytes = decode(encoded)?;
            let record = SignedRecord::parse(&bytes)?;
            let root = VerifyingKey::from_bytes(&record::hex(
                record.body()["root_public_key"]
                    .as_str()
                    .ok_or(RecordError::Json)?,
            )?)
            .map_err(|_| RecordError::Signature)?;
            let credential = VerifiedCredential::verify(&bytes, &root)?;
            if credentials.insert(credential.id(), credential).is_some() {
                return Err(RecordError::Authority);
            }
        }
        let controller = credentials
            .get(&body.controller_credential_id)
            .ok_or(RecordError::Authority)?
            .clone();
        let mut authority = Authority::new(genesis.bytes(), space, &root, controller, stream)?;
        for credential in credentials.into_values() {
            authority.add_credential(credential);
        }
        for encoded in &self.configs {
            match authority.apply_config(SignedRecord::parse(&decode(encoded)?)?)? {
                ConfigAdmission::Applied | ConfigAdmission::Historical => {}
                _ => return Err(RecordError::Authority),
            }
        }
        if authority.is_forked() {
            return Err(RecordError::Authority);
        }
        authority.head()?;
        Ok(authority)
    }
}

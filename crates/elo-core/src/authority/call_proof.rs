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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
}

impl Authority {
    /// Only the controller can issue a new checkpoint. Other members reuse the
    /// ordinary proof; an absent controller key must never weaken verification.
    pub fn call_proof_signed(&self, key: &SigningKey) -> Result<CallAuthorityProof> {
        if self.controller().key() != &key.verifying_key() {
            return self.call_proof();
        }
        self.checkpoint_proof(self.sign_checkpoint(key)?)
    }

    fn checkpoint_proof(&self, signed: SignedRecord) -> Result<CallAuthorityProof> {
        let ids = self
            .head()?
            .members
            .iter()
            .flat_map(|m| m.credential_ids.iter().copied())
            .chain([self.initial_controller().id(), self.controller().id()])
            .collect::<BTreeSet<_>>();
        let proof = CallAuthorityProof {
            v: 2,
            genesis: STANDARD.encode(self.genesis.bytes()),
            credentials: ids
                .into_iter()
                .map(|id| {
                    self.credential(id)
                        .map(|c| STANDARD.encode(c.record().bytes()))
                })
                .collect::<Result<_>>()?,
            configs: vec![
                STANDARD.encode(
                    self.config_record(self.head_id().ok_or(RecordError::Authority)?)?
                        .bytes(),
                ),
            ],
            checkpoint: Some(STANDARD.encode(signed.bytes())),
        };
        proof.check_size()?;
        Ok(proof)
    }

    pub fn call_proof(&self) -> Result<CallAuthorityProof> {
        if let Some(checkpoint) = self.current_checkpoint() {
            if self.is_forked() {
                return Err(RecordError::Authority);
            }
            return self.checkpoint_proof(checkpoint.clone());
        }
        if self.is_forked() {
            return Err(RecordError::Authority);
        }
        let mut configs = self.configs.values().collect::<Vec<_>>();
        configs.sort_by_key(|(record, config)| (config.sequence, record.id()));
        let proof = CallAuthorityProof {
            v: 1,
            checkpoint: None,
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
        if !matches!((self.v, self.checkpoint.is_some()), (1, false) | (2, true))
            || (self.v == 2 && self.configs.len() != 1)
            || self.credentials.len() > 8192
            || self.configs.len() > 4096
            || self.configs.is_empty()
            || self
                .genesis
                .len()
                .saturating_add(self.checkpoint.as_ref().map_or(0, String::len))
                .saturating_add(
                    self.credentials
                        .iter()
                        .chain(&self.configs)
                        .map(String::len)
                        .sum::<usize>(),
                )
                > MAX_PROOF_BYTES
        {
            return Err(RecordError::Authority);
        }
        Ok(())
    }

    /// Verify only the named device before spending work on its config chain.
    pub fn credential(&self, id: RecordId) -> Result<VerifiedCredential> {
        self.check_size()?;
        for encoded in &self.credentials {
            let bytes = STANDARD.decode(encoded).map_err(|_| RecordError::Json)?;
            if RecordId::of_record_bytes(&bytes) != id {
                continue;
            }
            let signed = SignedRecord::parse(&bytes)?;
            let root = VerifyingKey::from_bytes(&record::hex(
                signed.body()["root_public_key"]
                    .as_str()
                    .ok_or(RecordError::Json)?,
            )?)
            .map_err(|_| RecordError::Signature)?;
            return VerifiedCredential::verify(&bytes, &root);
        }
        Err(RecordError::Authority)
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
        if let Some(checkpoint) = &self.checkpoint {
            authority.load_checkpoint(
                SignedRecord::parse(&decode(checkpoint)?)?,
                SignedRecord::parse(&decode(&self.configs[0])?)?,
            )?;
            return Ok(authority);
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

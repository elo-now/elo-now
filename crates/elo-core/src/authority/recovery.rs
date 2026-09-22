//! Explicit root-authorized replacement of a lost controller with a fresh key.
//! A generation fences old signers only at clients that have adopted its proof.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerRecovery {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub sequence: u64,
    pub previous_recovery_id: Option<RecordId>,
    pub previous_controller_credential_id: RecordId,
    pub controller_credential_id: RecordId,
}

fn embedded(c: &StreamConfig) -> Result<Option<SignedRecord>> {
    c.recovery
        .as_ref()
        .map(|s| {
            if s.len() > 8192 {
                return Err(RecordError::Framing);
            }
            SignedRecord::parse(&STANDARD.decode(s).map_err(|_| RecordError::Json)?)
        })
        .transpose()
}

impl Authority {
    /// Compare the controller generations known across this Space's Streams.
    /// Include this authority even when it is a newly received external proof.
    pub fn controller_ready_with(&self, peers: &[Self]) -> bool {
        let mut children = BTreeMap::new();
        let mut latest = (0, self.initial_controller().id());
        for peer in peers
            .iter()
            .chain(std::iter::once(self))
            .filter(|p| p.space() == self.space())
        {
            let Ok(records) = peer.recovery_records() else {
                return false;
            };
            for r in records {
                let Ok(b) = r.decode::<crate::authority::ControllerRecovery>() else {
                    return false;
                };
                if children
                    .insert(b.previous_recovery_id, r.id())
                    .is_some_and(|old| old != r.id())
                {
                    return false;
                }
                if b.sequence > latest.0 {
                    latest = (b.sequence, b.controller_credential_id);
                }
            }
        }
        !self.is_forked() && self.controller().id() == latest.1
    }
    pub fn controller_recovery_chain(&self) -> Result<Vec<SignedRecord>> {
        self.chain_at(self.head)
    }
    /// Check the narrow controller proof carried by invitations, without
    /// revealing a Stream's membership/configuration history to its holder.
    pub fn verify_controller_export(
        &self,
        chain: &[SignedRecord],
        current: &VerifiedCredential,
    ) -> Result<()> {
        let initial = self.initial_controller();
        let root = VerifyingKey::from_bytes(&record::hex(
            initial.record().body()["root_public_key"]
                .as_str()
                .ok_or(RecordError::Authority)?,
        )?)
        .map_err(|_| RecordError::Authority)?;
        let mut previous = None;
        let mut controller = initial.id();
        if chain.len() > 64
            || current.identity() != initial.identity()
            || current.record().body()["root_public_key"]
                != initial.record().body()["root_public_key"]
        {
            return Err(RecordError::Authority);
        }
        let mut seen = BTreeSet::from([controller]);
        for (i, r) in chain.iter().enumerate() {
            r.verify_signature(&root)?;
            let b: ControllerRecovery = r.decode()?;
            record::hex::<16>(&b.nonce)?;
            if b.v != 1
                || b.kind != "space.controller.recovered"
                || b.space_id != self.space()
                || b.sequence != i as u64 + 1
                || b.previous_recovery_id != previous
                || b.previous_controller_credential_id != controller
                || !seen.insert(b.controller_credential_id)
            {
                return Err(RecordError::Authority);
            }
            previous = Some(r.id());
            controller = b.controller_credential_id;
        }
        if controller != current.id() {
            return Err(RecordError::Authority);
        }
        Ok(())
    }
    fn chain_at(&self, mut id: Option<RecordId>) -> Result<Vec<SignedRecord>> {
        let mut chain = Vec::new();
        while let Some(next) = id {
            let c = self.config(next)?;
            if let Some(r) = embedded(c)? {
                chain.push(r);
            }
            id = c.previous_config_id;
        }
        chain.reverse();
        Ok(chain)
    }
    pub fn recovery_id(&self) -> Option<RecordId> {
        self.chain_at(self.head)
            .ok()
            .and_then(|p| p.last().map(SignedRecord::id))
    }
    pub fn initial_controller(&self) -> &VerifiedCredential {
        &self.credentials[&self.body.controller_credential_id]
    }
    pub fn recovery_records(&self) -> Result<Vec<SignedRecord>> {
        let mut records = BTreeMap::new();
        for (_, c) in self.configs.values() {
            if let Some(r) = embedded(c)? {
                let b: ControllerRecovery = r.decode()?;
                records.insert((b.sequence, r.id()), r);
            }
        }
        Ok(records.into_values().collect())
    }
    /// The owner explicitly approves a new generation. Reuse this exact record
    /// for the other Streams of this Space; never create a parallel certificate.
    pub fn sign_recovery(
        &self,
        fresh: &VerifiedCredential,
        root: &SigningKey,
    ) -> Result<SignedRecord> {
        let initial = self.initial_controller();
        if self.is_forked()
            || initial.identity() != IdentityId::of_root_key(root.verifying_key().as_bytes())
            || fresh.identity() != initial.identity()
        {
            return Err(RecordError::Authority);
        }
        let chain = self.chain_at(self.head)?;
        let body = ControllerRecovery {
            v: 1,
            kind: "space.controller.recovered".into(),
            nonce: record::random_hex::<16>()?,
            space_id: self.space(),
            sequence: chain.len() as u64 + 1,
            previous_recovery_id: chain.last().map(SignedRecord::id),
            previous_controller_credential_id: self.controller().id(),
            controller_credential_id: fresh.id(),
        };
        SignedRecord::sign(
            &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
            root,
        )
    }
    /// Preserve the selected checkpoint's members and capabilities, replacing
    /// every device of the controlling owner. The new device signs the config.
    pub fn prepare_recovery(
        &self,
        certificate: &SignedRecord,
        key: &SigningKey,
    ) -> Result<SignedRecord> {
        let cert: ControllerRecovery = certificate.decode()?;
        let mut c = self.head()?.clone();
        c.nonce = record::random_hex::<16>()?;
        c.sequence += 1;
        c.previous_config_id = self.head;
        c.controller_credential_id = cert.controller_credential_id;
        c.recovery = Some(STANDARD.encode(certificate.bytes()));
        c.action = ConfigAction {
            operation: "controller.recovered".into(),
            actor_identity: self.initial_controller().identity(),
            request_record_id: Some(certificate.id()),
        };
        let owner = self.initial_controller().identity();
        for member in &mut c.members {
            if member.identity_id == owner {
                member.credential_ids = vec![cert.controller_credential_id];
            }
        }
        c.owner_credential_ids = self.owner_devices(&c.members);
        let r = c.sign(key)?;
        let mut trial = self.clone();
        if trial.apply_config(r.clone())? != ConfigAdmission::Applied {
            return Err(RecordError::Authority);
        }
        Ok(r)
    }
    fn owner_devices(&self, members: &[Member]) -> Vec<RecordId> {
        members
            .iter()
            .filter(|m| {
                self.body
                    .owners
                    .iter()
                    .any(|o| o.identity_id == m.identity_id)
            })
            .flat_map(|m| m.credential_ids.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    pub(super) fn validate_controller_transition(&self, c: &StreamConfig) -> Result<()> {
        let parent = c.previous_config_id.map(|id| self.config(id)).transpose()?;
        let prior_controller = parent
            .map(|p| p.controller_credential_id)
            .unwrap_or(self.body.controller_credential_id);
        let Some(r) = embedded(c)? else {
            if c.action.operation == "controller.recovered"
                || c.controller_credential_id != prior_controller
            {
                return Err(RecordError::Authority);
            }
            return Ok(());
        };
        let parent = parent.ok_or(RecordError::Authority)?;
        let b: ControllerRecovery = r.decode()?;
        let chain = self.chain_at(c.previous_config_id)?;
        let initial = self.initial_controller();
        let root = VerifyingKey::from_bytes(&record::hex(
            initial.record().body()["root_public_key"]
                .as_str()
                .ok_or(RecordError::Authority)?,
        )?)
        .map_err(|_| RecordError::Authority)?;
        r.verify_signature(&root)?;
        record::hex::<16>(&b.nonce)?;
        let fresh = self.credential(c.controller_credential_id)?;
        if b.v != 1
            || b.kind != "space.controller.recovered"
            || b.space_id != self.space()
            || b.sequence != chain.len() as u64 + 1
            || b.sequence > 64
            || b.previous_recovery_id != chain.last().map(SignedRecord::id)
            || b.previous_controller_credential_id != prior_controller
            || b.controller_credential_id != fresh.id()
            || fresh.id() == prior_controller
            || fresh.identity() != initial.identity()
            || fresh.record().body()["root_public_key"]
                != initial.record().body()["root_public_key"]
            || c.action.operation != "controller.recovered"
            || c.action.request_record_id != Some(r.id())
        {
            return Err(RecordError::Authority);
        }
        let mut expected = parent.members.clone();
        for m in &mut expected {
            if m.identity_id == initial.identity() {
                m.credential_ids = vec![fresh.id()];
            }
        }
        if c.members != expected || c.owner_credential_ids != self.owner_devices(&expected) {
            return Err(RecordError::Authority);
        }
        // A restored/reissued old key must not masquerade as a fresh controller.
        let mut ancestor = c.previous_config_id;
        while let Some(id) = ancestor {
            let config = self.config(id)?;
            for id in config.members.iter().flat_map(|m| &m.credential_ids) {
                let old = self.credential(*id)?;
                if old.key() == fresh.key() || old.recipient() == fresh.recipient() {
                    return Err(RecordError::Authority);
                }
            }
            ancestor = config.previous_config_id;
        }
        Ok(())
    }
    pub(super) fn select_controller_head(&mut self) -> Result<()> {
        let certificates = self.recovery_records()?;
        let mut children = BTreeMap::new();
        let mut current = self.body.controller_credential_id;
        for r in certificates {
            let b: ControllerRecovery = r.decode()?;
            if children.insert(b.previous_recovery_id, r.id()).is_some() {
                self.forked = true;
                return Ok(());
            }
            current = b.controller_credential_id;
        }
        // Old-generation branches remain verifiable historical evidence. They
        // cannot replace the explicitly adopted controller or freeze its head.
        let active = self
            .configs
            .iter()
            .filter(|(_, (_, c))| c.controller_credential_id == current)
            .collect::<Vec<_>>();
        let mut parents = BTreeSet::new();
        let mut recovery_count = 0;
        for (_, (_, c)) in &active {
            if c.recovery.is_some() {
                recovery_count += 1;
            }
            if !parents.insert(c.previous_config_id) || recovery_count > 1 {
                self.forked = true;
                return Ok(());
            }
        }
        self.forked = false;
        self.head = active
            .into_iter()
            .max_by_key(|(_, (_, c))| c.sequence)
            .map(|(id, _)| *id);
        Ok(())
    }
}

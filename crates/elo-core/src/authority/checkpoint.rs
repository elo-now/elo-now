//! Compact, controller-signed current authority. Historical records stay local.
//! A checkpoint is not proof of global freshness: consumers retain their floors.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    v: u8,
    kind: String,
    space_id: SpaceId,
    stream_id: StreamId,
    controller_credential_id: RecordId,
    config_id: RecordId,
    sequence: u64,
    /// Ordered from genesis to the checkpoint, including the selected head.
    ancestry: Vec<RecordId>,
    recovery: Vec<String>,
}

#[derive(Clone)]
pub(super) struct CheckpointEvidence {
    pub ancestry: Vec<RecordId>,
    pub recovery: Vec<SignedRecord>,
}

impl Authority {
    pub(super) fn current_checkpoint(&self) -> Option<&SignedRecord> {
        self.cached_checkpoint.as_ref().filter(|r| {
            !self.is_forked()
                && r.decode::<Checkpoint>()
                    .is_ok_and(|p| Some(p.config_id) == self.head_id())
        })
    }

    pub(crate) fn accept_cached_checkpoint(&mut self, record: SignedRecord) -> Result<()> {
        let body: Checkpoint = record.decode()?;
        let expected = self.head_id().ok_or(RecordError::Authority)?;
        if self.is_forked() || body.config_id != expected || body.sequence != self.head()?.sequence
        {
            return Err(RecordError::Authority);
        }
        record.verify_signature(self.controller().key())?;
        let actual = self.sign_checkpoint_body()?;
        // Compare every signed field, including ancestry and recovery evidence.
        if serde_json::to_value(body).map_err(|_| RecordError::Json)?
            != serde_json::to_value(actual).map_err(|_| RecordError::Json)?
        {
            return Err(RecordError::Authority);
        }
        self.cached_checkpoint = Some(record);
        Ok(())
    }

    /// Current-state consumers can check a retained rollback floor without
    /// pretending a checkpoint contains historical membership or message keys.
    pub fn proves_config_ancestor(&self, id: RecordId) -> bool {
        self.configs.contains_key(&id)
            || self
                .checkpoint_evidence
                .as_ref()
                .is_some_and(|p| p.ancestry.contains(&id))
    }

    /// A compact controller assertion cannot undo a root-authorized recovery.
    pub fn proves_recovery_ancestor(&self, floor: Option<RecordId>) -> bool {
        floor.is_none_or(|id| {
            self.controller_recovery_chain()
                .is_ok_and(|chain| chain.iter().any(|r| r.id() == id))
        })
    }

    pub fn proves_config_at(&self, id: RecordId, sequence: u64) -> bool {
        self.config(id).is_ok_and(|c| c.sequence == sequence)
            || self.checkpoint_evidence.as_ref().is_some_and(|p| {
                sequence
                    .checked_sub(1)
                    .and_then(|n| usize::try_from(n).ok())
                    .and_then(|n| p.ancestry.get(n))
                    == Some(&id)
            })
    }

    pub(crate) fn sign_checkpoint(&self, key: &SigningKey) -> Result<SignedRecord> {
        if self.is_forked()
            || self.checkpoint_evidence.is_some()
            || self.controller().key() != &key.verifying_key()
        {
            return Err(RecordError::Authority);
        }
        SignedRecord::sign(
            &serde_json::to_vec(&self.sign_checkpoint_body()?).map_err(|_| RecordError::Json)?,
            key,
        )
    }

    fn sign_checkpoint_body(&self) -> Result<Checkpoint> {
        let mut ancestry = Vec::new();
        let mut next = self.head_id();
        while let Some(id) = next {
            ancestry.push(id);
            next = self.config(id)?.previous_config_id;
        }
        ancestry.reverse();
        let c = self.head()?;
        let body = Checkpoint {
            v: 1,
            kind: "stream.checkpoint".into(),
            space_id: self.space(),
            stream_id: self.stream(),
            controller_credential_id: self.controller().id(),
            config_id: self.head_id().ok_or(RecordError::Authority)?,
            sequence: c.sequence,
            ancestry,
            recovery: self
                .controller_recovery_chain()?
                .iter()
                .map(|r| STANDARD.encode(r.bytes()))
                .collect(),
        };
        Ok(body)
    }

    pub(super) fn load_checkpoint(
        &mut self,
        signed: SignedRecord,
        config: SignedRecord,
    ) -> Result<()> {
        if self.head.is_some() || self.checkpoint_evidence.is_some() {
            return Err(RecordError::Authority);
        }
        let c: StreamConfig = config.decode()?;
        let body: Checkpoint = signed.decode()?;
        let controller = self.credential(body.controller_credential_id)?;
        signed.verify_signature(controller.key())?;
        config.verify_signature(controller.key())?;
        self.validate_config(&c)?;
        if body.v != 1
            || body.kind != "stream.checkpoint"
            || body.space_id != self.space()
            || body.stream_id != self.stream()
            || body.config_id != config.id()
            || body.sequence != c.sequence
            || body.controller_credential_id != c.controller_credential_id
            || body.ancestry.is_empty()
            || body.ancestry.len() > 4096
            || body.ancestry.len() as u64 != c.sequence
            || body.ancestry.last() != Some(&config.id())
            || body.ancestry.iter().collect::<BTreeSet<_>>().len() != body.ancestry.len()
            || c.previous_config_id != body.ancestry.iter().rev().nth(1).copied()
            || body.recovery.len() > 64
        {
            return Err(RecordError::Authority);
        }
        let chain = body
            .recovery
            .iter()
            .map(|encoded| {
                SignedRecord::parse(&STANDARD.decode(encoded).map_err(|_| RecordError::Json)?)
            })
            .collect::<Result<Vec<_>>>()?;
        self.verify_controller_export(&chain, controller)?;
        if let Some(encoded) = &c.recovery {
            let certificate =
                SignedRecord::parse(&STANDARD.decode(encoded).map_err(|_| RecordError::Json)?)?;
            if chain.last().map(SignedRecord::id) != Some(certificate.id())
                || c.action.operation != "controller.recovered"
                || c.action.request_record_id != Some(certificate.id())
            {
                return Err(RecordError::Authority);
            }
        } else if c.action.operation == "controller.recovered" {
            return Err(RecordError::Authority);
        }
        self.checkpoint_evidence = Some(CheckpointEvidence {
            ancestry: body.ancestry,
            recovery: chain,
        });
        self.head = Some(config.id());
        self.configs.insert(config.id(), (config, c));
        Ok(())
    }
}

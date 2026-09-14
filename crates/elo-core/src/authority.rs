//! Single-controller, pinned-genesis authority. No clock-based revocation claims.
use crate::{
    identity::VerifiedCredential,
    ids::{IdentityId, RecordId, SpaceId, StreamId},
    record::{self, ChatMessage, RecordError, Result, SignedRecord},
    sync::{ChatAuthority, VerifiedChat},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
mod recovery;
pub use recovery::ControllerRecovery;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub identity_id: IdentityId,
    pub root_public_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceGenesis {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub issuer_identity: IdentityId,
    pub owners: Vec<Owner>,
    pub controller_credential_id: RecordId,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Capability {
    Read,
    Post,
    ShareHistory,
    Manage,
    Replicate,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub identity_id: IdentityId,
    pub identity_type: String,
    pub root_public_key: String,
    pub capabilities: Vec<Capability>,
    pub credential_ids: Vec<RecordId>,
    pub external: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigAction {
    pub operation: String,
    pub actor_identity: IdentityId,
    pub request_record_id: Option<RecordId>,
}
/// Signed presentation category. It does not grant membership or capabilities.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatKind {
    Chat,
    Direct,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub sequence: u64,
    pub previous_config_id: Option<RecordId>,
    pub controller_credential_id: RecordId,
    pub members: Vec<Member>,
    pub owner_credential_ids: Vec<RecordId>,
    pub action: ConfigAction,
    /// Fixed once set; legacy streams may add it in a later controller-signed config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_kind: Option<ChatKind>,
    /// Root-signed Space controller transition, present only on the first config
    /// of a new controller generation. Old configs retain their exact bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
}
impl StreamConfig {
    pub fn sign(&self, key: &SigningKey) -> Result<SignedRecord> {
        SignedRecord::sign(
            &serde_json::to_vec(self).map_err(|_| RecordError::Json)?,
            key,
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigAdmission {
    Applied,
    Historical,
    AlreadyPresent,
    WaitingForProof,
    Forked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Accepted,
    WaitingForProof,
    QuarantinedStale,
    Forked,
}
#[derive(Clone)]
pub struct Authority {
    genesis: SignedRecord,
    body: SpaceGenesis,
    stream: StreamId,
    credentials: BTreeMap<RecordId, VerifiedCredential>,
    configs: BTreeMap<RecordId, (SignedRecord, StreamConfig)>,
    head: Option<RecordId>,
    forked: bool,
    persisted_snapshot: Option<crate::ids::ObjectId>,
}
impl Authority {
    pub fn new(
        genesis: &[u8],
        pinned_space: SpaceId,
        pinned_root: &VerifyingKey,
        controller: VerifiedCredential,
        stream: StreamId,
    ) -> Result<Self> {
        let genesis = SignedRecord::parse(genesis)?;
        if genesis.id().to_string() != pinned_space.to_string() {
            return Err(RecordError::Authority);
        }
        genesis.verify_signature(pinned_root)?;
        let body: SpaceGenesis = genesis.decode()?;
        record::hex::<16>(&body.nonce)?;
        if body.v != 1
            || body.kind != "space.genesis"
            || body.issuer_identity != IdentityId::of_root_key(pinned_root.as_bytes())
            || body.controller_credential_id != controller.id()
            || !record::sorted_unique(
                &body
                    .owners
                    .iter()
                    .map(|o| o.identity_id)
                    .collect::<Vec<_>>(),
                1,
                16,
            )
        {
            return Err(RecordError::Authority);
        }
        for owner in &body.owners {
            let key = VerifyingKey::from_bytes(&record::hex(&owner.root_public_key)?)
                .map_err(|_| RecordError::Signature)?;
            if key.is_weak() || IdentityId::of_root_key(key.as_bytes()) != owner.identity_id {
                return Err(RecordError::Authority);
            }
        }
        let owner = body
            .owners
            .iter()
            .find(|o| o.identity_id == controller.identity())
            .ok_or(RecordError::Authority)?;
        if controller.record().body()["root_public_key"] != owner.root_public_key
            || !body
                .owners
                .iter()
                .any(|o| o.identity_id == body.issuer_identity)
        {
            return Err(RecordError::Authority);
        }
        let mut credentials = BTreeMap::new();
        credentials.insert(controller.id(), controller);
        Ok(Self {
            genesis,
            body,
            stream,
            credentials,
            configs: BTreeMap::new(),
            head: None,
            forked: false,
            persisted_snapshot: None,
        })
    }
    pub fn genesis(&self) -> &SignedRecord {
        &self.genesis
    }
    pub fn space(&self) -> SpaceId {
        self.genesis
            .id()
            .to_string()
            .parse()
            .expect("same hex size")
    }
    pub fn stream(&self) -> StreamId {
        self.stream
    }
    pub fn head_id(&self) -> Option<RecordId> {
        self.head
    }
    pub fn head(&self) -> Result<&StreamConfig> {
        self.head
            .and_then(|id| self.configs.get(&id))
            .map(|(_, c)| c)
            .ok_or(RecordError::Authority)
    }
    pub fn is_forked(&self) -> bool {
        self.forked
    }
    pub fn credential(&self, id: RecordId) -> Result<&VerifiedCredential> {
        self.credentials.get(&id).ok_or(RecordError::Authority)
    }
    pub fn controller(&self) -> &VerifiedCredential {
        let id = self
            .head()
            .map(|c| c.controller_credential_id)
            .unwrap_or(self.body.controller_credential_id);
        &self.credentials[&id]
    }
    pub fn add_credential(&mut self, credential: VerifiedCredential) {
        self.credentials.insert(credential.id(), credential);
    }
    pub fn config_record(&self, id: RecordId) -> Result<&SignedRecord> {
        self.configs
            .get(&id)
            .map(|(r, _)| r)
            .ok_or(RecordError::Authority)
    }
    pub fn config(&self, id: RecordId) -> Result<&StreamConfig> {
        self.configs
            .get(&id)
            .map(|(_, c)| c)
            .ok_or(RecordError::Authority)
    }
    pub(crate) fn has_membership_approval(&self, proof: RecordId) -> bool {
        self.configs.values().any(|(_, c)| {
            c.action.operation == "invite.approved" && c.action.request_record_id == Some(proof)
        })
    }
    pub fn apply_config(&mut self, record: SignedRecord) -> Result<ConfigAdmission> {
        if self.configs.contains_key(&record.id()) {
            return Ok(ConfigAdmission::AlreadyPresent);
        }
        let config: StreamConfig = record.decode()?;
        record.verify_signature(self.credential(config.controller_credential_id)?.key())?;
        self.validate_config(&config)?;
        let prior_seq = match config.previous_config_id {
            None => 0,
            Some(id) => match self.configs.get(&id) {
                Some((_, c)) => {
                    if c.chat_kind.is_some() && config.chat_kind != c.chat_kind {
                        return Err(RecordError::Authority);
                    }
                    c.sequence
                }
                None => return Ok(ConfigAdmission::WaitingForProof),
            },
        };
        if config.sequence != prior_seq + 1 {
            return Err(RecordError::Authority);
        }
        self.validate_controller_transition(&config)?;
        if self.configs.len() >= 4096 {
            return Err(RecordError::Authority);
        }
        let id = record.id();
        self.configs.insert(id, (record, config));
        self.select_controller_head()?;
        if self.forked {
            return Ok(ConfigAdmission::Forked);
        }
        Ok(if self.head == Some(id) {
            ConfigAdmission::Applied
        } else {
            ConfigAdmission::Historical
        })
    }
    fn validate_config(&self, c: &StreamConfig) -> Result<()> {
        record::hex::<16>(&c.nonce)?;
        if c.v != 1
            || c.kind != "stream.config"
            || c.space_id != self.space()
            || c.stream_id != self.stream
            || c.sequence == 0
            || c.sequence > record::MAX_INTEGER
            || (c.sequence == 1) != c.previous_config_id.is_none()
            || c.action.actor_identity != self.credential(c.controller_credential_id)?.identity()
            || ![
                "create",
                "replace",
                "invite.approved",
                "member.removed",
                "device.removed",
                "controller.recovered",
            ]
            .contains(&c.action.operation.as_str())
        {
            return Err(RecordError::Authority);
        }
        if !record::sorted_unique(
            &c.members.iter().map(|m| m.identity_id).collect::<Vec<_>>(),
            1,
            record::MAX_CHAT_MEMBERS,
        ) {
            return Err(RecordError::Authority);
        }
        let mut all = BTreeSet::new();
        for member in &c.members {
            if !["HUMAN", "SERVICE", "DEVICE"].contains(&member.identity_type.as_str())
                || !record::sorted_unique(&member.credential_ids, 1, 32)
                || !record::sorted_unique(&member.capabilities, 1, 5)
                || (member.capabilities.contains(&Capability::ShareHistory)
                    && !member.capabilities.contains(&Capability::Read))
            {
                return Err(RecordError::Authority);
            }
            let root = record::hex::<32>(&member.root_public_key)?;
            if IdentityId::of_root_key(&root) != member.identity_id {
                return Err(RecordError::Authority);
            }
            for id in &member.credential_ids {
                let credential = self.credential(*id)?;
                if credential.identity() != member.identity_id
                    || credential.record().body()["root_public_key"] != member.root_public_key
                    || !all.insert(*id)
                {
                    return Err(RecordError::Authority);
                }
            }
        }
        if all.len() > record::MAX_CHAT_CREDENTIALS {
            return Err(RecordError::Authority);
        }
        let mut owners = BTreeSet::new();
        for owner in &self.body.owners {
            let member = c
                .members
                .iter()
                .find(|m| m.identity_id == owner.identity_id)
                .ok_or(RecordError::Authority)?;
            if member.root_public_key != owner.root_public_key
                || member.identity_type != "HUMAN"
                || ![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ]
                .iter()
                .all(|cap| member.capabilities.contains(cap))
            {
                return Err(RecordError::Authority);
            }
            owners.extend(member.credential_ids.iter().copied());
        }
        if c.owner_credential_ids != owners.into_iter().collect::<Vec<_>>()
            || !c.owner_credential_ids.contains(&c.controller_credential_id)
        {
            return Err(RecordError::Authority);
        }
        Ok(())
    }
    pub fn has(&self, config: RecordId, identity: IdentityId, cap: Capability) -> bool {
        self.config(config).ok().is_some_and(|c| {
            c.members
                .iter()
                .any(|m| m.identity_id == identity && m.capabilities.contains(&cap))
        })
    }
    pub fn expected_recipients(
        &self,
        config: RecordId,
        author: RecordId,
    ) -> Result<(Vec<IdentityId>, Vec<RecordId>)> {
        let c = self.config(config)?;
        let author = self.credential(author)?;
        if !c
            .members
            .iter()
            .any(|m| m.identity_id == author.identity() && m.credential_ids.contains(&author.id()))
        {
            return Err(RecordError::Authority);
        }
        let readers: Vec<_> = c
            .members
            .iter()
            .filter(|m| m.capabilities.contains(&Capability::Read))
            .map(|m| m.identity_id)
            .collect();
        let mut recipients = BTreeSet::new();
        for member in &c.members {
            if readers.contains(&member.identity_id) {
                recipients.extend(member.credential_ids.iter().copied());
            }
        }
        recipients.insert(author.id());
        Ok((readers, recipients.into_iter().collect()))
    }
    pub fn verify_historical(&self, r: &SignedRecord) -> Result<ChatMessage> {
        let chat = r.chat()?;
        if chat.space_id != self.space() || chat.stream_id != self.stream {
            return Err(RecordError::Authority);
        }
        self.credential(chat.issuer_credential)?.verify_chat(r)?;
        let (audience, recipients) =
            self.expected_recipients(chat.config_id, chat.issuer_credential)?;
        if !self.has(chat.config_id, chat.issuer_identity, Capability::Post)
            || chat.audience != audience
            || chat.recipient_credentials != recipients
        {
            return Err(RecordError::Authority);
        }
        Ok(chat)
    }
    pub fn admission(
        &self,
        r: &SignedRecord,
        recipient: RecordId,
        already_accepted: bool,
    ) -> Result<Admission> {
        let chat = r.chat()?;
        if chat.space_id != self.space() || chat.stream_id != self.stream {
            return Err(RecordError::Authority);
        }
        if !self.configs.contains_key(&chat.config_id) {
            return Ok(Admission::WaitingForProof);
        }
        self.verify_historical(r)?;
        if !chat.recipient_credentials.contains(&recipient) {
            return Err(RecordError::Authority);
        }
        if already_accepted {
            return Ok(Admission::Accepted);
        }
        if self.forked {
            return Ok(Admission::Forked);
        }
        if Some(chat.config_id) != self.head {
            return Ok(Admission::QuarantinedStale);
        }
        Ok(Admission::Accepted)
    }
    pub fn prepare_chat(&self, mut chat: ChatMessage, key: &SigningKey) -> Result<SignedRecord> {
        if self.forked {
            return Err(RecordError::Authority);
        }
        let id = self.head.ok_or(RecordError::Authority)?;
        let own = self.credential(chat.issuer_credential)?;
        if own.key() != &key.verifying_key() {
            return Err(RecordError::Authority);
        }
        let (audience, recipients) = self.expected_recipients(id, own.id())?;
        chat.space_id = self.space();
        chat.stream_id = self.stream;
        chat.config_id = id;
        chat.issuer_identity = own.identity();
        chat.audience = audience;
        chat.recipient_credentials = recipients;
        let r = chat.sign(key)?;
        self.verify(&r, own.id())?;
        Ok(r)
    }
}
impl ChatAuthority for Authority {
    fn verify_outgoing(&self, r: &SignedRecord, own: RecordId) -> Result<()> {
        match r.body()["kind"].as_str() {
            Some("file.body" | "file.shared") => crate::files::verify_outgoing(self, r, own),
            Some("history.access.granted") => crate::history::verify_outgoing(self, r, own),
            _ => self.verify(r, own).map(|_| ()),
        }
    }

    fn admit(
        &self,
        r: &SignedRecord,
        recipient: RecordId,
        known: bool,
    ) -> Result<crate::sync::ChatDecision> {
        use crate::sync::ChatDecision;
        if r.body()["kind"] == "file.shared" {
            let share = crate::files::VerifiedFileShare::verify(r, self, recipient, true)?;
            if known {
                return Ok(ChatDecision::FileShared(Box::new(share)));
            }
            if self.forked {
                return Ok(ChatDecision::Forked);
            }
            if Some(share.body().config_id) != self.head {
                return Ok(ChatDecision::QuarantinedStale);
            }
            return Ok(ChatDecision::FileShared(Box::new(share)));
        }
        if r.body()["kind"] == "history.access.granted" {
            return Ok(ChatDecision::WaitingForProof);
        }

        Ok(match self.admission(r, recipient, known)? {
            Admission::Accepted => {
                ChatDecision::Accepted(Box::new(VerifiedChat::new(r.clone(), r.chat()?)))
            }
            Admission::WaitingForProof => ChatDecision::WaitingForProof,
            Admission::QuarantinedStale => ChatDecision::QuarantinedStale,
            Admission::Forked => ChatDecision::Forked,
        })
    }

    fn verify(&self, r: &SignedRecord, recipient: RecordId) -> Result<VerifiedChat> {
        if self.admission(r, recipient, false)? != Admission::Accepted {
            return Err(RecordError::Authority);
        }
        Ok(VerifiedChat::new(r.clone(), r.chat()?))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityProofs {
    v: u64,
    genesis: String,
    credentials: Vec<String>,
    configs: Vec<String>,
}
impl Authority {
    pub fn seal_snapshot(&self, recipient: &age::x25519::Recipient) -> Result<Vec<u8>> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let mut configs = self.configs.values().collect::<Vec<_>>();
        configs.sort_by_key(|(r, c)| (c.sequence, r.id()));
        let proofs = AuthorityProofs {
            v: 1,
            genesis: STANDARD.encode(self.genesis.bytes()),
            credentials: self
                .credentials
                .values()
                .map(|c| STANDARD.encode(c.record().bytes()))
                .collect(),
            configs: configs
                .iter()
                .map(|(record, _)| STANDARD.encode(record.bytes()))
                .collect(),
        };
        let bytes = serde_json::to_vec(&proofs).map_err(|_| RecordError::Json)?;
        crate::crypto::seal_bytes(&bytes, std::slice::from_ref(recipient), 8 * 1024 * 1024)
            .map_err(|_| RecordError::Authority)
    }
    pub fn open_snapshot(
        bytes: &[u8],
        identity: &age::x25519::Identity,
        pinned_space: SpaceId,
        pinned_root: &VerifyingKey,
        stream: StreamId,
    ) -> Result<Self> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let snapshot_id = crate::ids::ObjectId::of_ciphertext(bytes);
        let bytes = crate::crypto::open_bytes(bytes, identity, 8 * 1024 * 1024)
            .map_err(|_| RecordError::Authority)?;
        let v = record::strict_json(&bytes, 8 * 1024 * 1024 + 72)?;
        let p: AuthorityProofs = serde_json::from_value(v).map_err(|_| RecordError::Json)?;
        if p.v != 1 || p.credentials.len() > 8192 || p.configs.len() > 4096 {
            return Err(RecordError::Authority);
        }
        let decode = |s: &str| STANDARD.decode(s).map_err(|_| RecordError::Json);
        let genesis = decode(&p.genesis)?;
        let g = SignedRecord::parse(&genesis)?;
        let body: SpaceGenesis = g.decode()?;
        let mut credentials = Vec::new();
        for encoded in &p.credentials {
            let bytes = decode(encoded)?;
            let r = SignedRecord::parse(&bytes)?;
            let key = VerifyingKey::from_bytes(&record::hex(
                r.body()["root_public_key"]
                    .as_str()
                    .ok_or(RecordError::Json)?,
            )?)
            .map_err(|_| RecordError::Signature)?;
            credentials.push(VerifiedCredential::verify(&bytes, &key)?);
        }
        let controller = credentials
            .iter()
            .find(|c| c.id() == body.controller_credential_id)
            .ok_or(RecordError::Authority)?
            .clone();
        let mut authority = Self::new(&genesis, pinned_space, pinned_root, controller, stream)?;
        for credential in credentials {
            authority.add_credential(credential);
        }
        for encoded in &p.configs {
            let bytes = decode(encoded)?;
            if authority.apply_config(SignedRecord::parse(&bytes)?)?
                == ConfigAdmission::WaitingForProof
            {
                return Err(RecordError::Authority);
            }
        }
        authority.persisted_snapshot = Some(snapshot_id);
        Ok(authority)
    }
    pub async fn commit_update(
        &mut self,
        store: &crate::store::ClientStore,
        record: SignedRecord,
        own_identity: &age::x25519::Identity,
        now: crate::store::LocalTime,
    ) -> std::result::Result<ConfigAdmission, crate::store::StoreError> {
        self.commit_update_inner(store, record, own_identity, now, None)
            .await
    }
    pub(crate) async fn commit_invited_update(
        &mut self,
        store: &crate::store::ClientStore,
        record: SignedRecord,
        own_identity: &age::x25519::Identity,
        now: crate::store::LocalTime,
        invite: (RecordId, RecordId),
    ) -> std::result::Result<ConfigAdmission, crate::store::StoreError> {
        self.commit_update_inner(store, record, own_identity, now, Some(invite))
            .await
    }
    async fn commit_update_inner(
        &mut self,
        store: &crate::store::ClientStore,
        record: SignedRecord,
        own_identity: &age::x25519::Identity,
        now: crate::store::LocalTime,
        invite: Option<(RecordId, RecordId)>,
    ) -> std::result::Result<ConfigAdmission, crate::store::StoreError> {
        let mut next = self.clone();
        let outcome = next
            .apply_config(record.clone())
            .map_err(|_| crate::store::StoreError::InvalidInput("invalid configuration"))?;
        if outcome == ConfigAdmission::WaitingForProof || outcome == ConfigAdmission::AlreadyPresent
        {
            return Ok(outcome);
        }
        let config = next
            .config(record.id())
            .map_err(|_| crate::store::StoreError::InvalidInput("configuration unavailable"))?;
        let recipients = config
            .members
            .iter()
            .flat_map(|m| m.credential_ids.iter())
            .map(|id| next.credential(*id).map(|c| c.recipient()))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| crate::store::StoreError::InvalidInput("recipient proof unavailable"))?;
        let ciphertext = crate::crypto::seal_record(&record, &recipients).map_err(|_| {
            crate::store::StoreError::InvalidInput("configuration encryption failed")
        })?;
        let snapshot = next
            .seal_snapshot(&own_identity.to_public())
            .map_err(|_| crate::store::StoreError::InvalidInput("snapshot encryption failed"))?;
        let snapshot_id = crate::ids::ObjectId::of_ciphertext(&snapshot);
        let input = crate::store::PreparedLocalRecord::new(
            record.id(),
            ciphertext,
            crate::store::RecordMetadata::new(
                "stream.config",
                Some(self.space()),
                Some(self.stream),
                Some(record.id()),
            )?,
            vec![],
            now,
        )?;
        store
            .commit_configuration(
                input,
                crate::store::ConfigurationState {
                    expected_head: self.head,
                    expected_snapshot: self.persisted_snapshot,
                    head: next
                        .head
                        .ok_or(crate::store::StoreError::InvalidInput("head unavailable"))?,
                    sequence: next
                        .head()
                        .map_err(|_| crate::store::StoreError::InvalidInput("head unavailable"))?
                        .sequence,
                    forked: next.forked,
                    snapshot,
                },
                invite,
            )
            .await?;
        next.persisted_snapshot = Some(snapshot_id);
        *self = next;
        Ok(outcome)
    }
}

impl Authority {
    /// Merge already verified proofs without replacing a known head with an older snapshot.
    pub async fn merge_into_store(
        &self,
        existing: Option<&Self>,
        store: &crate::store::ClientStore,
        own: &age::x25519::Identity,
        now: crate::store::LocalTime,
    ) -> std::result::Result<Self, crate::store::StoreError> {
        if existing.is_some_and(|old| {
            old.genesis.bytes() != self.genesis.bytes() || old.stream != self.stream
        }) {
            return Err(crate::store::StoreError::InvalidInput(
                "pinned genesis mismatch",
            ));
        }
        let mut target = existing.cloned().unwrap_or_else(|| {
            let mut a = self.clone();
            a.configs.clear();
            a.head = None;
            a.forked = false;
            a.persisted_snapshot = None;
            a
        });
        for c in self.credentials.values() {
            target.add_credential(c.clone());
        }
        let mut configs = self.configs.values().collect::<Vec<_>>();
        configs.sort_by_key(|(r, c)| (c.sequence, r.id()));
        for (r, _) in configs {
            target.commit_update(store, r.clone(), own, now).await?;
        }
        Ok(target)
    }
}

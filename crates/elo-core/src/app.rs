//! Headless application service shared by native UI and integration tests.
//! Decrypted content is an in-memory projection, never a plaintext SQLite index.
use crate::{
    authority::{
        Authority, Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig,
    },
    crypto, history,
    identity::VerifiedCredential,
    ids::{IdentityId, RecordId, SpaceId, StreamId},
    invite,
    record::{self, ChatMessage, SignedRecord, TextPayload},
    store::{ClientStore, DeliveryTarget, LocalTime, PreparedLocalRecord, RecordMetadata},
    sync::{ChatAuthority, ChatDecision, Peer, PeerDescriptor, SyncClient, VerifiedChat},
    vault::{self, RecoveryCard, Session},
};
use age::secrecy::{ExposeSecret, SecretString};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const MAX_EXCHANGE: usize = 12 * 1024 * 1024;
// Bound local metadata by serialized size rather than the number of chats.
// Leave room for age framing below the shared ciphertext bound.
const MAX_READ_STATE: usize = 14 * 1024 * 1024;
mod chats;
mod groups;
mod history_reader;
mod invitations;
mod message_actions;
mod message_audit;
pub mod pairing;
#[cfg(test)]
mod performance;
mod presentation;
pub use history_reader::HistorySnapshot;
use history_reader::Shared;
mod profile;
pub use invitations::{push, team};
pub mod profile_backup;
mod recovery;
pub mod recovery_qr;
pub mod space_service;
pub mod spaces;
use groups::ChatGroup;
pub use profile::ProfileDraft;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    name: String,
    space: SpaceId,
    stream: StreamId,
    root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chat_kind: Option<ChatKind>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    created_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workspace {
    v: u8,
    pins: Vec<Pin>,
    #[serde(default)]
    groups: Vec<ChatGroup>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadState {
    v: u8,
    seen: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    unread: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    reminders: Vec<message_actions::Reminder>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    muted_streams: BTreeSet<StreamId>,
}
impl ReadState {
    fn validate(&self) -> Result<()> {
        if self.v != 1 || self.reminders.len() > 100 {
            return Err("invalid read state".into());
        }
        if self.reminders.iter().any(|r| r.due_at <= 0)
            || self.reminders.iter().enumerate().any(|(i, r)| {
                self.reminders[..i]
                    .iter()
                    .any(|old| old.stream == r.stream && old.record == r.record)
            })
        {
            return Err("invalid read state".into());
        }
        for (stream, records) in self.seen.iter().chain(&self.unread) {
            stream.parse::<StreamId>()?;
            if !records.windows(2).all(|pair| pair[0] < pair[1])
                || records
                    .iter()
                    .any(|record| record.parse::<RecordId>().is_err())
            {
                return Err("invalid read state".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Authorities(Shared<Vec<Authority>>);
impl Authorities {
    fn space_ready(&self, a: &Authority) -> bool {
        a.controller_ready_with(&self.0)
    }
    fn for_record(&self, r: &SignedRecord) -> record::Result<&Authority> {
        let space: SpaceId = serde_json::from_value(r.body()["space_id"].clone())
            .map_err(|_| record::RecordError::Authority)?;
        let stream: StreamId = serde_json::from_value(r.body()["stream_id"].clone())
            .map_err(|_| record::RecordError::Authority)?;
        let a = self
            .0
            .iter()
            .find(|a| a.space() == space && a.stream() == stream)
            .ok_or(record::RecordError::Authority)?;
        if !self.space_ready(a) {
            return Err(record::RecordError::Authority);
        }
        Ok(a)
    }
}
impl ChatAuthority for Authorities {
    fn verify(&self, r: &SignedRecord, c: RecordId) -> record::Result<VerifiedChat> {
        self.for_record(r)?.verify(r, c)
    }
    fn admit(&self, r: &SignedRecord, c: RecordId, known: bool) -> record::Result<ChatDecision> {
        match self.for_record(r) {
            Ok(a) => a.admit(r, c, known),
            Err(_) => Ok(ChatDecision::WaitingForProof),
        }
    }
    fn verify_outgoing(&self, r: &SignedRecord, c: RecordId) -> record::Result<()> {
        self.for_record(r)?.verify_outgoing(r, c)
    }
}
pub struct ClientApp {
    directory: PathBuf,
    session: Session,
    password: SecretString,
    store: ClientStore,
    pins: Vec<Pin>,
    groups: Vec<ChatGroup>,
    profile_details: Option<profile::ProfileDetails>,
    read: Shared<ReadState>,
    authorities: Authorities,
    peers: Vec<Peer>,
    allow_loopback: bool,
    sync_round: usize,
    push_endpoint: Option<String>,
    push_allow_loopback: bool,
    team: Option<team::TeamDescriptor>,
    team_next: u64,
    spaces: Option<Box<spaces::Spaces>>,
    presentation: std::sync::Arc<presentation::Presentation>,
}
fn now() -> Result<LocalTime> {
    Ok(LocalTime::from_millis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
    )?)
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(|| "missing text field".into())
}
fn root_key(s: &str) -> Result<VerifyingKey> {
    Ok(VerifyingKey::from_bytes(&record::hex(s)?)?)
}
fn decode_record(s: &str) -> Result<SignedRecord> {
    Ok(SignedRecord::parse(&STANDARD.decode(s)?)?)
}
fn read_exchange(path: &Path, max: usize) -> Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > max as u64 {
        return Err("exchange file is unsafe or too large".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err("exchange file too large".into());
    }
    Ok(bytes)
}
fn write_export(path: &Path, bytes: &[u8]) -> Result<()> {
    // A user-selected export is written directly, without a plaintext temporary file.
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
impl ClientApp {
    /// Checks the unlock password without exposing the retained secret.
    pub fn password_matches(&self, candidate: &SecretString) -> bool {
        bool::from(
            self.password
                .expose_secret()
                .as_bytes()
                .ct_eq(candidate.expose_secret().as_bytes()),
        )
    }

    pub async fn open(
        directory: PathBuf,
        password: SecretString,
        allow_loopback: bool,
    ) -> Result<Self> {
        if directory.join(".initializing").exists() {
            return Err("Profile initialization was interrupted; keep this directory for diagnosis and choose a new profile directory".into());
        }
        Self::open_initialized(directory, password, allow_loopback).await
    }
    async fn open_initialized(
        directory: PathBuf,
        password: SecretString,
        allow_loopback: bool,
    ) -> Result<Self> {
        let public: Value =
            serde_json::from_slice(&vault::read_private(&directory.join("profile.json"))?)?;
        let expected: IdentityId = serde_json::from_value(public["identity_id"].clone())?;
        let session = Session::open(
            &vault::read_private(&directory.join("vault.age"))?,
            password.clone(),
            expected,
        )?;
        let peers = session
            .peers()
            .iter()
            .cloned()
            .map(|p| Peer::new(p, allow_loopback))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let workspace = if directory.join("workspace.age").exists() {
            let bytes = read_exchange(&directory.join("workspace.age"), MAX_EXCHANGE)?;
            let plain = Zeroizing::new(crypto::open_bytes(
                &bytes,
                session.age_identity(),
                1024 * 1024,
            )?);
            let ws: Workspace = serde_json::from_slice(&plain)?;
            ws.validate()?;
            ws
        } else {
            Workspace {
                v: 3,
                pins: vec![],
                groups: vec![],
            }
        };
        let mut migrate_workspace = workspace.v < 3;
        let mut pins = workspace.pins;
        let read = if directory.join("read-state.age").exists() {
            let bytes = read_exchange(&directory.join("read-state.age"), crypto::MAX_CIPHERTEXT)?;
            let plain = Zeroizing::new(crypto::open_bytes(
                &bytes,
                session.age_identity(),
                MAX_READ_STATE,
            )?);
            let value: ReadState = serde_json::from_slice(&plain)?;
            value.validate()?;
            value
        } else {
            ReadState {
                v: 1,
                ..ReadState::default()
            }
        };
        let profile_details = profile::ProfileDetails::load(&directory, &session)?;
        let store = ClientStore::open(&directory).await?;
        let loaded: Result<Vec<_>> = async {
            let mut all = Vec::new();
            for p in &mut pins {
                let bytes = store
                    .authority_snapshot(p.space, p.stream)
                    .await?
                    .ok_or("authority snapshot unavailable")?;
                let authority = Authority::open_snapshot(
                    &bytes,
                    session.age_identity(),
                    p.space,
                    &root_key(&p.root)?,
                    p.stream,
                )?;
                let kind = authority
                    .head()?
                    .chat_kind
                    .or(p.chat_kind)
                    .unwrap_or(chats::imported_kind(&authority, session.identity_id())?);
                if p.chat_kind != Some(kind) {
                    p.chat_kind = Some(kind);
                    migrate_workspace = true;
                }
                all.push(authority);
            }
            Ok(all)
        }
        .await;
        match loaded {
            Ok(all) => {
                let app = Self {
                    directory,
                    session,
                    password,
                    store,
                    pins,
                    groups: workspace.groups,
                    profile_details,
                    read: read.into(),
                    authorities: Authorities(all.into()),
                    peers,
                    allow_loopback,
                    sync_round: 0,
                    push_endpoint: None,
                    push_allow_loopback: false,
                    team: None,
                    team_next: 0,
                    spaces: None,
                    presentation: Default::default(),
                };
                if migrate_workspace && let Err(error) = app.persist_workspace() {
                    app.store.close().await?;
                    return Err(error);
                }
                Ok(app)
            }
            Err(e) => {
                store.close().await?;
                Err(e)
            }
        }
    }
    pub async fn close(mut self) -> Result<()> {
        if let Some(spaces) = self.spaces.take() {
            spaces.close().await?;
        }
        self.store.close().await?;
        Ok(())
    }
    fn authority_index(&self, v: &Value) -> Result<usize> {
        let stream: StreamId = field(v, "stream")?.parse()?;
        let space: SpaceId = field(v, "space")?.parse()?;
        self.authorities
            .0
            .iter()
            .position(|a| a.stream() == stream && a.space() == space)
            .ok_or_else(|| "unknown pinned stream".into())
    }
    fn targets(&self) -> Vec<DeliveryTarget> {
        self.session
            .peers()
            .iter()
            .zip(&self.peers)
            .filter(|(d, _)| d.write_token.is_some())
            .map(|(_, p)| DeliveryTarget {
                peer_id: p.id(),
                mailbox_id: p.mailbox(),
            })
            .collect()
    }
    /// Add a private transport configuration without replacing existing mailboxes.
    /// Reopening a preconfigured test build must not rotate credentials or keys.
    pub fn ensure_peer(&mut self, descriptor: PeerDescriptor) -> Result<bool> {
        let peer = Peer::new(descriptor.clone(), self.allow_loopback)?;
        if self
            .peers
            .iter()
            .any(|old| old.id() == peer.id() && old.mailbox() == peer.mailbox())
        {
            return Ok(false);
        }
        let previous = self.session.peers().to_vec();
        let mut descriptors = previous.clone();
        descriptors.push(descriptor);
        self.session.set_peers(descriptors)?;
        if let Err(error) = self.persist_vault() {
            self.session.set_peers(previous)?;
            return Err(error);
        }
        self.peers.push(peer);
        Ok(true)
    }
    fn persist_workspace(&self) -> Result<()> {
        self.write_workspace(&Workspace {
            v: 3,
            pins: self.pins.clone(),
            groups: self.groups.clone(),
        })
    }
    fn write_workspace(&self, workspace: &Workspace) -> Result<()> {
        workspace.validate()?;
        let plain = Zeroizing::new(serde_json::to_vec(workspace)?);
        let bytes = crypto::seal_bytes(
            &plain,
            &[self.session.age_identity().to_public()],
            1024 * 1024,
        )?;
        vault::write_private(&self.directory.join("workspace.age"), &bytes, true)?;
        Ok(())
    }
    fn persist_vault(&self) -> Result<()> {
        vault::write_private(
            &self.directory.join("vault.age"),
            &self.session.seal(self.password.clone())?,
            true,
        )?;
        Ok(())
    }
    fn write_read_state(&self, state: &ReadState) -> Result<()> {
        state.validate()?;
        let plain = Zeroizing::new(serde_json::to_vec(state)?);
        let bytes = crypto::seal_bytes(
            &plain,
            &[self.session.age_identity().to_public()],
            MAX_READ_STATE,
        )?;
        vault::write_private(&self.directory.join("read-state.age"), &bytes, true)?;
        Ok(())
    }
    async fn originals(&self, a: &Authority) -> Result<Vec<(SignedRecord, String)>> {
        self.history_view().originals(a).await
    }
    async fn originals_from(
        &self,
        a: &Authority,
        sources: Vec<crate::store::DisplaySource>,
    ) -> Result<Vec<(SignedRecord, String)>> {
        self.history_view().originals_from(a, sources).await
    }
    async fn open_sources(
        &self,
        a: &Authority,
        sources: Vec<crate::store::DisplaySource>,
    ) -> Result<Vec<(SignedRecord, String)>> {
        self.history_view().open_sources(a, sources).await
    }
    pub async fn view(&self) -> Result<Value> {
        if self.presentation.deferred() {
            return Ok(Value::Null);
        }
        if let Some(spaces) = &self.spaces {
            return spaces.view(self).await;
        }
        self.view_local().await
    }
    async fn view_local(&self) -> Result<Value> {
        self.view_local_scope(None).await
    }
    async fn view_local_scope(&self, only: Option<StreamId>) -> Result<Value> {
        let mut streams = Vec::new();
        let direct = self.direct_summaries()?;
        for (p, a) in self.pins.iter().zip(&self.authorities.0) {
            if only.is_some_and(|id| id != p.stream) {
                continue;
            }
            let seen = self.read.seen.get(&p.stream.to_string());
            let mut member_names = if self.presentation.enabled() {
                self.presentation.member_names(a)
            } else {
                BTreeMap::new()
            };
            let originals = if self.presentation.enabled() {
                self.originals_from(
                    a,
                    self.store
                        .summary_sources(
                            a.space(),
                            a.stream(),
                            seen.cloned().unwrap_or_default(),
                            self.read
                                .unread
                                .get(&p.stream.to_string())
                                .cloned()
                                .unwrap_or_default(),
                        )
                        .await?,
                )
                .await?
            } else {
                self.originals(a).await?
            };
            if self.team.is_some()
                && self
                    .pins
                    .first()
                    .is_some_and(|first| first.stream == p.stream)
                && p.name == "General"
                && originals.is_empty()
                && a.head()?.sequence == 1
                && a.head()?.members.len() == 1
                && a.controller().identity() == self.session.identity_id()
            {
                continue;
            }
            let actions = message_actions::Projection::new(&originals);
            let rows = originals.into_iter()
                .filter(|(r,_)| r.body()["kind"] != "chat.action")
                .map(|(r, state)| {
                    // originals() verifies signatures and authority before this projection.
                    // Keep names scoped to this chat; transport metadata cannot name a sender.
                    if let Some(name) = r.body()["payload"]["sender_name"].as_str()
                        && let Some(identity) = r.body()["issuer_identity"].as_str()
                    {
                        member_names.insert(identity.into(), name.into());
                    }
                    let id = r.id().to_string();
                    let unread = self.read.unread.get(&p.stream.to_string()).is_some_and(|ids|ids.contains(&id)) || (r.body()["issuer_identity"] != json!(self.session.identity_id())
                        && !seen.is_some_and(|values| values.binary_search(&id).is_ok()));
                    json!({"id":id,"state":state,"body":r.body(),"unread":unread,"marked_unread":self.read.unread.get(&p.stream.to_string()).is_some_and(|ids|ids.contains(&id)),"reactions":actions.reactions(r.id(),self.session.identity_id()),"pinned":actions.is_pinned(r.id())})
                })
                .collect::<Vec<_>>();
            let unread_count = rows.iter().filter(|row| row["unread"] == true).count();
            let is_general = self.team.as_ref().is_some_and(|team| {
                team.scope.space == p.space
                    && team.scope.stream == p.stream
                    && team.scope.root == p.root
            });
            streams.push(json!({"name":p.name.clone(),"is_general":is_general,"chat_kind":a.head()?.chat_kind.or(p.chat_kind),"direct_invitation":direct.get(&p.stream),"group":p.group,"created_at":p.created_at,"space":p.space,"stream":p.stream,"head":a.head_id(),"controller":a.controller().id(),"recovery":a.recovery_id(),"forked":!self.authorities.space_ready(a),"members":a.head()?.members,"member_names":member_names,"owners":a.genesis().body()["owners"],"rows":rows,"unread_count":unread_count,"muted":self.read.muted_streams.contains(&p.stream),"can_manage_members":self.require_controller(a).is_ok(),"can_post":self.authorities.space_ready(a) && a.has(a.head_id().ok_or("head")?,self.session.identity_id(),Capability::Post) && a.head()?.members.iter().any(|m|m.credential_ids.contains(&self.session.credential().id()))}));
        }
        // A one-to-one title belongs to the other participant. Derive it from
        // verified names without rewriting historical signed chat records.
        let mut names = self
            .contact_summary()?
            .into_iter()
            .filter_map(|p| Some((p["id"].as_str()?.to_owned(), p["name"].as_str()?.to_owned())))
            .collect::<BTreeMap<_, _>>();
        for stream in &streams {
            if let Some(members) = stream["member_names"].as_object() {
                for (id, name) in members {
                    if let Some(name) = name.as_str() {
                        names.insert(id.clone(), name.into());
                    }
                }
            }
        }
        for stream in &mut streams {
            if let Some(team) = &self.team {
                if stream["stream"] == json!(team.scope.stream) {
                    if let Some(authority) = self
                        .authorities
                        .0
                        .iter()
                        .find(|a| a.stream() == team.scope.stream)
                    {
                        stream["member_names"][authority.controller().identity().to_string()] =
                            json!("elo.now");
                    }
                } else if stream["name"] == "General" {
                    let owner = self
                        .authorities
                        .0
                        .iter()
                        .find(|a| json!(a.stream()) == stream["stream"])
                        .map(|a| a.controller().identity().to_string());
                    let owner_name = owner.as_ref().and_then(|id| {
                        if id == &self.session.identity_id().to_string() {
                            self.profile_details.as_ref().map(|p| &p.name)
                        } else {
                            names.get(id)
                        }
                    });
                    stream["name"] = json!(
                        owner_name
                            .map(|name| format!("General · {name}"))
                            .unwrap_or_else(|| "General (earlier)".into())
                    );
                }
            }
            if stream["chat_kind"] == "direct"
                && stream["members"].as_array().is_some_and(|m| m.len() == 2)
            {
                let person = stream["members"]
                    .as_array()
                    .and_then(|ms| {
                        ms.iter()
                            .find(|m| m["identity_id"] != json!(self.session.identity_id()))
                    })
                    .and_then(|m| m["identity_id"].as_str());
                if let Some(name) = person.and_then(|id| names.get(id)) {
                    stream["name"] = json!(name);
                }
            }
        }
        let s = self.store.stats().await?;
        Ok(
            json!({"paged":self.presentation.enabled(),"contacts":self.contact_summary()?,"reminders":self.read.reminders,"identity":self.session.identity_id(),"name":self.profile_details.as_ref().map(|p| &p.name),"avatar":self.profile_details.as_ref().and_then(|p| p.avatar.as_ref()),"credential":self.session.credential().id(),"invitations":self.invitation_summary()?,"groups":self.groups,"streams":streams,"replicas":self.peers.iter().map(|p|json!({"id":p.id(),"mailbox":p.mailbox()})).collect::<Vec<_>>(),"counts":{"pending":s.pending,"stored":s.stored,"held":s.held,"rejected":s.rejected,"repair_pending":self.store.missing_copies().await?},"inbox":self.store.inbox_states().await?,"history_warning_code":"history_may_be_incomplete","history_warning":"History may be incomplete; the local head does not prove that other participants are up to date.","alpha_ready":false}),
        )
    }
    async fn create_space(&mut self, name: &str, card: &RecoveryCard) -> Result<()> {
        if name.is_empty() || name.len() > 120 {
            return Err("invalid channel name".into());
        }
        let root = card.recover_root(self.session.identity_id())?;
        let c = self.session.credential();
        let g = SpaceGenesis {
            v: 1,
            kind: "space.genesis".into(),
            nonce: record::random_hex::<16>()?,
            issuer_identity: c.identity(),
            owners: vec![Owner {
                identity_id: c.identity(),
                root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            }],
            controller_credential_id: c.id(),
        };
        let genesis = SignedRecord::sign(&serde_json::to_vec(&g)?, &root)?;
        let space = genesis.id().to_string().parse()?;
        let stream = record::random_hex::<16>()?.parse()?;
        let mut a = Authority::new(
            genesis.bytes(),
            space,
            &root.verifying_key(),
            c.clone(),
            stream,
        )?;
        let config = StreamConfig {
            chat_kind: Some(ChatKind::Chat),
            recovery: None,
            v: 1,
            kind: "stream.config".into(),
            nonce: record::random_hex::<16>()?,
            space_id: space,
            stream_id: stream,
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: c.id(),
            members: vec![Member {
                identity_id: c.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: g.owners[0].root_public_key.clone(),
                capabilities: vec![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ],
                credential_ids: vec![c.id()],
                external: false,
            }],
            owner_credential_ids: vec![c.id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: c.identity(),
                request_record_id: None,
            },
        };
        a.commit_update(
            &self.store,
            config.sign(self.session.signing_key())?,
            self.session.age_identity(),
            now()?,
        )
        .await?;
        self.session.activate_new_space_controller(space)?;
        self.persist_vault()?;
        self.pins.push(Pin {
            chat_kind: Some(ChatKind::Chat),
            name: name.into(),
            space,
            stream,
            root: g.owners[0].root_public_key.clone(),
            group: None,
            created_at: now()?.as_millis(),
        });
        self.authorities.0.push(a);
        self.persist_workspace()?;
        Ok(())
    }
    pub async fn operate(&mut self, v: Value) -> Result<Value> {
        if let Some(mut spaces) = self.spaces.take() {
            let result = spaces.operate(self, v).await;
            self.spaces = Some(spaces);
            return result;
        }
        self.operate_local(v).await
    }
    async fn operate_local(&mut self, v: Value) -> Result<Value> {
        if let Some(expected) = v.get("expected_identity")
            && expected != &json!(self.session.identity_id())
        {
            return Err("The open profile has changed".into());
        }
        if v["op"] == "history_page" {
            return self.history_page(&v).await;
        }
        if field(&v, "op")?.starts_with("invitation_")
            || field(&v, "op")?.starts_with("contact_")
            || field(&v, "op")? == "create_dm"
        {
            return self.invitation_operation(v).await;
        }
        if matches!(
            field(&v, "op")?,
            "history_request"
                | "history_preview"
                | "history_approve"
                | "history_import"
                | "file_share"
                | "file_download"
        ) {
            let i = self.authority_index(&v)?;
            if !self.authorities.space_ready(&self.authorities.0[i]) {
                return Err("Space controller transition incomplete or conflicting".into());
            }
        }
        match field(&v, "op")? {
            "set_profile_name" => {
                self.set_profile_name(field(&v, "name")?)?;
            }
            "set_profile_details" => {
                let avatar = match v.get("avatar") {
                    Some(Value::Null) => None,
                    Some(Value::String(value)) => Some(value.as_str()),
                    _ => return Err("invalid profile photo".into()),
                };
                self.set_profile_details(field(&v, "name")?, avatar)?;
            }
            "create_chat" => {
                let group = self.parse_group(&v)?;
                let kind = match v.get("chat_kind") {
                    None => ChatKind::Chat,
                    Some(value) => {
                        serde_json::from_value(value.clone()).map_err(|_| "invalid chat type")?
                    }
                };
                self.create_chat(field(&v, "name")?, group.as_deref(), kind)
                    .await?;
            }
            "create_group" => {
                self.create_group(field(&v, "name")?)?;
            }
            "set_chat_group" => {
                self.set_chat_group(&v)?;
            }
            "set_chat_muted" => {
                // A private preference, including for members who cannot post
                // or manage the chat. Never alter shared authority/read markers.
                let i = self.authority_index(&v)?;
                let muted = v["muted"].as_bool().ok_or("invalid mute setting")?;
                let mut read = (*self.read).clone();
                if muted {
                    read.muted_streams.insert(self.pins[i].stream);
                } else {
                    read.muted_streams.remove(&self.pins[i].stream);
                }
                self.write_read_state(&read)?;
                self.read = read.into();
            }
            "device_export" | "recovery_export" | "recovery_preview" | "config_preview"
            | "controller_recover" => return self.recovery_operation(v).await,
            "view" => return self.view().await,
            "message_debug" => return Ok(json!({"result":self.message_debug(&v).await?})),
            "create_space" => {
                let name = field(&v, "name")?;
                let bytes =
                    Zeroizing::new(vault::read_private(Path::new(field(&v, "recovery_card")?))?);
                let card: RecoveryCard = serde_json::from_slice(&bytes)?;
                self.create_space(name, &card).await?;
            }
            "import_stream" => {
                let space: SpaceId = field(&v, "space")?.parse()?;
                let stream: StreamId = field(&v, "stream")?.parse()?;
                let root = field(&v, "root")?;
                let name = field(&v, "name")?;
                if name.is_empty() || name.len() > 120 {
                    return Err("invalid channel name".into());
                }
                let bytes = read_exchange(Path::new(field(&v, "path")?), MAX_EXCHANGE)?;
                let incoming = Authority::open_snapshot(
                    &bytes,
                    self.session.age_identity(),
                    space,
                    &root_key(root)?,
                    stream,
                )?;
                let index = self
                    .pins
                    .iter()
                    .position(|p| p.space == space && p.stream == stream);
                if index.is_none()
                    && !incoming
                        .head()?
                        .members
                        .iter()
                        .any(|m| m.credential_ids.contains(&self.session.credential().id()))
                {
                    return Err("device requires explicit membership approval".into());
                }
                if incoming.recovery_id().is_some()
                    && index.and_then(|i| self.authorities.0[i].recovery_id())
                        != incoming.recovery_id()
                {
                    Self::confirm_recovery_import(&v, &bytes, &incoming)?;
                }
                let a = incoming
                    .merge_into_store(
                        index.map(|i| &self.authorities.0[i]),
                        &self.store,
                        self.session.age_identity(),
                        now()?,
                    )
                    .await?;
                if let Some(i) = index {
                    self.authorities.0[i] = a;
                } else {
                    self.pins.push(Pin {
                        chat_kind: Some(chats::imported_kind(&a, self.session.identity_id())?),
                        name: name.into(),
                        space,
                        stream,
                        root: root.into(),
                        group: None,
                        created_at: now()?.as_millis(),
                    });
                    self.authorities.0.push(a);
                }
                self.persist_workspace()?;
            }
            "send" => {
                let i = self.authority_index(&v)?;
                let a = &self.authorities.0[i];
                if !self.authorities.space_ready(a) {
                    return Err("Space controller transition incomplete or conflicting".into());
                }
                let time = now()?;
                let mut originals = self.originals(a).await?;
                if let Some(target) = v.get("reply_to").and_then(Value::as_str) {
                    let record = self.message_record(a, target.parse()?).await?;
                    if let Some(root) = record.body()["payload"]["thread_root"].as_str() {
                        originals
                            .push((self.message_record(a, root.parse()?).await?, String::new()));
                    }
                    originals.push((record, String::new()));
                }
                let thread_root = match v.get("reply_to") {
                    None => None,
                    Some(value) => {
                        let target: RecordId = value
                            .as_str()
                            .ok_or("invalid reply target")?
                            .parse()
                            .map_err(|_| "invalid reply target")?;
                        let record = originals
                            .iter()
                            .find(|(r, _)| r.id() == target && r.body()["kind"] != "chat.action")
                            .map(|(r, _)| r)
                            .ok_or("reply target unavailable in this chat")?;
                        let root = if record.body()["kind"] == "chat.message" {
                            record.chat()?.payload.thread_root.unwrap_or(target)
                        } else {
                            target
                        };
                        let original = originals
                            .iter()
                            .find(|(r, _)| r.id() == root && r.body()["kind"] != "chat.action")
                            .map(|(r, _)| r)
                            .ok_or("thread original unavailable in this chat")?;
                        if original.body()["kind"] == "chat.message"
                            && original.chat()?.payload.thread_root.is_some()
                        {
                            return Err("invalid thread root".into());
                        }
                        Some(root)
                    }
                };
                let highest = originals
                    .iter()
                    .filter_map(|(r, _)| r.body()["logical_time"].as_u64())
                    .max()
                    .unwrap_or(0);
                let r = a.prepare_chat(
                    ChatMessage {
                        v: 1,
                        kind: "chat.message".into(),
                        nonce: record::random_hex::<16>()?,
                        space_id: a.space(),
                        stream_id: a.stream(),
                        issuer_identity: self.session.identity_id(),
                        issuer_credential: self.session.credential().id(),
                        config_id: a.head_id().ok_or("head")?,
                        audience: vec![],
                        recipient_credentials: vec![],
                        logical_time: highest
                            .checked_add(1)
                            .ok_or("logical time overflow")?
                            .max(u64::try_from(time.as_millis())?),
                        created_at: field(&v, "created_at")?.into(),
                        parents: vec![],
                        payload: TextPayload {
                            text: field(&v, "text")?.into(),
                            sender_name: self.profile_details.as_ref().map(|p| p.name.clone()),
                            thread_root,
                            action: None,
                        },
                    },
                    self.session.signing_key(),
                )?;
                let chat = r.chat()?;
                let recipients = chat
                    .recipient_credentials
                    .iter()
                    .map(|id| a.credential(*id).cloned())
                    .collect::<record::Result<Vec<_>>>()?;
                let cipher = crypto::seal_chat(&r, &recipients)?;
                self.store
                    .commit_local_record_with_outbox(PreparedLocalRecord::new(
                        r.id(),
                        cipher,
                        RecordMetadata::new(
                            "chat.message",
                            Some(a.space()),
                            Some(a.stream()),
                            a.head_id(),
                        )?,
                        self.targets(),
                        time,
                    )?)
                    .await?;
            }
            "add_peer" => {
                let p: PeerDescriptor =
                    serde_json::from_slice(&vault::read_private(Path::new(field(&v, "path")?))?)?;
                if !self.ensure_peer(p)? {
                    return Err("peer mailbox already configured".into());
                }
            }
            "sync" | "sync_live" => {
                let live = field(&v, "op")? == "sync_live";
                let receive_only = live && v["receive_only"] == true;
                let delivery = if live {
                    Value::Null
                } else {
                    self.sync_invitations(true).await?
                };
                let sync = SyncClient {
                    store: &self.store,
                    identity: self.session.age_identity(),
                    credential: self.session.credential().id(),
                    authority: &self.authorities,
                    peers: &self.peers,
                };
                let report = if live {
                    let report = if receive_only {
                        sync.receive_foreground(now()?, self.sync_round).await?
                    } else {
                        sync.foreground(now()?, self.sync_round).await?
                    };
                    self.sync_round = self.sync_round.wrapping_add(1);
                    report
                } else {
                    sync.once(now()?).await?
                };
                if !receive_only {
                    self.send_wakes().await;
                }
                return Ok(
                    json!({"view":if !live || report.changes_view() { Some(self.view().await?) } else { None },"result":report,"delivery":delivery["delivery"]}),
                );
            }
            "invite_create" => {
                let i = self.authority_index(&v)?;
                let a = &self.authorities.0[i];
                self.require_controller(a)?;
                let r = invite::create(a, self.session.signing_key())?;
                let p = &self.pins[i];
                let recovery = a
                    .controller_recovery_chain()?
                    .iter()
                    .map(|r| STANDARD.encode(r.bytes()))
                    .collect::<Vec<_>>();
                let exported = json!({"v":1,"space":p.space,"stream":p.stream,"root":p.root,"invitation":STANDARD.encode(r.bytes()),"genesis":STANDARD.encode(a.genesis().bytes()),"controller":STANDARD.encode(a.controller().record().bytes()),"initial_controller":STANDARD.encode(a.initial_controller().record().bytes()),"controller_recovery":recovery});
                write_export(
                    Path::new(field(&v, "output")?),
                    &serde_json::to_vec(&exported)?,
                )?;
            }
            "invite_request" => {
                let exchange: Value = serde_json::from_slice(&read_exchange(
                    Path::new(field(&v, "path")?),
                    512 * 1024,
                )?)?;
                let expected: SpaceId = field(&v, "space")?.parse()?;
                let root = root_key(field(&v, "root")?)?;
                if exchange["space"] != json!(expected)
                    || exchange["root"] != json!(record::encode_hex(root.as_bytes()))
                {
                    return Err("confirm the Space and root fingerprint out of band".into());
                }
                let controller_record = decode_record(field(&exchange, "controller")?)?;
                let controller = VerifiedCredential::verify(
                    controller_record.bytes(),
                    &root_key(field(controller_record.body(), "root_public_key")?)?,
                )?;
                let initial_record = if exchange["initial_controller"].is_string() {
                    decode_record(field(&exchange, "initial_controller")?)?
                } else {
                    controller_record.clone()
                };
                let initial = VerifiedCredential::verify(
                    initial_record.bytes(),
                    &root_key(field(initial_record.body(), "root_public_key")?)?,
                )?;
                let invitation = decode_record(field(&exchange, "invitation")?)?;
                let genesis = decode_record(field(&exchange, "genesis")?)?;
                let authority = Authority::new(
                    genesis.bytes(),
                    expected,
                    &root,
                    initial,
                    field(&exchange, "stream")?.parse()?,
                )?;
                let chain = exchange["controller_recovery"]
                    .as_array()
                    .map(|records| {
                        records
                            .iter()
                            .map(|r| decode_record(r.as_str().ok_or("invalid recovery proof")?))
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                authority.verify_controller_export(&chain, &controller)?;
                let invitation_body: invite::Invitation = invitation.decode()?;
                if invitation_body.space_id != expected
                    || json!(invitation_body.stream_id) != exchange["stream"]
                {
                    return Err("invitation scope mismatch".into());
                }
                let request = invite::request(
                    &invitation,
                    &controller,
                    self.session.credential(),
                    self.session.signing_key(),
                )?;
                let exported = json!({"invitation":STANDARD.encode(invitation.bytes()),"request":STANDARD.encode(request.bytes()),"credential":STANDARD.encode(self.session.credential().record().bytes())});
                write_export(
                    Path::new(field(&v, "output")?),
                    &serde_json::to_vec(&exported)?,
                )?;
            }
            "invite_approve" => {
                let i = self.authority_index(&v)?;
                self.require_controller(&self.authorities.0[i])?;
                let exchange: Value = serde_json::from_slice(&read_exchange(
                    Path::new(field(&v, "path")?),
                    512 * 1024,
                )?)?;
                let cr = decode_record(field(&exchange, "credential")?)?;
                let c = VerifiedCredential::verify(
                    cr.bytes(),
                    &root_key(field(cr.body(), "root_public_key")?)?,
                )?;
                let mut caps = vec![Capability::Read];
                if v["post"] == true {
                    caps.push(Capability::Post);
                }
                if v["share_history"] == true {
                    caps.push(Capability::ShareHistory);
                }
                let a = &mut self.authorities.0[i];
                invite::approve(
                    a,
                    &self.store,
                    invite::CandidateApproval {
                        invitation: decode_record(field(&exchange, "invitation")?)?,
                        request: decode_record(field(&exchange, "request")?)?,
                        credential: c.clone(),
                        confirmed_identity: field(&v, "fingerprint")?.parse()?,
                        capabilities: caps,
                    },
                    self.session.signing_key(),
                    self.session.age_identity(),
                    now()?,
                )
                .await?;
                write_export(
                    Path::new(field(&v, "output")?),
                    &a.seal_snapshot(&c.recipient())?,
                )?;
            }
            "export_config" => {
                let i = self.authority_index(&v)?;
                let a = &self.authorities.0[i];
                self.require_controller(a)?;
                let c = a.credential(field(&v, "credential")?.parse()?)?;
                if !a
                    .head()?
                    .members
                    .iter()
                    .any(|m| m.credential_ids.contains(&c.id()))
                {
                    return Err("recipient is not a current member".into());
                }
                write_export(
                    Path::new(field(&v, "output")?),
                    &a.seal_snapshot(&c.recipient())?,
                )?;
            }
            "remove_member" => return self.remove_chat_member(v).await,
            "history_request" => {
                let i = self.authority_index(&v)?;
                let count = v["count"].as_u64().ok_or("count")?;
                if ![20, 50, 100].contains(&count) {
                    return Err("choose 20, 50 or 100".into());
                }
                let r = history::create_request(
                    &self.authorities.0[i],
                    self.session.credential().id(),
                    count,
                    None,
                    self.session.signing_key(),
                )?;
                write_export(Path::new(field(&v, "output")?), r.bytes())?;
            }
            "history_preview" | "history_approve" => {
                let i = self.authority_index(&v)?;
                let a = &self.authorities.0[i];
                let request = SignedRecord::parse(&read_exchange(
                    Path::new(field(&v, "path")?),
                    record::MAX_RECORD,
                )?)?;
                if field(&v, "op")? == "history_approve" {
                    let expected: RecordId = field(&v, "expected_request")?.parse()?;
                    if request.id() != expected {
                        return Err("history request changed after preview".into());
                    }
                }
                let requested: history::HistoryRequest = request.decode()?;
                let mut available = self
                    .originals(a)
                    .await?
                    .into_iter()
                    .map(|(r, _)| r)
                    .filter(|r| r.body()["kind"] == "chat.message")
                    .collect::<Vec<_>>();
                let selection = if field(&v, "op")? == "history_preview" {
                    let start = available
                        .len()
                        .saturating_sub(usize::try_from(requested.count.min(100))?);
                    available.drain(..start);
                    available
                } else {
                    let ids: Vec<RecordId> = serde_json::from_value(v["selection"].clone())?;
                    if ids.is_empty() || ids.len() > 100 {
                        return Err("explicit history selection required".into());
                    }
                    let records = available
                        .into_iter()
                        .map(|r| (r.id(), r))
                        .collect::<BTreeMap<_, _>>();
                    ids.iter()
                        .map(|id| {
                            records
                                .get(id)
                                .cloned()
                                .ok_or("selected original unavailable")
                        })
                        .collect::<std::result::Result<Vec<_>, _>>()?
                };
                let grant = history::approve(
                    a,
                    &request,
                    self.session.credential().id(),
                    &selection,
                    self.session.signing_key(),
                )?;
                if field(&v, "op")? == "history_preview" {
                    return Ok(
                        json!({"request_id":request.id(),"recipient":requested.issuer_identity,"selection":selection.iter().map(|r|json!({"id":r.id(),"text":r.body()["payload"]["text"]})).collect::<Vec<_>>()}),
                    );
                }
                let cipher = history::seal(a, &grant)?;
                self.store
                    .commit_local_record_with_outbox(PreparedLocalRecord::new(
                        grant.id(),
                        cipher.clone(),
                        RecordMetadata::new(
                            "history.access.granted",
                            Some(a.space()),
                            Some(a.stream()),
                            a.head_id(),
                        )?,
                        self.targets(),
                        now()?,
                    )?)
                    .await?;
                write_export(Path::new(field(&v, "output")?), &cipher)?;
            }
            "history_import" => {
                let i = self.authority_index(&v)?;
                let request = SignedRecord::parse(&read_exchange(
                    Path::new(field(&v, "request")?),
                    record::MAX_RECORD,
                )?)?;
                let bytes = read_exchange(Path::new(field(&v, "path")?), MAX_EXCHANGE)?;
                let bundle = history::VerifiedBundle::open(
                    &bytes,
                    self.session.age_identity(),
                    self.session.credential().id(),
                    &self.authorities.0[i],
                    &request,
                )?;
                self.store.import_history(bundle, now()?).await?;
            }
            "file_share" => {
                let i = self.authority_index(&v)?;
                let path = Path::new(field(&v, "path")?);
                let bytes = Zeroizing::new(read_exchange(path, crate::files::MAX_FILE)?);
                let file = crate::files::prepare(
                    &self.authorities.0[i],
                    self.session.credential().id(),
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .ok_or("filename")?,
                    "application/octet-stream",
                    &bytes,
                    self.session.signing_key(),
                )?;
                self.store.commit_file(file, self.targets(), now()?).await?;
            }
            "file_download" => {
                let i = self.authority_index(&v)?;
                let a = &self.authorities.0[i];
                let id: RecordId = field(&v, "record")?.parse()?;
                let r = self.message_record(a, id).await?;
                let share = crate::files::VerifiedFileShare::verify(
                    &r,
                    a,
                    self.session.credential().id(),
                    true,
                )?;
                let mut bytes = self.store.get_object(share.body().object_id).await?;
                if bytes.is_none() {
                    'peers: for peer in &self.peers {
                        let mut after = 0;
                        for _ in 0..8 {
                            let page = match peer.inventory(after).await {
                                Ok(p) => p,
                                Err(_) => break,
                            };
                            for entry in &page.entries {
                                if entry.object_id == share.body().object_id
                                    && let Ok(found) =
                                        peer.get(entry.object_id, entry.size_bytes).await
                                {
                                    bytes = Some(found);
                                    break 'peers;
                                }
                            }
                            if page.entries.is_empty()
                                || page
                                    .entries
                                    .last()
                                    .is_some_and(|e| e.arrival_seq == page.head)
                            {
                                break;
                            }
                            after = page.entries.last().ok_or("inventory")?.arrival_seq;
                        }
                    }
                }
                let bytes = bytes.ok_or(
                    "unavailable: no reachable replica supplied the file in the bounded inventory",
                )?;
                let file = crate::files::open(
                    &bytes,
                    self.session.age_identity(),
                    self.session.credential().id(),
                    &share,
                    a,
                )?;
                // An explicit, fully verified download also retains its original
                // ciphertext for offline reuse and repair of previously known copies.
                self.store
                    .cache_repair_object(share.body().object_id, bytes, now()?)
                    .await?;
                let content = Zeroizing::new(file.bytes);
                write_export(Path::new(field(&v, "output")?), &content)?;
            }
            "message_action" => {
                self.message_action(&v).await?;
            }
            "remind" | "reminder_remove" => {
                self.update_reminder(&v).await?;
            }
            "mark_read" | "mark_unread" => {
                let i = self.authority_index(&v)?;
                let stream = self.pins[i].stream.to_string();
                let ids = v["records"]
                    .as_array()
                    .ok_or("invalid read marker")?
                    .iter()
                    .map(|value| value.as_str().ok_or_else(|| "invalid read marker".into()))
                    .collect::<Result<Vec<_>>>()?;
                if ids.is_empty() || ids.len() > 1000 {
                    return Err("invalid read marker".into());
                }
                for id in &ids {
                    self.message_record(&self.authorities.0[i], id.parse()?)
                        .await?;
                }
                let mut read = (*self.read).clone();
                let unread = read.unread.entry(stream.clone()).or_default();
                let seen = read.seen.entry(stream).or_default();
                if field(&v, "op")? == "mark_unread" {
                    seen.retain(|id| !ids.contains(&id.as_str()));
                    unread.extend(ids.into_iter().map(str::to_owned));
                } else {
                    unread.retain(|id| !ids.contains(&id.as_str()));
                    seen.extend(ids.into_iter().map(str::to_owned));
                }
                unread.sort();
                unread.dedup();
                seen.sort();
                seen.dedup();
                self.write_read_state(&read)?;
                self.read = read.into();
            }
            _ => return Err("unsupported operation".into()),
        }
        let view = if self.presentation.enabled()
            && matches!(
                v["op"].as_str(),
                Some("send" | "message_action" | "mark_read" | "mark_unread" | "set_chat_muted")
            ) {
            let index = self.authority_index(&v)?;
            let mut view = self.view_local_scope(Some(self.pins[index].stream)).await?;
            view["partial"] = json!(true);
            view
        } else {
            self.view().await?
        };
        Ok(json!({"view":view,"result":{"status":"completed"}}))
    }
    fn require_controller(&self, a: &Authority) -> Result<()> {
        if !self.session.can_control(a.space())
            || a.controller().id() != self.session.credential().id()
            || !self.authorities.space_ready(a)
        {
            return Err("controller unavailable, retired, restored follower, or forked".into());
        }
        Ok(())
    }
}

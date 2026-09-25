//! Explicit bounded text history disclosure. Never changes original audiences.
use crate::{
    authority::{Authority, Capability},
    crypto,
    ids::{IdentityId, ObjectId, RecordId, SpaceId, StreamId},
    record::{self, ChatMessage, RecordError, Result, SignedRecord},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
pub const MAX_BUNDLE: usize = 8 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRequest {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub config_id: RecordId,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
    pub count: u64,
    pub anchor_record_id: Option<RecordId>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub record_id: RecordId,
    pub signed_record_base64: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionBasis {
    pub anchor_record_id: Option<RecordId>,
    pub order: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryGrant {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub config_id: RecordId,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
    pub audience: Vec<IdentityId>,
    pub recipient_credentials: Vec<RecordId>,
    pub request_id: RecordId,
    pub recipient_identity: IdentityId,
    pub selection: Vec<Selection>,
    pub proofs: Vec<String>,
    pub count: u64,
    pub selection_basis: SelectionBasis,
}
pub fn create_request(
    a: &Authority,
    credential: RecordId,
    count: u64,
    anchor: Option<RecordId>,
    key: &SigningKey,
) -> Result<SignedRecord> {
    let c = a.credential(credential)?;
    let head = a.head_id().ok_or(RecordError::Authority)?;
    if a.is_forked()
        || c.key() != &key.verifying_key()
        || !a.has(head, c.identity(), Capability::Read)
        || !(1..=100).contains(&count)
        || !a
            .head()?
            .members
            .iter()
            .any(|m| m.credential_ids.contains(&credential))
    {
        return Err(RecordError::Authority);
    }
    let request = HistoryRequest {
        v: 1,
        kind: "history.access.requested".into(),
        nonce: record::random_hex::<16>()?,
        space_id: a.space(),
        stream_id: a.stream(),
        config_id: head,
        issuer_identity: c.identity(),
        issuer_credential: credential,
        count,
        anchor_record_id: anchor,
    };
    SignedRecord::sign(
        &serde_json::to_vec(&request).map_err(|_| RecordError::Json)?,
        key,
    )
}
fn verify_request(a: &Authority, r: &SignedRecord) -> Result<HistoryRequest> {
    let request: HistoryRequest = r.decode()?;
    record::hex::<16>(&request.nonce)?;
    let c = a.credential(request.issuer_credential)?;
    r.verify_signature(c.key())?;
    if a.is_forked()
        || request.v != 1
        || request.kind != "history.access.requested"
        || request.space_id != a.space()
        || request.stream_id != a.stream()
        || Some(request.config_id) != a.head_id()
        || request.issuer_identity != c.identity()
        || !(1..=100).contains(&request.count)
        || !a.has(request.config_id, c.identity(), Capability::Read)
        || !a
            .head()?
            .members
            .iter()
            .any(|m| m.credential_ids.contains(&c.id()))
    {
        return Err(RecordError::Authority);
    }
    Ok(request)
}
fn recipients(
    a: &Authority,
    requester: IdentityId,
    exporter: IdentityId,
) -> Result<(Vec<IdentityId>, Vec<RecordId>)> {
    let mut audience = std::collections::BTreeSet::from([requester, exporter]);
    for id in &a.head()?.owner_credential_ids {
        audience.insert(a.credential(*id)?.identity());
    }
    let credentials = a
        .head()?
        .members
        .iter()
        .filter(|m| audience.contains(&m.identity_id))
        .flat_map(|m| m.credential_ids.iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    Ok((
        audience.into_iter().collect(),
        credentials.into_iter().collect(),
    ))
}
fn validate_exporter(a: &Authority, id: RecordId) -> Result<IdentityId> {
    let c = a.credential(id)?;
    let head = a.head_id().ok_or(RecordError::Authority)?;
    if !a.has(head, c.identity(), Capability::Read)
        || !a.has(head, c.identity(), Capability::ShareHistory)
        || !a
            .head()?
            .members
            .iter()
            .any(|m| m.credential_ids.contains(&id))
    {
        return Err(RecordError::Authority);
    }
    Ok(c.identity())
}
fn order(chat: &ChatMessage, id: RecordId) -> (u64, RecordId, RecordId) {
    (chat.logical_time, chat.issuer_credential, id)
}
fn proofs(a: &Authority, records: &[SignedRecord]) -> Result<Vec<String>> {
    let mut needed = std::collections::BTreeSet::new();
    for r in records {
        let mut id = Some(r.chat()?.config_id);
        while let Some(config) = id {
            if !needed.insert(config) {
                break;
            }
            id = a.config(config)?.previous_config_id;
        }
    }
    let mut configs = needed.into_iter().collect::<Vec<_>>();
    configs.sort_by_key(|id| a.config(*id).map(|c| c.sequence).unwrap_or(0));
    let mut credentials =
        std::collections::BTreeSet::from([a.initial_controller().id(), a.controller().id()]);
    for id in &configs {
        for member in &a.config(*id)?.members {
            credentials.extend(member.credential_ids.iter().copied());
        }
    }
    let mut p = vec![STANDARD.encode(a.genesis().bytes())];
    for id in credentials {
        p.push(STANDARD.encode(a.credential(id)?.record().bytes()));
    }
    for id in configs {
        p.push(STANDARD.encode(a.config_record(id)?.bytes()));
    }
    Ok(p)
}
pub fn approve(
    a: &Authority,
    request: &SignedRecord,
    exporter: RecordId,
    selection: &[SignedRecord],
    key: &SigningKey,
) -> Result<SignedRecord> {
    let requested = verify_request(a, request)?;
    let identity = validate_exporter(a, exporter)?;
    if a.credential(exporter)?.key() != &key.verifying_key()
        || selection.is_empty()
        || selection.len() > 100
        || selection.len() > requested.count as usize
    {
        return Err(RecordError::Authority);
    }
    let mut ordered = Vec::new();
    for r in selection {
        let chat = a.verify_historical(r)?;
        ordered.push((order(&chat, r.id()), r.clone()));
    }
    ordered.sort_by_key(|(key, _)| *key);
    if ordered.windows(2).any(|p| p[0].1.id() == p[1].1.id()) {
        return Err(RecordError::Authority);
    }
    if let Some(anchor) = requested.anchor_record_id {
        let anchor_record = selection
            .iter()
            .find(|r| r.id() == anchor)
            .ok_or(RecordError::Authority)?;
        let upper = order(&anchor_record.chat()?, anchor);
        if ordered.iter().any(|(k, _)| *k > upper) {
            return Err(RecordError::Authority);
        }
    }
    let originals: Vec<_> = ordered.into_iter().map(|(_, r)| r).collect();
    let (audience, recipient_credentials) = recipients(a, requested.issuer_identity, identity)?;
    let grant = HistoryGrant {
        v: 1,
        kind: "history.access.granted".into(),
        nonce: record::random_hex::<16>()?,
        space_id: a.space(),
        stream_id: a.stream(),
        config_id: a.head_id().ok_or(RecordError::Authority)?,
        issuer_identity: identity,
        issuer_credential: exporter,
        audience,
        recipient_credentials,
        request_id: request.id(),
        recipient_identity: requested.issuer_identity,
        count: originals.len() as u64,
        selection: originals
            .iter()
            .map(|r| Selection {
                record_id: r.id(),
                signed_record_base64: STANDARD.encode(r.bytes()),
            })
            .collect(),
        proofs: proofs(a, &originals)?,
        selection_basis: SelectionBasis {
            anchor_record_id: requested.anchor_record_id,
            order: "logical_time,issuer_credential,record_id".into(),
        },
    };
    SignedRecord::sign_bounded(
        &serde_json::to_vec(&grant).map_err(|_| RecordError::Json)?,
        key,
        MAX_BUNDLE,
    )
}
pub fn seal(a: &Authority, grant: &SignedRecord) -> Result<Vec<u8>> {
    let g: HistoryGrant = grant.decode()?;
    if g.v != 1 || g.kind != "history.access.granted" || Some(g.config_id) != a.head_id() {
        return Err(RecordError::Authority);
    }
    let keys = g
        .recipient_credentials
        .iter()
        .map(|id| a.credential(*id).map(|c| c.recipient()))
        .collect::<Result<Vec<_>>>()?;
    crypto::seal_bytes(grant.bytes(), &keys, MAX_BUNDLE).map_err(|_| RecordError::Authority)
}
pub struct VerifiedBundle {
    record: SignedRecord,
    grant: HistoryGrant,
    originals: Vec<SignedRecord>,
    ciphertext: Vec<u8>,
}
impl VerifiedBundle {
    pub fn open(
        ciphertext: &[u8],
        identity: &dyn crate::crypto::DecryptionIdentity,
        own_credential: RecordId,
        a: &Authority,
        request: &SignedRecord,
    ) -> Result<Self> {
        let bytes = crypto::open_bytes(ciphertext, identity, MAX_BUNDLE)
            .map_err(|_| RecordError::Authority)?;
        let record = SignedRecord::parse_bounded(&bytes, MAX_BUNDLE)?;
        let grant: HistoryGrant = record.decode()?;
        let requested = verify_request(a, request)?;
        record::hex::<16>(&grant.nonce)?;
        let exporter = validate_exporter(a, grant.issuer_credential)?;
        record.verify_signature(a.credential(grant.issuer_credential)?.key())?;
        let (audience, recipients) = recipients(a, requested.issuer_identity, exporter)?;
        if grant.v != 1
            || grant.kind != "history.access.granted"
            || grant.space_id != a.space()
            || grant.stream_id != a.stream()
            || Some(grant.config_id) != a.head_id()
            || grant.issuer_identity != exporter
            || grant.request_id != request.id()
            || grant.recipient_identity != requested.issuer_identity
            || grant.audience != audience
            || grant.recipient_credentials != recipients
            || !recipients.contains(&own_credential)
            || a.credential(own_credential)?.recipient() != identity.to_public()
            || grant.selection.is_empty()
            || grant.selection.len() > 100
            || grant.count != grant.selection.len() as u64
            || grant.count > requested.count
            || grant.selection_basis.order != "logical_time,issuer_credential,record_id"
            || grant.selection_basis.anchor_record_id != requested.anchor_record_id
        {
            return Err(RecordError::Authority);
        }
        let mut originals = Vec::new();
        let mut last = None;
        for selected in &grant.selection {
            if selected.signed_record_base64.len() > record::MAX_RECORD.div_ceil(3) * 4 {
                return Err(RecordError::Framing);
            }
            let bytes = STANDARD
                .decode(&selected.signed_record_base64)
                .map_err(|_| RecordError::Json)?;
            let r = SignedRecord::parse(&bytes)?;
            if r.id() != selected.record_id {
                return Err(RecordError::Authority);
            }
            let chat = a.verify_historical(&r)?;
            let key = order(&chat, r.id());
            if last.is_some_and(|p| p >= key) {
                return Err(RecordError::Authority);
            }
            last = Some(key);
            originals.push(r);
        }
        if let Some(anchor) = requested.anchor_record_id
            && originals.last().map(SignedRecord::id) != Some(anchor)
        {
            return Err(RecordError::Authority);
        }
        if grant.proofs != proofs(a, &originals)? {
            return Err(RecordError::Authority);
        }
        Ok(Self {
            record,
            grant,
            originals,
            ciphertext: ciphertext.to_vec(),
        })
    }
    pub fn originals(&self) -> &[SignedRecord] {
        &self.originals
    }
    pub fn record(&self) -> &SignedRecord {
        &self.record
    }
    pub fn grant(&self) -> &HistoryGrant {
        &self.grant
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn object_id(&self) -> ObjectId {
        ObjectId::of_ciphertext(&self.ciphertext)
    }
}

pub(crate) fn verify_outgoing(a: &Authority, r: &SignedRecord, own: RecordId) -> Result<()> {
    let g: HistoryGrant = r.decode()?;
    let exporter = validate_exporter(a, own)?;
    let (audience, recipients) = recipients(a, g.recipient_identity, exporter)?;
    r.verify_signature(a.credential(own)?.key())?;
    if a.is_forked()
        || g.v != 1
        || g.kind != "history.access.granted"
        || g.issuer_credential != own
        || g.issuer_identity != exporter
        || g.space_id != a.space()
        || g.stream_id != a.stream()
        || Some(g.config_id) != a.head_id()
        || g.audience != audience
        || g.recipient_credentials != recipients
        || g.count == 0
        || g.count > 100
        || g.selection.len() as u64 != g.count
    {
        return Err(RecordError::Authority);
    }
    Ok(())
}

//! A bounded sync pass over durable storage; fixed authority is for lab fixtures.
use crate::{
    crypto,
    identity::VerifiedCredential,
    ids::{IdentityId, MailboxId, ObjectId, PeerId, RecordId, SpaceId, StreamId},
    record::{ChatMessage, RecordError, SignedRecord},
    replica::{self, Inventory, TransferHint, VerifiedReceipt},
    store::{ClientStore, LocalTime, RetryReason, TransportFailure},
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("invalid peer endpoint or bounded response")]
    Peer,
    #[error("network request failed")]
    Network,
    #[error("transport request failed: {0:?}")]
    Transport(TransportFailure),
    #[error("record is not authorized in the supplied context")]
    Authority,
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}
type Result<T> = std::result::Result<T, SyncError>;

impl SyncError {
    fn diagnostic(&self) -> TransportFailure {
        match self {
            Self::Transport(failure) => *failure,
            Self::Peer => TransportFailure::InvalidResponse,
            _ => TransportFailure::Network,
        }
    }
}

fn network_error(error: reqwest::Error) -> SyncError {
    // Classify locally; never return/persist the source text, URL or headers.
    let failure = if error.is_timeout() {
        TransportFailure::Timeout
    } else {
        use std::error::Error;
        let mut source = error.source();
        let mut description = String::new();
        while let Some(cause) = source {
            description.push_str(&cause.to_string().to_ascii_lowercase());
            source = cause.source();
        }
        if description.contains("certificate") && description.contains("revoked") {
            TransportFailure::TlsRevoked
        } else if description.contains("certificate") && description.contains("expired") {
            TransportFailure::TlsExpired
        } else if description.contains("unknownissuer")
            || description.contains("unknown issuer")
            || description.contains("not trusted")
        {
            TransportFailure::TlsUntrusted
        } else if description.contains("certificate")
            || description.contains("tls")
            || description.contains("verifier")
        {
            TransportFailure::Tls
        } else if description.contains("dns")
            || description.contains("resolve")
            || description.contains("name or service")
        {
            TransportFailure::Dns
        } else if error.is_connect() {
            TransportFailure::Connect
        } else {
            TransportFailure::Network
        }
    };
    SyncError::Transport(failure)
}

#[derive(Clone)]
pub struct VerifiedChat {
    record: SignedRecord,
    chat: ChatMessage,
}
impl VerifiedChat {
    pub fn record(&self) -> &SignedRecord {
        &self.record
    }
    pub fn chat(&self) -> &ChatMessage {
        &self.chat
    }
    pub(crate) fn new(record: SignedRecord, chat: ChatMessage) -> Self {
        Self { record, chat }
    }
}
pub enum ChatDecision {
    Accepted(Box<VerifiedChat>),
    FileShared(Box<crate::files::VerifiedFileShare>),
    WaitingForProof,
    QuarantinedStale,
    Forked,
}
pub trait ChatAuthority: Sync {
    fn verify_outgoing(
        &self,
        record: &SignedRecord,
        recipient: RecordId,
    ) -> std::result::Result<(), RecordError> {
        self.verify(record, recipient).map(|_| ())
    }
    fn admit(
        &self,
        record: &SignedRecord,
        recipient: RecordId,
        _already_accepted: bool,
    ) -> std::result::Result<ChatDecision, RecordError> {
        self.verify(record, recipient)
            .map(|record| ChatDecision::Accepted(Box::new(record)))
    }
    fn verify(
        &self,
        record: &SignedRecord,
        recipient: RecordId,
    ) -> std::result::Result<VerifiedChat, RecordError>;
}
/// Explicit trusted fixture, never loaded from an unverified network snapshot.
/// T06 supplies a genesis/config chain instead of this lab-only context.
pub struct FixedDemoAuthority {
    pub space: SpaceId,
    pub stream: StreamId,
    pub config: RecordId,
    pub readers: BTreeSet<IdentityId>,
    pub posters: BTreeSet<IdentityId>,
    pub credentials: BTreeMap<RecordId, VerifiedCredential>,
}
impl ChatAuthority for FixedDemoAuthority {
    fn verify(
        &self,
        record: &SignedRecord,
        recipient: RecordId,
    ) -> std::result::Result<VerifiedChat, RecordError> {
        let chat = record.chat()?;
        let issuer = self
            .credentials
            .get(&chat.issuer_credential)
            .ok_or(RecordError::Authority)?;
        issuer.verify_chat(record)?;
        if chat.space_id != self.space
            || chat.stream_id != self.stream
            || chat.config_id != self.config
            || !self.posters.contains(&chat.issuer_identity)
            || chat.audience != self.readers.iter().copied().collect::<Vec<_>>()
        {
            return Err(RecordError::Authority);
        }
        let expected: Vec<_> = self
            .credentials
            .iter()
            .filter(|(id, c)| {
                self.readers.contains(&c.identity()) || **id == chat.issuer_credential
            })
            .map(|(id, _)| *id)
            .collect();
        if expected != chat.recipient_credentials || !expected.contains(&recipient) {
            return Err(RecordError::Authority);
        }
        Ok(VerifiedChat::new(record.clone(), chat))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerDescriptor {
    pub url: String,
    pub signing_public_key: String,
    pub mailbox_id: MailboxId,
    pub read_token: Option<String>,
    pub write_token: Option<String>,
}
#[derive(Clone)]
pub struct Peer {
    base: reqwest::Url,
    key: VerifyingKey,
    descriptor: PeerDescriptor,
    client: reqwest::Client,
}
impl Peer {
    pub async fn create_child(&self, child: &replica::ChildMailbox) -> Result<()> {
        let response = self
            .client
            .post(self.url("children")?)
            .bearer_auth(
                self.descriptor
                    .write_token
                    .as_ref()
                    .ok_or(SyncError::Peer)?,
            )
            .json(child)
            .send()
            .await
            .map_err(network_error)?;
        bounded_body(response, 4096).await?;
        Ok(())
    }
    pub fn new(descriptor: PeerDescriptor, allow_insecure_loopback: bool) -> Result<Self> {
        let base = reqwest::Url::parse(&descriptor.url).map_err(|_| SyncError::Peer)?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(SyncError::Peer);
        }
        let local = base
            .host_str()
            .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if base.scheme() != "https"
            && !(allow_insecure_loopback && local && base.scheme() == "http")
        {
            return Err(SyncError::Peer);
        }
        let key = VerifyingKey::from_bytes(
            &crate::record::hex(&descriptor.signing_public_key).map_err(|_| SyncError::Peer)?,
        )
        .map_err(|_| SyncError::Peer)?;
        if key.is_weak() {
            return Err(SyncError::Peer);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| SyncError::Peer)?;
        Ok(Self {
            base,
            key,
            descriptor,
            client,
        })
    }
    pub fn id(&self) -> PeerId {
        replica::peer_id(&self.key)
    }
    pub fn mailbox(&self) -> MailboxId {
        self.descriptor.mailbox_id
    }
    fn url(&self, path: &str) -> Result<reqwest::Url> {
        self.base
            .join(&format!("v1/mailboxes/{}/{path}", self.mailbox()))
            .map_err(|_| SyncError::Peer)
    }
    pub async fn inventory(&self, after: u64) -> Result<Inventory> {
        let token = self.descriptor.read_token.as_ref().ok_or(SyncError::Peer)?;
        let mut url = self.url("inventory")?;
        url.query_pairs_mut()
            .append_pair("after", &after.to_string())
            .append_pair("limit", "128");
        let response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(network_error)?;
        let bytes = bounded_body(response, 128 * 1024).await?;
        let page: Inventory = serde_json::from_slice(&bytes).map_err(|_| SyncError::Peer)?;
        crate::record::hex::<32>(&page.storage_generation).map_err(|_| SyncError::Peer)?;
        let mut prev = after;
        if page.entries.len() > 128 || page.head > crate::record::MAX_INTEGER {
            return Err(SyncError::Peer);
        }
        for item in &page.entries {
            if item.arrival_seq <= prev
                || item.arrival_seq > page.head
                || item.size_bytes == 0
                || item.size_bytes > crypto::MAX_CIPHERTEXT as u64
            {
                return Err(SyncError::Peer);
            }
            prev = item.arrival_seq;
        }
        Ok(page)
    }
    pub async fn get(&self, id: ObjectId, size: u64) -> Result<Vec<u8>> {
        if size == 0 || size > crypto::MAX_CIPHERTEXT as u64 {
            return Err(SyncError::Peer);
        }
        let response = self
            .client
            .get(self.url(&format!("objects/{id}"))?)
            .bearer_auth(self.descriptor.read_token.as_ref().ok_or(SyncError::Peer)?)
            .send()
            .await
            .map_err(network_error)?;
        let bytes = bounded_body(response, size as usize).await?;
        if bytes.len() as u64 != size || ObjectId::of_ciphertext(&bytes) != id {
            return Err(SyncError::Peer);
        }
        Ok(bytes)
    }
    pub(crate) async fn post(
        &self,
        id: ObjectId,
        bytes: Vec<u8>,
        hint: TransferHint,
    ) -> Result<VerifiedReceipt> {
        self.post_with_status(id, bytes, hint)
            .await
            .map(|(receipt, _)| receipt)
    }
    async fn post_with_status(
        &self,
        id: ObjectId,
        bytes: Vec<u8>,
        hint: TransferHint,
    ) -> Result<(VerifiedReceipt, u16)> {
        let size = bytes.len();
        let response = self
            .client
            .post(self.url(&format!("objects/{id}"))?)
            .bearer_auth(
                self.descriptor
                    .write_token
                    .as_ref()
                    .ok_or(SyncError::Peer)?,
            )
            .header("x-elo-transfer", hint.as_str())
            .body(bytes)
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status().as_u16();
        let receipt = bounded_body(response, crate::record::MAX_RECORD).await?;
        let verified = VerifiedReceipt::verify(&receipt, &self.key, self.mailbox(), id, size)
            .map_err(|_| SyncError::Transport(TransportFailure::InvalidReceiptResponse(status)))?;
        Ok((verified, status))
    }
}
async fn bounded_body(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(SyncError::Transport(TransportFailure::Http(
            response.status().as_u16(),
        )));
    }
    if response
        .content_length()
        .is_some_and(|n| n > maximum as u64)
    {
        return Err(SyncError::Peer);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
        if chunk.len() > maximum - bytes.len() {
            return Err(SyncError::Peer);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
#[derive(Default, Debug, Serialize)]
pub struct SyncReport {
    /// More durable inventory or admission work remains; this is not a total.
    pub more: bool,
    /// Newly admitted text records only; replay, history import and actions do not notify.
    pub received_messages: Vec<RecordId>,
    pub downloaded: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub stored: u64,
    pub held: u64,
    pub deferred: u64,
    pub waiting_for_proof: u64,
    pub quarantined: u64,
    pub retry: u64,
    pub generation_changes: u64,
    pub inventory_scans: u64,
    pub repaired: u64,
    pub repair_downloaded: u64,
    pub repair_deferred: u64,
    pub repair_pending: u64,
}
impl SyncReport {
    /// Inventory traversal alone does not require decrypting the whole UI view.
    pub fn changes_view(&self) -> bool {
        self.downloaded > 0
            || self.accepted > 0
            || self.rejected > 0
            || self.stored > 0
            || self.held > 0
            || self.waiting_for_proof > 0
            || self.quarantined > 0
            || self.generation_changes > 0
            || self.repaired > 0
            || self.repair_downloaded > 0
            || self.repair_pending > 0
    }
}
pub struct SyncClient<'a> {
    pub store: &'a ClientStore,
    pub identity: &'a age::x25519::Identity,
    pub credential: RecordId,
    pub authority: &'a dyn ChatAuthority,
    pub peers: &'a [Peer],
}
impl SyncClient<'_> {
    pub async fn once(&self, now: LocalTime) -> Result<SyncReport> {
        self.run(now, None, 0, false).await
    }

    /// Foreground passes share the durable sync algorithm, with a short network
    /// budget and rotating peer order. Local admission/commits are never cancelled.
    pub async fn foreground(&self, now: LocalTime, offset: usize) -> Result<SyncReport> {
        self.run(
            now,
            Some(tokio::time::Instant::now() + Duration::from_secs(6)),
            offset,
            false,
        )
        .await
    }

    /// A notification tap receives new arrivals before outbound work or full
    /// reconciliation. Admission and durable ciphertext/cursor commits are unchanged.
    pub async fn receive_foreground(&self, now: LocalTime, offset: usize) -> Result<SyncReport> {
        self.run(
            now,
            Some(tokio::time::Instant::now() + Duration::from_secs(6)),
            offset,
            true,
        )
        .await
    }

    async fn run(
        &self,
        now: LocalTime,
        deadline: Option<tokio::time::Instant>,
        offset: usize,
        receive_only: bool,
    ) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        // Reserve an upload opportunity even when an unreachable read peer uses
        // the download budget. An interrupted HTTP upload still takes the normal
        // durable retry path; it never abandons a claimed outbox attempt.
        if deadline.is_some() && !receive_only {
            self.upload_outbox(
                now,
                &mut report,
                Some(tokio::time::Instant::now() + Duration::from_secs(5)),
                8,
            )
            .await?;
        }
        // The demo context is a fixed, pre-approved fixture. T06 must update authority
        // before this pass; no network-provided config is silently trusted here.
        'peers: for peer in self
            .peers
            .iter()
            .cycle()
            .skip(offset % self.peers.len().max(1))
            .take(self.peers.len())
            .filter(|p| p.descriptor.read_token.is_some())
        {
            if exhausted(deadline) {
                report.more = true;
                break;
            }
            let mut cursor = self.store.cursor(peer.id(), peer.mailbox()).await?;
            let mut scan = self.store.scan_cursor(peer.id(), peer.mailbox()).await?;
            // Repeat complete ID scans, one bounded page per pass. This also finds
            // holes whose deletion did not change generation or the high-water mark.
            // Taps continue from the durable arrival cursor, without moving the
            // separate full-scan cursor or declaring unscanned copies missing.
            let mut after = if receive_only {
                cursor.as_ref().map_or(0, |c| c.arrival_seq)
            } else {
                scan.as_ref().map_or(0, |s| s.next_after())
            };
            let mut page = match network(deadline, peer.inventory(after)).await {
                Ok(page) => page,
                Err(_) => {
                    report.retry += 1;
                    continue;
                }
            };
            if cursor.as_ref().is_some_and(|c| {
                c.storage_generation != page.storage_generation || page.head < c.arrival_seq
            }) || scan
                .as_ref()
                .is_some_and(|s| s.generation != page.storage_generation || page.head < s.head)
                || self
                    .store
                    .inventory_reuses_sequence(peer.id(), peer.mailbox(), page.clone())
                    .await?
            {
                after = 0;
                page = match network(deadline, peer.inventory(after)).await {
                    Ok(page) => page,
                    Err(_) => {
                        report.retry += 1;
                        continue;
                    }
                };
                self.store
                    .reset_peer_cursor(peer.id(), peer.mailbox(), page.storage_generation.clone())
                    .await?;
                cursor = self.store.cursor(peer.id(), peer.mailbox()).await?;
                scan = self.store.scan_cursor(peer.id(), peer.mailbox()).await?;
                report.generation_changes += 1;
            }
            let active_scan = if receive_only {
                None
            } else {
                Some(
                    self.store
                        .begin_scan(
                            peer.id(),
                            peer.mailbox(),
                            scan,
                            page.storage_generation.clone(),
                            page.head,
                        )
                        .await?,
                )
            };
            // The head can contain gaps and lazy attachments, so do not expose
            // it as a total number of messages or a completion percentage.
            report.more |= page
                .entries
                .last()
                .is_some_and(|e| e.arrival_seq < page.head)
                && cursor.as_ref().is_none_or(|c| c.arrival_seq < page.head);
            for entry in &page.entries {
                if exhausted(deadline) {
                    report.more = true;
                    break 'peers;
                }
                if cursor.as_ref().is_some_and(|c| {
                    c.storage_generation == page.storage_generation
                        && entry.arrival_seq <= c.arrival_seq
                }) && self
                    .store
                    .inbox_entry_known(
                        peer.id(),
                        peer.mailbox(),
                        page.storage_generation.clone(),
                        entry.clone(),
                    )
                    .await?
                {
                    continue;
                }
                let bytes = if entry.transfer_hint == TransferHint::Lazy {
                    report.deferred += 1;
                    None
                } else if let Some(bytes) = self.store.get_object(entry.object_id).await? {
                    Some(bytes)
                } else {
                    match network(deadline, peer.get(entry.object_id, entry.size_bytes)).await {
                        Ok(bytes) => {
                            report.downloaded += 1;
                            Some(bytes)
                        }
                        Err(SyncError::Peer) => {
                            report.rejected += 1;
                            None
                        }
                        Err(_) => {
                            report.retry += 1;
                            continue 'peers;
                        }
                    }
                };
                self.store
                    .stage_inbox(
                        peer.id(),
                        peer.mailbox(),
                        page.storage_generation.clone(),
                        entry.clone(),
                        bytes,
                        now,
                    )
                    .await?;
            }
            if let Some(active_scan) = active_scan
                && self
                    .store
                    .finish_scan_page(peer.id(), peer.mailbox(), active_scan, page)
                    .await?
            {
                report.inventory_scans += 1;
            }
        }
        // Pending work survives a crash after the atomic ciphertext+cursor commit.
        let admission_deadline =
            deadline.map(|_| tokio::time::Instant::now() + Duration::from_millis(500));
        for (index, item) in self.store.pending_inbox(128).await?.into_iter().enumerate() {
            // Finish at least one record, and never interrupt verification or
            // its transaction. The remaining encrypted inbox is durable.
            if index > 0 && exhausted(admission_deadline) {
                report.more = true;
                break;
            }
            let bytes = self
                .store
                .get_object(item.object)
                .await?
                .ok_or(SyncError::Peer)?;
            let opened = crypto::open_object(&bytes, self.identity);
            let mut new_message = None;
            let decision = if let Ok(record) = opened {
                let known = self.store.previously_accepted(record.id()).await?;
                if !known && record.body()["kind"] == "chat.message" {
                    new_message = Some(record.id());
                }
                self.authority.admit(&record, self.credential, known).ok()
            } else {
                None
            };
            match decision {
                Some(ChatDecision::FileShared(verified)) => {
                    report.accepted += 1;
                    self.store.finish_file_share(item, *verified, now).await?;
                }
                Some(ChatDecision::Accepted(verified)) => {
                    report.accepted += 1;
                    self.store.finish_inbox(item, Some(*verified), now).await?;
                    if let Some(id) = new_message {
                        report.received_messages.push(id);
                    }
                }
                Some(ChatDecision::QuarantinedStale) => {
                    report.quarantined += 1;
                    self.store.defer_inbox(item, true).await?;
                }
                Some(ChatDecision::WaitingForProof | ChatDecision::Forked) => {
                    report.waiting_for_proof += 1;
                    self.store.defer_inbox(item, false).await?;
                }
                None => {
                    report.rejected += 1;
                    self.store.finish_inbox(item, None, now).await?;
                }
            }
        }
        report.more |= !self.store.pending_inbox(1).await?.is_empty();
        if deadline.is_none() && !receive_only {
            self.upload_outbox(now, &mut report, None, 128).await?;
        }
        if !receive_only {
            self.repair_copies(now, &mut report, deadline).await?;
        }
        report.repair_pending = self.store.missing_copies().await?;
        Ok(report)
    }

    async fn upload_outbox(
        &self,
        now: LocalTime,
        report: &mut SyncReport,
        deadline: Option<tokio::time::Instant>,
        limit: usize,
    ) -> Result<()> {
        for _ in 0..limit {
            if exhausted(deadline) {
                break;
            }
            let Some(attempt) = self.store.claim_next(now).await? else {
                break;
            };
            let bytes = self
                .store
                .get_object(attempt.object_id())
                .await?
                .ok_or(SyncError::Peer)?;
            let opened = crypto::open_object(&bytes, self.identity).ok();
            let valid = opened
                .as_ref()
                .and_then(|r| self.authority.verify_outgoing(r, self.credential).ok());
            let hint = if opened
                .as_ref()
                .is_some_and(|r| r.body()["kind"] == "file.body")
            {
                TransferHint::Lazy
            } else {
                TransferHint::Eager
            };
            if valid.is_none() {
                self.store.hold_record(attempt.record_id()).await?;
                report.held += 1;
                continue;
            }
            let peer = self.peers.iter().find(|p| {
                p.id() == attempt.target().peer_id && p.mailbox() == attempt.target().mailbox_id
            });
            let result = match peer {
                Some(p) => {
                    network_with_timeout(
                        deadline,
                        Duration::from_secs(5),
                        p.post_with_status(attempt.object_id(), bytes, hint),
                    )
                    .await
                }
                None => Err(SyncError::Peer),
            };
            match result {
                Ok((receipt, status)) => {
                    self.store
                        .confirm_stored_with_status(attempt, receipt, Some(status))
                        .await?;
                    report.stored += 1;
                }
                Err(error) => {
                    let mut jitter = [0u8; 8];
                    getrandom::fill(&mut jitter).map_err(|_| SyncError::Network)?;
                    let delay = retry_delay_ms(attempt.number() as u64, u64::from_le_bytes(jitter));
                    let next = now.as_millis().saturating_add(delay as i64);
                    self.store
                        .retry_with_diagnostics(
                            attempt,
                            LocalTime::from_millis(next as u64)?,
                            RetryReason::RemoteUnavailable,
                            Some(error.diagnostic()),
                        )
                        .await?;
                    report.retry += 1;
                }
            }
        }
        Ok(())
    }

    async fn repair_copies(
        &self,
        now: LocalTime,
        report: &mut SyncReport,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<()> {
        for peer in self
            .peers
            .iter()
            .filter(|p| p.descriptor.read_token.is_some() && p.descriptor.write_token.is_some())
        {
            let target = crate::store::DeliveryTarget {
                peer_id: peer.id(),
                mailbox_id: peer.mailbox(),
            };
            for _ in 0..128 {
                if exhausted(deadline) {
                    return Ok(());
                }
                let mut random = [0u8; 8];
                getrandom::fill(&mut random).map_err(|_| SyncError::Network)?;
                let Some(attempt) = self
                    .store
                    .claim_repair(target, now, u64::from_le_bytes(random))
                    .await?
                else {
                    break;
                };
                let mut bytes = self.store.get_object(attempt.object).await?;
                // Binary bodies are never fetched by background synchronization.
                // Already cached ciphertext can be restored to its original target.
                if bytes.is_none() && attempt.hint == TransferHint::Lazy {
                    report.repair_deferred += 1;
                    continue;
                }
                if bytes.is_none() {
                    for (source, size) in self.store.copy_sources(attempt.object).await? {
                        if source == target || (attempt.size != 0 && attempt.size != size) {
                            continue;
                        }
                        let Some(other) = self.peers.iter().find(|p| {
                            p.id() == source.peer_id
                                && p.mailbox() == source.mailbox_id
                                && p.descriptor.read_token.is_some()
                        }) else {
                            continue;
                        };
                        if let Ok(found) = network(deadline, other.get(attempt.object, size)).await
                        {
                            self.store
                                .cache_repair_object(attempt.object, found.clone(), now)
                                .await?;
                            report.repair_downloaded += 1;
                            bytes = Some(found);
                            break;
                        }
                    }
                }
                let Some(bytes) = bytes else {
                    report.retry += 1;
                    continue;
                };
                if attempt.size != 0 && attempt.size != bytes.len() as u64 {
                    report.retry += 1;
                    continue;
                }
                // This restores exact bytes to a mailbox already holding this ID.
                // It cannot create an outbox target, re-encrypt, admit a record or
                // release a never-sent message held by the authority layer.
                match network(deadline, peer.post(attempt.object, bytes, attempt.hint)).await {
                    Ok(receipt) if receipt.body().storage_generation == attempt.generation => {
                        self.store.confirm_repair(attempt, receipt).await?;
                        report.repaired += 1;
                    }
                    Err(error) => {
                        self.store
                            .audit_repair_failure(
                                attempt.object,
                                attempt.target,
                                attempt.number,
                                error.diagnostic(),
                            )
                            .await?;
                        report.retry += 1;
                    }
                    Ok(_) => {
                        self.store
                            .audit_repair_failure(
                                attempt.object,
                                attempt.target,
                                attempt.number,
                                TransportFailure::InvalidReceipt,
                            )
                            .await?;
                        report.retry += 1;
                    }
                }
            }
        }
        Ok(())
    }
}

fn exhausted(deadline: Option<tokio::time::Instant>) -> bool {
    deadline.is_some_and(|value| tokio::time::Instant::now() >= value)
}

async fn network<T>(
    deadline: Option<tokio::time::Instant>,
    request: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    network_with_timeout(deadline, Duration::from_secs(2), request).await
}

async fn network_with_timeout<T>(
    deadline: Option<tokio::time::Instant>,
    timeout: Duration,
    request: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if let Some(deadline) = deadline {
        tokio::time::timeout_at(deadline.min(tokio::time::Instant::now() + timeout), request)
            .await
            .map_err(|_| SyncError::Transport(TransportFailure::Timeout))?
    } else {
        request.await
    }
}
pub fn retry_delay_ms(attempt: u64, jitter: u64) -> u64 {
    let base = 1000u64.saturating_mul(1u64 << attempt.saturating_sub(1).min(6));
    base.saturating_add(jitter % 251).min(60_000)
}

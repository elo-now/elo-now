//! Unlock-bound snapshots for live hints. No ephemeral event enters durable history.
use super::*;
use crate::ids::MailboxId;
use crate::realtime::{ClientFrame, PublicationRequest, SubscriptionRequest};
use ed25519_dalek::SigningKey;
use std::sync::Arc;

pub const MAX_SCOPES: usize = 256;
pub const MAX_ENVELOPE: usize = 65_536;
const MAX_PLAINTEXT: usize = 16 * 1024;
const MAX_RECIPIENTS: usize = 256;

fn fits_envelope(record_bytes: usize, recipients: usize) -> bool {
    // Native X25519 stanzas fit in 128 bytes each. Reserve another KiB for
    // the age header, random extension stanza, nonce and final chunk tag.
    // The final encoded-size check remains authoritative after encryption.
    record_bytes <= MAX_PLAINTEXT
        && (1..=MAX_RECIPIENTS).contains(&recipients)
        && (record_bytes + recipients * 128 + 1024).div_ceil(3) * 4 <= MAX_ENVELOPE
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub space_context: String,
    pub space: SpaceId,
    pub stream: StreamId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    Typing {
        active: bool,
    },
    Presence {
        active: bool,
    },
    Upload {
        attachment_id: AttachmentId,
        name: String,
        size: u64,
        status: UploadStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        record: Option<RecordId>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadStatus {
    Uploading,
    Interrupted,
    Cancelled,
    Ready,
}

impl Payload {
    pub fn lifetime(&self) -> u64 {
        match self {
            Self::Typing { .. } => 8_000,
            Self::Presence { .. } => 60_000,
            Self::Upload {
                status: UploadStatus::Uploading,
                ..
            } => 30_000,
            Self::Upload { .. } => 60_000,
        }
    }
    fn validate(&self) -> Result<()> {
        if let Self::Upload {
            name,
            size,
            status,
            record,
            ..
        } = self
            && (name.is_empty()
                || name.len() > 255
                || name == "."
                || name == ".."
                || name
                    .chars()
                    .any(|c| record::unsafe_display_character(c) || c == '/' || c == '\\')
                || *size > crate::attachments::MAX_ATTACHMENT_FILE_SIZE
                || (*status == UploadStatus::Ready) != record.is_some())
        {
            return Err("Invalid live attachment state.".into());
        }
        Ok(())
    }
    fn capability(&self) -> Capability {
        match self {
            Self::Presence { .. } => Capability::Read,
            _ => Capability::Post,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEvent {
    v: u8,
    kind: String,
    context: String,
    space: SpaceId,
    stream: StreamId,
    config: RecordId,
    issuer_identity: IdentityId,
    issuer_credential: RecordId,
    created_at_ms: u64,
    expires_at_ms: u64,
    nonce: String,
    payload: Payload,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub space_context: String,
    pub space: SpaceId,
    pub stream: StreamId,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: String,
    pub payload: Payload,
    #[serde(skip)]
    config: RecordId,
}
impl Event {
    pub fn scope(&self) -> Scope {
        Scope {
            space_context: self.space_context.clone(),
            space: self.space,
            stream: self.stream,
        }
    }
    pub fn key(&self) -> String {
        let kind = match &self.payload {
            Payload::Typing { .. } => "typing".into(),
            Payload::Presence { .. } => "presence".into(),
            Payload::Upload { attachment_id, .. } => format!("upload/{attachment_id}"),
        };
        format!(
            "{}/{}/{}/{}/{}",
            self.space_context, self.space, self.stream, self.issuer_credential, kind
        )
    }
}

struct Context {
    identity: IdentityId,
    credential: RecordId,
    signing: SigningKey,
    signer: crate::sync::access::Signer,
    age: crate::crypto::DecryptionKeys,
    authorities: Authorities,
    blocked: blocking::Blocked,
    membership: membership::MembershipSnapshot,
    peers: Vec<PeerDescriptor>,
    allow_loopback: bool,
}
impl Context {
    fn new(client: &ClientApp) -> Self {
        Self {
            identity: client.identity_id(),
            credential: client.session.credential().id(),
            signing: client.session.signing_key().clone(),
            signer: crate::sync::access::Signer::new(&client.session),
            age: client.session.age_identity().clone(),
            authorities: client.authorities.clone(),
            blocked: client.blocked.clone(),
            membership: client.membership_snapshot(),
            peers: client.session.peers().to_vec(),
            allow_loopback: client.allow_loopback,
        }
    }
    fn authority(&self, scope: &Scope) -> Result<&Authority> {
        let a = self
            .authorities
            .0
            .iter()
            .find(|a| a.space() == scope.space && a.stream() == scope.stream)
            .ok_or("Unknown live conversation.")?;
        if a.is_forked() || !self.authorities.space_ready(a) {
            return Err("Chat permissions need to be refreshed.".into());
        }
        let head = a
            .head_id()
            .ok_or("Chat permissions need to be refreshed.")?;
        let (_, credentials) = a.expected_recipients(head, self.credential)?;
        if !credentials.contains(&self.credential) || !a.has(head, self.identity, Capability::Read)
        {
            return Err("Live conversation access denied.".into());
        }
        Ok(a)
    }
}

#[cfg(test)]
mod tests;

/// Contains signing/decryption keys; only native code may hold it while unlocked.
pub struct Snapshot {
    pub identity: IdentityId,
    pub active_space: Option<String>,
    contexts: BTreeMap<String, Context>,
}

/// Transport credentials are deliberately not serializable to the renderer.
#[derive(Clone)]
pub struct Target {
    pub id: String,
    pub space_context: String,
    pub url: String,
    pub credential: RecordId,
    descriptor: PeerDescriptor,
    signer: crate::sync::access::Signer,
}
impl Target {
    pub fn signature(&self) -> String {
        // Detect key/token rotations without exposing credentials in logs or UI.
        use sha2::{Digest, Sha256};
        record::encode_hex(&Sha256::digest(
            serde_json::to_vec(&self.descriptor).unwrap_or_default(),
        ))
    }
    pub fn subscribe(&self) -> Result<ClientFrame> {
        let base = reqwest::Url::parse(&self.descriptor.url)?;
        let socket = reqwest::Url::parse(&self.url)?;
        let request = SubscriptionRequest {
            id: self.id.clone(),
            replica: base.path().into(),
            mailbox: self.descriptor.mailbox_id,
            read_token: self
                .descriptor
                .read_token
                .clone()
                .ok_or("Replica read access unavailable.")?,
        };
        let key = root_key(&self.descriptor.signing_public_key)?;
        let body = serde_json::to_vec(&request)?;
        let proof = self
            .signer
            .proof(&crate::sync::access::RequestContext {
                origin: &base.origin().ascii_serialization(),
                replica: &key,
                method: "SUBSCRIBE",
                path: socket.path(),
                body: &body,
                transfer: "",
                retention: "",
            })
            .map_err(|_| "Could not authorize live synchronization.")?;
        Ok(ClientFrame::Subscribe { request, proof })
    }
    pub fn mailbox(&self) -> MailboxId {
        self.descriptor.mailbox_id
    }
}

impl ClientApp {
    pub fn realtime_snapshot(&self) -> Arc<Snapshot> {
        let clients = if let Some(spaces) = &self.spaces {
            spaces.history_clients(self).1
        } else {
            vec![(String::new(), self)]
        };
        Arc::new(Snapshot {
            identity: self.identity_id(),
            active_space: self.active_space_id().map(str::to_owned),
            contexts: clients
                .into_iter()
                .map(|(id, client)| (id, Context::new(client)))
                .collect(),
        })
    }
}

impl Snapshot {
    /// Prioritize the visible chat in the existing bounded status-sync batch.
    pub fn prioritize_membership_focus(&self, focus: Option<&Scope>) {
        for (context, client) in &self.contexts {
            let scope = focus
                .filter(|scope| &scope.space_context == context && client.authority(scope).is_ok())
                .map(|scope| (scope.space, scope.stream));
            client.membership.prioritize(scope);
        }
    }

    pub fn targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();
        for (context, client) in &self.contexts {
            for descriptor in &client.peers {
                if descriptor.read_token.is_none() {
                    continue;
                }
                let Ok((mut url, key)) =
                    Peer::validated_endpoint(descriptor, client.allow_loopback)
                else {
                    continue;
                };
                // A mailbox ID is local to its Replica. Preserve the full base
                // path and pinned server key before mapping to a shared socket.
                let Ok(namespace) = serde_json::to_vec(&(
                    context,
                    url.as_str(),
                    key.as_bytes(),
                    descriptor.mailbox_id,
                )) else {
                    continue;
                };
                let id = crate::ids::ObjectId::of_ciphertext(&namespace).to_string();
                let path = if url.path() == "/" {
                    crate::realtime::PATH
                } else {
                    crate::realtime::HOST_PATH
                };
                let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
                if url.set_scheme(scheme).is_err() {
                    continue;
                }
                url.set_path(path);
                targets.push(Target {
                    id,
                    space_context: context.clone(),
                    url: url.to_string(),
                    credential: client.credential,
                    descriptor: descriptor.clone(),
                    signer: client.signer.clone(),
                });
            }
        }
        targets
    }
    pub fn permits(&self, scope: &Scope) -> bool {
        self.contexts
            .get(&scope.space_context)
            .is_some_and(|client| client.authority(scope).is_ok())
    }
    /// Recheck a previously authenticated hint after membership or block changes.
    pub fn allows_event(&self, event: &Event) -> bool {
        let Some(client) = self.contexts.get(&event.space_context) else {
            return false;
        };
        if client.blocked.contains(event.issuer_identity) {
            return false;
        }
        let Ok(authority) = client.authority(&event.scope()) else {
            return false;
        };
        authority.head_id() == Some(event.config)
            && authority.has(
                event.config,
                event.issuer_identity,
                event.payload.capability(),
            )
            && authority
                .credential(event.issuer_credential)
                .is_ok_and(|issuer| issuer.identity() == event.issuer_identity)
            && authority
                .expected_recipients(event.config, event.issuer_credential)
                .is_ok()
    }
    pub fn seal(
        &self,
        scope: &Scope,
        payload: Payload,
        time: u64,
    ) -> Result<(Vec<IdentityId>, String)> {
        payload.validate()?;
        let client = self
            .contexts
            .get(&scope.space_context)
            .ok_or("Unknown live Space.")?;
        let authority = client.authority(scope)?;
        if !client.membership.allows(scope.space, scope.stream) {
            return Err("Chat permissions need to be refreshed.".into());
        }
        let config = authority
            .head_id()
            .ok_or("Chat permissions need to be refreshed.")?;
        if !authority.has(config, client.identity, payload.capability()) {
            return Err("Live conversation access denied.".into());
        }
        let (audience, credentials) = authority.expected_recipients(config, client.credential)?;
        let audience: Vec<_> = audience
            .into_iter()
            .filter(|id| !client.blocked.contains(*id))
            .collect();
        if audience.is_empty() || audience.len() > MAX_RECIPIENTS {
            return Err("Live conversation is too large.".into());
        }
        let mut keys = BTreeMap::new();
        for credential in credentials {
            let credential = authority.credential(credential)?;
            if audience.contains(&credential.identity()) {
                let key = credential.recipient();
                keys.insert(key.to_string(), key);
                if keys.len() > MAX_RECIPIENTS {
                    return Err("Live conversation is too large.".into());
                }
            }
        }
        let body = SignedEvent {
            v: 1,
            kind: "chat.ephemeral".into(),
            context: scope.space_context.clone(),
            space: scope.space,
            stream: scope.stream,
            config,
            issuer_identity: client.identity,
            issuer_credential: client.credential,
            created_at_ms: time,
            expires_at_ms: time.saturating_add(payload.lifetime()),
            nonce: record::random_hex::<16>()?,
            payload,
        };
        let body = serde_json::to_vec(&body)?;
        if !fits_envelope(body.len().saturating_add(72), keys.len()) {
            return Err("Live conversation is too large.".into());
        }
        let signed = SignedRecord::sign_bounded(&body, &client.signing, MAX_PLAINTEXT)?;
        let cipher = crypto::seal_record(&signed, &keys.into_values().collect::<Vec<_>>())?;
        let envelope = STANDARD.encode(cipher);
        if envelope.len() > MAX_ENVELOPE {
            return Err("Live conversation is too large.".into());
        }
        Ok((audience, envelope))
    }
    pub fn publication(
        &self,
        target: &Target,
        scope: &Scope,
        payload: Payload,
        time: u64,
    ) -> Result<ClientFrame> {
        if target.space_context != scope.space_context {
            return Err("Live Space mismatch.".into());
        }
        let (recipients, envelope) = self.seal(scope, payload, time)?;
        Ok(ClientFrame::Publish {
            request: PublicationRequest {
                subscription: target.id.clone(),
                recipients,
                envelope,
            },
        })
    }
    pub fn open(
        &self,
        context: &str,
        envelope: &str,
        sender: IdentityId,
        credential: RecordId,
        time: u64,
    ) -> Result<Event> {
        if envelope.len() > MAX_ENVELOPE {
            return Err("Invalid live event.".into());
        }
        let client = self.contexts.get(context).ok_or("Unknown live Space.")?;
        if client.blocked.contains(sender) {
            return Err("Live sender blocked.".into());
        }
        let signed =
            crypto::open_record_bounded(&STANDARD.decode(envelope)?, &client.age, MAX_PLAINTEXT)?;
        let body: SignedEvent = signed.decode()?;
        body.payload.validate()?;
        record::hex::<16>(&body.nonce)?;
        if body.v != 1
            || body.kind != "chat.ephemeral"
            || body.context != context
            || body.issuer_identity != sender
            || body.issuer_credential != credential
            || body.created_at_ms > time.saturating_add(2_000)
            || body.expires_at_ms <= time
            || body.expires_at_ms <= body.created_at_ms
            || body.expires_at_ms - body.created_at_ms > body.payload.lifetime()
        {
            return Err("Invalid live event.".into());
        }
        let scope = Scope {
            space_context: context.into(),
            space: body.space,
            stream: body.stream,
        };
        let authority = client.authority(&scope)?;
        if Some(body.config) != authority.head_id()
            || !authority.has(body.config, sender, body.payload.capability())
        {
            return Err("Live conversation access denied.".into());
        }
        let issuer = authority.credential(credential)?;
        if issuer.identity() != sender {
            return Err("Live sender mismatch.".into());
        }
        authority.expected_recipients(body.config, credential)?;
        signed.verify_signature(issuer.key())?;
        Ok(Event {
            space_context: context.into(),
            space: body.space,
            stream: body.stream,
            issuer_identity: sender,
            issuer_credential: credential,
            created_at_ms: body.created_at_ms,
            expires_at_ms: body.expires_at_ms,
            nonce: body.nonce,
            payload: body.payload,
            config: body.config,
        })
    }
}

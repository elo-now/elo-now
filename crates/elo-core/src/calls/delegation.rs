//! Short-lived, scope-bound call keys. These cannot decrypt message history or
//! authorize another protocol. The parent device remains subject to live admission.
use super::*;
use age::secrecy::ExposeSecret;
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroize;

pub const MAX_DELEGATION_TTL: u64 = 24 * 60 * 60;
const MAX_CERTIFICATE: usize = 8192;
const MAX_SECRET: usize = 16 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub v: u8,
    pub kind: String,
    pub audience: String,
    pub hosting_space_id: SpaceId,
    pub scope: CallScope,
    pub config_id: RecordId,
    pub issuer_credential: RecordId,
    pub signing_public_key: String,
    pub age_recipient: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub struct VerifiedDelegation {
    pub body: Delegation,
    pub certificate: SignedRecord,
    key: VerifyingKey,
    recipient: age::x25519::Recipient,
}
impl VerifiedDelegation {
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }
    pub fn recipient(&self) -> age::x25519::Recipient {
        self.recipient.clone()
    }
}

/// This check establishes device authorship only. The server must independently
/// verify the current authority and hosting admission before accepting a command.
pub fn verify_authorship(
    credential: &crate::identity::VerifiedCredential,
    certificate: &SignedRecord,
    audience: &str,
    now: u64,
) -> Result<VerifiedDelegation> {
    if certificate.bytes().len() > MAX_CERTIFICATE {
        return Err(RecordError::Framing);
    }
    let body: Delegation = certificate.decode()?;
    if body.v != 1
        || body.kind != "call.delegation"
        || body.audience != audience
        || body.issuer_credential != credential.id()
        || body.issued_at > now.saturating_add(15)
        || body.expires_at <= now
        || body.expires_at <= body.issued_at
        || body.expires_at > body.issued_at.saturating_add(MAX_DELEGATION_TTL)
    {
        return Err(RecordError::Authority);
    }
    certificate.verify_signature(credential.key())?;
    let key = VerifyingKey::from_bytes(&record::hex::<32>(&body.signing_public_key)?)
        .map_err(|_| RecordError::Signature)?;
    let recipient = body.age_recipient.parse().map_err(|_| RecordError::Json)?;
    Ok(VerifiedDelegation {
        body,
        certificate: certificate.clone(),
        key,
        recipient,
    })
}

pub fn verify(
    authority: &Authority,
    certificate: &SignedRecord,
    hosting_space_id: SpaceId,
    audience: &str,
    now: u64,
) -> Result<VerifiedDelegation> {
    let body: Delegation = certificate.decode()?;
    require_member(authority, body.issuer_credential)?;
    let verified = verify_authorship(
        authority.credential(body.issuer_credential)?,
        certificate,
        audience,
        now,
    )?;
    if verified.body.hosting_space_id != hosting_space_id
        || verified.body.scope.space_id != authority.space()
        || verified.body.scope.stream_id != authority.stream()
        || Some(verified.body.config_id) != authority.head_id()
    {
        return Err(RecordError::Authority);
    }
    Ok(verified)
}

pub fn decode_certificate(encoded: &str) -> Result<SignedRecord> {
    if encoded.len() > MAX_CERTIFICATE * 2 {
        return Err(RecordError::Framing);
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| RecordError::Json)?;
    if bytes.len() > MAX_CERTIFICATE {
        return Err(RecordError::Framing);
    }
    SignedRecord::parse(&bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secret {
    v: u8,
    certificate: String,
    signing_key: String,
    age_identity: String,
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.signing_key.zeroize();
        self.age_identity.zeroize();
    }
}

/// Rust-only bundle for protected native storage. Its deliberate serialization
/// contains limited call keys, never profile keys; it must not enter WebView IPC.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallDelegateBinding {
    pub identity: IdentityId,
    pub credential: RecordId,
    pub space_context: String,
    pub name: String,
    pub audience: String,
    pub push_endpoint: Option<String>,
    pub hosting_space_id: SpaceId,
    pub scope: CallScope,
    pub config_id: RecordId,
    pub proof: crate::authority::CallAuthorityProof,
    pub delegate: Vec<u8>,
}
impl Drop for CallDelegateBinding {
    fn drop(&mut self) {
        self.delegate.zeroize();
    }
}

/// Only export() deliberately exposes the limited keys for protected native
/// storage. No Debug implementation can accidentally print them.
pub struct CallDelegate {
    signing: SigningKey,
    age: age::x25519::Identity,
    certificate: SignedRecord,
    body: Delegation,
}
impl CallDelegate {
    pub fn create(
        authority: &Authority,
        session: &Session,
        hosting_space_id: SpaceId,
        audience: &str,
        now: u64,
    ) -> Result<Self> {
        require_member(authority, session.credential().id())?;
        let url = reqwest::Url::parse(audience).map_err(|_| RecordError::Authority)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || audience.len() > 2048
        {
            return Err(RecordError::Authority);
        }
        let signing = crate::identity::generate_signing_key()?;
        let age = age::x25519::Identity::generate();
        let body = Delegation {
            v: 1,
            kind: "call.delegation".into(),
            audience: audience.into(),
            hosting_space_id,
            scope: CallScope {
                space_id: authority.space(),
                stream_id: authority.stream(),
            },
            config_id: authority.head_id().ok_or(RecordError::Authority)?,
            issuer_credential: session.credential().id(),
            signing_public_key: record::encode_hex(signing.verifying_key().as_bytes()),
            age_recipient: age.to_public().to_string(),
            issued_at: now,
            expires_at: now.saturating_add(MAX_DELEGATION_TTL),
        };
        let certificate = SignedRecord::sign(
            &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
            session.signing_key(),
        )?;
        Ok(Self {
            signing,
            age,
            certificate,
            body,
        })
    }
    pub fn certificate(&self) -> &SignedRecord {
        &self.certificate
    }
    pub fn body(&self) -> &Delegation {
        &self.body
    }
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>> {
        let secret = Secret {
            v: 1,
            certificate: STANDARD.encode(self.certificate.bytes()),
            signing_key: STANDARD.encode(self.signing.to_bytes()),
            age_identity: self.age.to_string().expose_secret().to_owned(),
        };
        serde_json::to_vec(&secret)
            .map(Zeroizing::new)
            .map_err(|_| RecordError::Json)
    }
    pub fn import(
        bytes: &[u8],
        authority: &Authority,
        hosting_space_id: SpaceId,
        audience: &str,
        now: u64,
    ) -> Result<Self> {
        if bytes.len() > MAX_SECRET {
            return Err(RecordError::Framing);
        }
        let secret: Secret = serde_json::from_slice(bytes).map_err(|_| RecordError::Json)?;
        if secret.v != 1 {
            return Err(RecordError::Unsupported);
        }
        let certificate = decode_certificate(&secret.certificate)?;
        let verified = verify(authority, &certificate, hosting_space_id, audience, now)?;
        let seed = Zeroizing::new(
            STANDARD
                .decode(&secret.signing_key)
                .map_err(|_| RecordError::Json)?,
        );
        let signing = SigningKey::from_bytes(
            seed.as_slice()
                .try_into()
                .map_err(|_| RecordError::Framing)?,
        );
        let age: age::x25519::Identity =
            secret.age_identity.parse().map_err(|_| RecordError::Json)?;
        if signing.verifying_key() != *verified.key() || age.to_public() != verified.recipient() {
            return Err(RecordError::Authority);
        }
        Ok(Self {
            signing,
            age,
            certificate,
            body: verified.body,
        })
    }
    pub fn sign_command(
        &self,
        authority: &Authority,
        operation: Operation,
        now: u64,
    ) -> Result<SignedRecord> {
        verify(
            authority,
            &self.certificate,
            self.body.hosting_space_id,
            &self.body.audience,
            now,
        )?;
        if matches!(operation, Operation::Start { .. }) {
            return Err(RecordError::Authority);
        }
        operation.validate()?;
        let command = Command {
            v: 1,
            kind: "call.command".into(),
            audience: self.body.audience.clone(),
            hosting_space_id: self.body.hosting_space_id,
            scope: self.body.scope,
            config_id: self.body.config_id,
            credential_id: self.body.issuer_credential,
            nonce: record::random_hex::<16>()?,
            issued_at: now,
            expires_at: now.saturating_add(COMMAND_TTL).min(self.body.expires_at),
            operation,
        };
        SignedRecord::sign(
            &serde_json::to_vec(&command).map_err(|_| RecordError::Json)?,
            &self.signing,
        )
    }
}

pub fn verify_command_authorship(
    credential: &crate::identity::VerifiedCredential,
    command: &SignedRecord,
    certificate: &SignedRecord,
    audience: &str,
    now: u64,
) -> Result<Command> {
    let verified = verify_authorship(credential, certificate, audience, now)?;
    let body: Command = command.decode()?;
    if body.v != 1
        || body.kind != "call.command"
        || body.audience != audience
        || body.credential_id != verified.body.issuer_credential
        || body.hosting_space_id != verified.body.hosting_space_id
        || body.scope != verified.body.scope
        || body.config_id != verified.body.config_id
        || body.expires_at > verified.body.expires_at
        || matches!(body.operation, Operation::Start { .. })
    {
        return Err(RecordError::Authority);
    }
    record::hex::<16>(&body.nonce)?;
    check_time(body.issued_at, body.expires_at, now)?;
    body.operation.validate()?;
    command.verify_signature(verified.key())?;
    Ok(body)
}

pub fn verify_command(
    authority: &Authority,
    command: &SignedRecord,
    certificate: &SignedRecord,
    audience: &str,
    now: u64,
) -> Result<Command> {
    let unverified: Command = command.decode()?;
    let verified = verify(
        authority,
        certificate,
        unverified.hosting_space_id,
        audience,
        now,
    )?;
    let command = verify_command_authorship(
        authority.credential(verified.body.issuer_credential)?,
        command,
        certificate,
        audience,
        now,
    )?;
    if let Operation::Signal { to, .. } = command.operation {
        require_member(authority, to)?;
    }
    Ok(command)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignalEnvelope {
    v: u8,
    kind: String,
    audience: String,
    hosting_space_id: SpaceId,
    sender_delegation: Option<String>,
    recipient_delegation: Option<RecordId>,
    signal: Signal,
}

pub enum SignalKeys<'a> {
    Device(&'a Session),
    Delegate(&'a CallDelegate),
}
impl SignalKeys<'_> {
    fn credential(&self) -> RecordId {
        match self {
            Self::Device(s) => s.credential().id(),
            Self::Delegate(s) => s.body.issuer_credential,
        }
    }
    fn signing(&self) -> &SigningKey {
        match self {
            Self::Device(s) => s.signing_key(),
            Self::Delegate(s) => &s.signing,
        }
    }
    fn age(&self) -> &dyn crate::crypto::DecryptionIdentity {
        match self {
            Self::Device(s) => s.age_identity(),
            Self::Delegate(s) => &s.age,
        }
    }
    fn certificate(&self) -> Option<&SignedRecord> {
        match self {
            Self::Device(_) => None,
            Self::Delegate(s) => Some(&s.certificate),
        }
    }
}

#[derive(Clone, Copy)]
pub struct SignalContext<'a> {
    pub audience: &'a str,
    pub hosting_space_id: SpaceId,
    pub call_id: &'a str,
    pub epoch: u64,
}

pub fn seal_signal(
    authority: &Authority,
    sender: SignalKeys<'_>,
    context: SignalContext<'_>,
    to: RecordId,
    recipient_delegation: Option<&SignedRecord>,
    payload: SignalPayload,
    now: u64,
) -> Result<String> {
    require_member(authority, sender.credential())?;
    require_member(authority, to)?;
    record::hex::<16>(context.call_id)?;
    if context.epoch == 0 {
        return Err(RecordError::Authority);
    }
    payload.validate()?;
    let mut expires_at = now.saturating_add(COMMAND_TTL);
    if let Some(certificate) = sender.certificate() {
        let verified = verify(
            authority,
            certificate,
            context.hosting_space_id,
            context.audience,
            now,
        )?;
        if verified.body.issuer_credential != sender.credential() {
            return Err(RecordError::Authority);
        }
        expires_at = expires_at.min(verified.body.expires_at);
    }
    let recipient = if let Some(certificate) = recipient_delegation {
        let verified = verify(
            authority,
            certificate,
            context.hosting_space_id,
            context.audience,
            now,
        )?;
        if verified.body.issuer_credential != to {
            return Err(RecordError::Authority);
        }
        expires_at = expires_at.min(verified.body.expires_at);
        verified.recipient()
    } else {
        authority.credential(to)?.recipient()
    };
    let envelope = SignalEnvelope {
        v: 1,
        kind: "call.delegated_signal".into(),
        audience: context.audience.into(),
        hosting_space_id: context.hosting_space_id,
        sender_delegation: sender
            .certificate()
            .map(|certificate| STANDARD.encode(certificate.bytes())),
        recipient_delegation: recipient_delegation.map(SignedRecord::id),
        signal: Signal {
            v: 1,
            kind: "call.signal".into(),
            scope: CallScope {
                space_id: authority.space(),
                stream_id: authority.stream(),
            },
            config_id: authority.head_id().ok_or(RecordError::Authority)?,
            call_id: context.call_id.into(),
            epoch: context.epoch,
            from: sender.credential(),
            to,
            nonce: record::random_hex::<16>()?,
            issued_at: now,
            expires_at,
            payload,
        },
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| RecordError::Json)?);
    if bytes.len() > MAX_SIGNAL_BYTES {
        return Err(RecordError::Framing);
    }
    let signed = SignedRecord::sign(&bytes, sender.signing())?;
    crate::crypto::seal_bytes(signed.bytes(), &[recipient], MAX_SIGNAL_BYTES)
        .map(|cipher| STANDARD.encode(cipher))
        .map_err(|_| RecordError::Authority)
}

/// The controller still checks active sender membership, epoch and nonce replay.
/// The context must come from the locally trusted hosting and current session.
pub fn open_signal(
    authority: &Authority,
    recipient: SignalKeys<'_>,
    context: SignalContext<'_>,
    ciphertext: &str,
    expected_sender_delegation: Option<&SignedRecord>,
    now: u64,
) -> Result<Signal> {
    require_member(authority, recipient.credential())?;
    if ciphertext.len() > MAX_SIGNAL_BYTES * 2 {
        return Err(RecordError::Framing);
    }
    if let Some(certificate) = recipient.certificate() {
        verify(
            authority,
            certificate,
            context.hosting_space_id,
            context.audience,
            now,
        )?;
    }
    let cipher = STANDARD.decode(ciphertext).map_err(|_| RecordError::Json)?;
    let bytes = Zeroizing::new(
        crate::crypto::open_bytes(&cipher, recipient.age(), MAX_SIGNAL_BYTES)
            .map_err(|_| RecordError::Authority)?,
    );
    let signed = SignedRecord::parse(&bytes)?;
    let envelope: SignalEnvelope = signed.decode()?;
    if envelope.v != 1
        || envelope.kind != "call.delegated_signal"
        || envelope.audience != context.audience
        || envelope.hosting_space_id != context.hosting_space_id
        || envelope.recipient_delegation != recipient.certificate().map(SignedRecord::id)
    {
        return Err(RecordError::Authority);
    }
    let signal = envelope.signal;
    if signal.v != 1
        || signal.kind != "call.signal"
        || signal.call_id != context.call_id
        || context.epoch == 0
        || signal.epoch != context.epoch
        || signal.scope.space_id != authority.space()
        || signal.scope.stream_id != authority.stream()
        || Some(signal.config_id) != authority.head_id()
        || signal.to != recipient.credential()
    {
        return Err(RecordError::Authority);
    }
    require_member(authority, signal.from)?;
    if let Some(encoded) = envelope.sender_delegation {
        let certificate = decode_certificate(&encoded)?;
        if expected_sender_delegation.map(SignedRecord::id) != Some(certificate.id()) {
            return Err(RecordError::Authority);
        }
        let verified = verify(
            authority,
            &certificate,
            context.hosting_space_id,
            context.audience,
            now,
        )?;
        if verified.body.issuer_credential != signal.from
            || signal.expires_at > verified.body.expires_at
        {
            return Err(RecordError::Authority);
        }
        signed.verify_signature(verified.key())?;
    } else {
        if expected_sender_delegation.is_some() {
            return Err(RecordError::Authority);
        }
        signed.verify_signature(authority.credential(signal.from)?.key())?;
    }
    record::hex::<16>(&signal.nonce)?;
    check_time(signal.issued_at, signal.expires_at, now)?;
    signal.payload.validate()?;
    Ok(signal)
}

//! Ephemeral, signed call control and recipient-encrypted signalling.
//! No audio/video frames, passwords or media keys enter call-control records.
use crate::{
    authority::{Authority, Capability},
    ids::{IdentityId, RecordId, SpaceId, StreamId},
    record::{self, RecordError, Result, SignedRecord},
    vault::Session,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const COMMAND_TTL: u64 = 60;
pub mod wake;
pub const MAX_SIGNAL_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct CallScope {
    pub space_id: SpaceId,
    pub stream_id: StreamId,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Direct,
    Group,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InitialMedia {
    Audio,
    Video,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MediaState {
    pub audio_muted: bool,
    pub video_published: bool,
    pub screen_published: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Subscribe,
    Start {
        kind: CallKind,
        initial_media: InitialMedia,
    },
    Join {
        call_id: String,
    },
    Decline {
        call_id: String,
    },
    Leave {
        call_id: String,
    },
    Heartbeat {
        call_id: String,
    },
    ConnectMedia {
        call_id: String,
    },
    Media {
        call_id: String,
        state: MediaState,
    },
    Signal {
        call_id: String,
        to: RecordId,
        ciphertext: String,
    },
}

impl Operation {
    pub fn call_id(&self) -> Option<&str> {
        match self {
            Self::Subscribe | Self::Start { .. } => None,
            Self::Join { call_id }
            | Self::Decline { call_id }
            | Self::Leave { call_id }
            | Self::Heartbeat { call_id }
            | Self::ConnectMedia { call_id }
            | Self::Media { call_id, .. }
            | Self::Signal { call_id, .. } => Some(call_id),
        }
    }
    fn validate(&self) -> Result<()> {
        if let Some(id) = self.call_id() {
            record::hex::<16>(id)?;
        }
        if let Self::Signal { ciphertext, .. } = self {
            if ciphertext.len() > MAX_SIGNAL_BYTES * 2 {
                return Err(RecordError::Framing);
            }
            let bytes = STANDARD.decode(ciphertext).map_err(|_| RecordError::Json)?;
            if bytes.is_empty() || bytes.len() > MAX_SIGNAL_BYTES + 4096 {
                return Err(RecordError::Framing);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub v: u8,
    pub kind: String,
    pub audience: String,
    pub hosting_space_id: SpaceId,
    pub scope: CallScope,
    pub config_id: RecordId,
    pub credential_id: RecordId,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub operation: Operation,
}

fn check_time(issued: u64, expires: u64, now: u64) -> Result<()> {
    if issued > now.saturating_add(15)
        || expires <= now
        || expires <= issued
        || expires > issued.saturating_add(COMMAND_TTL)
    {
        return Err(RecordError::Authority);
    }
    Ok(())
}

pub fn require_member(authority: &Authority, credential: RecordId) -> Result<IdentityId> {
    if authority.is_forked() {
        return Err(RecordError::Authority);
    }
    let head = authority.head()?;
    let device = authority.credential(credential)?;
    if !head.members.iter().any(|member| {
        member.identity_id == device.identity()
            && member.credential_ids.contains(&credential)
            && member.capabilities.contains(&Capability::Post)
            && member.capabilities.contains(&Capability::Read)
    }) {
        return Err(RecordError::Authority);
    }
    Ok(device.identity())
}

pub fn sign_command(
    authority: &Authority,
    session: &Session,
    hosting_space_id: SpaceId,
    audience: &str,
    operation: Operation,
    now: u64,
) -> Result<SignedRecord> {
    require_member(authority, session.credential().id())?;
    operation.validate()?;
    if audience.is_empty() || audience.len() > 2048 || audience.chars().any(char::is_control) {
        return Err(RecordError::Authority);
    }
    let command = Command {
        v: 1,
        kind: "call.command".into(),
        audience: audience.into(),
        hosting_space_id,
        scope: CallScope {
            space_id: authority.space(),
            stream_id: authority.stream(),
        },
        config_id: authority.head_id().ok_or(RecordError::Authority)?,
        credential_id: session.credential().id(),
        nonce: record::random_hex::<16>()?,
        issued_at: now,
        expires_at: now.saturating_add(COMMAND_TTL),
        operation,
    };
    SignedRecord::sign(
        &serde_json::to_vec(&command).map_err(|_| RecordError::Json)?,
        session.signing_key(),
    )
}

pub fn verify_command(
    authority: &Authority,
    signed: &SignedRecord,
    audience: &str,
    now: u64,
) -> Result<Command> {
    let command: Command = signed.decode()?;
    if command.v != 1
        || command.kind != "call.command"
        || command.audience != audience
        || command.scope.space_id != authority.space()
        || command.scope.stream_id != authority.stream()
        || Some(command.config_id) != authority.head_id()
    {
        return Err(RecordError::Authority);
    }
    record::hex::<16>(&command.nonce)?;
    check_time(command.issued_at, command.expires_at, now)?;
    require_member(authority, command.credential_id)?;
    signed.verify_signature(authority.credential(command.credential_id)?.key())?;
    command.operation.validate()?;
    if let Operation::Signal { to, .. } = command.operation {
        require_member(authority, to)?;
    }
    Ok(command)
}

// Intentionally no Debug: these fields can contain media key material or SDP.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignalPayload {
    RequestOffer,
    MediaKey {
        epoch: u64,
        key: String,
    },
    Offer {
        sdp: String,
    },
    Answer {
        sdp: String,
    },
    Ice {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
    RequestKey {
        epoch: u64,
    },
}

impl SignalPayload {
    fn validate(&self) -> Result<()> {
        match self {
            Self::MediaKey { epoch, key } => {
                record::hex::<32>(key)?;
                if *epoch == 0 {
                    return Err(RecordError::Json);
                }
            }
            Self::RequestKey { epoch } if *epoch == 0 => return Err(RecordError::Json),
            Self::Offer { sdp } | Self::Answer { sdp }
                if sdp.is_empty() || sdp.len() > 48 * 1024 =>
            {
                return Err(RecordError::Framing);
            }
            Self::Ice {
                candidate, sdp_mid, ..
            } if candidate.len() > 4096
                || sdp_mid.as_ref().is_some_and(|value| value.len() > 256) =>
            {
                return Err(RecordError::Framing);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    pub v: u8,
    pub kind: String,
    pub scope: CallScope,
    pub config_id: RecordId,
    pub call_id: String,
    pub from: RecordId,
    pub to: RecordId,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub payload: SignalPayload,
}

pub fn seal_signal(
    authority: &Authority,
    session: &Session,
    call_id: &str,
    to: RecordId,
    payload: SignalPayload,
    now: u64,
) -> Result<String> {
    require_member(authority, session.credential().id())?;
    require_member(authority, to)?;
    record::hex::<16>(call_id)?;
    payload.validate()?;
    let signal = Signal {
        v: 1,
        kind: "call.signal".into(),
        scope: CallScope {
            space_id: authority.space(),
            stream_id: authority.stream(),
        },
        config_id: authority.head_id().ok_or(RecordError::Authority)?,
        call_id: call_id.into(),
        from: session.credential().id(),
        to,
        nonce: record::random_hex::<16>()?,
        issued_at: now,
        expires_at: now.saturating_add(COMMAND_TTL),
        payload,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&signal).map_err(|_| RecordError::Json)?);
    if plaintext.len() > MAX_SIGNAL_BYTES {
        return Err(RecordError::Framing);
    }
    let record = SignedRecord::sign(&plaintext, session.signing_key())?;
    let ciphertext = crate::crypto::seal_bytes(
        record.bytes(),
        &[authority.credential(to)?.recipient()],
        MAX_SIGNAL_BYTES,
    )
    .map_err(|_| RecordError::Authority)?;
    Ok(STANDARD.encode(ciphertext))
}

/// The caller also checks nonce replay and that the sender is an active peer in
/// the current call before accepting any media key or negotiation payload.
pub fn open_signal(
    authority: &Authority,
    session: &Session,
    call_id: &str,
    ciphertext: &str,
    now: u64,
) -> Result<Signal> {
    require_member(authority, session.credential().id())?;
    if ciphertext.len() > MAX_SIGNAL_BYTES * 2 {
        return Err(RecordError::Framing);
    }
    let bytes = STANDARD.decode(ciphertext).map_err(|_| RecordError::Json)?;
    let plaintext = Zeroizing::new(
        crate::crypto::open_bytes(&bytes, session.age_identity(), MAX_SIGNAL_BYTES)
            .map_err(|_| RecordError::Authority)?,
    );
    let signed = SignedRecord::parse(&plaintext)?;
    let signal: Signal = signed.decode()?;
    if signal.v != 1
        || signal.kind != "call.signal"
        || signal.call_id != call_id
        || signal.scope.space_id != authority.space()
        || signal.scope.stream_id != authority.stream()
        || Some(signal.config_id) != authority.head_id()
        || signal.to != session.credential().id()
    {
        return Err(RecordError::Authority);
    }
    record::hex::<16>(&signal.nonce)?;
    check_time(signal.issued_at, signal.expires_at, now)?;
    require_member(authority, signal.from)?;
    signed.verify_signature(authority.credential(signal.from)?.key())?;
    signal.payload.validate()?;
    Ok(signal)
}

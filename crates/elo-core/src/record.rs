//! Bounded ELO1 framing and signatures over preserved bytes. A signature alone
//! does not authorize a domain effect; callers must supply trusted context.
use crate::ids::{IdentityId, ObjectId, RecordId, SpaceId, StreamId};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::fmt;
use thiserror::Error;

pub const MAX_RECORD: usize = 1024 * 1024;
pub const MAX_CHAT_MEMBERS: usize = 1000;
pub const MAX_CHAT_CREDENTIALS: usize = 2000;
pub const MAX_INTEGER: u64 = (1 << 53) - 1;
pub const MAX_MESSAGE_CLOCK_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// Lamport ordering must not let a peer exhaust the wire integer range.
pub fn valid_message_time_at(value: u64, now: u64) -> bool {
    value <= MAX_INTEGER && value <= now.saturating_add(MAX_MESSAGE_CLOCK_SKEW_MS)
}

pub fn current_message_time_is_valid(value: u64) -> bool {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    valid_message_time_at(value, now.as_millis() as u64)
}

pub fn next_message_time(highest: u64, now: u64) -> u64 {
    let next = if valid_message_time_at(highest.saturating_add(1), now) {
        highest.saturating_add(1)
    } else {
        now
    };
    next.max(now).min(MAX_INTEGER)
}
const SIGN_DOMAIN: &[u8] = b"elo.now/signed-record/v1\0";

#[derive(Debug, Error)]
pub enum RecordError {
    #[error("invalid ELO1 framing or size")]
    Framing,
    #[error("invalid strict JSON or record schema")]
    Json,
    #[error("unsupported record version or kind")]
    Unsupported,
    #[error("invalid record signature or signing key")]
    Signature,
    #[error("record does not match trusted authority context")]
    Authority,
    #[error("randomness unavailable")]
    Random,
}
pub type Result<T> = std::result::Result<T, RecordError>;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                if v > MAX_INTEGER {
                    return Err(E::custom("integer range"));
                }
                Ok(Strict(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let Strict(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        d.deserialize_any(StrictVisitor)
    }
}

pub(crate) fn strict_json(body: &[u8], maximum: usize) -> Result<Value> {
    if body.len() > maximum.saturating_sub(72)
        || body.first() != Some(&b'{')
        || body.last() != Some(&b'}')
    {
        return Err(RecordError::Json);
    }
    let mut depth = 0u8;
    let mut quoted = false;
    let mut escaped = false;
    for &b in body {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else if b == b'"' {
            quoted = true;
        } else if b == b'{' || b == b'[' {
            depth = depth.checked_add(1).ok_or(RecordError::Json)?;
            if depth > 16 {
                return Err(RecordError::Json);
            }
        } else if b == b'}' || b == b']' {
            depth = depth.checked_sub(1).ok_or(RecordError::Json)?;
        } else if b == b'-' {
            return Err(RecordError::Json);
        }
    }
    serde_json::from_slice::<Strict>(body)
        .map(|v| v.0)
        .map_err(|_| RecordError::Json)
}

#[derive(Clone, Debug)]
pub struct SignedRecord {
    bytes: Vec<u8>,
    body: Value,
}
impl SignedRecord {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_bounded(bytes, MAX_RECORD)
    }
    pub(crate) fn parse_bounded(bytes: &[u8], maximum: usize) -> Result<Self> {
        if !(72..=maximum).contains(&bytes.len()) || &bytes[..4] != b"ELO1" {
            return Err(RecordError::Framing);
        }
        let length =
            u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| RecordError::Framing)?) as usize;
        if length != bytes.len() - 72 {
            return Err(RecordError::Framing);
        }
        let body = strict_json(&bytes[8..8 + length], maximum)?;
        if body.get("v").and_then(Value::as_u64) != Some(1)
            && !(body.get("v").and_then(Value::as_u64) == Some(2)
                && matches!(
                    body.get("kind").and_then(Value::as_str),
                    Some("device.credential" | "device.revoked")
                ))
        {
            return Err(RecordError::Unsupported);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            body,
        })
    }
    pub fn sign(body: &[u8], key: &SigningKey) -> Result<Self> {
        Self::sign_bounded(body, key, MAX_RECORD)
    }
    pub(crate) fn sign_bounded(body: &[u8], key: &SigningKey, maximum: usize) -> Result<Self> {
        strict_json(body, maximum)?;
        let length = u32::try_from(body.len()).map_err(|_| RecordError::Framing)?;
        let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + body.len());
        message.extend_from_slice(SIGN_DOMAIN);
        message.extend_from_slice(body);
        let mut bytes = Vec::with_capacity(body.len() + 72);
        bytes.extend_from_slice(b"ELO1");
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(&key.sign(&message).to_bytes());
        Self::parse_bounded(&bytes, maximum)
    }
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + self.body_bytes().len());
        message.extend_from_slice(SIGN_DOMAIN);
        message.extend_from_slice(self.body_bytes());
        let signature = Signature::from_slice(&self.bytes[self.bytes.len() - 64..])
            .map_err(|_| RecordError::Signature)?;
        key.verify_strict(&message, &signature)
            .map_err(|_| RecordError::Signature)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn body_bytes(&self) -> &[u8] {
        &self.bytes[8..self.bytes.len() - 64]
    }
    pub fn id(&self) -> RecordId {
        RecordId::of_record_bytes(&self.bytes)
    }
    pub fn body(&self) -> &Value {
        &self.body
    }
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.body.clone()).map_err(|_| RecordError::Json)
    }
    pub fn chat(&self) -> Result<ChatMessage> {
        if self.bytes.len() > MAX_RECORD {
            return Err(RecordError::Framing);
        }
        let chat: ChatMessage = self.decode()?;
        chat.validate()?;
        Ok(chat)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TextPayload {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
    /// The original record in this chat, never the immediately preceding reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_root: Option<RecordId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<MessageAction>,
}
/// Independent signed events. Retractions remain in history so delayed delivery
/// cannot resurrect an older reaction or pin. Identity, not device, owns a reaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageAction {
    Reaction {
        target: RecordId,
        emoji: String,
        active: bool,
    },
    Pin {
        target: RecordId,
        active: bool,
    },
    Delete {
        target: RecordId,
    },
}
pub fn reaction_choices() -> &'static [String] {
    static CHOICES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    CHOICES.get_or_init(|| {
        serde_json::from_str(include_str!("../../../protocol/reactions.json"))
            .expect("bundled reaction catalog")
    })
}
impl MessageAction {
    pub fn target(&self) -> RecordId {
        match self {
            Self::Reaction { target, .. } | Self::Pin { target, .. } | Self::Delete { target } => {
                *target
            }
        }
    }
    fn valid(&self) -> bool {
        match self {
            Self::Reaction { emoji, .. } => reaction_choices().contains(emoji),
            Self::Pin { .. } | Self::Delete { .. } => true,
        }
    }
}
pub fn valid_display_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 120
        && name.trim() == name
        && !name.chars().any(unsafe_display_character)
}

/// Reject invisible direction changes and separators used to disguise names/extensions.
pub fn unsafe_display_character(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{00ad}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChatMessage {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
    pub config_id: RecordId,
    pub audience: Vec<IdentityId>,
    pub recipient_credentials: Vec<RecordId>,
    pub logical_time: u64,
    pub created_at: String,
    pub parents: Vec<RecordId>,
    pub payload: TextPayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<MessageLocator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<MessageAccess>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MessageAccess {
    pub request_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_secret: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MessageLocator {
    pub message_record_id: RecordId,
    pub body_object_id: ObjectId,
    pub locator_nonce: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_secret: String,
}
impl ChatMessage {
    pub fn validate(&self) -> Result<()> {
        if self.v != 1
            || !matches!(
                self.kind.as_str(),
                "chat.message" | "chat.action" | "chat.locator"
            )
        {
            return Err(RecordError::Unsupported);
        }
        hex::<16>(&self.nonce)?;
        if !sorted_unique(&self.audience, 1, MAX_CHAT_MEMBERS)
            || !sorted_unique(&self.recipient_credentials, 1, MAX_CHAT_CREDENTIALS)
            || self.parents.len() > 16
            || self
                .parents
                .iter()
                .enumerate()
                .any(|(i, p)| self.parents[..i].contains(p))
            || self.logical_time > MAX_INTEGER
            || match (&*self.kind, &self.payload.action, &self.locator) {
                ("chat.message", None, None) => !(1..=16384).contains(&self.payload.text.len()),
                ("chat.action", Some(action), None) => {
                    !self.payload.text.is_empty()
                        || self.payload.thread_root.is_some()
                        || !action.valid()
                }
                ("chat.locator", None, Some(locator)) => {
                    !self.payload.text.is_empty()
                        || self.payload.sender_name.is_some()
                        || self.payload.action.is_some()
                        || hex::<16>(&locator.locator_nonce).is_err()
                        || (!locator.request_secret.is_empty()
                            && hex::<32>(&locator.request_secret).is_err())
                }
                _ => true,
            }
            || self
                .payload
                .sender_name
                .as_deref()
                .is_some_and(|name| !valid_display_name(name))
            || !valid_timestamp(&self.created_at)
        {
            return Err(RecordError::Json);
        }
        if self.access.as_ref().is_some_and(|access| {
            self.kind != "chat.message"
                || !crate::retention_access::valid_key(&access.request_key)
                || access
                    .accept_secret
                    .as_ref()
                    .is_some_and(|seed| hex::<32>(seed).is_err() || self.audience.len() != 2)
        }) {
            return Err(RecordError::Json);
        }
        Ok(())
    }
    pub fn sign(&self, key: &SigningKey) -> Result<SignedRecord> {
        self.validate()?;
        SignedRecord::sign(
            &serde_json::to_vec(self).map_err(|_| RecordError::Json)?,
            key,
        )
    }
}
pub(crate) fn sorted_unique<T: Ord>(items: &[T], min: usize, max: usize) -> bool {
    (min..=max).contains(&items.len()) && items.windows(2).all(|p| p[0] < p[1])
}
pub(crate) fn hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    crate::ids::parse_hex(value).map_err(|_| RecordError::Json)
}
pub fn random_hex<const N: usize>() -> Result<String> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| RecordError::Random)?;
    Ok(encode_hex(&bytes))
}
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn valid_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        let expected = match i {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            19 => Some(b'Z'),
            _ => None,
        };
        if expected.is_some_and(|e| e != *c) || (expected.is_none() && !c.is_ascii_digit()) {
            return false;
        }
    }
    let n = |a: usize, z: usize| s[a..z].parse::<u32>().unwrap_or(u32::MAX);
    let y = n(0, 4);
    let m = n(5, 7);
    let d = n(8, 10);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    y > 0 && d > 0 && d <= days && n(11, 13) < 24 && n(14, 16) < 60 && n(17, 19) < 60
}

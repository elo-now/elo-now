//! Typed, lower-case hexadecimal identifiers. Hashes do not imply authorization.

use std::{fmt, str::FromStr};

use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("identifier must contain exactly {expected} lower-case hexadecimal characters")]
pub struct InvalidId {
    expected: usize,
}

pub(crate) fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], InvalidId> {
    let error = InvalidId { expected: N * 2 };
    if value.len() != N * 2 {
        return Err(error);
    }
    fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[index] = digit(pair[0]).ok_or(error)? * 16 + digit(pair[1]).ok_or(error)?;
    }
    Ok(bytes)
}

macro_rules! identifier {
    ($name:ident, $length:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = InvalidId;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_hex(value).map(Self)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <String as serde::Deserialize>::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

identifier!(IdentityId, 32);
identifier!(ObjectId, 32);
identifier!(RecordId, 32);
identifier!(PeerId, 32);
identifier!(MailboxId, 32);
identifier!(SpaceId, 32);
identifier!(StreamId, 16);
identifier!(AttachmentId, 16);
identifier!(AttachmentObjectId, 16);

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    digest.finalize().into()
}

impl IdentityId {
    pub fn of_root_key(key: &[u8; 32]) -> Self {
        Self(hash(b"elo.now/identity/v1\0", key))
    }
}

impl ObjectId {
    /// Hashes opaque bytes. This does not check whether the bytes are age data.
    pub fn of_ciphertext(bytes: &[u8]) -> Self {
        Self(hash(b"elo.now/object-id/v1\0", bytes))
    }
}

impl RecordId {
    /// Hashes the entire ELO1 record. Framing/signature validation is separate.
    pub fn of_record_bytes(bytes: &[u8]) -> Self {
        Self(hash(b"elo.now/record-id/v1\0", bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip_without_accepting_uppercase_or_unicode() {
        let expected = ObjectId::from_bytes([0xab; 32]);
        assert_eq!(expected.to_string().parse::<ObjectId>().unwrap(), expected);
        assert!("AB".repeat(32).parse::<ObjectId>().is_err());
        assert!("é".repeat(32).parse::<ObjectId>().is_err());
        assert!("a".repeat(63).parse::<ObjectId>().is_err());
        assert!("g".repeat(64).parse::<ObjectId>().is_err());
        assert!("a".repeat(64).parse::<StreamId>().is_err());
    }

    #[test]
    fn record_hash_matches_supplied_fixture() {
        let record = include_bytes!("../../../protocol/fixtures/chat-message-v1.record.bin");
        assert_eq!(
            RecordId::of_record_bytes(record).to_string(),
            "a7bc602343d715d95ad10b57f3b08b5a94a8cd46278fb4fe05a0a21b0c044aa8"
        );
    }

    #[test]
    fn domains_are_distinct() {
        assert_ne!(
            ObjectId::of_ciphertext(b"same bytes").as_bytes(),
            RecordId::of_record_bytes(b"same bytes").as_bytes()
        );
    }
}

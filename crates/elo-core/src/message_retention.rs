//! Server delivery-copy policy. Message Keep and attachment expiry are separate.
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageRetention {
    Hours6,
    Hours12,
    #[default]
    Hours24,
    Hours48,
    NoExpiry,
}

impl MessageRetention {
    pub const fn seconds(self) -> Option<u64> {
        match self {
            Self::Hours6 => Some(21_600),
            Self::Hours12 => Some(43_200),
            Self::Hours24 => Some(86_400),
            Self::Hours48 => Some(172_800),
            Self::NoExpiry => None,
        }
    }
    pub const fn storage_value(self) -> &'static str {
        match self {
            Self::Hours6 => "6h",
            Self::Hours12 => "12h",
            Self::Hours24 => "24h",
            Self::Hours48 => "48h",
            Self::NoExpiry => "no_expiry",
        }
    }
    pub fn public_policies() -> Vec<Self> {
        vec![Self::Hours6, Self::Hours12, Self::Hours24]
    }
    pub fn validate_allowed(policies: &[Self]) -> bool {
        !policies.is_empty()
            && policies.len() <= 5
            && policies
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == policies.len()
    }
}
impl Serialize for MessageRetention {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.seconds() {
            Some(seconds) => serializer.serialize_u64(seconds),
            None => serializer.serialize_str("no_expiry"),
        }
    }
}
impl<'de> Deserialize<'de> for MessageRetention {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Seconds(u64),
            Explicit(String),
        }
        match Wire::deserialize(deserializer)? {
            Wire::Seconds(21_600) => Ok(Self::Hours6),
            Wire::Seconds(43_200) => Ok(Self::Hours12),
            Wire::Seconds(86_400) => Ok(Self::Hours24),
            Wire::Seconds(172_800) => Ok(Self::Hours48),
            Wire::Explicit(value) if value == "no_expiry" => Ok(Self::NoExpiry),
            _ => Err(de::Error::custom("invalid server message retention policy")),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_preserves_existing_numbers_and_requires_explicit_no_expiry() {
        for (wire, policy) in [
            ("21600", MessageRetention::Hours6),
            ("43200", MessageRetention::Hours12),
            ("86400", MessageRetention::Hours24),
            ("172800", MessageRetention::Hours48),
            ("\"no_expiry\"", MessageRetention::NoExpiry),
        ] {
            assert_eq!(
                serde_json::from_str::<MessageRetention>(wire).unwrap(),
                policy
            );
            assert_eq!(serde_json::to_string(&policy).unwrap(), wire);
        }
        for invalid in [
            "0",
            "1",
            "3153600000",
            "null",
            "-1",
            "86400.0",
            "\"86400\"",
            "\"forever\"",
            "true",
            "{}",
        ] {
            assert!(
                serde_json::from_str::<MessageRetention>(invalid).is_err(),
                "{invalid}"
            );
        }
        assert!(!MessageRetention::public_policies().contains(&MessageRetention::NoExpiry));
        assert!(!MessageRetention::public_policies().contains(&MessageRetention::Hours48));
    }
}

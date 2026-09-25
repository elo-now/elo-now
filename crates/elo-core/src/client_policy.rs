//! Additive discovery and release policy. This is not an authorization proof.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PATH: &str = "/client/v1/policy";
pub const MAX_BYTES: usize = 16 * 1024;
pub const PLATFORMS: [&str; 5] = ["ios", "android", "macos", "windows", "linux"];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Release {
    pub version: String,
    #[serde(default)]
    pub build: u32,
}
impl Release {
    fn order(&self) -> Result<(u32, u32, u32, u32), &'static str> {
        let parts = self.version.split('.').collect::<Vec<_>>();
        if parts.len() != 3
            || parts.iter().any(|p| {
                p.is_empty()
                    || p.len() > 9
                    || !p.bytes().all(|b| b.is_ascii_digit())
                    || (p.len() > 1 && p.starts_with('0'))
            })
        {
            return Err("Invalid release version.");
        }
        Ok((
            parts[0].parse().map_err(|_| "Invalid release version.")?,
            parts[1].parse().map_err(|_| "Invalid release version.")?,
            parts[2].parse().map_err(|_| "Invalid release version.")?,
            self.build,
        ))
    }
    pub fn before(&self, other: &Self) -> Result<bool, &'static str> {
        Ok(self.order()? < other.order()?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformPolicy {
    pub latest: Release,
    #[serde(default)]
    pub minimum: Option<Release>,
    /// Unix seconds; require the minimum only after store availability is confirmed.
    #[serde(default)]
    pub enforce_after: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientPolicy {
    pub v: u32,
    pub platforms: BTreeMap<String, PlatformPolicy>,
}
impl Default for ClientPolicy {
    fn default() -> Self {
        Self {
            v: 1,
            platforms: PLATFORMS
                .into_iter()
                .map(|platform| {
                    (
                        platform.into(),
                        PlatformPolicy {
                            latest: Release {
                                version: env!("CARGO_PKG_VERSION").into(),
                                build: 0,
                            },
                            minimum: None,
                            enforce_after: 0,
                        },
                    )
                })
                .collect(),
        }
    }
}
impl ClientPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.v != 1 || self.platforms.len() > 16 {
            return Err("Unsupported client policy.");
        }
        for platform in PLATFORMS {
            let rule = self
                .platforms
                .get(platform)
                .ok_or("Missing platform policy.")?;
            rule.latest.order()?;
            if let Some(minimum) = &rule.minimum {
                if rule.latest.before(minimum)? {
                    return Err("Minimum release exceeds the available release.");
                }
                if rule.enforce_after == 0 {
                    return Err("A required update needs an explicit activation time.");
                }
            }
        }
        Ok(())
    }
    pub fn required(
        &self,
        platform: &str,
        installed: &Release,
        now: u64,
    ) -> Result<bool, &'static str> {
        self.validate()?;
        installed.order()?;
        let rule = self
            .platforms
            .get(platform)
            .ok_or("Unknown client platform.")?;
        match &rule.minimum {
            Some(minimum) if now >= rule.enforce_after => installed.before(minimum),
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release(version: &str, build: u32) -> Release {
        Release {
            version: version.into(),
            build,
        }
    }
    #[test]
    fn numeric_versions_builds_and_activation_are_independent_per_platform() {
        let mut policy = ClientPolicy::default();
        let ios = policy.platforms.get_mut("ios").unwrap();
        ios.latest = release("1.10.0", 2000);
        ios.minimum = Some(release("1.2.0", 1090));
        ios.enforce_after = 100;
        assert!(!policy.required("ios", &release("1.1.0", 9999), 99).unwrap());
        assert!(
            policy
                .required("ios", &release("1.1.0", 9999), 100)
                .unwrap()
        );
        assert!(
            policy
                .required("ios", &release("1.2.0", 1089), 100)
                .unwrap()
        );
        assert!(
            !policy
                .required("ios", &release("1.2.0", 1090), 100)
                .unwrap()
        );
        assert!(!policy.required("ios", &release("1.10.0", 1), 100).unwrap());
        assert!(
            !policy
                .required("android", &release("1.0.0", 1082), 100)
                .unwrap()
        );
    }
    #[test]
    fn discovery_accepts_additions_but_rejects_unknown_schema_or_invalid_minimum() {
        let mut value = serde_json::to_value(ClientPolicy::default()).unwrap();
        value["future_capability"] = serde_json::json!({"anything":true});
        assert!(
            serde_json::from_value::<ClientPolicy>(value.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        value["v"] = 2.into();
        assert!(
            serde_json::from_value::<ClientPolicy>(value)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut policy = ClientPolicy::default();
        policy.platforms.get_mut("ios").unwrap().minimum = Some(release("2.0.0", 1));
        assert!(policy.validate().is_err());
        for invalid in ["1.0", "1.0.0-beta", "01.0.0", "-1.0.0", "1.0.0\n"] {
            assert!(release(invalid, 1).order().is_err());
        }
    }
}

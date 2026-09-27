//! Device-local choices survive logout, but never grant notification delivery.
use elo_core::vault;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const FILE: &str = "push-preferences.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    v: u8,
    identity: String,
    pub enabled: bool,
    pub calls_enabled: bool,
    pub call_ringtone: String,
}

impl Preferences {
    pub fn new(identity: &str) -> Self {
        Self {
            v: 1,
            identity: identity.into(),
            enabled: false,
            calls_enabled: false,
            call_ringtone: "classic".into(),
        }
    }

    pub fn load(root: &Path, identity: &str) -> Result<Option<Self>, String> {
        let path = root.join(FILE);
        if !path
            .try_exists()
            .map_err(|_| "Cannot read notification preferences")?
        {
            return Ok(None);
        }
        let bytes =
            vault::read_private(&path).map_err(|_| "Cannot read notification preferences")?;
        let value: Self =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid notification preferences")?;
        if value.v != 1
            || value.identity != identity
            || !["classic", "chime", "pulse", "silent"].contains(&value.call_ringtone.as_str())
        {
            return Err("Notification preferences do not match this profile".into());
        }
        Ok(Some(value))
    }

    pub fn save(&self, root: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec(self).map_err(|_| "Cannot save notification preferences")?;
        vault::write_private(&root.join(FILE), &bytes, true)
            .map_err(|_| "Cannot save notification preferences".into())
    }
}

/// Restoring an opt-in must never request OS permission or re-enable a logged-out profile.
pub fn should_resume(
    enabled: bool,
    permission: bool,
    maintain: bool,
    token_missing: bool,
    now: u64,
    retry_after: u64,
) -> bool {
    enabled && permission && maintain && token_missing && now >= retry_after
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_registration_removal_preserves_choices_only_for_the_same_local_profile() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let mut prefs = Preferences::new("profile-a");
        prefs.enabled = true;
        prefs.calls_enabled = true;
        prefs.call_ringtone = "chime".into();
        prefs.save(&first).unwrap();
        let registration = root.path().join("push-registration.json");
        std::fs::write(&registration, b"synthetic registration").unwrap();
        std::fs::remove_file(registration).unwrap();
        assert_eq!(Preferences::load(&first, "profile-a").unwrap(), Some(prefs));
        assert_eq!(Preferences::load(&second, "profile-a").unwrap(), None);
        assert!(Preferences::load(&first, "profile-b").is_err());
    }

    #[test]
    fn explicit_opt_out_and_call_only_opt_out_survive_reopening() {
        let root = tempfile::tempdir().unwrap();
        let mut prefs = Preferences::new("profile-a");
        prefs.enabled = true;
        prefs.calls_enabled = false;
        prefs.save(root.path()).unwrap();
        assert_eq!(
            Preferences::load(root.path(), "profile-a").unwrap(),
            Some(prefs.clone())
        );
        prefs.enabled = false;
        prefs.save(root.path()).unwrap();
        let reopened = Preferences::load(root.path(), "profile-a")
            .unwrap()
            .unwrap();
        assert!(!should_resume(reopened.enabled, true, true, true, 50, 0));
        let value: serde_json::Value =
            serde_json::from_slice(&vault::read_private(&root.path().join(FILE)).unwrap()).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        for secret in ["token", "owner", "route", "password"] {
            assert!(value.get(secret).is_none());
        }
    }

    #[test]
    fn automatic_registration_requires_opt_in_permission_maintenance_and_retry_delay() {
        assert!(should_resume(true, true, true, true, 30, 30));
        for (enabled, permission, maintain, missing, now) in [
            (false, true, true, true, 30),
            (true, false, true, true, 30),
            (true, true, false, true, 30),
            (true, true, true, false, 30),
            (true, true, true, true, 29),
        ] {
            assert!(!should_resume(
                enabled, permission, maintain, missing, now, 30
            ));
        }
    }
}

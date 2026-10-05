//! Permanent, authenticated device tombstones. Hosting shares this directory across
//! Spaces so deleting a Space cannot resurrect a retired device.
use super::*;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_REVOKED_DEVICES: usize = 65_536;
const MAX_REVOCATIONS_PER_HOUR: usize = 16;
const MAX_REVOCATIONS_PER_DAY: usize = 32;

#[derive(Default)]
struct Budget {
    identities: BTreeMap<IdentityId, BTreeMap<RecordId, u64>>,
    total: usize,
}
impl Budget {
    fn require_enrollment_budget(
        &self,
        identity: IdentityId,
        current: u64,
    ) -> crate::app::Result<()> {
        if let Some(entries) = self.identities.get(&identity)
            && (entries
                .values()
                .filter(|at| current.saturating_sub(**at) < 3_600)
                .count()
                >= MAX_REVOCATIONS_PER_HOUR
                || entries
                    .values()
                    .filter(|at| current.saturating_sub(**at) < 86_400)
                    .count()
                    >= MAX_REVOCATIONS_PER_DAY)
        {
            return Err(
                "Too many device changes for this profile. Try linking a device later.".into(),
            );
        }
        Ok(())
    }
    fn record(&mut self, identity: IdentityId, id: RecordId, at: u64) {
        if self
            .identities
            .entry(identity)
            .or_default()
            .insert(id, at)
            .is_none()
        {
            self.total += 1;
        }
    }
}

#[derive(Clone)]
pub struct Revocations {
    path: PathBuf,
    budget: Arc<Mutex<Budget>>,
}
impl Revocations {
    pub fn open(path: impl AsRef<Path>) -> crate::app::Result<Self> {
        let path = path.as_ref();
        if !path.try_exists()? {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path)?;
        }
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("Unsafe revocation registry.".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("Unsafe revocation registry.".into());
            }
        }
        // Build the quota index once per host startup. Proofs remain the durable
        // source of truth; no separate counter can be reset to bypass a quota.
        let mut budget = Budget::default();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file = entry.path();
            if file.extension().and_then(|extension| extension.to_str()) != Some("record") {
                continue;
            }
            if budget.total >= MAX_REVOKED_DEVICES {
                return Err("Device revocation registry is full.".into());
            }
            let record = SignedRecord::parse(&crate::vault::read_private(&file)?)?;
            let credential = DeviceRevocation::verify(&record)?;
            if file != path.join(format!("{}.record", credential.id())) {
                return Err("Invalid device revocation path.".into());
            }
            let at = entry
                .metadata()?
                .modified()?
                .duration_since(UNIX_EPOCH)?
                .as_secs();
            budget.record(credential.identity(), credential.id(), at);
        }
        Ok(Self {
            path: path.to_path_buf(),
            budget: Arc::new(Mutex::new(budget)),
        })
    }
    pub fn get(&self, id: RecordId) -> crate::app::Result<Option<SignedRecord>> {
        let path = self.path.join(format!("{id}.record"));
        if !path.try_exists()? {
            return Ok(None);
        }
        let record = SignedRecord::parse(&crate::vault::read_private(&path)?)?;
        if DeviceRevocation::verify(&record)?.id() != id {
            return Err("Invalid device revocation.".into());
        }
        Ok(Some(record))
    }
    pub fn insert(&self, record: &SignedRecord) -> crate::app::Result<()> {
        let credential = DeviceRevocation::verify(record)?;
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| "Device revocation registry unavailable.")?;
        if self.get(credential.id())?.is_some() {
            return Ok(());
        }
        // Only host-authorized requests may reach this method. Keep even
        // expired accounts' tombstones, never evict them to admit more entries.
        let current = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if budget.total >= MAX_REVOKED_DEVICES {
            return Err("Device revocation registry is full.".into());
        }
        let path = self.path.join(format!("{}.record", credential.id()));
        if let Err(error) = crate::vault::write_private(&path, record.bytes(), false)
            && self.get(credential.id())?.is_none()
        {
            return Err(error.into());
        }
        budget.record(credential.identity(), credential.id(), current);
        Ok(())
    }
    /// Limit replacement-device churn, never retirement of already admitted
    /// devices. A user must still be able to remove all compromised devices.
    pub fn require_enrollment_budget(&self, identity: IdentityId) -> crate::app::Result<()> {
        let current = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.budget
            .lock()
            .map_err(|_| "Device revocation registry unavailable.")?
            .require_enrollment_budget(identity, current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{self, Session};

    #[test]
    fn replacement_churn_limits_survive_restart_without_blocking_further_retirement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("revocations");
        let registry = Revocations::open(&path).unwrap();
        let (session, card) = Session::create().unwrap();
        let root = card.recover_root(session.identity_id()).unwrap();
        for _ in 0..MAX_REVOCATIONS_PER_HOUR {
            let device = Session::recover(&card, session.identity_id()).unwrap();
            let proof = DeviceRevocation::issue(&root, device.credential()).unwrap();
            registry.insert(&proof).unwrap();
            registry.insert(&proof).unwrap();
        }
        assert!(
            registry
                .require_enrollment_budget(session.identity_id())
                .is_err()
        );
        assert_eq!(
            registry.budget.lock().unwrap().total,
            MAX_REVOCATIONS_PER_HOUR
        );
        drop(registry);
        let registry = Revocations::open(&path).unwrap();
        assert!(
            registry
                .require_enrollment_budget(session.identity_id())
                .is_err()
        );
        // Even at the churn limit, previously admitted compromised devices
        // must remain removable. Only a new enrollment is rate limited.
        let proof = DeviceRevocation::issue(&root, session.credential()).unwrap();
        registry.insert(&proof).unwrap();
        assert!(registry.get(session.credential().id()).unwrap().is_some());
        let (another, _) = Session::create().unwrap();
        registry
            .require_enrollment_budget(another.identity_id())
            .unwrap();
    }

    #[test]
    fn replacement_budget_ages_out_without_deleting_tombstones() {
        let identity = IdentityId::from_bytes([1; 32]);
        let mut budget = Budget::default();
        for index in 0..MAX_REVOCATIONS_PER_HOUR {
            budget.record(identity, RecordId::from_bytes([index as u8; 32]), 1_000);
        }
        assert!(budget.require_enrollment_budget(identity, 1_001).is_err());
        budget.require_enrollment_budget(identity, 4_600).unwrap();
        for index in MAX_REVOCATIONS_PER_HOUR..MAX_REVOCATIONS_PER_DAY {
            budget.record(identity, RecordId::from_bytes([index as u8; 32]), 4_600);
        }
        assert!(budget.require_enrollment_budget(identity, 8_200).is_err());
        budget.require_enrollment_budget(identity, 91_000).unwrap();
        assert_eq!(budget.total, MAX_REVOCATIONS_PER_DAY);
    }

    #[test]
    fn root_proofs_reject_forgery_and_tombstones_survive_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("revocations");
        let registry = Revocations::open(&path).unwrap();
        let (session, card) = Session::create().unwrap();
        let root = card.recover_root(session.identity_id()).unwrap();
        let proof = DeviceRevocation::issue(&root, session.credential()).unwrap();
        let attacker = generate_signing_key().unwrap();
        assert!(DeviceRevocation::issue(&attacker, session.credential()).is_err());
        let body = serde_json::to_vec(proof.body()).unwrap();
        for key in [&attacker, session.signing_key()] {
            let forged = SignedRecord::sign(&body, key).unwrap();
            assert!(registry.insert(&forged).is_err());
        }
        assert!(registry.get(session.credential().id()).unwrap().is_none());
        registry.insert(&proof).unwrap();
        registry.insert(&proof).unwrap();
        drop(registry);
        let registry = Revocations::open(&path).unwrap();
        assert_eq!(
            registry
                .get(session.credential().id())
                .unwrap()
                .unwrap()
                .bytes(),
            proof.bytes()
        );
        let replacement = Session::recover(&card, session.identity_id()).unwrap();
        assert!(
            registry
                .get(replacement.credential().id())
                .unwrap()
                .is_none()
        );
        vault::write_private(
            &path.join(format!("{}.record", session.credential().id())),
            b"corrupt",
            true,
        )
        .unwrap();
        assert!(
            registry.get(session.credential().id()).is_err(),
            "a corrupt tombstone fails closed"
        );
    }

    #[test]
    fn device_proofs_bind_the_same_profile_target_and_authenticated_requester() {
        let (original, _) = Session::create().unwrap();
        let companion = original.linked_companion().unwrap();
        let other = original.linked_companion().unwrap();
        let (stranger, _) = Session::create().unwrap();
        let proof = DeviceRevocation::issue_from_device(
            companion.credential(),
            companion.signing_key(),
            original.credential(),
        )
        .unwrap();
        assert_eq!(
            DeviceRevocation::verify_request(&proof, companion.credential())
                .unwrap()
                .id(),
            original.credential().id()
        );
        assert!(DeviceRevocation::verify_request(&proof, other.credential()).is_err());
        assert!(DeviceRevocation::verify_request(&proof, stranger.credential()).is_err());
        assert!(
            DeviceRevocation::issue_from_device(
                companion.credential(),
                companion.signing_key(),
                companion.credential()
            )
            .is_err()
        );
        assert!(
            DeviceRevocation::issue_from_device(
                companion.credential(),
                companion.signing_key(),
                stranger.credential()
            )
            .is_err()
        );
        assert!(
            DeviceRevocation::issue_from_device(
                companion.credential(),
                stranger.signing_key(),
                original.credential()
            )
            .is_err()
        );
        let mut body = proof.body().clone();
        body["credential"] = serde_json::json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            stranger.credential().record().bytes()
        ));
        let cross_profile =
            SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), companion.signing_key())
                .unwrap();
        assert!(DeviceRevocation::verify(&cross_profile).is_err());
        let forged = SignedRecord::sign(
            &serde_json::to_vec(proof.body()).unwrap(),
            stranger.signing_key(),
        )
        .unwrap();
        assert!(DeviceRevocation::verify(&forged).is_err());

        let temp = tempfile::tempdir().unwrap();
        let registry = Revocations::open(temp.path().join("revocations")).unwrap();
        registry.insert(&proof).unwrap();
        drop(registry);
        let reopened = Revocations::open(temp.path().join("revocations")).unwrap();
        assert_eq!(
            reopened
                .get(original.credential().id())
                .unwrap()
                .unwrap()
                .bytes(),
            proof.bytes()
        );
    }
}

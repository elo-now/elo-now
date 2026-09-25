//! Permanent, authenticated device tombstones. Hosting shares this directory across
//! Spaces so deleting a Space cannot resurrect a retired device.
use super::*;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Revocations(PathBuf);
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
        Ok(Self(path.to_path_buf()))
    }
    pub fn get(&self, id: RecordId) -> crate::app::Result<Option<SignedRecord>> {
        let path = self.0.join(format!("{id}.record"));
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
        if self.get(credential.id())?.is_some() {
            return Ok(());
        }
        // Only host-authorized requests may reach this method. Keep even
        // expired accounts' tombstones, never evict them to admit more entries.
        if std::fs::read_dir(&self.0)?.take(65_536).count() >= 65_536 {
            return Err("Device revocation registry is full.".into());
        }
        let path = self.0.join(format!("{}.record", credential.id()));
        if let Err(error) = crate::vault::write_private(&path, record.bytes(), false)
            && self.get(credential.id())?.is_none()
        {
            return Err(error.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{self, Session};

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

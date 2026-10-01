//! Local provenance gates owner grants independently from signed Space roles.
use super::*;
use crate::authority::Authority;

impl Session {
    /// Use only after a completed live device-link exchange, including profiles
    /// that have not yet received any owner role. A portable backup is excluded.
    pub(crate) fn allow_live_owner_grants(&mut self) -> Result<bool> {
        if self.controller_mode == ControllerMode::Retired {
            return Err(VaultError::Invalid);
        }
        let changed = !self.owner_grant_eligible;
        self.owner_grant_eligible = true;
        Ok(changed)
    }

    /// Apply an exact device grant from a verified v2 General configuration.
    /// Restored and retired sessions cannot infer control from imported rosters.
    /// The caller must persist a changed session before using the new scope.
    pub(crate) fn activate_owner_grant(&mut self, authority: &Authority) -> Result<bool> {
        if !self.owner_grant_eligible
            || self.controller_mode == ControllerMode::Retired
            || !authority.is_owner_managed()
            || !authority.can_manage(self.credential.id())
            || self.can_control(authority.space())
        {
            return Ok(false);
        }
        self.activate_new_space_controller(authority.space())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::space_host,
        authority::{Capability, ConfigAction, Member},
    };

    fn promotion(target: &Session) -> Authority {
        let (owner, command) = space_host::tests::owner_creation();
        let mut authority = space_host::verify_creation_authority(&command, owner.credential())
            .unwrap()
            .unwrap();
        authority.add_credential(target.credential().clone());
        let mut config = authority.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = authority.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.members.push(Member {
            identity_id: target.identity_id(),
            identity_type: "HUMAN".into(),
            root_public_key: target.credential().record().body()["root_public_key"]
                .as_str()
                .unwrap()
                .into(),
            capabilities: vec![
                Capability::Read,
                Capability::Post,
                Capability::ShareHistory,
                Capability::Manage,
            ],
            credential_ids: vec![target.credential().id()],
            external: true,
        });
        config.members.sort_by_key(|member| member.identity_id);
        config.owner_credential_ids.push(target.credential().id());
        config.owner_credential_ids.sort();
        config.action = ConfigAction {
            operation: "replace".into(),
            actor_identity: owner.identity_id(),
            request_record_id: None,
        };
        authority
            .apply_config(config.sign(owner.signing_key()).unwrap())
            .unwrap();
        authority
    }

    #[test]
    fn independent_promoted_device_activates_only_its_exact_general_scope() {
        let profile = Session::create().unwrap().0;
        let mut compartment = profile.isolated_space();
        let authority = promotion(&profile);
        assert!(compartment.controller_mode() == ControllerMode::Follower);
        assert!(compartment.activate_owner_grant(&authority).unwrap());
        assert!(compartment.can_control(authority.space()));
        assert!(!compartment.can_control(SpaceId::from_bytes([12; 32])));
        assert!(!compartment.activate_owner_grant(&authority).unwrap());
        let reopened =
            Session::from_plaintext(&compartment.plaintext().unwrap(), compartment.identity_id())
                .unwrap();
        assert!(reopened.owner_grant_eligible && reopened.can_control(authority.space()));
        let mut other_device = profile.linked_companion().unwrap();
        assert!(!other_device.activate_owner_grant(&authority).unwrap());
    }

    #[test]
    fn backup_restore_and_retirement_cannot_reactivate_from_existing_owner_grants() {
        let profile = Session::create().unwrap().0;
        let authority = promotion(&profile);
        let password: SecretString = "synthetic owner grant restore password".into();
        let ciphertext = profile.seal(password.clone()).unwrap();
        let mut restored =
            Session::restore_backup(&ciphertext, password, profile.identity_id()).unwrap();
        assert!(!restored.owner_grant_eligible);
        assert!(!restored.activate_owner_grant(&authority).unwrap());
        let mut isolated = restored.isolated_space();
        assert!(!isolated.activate_owner_grant(&authority).unwrap());
        restored
            .activate_new_space_controller(SpaceId::from_bytes([12; 32]))
            .unwrap();
        assert!(!restored.activate_owner_grant(&authority).unwrap());
        let mut reopened =
            Session::from_plaintext(&restored.plaintext().unwrap(), restored.identity_id())
                .unwrap();
        assert!(!reopened.activate_owner_grant(&authority).unwrap());
        assert!(reopened.allow_live_owner_grants().unwrap());
        assert!(reopened.activate_owner_grant(&authority).unwrap());
        reopened.retire_controller();
        assert!(!reopened.activate_owner_grant(&authority).unwrap());
        assert!(reopened.allow_live_owner_grants().is_err());
        assert!(!reopened.isolated_space().owner_grant_eligible);
    }

    #[test]
    fn old_vault_migration_preserves_follower_and_retired_barriers() {
        let mut profile = Session::create().unwrap().0;
        for mode in [
            ControllerMode::Follower,
            ControllerMode::Retired,
            ControllerMode::Active,
        ] {
            profile.controller_mode = mode;
            let mut legacy: serde_json::Value =
                serde_json::from_slice(&profile.plaintext().unwrap()).unwrap();
            legacy
                .as_object_mut()
                .unwrap()
                .remove("owner_grant_eligible");
            let opened = Session::from_plaintext(
                &serde_json::to_vec(&legacy).unwrap(),
                profile.identity_id(),
            )
            .unwrap();
            assert_eq!(opened.owner_grant_eligible, mode == ControllerMode::Active);
        }
    }
}

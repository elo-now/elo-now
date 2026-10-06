//! Invitation-scoped discovery. Receiving a Space does not import a creation
//! provider or replace any existing device/Space trust anchor.
use super::*;
use crate::{
    hosting_profile::HostingProfile,
    witness::link::{InvitationLink, VerifiedDescriptor},
};

const CONFLICT: &str = "Hosting configuration cannot replace an approved trust anchor.";

fn compatible(previous: &HostingProfile, next: &HostingProfile) -> Result<()> {
    if previous.id() == next.id() {
        if previous != next && !previous.accepts_update(next) && !next.accepts_update(previous) {
            return Err(CONFLICT.into());
        }
    } else if previous.create_url == next.create_url {
        return Err(CONFLICT.into());
    }
    if previous.witness.url == next.witness.url && previous.witness != next.witness {
        return Err(CONFLICT.into());
    }
    Ok(())
}

impl Spaces {
    fn check_invitation_hosting(
        &self,
        root: &mut ClientApp,
        profile: &HostingProfile,
    ) -> Result<()> {
        profile.validate()?;
        for previous in root
            .hosting_services
            .profiles
            .values()
            .chain(self.catalog.hosting_bindings.values())
        {
            compatible(previous, profile)?;
        }
        // The built-in deployment is trusted even when it is hidden from the
        // creation picker. An invitation cannot bootstrap over those pins.
        root.check_default_invitation_hosting(profile)?;
        Ok(())
    }

    pub(super) async fn prepare_hosted_invitation(
        &self,
        root: &mut ClientApp,
        request: &Value,
    ) -> Result<Option<(hosting_services::Context, VerifiedDescriptor)>> {
        if !matches!(request["op"].as_str(), Some("space_preview" | "space_join")) {
            return Ok(None);
        }
        let Some(value) = request["link"]
            .as_str()
            .filter(|value| value.starts_with(crate::witness::link::PREFIX))
        else {
            return Ok(None);
        };
        let link = InvitationLink::parse(value)?;
        if link.hosting_origin().is_none() {
            return Ok(None);
        }
        let (invitation, profile) = root.open_hosted_invitation(&link).await?;
        self.check_invitation_hosting(root, &profile)?;
        let id = invitation.descriptor().address.scope.space.to_string();
        if let Some(entry) = self.catalog.entries.iter().find(|entry| entry.id == id)
            && let Some(address) = &entry.address
            && serde_json::to_value(address)?
                != serde_json::to_value(&invitation.descriptor().address)?
        {
            return Err("Space address changed. Data was preserved.".into());
        }
        Ok(Some((
            hosting_services::Context::profile(&profile)?,
            invitation,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_space_invitation_never_replaces_known_hosting_or_witness_pins() {
        let known = hosting_services::test_profile(11);
        assert!(compatible(&known, &known).is_ok());
        let mut policy_update = known.clone();
        policy_update.revision += 1;
        policy_update.name = "Renamed hosting".into();
        assert!(compatible(&known, &policy_update).is_ok());
        assert!(compatible(&policy_update, &known).is_ok());
        for mutate in 0..6 {
            let mut changed = known.clone();
            changed.revision += 1;
            match mutate {
                0 => changed.witness.public_key = "22".repeat(32),
                1 => changed.create_url = "https://other.example/spaces/v1/create".into(),
                2 => {
                    changed.storage.as_mut().unwrap().url =
                        "https://other.example/storage/v1".into()
                }
                3 => changed.push_url = Some("https://other.example/".into()),
                4 => changed.call_url = Some("https://other.example/calls/v1".into()),
                _ => {
                    changed.signing_public_key =
                        hosting_services::test_profile(21).signing_public_key
                }
            }
            assert!(
                compatible(&known, &changed).is_err(),
                "trust mutation {mutate}"
            );
        }
        let mut other = hosting_services::test_profile(21);
        other.witness.url = known.witness.url.clone();
        assert!(compatible(&known, &other).is_err());
        other.witness = known.witness.clone();
        assert!(compatible(&known, &other).is_ok());
    }

    #[tokio::test]
    async fn discovery_context_does_not_register_hosting_or_change_creation_selection() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save_named(
                temp.path().join("profile"),
                "synthetic hosting recipient password".into(),
                "General",
                "Hosting recipient",
            )
            .await
            .unwrap();
        app.enable_spaces().await.unwrap();
        let public = hosting_services::test_profile(31);
        app.configure_invitation_host(&public.create_url).unwrap();
        app.configure_witness_pin(Some(public.witness.clone()))
            .unwrap();
        app.configure_attachment_storage_endpoint(public.storage.as_ref().map(|s| s.url.as_str()))
            .unwrap();
        let original = hosting_services::test_profile(41);
        app.select_creation_hosting(Some(original.clone())).unwrap();
        let invitation = hosting_services::test_profile(51);
        let spaces = app.spaces.take().unwrap();
        spaces
            .check_invitation_hosting(&mut app, &invitation)
            .unwrap();
        {
            let scope = hosting_services::Scope::new(
                &mut app,
                hosting_services::Context::profile(&invitation).unwrap(),
            );
            assert_eq!(scope.current_hosting_id(), Some(invitation.id()));
        }
        assert!(app.hosting_profile_for_id(&invitation.id()).is_none());
        assert_eq!(app.hosting_services.creation, Some(original));
        assert!(spaces.catalog.hosting_bindings.is_empty());
        let mut forged_builtin = public.clone();
        forged_builtin.witness = invitation.witness;
        assert!(
            spaces
                .check_invitation_hosting(&mut app, &forged_builtin)
                .is_err()
        );
        app.spaces = Some(spaces);
        app.close().await.unwrap();
    }
}

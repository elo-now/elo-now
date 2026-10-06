//! Native-approved hosting configuration and scoped per-Space service routing.
use super::*;
use crate::hosting_profile::HostingProfile;
use std::ops::{Deref, DerefMut};

#[derive(Clone, Default)]
pub(super) struct Services {
    pub(super) defaults: Option<Context>,
    pub(super) profiles: BTreeMap<String, HostingProfile>,
    pub(super) creation: Option<HostingProfile>,
    pub(super) active: Option<HostingProfile>,
}

#[cfg(test)]
pub(super) fn test_profile(index: u8) -> HostingProfile {
    use ed25519_dalek::SigningKey;
    HostingProfile {
        v: 1,
        kind: "hosting.configuration".into(),
        revision: 1,
        name: format!("Hosting {index}"),
        signing_public_key: record::encode_hex(
            SigningKey::from_bytes(&[index; 32])
                .verifying_key()
                .as_bytes(),
        ),
        create_url: format!("https://api{index}.example.test/spaces/v1/create"),
        witness: crate::authority::WitnessPin {
            url: format!("https://witness{index}.example.test/witness/v1"),
            public_key: record::encode_hex(
                SigningKey::from_bytes(&[index + 1; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
            key_generation: 1,
        },
        storage: Some(crate::hosting_profile::Storage {
            url: format!("https://storage{index}.example.test/storage/v1"),
            managed: None,
        }),
        push_url: None,
        message_lifetimes: crate::message_retention::MessageRetention::public_policies(),
        default_message_lifetime: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn scoped_services_restore_on_cancellation_and_late_native_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save_named(
                temp.path().join("profile"),
                "synthetic hosting password".into(),
                "General",
                "Owner",
            )
            .await
            .unwrap();
        let private = test_profile(21);
        app.select_creation_hosting(Some(private.clone())).unwrap();
        // Native lifecycle may configure these after selecting/importing a host.
        let public = test_profile(31);
        app.configure_witness_pin(Some(public.witness.clone()))
            .unwrap();
        app.configure_invitation_host(&public.create_url).unwrap();
        app.configure_attachment_storage_endpoint(Some(
            "https://public-storage.example.test/storage/v1",
        ))
        .unwrap();
        app.configure_push("https://public-wake.example.test/", false)
            .unwrap();
        let context = app.creation_hosting_context().unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), async {
                let scope = Scope::new(&mut app, context);
                assert_eq!(scope.witness_pin, Some(private.witness.clone()));
                assert_eq!(scope.current_hosting_id(), Some(private.id()));
                assert!(scope.push_endpoint.is_none());
                std::future::pending::<()>().await;
            })
            .await
            .is_err()
        );
        assert_eq!(app.witness_pin, Some(public.witness));
        assert_eq!(
            app.push_endpoint.as_deref(),
            Some("https://public-wake.example.test/")
        );
        assert_eq!(
            app.attachment_storage_endpoint.as_deref(),
            Some("https://public-storage.example.test/storage/v1")
        );
        assert!(app.current_hosting_id().is_none());
        app.select_creation_hosting(None).unwrap();
        let defaults = app.creation_hosting_context().unwrap();
        let scope = Scope::new(&mut app, defaults);
        assert_eq!(
            scope.push_endpoint.as_deref(),
            Some("https://public-wake.example.test/")
        );
        drop(scope);
        app.close().await.unwrap();
    }
    #[tokio::test]
    async fn approved_profile_registry_rejects_replaced_pins_and_accepts_old_bound_revision() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save_named(
                temp.path().join("profile"),
                "synthetic hosting password".into(),
                "General",
                "Owner",
            )
            .await
            .unwrap();
        let first = test_profile(23);
        let mut next = first.clone();
        next.revision = 2;
        next.name = "Renamed hosting".into();
        app.configure_hosting_profile(first.clone()).unwrap();
        app.configure_hosting_profile(next.clone()).unwrap();
        app.configure_hosting_profile(first.clone()).unwrap();
        assert_eq!(app.hosting_profile_for_id(&first.id()), Some(&next));
        next.revision = 3;
        next.witness = test_profile(33).witness;
        assert!(app.configure_hosting_profile(next).is_err());
        let mut collision = test_profile(34);
        collision.create_url = first.create_url;
        assert!(app.configure_hosting_profile(collision).is_err());
        app.close().await.unwrap();
    }
}
#[derive(Clone)]
pub(super) struct Context {
    push: Option<String>,
    storage: Option<String>,
    witness: Option<crate::authority::WitnessPin>,
    invitation: Option<String>,
    push_allow_loopback: bool,
    profile: Option<HostingProfile>,
}
impl Context {
    pub(super) fn capture(app: &ClientApp) -> Self {
        Self {
            push: app.push_endpoint.clone(),
            storage: app.attachment_storage_endpoint.clone(),
            witness: app.witness_pin.clone(),
            invitation: app.invitation_api_origin.clone(),
            push_allow_loopback: app.push_allow_loopback,
            profile: app.hosting_services.active.clone(),
        }
    }
    pub(super) fn profile(profile: &HostingProfile) -> Result<Self> {
        profile.validate()?;
        let mut origin = reqwest::Url::parse(&profile.create_url)?;
        origin.set_path("/");
        Ok(Self {
            push: profile.push_url.clone(),
            storage: profile.storage.as_ref().map(|s| s.url.clone()),
            witness: Some(profile.witness.clone()),
            invitation: Some(origin.to_string()),
            push_allow_loopback: false,
            profile: Some(profile.clone()),
        })
    }
    pub(super) fn apply(self, app: &mut ClientApp) {
        if app.witness_pin != self.witness {
            app.membership_checks.clear_now();
        }
        app.push_endpoint = self.push;
        app.attachment_storage_endpoint = self.storage;
        app.witness_pin = self.witness;
        app.invitation_api_origin = self.invitation;
        app.push_allow_loopback = self.push_allow_loopback;
        app.hosting_services.active = self.profile;
    }
}
/// Restores even when a scoped asynchronous operation fails or is cancelled.
pub(super) struct Scope<'a> {
    app: &'a mut ClientApp,
    previous: Option<Box<Context>>,
}
impl<'a> Scope<'a> {
    pub(super) fn new(app: &'a mut ClientApp, context: Context) -> Self {
        let previous = Some(Box::new(Context::capture(app)));
        context.apply(app);
        Self { app, previous }
    }
}
impl Deref for Scope<'_> {
    type Target = ClientApp;
    fn deref(&self) -> &ClientApp {
        self.app
    }
}
impl DerefMut for Scope<'_> {
    fn deref_mut(&mut self) -> &mut ClientApp {
        self.app
    }
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            previous.apply(self.app);
        }
    }
}

impl ClientApp {
    /// Native trust decision only. Renderer/network payloads cannot register pins.
    pub fn configure_hosting_profile(&mut self, profile: HostingProfile) -> Result<()> {
        profile.validate()?;
        let id = profile.id();
        if let Some(previous) = self.hosting_services.profiles.get(&id)
            && profile.accepts_update(previous)
        {
            return Ok(());
        }
        if let Some(previous) = self.hosting_services.profiles.get(&id)
            && previous != &profile
            && !previous.accepts_update(&profile)
        {
            return Err("Hosting configuration cannot replace an approved trust anchor.".into());
        }
        if self
            .hosting_services
            .profiles
            .values()
            .any(|p| p.id() != id && p.create_url == profile.create_url)
        {
            return Err("This hosting address already has an approved configuration.".into());
        }
        self.hosting_services.profiles.insert(id, profile);
        Ok(())
    }
    /// Selects creation/join services, without changing connected Spaces.
    pub fn select_creation_hosting(&mut self, profile: Option<HostingProfile>) -> Result<()> {
        if let Some(profile) = &profile {
            self.configure_hosting_profile(profile.clone())?;
        }
        self.default_hosting_context();
        self.hosting_services.creation = profile;
        Ok(())
    }
    pub fn current_hosting_id(&self) -> Option<String> {
        self.hosting_services
            .active
            .as_ref()
            .map(HostingProfile::id)
    }
    pub fn hosting_profile_for_id(&self, id: &str) -> Option<&HostingProfile> {
        self.hosting_services.profiles.get(id)
    }
    pub(super) fn default_hosting_context(&mut self) -> Context {
        if self.hosting_services.defaults.is_none() {
            self.hosting_services.defaults = Some(Context::capture(self));
        }
        self.hosting_services.defaults.clone().unwrap()
    }
    pub(super) fn refresh_default_hosting_context(&mut self) {
        if self.hosting_services.active.is_none() {
            self.hosting_services.defaults = Some(Context::capture(self));
        }
    }
    pub(super) fn creation_hosting_context(&mut self) -> Result<Context> {
        match self.hosting_services.creation.as_ref() {
            Some(profile) => Context::profile(profile),
            None => Ok(self.default_hosting_context()),
        }
    }
}

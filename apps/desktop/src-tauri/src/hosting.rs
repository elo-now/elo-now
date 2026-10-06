//! Device-local, explicitly approved hosting profiles. Removed profiles retain
//! their signed trust pins so importing an old link cannot silently replace them.
use elo_core::{
    authority::WitnessPin,
    hosting_profile::{HostingProfile, Storage},
    message_retention::MessageRetention,
    vault,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::Manager;

const BUILTIN_ID: &str = "elo.now";
const MAX_PROFILES: usize = 32;
const MAX_CATALOG_BYTES: usize = 256 * 1024;
const MAX_LINK_BYTES: usize = elo_core::hosting_profile::MAX_BYTES * 2 + 32;
static CATALOG_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub(crate) struct Selection {
    pub id: String,
    pub create_url: String,
    pub storage: Option<Storage>,
    pub message_lifetimes: Vec<MessageRetention>,
    pub default_message_lifetime: MessageRetention,
    /// Only imported profiles have signed, explicitly approved trust anchors.
    pub profile: Option<HostingProfile>,
}

#[derive(Serialize)]
pub struct HostingProfileSummary {
    id: String,
    name: String,
    url: String,
    message_lifetimes: Vec<MessageRetention>,
    default_message_lifetime: MessageRetention,
    attachment_storage_available: bool,
    attachment_storage_managed: bool,
    builtin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_provider: Option<String>,
}

impl From<HostingProfile> for Selection {
    fn from(profile: HostingProfile) -> Self {
        Self {
            id: profile.id(),
            create_url: profile.create_url.clone(),
            storage: profile.storage.clone(),
            message_lifetimes: profile.message_lifetimes.clone(),
            default_message_lifetime: profile.default_message_lifetime,
            profile: Some(profile),
        }
    }
}

impl Selection {
    fn summary(&self) -> HostingProfileSummary {
        let managed = self
            .storage
            .as_ref()
            .and_then(|storage| storage.managed.as_ref());
        HostingProfileSummary {
            id: self.id.clone(),
            name: self
                .profile
                .as_ref()
                .map_or("elo.now", |profile| profile.name.as_str())
                .into(),
            url: self.create_url.clone(),
            message_lifetimes: self.message_lifetimes.clone(),
            default_message_lifetime: self.default_message_lifetime,
            attachment_storage_available: self.storage.is_some(),
            attachment_storage_managed: managed.is_some(),
            builtin: self.profile.is_none(),
            storage_provider: managed.map(|value| value.provider.clone()),
        }
    }
}

fn compiled_selection(
    create_url: &str,
    witness: &str,
    storage_url: &str,
) -> Result<Selection, String> {
    // Build-time endpoint validation permits local debug addresses. Imported
    // profiles always use the stricter signed-profile validator instead.
    if !witness.is_empty() {
        let pin: WitnessPin = serde_json::from_str(witness)
            .map_err(|_| "Invalid built-in hosting witness configuration.")?;
        pin.validate()
            .map_err(|_| "Invalid built-in hosting witness configuration.")?;
    }
    Ok(Selection {
        id: BUILTIN_ID.into(),
        create_url: create_url.into(),
        storage: (!storage_url.is_empty()).then(|| Storage {
            url: storage_url.into(),
            managed: None,
        }),
        message_lifetimes: MessageRetention::public_policies(),
        default_message_lifetime: MessageRetention::Hours24,
        profile: None,
    })
}

fn builtin() -> Result<Selection, String> {
    compiled_selection(
        env!("ELO_CONFIGURED_SPACE_HOST"),
        env!("ELO_CONFIGURED_WITNESS"),
        env!("ELO_CONFIGURED_STORAGE"),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProfile {
    link: String,
    enabled: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    v: u8,
    builtin_enabled: bool,
    profiles: Vec<StoredProfile>,
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            v: 1,
            builtin_enabled: true,
            profiles: Vec::new(),
        }
    }
}

fn parse_link(link: &str) -> Result<HostingProfile, String> {
    if link.len() > MAX_LINK_BYTES {
        return Err("The hosting link is too large.".into());
    }
    HostingProfile::parse_link(link)
        .map(|(profile, _)| profile)
        .map_err(|_| "Invalid signed hosting configuration.".into())
}

impl Catalog {
    fn validate(&self) -> Result<(), String> {
        if self.v != 1 || self.profiles.len() > MAX_PROFILES {
            return Err("Invalid hosting catalog.".into());
        }
        let mut ids = BTreeSet::new();
        for stored in &self.profiles {
            if !ids.insert(parse_link(&stored.link)?.id()) {
                return Err("Duplicate hosting configuration.".into());
            }
        }
        Ok(())
    }

    fn checked_import(&self, link: &str) -> Result<(HostingProfile, Option<usize>), String> {
        let profile = parse_link(link)?;
        let mut found = None;
        for (index, stored) in self.profiles.iter().enumerate() {
            let previous = parse_link(&stored.link)?;
            if previous.id() != profile.id() && previous.create_url == profile.create_url {
                return Err("This hosting address already has an approved configuration.".into());
            }
            if previous.id() == profile.id() {
                // Exact retransmission can restore a removed entry. Every
                // changed profile needs a higher revision and identical pins.
                if previous != profile && !previous.accepts_update(&profile) {
                    return Err("This hosting configuration conflicts with its saved trust pins or revision.".into());
                }
                found = Some(index);
                break;
            }
        }
        if found.is_none() && self.profiles.len() >= MAX_PROFILES {
            return Err("This device has reached its hosting configuration limit.".into());
        }
        Ok((profile, found))
    }

    fn add(&mut self, link: &str) -> Result<(), String> {
        let (_, index) = self.checked_import(link)?;
        let stored = StoredProfile {
            link: link.trim().into(),
            enabled: true,
        };
        match index {
            Some(index) => self.profiles[index] = stored,
            None => self.profiles.push(stored),
        }
        Ok(())
    }

    fn remove(&mut self, id: &str) -> Result<(), String> {
        if id == BUILTIN_ID {
            self.builtin_enabled = false;
            return Ok(());
        }
        for stored in &mut self.profiles {
            if parse_link(&stored.link)?.id() == id {
                stored.enabled = false;
                return Ok(());
            }
        }
        Err("Hosting configuration was not found.".into())
    }

    fn entries(&self, builtin: &Selection) -> Result<Vec<HostingProfileSummary>, String> {
        let mut entries = Vec::new();
        if self.builtin_enabled {
            entries.push(builtin.summary());
        }
        for stored in &self.profiles {
            if stored.enabled {
                entries.push(Selection::from(parse_link(&stored.link)?).summary());
            }
        }
        Ok(entries)
    }

    fn selected(&self, id: &str, builtin: Selection) -> Result<Option<Selection>, String> {
        if id == BUILTIN_ID {
            return Ok(self.builtin_enabled.then_some(builtin));
        }
        for stored in &self.profiles {
            let profile = parse_link(&stored.link)?;
            if profile.id() == id {
                return Ok(stored.enabled.then(|| profile.into()));
            }
        }
        Ok(None)
    }
}

fn catalog_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|_| "Cannot locate the hosting catalog.")?;
    std::fs::create_dir_all(&base).map_err(|_| "Cannot create the hosting catalog directory.")?;
    Ok(base.join("hosting-catalog.json"))
}

fn save(path: &Path, catalog: &Catalog, replace: bool) -> Result<(), String> {
    let bytes = serde_json::to_vec(catalog).map_err(|_| "Cannot encode the hosting catalog.")?;
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err("The hosting catalog is full.".into());
    }
    vault::write_private(path, &bytes, replace)
        .map_err(|_| "Cannot save the hosting catalog.".into())
}

fn load(path: &Path) -> Result<Catalog, String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let catalog = Catalog::default();
            save(path, &catalog, false)?;
            Ok(catalog)
        }
        Err(_) => Err("Cannot read the hosting catalog.".into()),
        Ok(_) => {
            let bytes = vault::read_private(path)
                .map_err(|_| "Cannot read the private hosting catalog.")?;
            if bytes.len() > MAX_CATALOG_BYTES {
                return Err("The hosting catalog is too large.".into());
            }
            let catalog: Catalog =
                serde_json::from_slice(&bytes).map_err(|_| "Invalid hosting catalog.")?;
            catalog.validate()?;
            Ok(catalog)
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    List {},
    Preview { link: String },
    Add { link: String },
    Remove { id: String },
    RestoreDefault {},
}

#[derive(Serialize)]
pub struct Reply {
    entries: Vec<HostingProfileSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<HostingProfileSummary>,
}

fn handle(path: &Path, request: Request, builtin: Selection) -> Result<Reply, String> {
    let mut catalog = load(path)?;
    let mut preview = None;
    let mut changed = true;
    match request {
        Request::List {} => changed = false,
        Request::Preview { link } => {
            let (profile, _) = catalog.checked_import(&link)?;
            if profile.create_url == builtin.create_url {
                return Err("This hosting address already has an approved configuration.".into());
            }
            preview = Some(Selection::from(profile).summary());
            changed = false;
        }
        Request::Add { link } => {
            if parse_link(&link)?.create_url == builtin.create_url {
                return Err("This hosting address already has an approved configuration.".into());
            }
            catalog.add(&link)?;
        }
        Request::Remove { id } => catalog.remove(&id)?,
        Request::RestoreDefault {} => catalog.builtin_enabled = true,
    }
    if changed {
        save(path, &catalog, true)?;
    }
    Ok(Reply {
        entries: catalog.entries(&builtin)?,
        preview,
    })
}

#[tauri::command]
pub fn hosting_catalog(app: tauri::AppHandle, request: Request) -> Result<Reply, String> {
    let _guard = CATALOG_LOCK
        .lock()
        .map_err(|_| "The hosting catalog is unavailable.")?;
    handle(&catalog_path(&app)?, request, builtin()?)
}

pub(crate) fn selected(app: &tauri::AppHandle, id: &str) -> Result<Option<Selection>, String> {
    let _guard = CATALOG_LOCK
        .lock()
        .map_err(|_| "The hosting catalog is unavailable.")?;
    load(&catalog_path(app)?)?.selected(id, builtin()?)
}

const MISSING_HOSTING: &str = "Add this hosting configuration before opening the invitation.";

fn creation_selection(
    requested: Option<&str>,
    pending: Option<Option<HostingProfile>>,
    mut lookup: impl FnMut(&str) -> Result<Option<Selection>, String>,
    builtin: Selection,
) -> Result<Selection, String> {
    if let Some(pending) = pending {
        let saved = pending.map(Selection::from).unwrap_or(builtin);
        if requested.is_some_and(|id| id != saved.id) {
            return Err("Continue creating the Space on its saved hosting.".into());
        }
        return Ok(saved);
    }
    let id = requested.ok_or("Choose hosting before creating a Space.")?;
    lookup(id)?.ok_or_else(|| "Choose hosting before creating a Space.".into())
}

fn creation_request(request: &mut serde_json::Value, selected: &Selection) -> Result<(), String> {
    let lifetime: MessageRetention =
        serde_json::from_value(request["message_lifetime_seconds"].clone())
            .map_err(|_| "Choose a valid server message retention policy.")?;
    if !selected.message_lifetimes.contains(&lifetime) {
        return Err("Choose a message retention policy offered by this hosting service.".into());
    }
    if selected
        .storage
        .as_ref()
        .and_then(|storage| storage.managed.as_ref())
        .is_some()
    {
        // The provider and its access credentials are server-owned. Never pass
        // stale own-storage fields from another host into managed provisioning.
        request["attachment_storage"] = serde_json::json!({"enabled":true,"managed":true});
    } else if request["attachment_storage"]["managed"] == true {
        return Err("This hosting service does not provide managed attachment storage.".into());
    } else if request["attachment_storage"]["enabled"] == true {
        if selected.storage.is_none() {
            return Err("Attachment storage is unavailable on this hosting service.".into());
        }
    } else {
        request
            .as_object_mut()
            .ok_or("Invalid application request.")?
            .remove("attachment_storage");
    }
    request["host"] = serde_json::json!(selected.create_url);
    request["hosting_id"] = serde_json::json!(selected.id);
    Ok(())
}

fn invitation_profile(
    link: &str,
    mut lookup: impl FnMut(&str) -> Result<Option<Selection>, String>,
) -> Result<Option<HostingProfile>, String> {
    if !link.starts_with(elo_core::witness::link::PREFIX) {
        return Ok(None);
    }
    let link = elo_core::witness::link::InvitationLink::parse(link)
        .map_err(|_| "Invalid Space invitation.")?;
    match link.hosting_id() {
        Some(id) => lookup(id)?
            .and_then(|selected| selected.profile)
            .map(Some)
            .ok_or_else(|| MISSING_HOSTING.into()),
        None => Ok(None),
    }
}

/// Called while the profile mutex is held, before any invitation or creation
/// request can contact a service. Other operations retain their Space binding.
pub(crate) fn prepare_operation(
    app: &tauri::AppHandle,
    client: &mut elo_core::app::ClientApp,
    request: &mut serde_json::Value,
) -> Result<(), String> {
    if !matches!(
        request["op"].as_str(),
        Some("space_create" | "space_preview" | "space_join")
    ) {
        return Ok(());
    }
    if request["expected_identity"] != serde_json::json!(client.identity_id()) {
        return Err("The open profile has changed.".into());
    }
    let profile = if request["op"] == "space_create" {
        if !request["hosting_id"].is_null() && !request["hosting_id"].is_string() {
            return Err("Choose hosting before creating a Space.".into());
        }
        let selection = creation_selection(
            request["hosting_id"].as_str(),
            client.pending_creation_hosting(),
            |id| selected(app, id),
            builtin()?,
        )?;
        creation_request(request, &selection)?;
        selection.profile
    } else {
        let link = request["link"]
            .as_str()
            .ok_or("Invalid Space invitation.")?;
        invitation_profile(link, |id| selected(app, id))?
    };
    client
        .select_creation_hosting(profile)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elo_core::{hosting_profile::ManagedStorage, record, vault::Session};

    fn profile(session: &Session) -> HostingProfile {
        HostingProfile {
            v: 1,
            kind: "hosting.configuration".into(),
            revision: 1,
            name: "Company hosting".into(),
            signing_public_key: record::encode_hex(
                session.signing_key().verifying_key().as_bytes(),
            ),
            create_url: "https://api.example.test/spaces/v1/create".into(),
            witness: WitnessPin {
                url: "https://witness.example.test/witness/v1".into(),
                public_key: record::encode_hex(session.signing_key().verifying_key().as_bytes()),
                key_generation: 1,
            },
            storage: Some(Storage {
                url: "https://storage.example.test/storage/v1".into(),
                managed: Some(ManagedStorage {
                    provider: "s3".into(),
                    retention_hours: 24,
                }),
            }),
            push_url: None,
            call_url: None,
            message_lifetimes: vec![MessageRetention::Hours48, MessageRetention::NoExpiry],
            default_message_lifetime: MessageRetention::NoExpiry,
        }
    }
    fn link(profile: &HostingProfile, session: &Session) -> String {
        HostingProfile::link(&profile.sign(session.signing_key()).unwrap()).unwrap()
    }
    fn fixture_builtin() -> Selection {
        compiled_selection("https://api.elo.example/spaces/v1/create", "", "").unwrap()
    }

    #[test]
    fn builtin_is_seeded_once_and_only_explicit_restore_reenables_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("hosting-catalog.json");
        assert_eq!(
            handle(&path, Request::List {}, fixture_builtin())
                .unwrap()
                .entries
                .len(),
            1
        );
        handle(
            &path,
            Request::Remove {
                id: BUILTIN_ID.into(),
            },
            fixture_builtin(),
        )
        .unwrap();
        assert!(
            handle(&path, Request::List {}, fixture_builtin())
                .unwrap()
                .entries
                .is_empty()
        );
        assert!(
            load(&path)
                .unwrap()
                .selected(BUILTIN_ID, fixture_builtin())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            handle(&path, Request::RestoreDefault {}, fixture_builtin())
                .unwrap()
                .entries
                .len(),
            1
        );
        let builtin = fixture_builtin();
        assert!(builtin.profile.is_none());
        assert_eq!(
            builtin.message_lifetimes,
            MessageRetention::public_policies()
        );
    }

    #[test]
    fn preview_never_imports_and_summaries_contain_only_public_choices() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("hosting-catalog.json");
        let session = Session::create().unwrap().0;
        let profile = profile(&session);
        let link = link(&profile, &session);
        let reply = handle(
            &path,
            Request::Preview { link: link.clone() },
            fixture_builtin(),
        )
        .unwrap();
        assert_eq!(reply.entries.len(), 1);
        assert!(load(&path).unwrap().profiles.is_empty());
        let preview = serde_json::to_value(reply.preview.unwrap()).unwrap();
        assert_eq!(preview["id"], profile.id());
        assert_eq!(preview["default_message_lifetime"], "no_expiry");
        assert_eq!(
            preview["message_lifetimes"],
            serde_json::json!([172800, "no_expiry"])
        );
        assert_eq!(preview["attachment_storage_managed"], true);
        assert_eq!(preview["storage_provider"], "s3");
        assert!(preview.get("witness").is_none());
        assert!(preview.get("link").is_none());
        handle(&path, Request::Add { link }, fixture_builtin()).unwrap();
        let selected = load(&path)
            .unwrap()
            .selected(&profile.id(), fixture_builtin())
            .unwrap()
            .unwrap();
        assert_eq!(selected.profile, Some(profile));
    }

    #[test]
    fn removed_profiles_keep_pins_and_revision_high_water_marks() {
        let session = Session::create().unwrap().0;
        let first = profile(&session);
        let mut catalog = Catalog::default();
        catalog.add(&link(&first, &session)).unwrap();
        catalog.remove(&first.id()).unwrap();
        assert!(catalog.profiles.iter().all(|stored| !stored.enabled));
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("hosting-catalog.json");
        save(&path, &catalog, false).unwrap();
        let mut catalog = load(&path).unwrap();
        let mut changed = first.clone();
        changed.revision = 2;
        changed.create_url = "https://other.example.test/spaces/v1/create".into();
        assert!(catalog.add(&link(&changed, &session)).is_err());
        changed = first.clone();
        changed.revision = 2;
        changed.name = "Renamed hosting".into();
        catalog.add(&link(&changed, &session)).unwrap();
        assert!(catalog.add(&link(&first, &session)).is_err());
        catalog.remove(&changed.id()).unwrap();
        catalog.add(&link(&changed, &session)).unwrap();
        assert_eq!(catalog.profiles.len(), 1);
        assert!(catalog.profiles[0].enabled);
        let mut same_revision = changed.clone();
        same_revision.name = "Another name".into();
        assert!(catalog.add(&link(&same_revision, &session)).is_err());
        let replacement_key = Session::create().unwrap().0;
        let replacement = profile(&replacement_key);
        catalog.remove(&changed.id()).unwrap();
        assert!(
            catalog
                .checked_import(&link(&replacement, &replacement_key))
                .is_err()
        );
    }

    #[test]
    fn corrupt_private_catalog_does_not_reset_to_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("hosting-catalog.json");
        vault::write_private(
            &path,
            br#"{"v":1,"builtin_enabled":false,"profiles":[{"link":"invalid","enabled":false}]}"#,
            false,
        )
        .unwrap();
        assert!(load(&path).is_err());
        assert!(handle(&path, Request::RestoreDefault {}, fixture_builtin()).is_err());
        assert!(
            serde_json::from_value::<Request>(
                serde_json::json!({"op":"list","path":"/tmp/anything"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<Request>(
                serde_json::json!({"op":"add","link":"fixture","url":"https://override.example/"})
            )
            .is_err()
        );
    }

    #[test]
    fn catalog_and_links_remain_bounded_including_removed_pins() {
        let session = Session::create().unwrap().0;
        let first = profile(&session);
        let link = link(&first, &session);
        let mut catalog = Catalog::default();
        // Invalid duplicate persisted identities are rejected independently of
        // the total limit, including entries hidden from the selector.
        catalog.profiles = (0..=MAX_PROFILES)
            .map(|_| StoredProfile {
                link: link.clone(),
                enabled: false,
            })
            .collect();
        assert!(catalog.validate().is_err());
        catalog.profiles.pop();
        assert!(catalog.validate().is_err());
        assert!(parse_link(&"x".repeat(MAX_LINK_BYTES + 1)).is_err());
        let temp = tempfile::tempdir().unwrap();
        catalog.profiles[0].link = "x".repeat(MAX_CATALOG_BYTES);
        assert!(save(&temp.path().join("catalog.json"), &catalog, false).is_err());
    }

    #[test]
    fn new_creation_requires_an_enabled_host_but_pending_creation_uses_its_saved_intent() {
        let session = Session::create().unwrap().0;
        let profile = profile(&session);
        assert!(creation_selection(None, None, |_| Ok(None), fixture_builtin()).is_err());
        assert!(
            creation_selection(Some("missing"), None, |_| Ok(None), fixture_builtin()).is_err()
        );
        let saved = creation_selection(
            Some(&profile.id()),
            Some(Some(profile.clone())),
            |_| panic!("A saved intent does not need a catalog entry"),
            fixture_builtin(),
        )
        .unwrap();
        assert_eq!(saved.profile, Some(profile.clone()));
        assert!(
            creation_selection(
                Some(BUILTIN_ID),
                Some(Some(profile)),
                |_| Ok(None),
                fixture_builtin()
            )
            .is_err()
        );
        let legacy = creation_selection(None, Some(None), |_| Ok(None), fixture_builtin()).unwrap();
        assert!(legacy.profile.is_none());
        assert_eq!(legacy.id, BUILTIN_ID);
    }

    #[test]
    fn renderer_host_and_managed_credentials_are_replaced_by_native_selection() {
        let session = Session::create().unwrap().0;
        let selection = Selection::from(profile(&session));
        let mut request = serde_json::json!({
            "host":"https://untrusted.example/spaces/v1/create",
            "message_lifetime_seconds":"no_expiry",
            "attachment_storage":{"enabled":true,"provider":"s3_compatible","secret_key":"fixture-secret"}
        });
        creation_request(&mut request, &selection).unwrap();
        assert_eq!(request["host"], selection.create_url);
        assert_eq!(request["hosting_id"], selection.id);
        assert_eq!(
            request["attachment_storage"],
            serde_json::json!({"enabled":true,"managed":true})
        );
        request["message_lifetime_seconds"] = serde_json::json!(21600);
        assert!(creation_request(&mut request, &selection).is_err());
        request["message_lifetime_seconds"] = serde_json::json!("no_expiry");
        assert!(creation_request(&mut request, &fixture_builtin()).is_err());
        request["message_lifetime_seconds"] = serde_json::json!(86400);
        assert!(creation_request(&mut request, &fixture_builtin()).is_err());
    }

    #[test]
    fn invitation_routing_resolves_only_a_previously_imported_id_and_resets_legacy_links() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let session = Session::create().unwrap().0;
        let profile = profile(&session);
        // Synthetic invitation framing is enough to prove routing occurs before
        // any descriptor fetch; no invitation seed is logged or returned.
        let legacy = format!(
            "{}{}",
            elo_core::witness::link::PREFIX,
            URL_SAFE_NO_PAD.encode([1_u8; 65])
        );
        let link = elo_core::witness::link::InvitationLink::parse(&legacy)
            .unwrap()
            .with_hosting(&profile.id())
            .unwrap()
            .to_url();
        assert_eq!(
            invitation_profile(&link, |_| Ok(None)).unwrap_err(),
            MISSING_HOSTING
        );
        let selected = invitation_profile(&link, |id| {
            assert_eq!(id, profile.id());
            Ok(Some(profile.clone().into()))
        })
        .unwrap();
        assert_eq!(selected, Some(profile));
        assert!(
            invitation_profile(&legacy, |_| panic!(
                "Legacy invitations select the built-in context"
            ))
            .unwrap()
            .is_none()
        );
        assert!(
            invitation_profile("elo://space/v1#legacy", |_| panic!(
                "Legacy invitations select the built-in context"
            ))
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn a_custom_signer_cannot_replace_the_builtin_address_after_removal() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("hosting-catalog.json");
        handle(
            &path,
            Request::Remove {
                id: BUILTIN_ID.into(),
            },
            fixture_builtin(),
        )
        .unwrap();
        let session = Session::create().unwrap().0;
        let mut profile = profile(&session);
        profile.create_url = fixture_builtin().create_url;
        let link = link(&profile, &session);
        assert!(
            handle(
                &path,
                Request::Preview { link: link.clone() },
                fixture_builtin()
            )
            .is_err()
        );
        assert!(handle(&path, Request::Add { link }, fixture_builtin()).is_err());
        assert!(
            handle(&path, Request::List {}, fixture_builtin())
                .unwrap()
                .entries
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn catalog_is_private_and_rejects_symlink_redirection() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("hosting-catalog.json");
        load(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
        let redirected = temp.path().join("redirected.json");
        symlink(&path, &redirected).unwrap();
        assert!(load(&redirected).is_err());
        assert!(save(&redirected, &Catalog::default(), true).is_err());
    }
}

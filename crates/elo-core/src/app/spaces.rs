//! User-facing Spaces are separate encrypted stores, not filters over one outbox.
//! Existing profile data stays in the root compartment during migration.
use super::space_service::{SpaceAddress, SpaceInvitation};
use super::*;

const MAX_SPACES: usize = 16;
const VAULT_CACHE: &str = "space-vault-cache.age";
const DATA_FILES: &[&str] = &[
    "workspace.age",
    "read-state.age",
    "invitations.age",
    "client.sqlite",
    "client.sqlite-wal",
    "client.sqlite-shm",
    "client.sqlite-journal",
];
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    name: String,
    root: bool,
    status: String,
    owner: bool,
    #[serde(default)]
    contact_email: Option<String>,
    message_lifetime_seconds: u64,
    address: Option<SpaceAddress>,
    #[serde(default)]
    requests: usize,
    #[serde(default)]
    role: String,
    #[serde(default)]
    roles_revision: u64,
    #[serde(default)]
    role_requests: Vec<Value>,
    #[serde(default)]
    membership_epoch: u64,
    #[serde(default, rename = "service_requests", skip_serializing)]
    _legacy_service_requests: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreationIntent {
    #[serde(default)]
    contact_email: String,
    host: String,
    request_id: String,
    name: String,
    message_lifetime_seconds: u64,
    #[serde(default)]
    space: Option<String>,
    #[serde(default)]
    invitation: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    v: u8,
    #[serde(default)]
    setup: bool,
    #[serde(default)]
    creation: Option<CreationIntent>,
    #[serde(default)]
    creation_retry: Option<CreationIntent>,
    #[serde(default)]
    notification_generation: u64,
    #[serde(default)]
    account_hosts: BTreeSet<String>,
    active: Option<String>,
    entries: Vec<Entry>,
    garbage: Vec<String>,
    root_disconnected: bool,
    personal_genesis: Option<String>,
}
pub(super) struct Spaces {
    catalog: Catalog,
    children: BTreeMap<String, ClientApp>,
    next_poll: u64,
    sync_round: usize,
    invitation_round: usize,
    invitation_force: bool,
    sync_backlog: BTreeSet<String>,
}

fn safe_id(id: &str) -> Result<()> {
    record::hex::<32>(id)?;
    Ok(())
}
fn child_path(root: &ClientApp, id: &str) -> Result<PathBuf> {
    safe_id(id)?;
    Ok(root.directory.join("spaces").join(id))
}
fn make_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}
fn check_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Unsafe Space directory.".into());
    }
    Ok(())
}
fn remove_child(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        return Ok(());
    }
    check_directory(path)?;
    let files = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
    let mut empty_transfer_cache = None;
    for file in &files {
        let name = file.file_name();
        let name = name.to_str().ok_or("Unexpected Space file.")?;
        if name == "attachment-transfers"
            && file.file_type()?.is_dir()
            && std::fs::read_dir(file.path())?.next().is_none()
        {
            empty_transfer_cache = Some(file.path());
            continue;
        }
        if !file.file_type()?.is_file()
            || !(DATA_FILES.contains(&name)
                || [
                    "profile.json",
                    "profile-details.age",
                    "blocked.age",
                    "vault.age",
                    VAULT_CACHE,
                    ".elo-client.lock",
                ]
                .contains(&name))
        {
            return Err("This Space contains an unexpected file; its data was preserved.".into());
        }
    }
    // Completed transfers leave this empty private directory. Never recurse:
    // unexpected contents or a symbolic link still preserve the whole Space.
    if let Some(cache) = &empty_transfer_cache {
        std::fs::remove_dir(cache)?;
    }
    for file in files {
        if empty_transfer_cache.as_ref() != Some(&file.path()) {
            std::fs::remove_file(file.path())?;
        }
    }
    std::fs::remove_dir(path)?;
    Ok(())
}
impl ClientApp {
    pub(super) fn device_addresses(&self) -> Vec<SpaceAddress> {
        let mut addresses = BTreeMap::new();
        if let Some(address) = &self.call_host {
            addresses.insert(address.url.clone(), address.clone());
        }
        if let Some(spaces) = &self.spaces {
            for entry in &spaces.catalog.entries {
                if let Some(address) = &entry.address {
                    addresses.insert(address.url.clone(), address.clone());
                }
            }
        }
        addresses.into_values().collect()
    }
    pub(super) fn account_hosts(&self) -> Result<BTreeSet<String>> {
        let mut hosts = BTreeSet::new();
        if let Some(spaces) = &self.spaces {
            hosts.extend(spaces.catalog.account_hosts.iter().cloned());
            for entry in &spaces.catalog.entries {
                if let Some(address) = &entry.address {
                    hosts.insert(super::account_deletion::endpoint(
                        &address.url,
                        self.allow_loopback,
                    )?);
                }
            }
            if let Some(creation) = &spaces.catalog.creation {
                hosts.insert(super::account_deletion::endpoint(
                    &creation.host,
                    self.allow_loopback,
                )?);
            }
        }
        Ok(hosts)
    }
    pub fn allows_default_space(&self) -> Result<bool> {
        let path = self.directory.join("spaces.age");
        if !path.try_exists()? {
            return Ok(true);
        }
        let catalog: Catalog = serde_json::from_slice(&Zeroizing::new(crypto::open_bytes(
            &vault::read_private(&path)?,
            self.session.age_identity(),
            512 * 1024,
        )?))?;
        Ok(!catalog.root_disconnected && catalog.entries.iter().any(|entry| entry.root))
    }
    /// Only a newly created profile enters setup; existing conversations are never migrated away.
    pub async fn begin_space_setup(&mut self) -> Result<()> {
        if self.directory.join("spaces.age").try_exists()? || self.spaces.is_some() {
            return Err("Space setup is only available for a new profile.".into());
        }
        self.enable_spaces().await?;
        let mut spaces = self.spaces.take().ok_or("Spaces unavailable.")?;
        spaces.catalog.entries.clear();
        spaces.catalog.active = None;
        spaces.catalog.setup = true;
        let result = spaces.save(self);
        self.spaces = Some(spaces);
        result
    }
    pub async fn join_default_space(
        &mut self,
        peer: PeerDescriptor,
        team: team::TeamDescriptor,
    ) -> Result<()> {
        let mut spaces = self.spaces.take().ok_or("Spaces unavailable.")?;
        let result: Result<()> = async {
            team.validate(self.allow_loopback)?;
            let candidate = Peer::new(peer.clone(), self.allow_loopback)?;
            let id = team.scope.space.to_string();
            if spaces
                .catalog
                .entries
                .iter()
                .any(|e| e.id == id && e.status == "joined")
            {
                spaces.catalog.active = Some(id);
                spaces.catalog.setup = false;
                return spaces.save(self);
            }
            if spaces.catalog.entries.iter().any(|e| e.root && e.id != id) {
                return Err("The current Space cannot be replaced by Demo.".into());
            }
            if !spaces.catalog.entries.iter().any(|e| e.id == id)
                && spaces.catalog.entries.len() >= MAX_SPACES
            {
                return Err("Disconnect an unused Space first.".into());
            }
            for client in spaces.children.values() {
                if client
                    .peers
                    .iter()
                    .any(|p| p.id() == candidate.id() && p.mailbox() == candidate.mailbox())
                {
                    return Err("This mailbox is already connected as another Space.".into());
                }
            }
            self.ensure_peer(peer)?;
            let address = SpaceAddress {
                url: team.url.replace("/team/v1/enroll", "/team/v1/spaces"),
                scope: team.scope.clone(),
                message_lifetime_seconds: team.message_lifetime_seconds,
            };
            self.configure_team(team)?;
            if self.authorities.0.is_empty()
                && let Some(genesis) = &spaces.catalog.personal_genesis
                && self
                    .session
                    .can_control(decode_record(genesis)?.id().to_string().parse()?)
            {
                self.seed_personal_chat(genesis).await?;
            }
            let entry = Entry {
                id: id.clone(),
                name: "Demo".into(),
                root: true,
                status: "joined".into(),
                owner: false,
                contact_email: None,
                message_lifetime_seconds: address.message_lifetime_seconds,
                address: Some(address),
                requests: 0,
                role: String::new(),
                roles_revision: 0,
                role_requests: vec![],
                membership_epoch: 0,
                _legacy_service_requests: false,
            };
            if let Some(previous) = spaces.catalog.entries.iter_mut().find(|e| e.id == id) {
                *previous = entry;
            } else {
                spaces.catalog.entries.push(entry);
            }
            spaces.catalog.active = Some(id);
            spaces.catalog.root_disconnected = false;
            spaces.catalog.setup = false;
            spaces.save(self)
        }
        .await;
        self.spaces = Some(spaces);
        result
    }
    /// Called after build configuration. An existing catalog always wins: a
    /// deliberately disconnected Demo must never be added back on unlock.
    pub async fn enable_spaces(&mut self) -> Result<()> {
        if self.spaces.is_some() {
            return Ok(());
        }
        let path = self.directory.join("spaces.age");
        let catalog: Catalog = if path.try_exists()? {
            serde_json::from_slice(&Zeroizing::new(crypto::open_bytes(
                &vault::read_private(&path)?,
                self.session.age_identity(),
                512 * 1024,
            )?))?
        } else {
            let address = self.team.as_ref().map(|team| SpaceAddress {
                url: team.url.replace("/team/v1/enroll", "/team/v1/spaces"),
                scope: team.scope.clone(),
                message_lifetime_seconds: team.message_lifetime_seconds,
            });
            let id = address
                .as_ref()
                .map(|a| a.scope.space.to_string())
                .unwrap_or(record::random_hex::<32>()?);
            let personal_genesis = self
                .authorities
                .0
                .iter()
                .find(|a| {
                    self.require_controller(a).is_ok()
                        && a.controller().identity() == self.identity_id()
                        && a.initial_controller().id() == self.session.credential().id()
                })
                .map(|a| STANDARD.encode(a.genesis().bytes()));
            Catalog {
                v: 1,
                setup: false,
                creation: None,
                creation_retry: None,
                notification_generation: 0,
                account_hosts: BTreeSet::new(),
                active: Some(id.clone()),
                entries: vec![Entry {
                    id,
                    name: if address.is_some() {
                        "Demo"
                    } else {
                        "Personal"
                    }
                    .into(),
                    root: true,
                    status: "joined".into(),
                    owner: false,
                    contact_email: None,
                    message_lifetime_seconds: address
                        .as_ref()
                        .map(|value| value.message_lifetime_seconds)
                        .unwrap_or(86_400),
                    address,
                    requests: 0,
                    role: String::new(),
                    roles_revision: 0,
                    role_requests: vec![],
                    membership_epoch: 0,
                    _legacy_service_requests: false,
                }],
                garbage: vec![],
                root_disconnected: false,
                personal_genesis,
            }
        };
        if catalog.v != 1
            || catalog.entries.len() > MAX_SPACES
            || catalog.garbage.len() > MAX_SPACES
            || catalog.entries.iter().filter(|e| e.root).count() > 1
            || (catalog.root_disconnected && catalog.entries.iter().any(|e| e.root))
        {
            return Err("Invalid Space catalog.".into());
        }
        let mut unique = BTreeSet::new();
        for entry in &catalog.entries {
            safe_id(&entry.id)?;
            if !unique.insert(&entry.id)
                || !["pending", "joined", "declined", "checking"].contains(&entry.status.as_str())
                || !record::valid_display_name(&entry.name)
            {
                return Err("Invalid Space catalog.".into());
            }
            if let Some(address) = &entry.address {
                address.validate(self.allow_loopback)?;
                if address.scope.space.to_string() != entry.id {
                    return Err("Space catalog scope mismatch.".into());
                }
            }
        }
        let mut garbage = BTreeSet::new();
        for id in &catalog.garbage {
            safe_id(id)?;
            if unique.contains(id) || !garbage.insert(id) {
                return Err("Invalid disconnected Space catalog.".into());
            }
        }
        if catalog.active.as_ref().is_some_and(|id| {
            !catalog
                .entries
                .iter()
                .any(|e| &e.id == id && e.status == "joined")
        }) {
            return Err("Invalid selected Space.".into());
        }
        let mut spaces = Spaces {
            catalog,
            children: BTreeMap::new(),
            next_poll: 0,
            sync_round: 0,
            invitation_round: 0,
            invitation_force: false,
            sync_backlog: BTreeSet::new(),
        };
        if spaces.catalog.root_disconnected {
            spaces.purge_root(self).await?;
        }
        for id in spaces.catalog.garbage.clone() {
            remove_child(&child_path(self, &id)?)?;
        }
        spaces.catalog.garbage.clear();
        for entry in &spaces.catalog.entries {
            if entry.root || entry.status != "joined" {
                continue;
            }
            let path = child_path(self, &entry.id)?;
            check_directory(&self.directory.join("spaces"))?;
            check_directory(&path)?;
            let mut child = self.open_space_child(path, entry.id.parse()?).await?;
            if child.identity_id() != self.identity_id()
                || child.session.credential().id() != self.session.credential().id()
            {
                child.close().await?;
                return Err("Space profile identity mismatch.".into());
            }
            if let Some(address) = &entry.address {
                child.configure_space_team(address)?;
            }
            child.push_endpoint = self.push_endpoint.clone();
            child.push_allow_loopback = self.push_allow_loopback;
            child.profile_details = self.profile_details.clone();
            child.blocked = self.blocked.clone();
            spaces.children.insert(entry.id.clone(), child);
        }
        spaces.save(self)?;
        if spaces
            .catalog
            .entries
            .iter()
            .any(|e| e.status == "checking")
        {
            spaces.poll(self).await?;
        }
        self.spaces = Some(Box::new(spaces));
        Ok(())
    }
    async fn open_space_child(&self, path: PathBuf, space: SpaceId) -> Result<ClientApp> {
        if path.join(".initializing").exists() {
            return Err("Space initialization was interrupted.".into());
        }
        let vault = vault::read_private(&path.join("vault.age"))?;
        let cache_path = path.join(VAULT_CACHE);
        let cached = vault::read_private(&cache_path).ok().and_then(|bytes| {
            Session::from_profile_cache(&bytes, &self.session, space, &vault).ok()
        });
        let cache_missing = cached.is_none();
        let session = match cached {
            Some(session) => session,
            None => Session::open(&vault, self.password.clone(), self.identity_id())?,
        };
        if session.credential().id() != self.session.credential().id() {
            return Err("Space profile identity mismatch.".into());
        }
        let cache = if cache_missing {
            Some(session.cache_for_profile(&self.session, space, &vault)?)
        } else {
            None
        };
        let child =
            ClientApp::open_session(path, self.password.clone(), self.allow_loopback, session)
                .await?;
        // A missing/unwritable cache must never prevent an authenticated open.
        if let Some(cache) = cache {
            let _ = vault::write_private(&cache_path, &cache, true);
        }
        Ok(child)
    }
    pub(super) fn quarantine_restored_spaces(&self) -> Result<()> {
        let path = self.directory.join("spaces.age");
        if !path.exists() {
            return Ok(());
        }
        let mut catalog: Catalog = serde_json::from_slice(&Zeroizing::new(crypto::open_bytes(
            &vault::read_private(&path)?,
            self.session.age_identity(),
            512 * 1024,
        )?))?;
        for entry in &mut catalog.entries {
            if entry.address.is_some() && entry.status == "joined" {
                entry.status = "checking".into();
                entry.owner = false;
                entry.role_requests.clear();
                entry.requests = 0;
            }
        }
        if catalog.active.as_ref().is_some_and(|id| {
            catalog
                .entries
                .iter()
                .any(|e| &e.id == id && e.status != "joined")
        }) {
            catalog.active = None;
        }
        let plain = Zeroizing::new(serde_json::to_vec(&catalog)?);
        vault::write_private(
            &path,
            &crypto::seal_bytes(
                &plain,
                &[self.session.age_identity().to_public()],
                512 * 1024,
            )?,
            true,
        )?;
        Ok(())
    }
    fn configure_space_team(&mut self, address: &SpaceAddress) -> Result<()> {
        // No reusable enrollment token is stored in a joined Space. Future
        // discovery accepts only the pinned administrator's signed membership.
        self.configure_team(team::TeamDescriptor {
            v: 1,
            url: address.url.replace("/team/v1/spaces", "/team/v1/enroll"),
            token: "00".repeat(32),
            scope: address.scope.clone(),
            message_lifetime_seconds: address.message_lifetime_seconds,
        })?;
        self.call_host = Some(address.clone());
        Ok(())
    }
    pub fn connected_space_ids(&self) -> Vec<String> {
        self.spaces
            .as_ref()
            .map(|s| {
                s.catalog
                    .entries
                    .iter()
                    .filter(|e| e.status == "joined")
                    .map(|e| e.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn active_space_id(&self) -> Option<&str> {
        self.spaces
            .as_ref()
            .and_then(|s| s.catalog.active.as_deref())
    }
    pub(super) fn selected_space_client(&self) -> Result<&ClientApp> {
        let Some(spaces) = &self.spaces else {
            return Ok(self);
        };
        match spaces.selected_child_id()? {
            Some(id) => spaces
                .children
                .get(id)
                .ok_or_else(|| "Space unavailable.".into()),
            None => Ok(self),
        }
    }
    pub(super) fn selected_space_client_mut(&mut self) -> Result<&mut ClientApp> {
        let child = self
            .spaces
            .as_ref()
            .map(|spaces| spaces.selected_child_id().map(|id| id.map(str::to_owned)))
            .transpose()?
            .flatten();
        match child {
            Some(id) => self
                .spaces
                .as_mut()
                .unwrap()
                .children
                .get_mut(&id)
                .ok_or_else(|| "Space unavailable.".into()),
            None => Ok(self),
        }
    }
    pub fn notification_generation(&self) -> u64 {
        self.spaces
            .as_ref()
            .map(|s| s.catalog.notification_generation)
            .unwrap_or(0)
    }
    pub fn has_spaces_catalog(&self) -> bool {
        self.directory.join("spaces.age").exists()
    }
}
pub(super) fn restore_file_removed(
    directory: &Path,
    session: &Session,
    name: &str,
) -> Result<bool> {
    let path = directory.join("spaces.age");
    if !path.exists() {
        return Ok(false);
    }
    let catalog: Catalog = serde_json::from_slice(&Zeroizing::new(crypto::open_bytes(
        &vault::read_private(&path)?,
        session.age_identity(),
        512 * 1024,
    )?))?;
    if let Some(id) = name
        .strip_prefix("spaces/")
        .and_then(|s| s.split('/').next())
    {
        safe_id(id)?;
        return Ok(!catalog.entries.iter().any(|e| e.id == id));
    }
    Ok(catalog.root_disconnected && DATA_FILES.contains(&name))
}
impl Spaces {
    fn save(&self, root: &ClientApp) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.catalog)?);
        vault::write_private(
            &root.directory.join("spaces.age"),
            &crypto::seal_bytes(
                &plain,
                &[root.session.age_identity().to_public()],
                512 * 1024,
            )?,
            true,
        )?;
        Ok(())
    }
    pub(super) fn awaiting_verification(&self) -> bool {
        self.catalog.entries.iter().any(|e| e.status == "checking")
    }
    pub(super) fn children(&self) -> &BTreeMap<String, ClientApp> {
        &self.children
    }
    fn selected_child_id(&self) -> Result<Option<&str>> {
        let id = self
            .catalog
            .active
            .as_deref()
            .ok_or("Join a Space first.")?;
        let entry = self
            .catalog
            .entries
            .iter()
            .find(|entry| entry.id == id && entry.status == "joined")
            .ok_or("Space unavailable.")?;
        Ok((!entry.root).then_some(id))
    }
    pub(super) async fn close(self) -> Result<()> {
        for (_, child) in self.children {
            Box::pin(child.close()).await?;
        }
        Ok(())
    }
    /// Profile-wide device linking needs a live Space transport, not the root
    /// vault's pre-Spaces peer list. Prefer the selected Space and exclude
    /// pending, disconnected and recovery-unverified entries.
    pub(super) fn pairing_client<'a>(&'a self, root: &'a ClientApp) -> Option<&'a ClientApp> {
        let eligible = |entry: &Entry| {
            if entry.status != "joined" {
                return None;
            }
            let client = if entry.root {
                root
            } else {
                self.children.get(&entry.id)?
            };
            client
                .session
                .peers()
                .iter()
                .any(|peer| peer.write_token.is_some())
                .then_some(client)
        };
        self.catalog
            .entries
            .iter()
            .find(|entry| Some(entry.id.as_str()) == self.catalog.active.as_deref())
            .and_then(eligible)
            .or_else(|| self.catalog.entries.iter().find_map(eligible))
    }
    pub(super) fn clients<'a>(&'a self, root: &'a ClientApp) -> Vec<&'a ClientApp> {
        let mut values = Vec::new();
        if self
            .catalog
            .entries
            .iter()
            .any(|entry| entry.root && entry.status == "joined")
        {
            values.push(root);
        }
        values.extend(self.children.values());
        values
    }
    pub(super) async fn view(&self, root: &ClientApp) -> Result<Value> {
        if root.presentation.enabled() {
            for child in self.children.values() {
                child.enable_paged_views();
            }
        }
        let entry = self
            .catalog
            .active
            .as_ref()
            .and_then(|id| self.catalog.entries.iter().find(|e| &e.id == id));
        let mut view = if let Some(entry) = entry {
            if entry.root {
                root.view_local().await?
            } else {
                self.children
                    .get(&entry.id)
                    .ok_or("Space is unavailable.")?
                    .view_local()
                    .await?
            }
        } else {
            let mut value = root.view_local().await?;
            for key in ["streams", "contacts", "groups", "reminders", "replicas"] {
                value[key] = json!([]);
            }
            value["invitations"] = json!({"enabled":false,"actionable":0,"notifications":0});
            value
        };
        view["name"] = json!(root.profile_details.as_ref().map(|p| &p.name));
        view["avatar"] = json!(
            root.profile_details
                .as_ref()
                .and_then(|p| p.avatar.as_ref())
        );
        view["active_space"] = json!(self.catalog.active);
        view["space_setup"] =
            json!(self.catalog.setup || !self.catalog.entries.iter().any(|e| e.status == "joined"));
        view["space_creation"] = self
            .catalog
            .creation
            .as_ref()
            .map(|c| json!({"name":c.name,"contact_email":c.contact_email,"message_lifetime_seconds":c.message_lifetime_seconds,"space":c.space,"invitation":c.invitation}))
            .unwrap_or(Value::Null);
        view["space_role_requests"] = json!(self.catalog.entries.iter().flat_map(|e|e.role_requests.iter().map(|request|json!({"space_id":e.id,"space_name":e.name,"revision":e.roles_revision,"request":request}))).collect::<Vec<_>>());
        if let Some(streams) = view["streams"].as_array_mut() {
            for stream in streams {
                stream["space_context"] = json!(self.catalog.active);
            }
        }

        view["spaces"] = json!(self.catalog.entries.iter().map(|e|json!({"id":e.id,"name":e.name,"status":e.status,"owner":e.owner,"requests":e.requests,"managed":e.address.is_some(),"role":e.role,"contact_email":e.contact_email,"message_lifetime_seconds":e.message_lifetime_seconds,"roles_revision":e.roles_revision,"deletable":e.address.as_ref().and_then(|a|reqwest::Url::parse(&a.url).ok()).is_some_and(|u|u.path().starts_with("/spaces/"))})).collect::<Vec<_>>());
        view["space_requests"] = json!(
            self.catalog
                .entries
                .iter()
                .map(|e| e.requests)
                .sum::<usize>()
        );
        // Foreground notification detection and explicit reminders must continue
        // across Spaces without exposing foreign rows in Messages or Buzz.
        let mut background = Vec::new();
        let mut reminders = Vec::new();
        let mut actionable = 0u64;
        let mut notifications = 0u64;
        for e in self.catalog.entries.iter().filter(|e| e.status == "joined") {
            let data = if self.catalog.active.as_deref() == Some(&e.id) {
                view.clone()
            } else if e.root {
                root.view_local().await?
            } else {
                self.children
                    .get(&e.id)
                    .ok_or("Space unavailable.")?
                    .view_local()
                    .await?
            };
            let count = data["invitations"]["actionable"].as_u64().unwrap_or(0);
            let notices = data["invitations"]["notifications"].as_u64().unwrap_or(0);
            actionable += count;
            notifications += notices;
            if let Some(entries) = view["spaces"].as_array_mut()
                && let Some(entry) = entries.iter_mut().find(|entry| entry["id"] == e.id)
            {
                entry["activity"] = json!(count + notices);
            }
            for mut stream in data["streams"].as_array().cloned().unwrap_or_default() {
                stream["space_context"] = json!(e.id);
                background.push(stream);
            }
            for mut reminder in data["reminders"].as_array().cloned().unwrap_or_default() {
                reminder["space_context"] = json!(e.id);
                reminders.push(reminder);
            }
        }
        view["all_invitations"] = json!({"actionable":actionable,"notifications":notifications});
        view["all_streams"] = json!(background);
        view["all_reminders"] = json!(reminders);
        Ok(view)
    }
    async fn purge_root(&self, root: &mut ClientApp) -> Result<()> {
        for name in DATA_FILES {
            let path = root.directory.join(name);
            if path.try_exists()? {
                let meta = std::fs::symlink_metadata(path)?;
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err("Unsafe Space data file.".into());
                }
            }
        }
        // A previous cleanup attempt may have closed the worker before a later
        // file/vault write failed. Closed is safe to retry; unknown outcomes are not.
        if let Err(error) = root.store.close().await
            && !matches!(error, crate::store::StoreError::Closed)
        {
            return Err(error.into());
        }
        for name in DATA_FILES {
            let path = root.directory.join(name);
            if path.try_exists()? {
                let meta = std::fs::symlink_metadata(&path)?;
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err("Unsafe Space data file.".into());
                }
                std::fs::remove_file(path)?;
            }
        }
        root.pins.clear();
        root.groups.clear();
        root.authorities.0.clear();
        root.read = ReadState {
            v: 1,
            ..ReadState::default()
        }
        .into();
        root.peers.clear();
        root.team = None;
        // Cleanup is retried on unlock, but an already empty vault must not be
        // re-encrypted (and recalibrate scrypt) every time. Retain the old peers
        // on write failure so an in-process retry still persists their removal.
        if !root.session.peers().is_empty() {
            let mut previous = std::mem::take(&mut root.session.peers);
            if let Err(error) = root.persist_vault() {
                root.session.peers = previous;
                return Err(error);
            }
            use zeroize::Zeroize;
            for peer in &mut previous {
                peer.read_token.zeroize();
                peer.write_token.zeroize();
            }
        }
        root.store = ClientStore::open(&root.directory).await?;
        Ok(())
    }
    async fn disconnect(&mut self, root: &mut ClientApp, id: &str) -> Result<()> {
        let entry = self
            .catalog
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or("Space not found.")?
            .clone();
        let previous = self.catalog.clone();
        self.catalog.notification_generation = self
            .catalog
            .notification_generation
            .checked_add(1)
            .ok_or("Notification generation limit reached.")?;
        if let Some(address) = &entry.address {
            self.catalog
                .account_hosts
                .insert(super::account_deletion::endpoint(
                    &address.url,
                    root.allow_loopback,
                )?);
        }
        self.catalog.entries.retain(|e| e.id != id);
        if self.catalog.active.as_deref() == Some(id) {
            self.catalog.active = self
                .catalog
                .entries
                .iter()
                .find(|e| e.status == "joined")
                .map(|e| e.id.clone());
        }
        if entry.root {
            self.catalog.root_disconnected = true;
        } else {
            self.catalog.garbage.push(id.into());
        }
        if let Err(error) = self.save(root) {
            self.catalog = previous;
            return Err(error);
        }
        if let Some(child) = self.children.remove(id) {
            child.close().await?;
        }
        if entry.root {
            self.purge_root(root).await?;
        } else {
            remove_child(&child_path(root, id)?)?;
        }
        self.catalog.garbage.retain(|old| old != id);
        self.save(root)?;
        Ok(())
    }
    async fn add_joined(
        &mut self,
        root: &mut ClientApp,
        address: SpaceAddress,
        result: Value,
    ) -> Result<String> {
        let id = address.scope.space.to_string();
        let status = field(&result, "status")?;
        if let Some(previous) = self
            .catalog
            .entries
            .iter()
            .find(|e| e.id == id)
            .and_then(|e| e.address.as_ref())
            && serde_json::to_value(previous)? != serde_json::to_value(&address)?
        {
            return Err("Space address changed. Data was preserved.".into());
        }

        if status == "deleted" || status == "removed" {
            if self
                .catalog
                .creation
                .as_ref()
                .is_some_and(|c| c.space.as_deref() == Some(&id))
            {
                self.catalog.creation = None;
            }
            if self.catalog.entries.iter().any(|e| e.id == id) {
                self.disconnect(root, &id).await?;
            }
            return Ok(id);
        }
        let name = field(&result, "name")?;
        if !record::valid_display_name(name)
            || !["pending", "approved", "declined"].contains(&status)
        {
            return Err("Invalid Space membership response.".into());
        }
        // A later admission epoch cannot resurrect history from before removal,
        // even when this device was offline throughout removal and rejoining.
        if let Some(previous) = self.catalog.entries.iter().find(|e| e.id == id) {
            if previous.address.as_ref().is_some_and(|a| {
                serde_json::to_value(a).ok() != serde_json::to_value(&address).ok()
            }) {
                return Err("Space address changed. Data was preserved.".into());
            }
            if result["membership_epoch"].as_u64().unwrap_or(0) > previous.membership_epoch {
                self.disconnect(root, &id).await?;
            }
        }
        let old = self.catalog.entries.iter().position(|e| e.id == id);
        if let Some(previous) = old.and_then(|i| self.catalog.entries[i].address.as_ref())
            && serde_json::to_value(previous)? != serde_json::to_value(&address)?
        {
            return Err(
                "This Space has a different address or signing key. Its data was preserved.".into(),
            );
        }
        if old.is_none() && self.catalog.entries.len() >= MAX_SPACES {
            return Err("Disconnect an unused Space first.".into());
        }
        if status == "approved" {
            let peer: PeerDescriptor = serde_json::from_value(result["peer"].clone())?;
            let candidate = Peer::new(peer.clone(), root.allow_loopback)?;
            // The same mailbox cannot silently represent two distinct Spaces.
            for e in self
                .catalog
                .entries
                .iter()
                .filter(|e| e.id != id && e.status == "joined")
            {
                let client = if e.root {
                    &*root
                } else {
                    self.children.get(&e.id).ok_or("Space unavailable.")?
                };
                if client
                    .peers
                    .iter()
                    .any(|p| p.id() == candidate.id() && p.mailbox() == candidate.mailbox())
                {
                    return Err("This mailbox is already connected as another Space.".into());
                }
            }
            let enrollment: Option<team::EnrollmentReply> =
                serde_json::from_value(result["enrollment"].clone())?;
            if enrollment.is_none() {
                let existing = if old.is_some_and(|i| self.catalog.entries[i].root) {
                    &*root
                } else {
                    self.children.get(&id).ok_or("Invalid Space response.")?
                };
                let general = existing
                    .authorities
                    .0
                    .iter()
                    .find(|a| {
                        a.space() == address.scope.space && a.stream() == address.scope.stream
                    })
                    .ok_or("Invalid Space response.")?;
                if result["general_head"] != json!(general.head_id())
                    || crate::calls::require_member(general, existing.session.credential().id())
                        .is_err()
                {
                    return Err("Chat permissions need to be refreshed.".into());
                }
            }
            if old.is_some_and(|i| self.catalog.entries[i].root) {
                // Migration never replaces or rewrites existing profile data.
                if let Some(enrollment) = enrollment {
                    root.accept_space_enrollment(enrollment).await?;
                }
            } else if let Some(child) = self.children.get_mut(&id) {
                if let Some(enrollment) = enrollment {
                    child.accept_space_enrollment(enrollment).await?;
                }
            } else {
                let enrollment = enrollment.ok_or("Invalid Space response.")?;
                let directory = child_path(root, &id)?;
                let parent = root.directory.join("spaces");
                if !parent.try_exists()? {
                    make_directory(&parent)?;
                } else {
                    check_directory(&parent)?;
                }
                let created = !directory.try_exists()?;
                let new_session = if created {
                    make_directory(&directory)?;
                    let mut session = root.session.isolated_space();
                    session.set_peers(vec![peer])?;
                    // Include our verified personal controller scope in the first
                    // durable vault write, before seeding its empty local chat.
                    if let Some(encoded) = &self.catalog.personal_genesis
                        && root
                            .session
                            .can_control(decode_record(encoded)?.id().to_string().parse()?)
                        && let Some(authority) =
                            ClientApp::personal_chat_authority(&session, encoded)?
                    {
                        session.activate_new_space_controller(authority.space())?;
                    }
                    vault::write_private(
                        &directory.join("vault.age"),
                        &session.seal(root.password.clone())?,
                        false,
                    )?;
                    vault::write_private(
                        &directory.join("profile.json"),
                        &vault::read_private(&root.directory.join("profile.json"))?,
                        false,
                    )?;
                    Some(session)
                } else {
                    check_directory(&directory)?;
                    None
                };

                let mut child = if let Some(session) = new_session {
                    ClientApp::open_session(
                        directory.clone(),
                        root.password.clone(),
                        root.allow_loopback,
                        session,
                    )
                    .await?
                } else {
                    ClientApp::open(
                        directory.clone(),
                        root.password.clone(),
                        root.allow_loopback,
                    )
                    .await?
                };
                let initialized: Result<()> = async {
                    if child.identity_id() != root.identity_id()
                        || child.session.credential().id() != root.session.credential().id()
                        || child.peers.len() != 1
                        || child.peers[0].id() != candidate.id()
                        || child.peers[0].mailbox() != candidate.mailbox()
                    {
                        return Err(
                            "Existing Space data does not match this invitation. It was preserved."
                                .into(),
                        );
                    }
                    child.profile_details = root.profile_details.clone();
                    child.blocked = root.blocked.clone();
                    child.configure_space_team(&address)?;
                    child.push_endpoint = root.push_endpoint.clone();
                    child.push_allow_loopback = root.push_allow_loopback;
                    child.accept_space_enrollment(enrollment).await?;
                    if let Some(genesis) = &self.catalog.personal_genesis {
                        let signed = decode_record(genesis)?;
                        let body: SpaceGenesis = signed.decode()?;
                        if root.session.can_control(signed.id().to_string().parse()?)
                            && !child.pins.iter().any(|pin| {
                                body.owners
                                    .iter()
                                    .any(|owner| pin.root == owner.root_public_key)
                            })
                        {
                            child.seed_personal_chat(genesis).await?;
                        }
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = initialized {
                    child.close().await?;
                    if created {
                        remove_child(&directory)?;
                    }
                    return Err(error);
                }
                if let Ok(bytes) = vault::read_private(&directory.join("vault.age"))
                    && let Ok(cache) =
                        child
                            .session
                            .cache_for_profile(&root.session, id.parse()?, &bytes)
                {
                    let _ = vault::write_private(&directory.join(VAULT_CACHE), &cache, true);
                }
                self.children.insert(id.clone(), child);
            }
        }
        let entry = Entry {
            id: id.clone(),
            name: name.into(),
            root: old.is_some_and(|i| self.catalog.entries[i].root),
            status: if status == "approved" {
                "joined"
            } else {
                status
            }
            .into(),
            owner: result["owner"] == true,
            contact_email: result["contact_email"]
                .as_str()
                .filter(|email| super::space_service::validate_contact_email(email).is_ok())
                .map(str::to_owned),
            message_lifetime_seconds: address.message_lifetime_seconds,
            address: Some(address),
            requests: if result["owner"] == true {
                old.map(|i| self.catalog.entries[i].requests).unwrap_or(0)
            } else {
                0
            },
            role: result["role"]
                .as_str()
                .unwrap_or(if result["owner"] == true {
                    "owner"
                } else {
                    "member"
                })
                .into(),
            membership_epoch: result["membership_epoch"].as_u64().unwrap_or(0),
            _legacy_service_requests: false,
            roles_revision: result["roles_revision"].as_u64().unwrap_or(0),
            role_requests: result["role_requests"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        };
        if let Some(i) = old {
            self.catalog.entries[i] = entry;
        } else {
            self.catalog.entries.push(entry);
        }
        if status == "approved" && self.catalog.active.is_none() {
            self.catalog.active = Some(id.clone());
        }
        if status == "approved" && self.catalog.creation.is_none() {
            self.catalog.setup = false;
        }
        self.save(root)?;
        Ok(id)
    }
    async fn create(&mut self, root: &mut ClientApp, request: &Value) -> Result<()> {
        let host = field(request, "host")?;
        super::space_host::validate_host(host, root.allow_loopback)?;
        let email = field(request, "contact_email")?.trim();
        super::space_service::validate_contact_email(email)?;
        let message_lifetime_seconds = request["message_lifetime_seconds"]
            .as_u64()
            .ok_or("Choose a server message lifetime.")?;
        super::space_service::validate_message_lifetime(message_lifetime_seconds)?;
        // A client may be rebuilt for another hosting service while an earlier
        // creation was still only a local intent. Do not strand the new build
        // on that uncompleted endpoint; a joined Space is never discarded.
        if self
            .catalog
            .creation
            .as_ref()
            .is_some_and(|intent| intent.host != host && intent.space.is_none())
        {
            self.catalog.creation = None;
            self.save(root)?;
        }
        if let Some(intent) = &self.catalog.creation {
            if intent.host != host
                || request["name"].as_str().is_some_and(|n| n != intent.name)
                || (!intent.contact_email.is_empty() && email != intent.contact_email)
                || message_lifetime_seconds != intent.message_lifetime_seconds
            {
                return Err("Continue the pending Space creation first.".into());
            }
        } else {
            if self.catalog.entries.len() >= MAX_SPACES {
                return Err("Disconnect an unused Space first.".into());
            }
            let name = field(request, "name")?.trim();
            if !record::valid_display_name(name) {
                return Err("Enter a Space name.".into());
            }
            // A failed join may follow a successful server allocation. Reuse
            // its idempotency key for unchanged input without locking the form.
            let retry = self.catalog.creation_retry.take().filter(|intent| {
                intent.host == host
                    && intent.name == name
                    && intent.contact_email == email
                    && intent.message_lifetime_seconds == message_lifetime_seconds
            });
            self.catalog.creation = Some(retry.unwrap_or(CreationIntent {
                contact_email: email.into(),
                host: host.into(),
                request_id: record::random_hex::<16>()?,
                name: name.into(),
                message_lifetime_seconds,
                space: None,
                invitation: None,
            }));
            // Persist before the network request: retries after termination use
            // exactly the same identity and creation ID on the host.
            self.save(root)?;
        }
        if self
            .catalog
            .creation
            .as_ref()
            .is_some_and(|c| c.contact_email.is_empty())
        {
            self.catalog.creation.as_mut().unwrap().contact_email = email.into();
            self.save(root)?;
        }
        let intent = self
            .catalog
            .creation
            .clone()
            .ok_or("Space creation unavailable.")?;
        if intent.invitation.is_some() {
            return Ok(());
        }
        let link = root
            .create_hosted(
                host,
                &intent.request_id,
                &intent.name,
                &intent.contact_email,
                intent.message_lifetime_seconds,
            )
            .await?;
        let invite = SpaceInvitation::parse(&link, root.allow_loopback)?;
        let enrollment = root.team_enrollment_request(&invite.address.scope)?;
        let response = root
            .call_space(
                &invite.address,
                "join",
                json!({"token":invite.token,"enrollment":enrollment}),
            )
            .await?;
        if response["status"] != "approved" || response["role"] != "primary_owner" {
            return Err("The hosting service did not confirm your Space ownership.".into());
        }
        let id = self
            .add_joined(root, invite.address.clone(), response)
            .await?;
        self.catalog.active = Some(id.clone());
        self.catalog.creation.as_mut().unwrap().space = Some(id);
        self.save(root)?;
        // The host's bootstrap invitation is reusable and already requires
        // approval. Reuse it for sharing instead of creating a second offer.
        self.catalog.creation.as_mut().unwrap().invitation = Some(link);
        self.catalog.creation_retry = None;
        self.save(root)
    }
    async fn poll(&mut self, root: &mut ClientApp) -> Result<()> {
        let time = now()?.as_millis() as u64;
        if self.next_poll > time {
            return Ok(());
        }
        self.next_poll = time + 30_000;
        for entry in self.catalog.entries.clone() {
            self.poll_entry(root, entry, false).await?;
        }
        self.save(root)
    }
    async fn poll_entry(
        &mut self,
        root: &mut ClientApp,
        entry: Entry,
        foreground: bool,
    ) -> Result<bool> {
        let Some(address) = entry.address else {
            return Ok(false);
        };
        // Only the read-only network request is cancellable. Verified
        // enrollment, revocation and local journal commits finish normally.
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(if foreground { 2 } else { 24 });
        let enrollment = root.team_enrollment_request(&address.scope)?;
        let client = if entry.root {
            Some(&*root)
        } else {
            self.children.get(&entry.id)
        };
        let probe = client.and_then(|client| client.membership_probe().ok());
        let general_head = client.and_then(|client| {
            client
                .authorities
                .0
                .iter()
                .find(|a| a.space() == address.scope.space && a.stream() == address.scope.stream)
                .and_then(Authority::head_id)
        });
        let mut body = json!({"enrollment":enrollment,"known_general_head":general_head,"membership_epoch":entry.membership_epoch});
        if let Some(probe) = &probe {
            body["chat_heads"] = json!(probe.requests);
        }
        let status =
            tokio::time::timeout_at(deadline, root.call_space(&address, "status", body)).await;
        if let Ok(Ok(result)) = status {
            let confirmations = json!({"chat_heads":result["chat_heads"]});
            if self
                .add_joined(root, address.clone(), result)
                .await
                .is_err()
            {
                return Ok(true);
            }
            if let Some(probe) = probe {
                let client = if entry.root {
                    Some(&*root)
                } else {
                    self.children.get(&entry.id)
                };
                if let Some(client) = client {
                    client
                        .accept_membership_probe(probe, &confirmations)
                        .await?;
                }
            }
        } else {
            return Ok(true);
        }
        if self
            .catalog
            .entries
            .iter()
            .any(|e| e.id == entry.id && e.owner)
            && let Ok(Ok(manage)) =
                tokio::time::timeout_at(deadline, root.call_space(&address, "manage", json!({})))
                    .await
            && let Some(e) = self.catalog.entries.iter_mut().find(|e| e.id == entry.id)
        {
            e.requests = manage["requests"].as_array().map(Vec::len).unwrap_or(0);
        }
        Ok(false)
    }
    pub(super) fn history_clients<'a>(
        &'a self,
        root: &'a ClientApp,
    ) -> (Option<String>, Vec<(String, &'a ClientApp)>) {
        let clients = self
            .catalog
            .entries
            .iter()
            .filter(|entry| entry.status == "joined")
            .filter_map(|entry| {
                let client = if entry.root {
                    Some(root)
                } else {
                    self.children.get(&entry.id)
                }?;
                Some((entry.id.clone(), client))
            })
            .collect();
        (self.catalog.active.clone(), clients)
    }
    pub(super) async fn operate_attachment_transfer<F>(
        &mut self,
        root: &mut ClientApp,
        v: &Value,
        cancellation: AttachmentCancellation,
        progress: F,
    ) -> Result<Value>
    where
        F: Fn(u64, u64) + Send + Sync + 'static,
    {
        if v.get("expected_identity")
            .is_some_and(|id| id != &json!(root.identity_id()))
        {
            return Err("The open profile has changed.".into());
        }
        if let Some(expected) = v.get("expected_space")
            && expected != &json!(self.catalog.active)
        {
            return Err("The selected Space has changed. Try again.".into());
        }
        let op = field(v, "op")?;
        let id = self.catalog.active.clone().ok_or("Join a Space first.")?;
        let entry = self
            .catalog
            .entries
            .iter()
            .find(|entry| entry.id == id && entry.status == "joined")
            .ok_or("Space not found.")?;
        let address = entry
            .address
            .clone()
            .ok_or("Attachments are not available in this Space.")?;
        let result = if entry.root {
            if op == "attachment_upload" {
                root.upload_attachment_observed(&address, v, cancellation, progress)
                    .await?
            } else {
                root.download_attachment_observed(&address, v, cancellation, progress)
                    .await?
            }
        } else {
            let child = self.children.get_mut(&id).ok_or("Space unavailable.")?;
            if op == "attachment_upload" {
                child
                    .upload_attachment_observed(&address, v, cancellation, progress)
                    .await?
            } else {
                child
                    .download_attachment_observed(&address, v, cancellation, progress)
                    .await?
            }
        };
        let mut response = json!({"result":result});
        if op == "attachment_upload" {
            // The linked message is already committed. Publish its local view
            // now, rather than making the sender wait for network delivery.
            // A projection failure must not turn a committed send into a retry.
            if let Ok(view) = self.view(root).await {
                response["view"] = view;
            }
        }
        Ok(response)
    }
    pub(super) async fn operate(&mut self, root: &mut ClientApp, v: Value) -> Result<Value> {
        // Inner operations only mutate/report. Build one combined snapshot at
        // the Space boundary, or return the affected chat's partial snapshot.
        let _root_view = root.presentation.defer_view();
        let _child_views = self
            .children
            .values()
            .map(|child| child.presentation.defer_view())
            .collect::<Vec<_>>();
        if v.get("expected_identity")
            .is_some_and(|id| id != &json!(root.identity_id()))
        {
            return Err("The open profile has changed.".into());
        }
        let op = field(&v, "op")?;
        if let Some(expected) = v.get("expected_space")
            && expected != &json!(self.catalog.active)
            && !op.starts_with("space_")
        {
            return Err("The selected Space has changed. Try again.".into());
        }
        // Notification taps can read one verified message in a connected Space
        // before switching to it. Never change the active Space for a lookup.
        if op == "history_page" && v["target_space"].is_string() {
            let id = field(&v, "target_space")?;
            let entry = self
                .catalog
                .entries
                .iter()
                .find(|e| e.id == id && e.status == "joined")
                .ok_or("Space unavailable.")?;
            let mut result = if entry.root {
                root.history_page(&v).await?
            } else {
                self.children
                    .get(id)
                    .ok_or("Space unavailable.")?
                    .history_page(&v)
                    .await?
            };
            result["history"]["space_context"] = json!(id);
            return Ok(result);
        }
        let mut result = json!({});
        match op {
            "space_list" => {}
            "space_refresh" => {
                self.next_poll = 0;
                self.poll(root).await?;
            }
            "space_create" => {
                if let Err(error) = self.create(root, &v).await {
                    // Release the form for editing, but retain the allocation
                    // key so an unchanged retry cannot create a duplicate Space.
                    if self
                        .catalog
                        .creation
                        .as_ref()
                        .is_some_and(|intent| intent.space.is_none())
                    {
                        self.catalog.creation_retry = self.catalog.creation.take();
                        self.save(root)?;
                    }
                    return Err(error);
                }
            }
            "space_setup_done" => {
                if !self.catalog.entries.iter().any(|e| e.status == "joined") {
                    return Err("Create or join a Space first.".into());
                }
                self.catalog.creation = None;
                self.catalog.setup = false;
                self.save(root)?;
            }
            "space_select" => {
                let id = field(&v, "id")?;
                if !self
                    .catalog
                    .entries
                    .iter()
                    .any(|e| e.id == id && e.status == "joined")
                {
                    return Err("This Space is not ready yet.".into());
                }
                let old = self.catalog.active.replace(id.into());
                if let Err(error) = self.save(root) {
                    self.catalog.active = old;
                    return Err(error);
                }
            }
            "space_disconnect" => {
                if v["confirmed"] != true {
                    return Err("Confirm disconnecting this Space.".into());
                }
                self.disconnect(root, field(&v, "id")?).await?;
            }
            "space_preview" => {
                let invite = SpaceInvitation::parse(field(&v, "link")?, root.allow_loopback)?;
                result["preview"] = root.preview_space(&invite).await?;
                if result["preview"]["status"] == "deleted" {
                    return Err("This Space was deleted.".into());
                }
            }
            "space_join" => {
                #[cfg(debug_assertions)]
                let started = std::time::Instant::now();
                let note = super::space_service::join_note(&v)?;
                let invite = SpaceInvitation::parse(field(&v, "link")?, root.allow_loopback)?;
                let enrollment = root.team_enrollment_request(&invite.address.scope)?;
                #[cfg(debug_assertions)]
                let prepared = started.elapsed();
                let response = root
                    .call_space(
                        &invite.address,
                        "join",
                        json!({"token":invite.token,"enrollment":enrollment,"note":note}),
                    )
                    .await?;
                #[cfg(debug_assertions)]
                let received = started.elapsed();
                let id = self.add_joined(root, invite.address, response).await?;
                #[cfg(debug_assertions)]
                {
                    result["_space_join_timing"] = json!({
                        "prepare": prepared.as_millis(),
                        "server": received.saturating_sub(prepared).as_millis(),
                        "install": started.elapsed().saturating_sub(received).as_millis(),
                    });
                }
                if self
                    .catalog
                    .entries
                    .iter()
                    .any(|e| e.id == id && e.status == "joined")
                {
                    self.catalog.active = Some(id.clone());
                    self.save(root)?;
                }
                result["joined"] = json!(id);
            }
            "space_manage"
            | "space_invite"
            | "space_revoke"
            | "space_decide"
            | "space_role_change"
            | "space_role_decide"
            | "space_contact"
            | "space_contact_update"
            | "space_delete"
            | "space_storage"
            | "space_storage_prune"
            | "space_attachment_settings"
            | "space_attachment_retention"
            | "space_attachment_cleanup_preview"
            | "space_attachment_cleanup" => {
                let id = field(&v, "id")?;
                let entry = self
                    .catalog
                    .entries
                    .iter()
                    .find(|e| e.id == id)
                    .ok_or("Space not found.")?;
                let address = entry
                    .address
                    .clone()
                    .ok_or("This Space has no invitation service.")?;
                let action = op.strip_prefix("space_").ok_or("Invalid action.")?;
                if matches!(
                    op,
                    "space_decide" | "space_role_change" | "space_role_decide" | "space_delete"
                ) {
                    let client = if entry.root {
                        Some(&*root)
                    } else {
                        self.children.get(id)
                    };
                    if let Some(client) = client {
                        client.invalidate_membership_checks().await;
                    }
                }
                result["result"] = root.call_space(&address, action, v["body"].clone()).await?;
                if matches!(
                    result["result"]["status"].as_str(),
                    Some("deleted" | "removed")
                ) {
                    self.add_joined(root, address, result["result"].clone())
                        .await?;
                    result["view"] = self.view(root).await?;
                    return Ok(result);
                }
                if op == "space_manage" {
                    if let Some(entry) =
                        self.catalog.entries.iter_mut().find(|entry| entry.id == id)
                    {
                        entry.requests = result["result"]["requests"]
                            .as_array()
                            .map(Vec::len)
                            .unwrap_or(0);
                    }
                    self.save(root)?;
                }
                self.next_poll = 0;
                if matches!(
                    op,
                    "space_role_change" | "space_role_decide" | "space_contact_update"
                ) {
                    let enrollment = root.team_enrollment_request(&address.scope)?;
                    let status = root
                        .call_space(&address, "status", json!({"enrollment":enrollment}))
                        .await?;
                    self.add_joined(root, address, status).await?;
                }
            }
            "attachment_upload" | "attachment_download" => {
                let id = self.catalog.active.clone().ok_or("Join a Space first.")?;
                let entry = self
                    .catalog
                    .entries
                    .iter()
                    .find(|entry| entry.id == id && entry.status == "joined")
                    .ok_or("Space not found.")?;
                let address = entry
                    .address
                    .clone()
                    .ok_or("Attachments are not available in this Space.")?;
                result["result"] = if entry.root {
                    if op == "attachment_upload" {
                        root.upload_attachment(&address, &v).await?
                    } else {
                        root.download_attachment(&address, &v).await?
                    }
                } else {
                    let child = self.children.get_mut(&id).ok_or("Space unavailable.")?;
                    if op == "attachment_upload" {
                        child.upload_attachment(&address, &v).await?
                    } else {
                        child.download_attachment(&address, &v).await?
                    }
                };
            }
            "sync" | "sync_live" | "invitation_sync" => {
                let mut reports = Vec::new();
                let mut storage_full_spaces = Vec::new();
                let live = v["op"] == "sync_live";
                let foreground_discovery = op == "invitation_sync" && v["foreground"] == true;
                let mut poll_retry = false;
                let discovery_entry = if foreground_discovery && !self.catalog.entries.is_empty() {
                    let index = self.invitation_round % self.catalog.entries.len();
                    self.invitation_round = self.invitation_round.wrapping_add(1);
                    self.invitation_force |= v["force"] == true;
                    let entry = self.catalog.entries[index].clone();
                    let rest = index + 1 < self.catalog.entries.len();
                    poll_retry = self.poll_entry(root, entry.clone(), true).await?;
                    self.save(root)?;
                    Some((entry.id, rest))
                } else {
                    None
                };
                let mut v = v.clone();
                if foreground_discovery {
                    v["force"] = json!(self.invitation_force);
                    if discovery_entry.as_ref().is_none_or(|(_, rest)| !rest) {
                        self.invitation_force = false;
                    }
                }
                let ids = self
                    .catalog
                    .entries
                    .iter()
                    .filter(|e| e.status == "joined")
                    .map(|e| e.id.clone())
                    .collect::<Vec<_>>();
                let selected = if live && v["receive_only"] == true && v["target_space"].is_string()
                {
                    let id = field(&v, "target_space")?;
                    if !ids.iter().any(|joined| joined == id) {
                        return Err("Space unavailable.".into());
                    }
                    Some((id.to_owned(), false))
                } else if live && !ids.is_empty() {
                    let index = self.sync_round % ids.len();
                    self.sync_round = self.sync_round.wrapping_add(1);
                    Some((ids[index].clone(), index + 1 < ids.len()))
                } else {
                    None
                };
                for id in &ids {
                    if discovery_entry
                        .as_ref()
                        .is_some_and(|(selected, _)| selected != id)
                    {
                        continue;
                    }
                    if selected
                        .as_ref()
                        .is_some_and(|(selected, _)| selected != id)
                    {
                        continue;
                    }
                    let entry = self.catalog.entries.iter().find(|e| &e.id == id).unwrap();
                    let report = if entry.root {
                        root.operate_local(v.clone()).await
                    } else {
                        Box::pin(
                            self.children
                                .get_mut(id)
                                .ok_or("Space unavailable.")?
                                .operate_local(v.clone()),
                        )
                        .await
                    };
                    if live {
                        if report.as_ref().is_ok_and(|r| r["result"]["more"] == true) {
                            self.sync_backlog.insert(id.clone());
                        } else {
                            self.sync_backlog.remove(id);
                        }
                    }
                    if report
                        .as_ref()
                        .is_ok_and(|r| r["result"]["quota_exceeded"].as_u64().unwrap_or(0) > 0)
                    {
                        storage_full_spaces.push(json!({"id":id,"name":entry.name}));
                    }
                    reports.push(report);
                }
                self.sync_backlog.retain(|id| ids.contains(id));
                let mut summary = serde_json::Map::new();
                let mut received = Vec::new();
                let mut delivery_retry = u64::from(poll_retry);
                let mut delivery_more = false;
                let mut delivery_received = 0u64;
                let mut delivery_progressed = false;
                let mut report_more = false;
                for report in reports {
                    match report {
                        Ok(report) => {
                            report_more |= report["result"]["more"] == true;
                            delivery_retry += report["delivery"]["retry"].as_u64().unwrap_or(0);
                            delivery_more |= report["delivery"]["more"] == true;
                            delivery_received +=
                                report["delivery"]["received"].as_u64().unwrap_or(0);
                            delivery_progressed |= report["delivery"]["progressed"] == true;
                            if let Some(values) = report["result"].as_object() {
                                for (key, value) in values {
                                    if let Some(n) = value.as_u64() {
                                        let old =
                                            summary.get(key).and_then(Value::as_u64).unwrap_or(0);
                                        summary.insert(key.clone(), json!(old + n));
                                    }
                                }
                            }
                            received.extend(
                                report["result"]["received_messages"]
                                    .as_array()
                                    .cloned()
                                    .unwrap_or_default(),
                            );
                        }
                        Err(_) => {
                            delivery_retry += 1;
                            let old = summary.get("retry").and_then(Value::as_u64).unwrap_or(0);
                            summary.insert("retry".into(), json!(old + 1));
                        }
                    }
                }
                let changed = [
                    "downloaded",
                    "accepted",
                    "rejected",
                    "stored",
                    "held",
                    "waiting_for_proof",
                    "quarantined",
                    "generation_changes",
                    "repaired",
                    "repair_downloaded",
                    "repair_pending",
                ]
                .iter()
                .any(|key| summary.get(*key).and_then(Value::as_u64).unwrap_or(0) > 0);
                summary.insert("catching_up".into(), json!(!self.sync_backlog.is_empty()));
                let remaining_spaces = live && selected.as_ref().is_some_and(|(_, rest)| *rest);
                // A failed compartment must not delay receipt from the rest of
                // the round. Keep this distinct from backlog in the same Space.
                summary.insert("remaining_spaces".into(), json!(remaining_spaces));
                summary.insert(
                    "more".into(),
                    json!(
                        report_more
                            || (live && (!self.sync_backlog.is_empty() || remaining_spaces))
                    ),
                );
                summary.insert("storage_full_spaces".into(), json!(storage_full_spaces));
                summary.insert("received_messages".into(), json!(received));
                result["result"] = Value::Object(summary);
                let remaining_spaces = discovery_entry.as_ref().is_some_and(|(_, rest)| *rest);
                result["delivery"] = json!({"retry":delivery_retry,"more":delivery_more || remaining_spaces,"remaining_spaces":remaining_spaces,"received":delivery_received,"progressed":delivery_progressed});
                if !live && !foreground_discovery {
                    self.poll(root).await?;
                }
                if live && !changed {
                    result["view"] = Value::Null;
                    return Ok(result);
                }
            }
            "set_profile_name" | "set_profile_details" => {
                result = root.operate_local(v.clone()).await?;
                for child in self.children.values_mut() {
                    child.profile_details = root.profile_details.clone();
                }
            }
            "view" => return self.view(root).await,
            _ => {
                let call_operation = matches!(
                    op,
                    "call_authorization"
                        | "call_encrypt_signal"
                        | "call_open_signal"
                        | "call_endpoint"
                );
                let target = if call_operation
                    || matches!(op, "remind" | "reminder_remove" | "message_action")
                {
                    v["target_space"].as_str()
                } else {
                    None
                };
                let id = target
                    .or(self.catalog.active.as_deref())
                    .ok_or("Join a Space first.")?;
                let entry = self
                    .catalog
                    .entries
                    .iter()
                    .find(|e| e.id == id && e.status == "joined")
                    .ok_or("Space not found.")?;
                if call_operation
                    && (entry.address.is_none() || v["hosting_space_id"].as_str() != Some(id))
                {
                    return Err("Call Space authorization mismatch.".into());
                }
                if op == "call_endpoint" {
                    let mut endpoint = reqwest::Url::parse(
                        &entry.address.as_ref().ok_or("Join a Space first.")?.url,
                    )?;
                    endpoint.set_path("/calls/v1");
                    endpoint.set_query(None);
                    endpoint.set_fragment(None);
                    return Ok(json!({"url": endpoint.as_str()}));
                }
                result = if entry.root {
                    root.operate_local(v).await?
                } else {
                    Box::pin(
                        self.children
                            .get_mut(id)
                            .ok_or("Space unavailable.")?
                            .operate_local(v),
                    )
                    .await?
                };
                if call_operation {
                    return Ok(result);
                }
            }
        }
        if result.get("history").is_some() {
            result["history"]["space_context"] = json!(self.catalog.active);
            return Ok(result);
        }
        if result["view"]["partial"] == true {
            result["view"]["active_space"] = json!(self.catalog.active);
            if let Some(streams) = result["view"]["streams"].as_array_mut() {
                for stream in streams {
                    stream["space_context"] = json!(self.catalog.active);
                }
            }
            result["view"]["all_streams"] = result["view"]["streams"].clone();
            return Ok(result);
        }
        result["view"] = self.view(root).await?;
        Ok(result)
    }
}
impl ClientApp {
    fn personal_chat_authority(
        session: &vault::Session,
        encoded: &str,
    ) -> Result<Option<Authority>> {
        let signed = decode_record(encoded)?;
        let genesis: SpaceGenesis = signed.decode()?;
        if genesis.owners.len() != 1
            || genesis.owners[0].identity_id != session.identity_id()
            || genesis.controller_credential_id != session.credential().id()
        {
            return Ok(None);
        }
        let space: SpaceId = signed.id().to_string().parse()?;
        let stream: StreamId = record::random_hex::<16>()?.parse()?;
        let root = genesis.owners[0].root_public_key.clone();
        let authority = Authority::new(
            signed.bytes(),
            space,
            &root_key(&root)?,
            session.credential().clone(),
            stream,
        )?;
        Ok(Some(authority))
    }
    async fn seed_personal_chat(&mut self, encoded: &str) -> Result<()> {
        let Some(mut authority) = Self::personal_chat_authority(&self.session, encoded)? else {
            return Ok(());
        };
        let space = authority.space();
        let stream = authority.stream();
        let genesis: SpaceGenesis = authority.genesis().decode()?;
        let root = genesis.owners[0].root_public_key.clone();
        let c = self.session.credential();
        let config = StreamConfig {
            chat_kind: Some(ChatKind::Chat),
            v: 1,
            kind: "stream.config".into(),
            nonce: record::random_hex::<16>()?,
            space_id: space,
            stream_id: stream,
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: c.id(),
            members: vec![Member {
                identity_id: c.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: root.clone(),
                capabilities: vec![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ],
                credential_ids: vec![c.id()],
                external: false,
            }],
            owner_credential_ids: vec![c.id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: c.identity(),
                request_record_id: None,
            },
            recovery: None,
        };
        let record = config.sign(self.session.signing_key())?;
        Box::pin(self.publish_call_update(&authority, &record)).await?;
        authority
            .commit_update(&self.store, record, self.session.age_identity(), now()?)
            .await?;
        if !self.session.can_control(space) {
            self.session.activate_new_space_controller(space)?;
            self.persist_vault()?;
        }
        // The local marker hides this setup stream until it contains real history.
        self.pins.insert(
            0,
            Pin {
                personal_seed: Some(true),
                name: "General".into(),
                space,
                stream,
                root,
                chat_kind: Some(ChatKind::Chat),
                group: None,
                created_at: now()?.as_millis(),
            },
        );
        self.authorities.0.insert(0, authority);
        self.persist_workspace()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::space_service::ServiceConfig;
    use super::*;
    const PASSWORD: &str = "synthetic spaces test password";
    #[test]
    fn space_cleanup_accepts_empty_transfer_cache_and_preserves_unexpected_contents() {
        let temp = tempfile::tempdir().unwrap();
        let space = temp.path().join("space");
        std::fs::create_dir(&space).unwrap();
        std::fs::write(space.join("vault.age"), b"preserve until validated").unwrap();
        let cache = space.join("attachment-transfers");
        std::fs::create_dir(&cache).unwrap();
        std::fs::write(cache.join("unexpected.txt"), b"user data").unwrap();
        assert!(remove_child(&space).is_err());
        assert_eq!(
            std::fs::read(space.join("vault.age")).unwrap(),
            b"preserve until validated"
        );
        assert_eq!(
            std::fs::read(cache.join("unexpected.txt")).unwrap(),
            b"user data"
        );
        std::fs::remove_file(cache.join("unexpected.txt")).unwrap();
        remove_child(&space).unwrap();
        assert!(!space.exists());
    }
    #[cfg(unix)]
    #[test]
    fn space_cleanup_rejects_transfer_cache_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let space = temp.path().join("space");
        let external = temp.path().join("external");
        std::fs::create_dir(&space).unwrap();
        std::fs::create_dir(&external).unwrap();
        std::fs::write(space.join("vault.age"), b"keep").unwrap();
        std::os::unix::fs::symlink(&external, space.join("attachment-transfers")).unwrap();
        assert!(remove_child(&space).is_err());
        assert_eq!(std::fs::read(space.join("vault.age")).unwrap(), b"keep");
        assert!(external.is_dir());
    }
    async fn profile(base: &Path, name: &str) -> ClientApp {
        ProfileDraft::new()
            .unwrap()
            .save_named(base.join(name), PASSWORD.into(), "General", name)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        ClientApp::open(base.join(name), PASSWORD.into(), true)
            .await
            .unwrap()
    }
    async fn command(
        server: &std::sync::Arc<tokio::sync::Mutex<ClientApp>>,
        config: &ServiceConfig,
        client: &ClientApp,
        action: &str,
        body: Value,
    ) -> Result<Value> {
        let request = client.space_request(&config.address, action, body)?;
        let nonce = request.nonce.clone();
        let answer = server.lock().await.serve_space(config, request).await?;
        client.open_space_response(&config.address, &nonce, answer)
    }
    fn serve_test_space(
        server: std::sync::Arc<tokio::sync::Mutex<ClientApp>>,
        config: ServiceConfig,
        listener: tokio::net::TcpListener,
    ) -> tokio::task::JoinHandle<()> {
        let app = axum::Router::new().route(
            "/team/v1/spaces",
            axum::routing::post(
                move |axum::Json(request): axum::Json<super::super::space_service::Request>| {
                    let server = server.clone();
                    let config = config.clone();
                    async move {
                        server
                            .lock()
                            .await
                            .serve_space(&config, request)
                            .await
                            .map(axum::Json)
                            .map_err(|_| axum::http::StatusCode::BAD_REQUEST)
                    }
                },
            ),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        })
    }
    async fn attach(client: &mut ClientApp, address: SpaceAddress, value: Value) -> String {
        let mut spaces = client.spaces.take().unwrap();
        let id = spaces.add_joined(client, address, value).await.unwrap();
        client.spaces = Some(spaces);
        id
    }
    #[tokio::test]
    async fn signed_status_reuses_unchanged_enrollment_and_read_checks_do_not_write_state() {
        let temp = tempfile::tempdir().unwrap();
        let mut server = profile(temp.path(), "service").await;
        let mut owner = profile(temp.path(), "owner").await;
        let replica = crate::replica::ReplicaStore::open(temp.path().join("replica"))
            .await
            .unwrap();
        let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
        let peer = PeerDescriptor {
            url: "http://127.0.0.1:9/".into(),
            signing_public_key: record::encode_hex(replica.key().as_bytes()),
            mailbox_id: mailbox.mailbox_id,
            read_token: Some(mailbox.read_token),
            write_token: Some(mailbox.write_token),
        };
        server.ensure_peer(peer.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = ServiceConfig {
            name: "Permission test".into(),
            address: SpaceAddress {
                url: format!("http://{}/team/v1/spaces", listener.local_addr().unwrap()),
                scope: server.team_scope().unwrap(),
                message_lifetime_seconds: 86400,
            },
            owners: vec![owner.identity_id()],
            contact_email: None,
            peer,
        };
        let invitation = SpaceInvitation::parse(
            &server.bootstrap_space_invitation(&config.address).unwrap(),
            true,
        )
        .unwrap();
        let state_path = server.directory.join("space-service.sqlite");
        let server = std::sync::Arc::new(tokio::sync::Mutex::new(server));
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        let service = server.clone();
        let service_config = config.clone();
        let router = axum::Router::new().route(
            "/team/v1/spaces",
            axum::routing::post(
                move |axum::Json(request): axum::Json<super::super::space_service::Request>| {
                    let service = service.clone();
                    let config = service_config.clone();
                    if decode_record(request.record.as_ref().unwrap())
                        .unwrap()
                        .body()["action"]
                        == "chat_head_check"
                    {
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    async move {
                        axum::Json(
                            service
                                .lock()
                                .await
                                .serve_space(&config, request)
                                .await
                                .unwrap(),
                        )
                    }
                },
            ),
        );
        let worker = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        owner.begin_space_setup().await.unwrap();
        let enrollment = owner
            .team_enrollment_request(&config.address.scope)
            .unwrap();
        let full = command(
            &server,
            &config,
            &owner,
            "join",
            json!({"token":invitation.token,"enrollment":enrollment}),
        )
        .await
        .unwrap();
        assert!(!full["enrollment"].is_null());
        let id = attach(&mut owner, config.address.clone(), full.clone()).await;
        let child = &owner.spaces.as_ref().unwrap().children[&id];
        let probe = child.membership_probe().unwrap();
        let body = json!({"enrollment":enrollment,"known_general_head":full["general_head"],"membership_epoch":0,"chat_heads":probe.requests});
        let compact = command(&server, &config, &owner, "status", body.clone())
            .await
            .unwrap();
        assert!(
            compact["enrollment"].is_null(),
            "unchanged permissions must not resend the enrollment packet"
        );
        assert_eq!(compact["general_head"], full["general_head"]);
        let full_bytes = serde_json::to_vec(&full).unwrap().len();
        let compact_bytes = serde_json::to_vec(&compact).unwrap().len();
        assert!(compact_bytes < full_bytes);
        eprintln!(
            "Space status: full {} bytes, unchanged {} bytes including chat confirmations",
            full_bytes, compact_bytes
        );
        child
            .accept_membership_probe(probe, &compact)
            .await
            .unwrap();
        let general = child
            .authorities
            .0
            .iter()
            .find(|a| a.space() == config.address.scope.space)
            .unwrap();
        child.require_fresh_membership(general).await.unwrap(); // Sync supplied the proof.
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        let snapshot = vault::read_private(&state_path).unwrap();
        for _ in 0..3 {
            command(
                &server,
                &config,
                &owner,
                "chat_head_check",
                json!({"space":general.space(),"stream":general.stream(),"head":general.head_id()}),
            )
            .await
            .unwrap();
        }
        assert_eq!(
            vault::read_private(&state_path).unwrap(),
            snapshot,
            "read checks must not rewrite or grow encrypted service state"
        );
        attach(&mut owner, config.address.clone(), compact).await;
        let mut spaces = owner.spaces.take().unwrap();
        let entry = spaces
            .catalog
            .entries
            .iter()
            .find(|e| e.id == id)
            .unwrap()
            .clone();
        spaces.children[&id].invalidate_membership_checks().await;
        assert!(!spaces.poll_entry(&mut owner, entry, false).await.unwrap());
        let child = &spaces.children[&id];
        let general = child
            .authorities
            .0
            .iter()
            .find(|a| a.space() == config.address.scope.space)
            .unwrap();
        child.require_fresh_membership(general).await.unwrap();
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the ordinary poll must renew confirmations without a separate check"
        );
        owner.spaces = Some(spaces);
        // A stale head or different admission epoch forces the full signed packet.
        for patch in [
            json!({"known_general_head":"ff".repeat(32)}),
            json!({"membership_epoch":1}),
        ] {
            let mut request = body.clone();
            for (key, value) in patch.as_object().unwrap() {
                request[key] = value.clone();
            }
            let response = command(&server, &config, &owner, "status", request)
                .await
                .unwrap();
            assert!(!response["enrollment"].is_null());
        }
        let mut oversized = body;
        oversized["chat_heads"] = json!(vec![json!({}); 65]);
        assert!(
            command(&server, &config, &owner, "status", oversized)
                .await
                .is_err()
        );
        owner.close().await.unwrap();
        worker.abort();
        let _ = worker.await;
        std::sync::Arc::try_unwrap(server)
            .ok()
            .unwrap()
            .into_inner()
            .close()
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn failed_hosted_creation_releases_fields_for_editing() {
        let temp = tempfile::tempdir().unwrap();
        let mut user = profile(temp.path(), "owner").await;
        user.enable_spaces().await.unwrap();
        let host = "http://127.0.0.1:1/spaces/v1/create";
        let mut spaces = user.spaces.take().unwrap();
        let mut previous = None;
        for name in ["First name", "First name", "Edited name"] {
            let result = spaces
                .operate(
                    &mut user,
                    json!({"op":"space_create","host":host,"name":name,"contact_email":"owner@example.test","message_lifetime_seconds":86400}),
                )
                .await;
            assert!(result.is_err());
            assert!(spaces.catalog.creation.is_none());
            let retry = spaces.catalog.creation_retry.as_ref().unwrap();
            if let Some((old_name, old_id)) = &previous {
                assert_eq!(retry.request_id == *old_id, name == *old_name);
            }
            previous = Some((name, retry.request_id.clone()));
        }
        user.spaces = Some(spaces);
        user.close().await.unwrap();
    }
    #[tokio::test]
    async fn foreground_discovery_yields_between_spaces_after_a_stalled_connection() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Duration;
        let temp = tempfile::tempdir().unwrap();
        let mut user = profile(temp.path(), "offline").await;
        user.enable_spaces().await.unwrap();
        let first = "01".repeat(32);
        let second = "02".repeat(32);
        let hits = Arc::new(AtomicUsize::new(0));
        let second_hits = hits.clone();
        let router = axum::Router::new()
            .route(
                &format!("/spaces/{first}/team/v1/spaces"),
                axum::routing::post(|| async {
                    std::future::pending::<axum::http::StatusCode>().await
                }),
            )
            .route(
                &format!("/spaces/{second}/team/v1/spaces"),
                axum::routing::post(move || {
                    let hits = second_hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let scope = team::TeamScope {
            space: first.parse().unwrap(),
            stream: user.authorities.0[0].stream(),
            controller: user.session.credential().id(),
            root: field(user.session.credential().record().body(), "root_public_key")
                .unwrap()
                .into(),
        };
        let spaces = user.spaces.as_mut().unwrap();
        let template = spaces.catalog.entries[0].clone();
        spaces.catalog.active = None;
        spaces.catalog.entries = [&first, &second]
            .into_iter()
            .map(|id| Entry {
                id: id.clone(),
                name: "Pending fixture".into(),
                root: false,
                status: "pending".into(),
                owner: false,
                contact_email: None,
                address: Some(SpaceAddress {
                    url: format!("http://{address}/spaces/{id}/team/v1/spaces"),
                    scope: team::TeamScope {
                        space: id.parse().unwrap(),
                        ..scope.clone()
                    },
                    message_lifetime_seconds: 86_400,
                }),
                ..template.clone()
            })
            .collect();
        let request = json!({"op":"invitation_sync", "foreground":true, "force":true});
        let result = tokio::time::timeout(Duration::from_secs(5), user.operate(request.clone()))
            .await
            .expect("discovery waited for the full transport timeout")
            .unwrap();
        assert_eq!(result["delivery"]["retry"], 1);
        assert_eq!(result["delivery"]["remaining_spaces"], true);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "one pass must yield before the next Space"
        );
        let result = user.operate(request).await.unwrap();
        assert_eq!(result["delivery"]["remaining_spaces"], false);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(user.spaces.as_ref().unwrap().catalog.entries.len(), 2);
        assert!(
            user.spaces
                .as_ref()
                .unwrap()
                .catalog
                .entries
                .iter()
                .all(|entry| entry.status == "pending")
        );
        assert_eq!(user.view().await.unwrap()["active_space"], Value::Null);
        server.abort();
        user.close().await.unwrap();
    }
    #[tokio::test]
    async fn management_recovery_uses_selected_space_and_rejects_foreign_hosting_scope() {
        async fn container(child: ClientApp, parent: PathBuf, id: &str) -> ClientApp {
            make_directory(&parent).unwrap();
            let session = child.session.isolated_space();
            vault::write_private(
                &parent.join("vault.age"),
                &session.seal(child.password.clone()).unwrap(),
                false,
            )
            .unwrap();
            vault::write_private(
                &parent.join("profile.json"),
                &vault::read_private(&child.directory.join("profile.json")).unwrap(),
                false,
            )
            .unwrap();
            let mut root = ClientApp::open_session(parent, child.password.clone(), true, session)
                .await
                .unwrap();
            root.enable_spaces().await.unwrap();
            let spaces = root.spaces.as_mut().unwrap();
            let mut entry = spaces.catalog.entries[0].clone();
            entry.id = id.into();
            entry.root = false;
            spaces.catalog.active = Some(id.into());
            spaces.catalog.entries = vec![entry];
            spaces.children.insert(id.into(), child);
            root
        }
        let temp = tempfile::tempdir().unwrap();
        let (draft, owner, helper, restored) =
            super::super::control_recovery::tests::fixture(temp.path()).await;
        let pin = owner.pins[0].clone();
        let id = "ab".repeat(32);
        let mut helper = container(helper, temp.path().join("helper-root"), &id).await;
        let mut restored = container(restored, temp.path().join("restored-root"), &id).await;
        let request = restored.control_recovery_request();
        let device = restored.control_recovery_device();
        let choices = helper.control_recovery_choices(&request).await.unwrap();
        assert_eq!(choices["chats"].as_array().unwrap().len(), 1);
        assert_eq!(choices["chats"][0]["stream"], json!(pin.stream));
        let package = helper
            .control_recovery_export(&request, pin.space, pin.stream, device)
            .await
            .unwrap();
        let address = SpaceAddress {
            url: "http://127.0.0.1:9/team/v1/spaces".into(),
            scope: team::TeamScope {
                space: id.parse().unwrap(),
                stream: pin.stream,
                root: pin.root.clone(),
                controller: owner.team_scope().unwrap().controller,
            },
            message_lifetime_seconds: 86400,
        };
        helper.selected_space_client_mut().unwrap().call_host = Some(address.clone());
        restored.selected_space_client_mut().unwrap().call_host = Some(address.clone());
        let hosted = helper
            .control_recovery_export(&request, pin.space, pin.stream, device)
            .await
            .unwrap();
        assert_eq!(hosted["hosting_space"], id);
        restored.control_recovery_preview(&hosted).await.unwrap();
        assert!(
            restored.control_recovery_preview(&package).await.is_err(),
            "an unscoped file cannot be imported into a hosted Space"
        );
        restored
            .selected_space_client_mut()
            .unwrap()
            .call_host
            .as_mut()
            .unwrap()
            .scope
            .space = SpaceId::from_bytes([7; 32]);
        assert!(restored.control_recovery_preview(&hosted).await.is_err());
        restored.selected_space_client_mut().unwrap().call_host = None;
        assert!(restored.control_recovery_preview(&hosted).await.is_err());
        helper.selected_space_client_mut().unwrap().call_host = None;
        // Complete the cryptographic exchange inside selected local compartments.
        // Hosted admission itself is exercised by the service and physical QA tests.
        let mut preview = restored.control_recovery_preview(&package).await.unwrap();
        preview["confirmed"] = true.into();
        restored
            .control_recovery_confirm(&package, &preview, &draft.card().phrase)
            .await
            .unwrap();
        assert!(
            restored.pins.is_empty(),
            "the root compartment must remain untouched"
        );
        let notice = restored
            .control_recovery_share(pin.space, pin.stream)
            .unwrap();
        let mut adoption = helper.control_recovery_preview(&notice).await.unwrap();
        adoption["confirmed"] = true.into();
        helper
            .control_recovery_confirm(&notice, &adoption, "")
            .await
            .unwrap();
        assert!(helper.pins.is_empty());
        let child = helper.selected_space_client().unwrap();
        let i = child
            .authority_index(&json!({"space":pin.space,"stream":pin.stream}))
            .unwrap();
        assert_eq!(child.authorities.0[i].controller().id(), device);
        helper.spaces.as_mut().unwrap().catalog.active = None;
        assert!(
            helper.control_recovery_choices(&request).await.is_err(),
            "no selected Space must not fall back to the root"
        );
        helper.spaces.as_mut().unwrap().catalog.active = Some(id.clone());
        helper.spaces.as_mut().unwrap().catalog.entries[0].status = "checking".into();
        assert!(
            helper.control_recovery_choices(&request).await.is_err(),
            "unverified Spaces cannot supply recovery proofs"
        );
        owner.close().await.unwrap();
        helper.close().await.unwrap();
        restored.close().await.unwrap();
    }

    #[tokio::test]
    async fn prepared_personal_scope_avoids_a_second_vault_write_and_survives_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let first = profile(temp.path(), "first").await;
        let second = profile(temp.path(), "second").await;
        let encoded = STANDARD.encode(first.authorities.0[0].genesis().bytes());
        let foreign = second.authorities.0[0].space();
        let mut session = first.session.isolated_space();
        assert!(
            ClientApp::personal_chat_authority(&second.session, &encoded)
                .unwrap()
                .is_none()
        );
        let authority = ClientApp::personal_chat_authority(&session, &encoded)
            .unwrap()
            .unwrap();
        let own = authority.space();
        assert!(!session.can_control(own));
        session.activate_new_space_controller(own).unwrap();
        assert!(!session.can_control(foreign));
        let path = temp.path().join("child");
        make_directory(&path).unwrap();
        let vault_path = path.join("vault.age");
        let initial = session.seal(PASSWORD.into()).unwrap();
        vault::write_private(&vault_path, &initial, false).unwrap();
        vault::write_private(
            &path.join("profile.json"),
            &vault::read_private(&first.directory.join("profile.json")).unwrap(),
            false,
        )
        .unwrap();
        let mut child = ClientApp::open_session(path.clone(), PASSWORD.into(), true, session)
            .await
            .unwrap();
        child.seed_personal_chat(&encoded).await.unwrap();
        assert_eq!(vault::read_private(&vault_path).unwrap(), initial);
        child.close().await.unwrap();
        let reopened = ClientApp::open(path, PASSWORD.into(), true).await.unwrap();
        assert!(reopened.session.can_control(own));
        assert!(!reopened.session.can_control(foreign));
        assert_eq!(reopened.authorities.0.len(), 1);
        reopened.close().await.unwrap();
        first.close().await.unwrap();
        second.close().await.unwrap();
    }
    #[tokio::test]
    async fn space_vault_cache_reopens_falls_back_and_tracks_authority_changes() {
        let temp = tempfile::tempdir().unwrap();
        let root = profile(temp.path(), "root").await;
        let id = "ab".repeat(32);
        let space: SpaceId = id.parse().unwrap();
        let path = child_path(&root, &id).unwrap();
        make_directory(&root.directory.join("spaces")).unwrap();
        make_directory(&path).unwrap();
        let session = root.session.isolated_space();
        let original = session.seal(PASSWORD.into()).unwrap();
        vault::write_private(&path.join("vault.age"), &original, false).unwrap();
        vault::write_private(
            &path.join("profile.json"),
            &vault::read_private(&root.directory.join("profile.json")).unwrap(),
            false,
        )
        .unwrap();
        let cache_path = path.join(VAULT_CACHE);
        let mut child = root.open_space_child(path.clone(), space).await.unwrap();
        child.close().await.unwrap();
        let first_cache = vault::read_private(&cache_path).unwrap();
        child = root.open_space_child(path.clone(), space).await.unwrap();
        assert_eq!(vault::read_private(&cache_path).unwrap(), first_cache);

        child.session.retire_controller();
        child.persist_vault().unwrap();
        child.close().await.unwrap();
        child = root.open_space_child(path.clone(), space).await.unwrap();
        assert!(child.session.controller_mode() == vault::ControllerMode::Retired);
        assert_ne!(vault::read_private(&cache_path).unwrap(), first_cache);
        child.close().await.unwrap();
        vault::write_private(&cache_path, b"broken optional cache", true).unwrap();
        child = root.open_space_child(path.clone(), space).await.unwrap();
        assert!(child.session.controller_mode() == vault::ControllerMode::Retired);
        child.close().await.unwrap();
        let valid_cache = vault::read_private(&cache_path).unwrap();
        vault::write_private(&path.join("vault.age"), b"broken authoritative vault", true).unwrap();
        assert!(root.open_space_child(path.clone(), space).await.is_err());
        assert_eq!(vault::read_private(&cache_path).unwrap(), valid_cache);
        remove_child(&path).unwrap();
        assert!(!path.exists());
        root.close().await.unwrap();
    }
    #[tokio::test]
    async fn fresh_space_session_rejects_other_profiles_and_reopen_still_checks_password() {
        let temp = tempfile::tempdir().unwrap();
        let first = profile(temp.path(), "first").await;
        let second = profile(temp.path(), "second").await;
        let path = first.directory.clone();
        let bytes = vault::read_private(&path.join("vault.age")).unwrap();
        assert!(
            ClientApp::open_session(
                path.clone(),
                PASSWORD.into(),
                true,
                second.session.isolated_space(),
            )
            .await
            .is_err()
        );
        assert_eq!(vault::read_private(&path.join("vault.age")).unwrap(), bytes);
        first.close().await.unwrap();
        assert!(
            ClientApp::open(path.clone(), "incorrect test password".into(), true)
                .await
                .is_err()
        );
        ClientApp::open(path, PASSWORD.into(), true)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        second.close().await.unwrap();
    }
    #[tokio::test]
    async fn disconnected_root_retries_peer_removal_without_rewriting_an_empty_vault() {
        let temp = tempfile::tempdir().unwrap();
        let mut user = profile(temp.path(), "user").await;
        let replica = crate::replica::ReplicaStore::open(temp.path().join("replica"))
            .await
            .unwrap();
        let mailbox = replica.create_mailbox(1024 * 1024).await.unwrap();
        let peer = PeerDescriptor {
            url: "http://127.0.0.1:9/".into(),
            signing_public_key: record::encode_hex(replica.key().as_bytes()),
            mailbox_id: mailbox.mailbox_id,
            read_token: Some(mailbox.read_token),
            write_token: Some(mailbox.write_token),
        };
        assert!(user.ensure_peer(peer).unwrap());
        user.enable_spaces().await.unwrap();
        let mut spaces = user.spaces.take().unwrap();
        spaces.catalog.entries.clear();
        spaces.catalog.active = None;
        spaces.catalog.root_disconnected = true;
        spaces.save(&user).unwrap();

        let path = user.directory.clone();
        let vault_path = path.join("vault.age");
        let saved_path = path.join("blocked-vault.age");
        std::fs::rename(&vault_path, &saved_path).unwrap();
        std::fs::create_dir(&vault_path).unwrap();
        assert!(spaces.purge_root(&mut user).await.is_err());
        assert_eq!(user.session.peers().len(), 1);
        assert!(user.peers.is_empty());
        std::fs::remove_dir(&vault_path).unwrap();
        std::fs::rename(saved_path, &vault_path).unwrap();
        spaces.purge_root(&mut user).await.unwrap();
        assert!(user.session.peers().is_empty());
        let cleared_vault = vault::read_private(&vault_path).unwrap();
        user.close().await.unwrap();

        // An interrupted cleanup can leave data files behind. Removing those on
        // the next unlock must not require another password-vault rewrite.
        let stale = path.join("invitations.age");
        vault::write_private(&stale, b"stale synthetic invitation data", false).unwrap();
        let mut reopened = ClientApp::open(path, PASSWORD.into(), true).await.unwrap();
        assert!(reopened.session.peers().is_empty());
        reopened.enable_spaces().await.unwrap();
        assert!(!stale.exists());
        assert!(reopened.pins.is_empty());
        assert!(reopened.peers.is_empty());
        assert_eq!(vault::read_private(&vault_path).unwrap(), cleared_vault);
        reopened.close().await.unwrap();
    }
    #[tokio::test]
    async fn spaces_require_owner_approval_isolate_mailboxes_and_survive_backup_and_disconnect() {
        let temp = tempfile::tempdir().unwrap();
        let mut first = profile(temp.path(), "first service").await;
        let mut second = profile(temp.path(), "second service").await;
        let mut owner = profile(temp.path(), "owner").await;
        let mut user = profile(temp.path(), "user").await;
        let replica = crate::replica::ReplicaStore::open(temp.path().join("replica"))
            .await
            .unwrap();
        let mut configurations = Vec::new();
        let mut listeners = Vec::new();
        for (name, server) in [("Company A", &mut first), ("Company B", &mut second)] {
            let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
            let peer = PeerDescriptor {
                url: "http://127.0.0.1:9/".into(),
                signing_public_key: record::encode_hex(replica.key().as_bytes()),
                mailbox_id: mailbox.mailbox_id,
                read_token: Some(mailbox.read_token),
                write_token: Some(mailbox.write_token),
            };
            server.ensure_peer(peer.clone()).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let service_url = format!("http://{}/team/v1/spaces", listener.local_addr().unwrap());
            listeners.push(listener);
            configurations.push(ServiceConfig {
                name: name.into(),
                address: SpaceAddress {
                    url: service_url,
                    scope: server.team_scope().unwrap(),
                    message_lifetime_seconds: 86_400,
                },
                owners: vec![owner.identity_id()],
                contact_email: None,
                peer,
            });
        }
        let first = std::sync::Arc::new(tokio::sync::Mutex::new(first));
        let second = std::sync::Arc::new(tokio::sync::Mutex::new(second));
        let mut services = [&first, &second]
            .into_iter()
            .zip(&configurations)
            .zip(listeners)
            .map(|((server, config), listener)| {
                serve_test_space(server.clone(), config.clone(), listener)
            })
            .collect::<Vec<_>>();
        owner.begin_space_setup().await.unwrap();
        assert_eq!(owner.view().await.unwrap()["space_setup"], true);
        assert!(
            owner.view().await.unwrap()["spaces"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!owner.allows_default_space().unwrap());
        owner.close().await.unwrap();
        owner = ClientApp::open(temp.path().join("owner"), PASSWORD.into(), true)
            .await
            .unwrap();
        owner.enable_spaces().await.unwrap();
        assert_eq!(owner.view().await.unwrap()["space_setup"], true);
        user.enable_spaces().await.unwrap();
        let personal = user.view().await.unwrap()["active_space"]
            .as_str()
            .unwrap()
            .to_owned();
        let a = &configurations[0];
        let b = &configurations[1];
        // Explicit Demo admission also replaces a pending invitation for that
        // same Space, rather than selecting a compartment that does not exist.
        attach(
            &mut owner,
            a.address.clone(),
            json!({"name":"Demo","status":"pending"}),
        )
        .await;
        owner
            .join_default_space(
                a.peer.clone(),
                team::TeamDescriptor {
                    v: 1,
                    url: a.address.url.replace("/spaces", "/enroll"),
                    token: "fe".repeat(32),
                    scope: a.address.scope.clone(),
                    message_lifetime_seconds: a.address.message_lifetime_seconds,
                },
            )
            .await
            .unwrap();
        assert_eq!(owner.view().await.unwrap()["space_setup"], false);
        assert_eq!(owner.view().await.unwrap()["spaces"][0]["name"], "Demo");
        assert!(owner.allows_default_space().unwrap());
        let request = owner
            .space_request(&a.address, "manage", json!({}))
            .unwrap();
        let nonce = request.nonce.clone();
        let response = first.lock().await.serve_space(a, request).await.unwrap();
        assert!(response.ciphertext.is_some());
        assert!(
            owner
                .open_space_response(&a.address, &nonce, response.clone())
                .is_ok()
        );
        assert!(
            user.open_space_response(&a.address, &nonce, response.clone())
                .is_err()
        );
        assert!(
            owner
                .open_space_response(&a.address, &"ab".repeat(16), response.clone())
                .is_err()
        );
        assert!(
            owner
                .open_space_response(&b.address, &nonce, response.clone())
                .is_err()
        );
        let mut tampered = response;
        let mut ciphertext = STANDARD
            .decode(tampered.ciphertext.as_ref().unwrap())
            .unwrap();
        *ciphertext.last_mut().unwrap() ^= 1;
        tampered.ciphertext = Some(STANDARD.encode(ciphertext));
        assert!(
            owner
                .open_space_response(&a.address, &nonce, tampered)
                .is_err()
        );
        let mut expired = owner
            .space_request(&a.address, "manage", json!({}))
            .unwrap();
        let mut body: Value = decode_record(expired.record.as_ref().unwrap())
            .unwrap()
            .decode()
            .unwrap();
        body["issued"] = json!(0);
        expired.record = Some(
            STANDARD.encode(
                SignedRecord::sign(
                    &serde_json::to_vec(&body).unwrap(),
                    owner.session.signing_key(),
                )
                .unwrap()
                .bytes(),
            ),
        );
        assert!(first.lock().await.serve_space(a, expired).await.is_err());
        assert!(
            command(
                &first,
                a,
                &user,
                "invite",
                json!({"lifetime":86400,"require_approval":false})
            )
            .await
            .is_err()
        );
        let offer = command(
            &first,
            a,
            &owner,
            "invite",
            json!({"lifetime":86400,"require_approval":true}),
        )
        .await
        .unwrap();
        let invitation = SpaceInvitation::parse(offer["link"].as_str().unwrap(), true).unwrap();
        assert!(
            !offer["link"]
                .as_str()
                .unwrap()
                .contains(a.peer.read_token.as_ref().unwrap())
        );
        let enrollment = user.team_enrollment_request(&a.address.scope).unwrap();
        let pending = command(
            &first,
            a,
            &user,
            "join",
            json!({"token":invitation.token,"enrollment":enrollment}),
        )
        .await
        .unwrap();
        assert_eq!(pending["status"], "pending");
        assert!(pending.get("peer").is_none());
        let a_id = attach(&mut user, a.address.clone(), pending).await;
        assert!(user.spaces.as_ref().unwrap().children.is_empty());
        let manage = command(&first, a, &owner, "manage", json!({}))
            .await
            .unwrap();
        command(
            &first,
            a,
            &owner,
            "decide",
            json!({"id":manage["requests"][0]["id"],"approve":true}),
        )
        .await
        .unwrap();
        let approved = command(&first, a, &user, "status", json!({"enrollment":enrollment}))
            .await
            .unwrap();
        attach(&mut user, a.address.clone(), approved).await;
        let offer_b = command(
            &second,
            b,
            &owner,
            "invite",
            json!({"lifetime":86400,"require_approval":false}),
        )
        .await
        .unwrap();
        let invitation_b = SpaceInvitation::parse(offer_b["link"].as_str().unwrap(), true).unwrap();
        let approved_b=command(&second,b,&user,"join",json!({"token":invitation_b.token,"enrollment":user.team_enrollment_request(&b.address.scope).unwrap()})).await.unwrap();
        let b_id = attach(&mut user, b.address.clone(), approved_b).await;
        for (id, expected_peer, text) in [(&a_id, &a.peer, "Only A"), (&b_id, &b.peer, "Only B")] {
            user.operate(json!({"op":"space_select","id":id}))
                .await
                .unwrap();
            let view = user.view().await.unwrap();
            assert_eq!(view["replicas"].as_array().unwrap().len(), 1);
            let chat = view["streams"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["name"] == "General")
                .unwrap();
            assert_eq!(chat["is_general"], true);
            assert_eq!(
                view["streams"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|s| s["is_general"] == true)
                    .count(),
                1
            );
            user.operate(json!({"op":"send","space":chat["space"],"stream":chat["stream"],"text":text,"created_at":"2026-09-13T12:00:00Z","expected_space":id})).await.unwrap();
            user.operate(json!({"op":"create_group","name":text}))
                .await
                .unwrap();
            let child = &user.spaces.as_ref().unwrap().children[id];
            assert_eq!(child.targets().len(), 1);
            assert_eq!(child.targets()[0].mailbox_id, expected_peer.mailbox_id);
            assert_eq!(child.view_local().await.unwrap()["groups"][0]["name"], text);
        }
        assert!(
            user.operate(json!({"op":"create_group","name":"stale edit","expected_space":a_id}))
                .await
                .is_err()
        );
        let before = user.view().await.unwrap();
        assert!(!before["streams"].to_string().contains("Only A"));
        let chat_a = before["all_streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["space_context"] == a_id)
            .unwrap();
        let mut lookup = json!({"op":"history_page", "expected_identity":user.identity_id(),
            "expected_space":b_id, "target_space":a_id, "space":chat_a["space"],
            "stream":chat_a["stream"], "records":[chat_a["rows"][0]["id"]]});
        let history_reader = user.history_snapshot();
        let page = user.operate(lookup.clone()).await.unwrap();
        assert_eq!(history_reader.history_page(&lookup).await.unwrap(), page);
        assert_eq!(page["history"]["space_context"], a_id);
        assert_eq!(
            page["history"]["rows"][0]["body"]["payload"]["text"],
            "Only A"
        );
        assert_eq!(user.view().await.unwrap()["active_space"], b_id);
        lookup["target_space"] = json!("unknown-space");
        assert!(history_reader.history_page(&lookup).await.is_err());
        assert!(user.operate(lookup.clone()).await.is_err());
        lookup["target_space"] = json!(a_id);
        lookup["expected_space"] = json!(a_id);
        assert!(history_reader.history_page(&lookup).await.is_err());
        assert!(user.operate(lookup).await.is_err());
        drop(history_reader);
        assert_eq!(
            before["all_streams"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|s| !s["rows"].as_array().unwrap().is_empty())
                .count(),
            2
        );
        // Foreground delivery visits one compartment at a time, returns no
        // unchanged UI snapshot, and requests only the rest of the current round.
        let root_peers = std::mem::take(&mut user.peers);
        let mut child_peers = BTreeMap::new();
        for (id, child) in &mut user.spaces.as_mut().unwrap().children {
            child_peers.insert(id.clone(), std::mem::take(&mut child.peers));
        }
        let targeted = json!({"op":"sync_live", "receive_only":true,
            "expected_identity":user.identity_id(), "expected_space":b_id, "target_space":a_id});
        let result = user.operate(targeted.clone()).await.unwrap();
        assert_eq!(result["result"]["more"], false);
        assert_eq!(result["result"]["remaining_spaces"], false);
        assert_eq!(user.view().await.unwrap()["active_space"], b_id);
        let mut invalid = targeted;
        invalid["target_space"] = json!("disconnected-space");
        assert!(user.operate(invalid).await.is_err());
        for more in [true, true, false] {
            let result = user.operate(json!({"op":"sync_live"})).await.unwrap();
            assert_eq!(result["result"]["more"], more);
            assert_eq!(result["result"]["remaining_spaces"], more);
            assert_eq!(result["result"]["catching_up"], false);
            assert!(result["view"].is_null());
        }
        user.peers = root_peers;
        for (id, peers) in child_peers {
            user.spaces
                .as_mut()
                .unwrap()
                .children
                .get_mut(&id)
                .unwrap()
                .peers = peers;
        }
        let backup = user.export_profile(PASSWORD.into()).await.unwrap();
        // Joining needs the live service for call permissions. Only the restore
        // stage is offline, to exercise quarantined history without approval.
        for task in services.drain(..) {
            task.abort();
            let _ = task.await;
        }
        assert_eq!(
            user.call_space(&a.address, "status", json!({}))
                .await
                .unwrap_err()
                .to_string(),
            "Space server unreachable."
        );
        let mut restored = ClientApp::restore_profile(
            temp.path().join("restored"),
            &backup,
            PASSWORD.into(),
            user.identity_id(),
            "synthetic new spaces password".into(),
            true,
        )
        .await
        .unwrap();
        // Restored managed compartments stay hidden until a fresh pinned
        // service answer is applied after the servers become reachable again.
        assert!(
            restored
                .spaces
                .as_ref()
                .unwrap()
                .catalog
                .entries
                .iter()
                .filter(|e| e.address.is_some())
                .all(|e| e.status == "checking")
        );
        assert!(
            restored.export_profile(PASSWORD.into()).await.is_err(),
            "do not omit quarantined history silently from a new backup"
        );
        for (server, config) in [&first, &second].into_iter().zip(&configurations) {
            let url = reqwest::Url::parse(&config.address.url).unwrap();
            let listener =
                tokio::net::TcpListener::bind((url.host_str().unwrap(), url.port().unwrap()))
                    .await
                    .unwrap();
            services.push(serve_test_space(server.clone(), config.clone(), listener));
        }
        for (server, config) in [(&first, &configurations[0]), (&second, &configurations[1])] {
            let enrollment = restored
                .team_enrollment_request(&config.address.scope)
                .unwrap();
            let reply = command(
                server,
                config,
                &restored,
                "status",
                json!({"enrollment":enrollment}),
            )
            .await
            .unwrap();
            attach(&mut restored, config.address.clone(), reply).await;
        }
        let mut expected = before["all_streams"].clone();
        for stream in expected.as_array_mut().unwrap() {
            stream["can_manage_members"] = json!(false);
        }
        assert_eq!(restored.view().await.unwrap()["all_streams"], expected);
        for child in restored.spaces.as_ref().unwrap().children.values() {
            assert!(child.session.controller_mode() == vault::ControllerMode::Follower);
        }
        restored.close().await.unwrap();
        user.operate(json!({"op":"space_disconnect","id":a_id,"confirmed":true}))
            .await
            .unwrap();
        assert!(!temp.path().join("user/spaces").join(&a_id).exists());
        assert_eq!(user.view().await.unwrap()["streams"], before["streams"]);
        assert!(
            user.history_snapshot()
                .history_page(&json!({
                    "op":"history_page", "expected_identity":user.identity_id(),
                    "expected_space":b_id, "target_space":a_id,
                    "space":chat_a["space"], "stream":chat_a["stream"]
                }))
                .await
                .is_err()
        );
        user.operate(json!({"op":"space_disconnect","id":personal,"confirmed":true}))
            .await
            .unwrap();
        assert!(!user.allows_default_space().unwrap());
        let identity = user.identity_id();
        user.close().await.unwrap();
        user = ClientApp::open(temp.path().join("user"), PASSWORD.into(), true)
            .await
            .unwrap();
        user.enable_spaces().await.unwrap();
        assert_eq!(user.identity_id(), identity);
        assert_eq!(user.notification_generation(), 2);
        assert_eq!(user.view().await.unwrap()["streams"], before["streams"]);
        command(&second, b, &owner, "revoke", json!({"id":offer_b["id"]}))
            .await
            .unwrap();
        assert!(command(&second,b,&owner,"join",json!({"token":invitation_b.token,"enrollment":owner.team_enrollment_request(&b.address.scope).unwrap()})).await.is_err());
        let wrong = user.space_request(&a.address, "manage", json!({})).unwrap();
        assert!(second.lock().await.serve_space(b, wrong).await.is_err());
        user.close().await.unwrap();
        owner.close().await.unwrap();
        for task in services {
            task.abort();
            let _ = task.await;
        }
        for server in [first, second] {
            std::sync::Arc::try_unwrap(server)
                .ok()
                .unwrap()
                .into_inner()
                .close()
                .await
                .unwrap();
        }
    }
}

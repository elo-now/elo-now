//! User-facing Spaces are separate encrypted stores, not filters over one outbox.
//! Existing profile data stays in the root compartment during migration.
use super::space_service::{SpaceAddress, SpaceInvitation};
use super::*;

const MAX_SPACES: usize = 16;
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
    address: Option<SpaceAddress>,
    #[serde(default)]
    requests: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    v: u8,
    #[serde(default)]
    setup: bool,
    #[serde(default)]
    notification_generation: u64,
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
    for file in &files {
        let name = file.file_name();
        let name = name.to_str().ok_or("Unexpected Space file.")?;
        if !file.file_type()?.is_file()
            || !(DATA_FILES.contains(&name)
                || [
                    "profile.json",
                    "profile-details.age",
                    "vault.age",
                    ".elo-client.lock",
                ]
                .contains(&name))
        {
            return Err("This Space contains an unexpected file; its data was preserved.".into());
        }
    }
    for file in files {
        std::fs::remove_file(file.path())?;
    }
    std::fs::remove_dir(path)?;
    Ok(())
}
impl ClientApp {
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
                address: Some(address),
                requests: 0,
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
                notification_generation: 0,
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
                    address,
                    requests: 0,
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
                || !["pending", "joined", "declined"].contains(&entry.status.as_str())
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
            let mut child = Self::open(path, self.password.clone(), self.allow_loopback).await?;
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
            spaces.children.insert(entry.id.clone(), child);
        }
        spaces.save(self)?;
        self.spaces = Some(Box::new(spaces));
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
        })
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
    pub(super) fn children(&self) -> &BTreeMap<String, ClientApp> {
        &self.children
    }
    pub(super) async fn close(self) -> Result<()> {
        for (_, child) in self.children {
            Box::pin(child.close()).await?;
        }
        Ok(())
    }
    pub(super) fn clients<'a>(&'a self, root: &'a ClientApp) -> Vec<&'a ClientApp> {
        let mut values = Vec::new();
        if self.catalog.entries.iter().any(|entry| entry.root) {
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
        view["space_setup"] = json!(self.catalog.setup);
        if let Some(streams) = view["streams"].as_array_mut() {
            for stream in streams {
                stream["space_context"] = json!(self.catalog.active);
            }
        }

        view["spaces"] = json!(self.catalog.entries.iter().map(|e|json!({"id":e.id,"name":e.name,"status":e.status,"owner":e.owner,"requests":e.requests,"managed":e.address.is_some()})).collect::<Vec<_>>());
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
        root.store.close().await?;
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
        root.session.set_peers(vec![])?;
        root.team = None;
        root.persist_vault()?;
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
        let name = field(&result, "name")?;
        if !record::valid_display_name(name)
            || !["pending", "approved", "declined"].contains(&status)
        {
            return Err("Invalid Space membership response.".into());
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
            let enrollment: team::EnrollmentReply =
                serde_json::from_value(result["enrollment"].clone())?;
            if old.is_some_and(|i| self.catalog.entries[i].root) {
                // Migration never replaces or rewrites existing profile data.
                root.accept_space_enrollment(enrollment).await?;
            } else if let Some(child) = self.children.get_mut(&id) {
                child.accept_space_enrollment(enrollment).await?;
            } else {
                let directory = child_path(root, &id)?;
                let parent = root.directory.join("spaces");
                if !parent.try_exists()? {
                    make_directory(&parent)?;
                } else {
                    check_directory(&parent)?;
                }
                let created = !directory.try_exists()?;
                if created {
                    make_directory(&directory)?;
                    let mut session = root.session.isolated_space();
                    session.set_peers(vec![peer])?;
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
                } else {
                    check_directory(&directory)?;
                }

                let mut child = ClientApp::open(
                    directory.clone(),
                    root.password.clone(),
                    root.allow_loopback,
                )
                .await?;
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
            address: Some(address),
            requests: old.map(|i| self.catalog.entries[i].requests).unwrap_or(0),
        };
        if let Some(i) = old {
            self.catalog.entries[i] = entry;
        } else {
            self.catalog.entries.push(entry);
        }
        if status == "approved" && self.catalog.active.is_none() {
            self.catalog.active = Some(id.clone());
        }
        self.catalog.setup = false;
        self.save(root)?;
        Ok(id)
    }
    async fn poll(&mut self, root: &mut ClientApp) -> Result<()> {
        let time = now()?.as_millis() as u64;
        if self.next_poll > time {
            return Ok(());
        }
        self.next_poll = time + 30_000;
        for entry in self.catalog.entries.clone() {
            let Some(address) = entry.address else {
                continue;
            };
            let enrollment = root.team_enrollment_request(&address.scope)?;
            if let Ok(result) = root
                .call_space(&address, "status", json!({"enrollment":enrollment}))
                .await
            {
                let _ = self.add_joined(root, address.clone(), result).await;
            }
            if self
                .catalog
                .entries
                .iter()
                .any(|e| e.id == entry.id && e.owner)
                && let Ok(manage) = root.call_space(&address, "manage", json!({})).await
                && let Some(e) = self.catalog.entries.iter_mut().find(|e| e.id == entry.id)
            {
                e.requests = manage["requests"].as_array().map(Vec::len).unwrap_or(0);
            }
        }
        self.save(root)
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
            "space_setup_done" => {
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
            }
            "space_join" => {
                let invite = SpaceInvitation::parse(field(&v, "link")?, root.allow_loopback)?;
                let enrollment = root.team_enrollment_request(&invite.address.scope)?;
                let response = root
                    .call_space(
                        &invite.address,
                        "join",
                        json!({"token":invite.token,"enrollment":enrollment}),
                    )
                    .await?;
                let id = self.add_joined(root, invite.address, response).await?;
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
            "space_manage" | "space_invite" | "space_revoke" | "space_decide" => {
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
                result["result"] = root.call_space(&address, action, v["body"].clone()).await?;
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
            }
            "sync" | "sync_live" | "invitation_sync" => {
                let mut reports = Vec::new();
                let live = v["op"] == "sync_live";
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
                    reports.push(report);
                }
                self.sync_backlog.retain(|id| ids.contains(id));
                let mut summary = serde_json::Map::new();
                let mut received = Vec::new();
                let mut delivery_retry = 0u64;
                let mut delivery_more = false;
                let mut delivery_received = 0u64;
                let mut report_more = false;
                for report in reports {
                    match report {
                        Ok(report) => {
                            report_more |= report["result"]["more"] == true;
                            delivery_retry += report["delivery"]["retry"].as_u64().unwrap_or(0);
                            delivery_more |= report["delivery"]["more"] == true;
                            delivery_received +=
                                report["delivery"]["received"].as_u64().unwrap_or(0);
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
                summary.insert(
                    "more".into(),
                    json!(
                        report_more
                            || (live
                                && (!self.sync_backlog.is_empty()
                                    || selected.is_some_and(|(_, rest)| rest)))
                    ),
                );
                summary.insert("received_messages".into(), json!(received));
                result["result"] = Value::Object(summary);
                result["delivery"] = json!({"retry":delivery_retry,"more":delivery_more,"received":delivery_received});
                if !live {
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
                let target = if matches!(op, "remind" | "reminder_remove") {
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
                    .find(|e| e.id == id)
                    .ok_or("Space not found.")?;
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
    async fn seed_personal_chat(&mut self, encoded: &str) -> Result<()> {
        let signed = decode_record(encoded)?;
        let genesis: SpaceGenesis = signed.decode()?;
        if genesis.owners.len() != 1
            || genesis.owners[0].identity_id != self.identity_id()
            || genesis.controller_credential_id != self.session.credential().id()
        {
            return Ok(());
        }
        let space: SpaceId = signed.id().to_string().parse()?;
        let stream: StreamId = record::random_hex::<16>()?.parse()?;
        let root = genesis.owners[0].root_public_key.clone();
        let mut authority = Authority::new(
            signed.bytes(),
            space,
            &root_key(&root)?,
            self.session.credential().clone(),
            stream,
        )?;
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
        authority
            .commit_update(
                &self.store,
                config.sign(self.session.signing_key())?,
                self.session.age_identity(),
                now()?,
            )
            .await?;
        self.session.activate_new_space_controller(space)?;
        self.persist_vault()?;
        // Keep the personal seed first so the existing empty-General rule hides it.
        self.pins.insert(
            0,
            Pin {
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
        server: &mut ClientApp,
        config: &ServiceConfig,
        client: &ClientApp,
        action: &str,
        body: Value,
    ) -> Result<Value> {
        let request = client.space_request(&config.address, action, body)?;
        let nonce = request.nonce.clone();
        let answer = server.serve_space(config, request).await?;
        client.open_space_response(&config.address, &nonce, answer)
    }
    async fn attach(client: &mut ClientApp, address: SpaceAddress, value: Value) -> String {
        let mut spaces = client.spaces.take().unwrap();
        let id = spaces.add_joined(client, address, value).await.unwrap();
        client.spaces = Some(spaces);
        id
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
            configurations.push(ServiceConfig {
                name: name.into(),
                address: SpaceAddress {
                    url: "http://127.0.0.1:9/team/v1/spaces".into(),
                    scope: server.team_scope().unwrap(),
                },
                owners: vec![owner.identity_id()],
                peer,
            });
        }
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
        let response = first.serve_space(a, request).await.unwrap();
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
        assert!(first.serve_space(a, expired).await.is_err());
        assert!(
            command(
                &mut first,
                a,
                &user,
                "invite",
                json!({"lifetime":86400,"require_approval":false})
            )
            .await
            .is_err()
        );
        let offer = command(
            &mut first,
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
            &mut first,
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
        let manage = command(&mut first, a, &owner, "manage", json!({}))
            .await
            .unwrap();
        command(
            &mut first,
            a,
            &owner,
            "decide",
            json!({"id":manage["requests"][0]["id"],"approve":true}),
        )
        .await
        .unwrap();
        let approved = command(
            &mut first,
            a,
            &user,
            "status",
            json!({"enrollment":enrollment}),
        )
        .await
        .unwrap();
        attach(&mut user, a.address.clone(), approved).await;
        let offer_b = command(
            &mut second,
            b,
            &owner,
            "invite",
            json!({"lifetime":86400,"require_approval":false}),
        )
        .await
        .unwrap();
        let invitation_b = SpaceInvitation::parse(offer_b["link"].as_str().unwrap(), true).unwrap();
        let approved_b=command(&mut second,b,&user,"join",json!({"token":invitation_b.token,"enrollment":user.team_enrollment_request(&b.address.scope).unwrap()})).await.unwrap();
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
        assert_eq!(user.view().await.unwrap()["active_space"], b_id);
        let mut invalid = targeted;
        invalid["target_space"] = json!("disconnected-space");
        assert!(user.operate(invalid).await.is_err());
        for more in [true, true, false] {
            let result = user.operate(json!({"op":"sync_live"})).await.unwrap();
            assert_eq!(result["result"]["more"], more);
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
        let restored = ClientApp::restore_profile(
            temp.path().join("restored"),
            &backup,
            PASSWORD.into(),
            user.identity_id(),
            "synthetic new spaces password".into(),
            true,
        )
        .await
        .unwrap();
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
        command(
            &mut second,
            b,
            &owner,
            "revoke",
            json!({"id":offer_b["id"]}),
        )
        .await
        .unwrap();
        assert!(command(&mut second,b,&owner,"join",json!({"token":invitation_b.token,"enrollment":owner.team_enrollment_request(&b.address.scope).unwrap()})).await.is_err());
        let wrong = user.space_request(&a.address, "manage", json!({})).unwrap();
        assert!(second.serve_space(b, wrong).await.is_err());
        user.close().await.unwrap();
        owner.close().await.unwrap();
        first.close().await.unwrap();
        second.close().await.unwrap();
    }
}

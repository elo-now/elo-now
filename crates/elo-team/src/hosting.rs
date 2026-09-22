//! Hosting provisions independent mailboxes and General service identities.
//! The replica remains a ciphertext store; no user recovery secret is accepted.
use super::*;
use crate::attachments::{AttachmentStorage, AttachmentStorageConfig};
use axum::{
    body::Body,
    extract::{Path, Request},
    http::{HeaderMap, header},
    response::{Html, IntoResponse},
};
use elo_core::{
    app::{
        space_host::{self, CreateCommand, CreateRequest, CreateResponse},
        space_service::{DeletionReceipt, SpaceAddress},
    },
    ids::{IdentityId, ObjectId},
    replica::{MailboxDescriptor, ReplicaStore},
    sync::PeerDescriptor,
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path as FilePath,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tower::ServiceExt;
mod account_deletion;
mod calls;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostConfig {
    pub root: PathBuf,
    pub public_url: String,
    pub max_spaces_per_identity: usize,
    pub mailbox_quota_bytes: u64,
    #[serde(default)]
    pub operator_snapshot: Option<PathBuf>,
    #[serde(default)]
    pub call_admission_key: Option<PathBuf>,
    #[serde(default)]
    pub attachment_storage: Option<AttachmentStorageConfig>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    creator: Option<IdentityId>,
    request_id: String,
    name: String,
    #[serde(default)]
    contact_email: Option<String>,
    message_lifetime_seconds: u64,
    mailbox: MailboxDescriptor,
    password: String,
    #[serde(default)]
    invitation: Option<String>,
    #[serde(default)]
    invitation_issued: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deleted {
    receipt: DeletionReceipt,
    mailbox: elo_core::ids::MailboxId,
}
struct HostedSpace {
    id: String,
    replica: ReplicaStore,
    transport: Router,
    serving: RwLock<bool>,
    client: Mutex<Option<ClientApp>>,
    config: ServiceConfig,
    mailbox: elo_core::ids::MailboxId,
}
struct Host {
    config: HostConfig,
    call_admission_key: Option<Zeroizing<Vec<u8>>>,
    spaces: RwLock<BTreeMap<String, Arc<HostedSpace>>>,
    // A single admitted creator bounds Argon2 work and makes reservations atomic.
    creation: Mutex<()>,
    accounts: Mutex<()>,
    started: std::time::Instant,
    allow_loopback: bool,
    attachment_storage: Option<Arc<dyn AttachmentStorage>>,
}
fn current() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}
fn private_directory(path: &FilePath) -> Result<()> {
    if path.exists() {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("Unsafe hosting directory.".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("Hosting storage must be private.".into());
            }
        }
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}
fn save<T: Serialize>(path: &FilePath, value: &T) -> Result<()> {
    vault::write_private(path, &Zeroizing::new(serde_json::to_vec(value)?), true)?;
    Ok(())
}
fn reservation_id(creator: IdentityId, request_id: &str) -> String {
    ObjectId::of_ciphertext(format!("elo.host.v1:{creator}:{request_id}").as_bytes()).to_string()
}
impl Host {
    async fn open(config: HostConfig, allow_loopback: bool) -> Result<Arc<Self>> {
        space_host::validate_host(
            &format!("{}/spaces/v1/create", config.public_url),
            allow_loopback,
        )?;
        if config.public_url.ends_with('/')
            || config.max_spaces_per_identity == 0
            || !(16 * 1024 * 1024..=1024 * 1024 * 1024).contains(&config.mailbox_quota_bytes)
        {
            return Err("Invalid hosting capacity.".into());
        }
        private_directory(&config.root)?;
        private_directory(&config.root.join("spaces"))?;
        private_directory(&config.root.join("deleted"))?;
        private_directory(&config.root.join("account-deletions"))?;
        private_directory(&config.root.join("account-receipts"))?;
        if config.root.join("replica").exists() {
            return Err("Shared Replica storage requires a separate migration. Use a new hosting directory.".into());
        }
        let attachment_storage = match config.attachment_storage.as_ref() {
            Some(storage) => Some(storage.open().await?),
            None => None,
        };
        let host = Arc::new(Self {
            call_admission_key: calls::load_key(config.call_admission_key.as_deref())?,
            config,
            spaces: RwLock::new(BTreeMap::new()),
            creation: Mutex::new(()),
            accounts: Mutex::new(()),
            started: std::time::Instant::now(),
            allow_loopback,
            attachment_storage,
        });
        let mut pending_deletions = Vec::new();
        for entry in std::fs::read_dir(host.config.root.join("deleted"))? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".elo-") && name.ends_with(".tmp"))
            {
                continue;
            }
            let id = entry
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or("Invalid deletion marker.")?
                .to_owned();
            let _: ObjectId = id.parse()?;
            pending_deletions.push(id);
        }
        for entry in std::fs::read_dir(host.config.root.join("spaces"))? {
            let entry = entry?;
            let id = entry
                .file_name()
                .to_str()
                .ok_or("Invalid hosted Space directory.")?
                .to_owned();
            let _: ObjectId = id.parse()?;
            private_directory(&entry.path())?;
            // A crash during directory removal can leave only Replica files.
            // The durable deletion marker, not a missing reservation, owns
            // that remainder; finish_deletion validates it before cleanup.
            if pending_deletions.contains(&id) && !entry.path().join("config.json").exists() {
                continue;
            }
            let reservation: Reservation = serde_json::from_slice(&Zeroizing::new(
                vault::read_private(&entry.path().join("reservation.json"))?,
            ))?;
            if reservation
                .creator
                .is_some_and(|creator| reservation_id(creator, &reservation.request_id) != id)
            {
                return Err("Hosting reservation mismatch.".into());
            }
            if entry.path().join("config.json").exists() {
                let space = host.open_ready(&id, &reservation, None).await?;
                host.spaces.write().await.insert(id, space);
            }
        }
        // Open a Space before finishing an interrupted deletion so its signed
        // attachment inventory is available to every storage provider.
        for id in pending_deletions {
            host.finish_deletion(&id).await?;
        }
        Ok(host)
    }
    async fn open_ready(
        &self,
        id: &str,
        reservation: &Reservation,
        prepared: Option<ClientApp>,
    ) -> Result<Arc<HostedSpace>> {
        let path = self.config.root.join("spaces").join(id);
        let config: ServiceConfig = serde_json::from_slice(&Zeroizing::new(vault::read_private(
            &path.join("config.json"),
        )?))?;
        config.address.validate(self.allow_loopback)?;
        if config.name != reservation.name
            || config.address.url
                != format!("{}/spaces/{id}/team/v1/spaces", self.config.public_url)
            || config.peer.mailbox_id != reservation.mailbox.mailbox_id
        {
            return Err("Hosted Space configuration mismatch.".into());
        }
        let replica = ReplicaStore::open(path.join("replica")).await?;
        if replica.supports_account_erasure().await? {
            replica.require_content_ownership().await?;
        }
        if config.peer.url != format!("{}/spaces/{id}/replica/", self.config.public_url)
            || config.peer.signing_public_key != record::encode_hex(replica.key().as_bytes())
        {
            return Err("Hosted Space Replica identity mismatch.".into());
        }
        replica
            .reserve_mailbox(reservation.mailbox.clone(), self.config.mailbox_quota_bytes)
            .await?;
        let client = match prepared {
            // New provisioning has already authenticated and persisted this profile.
            Some(client) => client,
            None => {
                ClientApp::open(
                    path.join("profile"),
                    reservation.password.clone().into(),
                    self.allow_loopback,
                )
                .await?
            }
        };
        client.set_attachment_storage_available(self.attachment_storage.is_some())?;
        if serde_json::to_value(client.team_scope()?)?
            != serde_json::to_value(&config.address.scope)?
        {
            return Err("Hosted Space profile mismatch.".into());
        }
        replica
            .set_space_members(
                reservation.mailbox.mailbox_id,
                client.space_access_members()?,
            )
            .await?;
        Ok(Arc::new(HostedSpace {
            id: id.to_owned(),
            transport: elo_core::http::space_router(replica.clone(), id.parse()?),
            replica,
            serving: RwLock::new(true),
            client: Mutex::new(Some(client)),
            mailbox: reservation.mailbox.mailbox_id,
            config,
        }))
    }
    async fn finish_deletion(&self, id: &str) -> Result<DeletionReceipt> {
        let deleted: Deleted = serde_json::from_slice(&Zeroizing::new(vault::read_private(
            &self.config.root.join("deleted").join(format!("{id}.json")),
        )?))?;
        if let Some(storage) = &self.attachment_storage {
            if let Some(space) = self.spaces.read().await.get(id).cloned() {
                let targets = {
                    let client = space.client.lock().await;
                    client
                        .as_ref()
                        .map(ClientApp::attachment_all_targets)
                        .transpose()?
                        .unwrap_or_default()
                };
                for target in targets {
                    storage.delete(id, &target.object_id.to_string()).await?;
                }
            }
            storage.delete_space(id).await?;
        }
        let removed = self.spaces.write().await.remove(id);
        let path = self.config.root.join("spaces").join(id);
        if let Some(space) = removed {
            // Drain transport before revoking the mailbox and unlinking its DB.
            // Requests holding a previous Arc must also observe this closed gate.
            *space.serving.write().await = false;
            if let Some(client) = space.client.lock().await.take() {
                client.close().await?;
            }
            space.replica.delete_mailbox_tree(deleted.mailbox).await?;
        } else if path.join("replica").exists() {
            let replica = ReplicaStore::open(path.join("replica")).await?;
            replica.delete_mailbox_tree(deleted.mailbox).await?;
        }
        if path.exists() {
            private_directory(&path)?;
            std::fs::remove_dir_all(&path)?;
        }
        // Hosting backups are separated per Space, never a mixed full database.
        let backup = self.config.root.join("backups").join(id);
        if backup.exists() {
            private_directory(&backup)?;
            std::fs::remove_dir_all(&backup)?;
        }
        Ok(deleted.receipt)
    }
    async fn provision(
        &self,
        command: &CreateCommand,
        creator: IdentityId,
    ) -> Result<(String, Reservation)> {
        let id = reservation_id(creator, &command.request_id);
        let path = self.config.root.join("spaces").join(&id);
        if self
            .config
            .root
            .join("deleted")
            .join(format!("{id}.json"))
            .exists()
        {
            return Err("This Space was deleted.".into());
        }
        let reservation_path = path.join("reservation.json");
        let mut reservation: Reservation = if reservation_path.exists() {
            serde_json::from_slice(&Zeroizing::new(vault::read_private(&reservation_path)?))?
        } else {
            let entries = std::fs::read_dir(self.config.root.join("spaces"))?
                .collect::<std::io::Result<Vec<_>>>()?;
            let mut owned = 0;
            for entry in &entries {
                let r: Reservation = serde_json::from_slice(&Zeroizing::new(vault::read_private(
                    &entry.path().join("reservation.json"),
                )?))?;
                if r.creator == Some(creator) {
                    owned += 1;
                }
            }
            if owned >= self.config.max_spaces_per_identity {
                return Err("Hosting capacity reached.".into());
            }
            let value = Reservation {
                creator: Some(creator),
                request_id: command.request_id.clone(),
                name: command.name.clone(),
                contact_email: Some(command.contact_email.clone()),
                message_lifetime_seconds: command.message_lifetime_seconds,
                mailbox: MailboxDescriptor::random()?,
                password: record::random_hex::<32>()?,
                invitation: None,
                invitation_issued: 0,
            };
            // Stage and rename the reservation directory so a crash cannot leave
            // a counted directory without its durable allocation descriptor.
            let stage = self.config.root.join("reservation-stage");
            if stage.exists() {
                private_directory(&stage)?;
                std::fs::remove_dir_all(&stage)?;
            }
            private_directory(&stage)?;
            save(&stage.join("reservation.json"), &value)?;
            std::fs::rename(stage, &path)?;
            std::fs::File::open(self.config.root.join("spaces"))?.sync_all()?;
            value
        };
        if reservation.creator != Some(creator)
            || reservation.request_id != command.request_id
            || reservation.name != command.name
            || reservation.contact_email.as_deref() != Some(&command.contact_email)
            || reservation.message_lifetime_seconds != command.message_lifetime_seconds
        {
            return Err("Creation request cannot be changed.".into());
        }
        if !self.spaces.read().await.contains_key(&id) {
            let mut prepared = None;
            if !path.join("config.json").exists() {
                let replica = ReplicaStore::open(path.join("replica")).await?;
                replica
                    .reserve_mailbox(reservation.mailbox.clone(), self.config.mailbox_quota_bytes)
                    .await?;
                // This profile has never been advertised until config.json is
                // committed. An interrupted preparation may be rebuilt safely.
                let profile = path.join("profile");
                if profile.exists() {
                    private_directory(&profile)?;
                    std::fs::remove_dir_all(&profile)?;
                }
                let peer = PeerDescriptor {
                    url: format!("{}/spaces/{id}/replica/", self.config.public_url),
                    signing_public_key: record::encode_hex(replica.key().as_bytes()),
                    mailbox_id: reservation.mailbox.mailbox_id,
                    read_token: Some(reservation.mailbox.read_token.clone()),
                    write_token: Some(reservation.mailbox.write_token.clone()),
                };
                // Only General's service holds a sending capability. New members
                // receive the full Space descriptor in their encrypted reply.
                let client = ProfileDraft::new()?
                    .with_peer(
                        PeerDescriptor {
                            read_token: None,
                            ..peer.clone()
                        },
                        self.allow_loopback,
                    )?
                    .save_named(
                        profile,
                        reservation.password.clone().into(),
                        "General",
                        "elo.now",
                    )
                    .await?;
                let config = ServiceConfig {
                    name: reservation.name.clone(),
                    address: SpaceAddress {
                        url: format!("{}/spaces/{id}/team/v1/spaces", self.config.public_url),
                        scope: client.team_scope()?,
                        message_lifetime_seconds: reservation.message_lifetime_seconds,
                    },
                    owners: vec![creator],
                    contact_email: reservation.contact_email.clone(),
                    peer,
                };
                save(&path.join("config.json"), &config)?;
                prepared = Some(client);
            }
            self.spaces.write().await.insert(
                id.clone(),
                self.open_ready(&id, &reservation, prepared).await?,
            );
        }
        if reservation.invitation.is_none()
            || current()?.saturating_sub(reservation.invitation_issued) > 23 * 3_600_000
        {
            let space = self
                .spaces
                .read()
                .await
                .get(&id)
                .cloned()
                .ok_or("Space unavailable.")?;
            reservation.invitation = Some(
                space
                    .client
                    .lock()
                    .await
                    .as_ref()
                    .ok_or("Space was deleted.")?
                    .bootstrap_space_invitation(&space.config.address)?,
            );
            reservation.invitation_issued = current()?;
            save(&reservation_path, &reservation)?;
        }
        Ok((id, reservation))
    }
}
async fn create(
    State(host): State<Arc<Host>>,
    Json(request): Json<CreateRequest>,
) -> std::result::Result<Json<CreateResponse>, StatusCode> {
    let _accounts = host
        .accounts
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let expected = format!("{}/spaces/v1/create", host.config.public_url);
    let (command, credential) = space_host::verify_create(
        &request,
        &expected,
        current().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    if host.account_requested(credential.identity()) {
        return Err(StatusCode::GONE);
    }
    let _permit = host
        .creation
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let (_, reservation) = host
        .provision(&command, credential.identity())
        .await
        .map_err(|e| {
            if e.to_string() == "Hosting capacity reached." {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        })?;
    space_host::seal_creation(
        &credential,
        &command,
        reservation
            .invitation
            .as_deref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?,
    )
    .map(Json)
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
async fn command(
    State(host): State<Arc<Host>>,
    Path(id): Path<String>,
    Json(request): Json<SpaceRequest>,
) -> std::result::Result<axum::response::Response, StatusCode> {
    let _accounts = host
        .accounts
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let _: ObjectId = id.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    if elo_core::app::space_service::request_identity(&request)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .is_some_and(|identity| host.account_requested(identity))
    {
        return Err(StatusCode::GONE);
    }
    // Prevent a pending deletion target becoming primary between admission and cleanup.
    if host
        .account_scope_pending(&id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let marker = host.config.root.join("deleted").join(format!("{id}.json"));
    if marker.exists() {
        let _permit = host
            .creation
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let receipt = host
            .finish_deletion(&id)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        return Ok((StatusCode::GONE, Json(receipt)).into_response());
    }
    let space = host
        .spaces
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut guard = space
        .client
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let client = guard.as_mut().ok_or(StatusCode::GONE)?;
    if let Some(receipt) = client
        .authorize_space_deletion(&space.config, &request)
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let _permit = host
            .creation
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        save(
            &marker,
            &Deleted {
                receipt,
                mailbox: space.mailbox,
            },
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        guard
            .take()
            .unwrap()
            .close()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        drop(guard);
        let receipt = host
            .finish_deletion(&id)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        return Ok((StatusCode::GONE, Json(receipt)).into_response());
    }
    let reply = client
        .serve_hosted_space(&space.config, request, &space.replica)
        .await;
    space
        .replica
        .set_space_members(
            space.mailbox,
            client
                .space_access_members()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    reply
        .map(|r| Json(r).into_response())
        .map_err(|_| StatusCode::BAD_REQUEST)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && value.len() <= 256)
}

#[derive(Clone)]
struct UploadDigest {
    bytes: u64,
    hash: Sha256,
    overflow: bool,
}

async fn attachment_upload(
    State(host): State<Arc<Host>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> StatusCode {
    if id.parse::<ObjectId>().is_err() {
        return StatusCode::NOT_FOUND;
    }
    let Some(token) = bearer(&headers).map(str::to_owned) else {
        return StatusCode::UNAUTHORIZED;
    };
    let Some(storage) = host.attachment_storage.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let Some(space) = host.spaces.read().await.get(&id).cloned() else {
        return StatusCode::NOT_FOUND;
    };
    if !*space.serving.read().await {
        return StatusCode::GONE;
    }
    let grant = {
        let client = match tokio::time::timeout(Duration::from_secs(2), space.client.lock()).await {
            Ok(client) => client,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
        };
        let Some(client) = client.as_ref() else {
            return StatusCode::GONE;
        };
        match client.attachment_upload_grant(&token, current().unwrap_or_default()) {
            Ok(grant) => grant,
            Err(_) => return StatusCode::UNAUTHORIZED,
        }
    };
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        != Some(grant.encrypted_size)
    {
        return StatusCode::BAD_REQUEST;
    }
    let digest = Arc::new(std::sync::Mutex::new(UploadDigest {
        bytes: 0,
        hash: Sha256::new(),
        overflow: false,
    }));
    let tracker = digest.clone();
    let maximum = grant.encrypted_size;
    let stream = request.into_body().into_data_stream().map(move |chunk| {
        let chunk = chunk.map_err(std::io::Error::other)?;
        let mut state = tracker
            .lock()
            .map_err(|_| std::io::Error::other("upload state"))?;
        state.bytes = state
            .bytes
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| std::io::Error::other("attachment size"))?;
        if state.bytes > maximum {
            state.overflow = true;
            return Err(std::io::Error::other("attachment size"));
        }
        state.hash.update(&chunk);
        Ok(chunk)
    });
    if storage
        .put(
            &id,
            &grant.object_id.to_string(),
            Body::from_stream(stream),
            grant.encrypted_size,
        )
        .await
        .is_err()
    {
        let _ = storage.delete(&id, &grant.object_id.to_string()).await;
        return StatusCode::BAD_GATEWAY;
    }
    let (bytes, checksum, overflow) = {
        let state = match digest.lock() {
            Ok(state) => state,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            state.bytes,
            elo_core::record::encode_hex(&state.hash.clone().finalize()),
            state.overflow,
        )
    };
    if overflow || bytes != grant.encrypted_size || checksum != grant.ciphertext_sha256 {
        let _ = storage.delete(&id, &grant.object_id.to_string()).await;
        if let Ok(client) = space.client.try_lock()
            && let Some(client) = client.as_ref()
        {
            let _ = client.attachment_mark_missing(grant.attachment_id);
        }
        return StatusCode::UNPROCESSABLE_ENTITY;
    }
    let client = match tokio::time::timeout(Duration::from_secs(2), space.client.lock()).await {
        Ok(client) => client,
        Err(_) => {
            let _ = storage.delete(&id, &grant.object_id.to_string()).await;
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    };
    let Some(client) = client.as_ref() else {
        let _ = storage.delete(&id, &grant.object_id.to_string()).await;
        return StatusCode::GONE;
    };
    match client.attachment_upload_complete(&token, current().unwrap_or_default()) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => {
            let _ = storage.delete(&id, &grant.object_id.to_string()).await;
            StatusCode::CONFLICT
        }
    }
}

async fn attachment_download(
    State(host): State<Arc<Host>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    if id.parse::<ObjectId>().is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(token) = bearer(&headers).map(str::to_owned) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(storage) = host.attachment_storage.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(space) = host.spaces.read().await.get(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let grant = {
        let client = match tokio::time::timeout(Duration::from_secs(2), space.client.lock()).await {
            Ok(client) => client,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        let Some(client) = client.as_ref() else {
            return StatusCode::GONE.into_response();
        };
        match client.attachment_download_grant(&token, current().unwrap_or_default()) {
            Ok(grant) => grant,
            Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
        }
    };
    let stored = match storage.get(&id, &grant.object_id.to_string()).await {
        Ok(stored) => stored,
        Err(_) => {
            if let Ok(client) = space.client.try_lock()
                && let Some(client) = client.as_ref()
            {
                let _ = client.attachment_mark_missing(grant.attachment_id);
            }
            return StatusCode::NOT_FOUND.into_response();
        }
    };
    if stored.size != grant.encrypted_size {
        let _ = storage.delete(&id, &grant.object_id.to_string()).await;
        if let Ok(client) = space.client.try_lock()
            && let Some(client) = client.as_ref()
        {
            let _ = client.attachment_mark_missing(grant.attachment_id);
        }
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let mut response = axum::response::Response::new(Body::from_stream(stored.body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&stored.size.to_string()).expect("bounded length"),
    );
    response
}
// The operator listener is separate and loopback-only. The public router never
// exposes these endpoints, even if a reverse proxy accidentally forwards a path.
async fn statistics(State(host): State<Arc<Host>>) -> impl IntoResponse {
    let spaces: Vec<_> = host
        .spaces
        .read()
        .await
        .iter()
        .map(|(id, s)| (id.clone(), s.clone()))
        .collect();
    let mut summaries = Vec::new();
    let mut storage = json!({"objects":0u64,"bytes":0u64,"mailboxes":[]});
    let mut complete = true;
    for (id, space) in spaces {
        let (counts, attachments) = match space.client.try_lock() {
            Ok(client) => (
                client
                    .as_ref()
                    .and_then(|c| c.space_service_statistics().ok()),
                client
                    .as_ref()
                    .and_then(|c| c.attachment_storage_usage().ok()),
            ),
            Err(_) => (None, None),
        };
        match space.replica.storage_statistics().await {
            Ok(value) => {
                for key in ["objects", "bytes"] {
                    storage[key] =
                        json!(storage[key].as_u64().unwrap() + value[key].as_u64().unwrap_or(0));
                }
                if let Some(rows) = value["mailboxes"].as_array() {
                    storage["mailboxes"]
                        .as_array_mut()
                        .unwrap()
                        .extend(rows.iter().cloned());
                }
            }
            Err(_) => complete = false,
        }
        summaries.push(
            json!({"id":id,"name":space.config.name,"mailbox":space.mailbox,"membership":counts,"attachments":attachments}),
        );
    }
    let storage = complete.then_some(storage);
    let snapshot = host
        .config
        .operator_snapshot
        .as_ref()
        .and_then(|path| vault::read_private(path).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    Json(
        json!({"spaces":summaries,"storage":storage,"uptime_seconds":host.started.elapsed().as_secs(),
        "capacity":{"per_identity":host.config.max_spaces_per_identity,"bytes_per_space":host.config.mailbox_quota_bytes},
        "system":system_statistics(),"operator_snapshot":snapshot}),
    )
}
fn system_statistics() -> Value {
    let load = std::fs::read_to_string("/proc/loadavg").ok().map(|s| {
        s.split_whitespace()
            .take(3)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    let memory = std::fs::read_to_string("/proc/meminfo").ok().map(|s| {
        s.lines()
            .filter(|l| l.starts_with("MemTotal:") || l.starts_with("MemAvailable:"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    json!({"load_average":load,"memory":memory})
}
// Route by the stable reservation in the path, never by profile or backend IP.
async fn replica_request(
    State(host): State<Arc<Host>>,
    request: Request,
) -> axum::response::Response {
    let Some((id, _)) = request
        .uri()
        .path()
        .strip_prefix("/spaces/")
        .and_then(|rest| rest.split_once("/replica/"))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if id.parse::<ObjectId>().is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let space = host.spaces.read().await.get(id).cloned();
    let Some(space) = space else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let serving = space.serving.read().await;
    if !*serving {
        return StatusCode::GONE.into_response();
    }
    // No prefix rewriting: the inner router checks the complete signed URI.
    space.transport.clone().oneshot(request).await.unwrap()
}

fn app(host: Arc<Host>) -> Router {
    Router::new()
        .route("/spaces/v1/create", post(create))
        .route(
            elo_core::app::account_deletion::PATH,
            post(account_deletion::request),
        )
        .route(
            elo_core::app::account_deletion::STATUS_PATH,
            post(account_deletion::status),
        )
        .route("/spaces/{id}/team/v1/spaces", post(command))
        .route(
            "/spaces/{id}/attachments/v1/upload",
            axum::routing::put(attachment_upload).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/spaces/{id}/attachments/v1/download",
            get(attachment_download),
        )
        .route("/spaces/v1/health", get(|| async { StatusCode::OK }))
        .layer(DefaultBodyLimit::max(space_host::CREATE_LIMIT))
        .fallback(replica_request)
        .with_state(host)
}
pub(super) async fn run(config: PathBuf, bind: std::net::SocketAddr) -> Result<()> {
    if !bind.ip().is_loopback() || bind.port() == 65535 {
        return Err("Bind hosting to loopback behind HTTPS.".into());
    }
    let config: HostConfig =
        serde_json::from_slice(&Zeroizing::new(vault::read_private(&config)?))?;
    let host = Host::open(config, false).await?;
    let worker = host.clone();
    let task = tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(5));
        loop {
            timer.tick().await;
            let _ = worker.process_account_deletions().await;
            let spaces: Vec<_> = worker.spaces.read().await.values().cloned().collect();
            for space in spaces {
                let _ = space.replica.maintain_message_lifetime().await;
                let mut cleanup = Vec::new();
                if let Ok(client) = space.client.try_lock()
                    && let Some(client) = client.as_ref()
                {
                    let _ = client.deliver_team_memberships().await;
                    cleanup = client
                        .attachment_cleanup_targets(current().unwrap_or_default(), 32)
                        .unwrap_or_default();
                }
                if let Some(storage) = &worker.attachment_storage {
                    for target in cleanup {
                        if storage
                            .delete(&space.id, &target.object_id.to_string())
                            .await
                            .is_ok()
                            && let Ok(client) = space.client.try_lock()
                            && let Some(client) = client.as_ref()
                        {
                            let _ = client.attachment_cleanup_complete(target.attachment_id);
                        }
                    }
                }
            }
        }
    });
    let operator = Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("hosting/admin.html")) }),
        )
        .route("/stats", get(statistics))
        .route("/internal/calls/admission", post(calls::admit))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(host.clone());
    let public_listener = tokio::net::TcpListener::bind(bind).await?;
    let operator_listener =
        tokio::net::TcpListener::bind(std::net::SocketAddr::new(bind.ip(), bind.port() + 1))
            .await?;
    let operator_task = tokio::spawn(async move { axum::serve(operator_listener, operator).await });
    let result = axum::serve(public_listener, app(host.clone()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    task.abort();
    operator_task.abort();
    let _ = task.await;
    let _ = operator_task.await;
    for (_, space) in std::mem::take(&mut *host.spaces.write().await) {
        Arc::try_unwrap(space)
            .map_err(|_| "Could not close hosted Space.")?
            .client
            .into_inner()
            .ok_or("Space already closed.")?
            .close()
            .await?;
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &str = "synthetic hosted Spaces test password";
    pub(super) async fn profile(path: &FilePath) -> ClientApp {
        ProfileDraft::new()
            .unwrap()
            .save_named(
                path.to_path_buf(),
                PASSWORD.into(),
                "General",
                "Test person",
            )
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        let mut client = ClientApp::open(path.to_path_buf(), PASSWORD.into(), true)
            .await
            .unwrap();
        client.begin_space_setup().await.unwrap();
        client
    }
    pub(super) async fn close_host(host: Arc<Host>) {
        for (_, space) in std::mem::take(&mut *host.spaces.write().await) {
            Arc::try_unwrap(space)
                .ok()
                .unwrap()
                .client
                .into_inner()
                .unwrap()
                .close()
                .await
                .unwrap();
        }
        drop(host);
    }
    #[tokio::test]
    async fn device_link_uses_selected_space_and_transfers_the_entire_profile() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use elo_core::app::pairing::{PREFIX, PairSource, PairTarget};
        let temp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let host = Host::open(
            HostConfig {
                root: temp.path().join("host"),
                public_url: base.clone(),
                max_spaces_per_identity: 3,
                mailbox_quota_bytes: 256 * 1024 * 1024,
                operator_snapshot: None,
                call_admission_key: None,
                attachment_storage: None,
            },
            true,
        )
        .await
        .unwrap();
        let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
        let mut owner = profile(&temp.path().join("owner")).await;
        assert_eq!(
            PairSource::new(&owner).await.err().unwrap().to_string(),
            "Connect to a Space before linking a device."
        );
        let mut ids = Vec::new();
        for name in ["Family", "Work"] {
            let created = owner
                .operate(
                    json!({"op":"space_create", "host":format!("{base}/spaces/v1/create"),
                "name":name,"contact_email":"owner@example.test","message_lifetime_seconds":86400}),
                )
                .await
                .unwrap();
            ids.push(created["view"]["active_space"].as_str().unwrap().to_owned());
            owner
                .operate(json!({"op":"space_setup_done"}))
                .await
                .unwrap();
            let view = owner.view().await.unwrap();
            let general = view["streams"]
                .as_array()
                .unwrap()
                .iter()
                .find(|stream| stream["is_general"] == true)
                .unwrap();
            owner
                .operate(
                    json!({"op":"send","space":general["space"],"stream":general["stream"],
                "text":format!("Only {name}"),"created_at":"2026-09-21T10:00:00Z"}),
                )
                .await
                .unwrap();
        }
        owner
            .operate(json!({"op":"space_select","id":ids[0]}))
            .await
            .unwrap();
        let mut source = PairSource::new(&owner).await.unwrap();
        let link = source.link().unwrap();
        let offer: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(link.strip_prefix(PREFIX).unwrap())
                .unwrap(),
        )
        .unwrap();
        let selected = owner.view().await.unwrap()["replicas"][0]["id"].clone();
        let descriptor: PeerDescriptor = serde_json::from_value(offer["mailbox"].clone()).unwrap();
        assert_eq!(
            json!(elo_core::sync::Peer::new(descriptor, true).unwrap().id()),
            selected
        );
        let mut target = PairTarget::new(&link, "New device", true).unwrap();
        target.send().await.unwrap();
        let pending = source.poll().await.unwrap();
        let request = &pending["requests"][0];
        let code = target.summary().unwrap()["code"]
            .as_str()
            .unwrap()
            .to_owned();
        source
            .approve(&owner, request["id"].as_str().unwrap(), &code)
            .await
            .unwrap();
        target.poll().await.unwrap();
        let mut linked = target
            .finish(temp.path().join("linked"), PASSWORD.into(), &code)
            .await
            .unwrap();
        linked.enable_spaces().await.unwrap();
        assert_eq!(linked.identity_id(), owner.identity_id());
        assert_eq!(linked.connected_space_ids().len(), 2);
        for (id, name) in ids.iter().zip(["Family", "Work"]) {
            linked
                .operate(json!({"op":"space_select","id":id}))
                .await
                .unwrap();
            let view = linked.view().await.unwrap();
            let general = view["streams"]
                .as_array()
                .unwrap()
                .iter()
                .find(|stream| stream["is_general"] == true)
                .unwrap();
            assert!(
                general["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|message| message["body"]["payload"]["text"] == format!("Only {name}")),
                "device transfer retains each Space's separate history"
            );
        }
        // Disconnect must never fall back to the former root mailbox or a stale
        // child. Another joined Space remains a valid pairing transport.
        owner
            .operate(json!({"op":"space_disconnect","id":ids[0],"confirmed":true}))
            .await
            .unwrap();
        let next = PairSource::new(&owner).await.unwrap().link().unwrap();
        let next: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(next.strip_prefix(PREFIX).unwrap())
                .unwrap(),
        )
        .unwrap();
        let selected = owner.view().await.unwrap()["replicas"][0]["id"].clone();
        let descriptor: PeerDescriptor = serde_json::from_value(next["mailbox"].clone()).unwrap();
        assert_eq!(
            json!(elo_core::sync::Peer::new(descriptor, true).unwrap().id()),
            selected
        );
        owner
            .operate(json!({"op":"space_disconnect","id":ids[1],"confirmed":true}))
            .await
            .unwrap();
        assert!(PairSource::new(&owner).await.is_err());
        linked.close().await.unwrap();
        owner.close().await.unwrap();
        task.abort();
        let _ = task.await;
        close_host(host).await;
    }

    #[tokio::test]
    async fn attachments_are_encrypted_outside_the_replica_and_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let external = temp.path().join("external-attachments");
        let config = HostConfig {
            root: temp.path().join("host"),
            public_url: base.clone(),
            max_spaces_per_identity: 3,
            mailbox_quota_bytes: 32 * 1024 * 1024,
            operator_snapshot: None,
            call_admission_key: None,
            attachment_storage: Some(AttachmentStorageConfig::Local {
                root: external.clone(),
            }),
        };
        let host = Host::open(config, true).await.unwrap();
        let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
        let mut owner = profile(&temp.path().join("owner")).await;
        let created = owner
            .operate(json!({
                "op":"space_create",
                "contact_email":"owner@example.test",
                "host":format!("{base}/spaces/v1/create"),
                "message_lifetime_seconds":86400,
                "name":"Files"
            }))
            .await
            .unwrap();
        assert!(created["view"]["active_space"].as_str().is_some());
        owner
            .operate(json!({"op":"space_setup_done"}))
            .await
            .unwrap();
        let view = owner.view().await.unwrap();
        let general = view["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stream| stream["is_general"] == true)
            .unwrap();
        owner
            .operate(json!({
                "op":"send",
                "space":general["space"],
                "stream":general["stream"],
                "text":"Before attachment",
                "created_at":"2000-01-01T00:00:00Z"
            }))
            .await
            .unwrap();
        let input = temp.path().join("family-photo.txt");
        let content = b"ciphertext belongs in external attachment storage".repeat(500);
        std::fs::write(&input, &content).unwrap();
        // Cancel from the first emitted ciphertext bytes, not before starting.
        // The independent cancellation handle must stop without committing a row.
        let cancellation = elo_core::app::AttachmentCancellation::default();
        let cancel_upload = cancellation.clone();
        let cancelled = owner
            .operate_attachment_transfer(
                json!({
                    "op":"attachment_upload", "space":general["space"], "stream":general["stream"],
                    "path":input, "name":"family-photo.txt"
                }),
                cancellation,
                move |sent, _| {
                    if sent > 0 {
                        cancel_upload.cancel();
                    }
                },
            )
            .await;
        assert!(
            cancelled
                .unwrap_err()
                .to_string()
                .contains("Attachment transfer cancelled")
        );
        let cancelled_history = owner
            .operate(json!({"op":"history_page", "space":general["space"],
            "stream":general["stream"], "expected_identity":owner.identity_id()}))
            .await
            .unwrap();
        assert!(
            cancelled_history["history"]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["body"]["kind"] != "file.shared")
        );
        assert_eq!(
            std::fs::read(&input).unwrap(),
            content,
            "cancelling preserves the selected input for retry"
        );
        // Run the same five-second cleanup operation as the host worker.
        for hosted in host.spaces.read().await.values() {
            let client = hosted.client.lock().await;
            let client = client.as_ref().unwrap();
            let targets = client
                .attachment_cleanup_targets(current().unwrap(), 32)
                .unwrap();
            assert_eq!(
                targets.len(),
                1,
                "cancelled reservation is reclaimed without waiting for its TTL"
            );
            for target in targets {
                host.attachment_storage
                    .as_ref()
                    .unwrap()
                    .delete(&hosted.id, &target.object_id.to_string())
                    .await
                    .unwrap();
                client
                    .attachment_cleanup_complete(target.attachment_id)
                    .unwrap();
            }
            let usage = client.attachment_storage_usage().unwrap();
            assert_eq!(usage.used_bytes + usage.reserved_bytes, 0);
        }

        owner.enable_paged_views();
        let uploaded = owner
            .operate_attachment_transfer(
                json!({
                    "op":"attachment_upload",
                    "space":general["space"],
                    "stream":general["stream"],
                    "path":input,
                    "name":"family-photo.txt",
                    "expected_identity":owner.identity_id(),
                    "expected_space":view["active_space"]
                }),
                elo_core::app::AttachmentCancellation::default(),
                |_, _| {},
            )
            .await
            .unwrap();
        let record = uploaded["result"]["record"].as_str().unwrap().to_owned();
        assert_eq!(uploaded["view"]["identity"], json!(owner.identity_id()));
        assert_eq!(uploaded["view"]["active_space"], view["active_space"]);
        assert_eq!(uploaded["view"]["paged"], true);
        let committed = uploaded["view"]["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stream| stream["stream"] == general["stream"])
            .unwrap();
        assert_eq!(committed["space_context"], view["active_space"]);
        assert!(
            committed["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == record && row["body"]["filename"] == "family-photo.txt"),
            "upload returns the committed local projection before any message sync"
        );
        owner
            .operate(json!({
                "op":"send",
                "space":general["space"],
                "stream":general["stream"],
                "text":"After attachment",
                "created_at":"2099-01-01T00:00:00Z"
            }))
            .await
            .unwrap();
        let identity = owner.identity_id();
        let history = owner
            .operate(json!({
                "op":"history_page",
                "expected_identity":identity,
                "space":general["space"],
                "stream":general["stream"]
            }))
            .await
            .unwrap();
        let kinds = history["history"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["body"]["kind"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(kinds, ["chat.message", "file.shared", "chat.message"]);
        owner.operate(json!({"op":"sync"})).await.unwrap();
        let stored_spaces = std::fs::read_dir(&external)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(stored_spaces.len(), 1);
        let object_files = std::fs::read_dir(stored_spaces[0].path())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(object_files.len(), 1);
        let encrypted = std::fs::read(object_files[0].path()).unwrap();
        assert!(
            !encrypted
                .windows(content.len())
                .any(|window| window == content)
        );
        let cancelled_output = temp.path().join("cancelled-download.txt");
        let cancellation = elo_core::app::AttachmentCancellation::default();
        let cancel_download = cancellation.clone();
        let cancelled = owner.operate_attachment_transfer(json!({
            "op":"attachment_download", "space":general["space"], "stream":general["stream"],
            "record":record, "output":cancelled_output
        }), cancellation, move |received, _| { if received > 0 { cancel_download.cancel(); } }).await;
        assert!(
            cancelled
                .unwrap_err()
                .to_string()
                .contains("Attachment transfer cancelled")
        );
        assert!(
            !cancelled_output.exists(),
            "cancelled downloads must not publish any plaintext file"
        );
        let output = temp.path().join("downloaded.txt");
        owner
            .operate(json!({
                "op":"attachment_download",
                "space":general["space"],
                "stream":general["stream"],
                "record":record,
                "output":output
            }))
            .await
            .unwrap();
        assert_eq!(std::fs::read(output).unwrap(), content);
        let second_output = temp.path().join("downloaded-again.txt");
        owner
            .operate(json!({
                "op":"attachment_download",
                "space":general["space"],
                "stream":general["stream"],
                "record":record,
                "output":second_output
            }))
            .await
            .unwrap();
        assert_eq!(std::fs::read(second_output).unwrap(), content);
        task.abort();
        let _ = task.await;
        close_host(host).await;
    }
    #[tokio::test]
    async fn removal_revokes_transport_and_backup_history_and_rejoining_requires_approval() {
        use elo_core::{
            replica::{ChildMailbox, MailboxDescriptor},
            sync::Peer,
            vault::Session,
        };
        let temp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let config = HostConfig {
            root: temp.path().join("host"),
            public_url: base.clone(),
            max_spaces_per_identity: 2,
            mailbox_quota_bytes: 32 * 1024 * 1024,
            operator_snapshot: None,
            call_admission_key: None,
            attachment_storage: None,
        };
        let host = Host::open(config.clone(), true).await.unwrap();
        let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
        let mut owner = profile(&temp.path().join("owner")).await;
        let mut guest = profile(&temp.path().join("guest")).await;
        let created = owner.operate(json!({"op":"space_create","contact_email":"owner@example.test","host":format!("{base}/spaces/v1/create"),"message_lifetime_seconds":86400,"name":"Family"})).await.unwrap();
        let space = created["view"]["active_space"].as_str().unwrap().to_owned();
        let first_invitation = created["view"]["space_creation"]["invitation"]
            .as_str()
            .unwrap();
        let offers = owner
            .operate(json!({"op":"space_manage","id":space,"body":{}}))
            .await
            .unwrap();
        assert_eq!(offers["result"]["offers"].as_array().unwrap().len(), 1);
        assert_eq!(offers["result"]["offers"][0]["link"], first_invitation);
        owner
            .operate(json!({"op":"space_setup_done"}))
            .await
            .unwrap();
        let invite = owner.operate(json!({"op":"space_invite","id":space,"body":{"lifetime":86400,"require_approval":false}})).await.unwrap()["result"]["link"].clone();
        let joined = guest
            .operate(json!({"op":"space_join","link":invite}))
            .await
            .unwrap();
        assert_eq!(joined["view"]["spaces"][0]["status"], "joined");
        let chat = joined["view"]["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["is_general"] == true)
            .unwrap();
        guest.operate(json!({"op":"send","space":chat["space"],"stream":chat["stream"],"text":"History before removal","created_at":"2026-09-14T12:00:00Z"})).await.unwrap();
        guest.operate(json!({"op":"sync"})).await.unwrap();
        let backup = guest.export_profile(PASSWORD.into()).await.unwrap();
        let session = Session::open(
            &vault::read_private(
                &temp
                    .path()
                    .join("guest/spaces")
                    .join(&space)
                    .join("vault.age"),
            )
            .unwrap(),
            PASSWORD.into(),
            guest.identity_id(),
        )
        .unwrap();
        let descriptor = session.peers()[0].clone();
        let peer = Peer::new(descriptor.clone(), true)
            .unwrap()
            .with_identity(&session);
        assert!(peer.inventory(0).await.is_ok());
        assert!(
            Peer::new(descriptor.clone(), true)
                .unwrap()
                .inventory(0)
                .await
                .is_err(),
            "a shared token without a current identity proof must not bypass admission"
        );
        let child = ChildMailbox {
            descriptor: MailboxDescriptor::random().unwrap(),
            quota_bytes: 1024 * 1024,
            expires_at: current().unwrap() + 600_000,
        };
        peer.create_child(&child).await.unwrap();
        let child_peer = Peer::new(
            PeerDescriptor {
                mailbox_id: child.descriptor.mailbox_id,
                read_token: Some(child.descriptor.read_token.clone()),
                write_token: Some(child.descriptor.write_token.clone()),
                ..descriptor.clone()
            },
            true,
        )
        .unwrap()
        .with_identity(&session);
        assert!(child_peer.inventory(0).await.is_ok());
        let restored = ClientApp::restore_profile(
            temp.path().join("allowed"),
            &backup,
            PASSWORD.into(),
            guest.identity_id(),
            PASSWORD.into(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            restored.view().await.unwrap()["spaces"][0]["status"],
            "joined"
        );
        restored.close().await.unwrap();
        owner.operate(json!({"op":"space_role_change","id":space,"body":{"revision":0,"kind":"remove_member","target":guest.identity_id()}})).await.unwrap();
        assert!(peer.inventory(0).await.is_err());
        assert!(
            child_peer.inventory(0).await.is_err(),
            "child capabilities inherit live Space revocation"
        );
        assert!(
            peer.create_child(&ChildMailbox {
                descriptor: MailboxDescriptor::random().unwrap(),
                ..child.clone()
            })
            .await
            .is_err()
        );
        let denied = ClientApp::restore_profile(
            temp.path().join("denied"),
            &backup,
            PASSWORD.into(),
            guest.identity_id(),
            PASSWORD.into(),
            true,
        )
        .await
        .unwrap();
        assert!(
            denied.view().await.unwrap()["spaces"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!temp.path().join("denied/spaces").join(&space).exists());
        denied.close().await.unwrap();
        let resume_dir = temp.path().join("resume-denied");
        for paused in [true, false] {
            let result = elo_core::app::profile_backup::restore(
                elo_core::app::profile_backup::RestoreRequest {
                    directory: resume_dir.clone(),
                    bytes: &backup,
                    secret: PASSWORD.into(),
                    expected: guest.identity_id(),
                    password: PASSWORD.into(),
                    allow_loopback: true,
                    resume: true,
                    paged: true,
                },
                &elo_core::app::profile_backup::RestoreProgress::new(move |stage, _, _| {
                    !paused || stage != elo_core::app::profile_backup::RestoreStage::Ready
                }),
            )
            .await;
            if paused {
                assert!(result.is_err());
            } else {
                let app = result.unwrap();
                assert!(
                    app.view().await.unwrap()["spaces"]
                        .as_array()
                        .unwrap()
                        .is_empty()
                );
                app.close().await.unwrap();
            }
        }
        task.abort();
        let _ = task.await;
        close_host(host).await;
        let mut offline = ClientApp::restore_profile(
            temp.path().join("offline"),
            &backup,
            PASSWORD.into(),
            guest.identity_id(),
            PASSWORD.into(),
            true,
        )
        .await
        .unwrap();
        let view = offline.view().await.unwrap();
        assert_eq!(view["spaces"][0]["status"], "checking");
        assert!(view["all_streams"].as_array().unwrap().is_empty());
        assert!(
            temp.path().join("offline/spaces").join(&space).exists(),
            "an outage must preserve quarantined history"
        );
        // Restart reconstructs the current membership gate before opening the listener.
        let host = Host::open(config, true).await.unwrap();
        let listener = tokio::net::TcpListener::bind(base.trim_start_matches("http://"))
            .await
            .unwrap();
        let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
        assert!(peer.inventory(0).await.is_err());
        let rejoin = guest
            .operate(json!({"op":"space_join","link":invite}))
            .await
            .unwrap();
        assert_eq!(
            rejoin["view"]["spaces"][0]["status"], "pending",
            "previous removal overrides automatic invitation approval"
        );
        assert!(!temp.path().join("guest/spaces").join(&space).exists());
        let manage = owner
            .operate(json!({"op":"space_manage","id":space,"body":{}}))
            .await
            .unwrap();
        owner.operate(json!({"op":"space_decide","id":space,"body":{"id":manage["result"]["requests"][0]["id"],"approve":true}})).await.unwrap();
        guest.operate(json!({"op":"space_refresh"})).await.unwrap();
        assert_eq!(guest.view().await.unwrap()["spaces"][0]["status"], "joined");
        let view = offline
            .operate(json!({"op":"space_refresh"}))
            .await
            .unwrap()["view"]
            .clone();
        assert_eq!(view["spaces"][0]["status"], "joined");
        assert!(
            !view["all_streams"]
                .to_string()
                .contains("History before removal"),
            "missing the removal while offline must not restore the prior membership's history"
        );
        owner.operate(json!({"op":"space_refresh"})).await.unwrap();
        owner.operate(json!({"op":"sync"})).await.unwrap();
        owner.operate(json!({"op":"send","space":chat["space"],"stream":chat["stream"],"text":"After readmission","created_at":"2026-09-14T12:01:00Z"})).await.unwrap();
        owner.operate(json!({"op":"sync"})).await.unwrap();
        for app in [&mut guest, &mut offline] {
            app.operate(json!({"op":"sync"})).await.unwrap();
            let streams = app.view().await.unwrap()["all_streams"].to_string();
            assert!(streams.contains("After readmission"));
            assert!(
                !streams.contains("History before removal"),
                "synchronization must not resurrect the removed membership's history"
            );
        }
        offline.close().await.unwrap();
        guest.close().await.unwrap();
        owner.close().await.unwrap();
        task.abort();
        let _ = task.await;
        close_host(host).await;
    }
    #[tokio::test]
    async fn hosted_creation_retries_restart_approval_roles_and_mailbox_isolation() {
        let temp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let config = HostConfig {
            root: temp.path().join("hosting"),
            public_url: base.clone(),
            max_spaces_per_identity: 1,
            mailbox_quota_bytes: 32 * 1024 * 1024,
            operator_snapshot: None,
            call_admission_key: None,
            attachment_storage: None,
        };
        let host = Host::open(config.clone(), true).await.unwrap();
        let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
        let mut owner = profile(&temp.path().join("owner")).await;
        let mut guest = profile(&temp.path().join("guest")).await;
        assert!(
            owner
                .operate(json!({"op":"space_setup_done"}))
                .await
                .is_err()
        );
        let create = json!({"op":"space_create","contact_email":"owner@example.test","host":format!("{base}/spaces/v1/create"),"message_lifetime_seconds":86400,"name":"Family"});
        let mut invalid = create.clone();
        invalid["contact_email"] = json!("owner@example.test\r\nBcc: stranger@example.test");
        assert!(owner.operate(invalid).await.is_err());
        assert_eq!(host.spaces.read().await.len(), 0);
        let first = owner.operate(create.clone()).await.unwrap();
        assert_eq!(
            first["view"]["spaces"][0]["contact_email"],
            "owner@example.test"
        );
        let space = first["view"]["active_space"].as_str().unwrap().to_owned();
        assert_eq!(first["view"]["spaces"][0]["role"], "primary_owner");
        assert_eq!(first["view"]["space_setup"], true);
        let invitation = first["view"]["space_creation"]["invitation"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            owner.operate(create.clone()).await.unwrap()["view"]["active_space"],
            space
        );
        assert_eq!(host.spaces.read().await.len(), 1);
        owner.close().await.unwrap();
        task.abort();
        let _ = task.await;
        close_host(host).await;
        let host = Host::open(config.clone(), true).await.unwrap();
        let listener = tokio::net::TcpListener::bind(base.trim_start_matches("http://"))
            .await
            .unwrap();
        let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
        owner = ClientApp::open(temp.path().join("owner"), PASSWORD.into(), true)
            .await
            .unwrap();
        owner.enable_spaces().await.unwrap();
        assert_eq!(
            owner.operate(create).await.unwrap()["view"]["active_space"],
            space
        );
        owner
            .operate(json!({"op":"space_setup_done"}))
            .await
            .unwrap();
        assert_eq!(owner.view().await.unwrap()["space_setup"], false);
        assert!(owner.operate(json!({"op":"space_create","contact_email":"owner@example.test","host":format!("{base}/spaces/v1/create"),"message_lifetime_seconds":86400,"name":"Another"})).await.is_err());
        assert_eq!(host.spaces.read().await.len(), 1);
        assert!(
            guest
                .operate(json!({"op":"space_join","link":invitation,"note":"x".repeat(501)}))
                .await
                .is_err()
        );
        let joined = guest
            .operate(json!({"op":"space_join","link":invitation,"note":"I am Marek from the design team.\nWe met on Monday."}))
            .await
            .unwrap();
        assert_eq!(joined["view"]["spaces"][0]["status"], "pending");
        assert_eq!(joined["view"]["space_setup"], true);
        assert!(
            guest
                .operate(json!({"op":"space_manage","id":space,"body":{}}))
                .await
                .is_err()
        );
        let manage = owner
            .operate(json!({"op":"space_manage","id":space,"body":{}}))
            .await
            .unwrap();
        assert_eq!(
            manage["result"]["requests"][0]["note"],
            "I am Marek from the design team.\nWe met on Monday."
        );
        assert_eq!(
            manage["result"]["requests"][0]["identity"],
            json!(guest.identity_id())
        );
        assert!(
            guest
                .operate(json!({"op":"space_contact","id":space,"body":{}}))
                .await
                .is_err()
        );
        owner.operate(json!({"op":"space_decide","id":space,"body":{"id":manage["result"]["requests"][0]["id"],"approve":true}})).await.unwrap();
        let approved = guest.operate(json!({"op":"space_refresh"})).await.unwrap();
        assert_eq!(approved["view"]["spaces"][0]["status"], "joined");
        assert_eq!(approved["view"]["space_setup"], false);
        assert_eq!(
            guest
                .operate(json!({"op":"space_contact","id":space,"body":{}}))
                .await
                .unwrap()["result"]["contact_email"],
            "owner@example.test"
        );
        assert!(guest.operate(json!({"op":"space_contact_update","id":space,"body":{"revision":0,"contact_email":"wrong@example.test"}})).await.is_err());
        owner.operate(json!({"op":"space_contact_update","id":space,"body":{"revision":0,"contact_email":"current@example.test"}})).await.unwrap();
        assert_eq!(
            guest
                .operate(json!({"op":"space_contact","id":space,"body":{}}))
                .await
                .unwrap()["result"]["contact_email"],
            "current@example.test"
        );
        // Signed storage commands require a current owner, not a mailbox token.
        assert!(
            guest
                .operate(json!({"op":"space_storage","id":space,"body":{"days":100}}))
                .await
                .is_err()
        );
        assert!(guest.operate(json!({"op":"space_storage_prune","id":space,"body":{"days":100,"before_ms":0,"confirmed":true}})).await.is_err());
        for days in [0, 36501] {
            assert!(
                owner
                    .operate(json!({"op":"space_storage","id":space,"body":{"days":days}}))
                    .await
                    .is_err()
            );
        }
        let transport = host
            .spaces
            .read()
            .await
            .values()
            .find(|s| s.config.address.scope.space.to_string() == space)
            .unwrap()
            .config
            .peer
            .clone();
        let replica = host
            .spaces
            .read()
            .await
            .values()
            .find(|s| s.config.address.scope.space.to_string() == space)
            .unwrap()
            .replica
            .clone();
        let fixture = b"PUBLIC HOSTED CONTROL FIXTURE".to_vec();
        replica
            .post(
                transport.mailbox_id,
                transport.write_token.unwrap(),
                ObjectId::of_ciphertext(&fixture),
                fixture,
                elo_core::replica::TransferHint::Eager,
            )
            .await
            .unwrap();
        let storage = owner
            .operate(json!({"op":"space_storage","id":space,"body":{"days":100}}))
            .await
            .unwrap()["result"]
            .clone();
        assert_eq!(storage["quota_bytes"], config.mailbox_quota_bytes);
        assert_eq!(storage["removable_copies"], 0);
        assert!(storage["used_bytes"].as_u64().unwrap() > 0);
        assert!(owner.operate(json!({"op":"space_storage_prune","id":space,"body":{"days":100,"before_ms":current().unwrap(),"confirmed":true}})).await.is_err());
        assert!(owner.operate(json!({"op":"space_storage_prune","id":space,"body":{"days":100,"before_ms":storage["before_ms"],"confirmed":false}})).await.is_err());
        let cleared=owner.operate(json!({"op":"space_storage_prune","id":space,"body":{"days":100,"before_ms":storage["before_ms"],"confirmed":true}})).await.unwrap();
        assert_eq!(cleared["result"]["removable_bytes"], 0);
        owner.operate(json!({"op":"space_role_change","id":space,"body":{"revision":0,"kind":"make_owner","target":guest.identity_id()}})).await.unwrap();
        guest.operate(json!({"op":"space_refresh"})).await.unwrap();
        assert_eq!(guest.view().await.unwrap()["spaces"][0]["role"], "owner");
        owner.operate(json!({"op":"space_role_change","id":space,"body":{"revision":1,"kind":"transfer_primary","target":guest.identity_id()}})).await.unwrap();
        let status = guest.operate(json!({"op":"space_refresh"})).await.unwrap();
        let request = &status["view"]["space_role_requests"][0];
        assert_eq!(request["request"]["kind"], "transfer_primary");
        assert!(guest.operate(json!({"op":"space_role_decide","id":space,"body":{"revision":2,"request_id":request["request"]["id"],"approve":true}})).await.is_err());
        assert_eq!(
            owner
                .operate(json!({"op":"space_contact","id":space,"body":{}}))
                .await
                .unwrap()["result"]["contact_email"],
            "current@example.test"
        );
        guest.operate(json!({"op":"space_role_decide","id":space,"body":{"revision":2,"request_id":request["request"]["id"],"approve":true,"contact_email":"new-owner@example.test"}})).await.unwrap();
        assert_eq!(
            owner
                .operate(json!({"op":"space_contact","id":space,"body":{}}))
                .await
                .unwrap()["result"]["contact_email"],
            "new-owner@example.test"
        );
        assert!(owner.operate(json!({"op":"space_contact_update","id":space,"body":{"revision":3,"contact_email":"old-owner@example.test"}})).await.is_err());
        assert_eq!(
            guest.view().await.unwrap()["spaces"][0]["role"],
            "primary_owner"
        );
        let other=guest.operate(json!({"op":"space_create","contact_email":"owner@example.test","host":format!("{base}/spaces/v1/create"),"message_lifetime_seconds":86400,"name":"Friends"})).await.unwrap();
        assert_ne!(other["view"]["active_space"], space);
        let mailboxes: Vec<_> = host
            .spaces
            .read()
            .await
            .values()
            .map(|s| s.mailbox)
            .collect();
        assert_eq!(mailboxes.len(), 2);
        assert_ne!(mailboxes[0], mailboxes[1]);
        let pins: Vec<_> = host
            .spaces
            .read()
            .await
            .values()
            .map(|s| s.config.peer.signing_public_key.clone())
            .collect();
        assert_ne!(pins[0], pins[1]);
        let (deleted_id, peer) = host
            .spaces
            .read()
            .await
            .iter()
            .find(|(_, s)| s.config.address.scope.space.to_string() == space)
            .map(|(id, s)| (id.clone(), s.config.peer.clone()))
            .unwrap();
        let delete = json!({"op":"space_delete","id":space,"body":{"revision":3,"name":"Family","confirmed":true}});
        assert!(owner.operate(delete.clone()).await.is_err());
        let original_mailbox = MailboxDescriptor {
            mailbox_id: peer.mailbox_id,
            read_token: peer.read_token.clone().unwrap(),
            write_token: peer.write_token.clone().unwrap(),
        };
        let child = elo_core::replica::ChildMailbox {
            descriptor: MailboxDescriptor::random().unwrap(),
            quota_bytes: 1024,
            expires_at: current().unwrap() + 600_000,
        };
        replica
            .create_child(
                peer.mailbox_id,
                peer.write_token.clone().unwrap(),
                child.clone(),
            )
            .await
            .unwrap();
        let payload = vec![42u8; 100];
        let object = ObjectId::of_ciphertext(&payload);
        replica
            .post(
                child.descriptor.mailbox_id,
                child.descriptor.write_token.clone(),
                object,
                payload,
                elo_core::replica::TransferHint::Eager,
            )
            .await
            .unwrap();
        let backup = host.config.root.join("backups");
        private_directory(&backup).unwrap();
        private_directory(&backup.join(&deleted_id)).unwrap();
        save(
            &backup.join(&deleted_id).join("synthetic.json"),
            &json!({"test":true}),
        )
        .unwrap();
        guest.operate(delete).await.unwrap();
        assert_eq!(host.spaces.read().await.len(), 1);
        assert!(!host.config.root.join("spaces").join(&deleted_id).exists());
        assert!(!backup.join(&deleted_id).exists());
        assert!(
            replica
                .authorize(peer.mailbox_id, peer.read_token.unwrap(), false)
                .await
                .is_err()
        );
        assert!(
            replica
                .authorize(
                    child.descriptor.mailbox_id,
                    child.descriptor.read_token,
                    false
                )
                .await
                .is_err()
        );
        let refreshed = owner.operate(json!({"op":"space_refresh"})).await.unwrap();
        assert_eq!(refreshed["view"]["space_setup"], true);
        assert!(refreshed["view"]["spaces"].as_array().unwrap().is_empty());
        let proof = host.finish_deletion(&deleted_id).await.unwrap();
        assert!(!serde_json::to_string(&proof).unwrap().contains("Family"));
        assert!(
            owner
                .operate(json!({"op":"space_preview","link":invitation}))
                .await
                .is_err()
        );
        assert!(
            replica.storage_statistics().await.unwrap()["mailboxes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|m| m["id"] != json!(peer.mailbox_id))
        );
        let public = reqwest::Client::new();
        assert_eq!(
            public
                .get(format!("{base}/stats"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            public
                .get(format!("{base}/"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        owner.close().await.unwrap();
        guest.close().await.unwrap();
        task.abort();
        let _ = task.await;
        // Simulate a crash after the durable deletion receipt but before every
        // storage directory and mailbox was removed. Startup must finish it.
        drop(replica);
        let deleted_path = host.config.root.join("spaces").join(&deleted_id);
        private_directory(&deleted_path).unwrap();
        let stale = ReplicaStore::open(deleted_path.join("replica"))
            .await
            .unwrap();
        stale
            .reserve_mailbox(original_mailbox.clone(), config.mailbox_quota_bytes)
            .await
            .unwrap();
        drop(stale);
        private_directory(&backup.join(&deleted_id)).unwrap();
        close_host(host).await;
        let recovered = Host::open(config, true).await.unwrap();
        assert_eq!(recovered.spaces.read().await.len(), 1);
        assert!(
            !recovered
                .config
                .root
                .join("spaces")
                .join(&deleted_id)
                .exists()
        );
        assert!(!backup.join(&deleted_id).exists());
        assert!(
            recovered
                .spaces
                .read()
                .await
                .values()
                .next()
                .unwrap()
                .replica
                .authorize(
                    original_mailbox.mailbox_id,
                    original_mailbox.read_token,
                    false
                )
                .await
                .is_err()
        );
        close_host(recovered).await;
    }
    #[tokio::test]
    async fn a_space_moves_between_nodes_without_changing_the_client_address_or_pin() {
        use elo_core::{replica::TransferHint, sync::Peer, vault::Session};
        let temp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let config = HostConfig {
            root: temp.path().join("node-a"),
            public_url: base.clone(),
            max_spaces_per_identity: 3,
            mailbox_quota_bytes: 32 * 1024 * 1024,
            operator_snapshot: None,
            call_admission_key: None,
            attachment_storage: None,
        };
        let host = Host::open(config.clone(), true).await.unwrap();
        let route = Arc::new(RwLock::new(app(host.clone())));
        let upstream = route.clone();
        let gateway = Router::new().fallback(move |request: Request| {
            let upstream = upstream.clone();
            async move {
                let service = upstream.read().await.clone();
                service.oneshot(request).await.unwrap()
            }
        });
        let server = tokio::spawn(axum::serve(listener, gateway).into_future());
        let mut owner = profile(&temp.path().join("owner")).await;
        let family = owner.operate(json!({"op":"space_create","contact_email":"owner@example.test","host":format!("{base}/spaces/v1/create"),"message_lifetime_seconds":86400,"name":"Family"})).await.unwrap();
        let family_space = family["view"]["active_space"].as_str().unwrap();
        let (id, descriptor) = host
            .spaces
            .read()
            .await
            .iter()
            .next()
            .map(|(id, space)| (id.clone(), space.config.peer.clone()))
            .unwrap();
        let session = Session::open(
            &vault::read_private(
                &temp
                    .path()
                    .join("owner/spaces")
                    .join(family_space)
                    .join("vault.age"),
            )
            .unwrap(),
            PASSWORD.into(),
            owner.identity_id(),
        )
        .unwrap();
        let peer = Peer::new(descriptor.clone(), true)
            .unwrap()
            .with_identity(&session);
        let payload = b"synthetic persisted object before relocation".to_vec();
        let object = ObjectId::of_ciphertext(&payload);
        host.spaces.read().await[&id]
            .replica
            .post(
                descriptor.mailbox_id,
                descriptor.write_token.clone().unwrap(),
                object,
                payload.clone(),
                TransferHint::Eager,
            )
            .await
            .unwrap();
        let before = peer.inventory(0).await.unwrap();
        owner
            .operate(json!({"op":"space_setup_done"}))
            .await
            .unwrap();
        owner.operate(json!({"op":"space_create","contact_email":"owner@example.test","host":format!("{base}/spaces/v1/create"),"message_lifetime_seconds":86400,"name":"Friends"})).await.unwrap();
        let other = host
            .spaces
            .read()
            .await
            .iter()
            .find(|(key, _)| *key != &id)
            .map(|(_, space)| space.config.peer.clone())
            .unwrap();
        assert_ne!(descriptor.signing_public_key, other.signing_public_key);
        let other_peer = Peer::new(other.clone(), true)
            .unwrap()
            .with_identity(&session);
        assert!(other_peer.inventory(0).await.is_ok());

        // Planned maintenance in an isolated fixture. This is not a production
        // migration API: writers are stopped before the entire directory moves.
        *route.write().await = Router::new();
        close_host(host).await;
        let destination = HostConfig {
            root: temp.path().join("node-b"),
            ..config.clone()
        };
        close_host(Host::open(destination.clone(), true).await.unwrap()).await;
        std::fs::rename(
            config.root.join("spaces").join(&id),
            destination.root.join("spaces").join(&id),
        )
        .unwrap();
        let node_a = Host::open(config.clone(), true).await.unwrap();
        let node_b = Host::open(destination.clone(), true).await.unwrap();
        assert_eq!(node_a.spaces.read().await.len(), 1);
        assert_eq!(node_b.spaces.read().await.len(), 1);
        assert_eq!(
            node_b.spaces.read().await[&id]
                .config
                .peer
                .signing_public_key,
            descriptor.signing_public_key
        );
        let a = app(node_a.clone());
        let b = app(node_b.clone());
        let prefix = format!("/spaces/{id}/");
        *route.write().await = Router::new().fallback(move |request: Request| {
            let target = if request.uri().path().starts_with(&prefix) {
                b.clone()
            } else {
                a.clone()
            };
            async move { target.oneshot(request).await.unwrap() }
        });
        // Reuse the same Peer and credential, without editing configuration,
        // installing a new client, rejoining or trusting another signing key.
        assert_eq!(
            peer.get(object, payload.len() as u64).await.unwrap(),
            payload
        );
        let after = peer.inventory(0).await.unwrap();
        assert_eq!(before.storage_generation, after.storage_generation);
        assert_eq!(before.head, after.head);
        let new_payload = b"synthetic object after relocation".to_vec();
        let new_id = ObjectId::of_ciphertext(&new_payload);
        node_b.spaces.read().await[&id]
            .replica
            .post(
                descriptor.mailbox_id,
                descriptor.write_token.clone().unwrap(),
                new_id,
                new_payload.clone(),
                TransferHint::Eager,
            )
            .await
            .unwrap();
        assert_eq!(
            peer.get(new_id, new_payload.len() as u64).await.unwrap(),
            new_payload
        );
        assert!(other_peer.inventory(0).await.is_ok());
        let misrouted = Peer::new(
            PeerDescriptor {
                url: other.url,
                ..descriptor
            },
            true,
        )
        .unwrap()
        .with_identity(&session);
        assert!(misrouted.inventory(0).await.is_err());
        owner.operate(json!({"op":"space_refresh"})).await.unwrap();
        assert_eq!(
            owner.view().await.unwrap()["spaces"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        owner.close().await.unwrap();
        server.abort();
        let _ = server.await;
        *route.write().await = Router::new();
        close_host(node_a).await;
        close_host(node_b).await;
    }

    #[tokio::test]
    async fn reservation_cannot_replace_capabilities_or_quota() {
        let temp = tempfile::tempdir().unwrap();
        let store = ReplicaStore::open(temp.path().join("replica"))
            .await
            .unwrap();
        let mailbox = MailboxDescriptor::random().unwrap();
        store.reserve_mailbox(mailbox.clone(), 100).await.unwrap();
        store.reserve_mailbox(mailbox.clone(), 100).await.unwrap();
        assert!(store.reserve_mailbox(mailbox.clone(), 101).await.is_err());
        let mut wrong = mailbox.clone();
        wrong.read_token = MailboxDescriptor::random().unwrap().read_token;
        assert!(store.reserve_mailbox(wrong, 100).await.is_err());
        store
            .authorize(mailbox.mailbox_id, mailbox.read_token, false)
            .await
            .unwrap();
        assert_eq!(
            store.storage_statistics().await.unwrap()["mailboxes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}

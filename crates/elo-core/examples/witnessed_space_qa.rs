//! Acceptance driver for isolated EU test services and freshly generated profiles.
//! It never opens an existing user profile or prints invitation secrets.
//! Usage: witnessed_space_qa CONFIG [--prepare | --cleanup]. Preparation prints
//! only the synthetic owner's public identity for operator allowlists. Optional
//! hosting_profile_file/hosting_profile_link explicitly approve a signed hosting
//! configuration bound to CONFIG's independently supplied host and witness pin.
//! Only the owner imports that configuration. Guests discover it from the Space
//! invitation, with a different built-in origin and no prior hosting registry.
//! managed_attachment tests a synthetic file. own_storage_file can supply a
//! private limited-provider configuration, which is never printed or archived.
//! Failed runs retain their profiles; --cleanup only deletes that run's Space.
use elo_core::{
    app::{ClientApp, ProfileDraft, Result},
    authority::WitnessPin,
    hosting_profile::HostingProfile,
    message_retention::MessageRetention,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const PASSWORD: &str = "Synthetic EU acceptance profile 2026 only";
const SPACE_NAME: &str = "Witnessed acceptance";
const CLEANUP_FILE: &str = "created-space.json";
const PREPARED_FILE: &str = "prepared-owner.json";
const GUEST_DEFAULT_HOST: &str = "https://unused-default.example.invalid/spaces/v1/create";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    root: PathBuf,
    host: String,
    witness: WitnessPin,
    #[serde(default)]
    hosting_profile_file: Option<PathBuf>,
    #[serde(default)]
    hosting_profile_link: Option<String>,
    #[serde(default)]
    message_lifetime_seconds: MessageRetention,
    #[serde(default)]
    managed_attachment: bool,
    #[serde(default)]
    own_storage_file: Option<PathBuf>,
    #[serde(default)]
    expected_call_url: Option<String>,
    #[serde(skip)]
    profile: Option<HostingProfile>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedOwner {
    owner_identity: String,
    host: String,
    witness: WitnessPin,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CleanupTarget {
    id: String,
    owner: String,
    host: String,
    witness: WitnessPin,
}

impl Config {
    fn load_hosting(&mut self) -> Result<()> {
        if self.hosting_profile_file.is_some() && self.hosting_profile_link.is_some() {
            return Err("Choose one signed hosting configuration source.".into());
        }
        let source = match (&self.hosting_profile_file, &self.hosting_profile_link) {
            (Some(path), None) => {
                let metadata = std::fs::symlink_metadata(path)?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > 65536
                {
                    return Err("Expected a bounded public hosting configuration file.".into());
                }
                Some(std::fs::read_to_string(path)?)
            }
            (None, Some(link)) => Some(link.clone()),
            _ => None,
        };
        self.profile = source
            .as_deref()
            .map(|source| -> Result<HostingProfile> {
                let trimmed = source.trim();
                let link = if trimmed.starts_with(elo_core::hosting_profile::PREFIX) {
                    trimmed.to_owned()
                } else {
                    let exported: Value = serde_json::from_str(trimmed)?;
                    exported["link"]
                        .as_str()
                        .ok_or("Hosting export has no signed link.")?
                        .to_owned()
                };
                let (profile, _) = HostingProfile::parse_link(&link)?;
                if profile.create_url != self.host || profile.witness != self.witness {
                    return Err(
                        "Signed hosting differs from the operator's independent endpoint/pin."
                            .into(),
                    );
                }
                if !profile
                    .message_lifetimes
                    .contains(&self.message_lifetime_seconds)
                {
                    return Err("Requested retention is not offered by this hosting.".into());
                }
                if let Some(expected) = &self.expected_call_url
                    && profile.call_url.as_ref() != Some(expected)
                {
                    return Err(
                        "Signed call endpoint differs from the operator's expectation.".into(),
                    );
                }
                if self.managed_attachment
                    && !profile.storage.as_ref().is_some_and(|s| {
                        s.url == "https://vps-fe606f9b.vps.ovh.net/storage/v1"
                            && s.managed.is_some()
                    })
                {
                    return Err("Managed attachment QA requires the isolated EU broker.".into());
                }
                Ok(profile)
            })
            .transpose()?;
        if self.managed_attachment && self.own_storage_file.is_some() {
            return Err("Choose managed or explicitly supplied own storage.".into());
        }
        if self.own_storage_file.is_some()
            && !self
                .profile
                .as_ref()
                .and_then(|p| p.storage.as_ref())
                .is_some_and(|s| {
                    s.url == "https://vps-fe606f9b.vps.ovh.net/storage/v1" && s.managed.is_none()
                })
        {
            return Err(
                "Own-storage QA requires the isolated EU broker without managed defaults.".into(),
            );
        }
        if self.profile.is_none()
            && (self.managed_attachment
                || self.own_storage_file.is_some()
                || self.expected_call_url.is_some())
        {
            return Err(
                "Private service QA requires an explicitly approved signed hosting profile.".into(),
            );
        }
        Ok(())
    }

    fn attachment_configuration(&self) -> Result<Value> {
        if let Some(path) = &self.own_storage_file {
            let bytes = Zeroizing::new(elo_core::vault::read_private(path)?);
            if bytes.len() > 32 * 1024 {
                return Err("Own storage configuration exceeds its bound.".into());
            }
            let provider: elo_core::attachments::broker::ProviderConfig =
                serde_json::from_slice(&bytes)
                    .map_err(|_| "Invalid private own-storage configuration.")?;
            provider
                .validate()
                .map_err(|_| "Invalid private own-storage configuration.")?;
            let mut value = serde_json::to_value(&provider)?;
            value["enabled"] = json!(true);
            return Ok(value);
        }
        Ok(if self.managed_attachment {
            json!({"enabled":true,"managed":true})
        } else {
            json!({"enabled":false})
        })
    }
}

fn private_root(path: &Path) -> Result<()> {
    let mut directory = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory.create(path)?;
    Ok(())
}

async fn prepare(config: &Config) -> Result<()> {
    private_root(&config.root)?;
    let mut owner = ProfileDraft::new()?
        .save_named(
            config.root.join("Owner"),
            PASSWORD.into(),
            "General",
            "Owner",
        )
        .await?;
    owner.begin_space_setup().await?;
    let prepared = PreparedOwner {
        owner_identity: owner.identity_id().to_string(),
        host: config.host.clone(),
        witness: config.witness.clone(),
    };
    owner.close().await?;
    elo_core::vault::write_private(
        &config.root.join(PREPARED_FILE),
        &serde_json::to_vec(&prepared)?,
        false,
    )?;
    println!("{}", json!({"owner_identity": prepared.owner_identity}));
    Ok(())
}

async fn disable_test_storage(owner: &mut ClientApp, id: &str) -> Result<()> {
    let status = checked(
        owner,
        json!({"op":"space_external_storage_status","id":id,"body":{}}),
        "read isolated attachment storage status",
    )
    .await?;
    if status["result"]["enabled"] == true {
        let revision = status["result"]["revision"]
            .as_u64()
            .ok_or("Missing storage revision")?;
        let disabled = checked(owner, json!({"op":"space_external_storage_disable","id":id,"body":{"expected_revision":revision}}), "disable uploads to the isolated attachment storage").await?;
        assert_eq!(disabled["result"]["enabled"], false);
    }
    Ok(())
}

async fn attachment_acceptance(
    config: &Config,
    owner: &mut ClientApp,
    guest: &mut ClientApp,
    id: &str,
    general: &Value,
) -> Result<()> {
    let plain = b"Synthetic elo hosting acceptance attachment. No user content.\n".repeat(64);
    let input = config.root.join("synthetic-upload.txt");
    elo_core::vault::write_private(&input, &plain, false)?;
    let owner_identity = owner.identity_id();
    let uploaded = checked(owner, json!({"op":"attachment_upload","space":general["space"],"stream":general["stream"],
        "expected_identity":owner_identity,"expected_space":id,"path":input,"name":"synthetic-acceptance.txt"}),
        "encrypt and upload a synthetic attachment through the selected broker").await?;
    let record = uploaded["result"]["record"]
        .as_str()
        .ok_or("Attachment record missing")?;
    checked(
        owner,
        json!({"op":"sync"}),
        "publish the encrypted attachment descriptor",
    )
    .await?;
    checked(
        guest,
        json!({"op":"sync"}),
        "receive the encrypted attachment descriptor",
    )
    .await?;
    let output = config.root.join("synthetic-downloaded.txt");
    let request = json!({"op":"attachment_download","space":general["space"],"stream":general["stream"],
        "expected_identity":guest.identity_id(),"expected_space":id,"record":record,"output":output});
    checked(
        guest,
        request.clone(),
        "download and authenticate the synthetic attachment",
    )
    .await?;
    assert_eq!(std::fs::read(&output)?, plain);
    disable_test_storage(owner, id).await?;
    let cached = config.root.join("synthetic-cached.txt");
    assert!(guest.cached_attachment(&request, &cached).await?.is_some());
    assert_eq!(std::fs::read(&cached)?, plain);
    println!(
        "PASS attachment bytes match and authenticated local cache survives remote storage disable"
    );
    Ok(())
}

async fn cleanup(config: &Config) -> Result<()> {
    let target: CleanupTarget = serde_json::from_slice(&elo_core::vault::read_private(
        &config.root.join(CLEANUP_FILE),
    )?)?;
    if target.host != config.host || target.witness != config.witness {
        return Err("Cleanup target does not match this isolated run".into());
    }
    let mut owner = open(config, "Owner", false).await?;
    let result: Result<()> = async {
        if owner.identity_id().to_string() != target.owner {
            return Err("Cleanup owner does not match this isolated run".into());
        }
        let entry = space(&owner.view().await?, &target.id)?;
        if entry["name"] != SPACE_NAME || entry["role"] != "primary_owner" {
            return Err("Cleanup requires the original synthetic Space and primary owner".into());
        }
        if config.managed_attachment || config.own_storage_file.is_some() {
            disable_test_storage(&mut owner, &target.id).await?;
        }
        let management = owner
            .operate(json!({"op":"space_manage","id":target.id,"body":{}}))
            .await?;
        let revision = management["result"]["roles_revision"]
            .as_u64()
            .ok_or("Cleanup role revision missing")?;
        let deleted = owner
            .operate(json!({"op":"space_delete","id":target.id,
                "body":{"revision":revision,"name":SPACE_NAME,"confirmed":true}}))
            .await?;
        if deleted["result"]["status"] != "deleted" {
            return Err("Cleanup requires a verified Space deletion receipt".into());
        }
        println!("CLEANUP temporary Space deleted through its primary owner");
        Ok(())
    }
    .await;
    let closed = owner.close().await;
    result?;
    closed?;
    // The root was created exclusively for this run; retain it on any failure.
    std::fs::remove_dir_all(&config.root)?;
    Ok(())
}

async fn open(config: &Config, name: &str, fresh: bool) -> Result<ClientApp> {
    let path = config.root.join(name);
    let mut app = if fresh {
        ProfileDraft::new()?
            .save_named(path, PASSWORD.into(), "General", name)
            .await?
    } else {
        ClientApp::open(path, PASSWORD.into(), false).await?
    };
    let discover_hosting = config.profile.is_some() && name != "Owner";
    app.configure_invitation_host(if discover_hosting {
        GUEST_DEFAULT_HOST
    } else {
        &config.host
    })?;
    app.configure_witness_pin(Some(config.witness.clone()))?;
    if let Some(profile) = &config.profile
        && !discover_hosting
    {
        app.configure_hosting_profile(profile.clone())?;
        app.select_creation_hosting(Some(profile.clone()))?;
    }
    if fresh {
        app.begin_space_setup().await?;
    } else {
        app.enable_spaces().await?;
    }
    Ok(app)
}
fn space(view: &Value, id: &str) -> Result<Value> {
    view["spaces"]
        .as_array()
        .and_then(|v| v.iter().find(|s| s["id"] == id))
        .cloned()
        .ok_or_else(|| "Space missing".into())
}
async fn checked(app: &mut ClientApp, request: Value, stage: &str) -> Result<Value> {
    let result = app
        .operate(request)
        .await
        .map_err(|e| format!("{stage}: {e}"))?;
    println!("PASS {stage}");
    Ok(result)
}
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("Expected acceptance config")?;
    let mode = match args.next().as_deref() {
        None => "run",
        Some("--cleanup") => "cleanup",
        Some("--prepare") => "prepare",
        _ => return Err("Expected CONFIG [--prepare | --cleanup]".into()),
    };
    if args.next().is_some() {
        return Err("Expected CONFIG [--prepare | --cleanup]".into());
    }
    let mut config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let host = reqwest::Url::parse(&config.host)?;
    let witness = reqwest::Url::parse(&config.witness.url)?;
    if host.scheme() != "https"
        || witness.scheme() != "https"
        || !matches!(host.host_str(), Some("vps-336e3c9f.vps.ovh.net"))
        || !matches!(witness.host_str(), Some("vps-fe606f9b.vps.ovh.net"))
        || config.root.parent() != Some(Path::new("/var/tmp"))
        || !config
            .root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("elo-witnessed-e2e-"))
        || config.root.is_symlink()
        || (mode == "prepare" && config.root.exists())
        || (mode == "cleanup" && !config.root.is_dir())
    {
        return Err("Only a fresh isolated EU fixture is allowed".into());
    }
    if mode == "prepare" {
        return prepare(&config).await;
    }
    config.load_hosting()?;
    if mode == "cleanup" {
        return cleanup(&config).await;
    }
    let prepared = if config.root.exists() {
        if config.root.join(CLEANUP_FILE).exists() {
            return Err("This run already created a Space; use its explicit cleanup.".into());
        }
        let prepared: PreparedOwner = serde_json::from_slice(&elo_core::vault::read_private(
            &config.root.join(PREPARED_FILE),
        )?)?;
        if prepared.host != config.host || prepared.witness != config.witness {
            return Err("Prepared owner belongs to another isolated run.".into());
        }
        Some(prepared)
    } else {
        private_root(&config.root)?;
        None
    };
    let mut owner = open(&config, "Owner", prepared.is_none()).await?;
    if let Some(prepared) = prepared
        && owner.identity_id().to_string() != prepared.owner_identity
    {
        return Err("Prepared owner identity changed.".into());
    }
    let attachment_configuration = config.attachment_configuration()?;
    let create = json!({"op":"space_create","host":config.host,"name":SPACE_NAME,"contact_email":"owner@example.test",
        "message_lifetime_seconds":config.message_lifetime_seconds,"require_approval":false,"attachment_storage":attachment_configuration});
    if let Some(profile) = &config.profile {
        for unsupported in [MessageRetention::Hours48, MessageRetention::NoExpiry] {
            if !profile.message_lifetimes.contains(&unsupported) {
                let mut invalid = create.clone();
                invalid["message_lifetime_seconds"] = json!(unsupported);
                assert!(owner.operate(invalid).await.is_err());
                assert!(owner.view().await?["space_creation"].is_null());
            }
        }
        println!("PASS signed hosting rejects retention outside its advertised policies");
    }
    let created = checked(
        &mut owner,
        create.clone(),
        "create Space and publish encrypted short invitation",
    )
    .await;
    if created.is_err() {
        // Storage provisioning can fail after a Space has been committed. Keep
        // enough signed local evidence for --cleanup without printing its link.
        if let Ok(view) = owner.view().await
            && let Some(id) = view["active_space"].as_str()
            && let Ok(entry) = space(&view, id)
            && entry["name"] == SPACE_NAME
            && entry["role"] == "primary_owner"
        {
            elo_core::vault::write_private(
                &config.root.join(CLEANUP_FILE),
                &serde_json::to_vec(&CleanupTarget {
                    id: id.to_owned(),
                    owner: owner.identity_id().to_string(),
                    host: config.host.clone(),
                    witness: config.witness.clone(),
                })?,
                false,
            )?;
        }
    }
    let created = created?;
    let id = created["view"]["active_space"]
        .as_str()
        .ok_or("Missing active Space")?
        .to_owned();
    elo_core::vault::write_private(
        &config.root.join(CLEANUP_FILE),
        &serde_json::to_vec(&CleanupTarget {
            id: id.clone(),
            owner: owner.identity_id().to_string(),
            host: config.host.clone(),
            witness: config.witness.clone(),
        })?,
        false,
    )?;
    println!("Disposable Space: {id}");
    let link = created["view"]["space_creation"]["invitation"]
        .as_str()
        .ok_or("Missing invitation")?
        .to_owned();
    let invitation = elo_core::witness::link::InvitationLink::parse(&link)?;
    assert_eq!(
        invitation.hosting_id(),
        config.profile.as_ref().map(HostingProfile::id).as_deref()
    );
    if let Some(profile) = &config.profile {
        let origin = format!(
            "{}/",
            reqwest::Url::parse(&profile.create_url)?
                .origin()
                .ascii_serialization()
        );
        assert_eq!(invitation.hosting_origin(), Some(origin.as_str()));
        assert!(link.len() <= elo_core::witness::link::PREFIX.len() + 2860);
    } else {
        assert!(invitation.hosting_origin().is_none());
        assert_eq!(link.len(), elo_core::witness::link::PREFIX.len() + 87);
    }
    assert_eq!(space(&created["view"], &id)?["role"], "primary_owner");
    assert_eq!(
        space(&created["view"], &id)?["message_lifetime_seconds"],
        json!(config.message_lifetime_seconds)
    );
    if let Some(expected) = &config.expected_call_url {
        let endpoint = checked(
            &mut owner,
            json!({"op":"call_endpoint","hosting_space_id":id,"target_space":id}),
            "resolve the signed hosting call endpoint",
        )
        .await?;
        assert_eq!(endpoint["url"], *expected);
    }
    owner.close().await?;
    owner = open(&config, "Owner", false).await?;
    let retried = checked(&mut owner, create, "creation retry after profile restart").await?;
    assert_eq!(retried["view"]["active_space"], id);
    assert!(retried["view"]["space_creation"]["invitation"] == link);
    assert_eq!(
        space(&retried["view"], &id)?["message_lifetime_seconds"],
        json!(config.message_lifetime_seconds)
    );
    checked(
        &mut owner,
        json!({"op":"space_setup_done"}),
        "finish owner setup",
    )
    .await?;
    owner.close().await?;
    // There is deliberately no live owner while the candidate is admitted.
    let mut guest = open(&config, "Guest", true).await?;
    let catalog_path = config.root.join("Guest").join("spaces.age");
    let preview_snapshot = if config.profile.is_some() {
        Some((guest.view().await?, std::fs::read(&catalog_path)?))
    } else {
        None
    };
    if let Some(profile) = &config.profile {
        assert!(guest.hosting_profile_for_id(&profile.id()).is_none());
        assert!(guest.current_hosting_id().is_none());
    }
    let preview = checked(
        &mut guest,
        json!({"op":"space_preview","link":link}),
        "download and verify short invitation",
    )
    .await?;
    assert_eq!(preview["preview"]["name"], "Witnessed acceptance");
    assert_eq!(preview["preview"]["require_approval"], false);
    if let (Some(profile), Some((before_preview, catalog_before_preview))) =
        (&config.profile, &preview_snapshot)
    {
        assert!(guest.hosting_profile_for_id(&profile.id()).is_none());
        assert!(guest.current_hosting_id().is_none());
        let after_preview = guest.view().await?;
        assert_eq!(after_preview["spaces"], before_preview["spaces"]);
        assert_eq!(
            after_preview["active_space"],
            before_preview["active_space"]
        );
        assert_eq!(
            after_preview["space_creation"],
            before_preview["space_creation"]
        );
        assert!(std::fs::read(&catalog_path)?.as_slice() == catalog_before_preview.as_slice());
        // Closing instead of joining models cancelling the preview. Reopening
        // must not turn its temporary verification context into an import.
        guest.close().await?;
        guest = open(&config, "Guest", false).await?;
        assert!(guest.hosting_profile_for_id(&profile.id()).is_none());
        assert!(guest.current_hosting_id().is_none());
        let cancelled = guest.view().await?;
        assert_eq!(cancelled["spaces"], before_preview["spaces"]);
        assert_eq!(cancelled["active_space"], before_preview["active_space"]);
        println!("PASS invitation preview and cancellation leave hosting unimported");
    }
    let joined = checked(
        &mut guest,
        json!({"op":"space_join","link":link}),
        "join without owner online",
    )
    .await?;
    assert_eq!(space(&joined["view"], &id)?["status"], "joined");
    assert_eq!(space(&joined["view"], &id)?["role"], "member");
    assert_eq!(
        space(&joined["view"], &id)?["message_lifetime_seconds"],
        json!(config.message_lifetime_seconds)
    );
    if let Some(expected) = &config.expected_call_url {
        let endpoint = checked(
            &mut guest,
            json!({"op":"call_endpoint","hosting_space_id":id,"target_space":id}),
            "joined member retains the signed call endpoint",
        )
        .await?;
        assert_eq!(endpoint["url"], *expected);
    }
    guest.close().await?;
    guest = open(&config, "Guest", false).await?;
    if let Some(profile) = &config.profile {
        assert_eq!(guest.hosting_profile_for_id(&profile.id()), Some(profile));
        assert!(guest.current_hosting_id().is_none());
        println!("PASS joined Space restores all hosting pins without a separate import");
    }
    let refreshed = checked(
        &mut guest,
        json!({"op":"space_refresh"}),
        "refresh member after restart",
    )
    .await?;
    assert_eq!(space(&refreshed["view"], &id)?["status"], "joined");
    if let Some(expected) = &config.expected_call_url {
        let endpoint = checked(
            &mut guest,
            json!({"op":"call_endpoint","hosting_space_id":id,"target_space":id}),
            "restarted member resolves the invitation's call endpoint",
        )
        .await?;
        assert_eq!(endpoint["url"], *expected);
    }
    checked(
        &mut guest,
        json!({"op":"space_join","link":link}),
        "repeat join preserves membership",
    )
    .await?;
    guest.close().await?;
    owner = open(&config, "Owner", false).await?;
    let current = checked(
        &mut owner,
        json!({"op":"space_refresh"}),
        "owner imports admitted member",
    )
    .await?;
    let general = current["view"]["streams"]
        .as_array()
        .and_then(|streams| streams.iter().find(|s| s["name"] == "General"))
        .ok_or("General missing")?;
    checked(
        &mut owner,
        json!({"op":"send","space":general["space"],"stream":general["stream"],
        "text":"Witnessed end-to-end message","created_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)}),
        "encrypt and enqueue message for admitted member",
    )
    .await?;
    checked(
        &mut owner,
        json!({"op":"sync"}),
        "store encrypted message on replica",
    )
    .await?;
    guest = open(&config, "Guest", false).await?;
    let delivered = checked(
        &mut guest,
        json!({"op":"sync"}),
        "member downloads and verifies encrypted message",
    )
    .await?;
    assert!(serde_json::to_string(&delivered)?.contains("Witnessed end-to-end message"));
    if config.managed_attachment || config.own_storage_file.is_some() {
        attachment_acceptance(&config, &mut owner, &mut guest, &id, general).await?;
    }
    guest.close().await?;
    let notes_request = json!({"op":"contact_open","identity":owner.identity_id(),"name":"Notes"});
    let notes = checked(
        &mut owner,
        notes_request.clone(),
        "open private Notes through witnessed hosting",
    )
    .await?;
    let notes_stream = notes["stream"].clone();
    let notes_chat = notes["view"]["streams"]
        .as_array()
        .and_then(|streams| streams.iter().find(|chat| chat["stream"] == notes_stream))
        .ok_or("Notes missing")?;
    assert_eq!(
        notes_chat["members"]
            .as_array()
            .ok_or("Notes members missing")?
            .len(),
        1
    );
    checked(
        &mut owner,
        json!({"op":"send","space":notes_chat["space"],"stream":notes_stream,
        "text":"Private witnessed Notes acceptance","created_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)}),
        "encrypt own Notes message",
    )
    .await?;
    checked(
        &mut owner,
        json!({"op":"sync"}),
        "store encrypted Notes on replica",
    )
    .await?;
    owner.close().await?;
    owner = open(&config, "Owner", false).await?;
    let reopened_notes = checked(
        &mut owner,
        notes_request,
        "reopen the same Notes after profile restart",
    )
    .await?;
    assert_eq!(reopened_notes["stream"], notes_stream);
    guest = open(&config, "Guest", false).await?;
    let guest_view = checked(
        &mut guest,
        json!({"op":"sync"}),
        "other member cannot discover private Notes",
    )
    .await?;
    assert!(!serde_json::to_string(&guest_view)?.contains("Private witnessed Notes acceptance"));
    assert!(
        !guest_view["view"]["streams"]
            .as_array()
            .is_some_and(|streams| streams.iter().any(|chat| chat["stream"] == notes_stream))
    );
    guest.close().await?;
    let invite = checked(
        &mut owner,
        json!({"op":"space_invite","id":id,"body":{"lifetime":3600,"require_approval":true}}),
        "create approval invitation",
    )
    .await?;
    let approved_link = invite["result"]["link"]
        .as_str()
        .ok_or("Missing approval invitation")?
        .to_owned();
    owner.close().await?;
    let mut waiting = open(&config, "Waiting", true).await?;
    let pending = checked(
        &mut waiting,
        json!({"op":"space_join","link":approved_link}),
        "persist approval request while owner offline",
    )
    .await?;
    assert_eq!(space(&pending["view"], &id)?["status"], "pending");
    waiting.close().await?;
    owner = open(&config, "Owner", false).await?;
    let manage = checked(
        &mut owner,
        json!({"op":"space_manage","id":id,"body":{}}),
        "owner loads public pending evidence",
    )
    .await?;
    let request = manage["result"]["requests"]
        .as_array()
        .and_then(|v| v.first())
        .ok_or("No pending request")?;
    checked(
        &mut owner,
        json!({"op":"space_decide","id":id,"body":{"id":request["id"],"approve":true}}),
        "owner approves durable request",
    )
    .await?;
    checked(
        &mut owner,
        json!({"op":"space_decide","id":id,"body":{"id":request["id"],"approve":true}}),
        "owner approval retry preserves signed approval",
    )
    .await?;
    owner.close().await?;
    waiting = open(&config, "Waiting", false).await?;
    let completed = checked(
        &mut waiting,
        json!({"op":"space_refresh"}),
        "complete approved admission after restart with owner offline",
    )
    .await?;
    assert_eq!(space(&completed["view"], &id)?["status"], "joined");
    waiting.close().await?;
    owner = open(&config, "Owner", false).await?;
    let manage = checked(
        &mut owner,
        json!({"op":"space_manage","id":id,"body":{}}),
        "load published invitations",
    )
    .await?;
    let offer = manage["result"]["offers"]
        .as_array()
        .and_then(|v| v.iter().find(|v| v["link"] == link))
        .ok_or("Missing original offer")?;
    checked(
        &mut owner,
        json!({"op":"space_revoke","id":id,"body":{"id":offer["id"]}}),
        "revoke original invitation",
    )
    .await?;
    owner.close().await?;
    let mut rejected = open(&config, "Revoked", true).await?;
    assert!(
        rejected
            .operate(json!({"op":"space_join","link":link}))
            .await
            .is_err()
    );
    assert!(
        !rejected.view().await?["spaces"]
            .as_array()
            .is_some_and(|v| v.iter().any(|s| s["status"] == "joined"))
    );
    rejected.close().await?;
    println!("PASS revoked invitation cannot admit a new device");
    cleanup(&config).await?;
    println!("PASS isolated native end-to-end acceptance");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fixture() -> (Config, HostingProfile, SigningKey) {
        let key = SigningKey::from_bytes(&[23; 32]);
        let public = key
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let mut config: Config = serde_json::from_value(json!({
            "root":"/var/tmp/elo-witnessed-e2e-synthetic-config",
            "host":"https://vps-336e3c9f.vps.ovh.net/spaces/v1/create",
            "witness":{"url":"https://vps-fe606f9b.vps.ovh.net/witness/v1","public_key":public,"key_generation":1}
        })).unwrap();
        let profile = HostingProfile {
            v: 1,
            kind: "hosting.configuration".into(),
            revision: 1,
            name: "Synthetic hosting QA".into(),
            signing_public_key: public,
            create_url: config.host.clone(),
            witness: config.witness.clone(),
            storage: None,
            push_url: None,
            call_url: Some("https://vps-336e3c9f.vps.ovh.net/calls/v1".into()),
            message_lifetimes: MessageRetention::public_policies(),
            default_message_lifetime: MessageRetention::Hours24,
        };
        config.hosting_profile_link =
            Some(HostingProfile::link(&profile.sign(&key).unwrap()).unwrap());
        (config, profile, key)
    }

    #[test]
    fn signed_profile_must_match_independent_host_witness_and_call_endpoint() {
        let (mut config, _, _) = fixture();
        config.expected_call_url = Some("https://vps-336e3c9f.vps.ovh.net/calls/v1".into());
        config.load_hosting().unwrap();
        config.witness.key_generation = 2;
        assert!(config.load_hosting().is_err());
        config.witness.key_generation = 1;
        config.expected_call_url = Some("https://untrusted.example/calls/v1".into());
        assert!(config.load_hosting().is_err());
        config.expected_call_url = None;
        config.host = "https://untrusted.example/spaces/v1/create".into();
        assert!(config.load_hosting().is_err());
    }

    #[test]
    fn public_retention_is_rejected_and_private_no_expiry_is_explicit() {
        let (mut config, mut profile, key) = fixture();
        assert_eq!(config.message_lifetime_seconds, MessageRetention::Hours24);
        config.message_lifetime_seconds = MessageRetention::NoExpiry;
        assert!(config.load_hosting().is_err());
        profile.message_lifetimes.push(MessageRetention::NoExpiry);
        config.hosting_profile_link =
            Some(HostingProfile::link(&profile.sign(&key).unwrap()).unwrap());
        config.load_hosting().unwrap();
    }

    #[test]
    fn attachment_test_never_infers_a_broker_or_provider_from_unapproved_input() {
        let (mut config, mut profile, key) = fixture();
        config.managed_attachment = true;
        assert!(config.load_hosting().is_err());
        profile.storage = Some(elo_core::hosting_profile::Storage {
            url: "https://vps-fe606f9b.vps.ovh.net/storage/v1".into(),
            managed: Some(elo_core::hosting_profile::ManagedStorage {
                provider: "s3".into(),
                retention_hours: 1,
            }),
        });
        config.hosting_profile_link =
            Some(HostingProfile::link(&profile.sign(&key).unwrap()).unwrap());
        config.load_hosting().unwrap();
        config.own_storage_file = Some(PathBuf::from("/does-not-get-read"));
        assert!(config.load_hosting().is_err());
        config.managed_attachment = false;
        assert!(config.load_hosting().is_err());
        profile.storage.as_mut().unwrap().managed = None;
        config.hosting_profile_link =
            Some(HostingProfile::link(&profile.sign(&key).unwrap()).unwrap());
        config.load_hosting().unwrap();
    }

    #[test]
    fn exported_public_profile_file_and_legacy_configuration_remain_supported() {
        let (mut config, profile, key) = fixture();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hosting-profile.json");
        let export =
            HostingProfile::export(&serde_json::to_vec(&profile).unwrap(), &key.to_bytes())
                .unwrap();
        std::fs::write(&path, serde_json::to_vec(&export).unwrap()).unwrap();
        config.hosting_profile_file = Some(path);
        assert!(config.load_hosting().is_err());
        config.hosting_profile_link = None;
        config.load_hosting().unwrap();
        assert_eq!(config.profile.as_ref().unwrap().id(), profile.id());
        config.hosting_profile_file = None;
        config.load_hosting().unwrap();
        assert!(config.profile.is_none());
        assert_eq!(
            config.attachment_configuration().unwrap(),
            json!({"enabled":false})
        );
    }
}

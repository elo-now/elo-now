use super::*;
use base64::engine::general_purpose::STANDARD;

const MAX_DETAILS: usize = 192 * 1024;
const MAX_AVATAR: usize = 128 * 1024;
const AVATAR_PREFIX: &str = "data:image/jpeg;base64,";

fn decode_avatar(value: &str) -> Result<image::DynamicImage> {
    if value.len() > MAX_AVATAR * 4 / 3 + AVATAR_PREFIX.len() + 4 {
        return Err("invalid profile photo".into());
    }
    let bytes = Zeroizing::new(
        STANDARD
            .decode(
                value
                    .strip_prefix(AVATAR_PREFIX)
                    .ok_or("invalid profile photo")?,
            )
            .map_err(|_| "invalid profile photo")?,
    );
    if bytes.len() > MAX_AVATAR {
        return Err("invalid profile photo".into());
    }
    let mut reader = image::ImageReader::with_format(
        std::io::Cursor::new(bytes.as_slice()),
        image::ImageFormat::Jpeg,
    );
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(384);
    limits.max_image_height = Some(384);
    limits.max_alloc = Some(8 * 1024 * 1024);
    reader.limits(limits);
    reader.decode().map_err(|_| "invalid profile photo".into())
}

fn normalize_avatar(value: &str) -> Result<String> {
    let photo = decode_avatar(value)?.into_rgb8();
    let mut bytes = Zeroizing::new(Vec::new());
    // Re-encode only pixels: no source EXIF, location, thumbnails or filenames.
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut *bytes, 85)
        .encode_image(&photo)
        .map_err(|_| "invalid profile photo")?;
    if bytes.len() > MAX_AVATAR {
        return Err("invalid profile photo".into());
    }
    Ok(format!("{AVATAR_PREFIX}{}", STANDARD.encode(&*bytes)))
}

/// Device-local presentation. New text messages include the current name;
/// existing signed records and the cryptographic identity never change.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileDetails {
    v: u8,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}
impl ProfileDetails {
    fn named(name: &str) -> Result<Self> {
        let name = name.trim();
        if !record::valid_display_name(name) {
            return Err("invalid profile name".into());
        }
        Ok(Self {
            v: 1,
            name: name.into(),
            avatar: None,
        })
    }
    pub(super) fn load(directory: &Path, session: &Session) -> Result<Option<Self>> {
        let path = directory.join("profile-details.age");
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let bytes = read_exchange(&path, MAX_DETAILS + 4096)?;
        let plain = Zeroizing::new(crypto::open_bytes(
            &bytes,
            session.age_identity(),
            MAX_DETAILS,
        )?);
        let details: Self = serde_json::from_slice(&plain)?;
        if !matches!(details.v, 1 | 2)
            || (details.v == 1 && details.avatar.is_some())
            || Self::named(&details.name)?.name != details.name
        {
            return Err("invalid profile details".into());
        }
        if let Some(avatar) = &details.avatar {
            decode_avatar(avatar)?;
        }
        Ok(Some(details))
    }
}
impl ClientApp {
    pub(super) fn set_profile_name(&mut self, name: &str) -> Result<()> {
        let mut details = ProfileDetails::named(name)?;
        if let Some(previous) = &self.profile_details {
            details.v = previous.v;
            details.avatar = previous.avatar.clone();
        }
        self.persist_profile_details(details)
    }
    pub(super) fn set_profile_details(&mut self, name: &str, avatar: Option<&str>) -> Result<()> {
        let mut details = ProfileDetails::named(name)?;
        details.v = 2;
        details.avatar = match avatar {
            Some(value)
                if self
                    .profile_details
                    .as_ref()
                    .and_then(|p| p.avatar.as_deref())
                    == Some(value) =>
            {
                Some(value.into())
            }
            Some(value) => Some(normalize_avatar(value)?),
            None => None,
        };
        self.persist_profile_details(details)
    }
    fn persist_profile_details(&mut self, details: ProfileDetails) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(&details)?);
        let encrypted = crypto::seal_bytes(
            &plain,
            &[self.session.age_identity().to_public()],
            MAX_DETAILS,
        )?;
        vault::write_private(
            &self.directory.join("profile-details.age"),
            &encrypted,
            true,
        )?;
        self.profile_details = Some(details);
        Ok(())
    }
}

/// A recovery card held only in memory until the user acknowledges an external
/// copy. Saving creates fresh device keys; the root is never put in the vault.
pub struct ProfileDraft {
    card: RecoveryCard,
    peer: Option<PeerDescriptor>,
    allow_loopback: bool,
}

impl ProfileDraft {
    pub fn recover(words: &str, identity: &str) -> Result<Self> {
        if words.len() > 2048 || identity.len() > 256 {
            return Err("Invalid recovery key".into());
        }
        let phrase = words
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join(" ");
        if phrase.split_whitespace().count() != 24 {
            return Err("Enter all 24 recovery words".into());
        }
        let identity_id = identity
            .trim()
            .to_ascii_lowercase()
            .parse()
            .map_err(|_| "Check the identity ID")?;
        let card = RecoveryCard {
            format: "elo.now identity-recovery-v1".into(),
            identity_id,
            phrase,
        };
        card.recover_root(identity_id)
            .map_err(|_| "The recovery words and identity ID do not match")?;
        Ok(Self {
            card,
            peer: None,
            allow_loopback: false,
        })
    }

    pub fn new() -> Result<Self> {
        let (_, card) = Session::create()?;
        Ok(Self {
            card,
            peer: None,
            allow_loopback: false,
        })
    }

    /// Validate an initial transport before any profile is written. Hosted
    /// provisioning persists its capability together with the controller keys.
    pub fn with_peer(mut self, peer: PeerDescriptor, allow_loopback: bool) -> Result<Self> {
        Peer::new(peer.clone(), allow_loopback)?;
        self.peer = Some(peer);
        self.allow_loopback = allow_loopback;
        Ok(self)
    }

    pub fn card(&self) -> &RecoveryCard {
        &self.card
    }

    pub async fn save(
        &self,
        directory: PathBuf,
        password: SecretString,
        initial_channel: &str,
    ) -> Result<ClientApp> {
        self.save_with_name(directory, password, initial_channel, None)
            .await
    }

    pub async fn save_named(
        &self,
        directory: PathBuf,
        password: SecretString,
        initial_channel: &str,
        name: &str,
    ) -> Result<ClientApp> {
        let details = ProfileDetails::named(name)?;
        self.save_with_name(directory, password, initial_channel, Some(details.name))
            .await
    }

    async fn save_with_name(
        &self,
        directory: PathBuf,
        password: SecretString,
        initial_channel: &str,
        name: Option<String>,
    ) -> Result<ClientApp> {
        if initial_channel.is_empty() || initial_channel.len() > 120 {
            return Err("invalid channel name".into());
        }
        let mut session = Session::recover(&self.card, self.card.identity_id)?;
        let genesis = ClientApp::initial_genesis(&session, &self.card)?;
        session.activate_new_space_controller(genesis.id().to_string().parse()?)?;
        if let Some(peer) = &self.peer {
            session.set_peers(vec![peer.clone()])?;
        }
        // The initial controller scope and optional transport are committed in
        // one password-encrypted vault, before the incomplete profile is opened.
        // Validate and encrypt before creating anything on disk.
        let encrypted = session.seal(password.clone())?;
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        // Atomic reservation: never reuse an existing directory or symlink.
        builder.create(&directory)?;
        vault::write_private(&directory.join(".initializing"), b"elo-profile-v1", false)?;
        vault::write_private(&directory.join("vault.age"), &encrypted, false)?;
        vault::write_private(
            &directory.join("profile.json"),
            &serde_json::to_vec(&json!({
                "identity_id": session.identity_id(),
                "credential_id": session.credential().id()
            }))?,
            false,
        )?;
        // seal() already verified this newly created session against the vault.
        // Keep it through initialization instead of repeating password derivation.
        let mut app = ClientApp::open_session(
            directory.clone(),
            password.clone(),
            self.allow_loopback,
            session,
        )
        .await?;
        let initialized: Result<()> = async {
            if let Some(name) = name {
                app.set_profile_name(&name)?;
            }
            app.initialize_space(initial_channel, genesis).await
        }
        .await;
        // Complete the database checkpoint before publishing initialization.
        // Retain only the authenticated session; reopen all persisted UI/data state.
        let closed = app.store.close().await;
        initialized?;
        closed?;
        let session = app.session;
        std::fs::remove_file(directory.join(".initializing"))?;
        #[cfg(unix)]
        {
            std::fs::File::open(&directory)?.sync_all()?;
            if let Some(parent) = directory.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        // An interrupted initialization stays marked and cannot be opened as a
        // completed profile. Preserve it for diagnosis, never delete user data.
        ClientApp::open_session(directory, password, self.allow_loopback, session).await
    }
}

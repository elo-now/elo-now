//! Portable age/scrypt vault. Root recovery and device backup are distinct.
use crate::{
    identity::{DeviceCredential, VerifiedCredential, generate_signing_key},
    ids::{IdentityId, SpaceId},
    record::{self, encode_hex, hex},
    sync::PeerDescriptor,
};
use age::secrecy::{ExposeSecret, SecretString};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
const MAX_VAULT: usize = 256 * 1024;
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("invalid vault, passphrase, key binding or recovery card")]
    Invalid,
    #[error("passphrase must contain 12..=1024 UTF-8 bytes")]
    Passphrase,
    #[error("vault file unavailable, unsafe permissions, or output already exists")]
    File,
    #[error("root recovery needs the expected public identity fingerprint")]
    Fingerprint,
}
pub type Result<T> = std::result::Result<T, VaultError>;
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControllerMode {
    Follower,
    Active,
    Retired,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secrets {
    v: u64,
    identity_id: IdentityId,
    root_public_key: String,
    credential: String,
    signing_seed: String,
    age_identity: String,
    peers: Vec<PeerDescriptor>,
    controller_mode: ControllerMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    controller_spaces: Option<Vec<SpaceId>>,
    transfer_nonce: String,
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.signing_seed.zeroize();
        self.age_identity.zeroize();
        for peer in &mut self.peers {
            peer.read_token.zeroize();
            peer.write_token.zeroize();
        }
    }
}
pub struct Session {
    pub(crate) key: SigningKey,
    pub(crate) age: age::x25519::Identity,
    pub(crate) credential: VerifiedCredential,
    pub(crate) peers: Vec<PeerDescriptor>,
    pub(crate) controller_mode: ControllerMode,
    pub(crate) controller_spaces: Option<Vec<SpaceId>>,
    transfer_nonce: String,
}
impl Drop for Session {
    fn drop(&mut self) {
        for peer in &mut self.peers {
            peer.read_token.zeroize();
            peer.write_token.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCard {
    pub format: String,
    pub identity_id: IdentityId,
    pub phrase: String,
}
impl Drop for RecoveryCard {
    fn drop(&mut self) {
        self.phrase.zeroize();
    }
}
impl RecoveryCard {
    fn from_root(root: &SigningKey) -> Result<Self> {
        let seed = Zeroizing::new(root.to_bytes());
        let mnemonic = bip39::Mnemonic::from_entropy(&*seed).map_err(|_| VaultError::Invalid)?;
        Ok(Self {
            format: "elo.now identity-recovery-v1".into(),
            identity_id: IdentityId::of_root_key(root.verifying_key().as_bytes()),
            phrase: mnemonic.to_string(),
        })
    }
    pub fn recover_root(&self, expected: IdentityId) -> Result<SigningKey> {
        if self.format != "elo.now identity-recovery-v1" || self.identity_id != expected {
            return Err(VaultError::Fingerprint);
        }
        let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, &self.phrase)
            .map_err(|_| VaultError::Invalid)?;
        if mnemonic.word_count() != 24 {
            return Err(VaultError::Invalid);
        }
        let entropy = Zeroizing::new(mnemonic.to_entropy());
        let seed: &[u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Invalid)?;
        let root = SigningKey::from_bytes(seed);
        if IdentityId::of_root_key(root.verifying_key().as_bytes()) != expected {
            return Err(VaultError::Fingerprint);
        }
        Ok(root)
    }
}
impl Session {
    pub fn create() -> Result<(Self, RecoveryCard)> {
        let root = generate_signing_key().map_err(|_| VaultError::Invalid)?;
        let card = RecoveryCard::from_root(&root)?;
        Ok((Self::enroll(&root)?, card))
    }
    fn enroll(root: &SigningKey) -> Result<Self> {
        let key = generate_signing_key().map_err(|_| VaultError::Invalid)?;
        let age = age::x25519::Identity::generate();
        let credential = DeviceCredential::issue(root, &key.verifying_key(), &age.to_public())
            .map_err(|_| VaultError::Invalid)?;
        Ok(Self {
            key,
            age,
            credential,
            peers: vec![],
            controller_mode: ControllerMode::Follower,
            controller_spaces: Some(vec![]),
            transfer_nonce: record::random_hex::<32>().map_err(|_| VaultError::Invalid)?,
        })
    }
    pub fn recover(card: &RecoveryCard, expected: IdentityId) -> Result<Self> {
        let root = card.recover_root(expected)?;
        Self::enroll(&root)
    }
    pub fn identity_id(&self) -> IdentityId {
        self.credential.identity()
    }
    pub fn credential(&self) -> &VerifiedCredential {
        &self.credential
    }
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
    pub fn age_identity(&self) -> &age::x25519::Identity {
        &self.age
    }
    pub fn peers(&self) -> &[PeerDescriptor] {
        &self.peers
    }
    /// Same device identity, isolated transport configuration and new authority scope.
    pub(crate) fn isolated_space(&self) -> Self {
        Self {
            key: self.key.clone(),
            age: self.age.clone(),
            credential: self.credential.clone(),
            peers: vec![],
            controller_mode: ControllerMode::Follower,
            controller_spaces: Some(vec![]),
            transfer_nonce: self.transfer_nonce.clone(),
        }
    }
    pub fn set_peers(&mut self, peers: Vec<PeerDescriptor>) -> Result<()> {
        if peers.len() > 8 {
            return Err(VaultError::Invalid);
        }
        self.peers = peers;
        Ok(())
    }
    pub fn controller_mode(&self) -> ControllerMode {
        self.controller_mode
    }
    pub fn can_control(&self, space: SpaceId) -> bool {
        self.controller_mode == ControllerMode::Active
            && self
                .controller_spaces
                .as_ref()
                .is_none_or(|spaces| spaces.contains(&space))
    }
    /// A new Space cannot reactivate an old Space from a restored device backup.
    pub fn activate_new_space_controller(&mut self, space: SpaceId) -> Result<()> {
        if self.controller_mode != ControllerMode::Active {
            self.controller_spaces = Some(vec![]);
        }
        if let Some(spaces) = &mut self.controller_spaces
            && !spaces.contains(&space)
        {
            if spaces.len() >= 32 {
                return Err(VaultError::Invalid);
            }
            spaces.push(space);
            spaces.sort();
        }
        self.controller_mode = ControllerMode::Active;
        Ok(())
    }
    /// Called only after persisting and verifying the root-authorized config.
    pub(crate) fn activate_recovered_controller(
        &mut self,
        authority: &crate::authority::Authority,
    ) -> Result<()> {
        if authority.is_forked()
            || authority.recovery_id().is_none()
            || authority.controller().id() != self.credential.id()
        {
            return Err(VaultError::Invalid);
        }
        self.activate_new_space_controller(authority.space())
    }
    pub fn retire_controller(&mut self) {
        self.controller_mode = ControllerMode::Retired;
    }
    fn plaintext(&self) -> Result<Zeroizing<Vec<u8>>> {
        let secrets = Secrets {
            v: 1,
            identity_id: self.identity_id(),
            root_public_key: self.credential.record().body()["root_public_key"]
                .as_str()
                .ok_or(VaultError::Invalid)?
                .into(),
            credential: STANDARD.encode(self.credential.record().bytes()),
            signing_seed: encode_hex(&self.key.to_bytes()),
            age_identity: self.age.to_string().expose_secret().to_owned(),
            peers: self.peers.clone(),
            controller_mode: self.controller_mode,
            controller_spaces: self.controller_spaces.clone(),
            transfer_nonce: self.transfer_nonce.clone(),
        };
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&secrets).map_err(|_| VaultError::Invalid)?);
        if plaintext.len() > MAX_VAULT {
            return Err(VaultError::Invalid);
        }
        Ok(plaintext)
    }
    pub fn seal(&self, passphrase: SecretString) -> Result<Vec<u8>> {
        validate_passphrase(&passphrase)?;
        let plaintext = self.plaintext()?;
        // Keep age's calibrated cost. No reduced-work test mode.
        let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
        let mut ciphertext = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|_| VaultError::Invalid)?;
        writer
            .write_all(&plaintext)
            .map_err(|_| VaultError::Invalid)?;
        writer.finish().map_err(|_| VaultError::Invalid)?;
        // Never save a newly generated vault above our decryptor's explicit work cap.
        let checked = decrypt(&ciphertext, passphrase)?;
        if *checked != *plaintext {
            return Err(VaultError::Invalid);
        }
        Ok(ciphertext)
    }
    pub fn open(ciphertext: &[u8], passphrase: SecretString, expected: IdentityId) -> Result<Self> {
        validate_passphrase(&passphrase)?;
        let plaintext = decrypt(ciphertext, passphrase)?;
        Self::from_plaintext(&plaintext, expected)
    }
    fn from_plaintext(plaintext: &[u8], expected: IdentityId) -> Result<Self> {
        let value =
            record::strict_json(plaintext, MAX_VAULT + 72).map_err(|_| VaultError::Invalid)?;
        let mut secrets: Secrets =
            serde_json::from_value(value).map_err(|_| VaultError::Invalid)?;
        if secrets.v != 1 || secrets.identity_id != expected || secrets.peers.len() > 8 {
            return Err(VaultError::Invalid);
        }
        if secrets
            .controller_spaces
            .as_ref()
            .is_some_and(|spaces| spaces.len() > 32 || spaces.windows(2).any(|p| p[0] >= p[1]))
        {
            return Err(VaultError::Invalid);
        }
        let root = VerifyingKey::from_bytes(
            &hex(&secrets.root_public_key).map_err(|_| VaultError::Invalid)?,
        )
        .map_err(|_| VaultError::Invalid)?;
        let credential = VerifiedCredential::verify(
            &STANDARD
                .decode(&secrets.credential)
                .map_err(|_| VaultError::Invalid)?,
            &root,
        )
        .map_err(|_| VaultError::Invalid)?;
        let seed =
            Zeroizing::new(hex::<32>(&secrets.signing_seed).map_err(|_| VaultError::Invalid)?);
        let key = SigningKey::from_bytes(&seed);
        let age: age::x25519::Identity = secrets
            .age_identity
            .parse()
            .map_err(|_| VaultError::Invalid)?;
        if credential.identity() != expected
            || credential.key() != &key.verifying_key()
            || credential.recipient() != age.to_public()
        {
            return Err(VaultError::Invalid);
        }
        Ok(Self {
            key,
            age,
            credential,
            peers: std::mem::take(&mut secrets.peers),
            controller_mode: secrets.controller_mode,
            controller_spaces: secrets.controller_spaces.take(),
            transfer_nonce: secrets.transfer_nonce.clone(),
        })
    }
    // Optional local acceleration only. The portable password vault remains
    // authoritative; its exact ciphertext and Space ID bind each cached session.
    pub(crate) fn cache_for_profile(
        &self,
        profile: &Self,
        space: SpaceId,
        vault: &[u8],
    ) -> Result<Vec<u8>> {
        if self.credential.id() != profile.credential.id()
            || self.identity_id() != profile.identity_id()
        {
            return Err(VaultError::Invalid);
        }
        let mut plain = Zeroizing::new(Vec::new());
        plain.extend_from_slice(&cache_binding(space, vault));
        plain.extend_from_slice(&self.plaintext()?);
        crate::crypto::seal_bytes(&plain, &[profile.age.to_public()], MAX_VAULT + 32)
            .map_err(|_| VaultError::Invalid)
    }
    pub(crate) fn from_profile_cache(
        cache: &[u8],
        profile: &Self,
        space: SpaceId,
        vault: &[u8],
    ) -> Result<Self> {
        let plain = Zeroizing::new(
            crate::crypto::open_bytes(cache, &profile.age, MAX_VAULT + 32)
                .map_err(|_| VaultError::Invalid)?,
        );
        if plain.get(..32) != Some(cache_binding(space, vault).as_slice()) {
            return Err(VaultError::Invalid);
        }
        let session = Self::from_plaintext(&plain[32..], profile.identity_id())?;
        if session.credential.id() != profile.credential.id() {
            return Err(VaultError::Invalid);
        }
        Ok(session)
    }
    /// Importing a device backup never automatically starts a second controller.
    pub fn restore_backup(
        ciphertext: &[u8],
        passphrase: SecretString,
        expected: IdentityId,
    ) -> Result<Self> {
        let mut session = Self::open(ciphertext, passphrase, expected)?;
        session.controller_mode = ControllerMode::Follower;
        session.controller_spaces = Some(vec![]);
        session.transfer_nonce = record::random_hex::<32>().map_err(|_| VaultError::Invalid)?;
        Ok(session)
    }
}
fn cache_binding(space: SpaceId, vault: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"elo-space-vault-cache-v1\0");
    digest.update(space.to_string().as_bytes());
    digest.update(vault);
    digest.finalize().into()
}
fn validate_passphrase(p: &SecretString) -> Result<()> {
    if !(12..=1024).contains(&p.expose_secret().len()) {
        return Err(VaultError::Passphrase);
    }
    Ok(())
}
fn decrypt(ciphertext: &[u8], passphrase: SecretString) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_VAULT + 4096 {
        return Err(VaultError::Invalid);
    }
    let decryptor =
        crate::crypto::bounded_decryptor(ciphertext).map_err(|_| VaultError::Invalid)?;
    if !decryptor.is_scrypt() {
        return Err(VaultError::Invalid);
    }
    let mut identity = age::scrypt::Identity::new(passphrase);
    identity.set_max_work_factor(20);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| VaultError::Invalid)?
        .take(MAX_VAULT as u64 + 1);
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| VaultError::Invalid)?;
    if plaintext.len() > MAX_VAULT {
        return Err(VaultError::Invalid);
    }
    Ok(plaintext)
}
pub fn read_private(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|_| VaultError::File)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(VaultError::File);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(VaultError::File);
        }
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| VaultError::File)?
        .take((MAX_VAULT + 4097) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::File)?;
    if bytes.len() > MAX_VAULT + 4096 {
        return Err(VaultError::File);
    }
    Ok(bytes)
}
/// Atomic replacement is explicit. Only encrypted bytes or a user-requested
/// recovery export belong here; no plaintext temporary vault is ever written.
pub fn write_private(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(VaultError::File)?;
    if let Ok(meta) = fs::symlink_metadata(path)
        && (!replace || !meta.is_file() || meta.file_type().is_symlink())
    {
        return Err(VaultError::File);
    }
    let temp = parent.join(format!(
        ".elo-{}.tmp",
        record::random_hex::<16>().map_err(|_| VaultError::File)?
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp).map_err(|_| VaultError::File)?;
        file.write_all(bytes).map_err(|_| VaultError::File)?;
        file.sync_all().map_err(|_| VaultError::File)?;
        drop(file);
        if replace {
            fs::rename(&temp, path).map_err(|_| VaultError::File)?;
        } else {
            // Android's app sandbox forbids hard links. An exclusive rename
            // retains atomic publication and refuses even a racing destination.
            #[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &temp,
                rustix::fs::CWD,
                path,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| VaultError::File)?;
            #[cfg(not(any(target_os = "android", target_os = "linux", target_vendor = "apple")))]
            {
                fs::hard_link(&temp, path).map_err(|_| VaultError::File)?;
                fs::remove_file(&temp).map_err(|_| VaultError::File)?;
            }
        }
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| VaultError::File)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    v: u64,
    kind: String,
    nonce: String,
    credential_id: crate::ids::RecordId,
    destination_nonce: String,
    space_id: crate::ids::SpaceId,
    config_id: crate::ids::RecordId,
}
impl Session {
    pub fn transfer_nonce(&self) -> &str {
        &self.transfer_nonce
    }
    /// Retire and durably save the source before releasing a signed transfer ticket.
    pub fn retire_for_transfer(
        &mut self,
        path: &Path,
        passphrase: SecretString,
        destination_nonce: &str,
        space: crate::ids::SpaceId,
        head: crate::ids::RecordId,
    ) -> Result<crate::record::SignedRecord> {
        if !self.can_control(space) || destination_nonce == self.transfer_nonce {
            return Err(VaultError::Invalid);
        }
        hex::<32>(destination_nonce).map_err(|_| VaultError::Invalid)?;
        let body = Transfer {
            v: 1,
            kind: "controller.transfer".into(),
            nonce: record::random_hex::<16>().map_err(|_| VaultError::Invalid)?,
            credential_id: self.credential.id(),
            destination_nonce: destination_nonce.into(),
            space_id: space,
            config_id: head,
        };
        let ticket = crate::record::SignedRecord::sign(
            &serde_json::to_vec(&body).map_err(|_| VaultError::Invalid)?,
            &self.key,
        )
        .map_err(|_| VaultError::Invalid)?;
        self.controller_mode = ControllerMode::Retired;
        let ciphertext = self.seal(passphrase)?;
        write_private(path, &ciphertext, true)?;
        Ok(ticket)
    }
    pub fn activate_transfer(
        &mut self,
        ticket: &crate::record::SignedRecord,
        space: crate::ids::SpaceId,
        head: crate::ids::RecordId,
    ) -> Result<()> {
        ticket
            .verify_signature(self.credential.key())
            .map_err(|_| VaultError::Invalid)?;
        let body: Transfer = ticket.decode().map_err(|_| VaultError::Invalid)?;
        if self.controller_mode != ControllerMode::Follower
            || body.v != 1
            || body.kind != "controller.transfer"
            || body.destination_nonce != self.transfer_nonce
            || body.space_id != space
            || body.config_id != head
            || body.credential_id != self.credential.id()
        {
            return Err(VaultError::Invalid);
        }
        hex::<16>(&body.nonce).map_err(|_| VaultError::Invalid)?;
        self.activate_new_space_controller(space)
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    #[test]
    fn space_cache_binds_profile_space_vault_and_authenticated_payload() {
        let (profile, card) = Session::create().unwrap();
        let mut child = profile.isolated_space();
        child.retire_controller();
        let space: SpaceId = "ab".repeat(32).parse().unwrap();
        let other_space: SpaceId = "cd".repeat(32).parse().unwrap();
        let vault = child.seal("synthetic cache test password".into()).unwrap();
        let cache = child.cache_for_profile(&profile, space, &vault).unwrap();
        let opened = Session::from_profile_cache(&cache, &profile, space, &vault).unwrap();
        assert!(opened.controller_mode() == ControllerMode::Retired);
        assert_eq!(opened.credential().id(), child.credential().id());
        assert_eq!(opened.transfer_nonce(), child.transfer_nonce());
        assert!(Session::from_profile_cache(&cache, &profile, other_space, &vault).is_err());
        assert!(Session::from_profile_cache(&cache, &profile, space, b"changed vault").is_err());
        let other = Session::create().unwrap().0;
        assert!(Session::from_profile_cache(&cache, &other, space, &vault).is_err());
        assert!(child.cache_for_profile(&other, space, &vault).is_err());
        let recovered = Session::recover(&card, profile.identity_id()).unwrap();
        assert!(Session::from_profile_cache(&cache, &recovered, space, &vault).is_err());
        let mut damaged = cache.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(Session::from_profile_cache(&damaged, &profile, space, &vault).is_err());
        assert!(
            Session::open(
                &vault,
                "incorrect cache test password".into(),
                profile.identity_id()
            )
            .is_err()
        );
    }
}

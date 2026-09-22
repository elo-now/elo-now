//! Personal safety preferences. Filtering never alters signed history or membership.
use super::*;
use std::sync::{Arc, RwLock};
const MAX_BLOCKS: usize = 4096;
const MAX_BYTES: usize = 1024 * 1024;
#[derive(Clone, Default)]
pub(super) struct Blocked(Arc<RwLock<BTreeMap<IdentityId, String>>>);
impl Blocked {
    pub(super) fn open(directory: &Path, identity: &age::x25519::Identity) -> Result<Self> {
        let path = directory.join("blocked.age");
        let entries = if path.exists() {
            let bytes = Zeroizing::new(crypto::open_bytes(
                &vault::read_private(&path)?,
                identity,
                MAX_BYTES,
            )?);
            let entries: BTreeMap<IdentityId, String> = serde_json::from_slice(&bytes)?;
            if entries.len() > MAX_BLOCKS
                || entries
                    .values()
                    .any(|name| name.len() > 240 || name.chars().any(char::is_control))
            {
                return Err("Invalid blocked users.".into());
            }
            entries
        } else {
            BTreeMap::new()
        };
        Ok(Self(Arc::new(RwLock::new(entries))))
    }
    pub(super) fn contains(&self, identity: IdentityId) -> bool {
        self.0
            .read()
            .map_or(true, |entries| entries.contains_key(&identity))
    }
    pub(super) fn permits(&self, record: &SignedRecord) -> bool {
        record.body()["issuer_identity"]
            .as_str()
            .and_then(|id| id.parse().ok())
            .is_none_or(|id| !self.contains(id))
    }
    pub(super) fn entries(&self) -> Result<BTreeMap<IdentityId, String>> {
        Ok(self
            .0
            .read()
            .map_err(|_| "Blocked users unavailable.")?
            .clone())
    }
}
impl ClientApp {
    pub(super) fn update_block(&mut self, v: &Value) -> Result<()> {
        if v["expected_identity"] != json!(self.identity_id()) {
            return Err("The open profile has changed.".into());
        }
        let id: IdentityId = field(v, "identity")?.parse()?;
        if id == self.identity_id() {
            return Err("You cannot block yourself.".into());
        }
        let enabled = v["blocked"].as_bool().ok_or("Invalid block setting.")?;
        if !enabled {
            // Persist dismissals while the old block is still active. A failed
            // write must not resurrect a previously hidden invitation.
            self.dismiss_all_blocked_invitations()?;
        }
        let mut entries = self.blocked.entries()?;
        if enabled {
            // An untrusted long/control-containing display name must not stop
            // the user blocking its identity. This is only a local label.
            let name: String = field(v, "name")?
                .trim()
                .chars()
                .filter(|c| !c.is_control())
                .take(60)
                .collect();
            if entries.len() >= MAX_BLOCKS && !entries.contains_key(&id) {
                return Err("Blocked users limit reached.".into());
            }
            entries.insert(id, name);
        } else {
            entries.remove(&id);
        }
        let plain = Zeroizing::new(serde_json::to_vec(&entries)?);
        vault::write_private(
            &self.directory.join("blocked.age"),
            &crypto::seal_bytes(
                &plain,
                &[self.session.age_identity().to_public()],
                MAX_BYTES,
            )?,
            true,
        )?;
        *self
            .blocked
            .0
            .write()
            .map_err(|_| "Blocked users unavailable.")? = entries;
        if enabled {
            // Permanently dismiss already-pending personal invitations. Unblock
            // does not unexpectedly resurface requests the user has rejected.
            self.dismiss_all_blocked_invitations()?;
        }
        Ok(())
    }
    fn dismiss_all_blocked_invitations(&self) -> Result<()> {
        if let Some(spaces) = &self.spaces {
            for client in spaces.clients(self) {
                client.dismiss_blocked_invitations()?;
            }
        } else {
            self.dismiss_blocked_invitations()?;
        }
        Ok(())
    }
    pub(super) fn blocked_view(&self) -> Result<Value> {
        Ok(json!(
            self.blocked
                .entries()?
                .into_iter()
                .map(|(identity, name)| json!({"identity":identity,"name":name}))
                .collect::<Vec<_>>()
        ))
    }
}

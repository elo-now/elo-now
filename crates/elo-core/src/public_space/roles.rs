//! Durable Space administration roles. General membership
//! is owner-managed; signed requests define the administration policy.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoleMember {
    pub identity: IdentityId,
    pub name: String,
    pub role: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    id: String,
    kind: String,
    target: IdentityId,
    target_name: String,
    requester: IdentityId,
    requester_name: String,
    created_at: u64,
    primary: IdentityId,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Roles {
    pub primary: IdentityId,
    #[serde(default)]
    pub contact_email: Option<String>,
    owners: BTreeSet<IdentityId>,
    pub revision: u64,
    pending: BTreeMap<String, Change>,
}
impl Roles {
    pub fn bootstrap(owners: &[IdentityId]) -> Result<Self> {
        Ok(Self {
            primary: *owners.first().ok_or("Space needs a primary owner.")?,
            owners: owners.iter().copied().collect(),
            contact_email: None,
            revision: 0,
            pending: BTreeMap::new(),
        })
    }
    pub fn is_owner(&self, identity: IdentityId) -> bool {
        self.owners.contains(&identity)
    }
    pub(crate) fn owner_identities(&self) -> BTreeSet<IdentityId> {
        self.owners.clone()
    }
    pub fn role(&self, identity: IdentityId) -> &'static str {
        if identity == self.primary {
            "primary_owner"
        } else if self.is_owner(identity) {
            "owner"
        } else {
            "member"
        }
    }
    fn can_decide(&self, actor: IdentityId, change: &Change) -> bool {
        actor == change.target
            || (matches!(change.kind.as_str(), "remove_owner" | "remove_member")
                && actor == self.primary)
    }
    pub fn requests_for(&self, actor: IdentityId) -> Vec<Value> {
        self.pending
            .values()
            .filter(|change| self.can_decide(actor, change))
            .map(|change| serde_json::to_value(change).expect("role request serialization"))
            .collect()
    }
    fn changed(&mut self) -> Result<()> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or("Space role revision limit reached.")?;
        let owners = &self.owners;
        let primary = self.primary;
        self.pending.retain(|_, c| {
            c.primary == primary
                && owners.contains(&c.requester)
                && c.target != primary
                && (c.kind != "remove_owner" || owners.contains(&c.target))
        });
        Ok(())
    }
    pub fn retire_member(&mut self, identity: IdentityId) {
        self.owners.remove(&identity);
        self.pending
            .retain(|_, c| c.target != identity && c.requester != identity);
    }
    pub fn apply_with_id(
        &mut self,
        actor: IdentityId,
        action: &str,
        body: &Value,
        members: &[RoleMember],
        current: u64,
        request_id: &str,
    ) -> Result<Value> {
        if body["revision"].as_u64() != Some(self.revision) {
            return Err("Space roles have changed. Refresh and try again.".into());
        }
        if !members.iter().any(|m| m.identity == actor) {
            return Err("Only a Space member can change roles.".into());
        }
        if action == "role_decide" {
            let id = field(body, "request_id")?;
            let change = self
                .pending
                .get(id)
                .cloned()
                .ok_or("This role request has already been handled.")?;
            let approve = body["approve"].as_bool().ok_or("Choose a decision.")?;
            if !self.can_decide(actor, &change) && !(actor == change.requester && !approve) {
                return Err("You cannot confirm this role change.".into());
            }
            if approve {
                if !members.iter().any(|m| m.identity == change.target) {
                    return Err("This person is no longer a Space member.".into());
                }
                match change.kind.as_str() {
                    "remove_owner" | "remove_member" => {
                        self.owners.remove(&change.target);
                    }
                    "transfer_primary" => {
                        let email = field(body, "contact_email")?.trim();
                        validate_contact_email(email)?;
                        self.contact_email = Some(email.into());
                        self.owners.insert(change.target);
                        self.primary = change.target;
                    }
                    _ => return Err("Invalid role change.".into()),
                }
            }
            self.pending.remove(id);
            self.changed()?;
            return Ok(
                json!({"status":if approve {"applied"} else {"declined"},"removed_identity":if approve && change.kind == "remove_member" {Some(change.target)} else {None}}),
            );
        }
        if !self.is_owner(actor) {
            return Err("Only a Space owner can change roles.".into());
        }
        let target: IdentityId = field(body, "target")?.parse()?;
        let member = members
            .iter()
            .find(|m| m.identity == target)
            .ok_or("Choose a current Space member.")?;
        let kind = field(body, "kind")?;
        match kind {
            "make_owner" => {
                if self.is_owner(target) {
                    return Err("This person is already an owner.".into());
                }
                self.owners.insert(target);
                self.changed()?;
                Ok(json!({"status":"applied"}))
            }
            "remove_owner" | "transfer_primary" | "remove_member" => {
                if target == self.primary {
                    return Err("The primary owner must transfer ownership first.".into());
                }
                if kind == "transfer_primary" && actor != self.primary {
                    return Err("Only the primary owner can transfer ownership.".into());
                }
                if kind == "remove_owner" && !self.is_owner(target) {
                    return Err("This person is not an owner.".into());
                }
                if (kind == "remove_owner" || kind == "remove_member")
                    && (actor == self.primary || actor == target || !self.is_owner(target))
                {
                    self.owners.remove(&target);
                    self.changed()?;
                    return Ok(
                        json!({"status":"applied","removed_identity":if kind == "remove_member" {Some(target)} else {None}}),
                    );
                }
                if self
                    .pending
                    .values()
                    .any(|c| c.target == target && c.kind == kind)
                    || (kind == "transfer_primary" && self.pending.values().any(|c| c.kind == kind))
                {
                    return Err("A confirmation is already pending.".into());
                }
                if self.pending.len() >= record::MAX_CHAT_MEMBERS {
                    return Err("Resolve pending role requests first.".into());
                }
                let id = request_id.to_owned();
                self.pending.insert(
                    id.clone(),
                    Change {
                        id,
                        kind: kind.into(),
                        target,
                        target_name: member.name.clone(),
                        requester: actor,
                        requester_name: members
                            .iter()
                            .find(|m| m.identity == actor)
                            .unwrap()
                            .name
                            .clone(),
                        created_at: current,
                        primary: self.primary,
                    },
                );
                self.changed()?;
                Ok(json!({"status":"pending"}))
            }
            _ => Err("Choose a valid role change.".into()),
        }
    }
}

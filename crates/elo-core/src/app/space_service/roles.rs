//! Durable Space administration roles. General's cryptographic controller stays
//! with the enrollment service; these roles authorize signed management requests.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleMember {
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
pub(super) struct Roles {
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
    pub fn apply(
        &mut self,
        actor: IdentityId,
        action: &str,
        body: &Value,
        members: &[RoleMember],
        current: u64,
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
                let id = record::random_hex::<16>()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(n: u8) -> IdentityId {
        format!("{n:02x}").repeat(32).parse().unwrap()
    }
    fn members() -> Vec<RoleMember> {
        (1..=4)
            .map(|n| RoleMember {
                identity: identity(n),
                name: format!("Person {n}"),
                role: "member".into(),
            })
            .collect()
    }
    fn change(roles: &mut Roles, actor: u8, target: u8, kind: &str) -> Result<Value> {
        roles.apply(
            identity(actor),
            "role_change",
            &json!({"revision":roles.revision,"target":identity(target),"kind":kind}),
            &members(),
            1,
        )
    }
    fn decide(roles: &mut Roles, actor: u8, approve: bool) -> Result<Value> {
        let id = roles.pending.keys().next().unwrap().clone();
        roles.apply(
            identity(actor),
            "role_decide",
            &json!({"revision":roles.revision,"request_id":id,"approve":approve,"contact_email":"recipient@example.test"}),
            &members(),
            2,
        )
    }
    #[test]
    fn membership_removal_preserves_primary_and_peer_owner_consent() {
        let mut roles = Roles::bootstrap(&[identity(1), identity(2), identity(3)]).unwrap();
        assert!(change(&mut roles, 2, 1, "remove_member").is_err());
        assert!(change(&mut roles, 4, 2, "remove_member").is_err());
        let pending = change(&mut roles, 2, 3, "remove_member").unwrap();
        assert_eq!(pending["status"], "pending");
        assert!(pending["removed_identity"].is_null());
        assert!(decide(&mut roles, 2, true).is_err());
        let mut roles: Roles =
            serde_json::from_slice(&serde_json::to_vec(&roles).unwrap()).unwrap();
        assert_eq!(
            decide(&mut roles, 1, true).unwrap()["removed_identity"],
            json!(identity(3))
        );
        assert!(!roles.is_owner(identity(3)));
        let removed = change(&mut roles, 2, 4, "remove_member").unwrap();
        assert_eq!(removed["removed_identity"], json!(identity(4)));
        assert_eq!(roles.primary, identity(1));
    }
    #[test]
    fn owners_cannot_demote_each_other_without_target_or_primary_confirmation() {
        for approver in [1, 3] {
            let mut roles = Roles::bootstrap(&[identity(1), identity(2), identity(3)]).unwrap();
            assert!(change(&mut roles, 4, 2, "remove_owner").is_err());
            assert!(change(&mut roles, 2, 1, "remove_owner").is_err());
            assert_eq!(
                change(&mut roles, 2, 3, "remove_owner").unwrap()["status"],
                "pending"
            );
            assert!(roles.is_owner(identity(3)));
            assert!(decide(&mut roles, 2, true).is_err());
            assert!(decide(&mut roles, 4, true).is_err());
            let serialized = serde_json::to_vec(&roles).unwrap();
            let mut roles: Roles = serde_json::from_slice(&serialized).unwrap();
            decide(&mut roles, approver, true).unwrap();
            assert!(!roles.is_owner(identity(3)));
            assert_eq!(roles.role(identity(3)), "member");
        }
    }
    #[test]
    fn primary_transfer_requires_the_recipient_and_invalidates_old_requests() {
        let mut roles = Roles::bootstrap(&[identity(1), identity(2), identity(3)]).unwrap();
        assert!(change(&mut roles, 2, 4, "transfer_primary").is_err());
        change(&mut roles, 1, 4, "transfer_primary").unwrap();
        assert!(decide(&mut roles, 1, true).is_err());
        assert!(decide(&mut roles, 2, true).is_err());
        decide(&mut roles, 4, true).unwrap();
        assert_eq!(roles.primary, identity(4));
        assert_eq!(roles.role(identity(1)), "owner");
        assert!(roles.pending.is_empty());
        assert!(change(&mut roles, 1, 4, "remove_owner").is_err());
        assert!(
            roles
                .apply(
                    identity(4),
                    "role_change",
                    &json!({"revision":0,"target":identity(2),"kind":"remove_owner"}),
                    &members(),
                    3
                )
                .is_err()
        );
        change(&mut roles, 4, 2, "remove_owner").unwrap();
        assert!(!roles.is_owner(identity(2)));
    }
    #[test]
    fn promotion_refusal_and_requester_demotion_are_durable() {
        let mut roles = Roles::bootstrap(&[identity(1), identity(2), identity(3)]).unwrap();
        assert!(change(&mut roles, 4, 4, "make_owner").is_err());
        change(&mut roles, 2, 4, "make_owner").unwrap();
        assert!(roles.is_owner(identity(4)));
        change(&mut roles, 2, 3, "remove_owner").unwrap();
        decide(&mut roles, 3, false).unwrap();
        assert!(roles.is_owner(identity(3)));
        change(&mut roles, 2, 3, "remove_owner").unwrap();
        change(&mut roles, 1, 2, "remove_owner").unwrap();
        assert!(roles.pending.is_empty());
    }
}

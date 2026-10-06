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
    fn require_change_authority(
        &self,
        actor: IdentityId,
        target: IdentityId,
        kind: &str,
    ) -> Result<()> {
        if kind == "transfer_primary" {
            return Err("Primary ownership cannot be transferred.".into());
        }
        if matches!(kind, "remove_owner" | "remove_member") && target == self.primary {
            return Err("The primary owner cannot be removed.".into());
        }
        if (matches!(kind, "make_owner" | "remove_owner")
            || (kind == "remove_member" && self.is_owner(target)))
            && actor != self.primary
        {
            return Err("Only the primary owner can change Space owners.".into());
        }
        Ok(())
    }
    pub fn retire_member(&mut self, identity: IdentityId) -> Result<()> {
        if identity == self.primary {
            return Err("The primary owner cannot be removed.".into());
        }
        self.owners.remove(&identity);
        self.pending
            .retain(|_, c| c.target != identity && c.requester != identity);
        Ok(())
    }
    pub fn apply(
        &mut self,
        actor: IdentityId,
        action: &str,
        body: &Value,
        members: &[RoleMember],
        _current: u64,
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
                if change.primary != self.primary || !self.is_owner(actor) {
                    return Err("You cannot confirm this role change.".into());
                }
                self.require_change_authority(actor, change.target, &change.kind)?;
                if !members.iter().any(|m| m.identity == change.target) {
                    return Err("This person is no longer a Space member.".into());
                }
                match change.kind.as_str() {
                    "remove_owner" | "remove_member" => {
                        self.owners.remove(&change.target);
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
        if !members.iter().any(|m| m.identity == target) {
            return Err("Choose a current Space member.".into());
        }
        let kind = field(body, "kind")?;
        self.require_change_authority(actor, target, kind)?;
        match kind {
            "make_owner" => {
                if self.is_owner(target) {
                    return Err("This person is already an owner.".into());
                }
                self.owners.insert(target);
                self.changed()?;
                Ok(json!({"status":"applied"}))
            }
            "remove_owner" | "remove_member" => {
                if kind == "remove_owner" && !self.is_owner(target) {
                    return Err("This person is not an owner.".into());
                }
                self.owners.remove(&target);
                self.changed()?;
                Ok(
                    json!({"status":"applied","removed_identity":if kind == "remove_member" {Some(target)} else {None}}),
                )
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
    fn historic_request(roles: &mut Roles, kind: &str) {
        roles.pending.insert(
            "historic".into(),
            Change {
                id: "historic".into(),
                kind: kind.into(),
                target: identity(3),
                target_name: "Person 3".into(),
                requester: identity(2),
                requester_name: "Person 2".into(),
                created_at: 1,
                primary: identity(1),
            },
        );
    }
    fn decide(roles: &mut Roles, actor: u8, approve: bool) -> Result<Value> {
        roles.apply(
            identity(actor),
            "role_decide",
            &json!({"revision":roles.revision,"request_id":"historic","approve":approve}),
            &members(),
            2,
        )
    }
    #[test]
    fn only_primary_changes_owner_identities_and_primary_cannot_be_removed() {
        let mut roles = Roles::bootstrap(&[identity(1), identity(2), identity(3)]).unwrap();
        for (actor, target, kind) in [
            (2, 4, "make_owner"),
            (2, 3, "remove_owner"),
            (2, 2, "remove_owner"),
            (2, 3, "remove_member"),
            (4, 3, "remove_member"),
            (1, 1, "remove_owner"),
            (1, 1, "remove_member"),
        ] {
            let before = serde_json::to_value(&roles).unwrap();
            assert!(change(&mut roles, actor, target, kind).is_err());
            assert_eq!(serde_json::to_value(&roles).unwrap(), before);
        }
        assert!(roles.retire_member(identity(1)).is_err());
        assert!(roles.is_owner(identity(1)));
        change(&mut roles, 1, 4, "make_owner").unwrap();
        change(&mut roles, 1, 3, "remove_owner").unwrap();
        assert!(roles.is_owner(identity(4)));
        assert!(!roles.is_owner(identity(3)));
        let restored: Roles =
            serde_json::from_value(serde_json::to_value(&roles).unwrap()).unwrap();
        assert_eq!(restored.primary, identity(1));
        assert_eq!(restored.role(identity(1)), "primary_owner");
    }
    #[test]
    fn coowner_still_removes_ordinary_members() {
        let mut roles = Roles::bootstrap(&[identity(1), identity(2)]).unwrap();
        let removed = change(&mut roles, 2, 4, "remove_member").unwrap();
        assert_eq!(removed["removed_identity"], json!(identity(4)));
        assert_eq!(roles.owners, BTreeSet::from([identity(1), identity(2)]));
    }
    #[test]
    fn transfers_are_disabled_but_historical_requests_can_be_declined() {
        let mut roles = Roles::bootstrap(&[identity(1), identity(2), identity(3)]).unwrap();
        for actor in [1, 2, 3] {
            assert!(change(&mut roles, actor, 4, "transfer_primary").is_err());
        }
        historic_request(&mut roles, "transfer_primary");
        assert!(decide(&mut roles, 3, true).is_err());
        assert_eq!(roles.primary, identity(1));
        assert_eq!(decide(&mut roles, 3, false).unwrap()["status"], "declined");
        assert!(roles.pending.is_empty());
    }
    #[test]
    fn historical_owner_removal_cannot_bypass_primary_authorization() {
        for kind in ["remove_owner", "remove_member"] {
            let mut roles = Roles::bootstrap(&[identity(1), identity(2), identity(3)]).unwrap();
            historic_request(&mut roles, kind);
            assert!(decide(&mut roles, 2, true).is_err());
            assert!(decide(&mut roles, 3, true).is_err());
            assert!(roles.is_owner(identity(3)));
            decide(&mut roles, 1, true).unwrap();
            assert!(!roles.is_owner(identity(3)));
            assert!(roles.is_owner(identity(1)));
        }
    }
}

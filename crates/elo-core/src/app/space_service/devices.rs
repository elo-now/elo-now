//! Device retirement is limited to an admitted device of the same profile.
use super::*;

impl ClientApp {
    pub(super) fn space_device_list(&self, credential: &VerifiedCredential) -> Result<Value> {
        let authority = self.authorities.0.first().ok_or("Space unavailable.")?;
        let member = authority
            .head()?
            .members
            .iter()
            .find(|m| m.identity_id == credential.identity())
            .ok_or("Join this Space using an invitation first.")?;
        let devices = member.credential_ids.iter().map(|id| {
            Ok(json!({"id":id,"credential":STANDARD.encode(authority.credential(*id)?.record().bytes())}))
        }).collect::<Result<Vec<_>>>()?;
        Ok(json!({"devices":devices}))
    }

    pub(super) async fn space_revoke_device(
        &mut self,
        state: &mut ServiceState,
        requester: &VerifiedCredential,
        body: &Value,
        replica: Option<&crate::replica::ReplicaStore>,
    ) -> Result<Value> {
        let replica = replica.ok_or("Device management requires a hosted Space.")?;
        let proof = decode_record(field(body, "proof")?)?;
        let target = crate::identity::DeviceRevocation::verify_request(&proof, requester)?;
        if target.identity() != requester.identity() || target.id() == requester.id() {
            return Err("Choose another device belonging to this profile.".into());
        }
        replica.require_active_device(requester.id())?;
        let admitted = self
            .authorities
            .0
            .first()
            .ok_or("Space unavailable.")?
            .head()?
            .members
            .iter()
            .any(|member| {
                member.identity_id == requester.identity()
                    && member.credential_ids.contains(&requester.id())
            });
        if !admitted {
            return Err("Join this Space using an invitation first.".into());
        }
        // Tombstone precedes config publication and remains effective if updating
        // General is interrupted. Every hosted endpoint consults this registry.
        replica.revocations().insert(&proof)?;
        self.apply_device_revocations(state, replica).await?;
        Ok(json!({"revoked":target.id()}))
    }

    pub(super) async fn apply_device_revocations(
        &mut self,
        state: &mut ServiceState,
        replica: &crate::replica::ReplicaStore,
    ) -> Result<()> {
        let authority = self.authorities.0.first().ok_or("Space unavailable.")?;
        let mut next = authority.head()?.clone();
        let mut retired = BTreeSet::new();
        for member in &next.members {
            for id in &member.credential_ids {
                if replica.revocations().get(*id)?.is_some() {
                    retired.insert(*id);
                }
            }
        }
        if retired.is_empty() {
            return Ok(());
        }
        if retired.contains(&next.controller_credential_id) {
            return Err("Space controller recovery is required.".into());
        }
        for member in &mut next.members {
            member.credential_ids.retain(|id| !retired.contains(id));
        }
        next.members
            .retain(|member| !member.credential_ids.is_empty());
        next.owner_credential_ids.retain(|id| !retired.contains(id));
        next.sequence += 1;
        next.previous_config_id = authority.head_id();
        next.nonce = record::random_hex::<16>()?;
        next.action = ConfigAction {
            operation: "device.updated".into(),
            actor_identity: self.identity_id(),
            request_record_id: None,
        };
        self.authorities.0[0]
            .commit_update(
                &self.store,
                next.sign(self.session.signing_key())?,
                self.session.age_identity(),
                now()?,
            )
            .await?;
        state
            .attachment_access
            .retain(|_, access| !access.credential.is_some_and(|id| retired.contains(&id)));
        self.save_service_state(state)?;
        self.queue_team_memberships()?;
        Ok(())
    }
}

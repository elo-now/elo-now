//! Live owner-device pairing changes only the owner's exact device grant. The
//! witness orders the signed proposal; the hosting registry cannot grant it.
use super::*;

impl ClientApp {
    fn linked_witnessed_owner_proposal(
        &self,
        authority: &Authority,
        credential: &VerifiedCredential,
    ) -> Result<Option<SignedRecord>> {
        self.trusted_witness(authority)?;
        self.require_controller(authority)?;
        if credential.identity() != self.identity_id()
            || credential.authorizing_device() != Some(self.session.credential().id())
            || authority
                .credential(self.session.credential().id())?
                .record()
                .bytes()
                != self.session.credential().record().bytes()
        {
            return Err("This device cannot manage General.".into());
        }
        if authority.can_manage(credential.id()) {
            if authority.credential(credential.id())?.record().bytes()
                != credential.record().bytes()
            {
                return Err("Invalid owner device.".into());
            }
            return Ok(None);
        }
        // A pairing retry may reuse its exact live grant, but must not restore
        // an old credential after revocation or promote an existing reader.
        if authority.credential(credential.id()).is_ok() {
            return Err("This device is no longer eligible for pairing.".into());
        }
        let mut config = authority.head()?.clone();
        add_member(&mut config, credential)?;
        config.owner_credential_ids.push(credential.id());
        config.owner_credential_ids.sort();
        config.owner_credential_ids.dedup();
        self.sign_witnessed_device_update(authority, config)
            .map(Some)
    }

    fn sign_witnessed_device_update(
        &self,
        authority: &Authority,
        mut config: StreamConfig,
    ) -> Result<SignedRecord> {
        config.sequence = config
            .sequence
            .checked_add(1)
            .ok_or("General sequence exhausted.")?;
        config.previous_config_id = authority.head_id();
        config.nonce = record::random_hex::<16>()?;
        config.controller_credential_id = self.session.credential().id();
        config.witness_evidence = None;
        config.action = ConfigAction {
            operation: "replace".into(),
            actor_identity: self.identity_id(),
            request_record_id: None,
        };
        Ok(config.sign(self.session.signing_key())?)
    }

    pub(super) async fn update_witnessed_owner_general(
        &mut self,
        address: &space_service::SpaceAddress,
        linked: Option<&VerifiedCredential>,
    ) -> Result<()> {
        let local = self
            .authorities
            .0
            .iter()
            .find(|authority| {
                authority.space() == address.scope.space
                    && authority.stream() == address.scope.stream
            })
            .ok_or("General is unavailable. Refresh the Space and try again.")?
            .clone();
        let mut current = self.witness_read_authority(&local).await?;
        self.require_controller(&current)?;
        if let Some(credential) = linked {
            if let Some(proposal) = self.linked_witnessed_owner_proposal(&current, credential)? {
                let receipt = self
                    .witness_owner_update(&current, &proposal, std::slice::from_ref(credential))
                    .await?;
                current = self.witness_read_authority(&current).await?;
                // Reconciliation may return later changes, but must prove the
                // exact acknowledged transition and still admit this device.
                let config = current.config(receipt.authority_head)?;
                if !current.proves_config_at(receipt.authority_head, config.sequence) {
                    return Err("Invalid owner device acknowledgement.".into());
                }
            }
            if !current.can_manage(credential.id())
                || current.credential(credential.id())?.record().bytes()
                    != credential.record().bytes()
            {
                return Err("This device is no longer admitted to General.".into());
            }
        }
        self.require_controller(&current)?;
        self.import_owner_general(&address.scope, &current.call_proof()?, &[], true)
            .await?;
        self.sync_witnessed_host(address, &current).await?;
        Ok(())
    }
    pub(in crate::app) async fn revoke_witnessed_owner_device(
        &mut self,
        address: &space_service::SpaceAddress,
        proof: &str,
    ) -> Result<Value> {
        let target = crate::identity::DeviceRevocation::verify_request(
            &decode_record(proof)?,
            self.session.credential(),
        )?;
        if target.identity() != self.identity_id() || target.id() == self.session.credential().id()
        {
            return Err("Choose another device belonging to this profile.".into());
        }
        let local = self
            .authorities
            .0
            .iter()
            .find(|authority| {
                authority.space() == address.scope.space
                    && authority.stream() == address.scope.stream
            })
            .ok_or("General is unavailable. Refresh the Space and try again.")?
            .clone();
        let mut current = self.witness_read_authority(&local).await?;
        self.require_controller(&current)?;
        if current.credential(target.id())?.record().bytes() != target.record().bytes() {
            return Err("Invalid owner device.".into());
        }
        if crate::calls::require_member(&current, target.id()).is_ok() {
            let mut config = current.head()?.clone();
            for member in &mut config.members {
                member.credential_ids.retain(|id| *id != target.id());
            }
            config
                .members
                .retain(|member| !member.credential_ids.is_empty());
            config.owner_credential_ids.retain(|id| *id != target.id());
            let proposal = self.sign_witnessed_device_update(&current, config)?;
            let receipt = self.witness_owner_update(&current, &proposal, &[]).await?;
            current = self.witness_read_authority(&current).await?;
            let config = current.config(receipt.authority_head)?;
            if !current.proves_config_at(receipt.authority_head, config.sequence) {
                return Err("Invalid device revocation acknowledgement.".into());
            }
        }
        if crate::calls::require_member(&current, target.id()).is_ok() {
            return Err("This device is still admitted to General.".into());
        }
        self.require_controller(&current)?;
        self.import_owner_general(&address.scope, &current.call_proof()?, &[], true)
            .await?;
        self.sync_witnessed_host(address, &current).await?;
        let _ = self.refresh_notes_access().await;
        Ok(json!({"revoked":target.id()}))
    }
}

#[cfg(test)]
mod tests;

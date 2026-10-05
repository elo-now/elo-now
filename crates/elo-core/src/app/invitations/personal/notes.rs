//! Notes uses ordinary encrypted messages in one private conversation per
//! hosting Space. The registry chooses a conversation, never its recipients.
use super::*;

#[cfg(test)]
mod tests;

impl ClientApp {
    pub(in crate::app) fn is_notes_authority(&self, authority: &Authority) -> bool {
        self.call_host.as_ref().is_some_and(|address| {
            authority.stream()
                == crate::notes::stream(
                    address.scope.space,
                    address.scope.stream,
                    self.identity_id(),
                )
        })
    }

    pub(in crate::app) fn notes_general(&self) -> Result<Authority> {
        let address = self.call_host.as_ref().ok_or("Join a Space first.")?;
        let general = self
            .authorities
            .0
            .iter()
            .find(|authority| {
                authority.space() == address.scope.space
                    && authority.stream() == address.scope.stream
            })
            .ok_or("General is unavailable. Refresh the Space and try again.")?;
        crate::calls::require_member(general, self.session.credential().id())?;
        Ok(general.clone())
    }

    fn prepare_notes(&self, general: &Authority) -> Result<Authority> {
        // A copied follower vault or a revoked grant cannot manufacture a new
        // namespace merely because it holds an old credential for this profile.
        if !self.authorities.0.iter().any(|authority| {
            self.require_controller(authority).is_ok()
                && (authority.is_owner_managed()
                    || authority.genesis().body()["owners"]
                        .as_array()
                        .is_some_and(|owners| {
                            owners.len() == 1
                                && owners[0]["identity_id"] == json!(self.identity_id())
                        }))
        }) {
            return Err("This device cannot create a private chat.".into());
        }
        let credential = self.session.credential();
        let stream = crate::notes::stream(general.space(), general.stream(), self.identity_id());
        let nonce = Sha256::digest(
            [
                b"elo.now/notes-genesis/v3\0".as_slice(),
                credential.id().as_bytes(),
                self.session.transfer_nonce().as_bytes(),
                general.space().as_bytes(),
                general.stream().as_bytes(),
            ]
            .concat(),
        );
        let root = field(credential.record().body(), "root_public_key")?.to_owned();
        let genesis = SpaceGenesis {
            witness: None,
            v: 3,
            kind: "space.genesis".into(),
            nonce: record::encode_hex(&nonce[..16]),
            issuer_identity: self.identity_id(),
            owners: vec![Owner {
                identity_id: self.identity_id(),
                root_public_key: root.clone(),
            }],
            controller_credential_id: credential.id(),
        };
        let signed =
            SignedRecord::sign(&serde_json::to_vec(&genesis)?, self.session.signing_key())?;
        let mut authority = Authority::new(
            signed.bytes(),
            SpaceId::from_bytes(*signed.id().as_bytes()),
            &root_key(&root)?,
            credential.clone(),
            stream,
        )?;
        let mut member = general
            .head()?
            .members
            .iter()
            .find(|member| member.identity_id == self.identity_id())
            .ok_or("This profile is no longer in the Space.")?
            .clone();
        member.external = false;
        member.capabilities = vec![
            Capability::Read,
            Capability::Post,
            Capability::ShareHistory,
            Capability::Manage,
        ];
        for id in &member.credential_ids {
            authority.add_credential(general.credential(*id)?.clone());
        }
        let config = StreamConfig {
            witness_evidence: None,
            chat_kind: Some(ChatKind::Direct),
            v: 3,
            kind: "stream.config".into(),
            nonce: stream.to_string(),
            space_id: authority.space(),
            stream_id: stream,
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: credential.id(),
            owner_credential_ids: member.credential_ids.clone(),
            members: vec![member],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: self.identity_id(),
                request_record_id: None,
            },
            recovery: None,
        };
        authority.apply_config(config.sign(self.session.signing_key())?)?;
        Ok(authority)
    }

    pub(super) async fn open_notes(&mut self, name: &str) -> Result<Value> {
        self.sync_notes(Some(name), true).await?;
        let general = self.notes_general()?;
        Ok(
            json!({"stream":crate::notes::stream(general.space(),general.stream(),self.identity_id()),"view":self.view().await?}),
        )
    }

    pub(in crate::app) async fn refresh_notes_access(&mut self) -> Result<()> {
        if self.call_host.is_none() {
            return Ok(());
        }
        let general = self.notes_general()?;
        let stream = crate::notes::stream(general.space(), general.stream(), self.identity_id());
        let Some(notes) = self.authorities.0.iter().find(|authority| {
            authority.stream() == stream
                && authority.controller().id() == self.session.credential().id()
        }) else {
            return Ok(());
        };
        if notes.head()?.members[0].credential_ids
            == general
                .head()?
                .members
                .iter()
                .find(|member| member.identity_id == self.identity_id())
                .ok_or("This profile is no longer in the Space.")?
                .credential_ids
        {
            return Ok(());
        }
        self.sync_notes(None, false).await
    }

    pub(in crate::app) async fn sync_notes(
        &mut self,
        name: Option<&str>,
        create: bool,
    ) -> Result<()> {
        let general = self.notes_general()?;
        self.require_fresh_membership(&general).await?;
        let address = self.call_host.clone().ok_or("Join a Space first.")?;
        let stream = crate::notes::stream(general.space(), general.stream(), self.identity_id());
        let mut reply = self
            .call_space(&address, "notes", json!({"general_head":general.head_id()}))
            .await?;
        if reply["general_head"] != json!(general.head_id()) {
            return Err("General permissions have changed. Refresh and try again.".into());
        }
        if reply["proof"].is_null() {
            if !create {
                return Err("Notes registry is unavailable.".into());
            }
            if self.pins.iter().any(|pin| pin.stream == stream) {
                return Err("Notes registry is unavailable.".into());
            }
            let authority = self.prepare_notes(&general)?;
            reply = self
                .call_space(
                    &address,
                    "notes",
                    json!({"general_head":general.head_id(),"proof":authority.call_proof()?}),
                )
                .await?;
        }
        let proof: crate::authority::CallAuthorityProof =
            serde_json::from_value(reply["proof"].clone())?;
        // The controller may narrow revoked devices or explicitly grant devices
        // already admitted to this same Space. Other devices only read the proof.
        let mut authority = crate::notes::verify_scope(&proof, &general, self.identity_id())?;
        let index = self.pins.iter().position(|pin| pin.stream == stream);
        if let Some(index) = index {
            let previous = &self.authorities.0[index];
            if previous.space() != authority.space()
                || !authority.proves_config_at(
                    previous.head_id().ok_or("Missing Notes head.")?,
                    previous.head()?.sequence,
                )
            {
                return Err("Notes authority changed unexpectedly.".into());
            }
        }
        if authority.controller().id() == self.session.credential().id() {
            let mut next = authority.head()?.clone();
            let accepted = &general
                .head()?
                .members
                .iter()
                .find(|member| member.identity_id == self.identity_id())
                .ok_or("This profile is no longer in the Space.")?
                .credential_ids;
            if next.members.len() != 1 || next.members[0].identity_id != self.identity_id() {
                return Err("Invalid Notes authority.".into());
            }
            if &next.members[0].credential_ids != accepted {
                if !self.session.can_control(authority.space()) {
                    return Err("Open Notes on its original device to update access.".into());
                }
                for id in accepted {
                    authority.add_credential(general.credential(*id)?.clone());
                }
                next.members[0].credential_ids = accepted.clone();
                next.owner_credential_ids = accepted.clone();
                next.sequence += 1;
                next.previous_config_id = authority.head_id();
                next.nonce = record::random_hex::<16>()?;
                next.action = ConfigAction {
                    operation: "device.updated".into(),
                    actor_identity: self.identity_id(),
                    request_record_id: None,
                };
                let expected = authority.head_id();
                authority.apply_config(next.sign(self.session.signing_key())?)?;
                reply = self.call_space(&address,"notes",json!({"general_head":general.head_id(),"expected_head":expected,"proof":authority.call_proof()?})).await?;
            }
        }
        if reply["general_head"] != json!(general.head_id()) {
            return Err("General permissions have changed. Refresh and try again.".into());
        }
        let proof = serde_json::from_value(reply["proof"].clone())?;
        let authority = crate::notes::verify(&proof, &general, self.identity_id())?;
        if crate::calls::require_member(&authority, self.session.credential().id())?
            != self.identity_id()
        {
            return Err("Open Notes on its original device to approve this device.".into());
        }
        let previous = index.map(|index| &self.authorities.0[index]);
        if let Some(previous) = previous
            && (previous.space() != authority.space()
                || !authority.proves_config_at(
                    previous.head_id().ok_or("Missing Notes head.")?,
                    previous.head()?.sequence,
                ))
        {
            return Err("Notes authority changed unexpectedly.".into());
        }
        let authority = authority
            .merge_into_store(previous, &self.store, self.session.age_identity(), now()?)
            .await?;
        if authority.controller().id() == self.session.credential().id()
            && !self.session.can_control(authority.space())
        {
            // Only the successful new creation can activate a new grant. An
            // imported namespace cannot reactivate an old follower vault.
            if index.is_some() {
                return Err("Notes controller is unavailable.".into());
            }
            if self.prepare_notes(&general)?.space() != authority.space() {
                return Err("Notes controller is unavailable.".into());
            }
            self.session
                .activate_new_space_controller(authority.space())?;
            self.persist_vault()?;
        }
        if let Some(index) = index {
            self.authorities.0[index] = authority;
            if let Some(name) = name {
                self.pins[index].name = name.into();
            }
        } else {
            self.pins.push(Pin {
                personal_seed: Some(false),
                chat_kind: Some(ChatKind::Direct),
                name: name.unwrap_or("Notes").into(),
                space: authority.space(),
                stream,
                root: authority.genesis().body()["owners"][0]["root_public_key"]
                    .as_str()
                    .ok_or("Invalid Notes root.")?
                    .into(),
                group: None,
                created_at: now()?.as_millis(),
            });
            self.authorities.0.push(authority);
        }
        self.persist_workspace()?;
        Ok(())
    }
}

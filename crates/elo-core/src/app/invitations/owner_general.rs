//! Owner-device General: clients sign membership, the host serializes public heads.
use super::*;
use crate::authority::CallAuthorityProof;

mod witnessed_devices;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    proof: CallAuthorityProof,
    contacts: Vec<Packet>,
}

impl ClientApp {
    /// The persisted creation ID makes retries reproduce the same signed genesis.
    pub(in crate::app) fn owner_general_creation(
        &self,
        request_id: &str,
    ) -> Result<CallAuthorityProof> {
        let stream = StreamId::from_bytes(record::hex::<16>(request_id)?);
        let credential = self.session.credential();
        let root = field(credential.record().body(), "root_public_key")?.to_owned();
        let version = if self.witness_pin.is_some() { 4 } else { 2 };
        let genesis = SpaceGenesis {
            witness: self.witness_pin.clone(),
            v: version,
            kind: "space.genesis".into(),
            nonce: request_id.into(),
            issuer_identity: credential.identity(),
            owners: vec![Owner {
                identity_id: credential.identity(),
                root_public_key: root.clone(),
            }],
            controller_credential_id: credential.id(),
        };
        let genesis =
            SignedRecord::sign(&serde_json::to_vec(&genesis)?, self.session.signing_key())?;
        let mut authority = Authority::new(
            genesis.bytes(),
            genesis.id().to_string().parse()?,
            &root_key(&root)?,
            credential.clone(),
            stream,
        )?;
        let config = StreamConfig {
            witness_evidence: None,
            v: version,
            kind: "stream.config".into(),
            nonce: request_id.into(),
            space_id: authority.space(),
            stream_id: stream,
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: credential.id(),
            members: vec![Member {
                identity_id: credential.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: root,
                capabilities: owner_capabilities(),
                credential_ids: vec![credential.id()],
                external: false,
            }],
            owner_credential_ids: vec![credential.id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: credential.identity(),
                request_record_id: None,
            },
            chat_kind: Some(ChatKind::Chat),
            recovery: None,
        };
        authority.apply_config(config.sign(self.session.signing_key())?)?;
        Ok(authority.call_proof()?)
    }

    pub(in crate::app) async fn accept_owner_general(&mut self, encoded: &str) -> Result<()> {
        let enrollment: Enrollment = serde_json::from_slice(&STANDARD.decode(encoded)?)?;
        let scope = self
            .team
            .as_ref()
            .ok_or("No team was configured.")?
            .scope
            .clone();
        self.import_owner_general(&scope, &enrollment.proof, &enrollment.contacts, true)
            .await?;
        Ok(())
    }

    async fn import_owner_general(
        &mut self,
        scope: &team::TeamScope,
        proof: &CallAuthorityProof,
        contacts: &[Packet],
        require_membership: bool,
    ) -> Result<Authority> {
        let incoming = self.verify_general_proof(proof, scope.space, scope.stream)?;
        let genesis: SpaceGenesis = incoming.genesis().decode()?;
        if !incoming.is_owner_managed()
            || incoming.is_forked()
            || incoming.initial_controller().id() != scope.controller
            || genesis
                .owners
                .first()
                .is_none_or(|o| o.root_public_key != scope.root)
            || incoming.head()?.chat_kind != Some(ChatKind::Chat)
        {
            return Err("Invalid General permissions.".into());
        }
        if require_membership
            && crate::calls::require_member(&incoming, self.session.credential().id()).is_err()
        {
            return Err("This General enrollment is for another device.".into());
        }
        let index = self
            .pins
            .iter()
            .position(|p| p.space == scope.space && p.stream == scope.stream);
        if let Some(index) = index {
            let previous = &self.authorities.0[index];
            if !previous.is_owner_managed()
                || previous.is_forked()
                || incoming.genesis().id() != previous.genesis().id()
                || !incoming.proves_config_at(
                    previous.head_id().ok_or("Missing configuration.")?,
                    previous.head()?.sequence,
                )
            {
                return Err("Unrelated General configuration.".into());
            }
        }
        if contacts.len() > record::MAX_CHAT_CREDENTIALS {
            return Err("Too many General contact cards.".into());
        }
        let mut state = self.invitation_state()?;
        for packet in contacts {
            if !matches!(packet, Packet::Contact { .. }) {
                return Err("Invalid General contact.".into());
            }
            let (_, credential, _) = candidate(packet, 0)?;
            crate::calls::require_member(&incoming, credential.id())?;
            if credential.identity() != self.identity_id() {
                state
                    .contacts
                    .insert(credential.id().to_string(), packet.clone());
            }
        }
        if index.is_none_or(|i| self.authorities.0[i].head_id() != incoming.head_id()) {
            let merged = incoming
                .merge_into_store(
                    index.map(|i| &self.authorities.0[i]),
                    &self.store,
                    self.session.age_identity(),
                    now()?,
                )
                .await?;
            if let Some(index) = index {
                self.authorities.0[index] = merged;
            } else {
                self.pins.push(Pin {
                    personal_seed: Some(false),
                    name: "General".into(),
                    space: scope.space,
                    stream: scope.stream,
                    root: scope.root.clone(),
                    chat_kind: Some(ChatKind::Chat),
                    group: None,
                    created_at: now()?.as_millis(),
                });
                self.authorities.0.push(merged);
            }
            self.persist_workspace()?;
            self.invalidate_membership_checks().await;
        }
        self.save_invitations(&state)?;
        let previous_mode = self.session.controller_mode;
        let previous_spaces = self.session.controller_spaces.clone();
        if self.session.activate_owner_grant(&incoming)?
            && let Err(error) = self.persist_vault()
        {
            self.session.controller_mode = previous_mode;
            self.session.controller_spaces = previous_spaces;
            return Err(error);
        }
        Ok(incoming)
    }

    /// Called from the existing Space synchronization cycle, never before each message.
    pub(in crate::app) async fn sync_owner_general(
        &mut self,
        address: &space_service::SpaceAddress,
    ) -> Result<()> {
        self.update_owner_general(address, None, None).await
    }

    pub(in crate::app) async fn sync_owner_general_foreground(
        &mut self,
        address: &space_service::SpaceAddress,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
        self.update_owner_general(address, None, Some(deadline))
            .await
    }

    async fn owner_general_request(
        &self,
        address: &space_service::SpaceAddress,
        action: &str,
        body: Value,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Value> {
        let request = self.call_space(address, action, body);
        if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, request)
                .await
                .map_err(|_| "Space server timed out.")?
        } else {
            request.await
        }
    }

    async fn update_owner_general(
        &mut self,
        address: &space_service::SpaceAddress,
        linked: Option<&VerifiedCredential>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<()> {
        let scope = &address.scope;
        let Some(local) = self
            .authorities
            .0
            .iter()
            .find(|a| a.space() == scope.space && a.stream() == scope.stream)
        else {
            return Ok(());
        };
        if !local.is_owner_managed() || self.require_controller(local).is_err() {
            return Ok(());
        }
        if local.witness_pin().is_some() {
            return self.update_witnessed_owner_general(address, linked).await;
        }
        for attempt in 0..3 {
            let response = self
                .owner_general_request(address, "authority", json!({}), deadline)
                .await?;
            let proof: CallAuthorityProof = serde_json::from_value(response["proof"].clone())?;
            let mut authority = self.import_owner_general(scope, &proof, &[], false).await?;
            self.require_controller(&authority)?;
            if response["head"] != json!(authority.head_id()) {
                return Err("Invalid General head.".into());
            }
            let policy = crate::owner_admission::verify_owner_policy(
                &authority,
                &response,
                now()?.as_millis() as u64,
            )?;
            let removed = policy.removed;
            let revoked = policy.revoked;
            let owners = policy.owner_identities;
            let mut config = authority.head()?.clone();
            config.members.retain(|m| !removed.contains(&m.identity_id));
            for member in &mut config.members {
                member.credential_ids.retain(|id| !revoked.contains(id));
            }
            config.members.retain(|m| !m.credential_ids.is_empty());
            let mut contacts = Vec::new();
            for pending in policy.pending {
                let packet = decode(&pending.request.contact)?;
                let credential = pending.credential;
                if !removed.contains(&credential.identity()) && !revoked.contains(&credential.id())
                {
                    if !authority
                        .head()?
                        .members
                        .iter()
                        .any(|member| member.credential_ids.contains(&credential.id()))
                        && let Some(parent) = credential.authorizing_device()
                        && (revoked.contains(&parent)
                            || crate::calls::require_member(&authority, parent).ok()
                                != Some(credential.identity()))
                    {
                        return Err("The authorizing device is no longer active.".into());
                    }
                    add_member(&mut config, &credential)?;
                    authority.add_credential(credential);
                    contacts.push(packet);
                }
            }
            if let Some(credential) = linked {
                if credential.identity() != self.identity_id()
                    || revoked.contains(&credential.id())
                    || credential
                        .authorizing_device()
                        .is_none_or(|parent| parent != self.session.credential().id())
                    || !owners.contains(&credential.identity())
                {
                    return Err("This device cannot manage General.".into());
                }
                add_member(&mut config, credential)?;
                authority.add_credential(credential.clone());
            }
            config.owner_credential_ids.clear();
            for member in &mut config.members {
                if owners.contains(&member.identity_id) {
                    member.capabilities = owner_capabilities();
                    config.owner_credential_ids.extend(&member.credential_ids);
                } else {
                    member.capabilities = vec![Capability::Read, Capability::Post];
                }
            }
            config.owner_credential_ids.sort();
            config.owner_credential_ids.dedup();
            config.members.sort_by_key(|member| member.identity_id);
            if config.members == authority.head()?.members
                && config.owner_credential_ids == authority.head()?.owner_credential_ids
                && policy.commitment == authority.head()?.action.request_record_id
            {
                return Ok(());
            }
            config.sequence = config
                .sequence
                .checked_add(1)
                .ok_or("General sequence exhausted.")?;
            config.previous_config_id = authority.head_id();
            config.nonce = record::random_hex::<16>()?;
            config.controller_credential_id = self.session.credential().id();
            config.action = ConfigAction {
                operation: "replace".into(),
                actor_identity: self.identity_id(),
                request_record_id: policy.commitment,
            };
            let expected_head = authority.head_id();
            authority.apply_config(config.sign(self.session.signing_key())?)?;
            let proposed = authority.call_proof()?;
            let result = self
                .owner_general_request(
                    address,
                    "authority_publish",
                    json!({"expected_head":expected_head,"proof":proposed}),
                    deadline,
                )
                .await;
            match result {
                Ok(result) => {
                    if result["head"] != json!(authority.head_id()) {
                        return Err("Invalid General commit receipt.".into());
                    }
                    self.import_owner_general(scope, &proposed, &contacts, false)
                        .await?;
                    return Ok(());
                }
                Err(error)
                    if attempt < 2
                        && error.to_string()
                            == "General permissions have changed. Refresh and try again." =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err("General permissions have changed. Refresh and try again.".into())
    }

    pub(in crate::app) async fn authorize_linked_owner_device(
        &mut self,
        credential: &VerifiedCredential,
    ) -> Result<()> {
        if let Some(address) = self.call_host.clone() {
            self.update_owner_general(&address, Some(credential), None)
                .await?;
            let _ = self.refresh_notes_access().await;
        }
        if let Some(spaces) = self.spaces.as_mut() {
            for child in spaces.children_mut().values_mut() {
                if let Some(address) = child.call_host.clone() {
                    child
                        .update_owner_general(&address, Some(credential), None)
                        .await?;
                    let _ = child.refresh_notes_access().await;
                }
            }
        }
        Ok(())
    }
}

fn owner_capabilities() -> Vec<Capability> {
    vec![
        Capability::Read,
        Capability::Post,
        Capability::ShareHistory,
        Capability::Manage,
    ]
}
fn add_member(config: &mut StreamConfig, credential: &VerifiedCredential) -> Result<()> {
    if let Some(member) = config
        .members
        .iter_mut()
        .find(|m| m.identity_id == credential.identity())
    {
        if member.root_public_key != field(credential.record().body(), "root_public_key")? {
            return Err("Invalid member root.".into());
        }
        if !member.credential_ids.contains(&credential.id()) {
            member.credential_ids.push(credential.id());
            member.credential_ids.sort();
        }
    } else {
        config.members.push(Member {
            identity_id: credential.identity(),
            identity_type: "HUMAN".into(),
            root_public_key: field(credential.record().body(), "root_public_key")?.into(),
            capabilities: vec![Capability::Read, Capability::Post],
            credential_ids: vec![credential.id()],
            external: true,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn profile(path: &Path, name: &str) -> ClientApp {
        ProfileDraft::new()
            .unwrap()
            .save_named(
                path.join(name),
                "synthetic owner General password".into(),
                "General",
                name,
            )
            .await
            .unwrap()
    }
    fn scope(proof: &CallAuthorityProof) -> team::TeamScope {
        let genesis = decode_record(&proof.genesis).unwrap();
        let body: SpaceGenesis = genesis.decode().unwrap();
        team::TeamScope {
            space: genesis.id().to_string().parse().unwrap(),
            stream: StreamId::from_bytes(record::hex(&body.nonce).unwrap()),
            root: body.owners[0].root_public_key.clone(),
            controller: body.controller_credential_id,
        }
    }
    #[tokio::test]
    async fn native_witness_pin_rejects_legacy_owner_enrollment_and_requires_the_exact_pin() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = profile(dir.path(), "Owner").await;
        let legacy = app.owner_general_creation(&"72".repeat(16)).unwrap();
        let legacy_scope = scope(&legacy);
        let descriptor = |scope| team::TeamDescriptor {
            v: 1,
            url: "https://host.example.test/team/v1/enroll".into(),
            token: "73".repeat(32),
            scope,
            message_lifetime_seconds: 86_400,
            service_credential: None,
        };
        app.configure_team(descriptor(legacy_scope.clone()))
            .unwrap();
        let pin = crate::authority::WitnessPin {
            url: "https://witness.example.test/witness/v1".into(),
            public_key: record::encode_hex(
                ed25519_dalek::SigningKey::from_bytes(&[74; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
            key_generation: 1,
        };
        app.configure_witness_pin(Some(pin.clone())).unwrap();
        let reply = |proof| team::EnrollmentReply {
            v: 2,
            packet: STANDARD.encode(
                serde_json::to_vec(&Enrollment {
                    proof,
                    contacts: Vec::new(),
                })
                .unwrap(),
            ),
        };
        let count = app.pins.len();
        assert!(
            app.accept_space_enrollment(reply(legacy.clone()))
                .await
                .is_err()
        );
        assert_eq!(
            app.pins.len(),
            count,
            "a new legacy General must not be imported"
        );
        let witnessed = app.owner_general_creation(&"75".repeat(16)).unwrap();
        let witnessed_scope = scope(&witnessed);
        app.configure_team(descriptor(witnessed_scope.clone()))
            .unwrap();
        app.configure_witness_pin(Some(crate::authority::WitnessPin {
            key_generation: 2,
            ..pin.clone()
        }))
        .unwrap();
        assert!(
            app.accept_space_enrollment(reply(witnessed.clone()))
                .await
                .is_err()
        );
        app.configure_witness_pin(Some(pin)).unwrap();
        app.accept_space_enrollment(reply(witnessed)).await.unwrap();
        assert_eq!(app.pins.len(), count + 1);
        let view = app.view_local().await.unwrap();
        let general = view["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stream| stream["is_general"] == true)
            .unwrap();
        assert_eq!(general["name"], "General");
        assert_eq!(general["owner_managed"], true);
        app.configure_witness_pin(None).unwrap();
        assert!(
            app.verify_general_proof(&legacy, legacy_scope.space, legacy_scope.stream)
                .is_ok()
        );
        app.close().await.unwrap();
    }
    #[tokio::test]
    async fn owner_general_creation_retries_are_identical_and_have_only_the_real_owner() {
        let dir = tempfile::tempdir().unwrap();
        let app = profile(dir.path(), "Owner").await;
        let id = "12".repeat(16);
        let proof = app.owner_general_creation(&id).unwrap();
        assert_eq!(
            serde_json::to_value(&proof).unwrap(),
            serde_json::to_value(app.owner_general_creation(&id).unwrap()).unwrap()
        );
        let scope = scope(&proof);
        let authority = proof.verify(scope.space, scope.stream).unwrap();
        assert_eq!(authority.head().unwrap().members.len(), 1);
        assert_eq!(
            authority.head().unwrap().members[0].identity_id,
            app.identity_id()
        );
        assert_eq!(
            authority.head().unwrap().members[0].credential_ids,
            vec![app.session.credential().id()]
        );
        assert!(authority.can_manage(app.session.credential().id()));
        let other = app.owner_general_creation(&"34".repeat(16)).unwrap();
        assert_ne!(other.genesis, proof.genesis);
        app.close().await.unwrap();
    }
    #[tokio::test]
    async fn restored_general_import_does_not_activate_control_and_rejects_rollback_or_another_root()
     {
        let dir = tempfile::tempdir().unwrap();
        let mut app = profile(dir.path(), "Owner").await;
        let proof = app.owner_general_creation(&"56".repeat(16)).unwrap();
        let scope = scope(&proof);
        let password = "synthetic restored General password";
        app.session = Session::restore_backup(
            &app.session.seal(password.into()).unwrap(),
            password.into(),
            app.identity_id(),
        )
        .unwrap();
        let mut authority = app
            .import_owner_general(&scope, &proof, &[], true)
            .await
            .unwrap();
        assert!(!app.session.can_control(scope.space));
        app.session
            .activate_new_space_controller(scope.space)
            .unwrap();
        assert!(app.require_controller(&authority).is_ok());
        let mut config = authority.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = authority.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        authority
            .apply_config(config.sign(app.session.signing_key()).unwrap())
            .unwrap();
        app.import_owner_general(&scope, &authority.call_proof().unwrap(), &[], true)
            .await
            .unwrap();
        assert!(
            app.import_owner_general(&scope, &proof, &[], true)
                .await
                .is_err()
        );
        let mut bad_scope = scope.clone();
        bad_scope.root = "99".repeat(32);
        assert!(
            app.import_owner_general(&bad_scope, &authority.call_proof().unwrap(), &[], true)
                .await
                .is_err()
        );
        // Importing one valid branch cannot hide a locally observed fork.
        let mut competing = authority.head().unwrap().clone();
        competing.nonce = record::random_hex::<16>().unwrap();
        let index = app
            .authorities
            .0
            .iter()
            .position(|a| a.space() == scope.space && a.stream() == scope.stream)
            .unwrap();
        app.authorities.0[index]
            .apply_config(competing.sign(app.session.signing_key()).unwrap())
            .unwrap();
        assert!(app.authorities.0[index].is_forked());
        assert!(
            app.import_owner_general(&scope, &authority.call_proof().unwrap(), &[], true)
                .await
                .is_err()
        );
        app.close().await.unwrap();
    }
}

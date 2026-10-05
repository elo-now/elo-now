//! Everyday chat creation uses an already authorized device, never a root key.
use super::*;
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

/// Legacy imports infer once; subsequent membership changes never recategorize a pin.
pub(super) fn imported_kind(authority: &Authority, identity: IdentityId) -> Result<ChatKind> {
    let config = authority.head()?;
    Ok(config.chat_kind.unwrap_or_else(|| {
        if config.members.len() == 2
            && config.members.iter().any(|m| m.identity_id == identity)
            && config.members.iter().all(|m| m.identity_type == "HUMAN")
        {
            ChatKind::Direct
        } else {
            ChatKind::Chat
        }
    }))
}

impl ClientApp {
    /// A linked owner has its own signing key. General's live owner grant may
    /// authorize a new private namespace, never another device's old streams.
    fn private_device_genesis(&self) -> Result<SignedRecord> {
        let scope = &self
            .team
            .as_ref()
            .ok_or("no active personal chat controller")?
            .scope;
        let general = self
            .authorities
            .0
            .iter()
            .find(|authority| {
                authority.is_owner_managed()
                    && authority.space() == scope.space
                    && authority.stream() == scope.stream
                    && authority.initial_controller().id() == scope.controller
                    && self.pins.iter().any(|pin| {
                        pin.space == scope.space
                            && pin.stream == scope.stream
                            && pin.root == scope.root
                    })
            })
            .ok_or("no active personal chat controller")?;
        self.require_controller(general)?;
        let credential = self.session.credential();
        // Reuse one namespace in this General and vault generation. Restoring
        // a backup rotates transfer_nonce, so creating a new Space cannot
        // reactivate an earlier private namespace with the same device key.
        let hash = Sha256::digest(
            [
                b"elo.now/private-genesis/v3\0".as_slice(),
                credential.id().as_bytes(),
                self.session.transfer_nonce().as_bytes(),
                scope.space.as_bytes(),
                scope.stream.as_bytes(),
            ]
            .concat(),
        );
        let genesis = SpaceGenesis {
            witness: None,
            v: 3,
            kind: "space.genesis".into(),
            nonce: record::encode_hex(&hash[..16]),
            issuer_identity: credential.identity(),
            owners: vec![Owner {
                identity_id: credential.identity(),
                root_public_key: field(credential.record().body(), "root_public_key")?.into(),
            }],
            controller_credential_id: credential.id(),
        };
        Ok(SignedRecord::sign(
            &serde_json::to_vec(&genesis)?,
            self.session.signing_key(),
        )?)
    }

    /// Publish a legacy stream's stable category when its controller invites someone.
    /// The signed update preserves every participant, permission and recovery proof.
    pub(super) async fn ensure_chat_kind(&mut self, index: usize) -> Result<()> {
        let authority = &self.authorities.0[index];
        self.require_private_chat_controller(authority)?;
        if authority.head()?.chat_kind.is_some() {
            return Ok(());
        }
        let mut config = authority.head()?.clone();
        config.chat_kind = self.pins[index].chat_kind;
        config.sequence += 1;
        config.previous_config_id = authority.head_id();
        config.nonce = record::random_hex::<16>()?;
        config.recovery = None;
        config.action = ConfigAction {
            operation: "replace".into(),
            actor_identity: self.session.identity_id(),
            request_record_id: None,
        };
        let record = config.sign(self.session.signing_key())?;
        Box::pin(self.publish_call_update(&self.authorities.0[index], &record)).await?;
        self.authorities.0[index]
            .commit_update(&self.store, record, self.session.age_identity(), now()?)
            .await?;
        Ok(())
    }

    pub(super) async fn create_chat(
        &mut self,
        name: &str,
        group: Option<&str>,
        kind: ChatKind,
    ) -> Result<()> {
        self.create_chat_at(name, group, kind, None).await
    }

    pub(super) async fn create_chat_at(
        &mut self,
        name: &str,
        group: Option<&str>,
        kind: ChatKind,
        requested_stream: Option<StreamId>,
    ) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.len() > 120 {
            return Err("invalid channel name".into());
        }
        self.validate_group(group)?;
        // Select from verified local authority, not the currently viewed chat
        // or caller-supplied identifiers. Other owners must never implicitly
        // receive access to an ordinary personal chat.
        let mut source = None;
        let mut recovered = false;
        for a in self.authorities.0.iter() {
            let genesis: SpaceGenesis = a.genesis().decode()?;
            if a.is_owner_managed()
                || genesis.owners.len() != 1
                || genesis.owners[0].identity_id != self.session.identity_id()
                || self.require_controller(a).is_err()
            {
                continue;
            }
            // Single-controller initial configs must be signed by the genesis device.
            // A recovered device cannot invent that signature or transplant
            // another Stream's config chain. Fail closed until the protocol
            // supports a recovery proof on an initial config.
            if a.controller().id() != a.initial_controller().id() {
                recovered = true;
                continue;
            }
            source = Some(a.genesis().clone());
            break;
        }
        let signed_genesis = match source {
            Some(genesis) => genesis,
            None => self.private_device_genesis().map_err(|_| {
                if recovered {
                    "new chat after controller recovery is not supported"
                } else {
                    "no active personal chat controller"
                }
            })?,
        };
        let genesis: SpaceGenesis = signed_genesis.decode()?;
        let space: SpaceId = signed_genesis.id().to_string().parse()?;
        let stream = match requested_stream {
            Some(stream) => stream,
            None => record::random_hex::<16>()?.parse()?,
        };
        let c = self.session.credential();
        let root = &genesis.owners[0].root_public_key;
        let mut authority = Authority::new(
            signed_genesis.bytes(),
            space,
            &root_key(root)?,
            c.clone(),
            stream,
        )?;
        let config = StreamConfig {
            witness_evidence: None,
            chat_kind: Some(kind),
            v: genesis.v,
            kind: "stream.config".into(),
            nonce: match requested_stream {
                Some(stream) => stream.to_string(),
                None => record::random_hex::<16>()?,
            },
            space_id: space,
            stream_id: stream,
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: c.id(),
            members: vec![Member {
                identity_id: c.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: root.clone(),
                capabilities: vec![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ],
                credential_ids: vec![c.id()],
                external: false,
            }],
            owner_credential_ids: vec![c.id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: c.identity(),
                request_record_id: None,
            },
            recovery: None,
        };
        let record = config.sign(self.session.signing_key())?;
        Box::pin(self.publish_call_update(&authority, &record)).await?;
        authority
            .commit_update(&self.store, record, self.session.age_identity(), now()?)
            .await?;
        if !self.session.can_control(space) {
            let previous_mode = self.session.controller_mode;
            let previous_spaces = self.session.controller_spaces.clone();
            let granted = self
                .session
                .activate_new_space_controller(space)
                .map_err(Into::into)
                .and_then(|()| self.persist_vault());
            if let Err(error) = granted {
                self.session.controller_mode = previous_mode;
                self.session.controller_spaces = previous_spaces;
                return Err(error);
            }
        }
        self.pins.push(Pin {
            personal_seed: Some(false),
            chat_kind: Some(kind),
            name: name.into(),
            space,
            stream,
            root: root.clone(),
            group: group.map(str::to_owned),
            created_at: now()?.as_millis(),
        });
        self.authorities.0.push(authority);
        // Existing namespaces do not rewrite the vault. The new config and
        // workspace remain encrypted, including device-created private chats.
        self.persist_workspace()?;
        Ok(())
    }
}

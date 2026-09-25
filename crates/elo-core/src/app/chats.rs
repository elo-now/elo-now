//! Everyday chat creation uses an already authorized device, never a root key.
use super::*;

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
    /// Publish a legacy stream's stable category when its controller invites someone.
    /// The signed update preserves every participant, permission and recovery proof.
    pub(super) async fn ensure_chat_kind(&mut self, index: usize) -> Result<()> {
        let authority = &self.authorities.0[index];
        self.require_controller(authority)?;
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
            if genesis.owners.len() != 1
                || genesis.owners[0].identity_id != self.session.identity_id()
                || self.require_controller(a).is_err()
            {
                continue;
            }
            // v1 initial Stream configs must be signed by the genesis device.
            // A recovered device cannot invent that signature or transplant
            // another Stream's config chain. Fail closed until the protocol
            // supports a recovery proof on an initial config.
            if a.controller().id() != a.initial_controller().id() {
                recovered = true;
                continue;
            }
            source = Some((a, genesis));
            break;
        }
        let (source, genesis) = source.ok_or(if recovered {
            "new chat after controller recovery is not supported"
        } else {
            "no active personal chat controller"
        })?;
        let space = source.space();
        let stream = match requested_stream {
            Some(stream) => stream,
            None => record::random_hex::<16>()?.parse()?,
        };
        let c = self.session.credential();
        let root = &genesis.owners[0].root_public_key;
        let mut authority = Authority::new(
            source.genesis().bytes(),
            space,
            &root_key(root)?,
            c.clone(),
            stream,
        )?;
        let config = StreamConfig {
            chat_kind: Some(kind),
            v: 1,
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
        // No vault rewrite or controller activation: existing device grants
        // remain unchanged. The new config and workspace are encrypted.
        self.persist_workspace()?;
        Ok(())
    }
}

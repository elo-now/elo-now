//! Opening a known person's one-to-one DM grants only that new conversation.
//! The recipient verifies a signed, two-person bootstrap before importing it.
use super::*;
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PersonalDraft {
    stream: StreamId,
    bundle: Option<Bundle>,
    contact: Option<Packet>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingDirect {
    pub(super) packet: Packet,
    pub(super) dismissed: bool,
}

impl ClientApp {
    pub(super) async fn open_contact(&mut self, v: Value, mut state: Invitations) -> Result<Value> {
        let person: IdentityId = field(&v, "identity")?.parse()?;
        let own = self.session.identity_id();
        if person == own {
            return Err("Choose another person.".into());
        }
        let name = field(&v, "name")?.trim();
        if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
            return Err("Invalid name.".into());
        }
        // Do not reopen a removed membership, match a group DM, or silently
        // alter an existing conversation's permissions/devices.
        for (index, (pin, authority)) in self.pins.iter().zip(&self.authorities.0).enumerate() {
            let head = authority.head()?;
            if head.chat_kind.or(pin.chat_kind) == Some(ChatKind::Direct)
                && self.authorities.space_ready(authority)
                && head.members.len() == 2
                && head.members.iter().any(|m| m.identity_id == person)
                && head.members.iter().any(|m| {
                    m.identity_id == own
                        && m.credential_ids.contains(&self.session.credential().id())
                        && m.capabilities.contains(&Capability::Read)
                })
            {
                // An interrupted local creation may still need its envelopes.
                if !state
                    .personal
                    .get(&person.to_string())
                    .is_some_and(|d| d.stream == pin.stream)
                {
                    let stream = pin.stream;
                    self.pins[index].name = name.into();
                    self.persist_workspace()?;
                    return Ok(json!({"stream":stream,"view":self.view().await?}));
                }
            }
        }
        let known = self.known_people()?;
        let credentials = known
            .get(&person)
            .ok_or("Add this person's contact code first.")?;
        if credentials.len() > 15 {
            return Err("This person has too many devices for this DM.".into());
        }
        let key = person.to_string();
        let mut draft = match state.personal.get(&key) {
            Some(draft) => draft.clone(),
            None => {
                if state.personal.len() >= MAX_ITEMS {
                    return Err("Chat limit reached.".into());
                }
                // Reuse an unfinished legacy one-person invitation, preserving
                // its stream/history rather than leaving a duplicate behind.
                let legacy = state.direct.values().find(|d| {
                    d.single_person(person)
                        && self.authorities.0.iter().any(|a| {
                            a.stream() == d.stream() && a.head().is_ok_and(|h| h.members.len() == 1)
                        })
                });
                let hash = Sha256::digest(
                    [
                        b"elo.now/contact-dm/v1\0".as_slice(),
                        own.as_bytes(),
                        person.as_bytes(),
                    ]
                    .concat(),
                );
                let draft = PersonalDraft {
                    stream: legacy
                        .map(|d| d.stream())
                        .unwrap_or(StreamId::from_bytes(hash[..16].try_into()?)),
                    bundle: None,
                    contact: None,
                };
                state.personal.insert(key.clone(), draft.clone());
                self.save_invitations(&state)?;
                draft
            }
        };
        if !self.pins.iter().any(|pin| pin.stream == draft.stream) {
            self.create_chat_at(name, None, ChatKind::Direct, Some(draft.stream))
                .await?;
        }
        let index = self
            .pins
            .iter()
            .position(|p| p.stream == draft.stream)
            .ok_or("DM not found.")?;
        if self.pins[index].name != name {
            self.pins[index].name = name.into();
            self.persist_workspace()?;
        }
        self.require_controller(&self.authorities.0[index])?;
        if draft.bundle.is_none() {
            let head = self.authorities.0[index].head()?;
            if head.members.len() != 1 || head.sequence != 1 {
                return Err("This DM requires a membership review.".into());
            }
            let mut bundle = self.offer_bundle(
                index,
                &json!({"post":true,"reusable":false}),
                36_525 * 86_400_000,
            )?;
            let mut offer: shared::Offer = decode_record(&bundle.invitation)?.decode()?;
            offer.invitees = vec![person];
            bundle.invitation = STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&offer)?, self.session.signing_key())?
                    .bytes(),
            );
            let c = self.session.credential();
            let sender_name = self
                .profile_details
                .as_ref()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| own.to_string()[..8].into());
            let card = shared::contact(
                c,
                self.session.signing_key(),
                &sender_name,
                offer.expires_at,
            )?;
            let card = self.attach_wake(&card, &state)?;
            draft.contact = Some(Packet::Contact {
                card: STANDARD.encode(card.bytes()),
                credential: STANDARD.encode(c.record().bytes()),
            });
            draft.bundle = Some(bundle);
            state.personal.insert(key.clone(), draft.clone());
            self.save_invitations(&state)?;
        }
        let bundle = draft.bundle.as_ref().ok_or("Missing DM proof.")?;
        let (proof, offer, _) = verify_bundle(bundle, 0)?;
        let authority = &mut self.authorities.0[index];
        if authority.head()?.members.len() == 1 {
            if authority.head_id() != Some(offer.base_config_id) {
                return Err("This DM has changed. Review its membership first.".into());
            }
            let mut config = authority.head()?.clone();
            for credential in credentials.values() {
                authority.add_credential(credential.clone());
            }
            config.members.push(Member {
                identity_id: person,
                identity_type: "HUMAN".into(),
                root_public_key: credentials
                    .values()
                    .next()
                    .ok_or("Missing contact.")?
                    .record()
                    .body()["root_public_key"]
                    .as_str()
                    .ok_or("Invalid contact.")?
                    .into(),
                capabilities: vec![Capability::Read, Capability::Post],
                credential_ids: credentials.keys().copied().collect(),
                external: true,
            });
            config.members.sort_by_key(|m| m.identity_id);
            config.sequence += 1;
            config.previous_config_id = authority.head_id();
            config.nonce = record::random_hex::<16>()?;
            config.action = ConfigAction {
                operation: "invite.approved".into(),
                actor_identity: own,
                request_record_id: Some(proof.id()),
            };
            authority
                .commit_update(
                    &self.store,
                    config.sign(self.session.signing_key())?,
                    self.session.age_identity(),
                    now()?,
                )
                .await?;
        }
        if !authority
            .head()?
            .members
            .iter()
            .any(|m| m.identity_id == person)
            || !authority.head()?.members.iter().any(|m| {
                m.identity_id == own && m.credential_ids.contains(&self.session.credential().id())
            })
        {
            return Err("This DM is no longer available. Review its membership first.".into());
        }
        if authority.head()?.sequence != 2 || !authority.has_membership_approval(proof.id()) {
            // Never replay an initial bootstrap after membership/recovery changes.
            return Ok(json!({"stream":draft.stream,"view":self.view().await?}));
        }
        let targets = self
            .session
            .peers()
            .iter()
            .filter(|p| p.write_token.is_some())
            .cloned()
            .collect::<Vec<_>>();
        let mut packets = Vec::new();
        for id in &authority
            .head()?
            .members
            .iter()
            .find(|m| m.identity_id == person)
            .ok_or("Missing recipient.")?
            .credential_ids
        {
            let recipient = authority.credential(*id)?.recipient();
            packets.push((
                *id,
                recipient.clone(),
                Packet::Direct {
                    bundle: bundle.clone(),
                    contact: Box::new(draft.contact.clone().ok_or("Missing sender proof.")?),
                    ciphertext: STANDARD.encode(authority.seal_snapshot(&recipient)?),
                },
            ));
        }
        for peer in targets {
            for (credential, recipient, packet) in &packets {
                let id = format!(
                    "personal:{}:{credential}:{}:{}",
                    proof.id(),
                    peer.signing_public_key,
                    peer.mailbox_id
                );
                self.queue_packet(
                    &mut state,
                    &id,
                    packet,
                    shared::DeliveryAddress {
                        url: peer.url.clone(),
                        signing_public_key: peer.signing_public_key.clone(),
                        mailbox_id: peer.mailbox_id,
                        write_token: peer
                            .write_token
                            .clone()
                            .ok_or("Missing delivery permission.")?,
                        expires_at: offer.expires_at,
                    },
                    recipient,
                )?;
                state
                    .jobs
                    .get_mut(&id)
                    .ok_or("Missing DM delivery.")?
                    .discovery = true;
            }
        }
        self.save_invitations(&state)?;
        Ok(json!({"stream":draft.stream,"view":self.view().await?}))
    }

    pub(super) fn verify_personal(&self, packet: &Packet) -> Result<(Authority, String, RecordId)> {
        let Packet::Direct {
            bundle,
            contact,
            ciphertext,
        } = packet
        else {
            return Err("Open a DM first.".into());
        };
        let (proof, offer, controller) = verify_bundle(bundle, 0)?;
        let (_, sender, name) = candidate(contact, 0)?;
        let own = self.session.identity_id();
        let a = Authority::open_snapshot(
            &STANDARD.decode(ciphertext)?,
            self.session.age_identity(),
            bundle.space,
            &root_key(&bundle.root)?,
            bundle.stream,
        )?;
        let h = a.head()?;
        let base = a.config(offer.base_config_id)?;
        let genesis: SpaceGenesis = a.genesis().decode()?;
        let member = h
            .members
            .iter()
            .find(|m| m.identity_id == own)
            .ok_or("This DM is for someone else.")?;
        if !matches!(contact.as_ref(), Packet::Contact { .. })
            || sender.id() != controller.id()
            || sender.identity() == own
            || a.controller().id() != controller.id()
            || a.initial_controller().id() != controller.id()
            || a.is_forked()
            || a.recovery_id().is_some()
            || !bundle.recovery.is_empty()
            || genesis.owners.len() != 1
            || genesis.owners[0].identity_id != sender.identity()
            || genesis.owners[0].root_public_key != bundle.root
            || offer.invitees != vec![own]
            || offer.reusable
            || offer.delivery.is_some()
            || offer.capabilities != vec![Capability::Read, Capability::Post]
            || base.sequence != 1
            || base.members.len() != 1
            || base.members[0].identity_id != sender.identity()
            || base.chat_kind != Some(ChatKind::Direct)
            || h.chat_kind != Some(ChatKind::Direct)
            || h.sequence != 2
            || h.previous_config_id != Some(offer.base_config_id)
            || h.action.operation != "invite.approved"
            || h.action.request_record_id != Some(proof.id())
            || h.members.len() != 2
            || h.owner_credential_ids != base.owner_credential_ids
            || h.members
                .iter()
                .find(|m| m.identity_id == sender.identity())
                .map(serde_json::to_value)
                .transpose()?
                != Some(serde_json::to_value(&base.members[0])?)
            || member.identity_type != "HUMAN"
            || member.capabilities != vec![Capability::Read, Capability::Post]
            || !member
                .credential_ids
                .contains(&self.session.credential().id())
            || self
                .pins
                .iter()
                .any(|p| p.space == bundle.space && p.root != bundle.root)
        {
            return Err("This DM does not match its signed two-person configuration.".into());
        }
        Ok((a, name, proof.id()))
    }

    pub(super) fn personal_preview(&self, packet: &Packet) -> Result<Value> {
        if matches!(packet, Packet::Members { .. }) {
            return self.membership_preview(packet);
        }
        let (a, name, id) = self.verify_personal(packet)?;
        Ok(
            json!({"kind":"grant","id":id,"name":name,"identity":a.controller().identity(),"space":a.space(),"stream":a.stream(),"capabilities":["READ","POST"]}),
        )
    }

    pub(super) async fn import_personal(&mut self, packet: &Packet) -> Result<()> {
        if matches!(packet, Packet::Members { .. }) {
            return self.import_membership(packet).await;
        }
        let (a, name, _) = self.verify_personal(packet)?;
        // A replay never restores a removed member or replaces a later head.
        if self
            .pins
            .iter()
            .any(|p| p.space == a.space() && p.stream == a.stream())
        {
            return Ok(());
        }
        let Packet::Direct { bundle, .. } = packet else {
            unreachable!()
        };
        let a = a
            .merge_into_store(None, &self.store, self.session.age_identity(), now()?)
            .await?;
        self.pins.push(Pin {
            chat_kind: Some(ChatKind::Direct),
            name,
            space: a.space(),
            stream: a.stream(),
            root: bundle.root.clone(),
            group: None,
            created_at: now()?.as_millis(),
        });
        self.authorities.0.push(a);
        self.persist_workspace()?;
        Ok(())
    }

    pub(super) async fn receive_personal(
        &mut self,
        packet: Packet,
        state: &mut Invitations,
    ) -> Result<bool> {
        let (authority, _, proof) = self.verify_personal(&packet)?;
        let key = proof.to_string();
        if self
            .pins
            .iter()
            .any(|p| p.space == authority.space() && p.stream == authority.stream())
            || state.pending_direct.contains_key(&key)
        {
            return Ok(false);
        }
        if self
            .known_people()?
            .get(&authority.controller().identity())
            .is_some_and(|cs| cs.contains_key(&authority.controller().id()))
        {
            self.import_personal(&packet).await?;
        } else {
            // A stranger can request a DM but cannot silently add a conversation.
            if state.pending_direct.len() >= MAX_ITEMS {
                return Err("There are too many pending DMs.".into());
            }
            state.pending_direct.insert(
                key,
                PendingDirect {
                    packet,
                    dismissed: false,
                },
            );
            self.save_invitations(state)?;
        }
        Ok(true)
    }

    pub(super) fn personal_activity(&self, state: &Invitations) -> Result<Vec<Value>> {
        let mut entries = Vec::new();
        for (id, pending) in &state.pending_direct {
            if pending.dismissed {
                continue;
            }
            let preview = self.personal_preview(&pending.packet)?;
            if self
                .pins
                .iter()
                .any(|p| json!(p.stream) == preview["stream"])
            {
                continue;
            }
            entries.push(json!({"id":id,"name":preview["name"],"identity":preview["identity"],"link":encode(&pending.packet)?}));
        }
        Ok(entries)
    }
}

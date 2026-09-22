//! Explicit additions from known contacts, with private, signed configuration delivery.
use super::*;
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Addition {
    space: SpaceId,
    stream: StreamId,
    people: Vec<IdentityId>,
    proof: RecordId,
    base: RecordId,
    snapshot: Option<String>,
    jobs: BTreeMap<String, delivery::Job>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Creation {
    stream: StreamId,
    name: String,
    kind: ChatKind,
    group: Option<String>,
    people: Vec<IdentityId>,
}

fn selection(v: &Value, own: IdentityId) -> Result<Vec<IdentityId>> {
    let mut people: Vec<IdentityId> = serde_json::from_value(v["people"].clone())?;
    people.sort();
    if people.is_empty()
        || people.len() >= record::MAX_CHAT_MEMBERS
        || people.contains(&own)
        || people.windows(2).any(|p| p[0] == p[1])
    {
        return Err("Choose between 1 and 999 different contacts.".into());
    }
    Ok(people)
}

pub(super) fn only_additions(
    previous: &StreamConfig,
    next: &StreamConfig,
) -> Result<Vec<IdentityId>> {
    if next.sequence != previous.sequence + 1
        || next.action.operation != "invite.approved"
        || next.action.request_record_id.is_none()
        || next.owner_credential_ids != previous.owner_credential_ids
        || next.controller_credential_id != previous.controller_credential_id
        || next.chat_kind != previous.chat_kind
        || next.recovery.is_some()
        || next.members.len() <= previous.members.len()
    {
        return Err("This update requires a separate membership review.".into());
    }
    for old in &previous.members {
        if !next.members.contains(old) {
            return Err("This update changes an existing member.".into());
        }
    }
    let mut added = Vec::new();
    for member in &next.members {
        if previous
            .members
            .iter()
            .any(|m| m.identity_id == member.identity_id)
        {
            continue;
        }
        if member.identity_type != "HUMAN"
            || member.capabilities != vec![Capability::Read, Capability::Post]
        {
            return Err("New contacts may only read and post.".into());
        }
        added.push(member.identity_id);
    }
    Ok(added)
}

impl ClientApp {
    pub(super) fn resume_committed_additions(&self, state: &mut Invitations) -> Result<()> {
        let mut changed = false;
        for draft in state.additions.values_mut() {
            if draft.snapshot.is_none() {
                continue;
            }
            let Some(current) = self
                .authorities
                .0
                .iter()
                .find(|a| a.space() == draft.space && a.stream() == draft.stream)
            else {
                continue;
            };
            // A restart may interrupt the gap between the authority commit and
            // activating its durable deliveries. Never commit a draft here or
            // send an obsolete snapshot after another membership change.
            if self.require_controller(current).is_err()
                || current.is_forked()
                || current.recovery_id().is_some()
                || !current.has_membership_approval(draft.proof)
                || current.head()?.action.request_record_id != Some(draft.proof)
                || current.head()?.previous_config_id != Some(draft.base)
            {
                continue;
            }
            let missing = draft
                .jobs
                .keys()
                .filter(|id| !state.jobs.contains_key(*id))
                .count();
            if state.jobs.len() + missing > 2 * MAX_ITEMS {
                continue;
            }
            for (id, job) in std::mem::take(&mut draft.jobs) {
                state.jobs.entry(id).or_insert(job);
            }
            draft.snapshot = None;
            changed = true;
        }
        if changed {
            self.save_invitations(state)?;
        }
        Ok(())
    }

    pub(super) async fn create_contact_chat(
        &mut self,
        v: Value,
        mut state: Invitations,
    ) -> Result<Value> {
        let nonce = record::hex::<16>(field(&v, "request_id")?)?;
        let key = record::encode_hex(&nonce);
        let people = selection(&v, self.session.identity_id())?;
        let name = field(&v, "name")?.trim().to_owned();
        let kind: ChatKind = serde_json::from_value(v["chat_kind"].clone())?;
        let group = self.parse_group(&v)?;
        if name.is_empty()
            || name.len() > 120
            || name.chars().any(char::is_control)
            || (kind == ChatKind::Direct && group.is_some())
        {
            return Err("Invalid chat name or group.".into());
        }
        let known = self.known_people()?;
        if !self.session.peers().iter().any(|p| p.write_token.is_some()) {
            return Err("This Space has no messaging connection.".into());
        }
        if people.iter().any(|p| !known.contains_key(p)) {
            return Err("Add this person's contact code first.".into());
        }
        if people.iter().map(|p| known[p].len()).sum::<usize>() + 1 > record::MAX_CHAT_CREDENTIALS {
            return Err("There are too many devices for this chat.".into());
        }
        let hash = Sha256::digest(
            [
                b"elo.now/contact-chat/v1\0".as_slice(),
                self.session.identity_id().as_bytes(),
                &nonce,
            ]
            .concat(),
        );
        let stream = StreamId::from_bytes(hash[..16].try_into()?);
        if let Some(saved) = state.contact_chats.get(&key) {
            if saved.name != name
                || saved.kind != kind
                || saved.group != group
                || saved.people != people
            {
                return Err("This chat creation has changed. Start a new one.".into());
            }
        } else {
            if state.contact_chats.len() >= MAX_ITEMS {
                return Err("Chat limit reached.".into());
            }
            state.contact_chats.insert(
                key,
                Creation {
                    stream,
                    name: name.clone(),
                    kind,
                    group: group.clone(),
                    people,
                },
            );
            self.save_invitations(&state)?;
        }
        if !self.pins.iter().any(|p| p.stream == stream) {
            self.create_chat_at(&name, group.as_deref(), kind, Some(stream))
                .await?;
        }
        let pin = self
            .pins
            .iter()
            .find(|p| p.stream == stream)
            .ok_or("Chat not found.")?;
        let mut request = v;
        request["space"] = json!(pin.space);
        request["stream"] = json!(stream);
        self.add_contact_members(request, state).await
    }

    pub(super) async fn add_contact_members(
        &mut self,
        v: Value,
        mut state: Invitations,
    ) -> Result<Value> {
        let key = record::encode_hex(&record::hex::<16>(field(&v, "request_id")?)?);
        let people = selection(&v, self.session.identity_id())?;
        let index = self.authority_index(&v)?;
        self.require_controller(&self.authorities.0[index])?;
        if !self.session.peers().iter().any(|p| p.write_token.is_some()) {
            return Err("This Space has no messaging connection.".into());
        }
        let pin = &self.pins[index];
        let (space, stream) = (pin.space, pin.stream);
        if self.authorities.0[index].recovery_id().is_some() {
            return Err("This recovered chat requires a membership review.".into());
        }
        if let Some(saved) = state.additions.get(&key) {
            if saved.space != space || saved.stream != stream || saved.people != people {
                return Err("This selection has changed. Start a new one.".into());
            }
        } else {
            if state.additions.len() >= MAX_ITEMS {
                return Err("Too many saved membership changes.".into());
            }
            self.ensure_chat_kind(index).await?;
            let known = self.known_people()?;
            let original = &self.authorities.0[index];
            let mut next = original.clone();
            let mut config = original.head()?.clone();
            if config.members.len() + people.len() > record::MAX_CHAT_MEMBERS {
                return Err("A chat can have up to 1000 people.".into());
            }
            for person in &people {
                if config.members.iter().any(|m| m.identity_id == *person) {
                    return Err("This person is already in the chat.".into());
                }
                let credentials = known
                    .get(person)
                    .ok_or("Add this person's contact code first.")?;
                for credential in credentials.values() {
                    next.add_credential(credential.clone());
                }
                config.members.push(Member {
                    identity_id: *person,
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
            }
            config.members.sort_by_key(|m| m.identity_id);
            if config
                .members
                .iter()
                .map(|m| m.credential_ids.len())
                .sum::<usize>()
                > record::MAX_CHAT_CREDENTIALS
            {
                return Err("There are too many devices for this chat.".into());
            }
            let mut bundle = self.offer_bundle(
                index,
                &json!({"post":true,"reusable":false}),
                36_525 * 86_400_000,
            )?;
            let mut offer: shared::Offer = decode_record(&bundle.invitation)?.decode()?;
            offer.invitees = people.clone();
            let proof =
                SignedRecord::sign(&serde_json::to_vec(&offer)?, self.session.signing_key())?;
            bundle.invitation = STANDARD.encode(proof.bytes());
            let base = original.head_id().ok_or("Missing configuration.")?;
            config.sequence += 1;
            config.previous_config_id = Some(base);
            config.nonce = record::random_hex::<16>()?;
            config.action = ConfigAction {
                operation: "invite.approved".into(),
                actor_identity: self.session.identity_id(),
                request_record_id: Some(proof.id()),
            };
            next.apply_config(config.sign(self.session.signing_key())?)?;
            let mut prepared = Invitations::default();
            for peer in self
                .session
                .peers()
                .iter()
                .filter(|p| p.write_token.is_some())
            {
                for credential in next.head()?.members.iter().flat_map(|m| &m.credential_ids) {
                    if *credential == self.session.credential().id() {
                        continue;
                    }
                    let recipient = next.credential(*credential)?.recipient();
                    let packet = Packet::Members {
                        bundle: bundle.clone(),
                        ciphertext: STANDARD.encode(next.seal_snapshot(&recipient)?),
                    };
                    let id = format!(
                        "members:{}:{credential}:{}:{}",
                        proof.id(),
                        peer.signing_public_key,
                        peer.mailbox_id
                    );
                    self.queue_packet(
                        &mut prepared,
                        &id,
                        &packet,
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
                        &recipient,
                    )?;
                    prepared
                        .jobs
                        .get_mut(&id)
                        .ok_or("Missing membership delivery.")?
                        .discovery = true;
                }
            }
            if state.jobs.len() + prepared.jobs.len() > 2 * MAX_ITEMS {
                return Err(
                    "There are too many pending deliveries. Try again after syncing.".into(),
                );
            }
            state.additions.insert(
                key.clone(),
                Addition {
                    space,
                    stream,
                    people: people.clone(),
                    proof: proof.id(),
                    base,
                    snapshot: Some(
                        STANDARD
                            .encode(next.seal_snapshot(&self.session.age_identity().to_public())?),
                    ),
                    jobs: prepared.jobs,
                },
            );
            // Persist the retry intent before changing authority. Uncommitted jobs
            // remain inside the draft and are never sent by the foreground worker.
            self.save_invitations(&state)?;
        }
        let draft = state
            .additions
            .get(&key)
            .ok_or("Missing membership change.")?
            .clone();
        let mut current = self.authorities.0[index].clone();
        if current.has_membership_approval(draft.proof) {
            if people.iter().any(|p| {
                !current
                    .head()
                    .is_ok_and(|h| h.members.iter().any(|m| m.identity_id == *p))
            }) {
                return Err("A selected person was removed. Start a new addition.".into());
            }
        } else {
            if current.head_id() != Some(draft.base) {
                return Err("The chat changed. Review its members before trying again.".into());
            }
            let next = Authority::open_snapshot(
                &STANDARD.decode(draft.snapshot.as_ref().ok_or("Missing membership proof.")?)?,
                self.session.age_identity(),
                space,
                &root_key(&self.pins[index].root)?,
                stream,
            )?;
            for id in next.head()?.members.iter().flat_map(|m| &m.credential_ids) {
                current.add_credential(next.credential(*id)?.clone());
            }
            Box::pin(self.publish_call_update(
                &current,
                next.config_record(next.head_id().ok_or("Missing configuration.")?)?,
            ))
            .await?;
            current
                .commit_update(
                    &self.store,
                    next.config_record(next.head_id().ok_or("Missing configuration.")?)?
                        .clone(),
                    self.session.age_identity(),
                    now()?,
                )
                .await?;
        }
        self.authorities.0[index] = current;
        self.resume_committed_additions(&mut state)?;
        Ok(json!({"stream":stream,"view":self.view().await?}))
    }

    pub(super) fn verified_membership(
        &self,
        packet: &Packet,
    ) -> Result<(Authority, shared::Offer, RecordId)> {
        let Packet::Members { bundle, ciphertext } = packet else {
            return Err("Invalid membership update.".into());
        };
        let (proof, offer, controller) = verify_bundle(bundle, 0)?;
        let a = Authority::open_snapshot(
            &STANDARD.decode(ciphertext)?,
            self.session.age_identity(),
            bundle.space,
            &root_key(&bundle.root)?,
            bundle.stream,
        )?;
        let h = a.head()?;
        let base = a.config(offer.base_config_id)?;
        if a.is_forked()
            || a.recovery_id().is_some()
            || !bundle.recovery.is_empty()
            || a.controller().id() != controller.id()
            || a.initial_controller().id() != controller.id()
            || offer.delivery.is_some()
            || offer.reusable
            || offer.capabilities != vec![Capability::Read, Capability::Post]
            || h.previous_config_id != Some(offer.base_config_id)
            || h.action.request_record_id != Some(proof.id())
            || only_additions(base, h)? != offer.invitees
            || !h.members.iter().any(|m| {
                m.identity_id == self.session.identity_id()
                    && m.credential_ids.contains(&self.session.credential().id())
                    && m.capabilities.contains(&Capability::Read)
            })
            || self
                .pins
                .iter()
                .any(|p| p.space == bundle.space && p.root != bundle.root)
        {
            return Err("This membership update does not match its signed selection.".into());
        }
        if let Some(old) = self
            .authorities
            .0
            .iter()
            .find(|old| old.space() == a.space() && old.stream() == a.stream())
        {
            if !self.authorities.space_ready(old)
                || old.controller().id() != controller.id()
                || old.recovery_id().is_some()
                || !old.head()?.members.iter().any(|m| {
                    m.identity_id == self.session.identity_id()
                        && m.credential_ids.contains(&self.session.credential().id())
                        && m.capabilities.contains(&Capability::Read)
                })
            {
                return Err("This chat requires a membership review.".into());
            }
            let current = old.head_id().ok_or("Missing configuration.")?;
            let incoming = a.head_id().ok_or("Missing configuration.")?;
            if old.config(incoming).is_err() {
                let mut cursor = incoming;
                while cursor != current {
                    let config = a.config(cursor)?;
                    let parent = config
                        .previous_config_id
                        .ok_or("Unrelated membership update.")?;
                    removal::membership_step(a.config(parent)?, config)?;
                    cursor = parent;
                }
            }
        } else if !offer.invitees.contains(&self.session.identity_id()) {
            return Err("This addition is for someone else.".into());
        }
        Ok((a, offer, proof.id()))
    }

    pub(super) fn membership_preview(&self, packet: &Packet) -> Result<Value> {
        let (a, offer, id) = self.verified_membership(packet)?;
        Ok(
            json!({"kind":"grant","id":id,"name":offer.name,"identity":a.controller().identity(),"space":a.space(),"stream":a.stream(),"capabilities":["READ","POST"]}),
        )
    }

    pub(super) async fn import_membership(&mut self, packet: &Packet) -> Result<()> {
        let (a, offer, _) = self.verified_membership(packet)?;
        let index = self
            .pins
            .iter()
            .position(|p| p.space == a.space() && p.stream == a.stream());
        if index.is_none() && self.blocked.contains(a.controller().identity()) {
            return Err("Unblock this user before contacting them.".into());
        }
        let incoming = a
            .merge_into_store(
                index.map(|i| &self.authorities.0[i]),
                &self.store,
                self.session.age_identity(),
                now()?,
            )
            .await?;
        if let Some(index) = index {
            self.authorities.0[index] = incoming;
        } else {
            let Packet::Members { bundle, .. } = packet else {
                unreachable!()
            };
            self.pins.push(Pin {
                chat_kind: incoming.head()?.chat_kind,
                name: offer.name,
                space: incoming.space(),
                stream: incoming.stream(),
                root: bundle.root.clone(),
                group: None,
                created_at: now()?.as_millis(),
            });
            self.authorities.0.push(incoming);
        }
        self.persist_workspace()?;
        Ok(())
    }

    pub(super) async fn receive_membership(
        &mut self,
        packet: Packet,
        state: &mut Invitations,
    ) -> Result<bool> {
        let (a, _, proof) = self.verified_membership(&packet)?;
        if self.blocked.contains(a.controller().identity())
            && !self
                .pins
                .iter()
                .any(|p| p.space == a.space() && p.stream == a.stream())
        {
            return Ok(false);
        }
        // A later contact save or ciphertext replay is not consent to a chat
        // that the recipient has already left pending or dismissed.
        if state.pending_direct.contains_key(&proof.to_string()) {
            return Ok(false);
        }
        if self.authorities.0.iter().any(|old| {
            old.space() == a.space()
                && old.stream() == a.stream()
                && old.config(a.head_id().unwrap()).is_ok()
        }) {
            return Ok(false);
        }
        if self
            .pins
            .iter()
            .any(|p| p.space == a.space() && p.stream == a.stream())
            || self
                .known_people()?
                .get(&a.controller().identity())
                .is_some_and(|cs| cs.contains_key(&a.controller().id()))
        {
            self.import_membership(&packet).await?;
        } else {
            let key = proof.to_string();
            if state.pending_direct.contains_key(&key) {
                return Ok(false);
            }
            if state.pending_direct.len() >= MAX_ITEMS {
                return Err("Too many pending chats.".into());
            }
            state.pending_direct.insert(
                key,
                personal::PendingDirect {
                    packet,
                    dismissed: false,
                },
            );
            self.save_invitations(state)?;
        }
        Ok(true)
    }
}

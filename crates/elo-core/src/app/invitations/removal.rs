//! Signed membership reductions delivered to every previously enrolled device.
use super::*;

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Removal {
    space: SpaceId,
    stream: StreamId,
    person: IdentityId,
    base: RecordId,
    head: RecordId,
    snapshot: Option<String>,
    jobs: BTreeMap<String, delivery::Job>,
}

fn only_removal(previous: &StreamConfig, next: &StreamConfig) -> Result<IdentityId> {
    if next.sequence != previous.sequence + 1
        || next.action.operation != "member.removed"
        || next.action.request_record_id.is_some()
        || next.owner_credential_ids != previous.owner_credential_ids
        || next.controller_credential_id != previous.controller_credential_id
        || next.chat_kind != previous.chat_kind
        || next.recovery.is_some()
        || previous.members.len() != next.members.len() + 1
        || next
            .members
            .iter()
            .any(|member| !previous.members.contains(member))
    {
        return Err("This update requires a separate membership review.".into());
    }
    Ok(previous
        .members
        .iter()
        .find(|member| !next.members.contains(member))
        .ok_or("Missing removed member.")?
        .identity_id)
}

pub(super) fn membership_step(previous: &StreamConfig, next: &StreamConfig) -> Result<()> {
    if next.action.operation == "member.removed" {
        only_removal(previous, next)?;
    } else {
        membership::only_additions(previous, next)?;
    }
    Ok(())
}

impl ClientApp {
    pub(in crate::app) async fn remove_chat_member(&mut self, request: Value) -> Result<Value> {
        let index = self.authority_index(&request)?;
        self.require_controller(&self.authorities.0[index])?;
        let original = &self.authorities.0[index];
        if original.recovery_id().is_some() {
            return Err("This recovered chat requires a membership review.".into());
        }
        let person: IdentityId = field(&request, "fingerprint")?.parse()?;
        let mut state = self.invitation_state()?;
        let base = original.head_id().ok_or("Missing configuration.")?;
        if !original
            .head()?
            .members
            .iter()
            .any(|member| member.identity_id == person)
        {
            if state.removals.values().any(|draft| {
                draft.space == original.space()
                    && draft.stream == original.stream()
                    && draft.person == person
                    && original.config(draft.head).is_ok()
            }) {
                self.resume_committed_removals(&mut state)?;
                return Ok(json!({"view":self.view().await?}));
            }
            return Err("This person is no longer in the conversation.".into());
        }
        if !self
            .session
            .peers()
            .iter()
            .any(|peer| peer.write_token.is_some())
        {
            return Err("Add a sync server before changing members.".into());
        }
        let key = format!("{base}:{person}");
        if !state.removals.contains_key(&key) {
            if state.removals.len() >= MAX_ITEMS {
                return Err("Too many saved membership changes.".into());
            }
            let mut config = original.head()?.clone();
            config.members.retain(|member| member.identity_id != person);
            config.previous_config_id = Some(base);
            config.sequence += 1;
            config.recovery = None;
            config.nonce = record::random_hex::<16>()?;
            config.action = ConfigAction {
                operation: "member.removed".into(),
                actor_identity: self.session.identity_id(),
                request_record_id: None,
            };
            only_removal(original.head()?, &config)?;
            let mut next = original.clone();
            next.apply_config(config.sign(self.session.signing_key())?)?;
            let head = next.head_id().ok_or("Missing configuration.")?;
            let bundle = self.offer_bundle(
                index,
                &json!({"post":true,"reusable":false}),
                36_525 * 86_400_000,
            )?;
            let mut queued = Invitations::default();
            for peer in self
                .session
                .peers()
                .iter()
                .filter(|peer| peer.write_token.is_some())
            {
                // The removed device gets only the signed public membership proof,
                // never a message, vault secret or newly encrypted conversation key.
                for id in original
                    .head()?
                    .members
                    .iter()
                    .flat_map(|member| &member.credential_ids)
                {
                    if *id == self.session.credential().id() {
                        continue;
                    }
                    let recipient = original.credential(*id)?.recipient();
                    let packet = Packet::MembershipChange {
                        bundle: bundle.clone(),
                        ciphertext: STANDARD.encode(next.seal_snapshot(&recipient)?),
                    };
                    let job_id = format!(
                        "removal:{head}:{id}:{}:{}",
                        peer.signing_public_key, peer.mailbox_id
                    );
                    self.queue_packet(
                        &mut queued,
                        &job_id,
                        &packet,
                        shared::DeliveryAddress {
                            url: peer.url.clone(),
                            signing_public_key: peer.signing_public_key.clone(),
                            mailbox_id: peer.mailbox_id,
                            write_token: peer
                                .write_token
                                .clone()
                                .ok_or("Missing delivery permission.")?,
                            expires_at: now()?.as_millis() as u64 + 36_525 * 86_400_000,
                        },
                        &recipient,
                    )?;
                    queued
                        .jobs
                        .get_mut(&job_id)
                        .ok_or("Missing membership delivery.")?
                        .discovery = true;
                }
            }
            if state.jobs.len() + queued.jobs.len() > 2 * MAX_ITEMS {
                return Err(
                    "There are too many pending deliveries. Try again after syncing.".into(),
                );
            }
            state.removals.insert(
                key.clone(),
                Removal {
                    space: original.space(),
                    stream: original.stream(),
                    person,
                    base,
                    head,
                    snapshot: Some(
                        STANDARD
                            .encode(next.seal_snapshot(&self.session.age_identity().to_public())?),
                    ),
                    jobs: queued.jobs,
                },
            );
            // Preserve the exact ciphertext before committing authority. A crash
            // can only leave a private draft or resumable committed deliveries.
            self.save_invitations(&state)?;
        }
        let draft = state
            .removals
            .get(&key)
            .ok_or("Missing membership change.")?;
        let next = Authority::open_snapshot(
            &STANDARD.decode(draft.snapshot.as_ref().ok_or("Missing membership proof.")?)?,
            self.session.age_identity(),
            draft.space,
            &root_key(&self.pins[index].root)?,
            draft.stream,
        )?;
        self.authorities.0[index]
            .commit_update(
                &self.store,
                next.config_record(draft.head)?.clone(),
                self.session.age_identity(),
                now()?,
            )
            .await?;
        self.resume_committed_removals(&mut state)?;
        Ok(json!({"view":self.view().await?}))
    }

    pub(super) fn resume_committed_removals(&self, state: &mut Invitations) -> Result<()> {
        let mut changed = false;
        for draft in state.removals.values_mut() {
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
            // A historical, committed reduction is safe to deliver: receivers
            // merge monotonically. It also informs a removed device that will
            // not be addressed by later membership changes.
            if self.require_controller(current).is_err()
                || current.is_forked()
                || current.recovery_id().is_some()
                || current.config(draft.head).is_err()
            {
                continue;
            }
            if state.jobs.len()
                + draft
                    .jobs
                    .keys()
                    .filter(|id| !state.jobs.contains_key(*id))
                    .count()
                > 2 * MAX_ITEMS
            {
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

    pub(super) fn verify_removal(&self, packet: &Packet) -> Result<Authority> {
        let Packet::MembershipChange { bundle, ciphertext } = packet else {
            return Err("Invalid membership update.".into());
        };
        let (_, offer, controller) = verify_bundle(bundle, 0)?;
        if self
            .pins
            .iter()
            .any(|pin| pin.space == bundle.space && pin.root != bundle.root)
        {
            return Err("Chat identity mismatch.".into());
        }
        let incoming = Authority::open_snapshot(
            &STANDARD.decode(ciphertext)?,
            self.session.age_identity(),
            bundle.space,
            &root_key(&bundle.root)?,
            bundle.stream,
        )?;
        if !bundle.recovery.is_empty()
            || offer.delivery.is_some()
            || offer.reusable
            || controller.id() != incoming.controller().id()
            || incoming.head()?.previous_config_id != Some(offer.base_config_id)
        {
            return Err("This membership update does not match its signed proof.".into());
        }
        if incoming.is_forked()
            || incoming.recovery_id().is_some()
            || incoming.controller().id() != incoming.initial_controller().id()
        {
            return Err("This chat requires a membership review.".into());
        }
        let head = incoming.head()?;
        let parent = head
            .previous_config_id
            .ok_or("Missing membership history.")?;
        only_removal(incoming.config(parent)?, head)?;
        let old = self
            .authorities
            .0
            .iter()
            .find(|a| a.space() == bundle.space && a.stream() == bundle.stream);
        let anchor = if let Some(old) = old {
            if !self.authorities.space_ready(old)
                || old.recovery_id().is_some()
                || old.controller().id() != incoming.controller().id()
            {
                return Err("This chat requires a membership review.".into());
            }
            if old
                .config(incoming.head_id().ok_or("Missing configuration.")?)
                .is_ok()
            {
                return Ok(incoming);
            }
            old.head_id()
        } else {
            // A person may learn about an addition and its removal out of order.
            // A known controller and signed historical enrollment are required;
            // every transition must preserve existing members and restrict new
            // members to Read/Post, just like a contact addition packet.
            if !self
                .known_people()?
                .get(&incoming.controller().identity())
                .is_some_and(|credentials| credentials.contains_key(&incoming.controller().id()))
            {
                return Err("Unknown conversation.".into());
            }
            if head
                .members
                .iter()
                .any(|member| member.identity_id == self.session.identity_id())
                && self
                    .invitation_state()?
                    .pending_direct
                    .values()
                    .any(|entry| match &entry.packet {
                        Packet::Members {
                            bundle: pending, ..
                        }
                        | Packet::Direct {
                            bundle: pending, ..
                        } => pending.space == bundle.space && pending.stream == bundle.stream,
                        _ => false,
                    })
            {
                return Err("Review the pending conversation first.".into());
            }
            None
        };
        let mut cursor = incoming.head_id().ok_or("Missing configuration.")?;
        let mut enrolled = false;
        loop {
            let config = incoming.config(cursor)?;
            enrolled |= config.members.iter().any(|member| {
                member.identity_id == self.session.identity_id()
                    && member
                        .credential_ids
                        .contains(&self.session.credential().id())
                    && member.capabilities.contains(&Capability::Read)
            });
            if Some(cursor) == anchor {
                break;
            }
            let Some(parent) = config.previous_config_id else {
                if anchor.is_some() {
                    return Err("Unrelated membership update.".into());
                }
                break;
            };
            membership_step(incoming.config(parent)?, config)?;
            cursor = parent;
        }
        if !enrolled {
            return Err("This membership update is for another device.".into());
        }
        Ok(incoming)
    }

    pub(super) async fn receive_removal(&mut self, packet: &Packet) -> Result<bool> {
        let incoming = self.verify_removal(packet)?;
        let index = self
            .pins
            .iter()
            .position(|pin| pin.space == incoming.space() && pin.stream == incoming.stream());
        if index.is_some_and(|i| {
            self.authorities.0[i]
                .config(incoming.head_id().unwrap())
                .is_ok()
        }) {
            return Ok(false);
        }
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
            let Packet::MembershipChange { bundle, .. } = packet else {
                unreachable!()
            };
            self.pins.push(Pin {
                name: verify_bundle(bundle, 0)?.1.name,
                space: merged.space(),
                stream: merged.stream(),
                root: bundle.root.clone(),
                chat_kind: merged.head()?.chat_kind,
                group: None,
                created_at: now()?.as_millis(),
            });
            self.authorities.0.push(merged);
        }
        self.persist_workspace()?;
        Ok(true)
    }
}

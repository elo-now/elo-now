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
    if next.action.operation == "device.updated" {
        only_device_update(previous, next)?;
    } else if next.action.operation == "member.removed" {
        only_removal(previous, next)?;
    } else {
        membership::only_additions(previous, next)?;
    }
    Ok(())
}

fn only_device_update(previous: &StreamConfig, next: &StreamConfig) -> Result<()> {
    if next.sequence != previous.sequence + 1
        || next.action.operation != "device.updated"
        || next.action.request_record_id.is_some()
        || next.controller_credential_id != previous.controller_credential_id
        || next.chat_kind != previous.chat_kind
        || next.recovery.is_some()
    {
        return Err("Invalid device membership update.".into());
    }
    let owners: BTreeSet<_> = previous
        .members
        .iter()
        .filter(|m| {
            m.credential_ids
                .iter()
                .any(|id| previous.owner_credential_ids.contains(id))
        })
        .map(|m| m.identity_id)
        .collect();
    let expected: BTreeSet<_> = next
        .members
        .iter()
        .filter(|m| owners.contains(&m.identity_id))
        .flat_map(|m| m.credential_ids.iter().copied())
        .collect();
    if next.owner_credential_ids != expected.into_iter().collect::<Vec<_>>() {
        return Err("A device update cannot change permissions.".into());
    }
    for member in &next.members {
        let old = previous
            .members
            .iter()
            .find(|m| m.identity_id == member.identity_id)
            .ok_or("A device update cannot add a person.")?;
        let mut allowed = old.clone();
        allowed.credential_ids = member.credential_ids.clone();
        if &allowed != member {
            return Err("A device update cannot change permissions.".into());
        }
    }
    Ok(())
}

impl ClientApp {
    fn device_update_jobs(
        &self,
        next: &Authority,
        bundle: &Bundle,
        prefix: &str,
    ) -> Result<BTreeMap<String, delivery::Job>> {
        let head = next.head_id().ok_or("Missing configuration.")?;
        let mut queued = Invitations::default();
        for peer in self
            .session
            .peers()
            .iter()
            .filter(|peer| peer.write_token.is_some())
        {
            // Deliver the signed membership proof only to current device keys.
            for id in next
                .head()?
                .members
                .iter()
                .flat_map(|member| &member.credential_ids)
            {
                if *id == self.session.credential().id() {
                    continue;
                }
                let recipient = next.credential(*id)?.recipient();
                let packet = Packet::MembershipChange {
                    bundle: bundle.clone(),
                    ciphertext: STANDARD
                        .encode(next.seal_snapshot_signed(&recipient, self.session.signing_key())?),
                };
                let job_id = format!(
                    "{prefix}:{head}:{id}:{}:{}",
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
        Ok(queued.jobs)
    }

    /// Repair presentation metadata already imported by another device. Reuse
    /// the verified membership proof without changing permissions or its head.
    async fn share_personal_seed_metadata(&self, index: usize) -> Result<()> {
        let authority = &self.authorities.0[index];
        if !self.is_personal_seed(&self.pins[index], authority)?
            || self.require_controller(authority).is_err()
            || authority.head()?.action.operation != "device.updated"
        {
            return Ok(());
        }
        let head = authority.head_id().ok_or("Missing configuration.")?;
        let mut state = self.invitation_state()?;
        if state.seed_metadata.get(&authority.stream()) == Some(&head) {
            return Ok(());
        }
        let mut bundle = self.offer_bundle(
            index,
            &json!({"post":true,"reusable":false}),
            36_525 * 86_400_000,
        )?;
        let signed = decode_record(&bundle.invitation)?;
        let mut body = signed.body().clone();
        body["base_config_id"] = json!(authority.head()?.previous_config_id);
        bundle.invitation = STANDARD.encode(
            SignedRecord::sign(&serde_json::to_vec(&body)?, self.session.signing_key())?.bytes(),
        );
        let jobs = self.device_update_jobs(authority, &bundle, "seed-metadata")?;
        if jobs.is_empty() {
            return Ok(());
        }
        if state.jobs.len() + jobs.len() > 2 * MAX_ITEMS {
            return Err("There are too many pending deliveries. Try again after syncing.".into());
        }
        state.jobs.extend(jobs);
        state.seed_metadata.insert(authority.stream(), head);
        self.save_invitations(&state)?;
        Ok(())
    }

    /// A hosted Space is the device roster authority; the chat controller keeps
    /// the existing identities and permissions while updating their recipient keys.
    pub(in crate::app) async fn refresh_chat_devices(&mut self) -> Result<()> {
        let Some(address) = &self.call_host else {
            return Ok(());
        };
        let Some(general) = self
            .authorities
            .0
            .iter()
            .find(|a| a.space() == address.scope.space && a.stream() == address.scope.stream)
            .cloned()
        else {
            return Ok(());
        };
        if !self.authorities.space_ready(&general) {
            return Ok(());
        }
        for index in 0..self.authorities.0.len() {
            let original = &self.authorities.0[index];
            if original.space() == general.space() && original.stream() == general.stream()
                || self.require_controller(original).is_err()
                || original.recovery_id().is_some()
            {
                continue;
            }
            let mut config = original.head()?.clone();
            for member in &mut config.members {
                member.credential_ids = general
                    .head()?
                    .members
                    .iter()
                    .find(|m| m.identity_id == member.identity_id)
                    .map(|m| m.credential_ids.clone())
                    .unwrap_or_default();
            }
            config.members.retain(|m| !m.credential_ids.is_empty());
            if config.members == original.head()?.members {
                self.share_personal_seed_metadata(index).await?;
                continue;
            }
            let owners: BTreeSet<_> = original
                .head()?
                .members
                .iter()
                .filter(|m| {
                    m.credential_ids.iter().any(|id| {
                        original
                            .head()
                            .is_ok_and(|c| c.owner_credential_ids.contains(id))
                    })
                })
                .map(|m| m.identity_id)
                .collect();
            config.owner_credential_ids = config
                .members
                .iter()
                .filter(|m| owners.contains(&m.identity_id))
                .flat_map(|m| m.credential_ids.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let ids: BTreeSet<_> = config
                .members
                .iter()
                .flat_map(|m| m.credential_ids.iter().copied())
                .collect();
            if !ids.contains(&config.controller_credential_id)
                || config
                    .owner_credential_ids
                    .iter()
                    .any(|id| !ids.contains(id))
            {
                return Err("Chat controller recovery is required.".into());
            }
            let base = original.head_id().ok_or("Missing configuration.")?;
            let mut state = self.invitation_state()?;
            let key = format!("devices:{base}");
            if !state.removals.contains_key(&key) {
                if state.removals.len() >= MAX_ITEMS {
                    return Err("Too many saved membership changes.".into());
                }
                config.previous_config_id = Some(base);
                config.sequence += 1;
                config.nonce = record::random_hex::<16>()?;
                config.action = ConfigAction {
                    operation: "device.updated".into(),
                    actor_identity: self.identity_id(),
                    request_record_id: None,
                };
                only_device_update(original.head()?, &config)?;
                let mut next = original.clone();
                for member in &config.members {
                    for id in &member.credential_ids {
                        next.add_credential(general.credential(*id)?.clone());
                    }
                }
                next.apply_config(config.sign(self.session.signing_key())?)?;
                let head = next.head_id().ok_or("Missing configuration.")?;
                let bundle = self.offer_bundle(
                    index,
                    &json!({"post":true,"reusable":false}),
                    36_525 * 86_400_000,
                )?;
                let queued_jobs = self.device_update_jobs(&next, &bundle, "devices")?;
                if state.jobs.len() + queued_jobs.len() > 2 * MAX_ITEMS {
                    return Err(
                        "There are too many pending deliveries. Try again after syncing.".into(),
                    );
                }
                if !queued_jobs.is_empty() && self.is_personal_seed(&self.pins[index], original)? {
                    state.seed_metadata.insert(original.stream(), head);
                }
                state.removals.insert(
                    key.clone(),
                    Removal {
                        space: original.space(),
                        stream: original.stream(),
                        person: self.identity_id(),
                        base,
                        head,
                        snapshot: Some(STANDARD.encode(next.seal_snapshot_signed(
                            &self.session.age_identity().to_public(),
                            self.session.signing_key(),
                        )?)),
                        jobs: queued_jobs,
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
            let mut updated = self.authorities.0[index].clone();
            for member in &next.head()?.members {
                for id in &member.credential_ids {
                    updated.add_credential(next.credential(*id)?.clone());
                }
            }
            Box::pin(self.publish_call_update(&updated, next.config_record(draft.head)?)).await?;
            updated
                .commit_update(
                    &self.store,
                    next.config_record(draft.head)?.clone(),
                    self.session.age_identity(),
                    now()?,
                )
                .await?;
            self.authorities.0[index] = updated;
            self.resume_committed_removals(&mut state)?;
            self.share_personal_seed_metadata(index).await?;
        }
        Ok(())
    }

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
            return Err("This Space has no messaging connection.".into());
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
                        ciphertext: STANDARD.encode(
                            next.seal_snapshot_signed(&recipient, self.session.signing_key())?,
                        ),
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
                    snapshot: Some(STANDARD.encode(next.seal_snapshot_signed(
                        &self.session.age_identity().to_public(),
                        self.session.signing_key(),
                    )?)),
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
        Box::pin(
            self.publish_call_update(&self.authorities.0[index], next.config_record(draft.head)?),
        )
        .await?;
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
        if !matches!(
            head.action.operation.as_str(),
            "member.removed" | "device.updated"
        ) {
            return Err("Invalid membership update.".into());
        }
        membership_step(incoming.config(parent)?, head)?;
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
            let own_registered_controller = incoming.controller().identity() == self.identity_id()
                && self.call_host.as_ref().is_some_and(|address| {
                    self.authorities.0.iter().any(|general| {
                        general.space() == address.scope.space
                            && general.stream() == address.scope.stream
                            && self.authorities.space_ready(general)
                            && general.head().is_ok_and(|head| {
                                head.members.iter().any(|member| {
                                    member.identity_id == self.identity_id()
                                        && member
                                            .credential_ids
                                            .contains(&incoming.controller().id())
                                })
                            })
                    })
                });
            if !own_registered_controller
                && !self
                    .known_people()?
                    .get(&incoming.controller().identity())
                    .is_some_and(|credentials| {
                        credentials.contains_key(&incoming.controller().id())
                    })
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
        let Packet::MembershipChange { bundle, .. } = packet else {
            unreachable!()
        };
        let offer = verify_bundle(bundle, 0)?.1;
        // The controller's signed hint can hide only an empty setup stream of
        // this same profile. Never infer this from a display name alone.
        let personal_seed = offer.personal_seed == Some(true)
            && offer.name == "General"
            && incoming.controller().identity() == self.identity_id()
            && incoming.genesis().decode::<SpaceGenesis>()?.owners.len() == 1
            && incoming.head()?.members.len() == 1;
        let index = self
            .pins
            .iter()
            .position(|pin| pin.space == incoming.space() && pin.stream == incoming.stream());
        if index.is_some_and(|i| {
            self.authorities.0[i]
                .config(incoming.head_id().unwrap())
                .is_ok()
        }) {
            let i = index.unwrap();
            if personal_seed && self.pins[i].personal_seed != Some(true) {
                self.pins[i].personal_seed = Some(true);
                self.persist_workspace()?;
                return Ok(true);
            }
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
            if personal_seed {
                self.pins[index].personal_seed = Some(true);
            }
        } else {
            self.pins.push(Pin {
                personal_seed: Some(personal_seed),
                name: offer.name,
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

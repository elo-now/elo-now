//! Invitations to people already known through verified, current memberships.
//! Discovery uses existing configured mailboxes; access still requires the normal
//! signed request, controller review and explicit Join. No public directory exists.
use super::*;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Draft {
    people: Vec<IdentityId>,
    name: String,
    stream: StreamId,
    offer: Option<String>,
    #[serde(default = "direct_kind")]
    kind: ChatKind,
    #[serde(default)]
    group: Option<String>,
}

impl Draft {
    pub(super) fn stream(&self) -> StreamId {
        self.stream
    }
    pub(super) fn single_person(&self, person: IdentityId) -> bool {
        self.kind == ChatKind::Direct && self.people == vec![person]
    }
}

fn direct_kind() -> ChatKind {
    ChatKind::Direct
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceivedOffer {
    bundle: Bundle,
    pub(super) dismissed: bool,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    after: u64,
    generation: Option<String>,
    next: u64,
    failures: u8,
}

#[derive(Default)]
pub(super) struct DiscoveryReport {
    pub received: usize,
    pub retry: usize,
    pub more: bool,
}

async fn discovery_request<T>(
    deadline: tokio::time::Instant,
    request: impl std::future::Future<Output = std::result::Result<T, crate::sync::SyncError>>,
) -> Result<Option<T>> {
    match tokio::time::timeout_at(
        deadline.min(tokio::time::Instant::now() + Duration::from_secs(2)),
        request,
    )
    .await
    {
        Ok(result) => Ok(Some(result?)),
        Err(_) if tokio::time::Instant::now() >= deadline => Ok(None),
        Err(error) => Err(error.into()),
    }
}

impl ClientApp {
    pub(in crate::app) fn known_people(
        &self,
    ) -> Result<BTreeMap<IdentityId, BTreeMap<RecordId, VerifiedCredential>>> {
        let mut people = BTreeMap::<IdentityId, BTreeMap<RecordId, VerifiedCredential>>::new();
        for (_, credential, _) in self.saved_contacts()? {
            people
                .entry(credential.identity())
                .or_default()
                .insert(credential.id(), credential);
        }
        for authority in self.authorities.0.iter() {
            let head = authority.head()?;
            if !self.authorities.space_ready(authority)
                || !head.members.iter().any(|member| {
                    member.identity_id == self.session.identity_id()
                        && member.capabilities.contains(&Capability::Read)
                        && member
                            .credential_ids
                            .contains(&self.session.credential().id())
                })
            {
                continue;
            }
            for member in &head.members {
                if member.identity_id == self.session.identity_id()
                    || member.identity_type != "HUMAN"
                {
                    continue;
                }
                for id in &member.credential_ids {
                    let credential = authority.credential(*id)?;
                    if credential.identity() == member.identity_id {
                        people
                            .entry(member.identity_id)
                            .or_default()
                            .insert(*id, credential.clone());
                    }
                }
            }
        }
        Ok(people)
    }

    pub(super) async fn create_dm(&mut self, v: Value, mut state: Invitations) -> Result<Value> {
        let kind: ChatKind = v
            .get("chat_kind")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?
            .unwrap_or(ChatKind::Direct);
        let group = v
            .get("group")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if kind == ChatKind::Direct && group.is_some() {
            return Err("DMs do not have a group.".into());
        }
        let nonce = record::hex::<16>(field(&v, "request_id")?)?;
        let request_id = record::encode_hex(&nonce);
        let mut people: Vec<IdentityId> = serde_json::from_value(v["people"].clone())
            .map_err(|_| "Choose people for this DM.")?;
        if people.is_empty()
            || people.len() >= record::MAX_CHAT_MEMBERS
            || people.contains(&self.session.identity_id())
        {
            return Err("Choose between 1 and 999 other people.".into());
        }
        people.sort();
        if people.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("A person can only be selected once.".into());
        }
        let name = field(&v, "name")?.trim();
        if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
            return Err("Invalid DM name.".into());
        }
        if let Some(saved) = state.direct.get(&request_id) {
            if saved.people != people
                || saved.name != name
                || saved.kind != kind
                || saved.group != group
            {
                return Err("This DM creation has changed. Start a new one.".into());
            }
            if saved.offer.is_some() {
                return Ok(json!({"stream":saved.stream,"view":self.view().await?}));
            }
        }
        let known = self.known_people()?;
        let mut recipients = BTreeMap::new();
        for person in &people {
            let credentials = known.get(person).ok_or(
                "This person is no longer available. Add their current contact code first.",
            )?;
            recipients.extend(credentials.iter().map(|(id, c)| (*id, c.clone())));
        }
        // Enforce the shared device-recipient bound before creating an invitation.
        if recipients.len() + 1 > record::MAX_CHAT_CREDENTIALS {
            return Err("There are too many devices for one DM. Choose fewer people.".into());
        }
        let targets = self
            .session
            .peers()
            .iter()
            .filter(|peer| peer.write_token.is_some())
            .count();
        if state.offers.len() >= MAX_ITEMS
            || state.jobs.len() + recipients.len() * targets > 2 * MAX_ITEMS
        {
            return Err(
                "There are too many pending invitations. Finish an earlier one first.".into(),
            );
        }
        let mut draft = match state.direct.get(&request_id) {
            Some(draft) => draft.clone(),
            None => {
                if state.direct.len() >= MAX_ITEMS {
                    return Err("Chat limit reached.".into());
                }
                let mut hash = Sha256::new();
                hash.update(b"elo.now/dm/creation/v1\0");
                hash.update(self.session.identity_id().as_bytes());
                hash.update(nonce);
                let hash = hash.finalize();
                let draft = Draft {
                    people: people.clone(),
                    name: name.into(),
                    stream: StreamId::from_bytes(hash[..16].try_into()?),
                    offer: None,
                    kind,
                    group,
                };
                state.direct.insert(request_id.clone(), draft.clone());
                self.save_invitations(&state)?;
                draft
            }
        };
        if !self.pins.iter().any(|pin| pin.stream == draft.stream) {
            self.create_chat_at(
                &draft.name,
                draft.group.as_deref(),
                draft.kind,
                Some(draft.stream),
            )
            .await?;
        }
        let index = self
            .pins
            .iter()
            .position(|pin| pin.stream == draft.stream)
            .ok_or("DM not found.")?;
        self.require_controller(&self.authorities.0[index])?;
        let mut bundle =
            self.offer_bundle(index, &json!({"post":true,"reusable":true}), 86_400_000)?;
        let mut offer: shared::Offer = decode_record(&bundle.invitation)?.decode()?;
        offer.invitees = people;
        let mailbox = self.offer_inbox(offer.expires_at)?;
        offer.delivery = mailbox.as_ref().map(delivery::Inbox::route);
        let signed = SignedRecord::sign(&serde_json::to_vec(&offer)?, self.session.signing_key())?;
        bundle.invitation = STANDARD.encode(signed.bytes());
        let id = signed.id().to_string();
        let packet = Packet::Invitation {
            bundle: bundle.clone(),
        };
        for peer in self
            .session
            .peers()
            .iter()
            .filter(|p| p.write_token.is_some())
        {
            for (credential, recipient) in &recipients {
                let job_id = format!(
                    "dm:{id}:{credential}:{}:{}",
                    peer.signing_public_key, peer.mailbox_id
                );
                self.queue_packet(
                    &mut state,
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
                        expires_at: offer.expires_at,
                    },
                    &recipient.recipient(),
                )?;
                // Normal message sync retains only the lazy inventory item. The
                // separate discovery cursor fetches and validates this envelope.
                state
                    .jobs
                    .get_mut(&job_id)
                    .ok_or("Missing invitation delivery.")?
                    .discovery = true;
            }
        }
        if let Some(mailbox) = mailbox {
            state.mailboxes.insert(id.clone(), mailbox);
        }
        state.offers.insert(
            id.clone(),
            OfferEntry {
                bundle,
                active: true,
            },
        );
        draft.offer = Some(id);
        state.direct.insert(request_id, draft.clone());
        self.save_invitations(&state)?;
        Ok(json!({"stream":draft.stream,"view":self.view().await?}))
    }

    pub(in crate::app) fn direct_summaries(&self) -> Result<BTreeMap<StreamId, Value>> {
        let state = self.invitation_state()?;
        let mut summaries = BTreeMap::new();
        for draft in state.direct.values() {
            let Some(id) = &draft.offer else { continue };
            let Some(entry) = state.offers.get(id) else {
                continue;
            };
            let Some(authority) = self
                .authorities
                .0
                .iter()
                .find(|a| a.stream() == draft.stream)
            else {
                continue;
            };
            let pending: Vec<_> = draft
                .people
                .iter()
                .filter(|id| {
                    !authority.head().is_ok_and(|head| {
                        head.members.iter().any(|member| member.identity_id == **id)
                    })
                })
                .collect();
            let offer: shared::Offer = decode_record(&entry.bundle.invitation)?.decode()?;
            let prefix = format!("dm:{id}:");
            let jobs: Vec<_> = state
                .jobs
                .iter()
                .filter(|(key, _)| key.starts_with(&prefix))
                .collect();
            summaries.insert(
                draft.stream,
                json!({
                    "people":draft.people,"pending":pending,"active":entry.active,
                    "expires_at":offer.expires_at,"automatic":!jobs.is_empty(),
                    "delivered":!jobs.is_empty() && jobs.iter().all(|(_, job)|job.stored),
                    "link":encode(&Packet::Invitation{bundle:entry.bundle.clone()})?
                }),
            );
        }
        Ok(summaries)
    }

    pub(super) fn discovery_enabled(&self) -> bool {
        self.session.peers().iter().any(|p| p.read_token.is_some())
    }

    pub(super) fn awaiting_invitation_response(&self, state: &Invitations, id: &str) -> bool {
        let Some(packet) = state.outgoing.get(id) else {
            return false;
        };
        let Some(response) = state.responses.get(id) else {
            return true;
        };
        let Packet::Request { bundle, .. } = packet else {
            return false;
        };
        if !matches!(response.packet, Packet::Grant { .. }) {
            return false;
        }
        let Ok((_, offer, _)) = verify_bundle(bundle, 0) else {
            return false;
        };
        if offer.invitees.is_empty() {
            return false;
        }
        !self.authorities.0.iter().any(|a| {
            a.space() == bundle.space
                && a.stream() == bundle.stream
                && a.head().is_ok_and(|head| {
                    offer.invitees.iter().all(|person| {
                        head.members
                            .iter()
                            .any(|member| member.identity_id == *person)
                    })
                })
        })
    }

    pub(super) fn refresh_direct_grants(
        &self,
        state: &mut Invitations,
        index: usize,
    ) -> Result<()> {
        let authority = &self.authorities.0[index];
        let pin = &self.pins[index];
        let mut updates = Vec::new();
        for (id, entry) in &state.incoming {
            if entry.status != "approved"
                || entry.space != pin.space
                || entry.stream != pin.stream
                || entry.grant_head == authority.head_id()
            {
                continue;
            }
            let Packet::Request { bundle, .. } = &entry.packet else {
                continue;
            };
            let (_, offer, _) = verify_bundle(bundle, 0)?;
            if offer.invitees.is_empty()
                || !authority.head()?.members.iter().all(|member| {
                    member.identity_id == authority.controller().identity()
                        || offer.invitees.contains(&member.identity_id)
                })
            {
                continue;
            }
            let (request, credential, _) = candidate(&entry.packet, 0)?;
            if !authority.head()?.members.iter().any(|member| {
                member.identity_id == credential.identity()
                    && member.credential_ids.contains(&credential.id())
            }) {
                continue;
            }
            let packet = Packet::Grant {
                reference: request.id(),
                space: pin.space,
                stream: pin.stream,
                root: pin.root.clone(),
                name: offer.name,
                ciphertext: STANDARD.encode(authority.seal_snapshot(&credential.recipient())?),
            };
            updates.push((id.clone(), entry.packet.clone(), packet));
        }
        for (id, request, response) in updates {
            self.queue_response(state, &id, &request, &response)?;
            let entry = state.incoming.get_mut(&id).ok_or("Request not found.")?;
            entry.grant = Some(encode(&response)?);
            entry.grant_head = authority.head_id();
        }
        Ok(())
    }

    /// Only finish the initially chosen DM membership set. General later changes,
    /// removals, different permissions, credentials and controller recovery still
    /// require the existing explicit configuration-review workflow.
    pub(super) async fn join_selected_dm_update(
        &mut self,
        id: &str,
        packet: &Packet,
        state: &Invitations,
    ) -> Result<bool> {
        let Some(Packet::Request { bundle, .. }) = state.outgoing.get(id) else {
            return Ok(false);
        };
        let (_, offer, _) = verify_bundle(bundle, 0)?;
        if offer.invitees.is_empty() {
            return Ok(false);
        }
        let Packet::Grant {
            space,
            stream,
            root,
            ciphertext,
            reference,
            ..
        } = packet
        else {
            return Ok(false);
        };
        let Some(current) = self
            .authorities
            .0
            .iter()
            .find(|a| a.space() == *space && a.stream() == *stream)
        else {
            return Ok(false);
        };
        let incoming = Authority::open_snapshot(
            &STANDARD.decode(ciphertext)?,
            self.session.age_identity(),
            *space,
            &root_key(root)?,
            *stream,
        )?;
        if !self.authorities.space_ready(current)
            || incoming.is_forked()
            || incoming.controller().id() != current.controller().id()
            || incoming.recovery_id() != current.recovery_id()
            || incoming.head()?.chat_kind != current.head()?.chat_kind
            || incoming.head()?.sequence <= current.head()?.sequence
            || !incoming.head()?.members.iter().all(|member| {
                member.identity_id == incoming.controller().identity()
                    || offer.invitees.contains(&member.identity_id)
            })
        {
            return Ok(false);
        }
        for member in &current.head()?.members {
            let Some(next) = incoming
                .head()?
                .members
                .iter()
                .find(|next| next.identity_id == member.identity_id)
            else {
                return Ok(false);
            };
            if serde_json::to_value(member)? != serde_json::to_value(next)? {
                return Ok(false);
            }
        }
        let mut head = incoming.head_id().ok_or("Missing configuration.")?;
        let previous = current.head_id().ok_or("Missing configuration.")?;
        while head != previous {
            let config = incoming.config(head)?;
            if config.sequence <= current.head()?.sequence
                || config.action.operation != "invite.approved"
            {
                return Ok(false);
            }
            let parent_id = config
                .previous_config_id
                .ok_or("Missing configuration proof.")?;
            let parent = incoming.config(parent_id)?;
            if config.members.len() != parent.members.len() + 1
                || config.owner_credential_ids != parent.owner_credential_ids
                || config.recovery.is_some()
                || !config.members.iter().all(|member| {
                    member.identity_id == incoming.controller().identity()
                        || (offer.invitees.contains(&member.identity_id)
                            && member.identity_type == "HUMAN"
                            && member
                                .capabilities
                                .iter()
                                .all(|cap| offer.capabilities.contains(cap)))
                })
            {
                return Ok(false);
            }
            for member in &parent.members {
                let Some(next) = config
                    .members
                    .iter()
                    .find(|next| next.identity_id == member.identity_id)
                else {
                    return Ok(false);
                };
                if serde_json::to_value(member)? != serde_json::to_value(next)? {
                    return Ok(false);
                }
            }
            head = parent_id;
        }
        self.join_invitation(
            packet.clone(),
            state,
            &json!({"trusted":true,"confirmed_reference":reference}),
        )
        .await?;
        Ok(true)
    }

    pub(super) fn received_offer_activity(&self, state: &Invitations) -> Result<Vec<Value>> {
        let time = now()?.as_millis() as u64;
        let mut entries = self.personal_activity(state)?;
        for (id, entry) in &state.received_offers {
            if self.authorities.0.iter().any(|a| {
                a.space() == entry.bundle.space
                    && a.stream() == entry.bundle.stream
                    && a.head().is_ok_and(|h| {
                        h.members.iter().any(|m| {
                            m.identity_id == self.session.identity_id()
                                && m.credential_ids.contains(&self.session.credential().id())
                        })
                    })
            }) {
                continue;
            }
            if entry.dismissed || state.outgoing.values().any(|packet|
                matches!(packet, Packet::Request{bundle,..} if bundle.invitation == entry.bundle.invitation)) {
                continue;
            }
            let Ok((_, offer, controller)) = verify_bundle(&entry.bundle, time) else {
                continue;
            };
            entries.push(
                json!({"id":id,"name":offer.name,"identity":controller.identity(),
                "link":encode(&Packet::Invitation{bundle:entry.bundle.clone()})?}),
            );
        }
        Ok(entries)
    }

    pub(super) async fn discover_offers(
        &mut self,
        state: &mut Invitations,
        force: bool,
        deadline: tokio::time::Instant,
    ) -> Result<DiscoveryReport> {
        if !self.discovery_enabled() {
            return Ok(DiscoveryReport::default());
        }
        let time = now()?.as_millis() as u64;
        let mut peers = Vec::new();
        for descriptor in self
            .session
            .peers()
            .iter()
            .filter(|p| p.read_token.is_some())
        {
            let peer = Peer::new(descriptor.clone(), self.allow_loopback)?;
            let key = format!("{}:{}", peer.id(), peer.mailbox());
            let cursor = state.discovery.get(&key).cloned().unwrap_or_default();
            if force || cursor.next <= time {
                peers.push((key, peer, cursor));
            }
        }
        peers.sort_by_key(|(_, _, cursor)| cursor.next);
        let mut report = DiscoveryReport {
            more: peers.len() > 2,
            ..DiscoveryReport::default()
        };
        for (key, peer, mut cursor) in peers.into_iter().take(2) {
            if tokio::time::Instant::now() >= deadline {
                report.more = true;
                break;
            }
            // Bound network calls, but finish each local membership transaction.
            // Reaching a batch budget is progress, not a network failure.
            let result = self
                .discover_page(
                    &peer,
                    &mut cursor,
                    state,
                    &mut report,
                    deadline.min(tokio::time::Instant::now() + Duration::from_secs(4)),
                )
                .await;
            if let Ok(more) = result {
                report.more |= more;
                cursor.failures = 0;
                cursor.next = if more { 0 } else { time + 30_000 };
            } else {
                report.retry += 1;
                cursor.failures = cursor.failures.saturating_add(1);
                cursor.next = time + (30_000 * (1u64 << cursor.failures.min(4))).min(300_000);
            }
            state.discovery.insert(key, cursor);
            self.save_invitations(state)?;
        }
        Ok(report)
    }

    async fn discover_page(
        &mut self,
        peer: &Peer,
        cursor: &mut Cursor,
        state: &mut Invitations,
        report: &mut DiscoveryReport,
        deadline: tokio::time::Instant,
    ) -> Result<bool> {
        let Some(mut page) = discovery_request(deadline, peer.inventory(cursor.after)).await?
        else {
            return Ok(true);
        };
        if cursor
            .generation
            .as_ref()
            .is_some_and(|generation| generation != &page.storage_generation)
            || page.head < cursor.after
        {
            cursor.after = 0;
            let Some(restarted) = discovery_request(deadline, peer.inventory(0)).await? else {
                return Ok(true);
            };
            page = restarted;
        }
        cursor.generation = Some(page.storage_generation);
        let mut known = self.known_people()?;
        let own = self.session.identity_id();
        let time = now()?.as_millis() as u64;
        let mut fetched = 0;
        for object in page.entries {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            if object.transfer_hint == crate::replica::TransferHint::Lazy
                && object.size_bytes <= (MAX_PACKET + 64 * 1024) as u64
            {
                if fetched >= 8 {
                    break;
                }
                fetched += 1;
                let Some(bytes) =
                    discovery_request(deadline, peer.get(object.object_id, object.size_bytes))
                        .await?
                else {
                    return Ok(true);
                };
                // Ordinary chat objects and envelopes addressed to other devices
                // are unrelated to this separate discovery cursor.
                let packet = crypto::open_bytes(&bytes, self.session.age_identity(), MAX_PACKET)
                    .ok()
                    .and_then(|plain| {
                        record::strict_json(&Zeroizing::new(plain), MAX_PACKET + 72).ok()
                    })
                    .and_then(|value| serde_json::from_value::<Packet>(value).ok());
                if let Some(packet @ Packet::Team { .. }) = &packet
                    && self.import_team(packet).await.unwrap_or(false)
                {
                    *state = self.invitation_state()?;
                    known = self.known_people()?;
                    report.received += 1;
                }
                if let Some(packet @ Packet::Direct { .. }) = &packet {
                    // Invalid bootstraps must not poison the shared discovery cursor.
                    if self.verify_personal(packet).is_ok()
                        && self.receive_personal(packet.clone(), state).await?
                    {
                        known = self.known_people()?;
                        report.received += 1;
                    }
                }
                if let Some(packet @ Packet::Members { .. }) = &packet {
                    // Invalid envelopes cannot change membership or poison discovery.
                    if self.membership_preview(packet).is_ok()
                        && self.receive_membership(packet.clone(), state).await?
                    {
                        known = self.known_people()?;
                        report.received += 1;
                    }
                }
                if let Some(packet @ Packet::MembershipChange { .. }) = &packet
                    && self.verify_removal(packet).is_ok()
                    && self.receive_removal(packet).await?
                {
                    known = self.known_people()?;
                    report.received += 1;
                }
                if let Some(Packet::Wake { record, credential }) = &packet {
                    // Wake advertisements grant no membership and never create unread activity.
                    // Use membership accepted earlier in this same inventory page.
                    let _ = self.receive_wake_route(record, credential, state, &known);
                }
                if let Some(Packet::Invitation { bundle }) = packet
                    && let Ok((signed, offer, controller)) = verify_bundle(&bundle, time)
                    && offer.invitees.contains(&own)
                    && known
                        .get(&controller.identity())
                        .is_some_and(|credentials| credentials.contains_key(&controller.id()))
                {
                    let id = signed.id().to_string();
                    if !state.received_offers.contains_key(&id) {
                        if state.received_offers.len() >= MAX_ITEMS {
                            return Err("There are too many saved invitations.".into());
                        }
                        state.received_offers.insert(
                            id,
                            ReceivedOffer {
                                bundle,
                                dismissed: false,
                            },
                        );
                        self.save_invitations(state)?;
                        report.received += 1;
                    }
                }
            }
            cursor.after = object.arrival_seq;
        }
        Ok(cursor.after < page.head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discovery_budget_yields_without_treating_it_as_a_connection_failure() {
        let result = discovery_request(
            tokio::time::Instant::now() + Duration::from_millis(2),
            std::future::pending::<std::result::Result<(), crate::sync::SyncError>>(),
        )
        .await
        .unwrap();
        assert!(result.is_none());
        let result = discovery_request(
            tokio::time::Instant::now() + Duration::from_secs(4),
            std::future::ready(Err::<(), _>(crate::sync::SyncError::Network)),
        )
        .await;
        assert!(result.is_err(), "actual connection failures still back off");
    }
}

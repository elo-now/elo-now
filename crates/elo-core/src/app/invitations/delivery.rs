//! Endpoint-driven encrypted exchange over ordinary bounded Replica mailboxes.
use super::*;
use crate::{
    ids::ObjectId,
    replica::{ChildMailbox, MailboxDescriptor, TransferHint},
};
use std::time::Duration;

const MAX_ENVELOPE: usize = MAX_PACKET + 64 * 1024;
const POLL_MS: u64 = 30_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inbox {
    parent: PeerDescriptor,
    child: ChildMailbox,
    ready: bool,
    after: u64,
    generation: Option<String>,
    next: u64,
    failures: u8,
}
impl Inbox {
    fn descriptor(&self) -> PeerDescriptor {
        PeerDescriptor {
            url: self.parent.url.clone(),
            signing_public_key: self.parent.signing_public_key.clone(),
            mailbox_id: self.child.descriptor.mailbox_id,
            read_token: Some(self.child.descriptor.read_token.clone()),
            write_token: Some(self.child.descriptor.write_token.clone()),
        }
    }
    pub(super) fn route(&self) -> shared::DeliveryAddress {
        shared::DeliveryAddress {
            url: self.parent.url.clone(),
            signing_public_key: self.parent.signing_public_key.clone(),
            mailbox_id: self.child.descriptor.mailbox_id,
            write_token: self.child.descriptor.write_token.clone(),
            expires_at: self.child.expires_at,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    #[serde(default)]
    notification: Option<NotificationJob>,
    pub(super) target: shared::DeliveryAddress,
    ciphertext: String,
    pub(super) stored: bool,
    next: u64,
    failures: u8,
    #[serde(default)]
    pub(super) discovery: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationJob {
    recipient: String,
    expires: u64,
    next: u64,
    membership: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResponseEntry {
    pub(super) packet: Packet,
    joined: bool,
    #[serde(default)]
    pub(super) seen: bool,
}
#[derive(Default, Serialize)]
struct Report {
    stored: usize,
    received: usize,
    rejected: usize,
    retry: usize,
    more: bool,
    progressed: bool,
}

fn inbox(parent: PeerDescriptor, expires_at: u64, quota_bytes: u64) -> Result<Inbox> {
    // Do not duplicate a parent's private read capability in the exchange state.
    let parent = PeerDescriptor {
        read_token: None,
        ..parent
    };
    Ok(Inbox {
        parent,
        child: ChildMailbox {
            descriptor: MailboxDescriptor::random()?,
            quota_bytes,
            expires_at,
        },
        ready: false,
        after: 0,
        generation: None,
        next: 0,
        failures: 0,
    })
}
fn retry_at(time: u64, failures: &mut u8) -> u64 {
    *failures = failures.saturating_add(1);
    time + (POLL_MS * (1u64 << (*failures).min(4))).min(300_000)
}
fn packet_bytes(packet: &Packet) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(serde_json::to_vec(packet)?);
    if bytes.len() > MAX_PACKET {
        return Err("This invitation is too large.".into());
    }
    Ok(bytes)
}
impl ClientApp {
    pub(super) fn offer_inbox(&self, expires_at: u64) -> Result<Option<Inbox>> {
        // Long-lived invitations keep working through manual replies. Do not
        // advertise a shorter-lived Replica address or extend its resource limits.
        if expires_at.saturating_sub(now()?.as_millis() as u64)
            > crate::replica::MAX_MAILBOX_LIFETIME_MS - 7 * 86_400_000
        {
            return Ok(None);
        }
        self.session
            .peers()
            .iter()
            .find(|p| p.write_token.is_some())
            .map(|p| inbox(p.clone(), expires_at + 7 * 86_400_000, 8 * 1024 * 1024))
            .transpose()
    }
    pub(super) fn reply_inbox(&self, offer: &shared::Offer) -> Result<Option<Inbox>> {
        offer
            .delivery
            .as_ref()
            .map(|route| {
                Peer::new(route.descriptor(), self.allow_loopback)?.with_identity(&self.session);
                inbox(route.descriptor(), route.expires_at, 2 * 1024 * 1024)
            })
            .transpose()
    }
    pub(super) fn queue_packet(
        &self,
        state: &mut Invitations,
        id: &str,
        packet: &Packet,
        target: shared::DeliveryAddress,
        recipient: &age::x25519::Recipient,
    ) -> Result<()> {
        if state.jobs.contains_key(id) {
            return Ok(());
        }
        Peer::new(target.descriptor(), self.allow_loopback)?.with_identity(&self.session);
        let ciphertext = crypto::seal_bytes(
            &packet_bytes(packet)?,
            std::slice::from_ref(recipient),
            MAX_PACKET,
        )?;
        let ciphertext = crate::erasure::wrap_subjects(
            ciphertext,
            self.session.credential(),
            self.session.signing_key(),
            packet_subjects(packet)?,
        )?;
        state.jobs.insert(
            id.into(),
            Job {
                notification: if matches!(
                    packet,
                    Packet::Direct { .. }
                        | Packet::Invitation { .. }
                        | Packet::Request { .. }
                        | Packet::Grant { .. }
                        | Packet::Declined { .. }
                        | Packet::MembershipChange { .. }
                ) {
                    Some(NotificationJob {
                        recipient: recipient.to_string(),
                        expires: now()?.as_millis() as u64 + 86_400_000,
                        next: 0,
                        membership: matches!(packet, Packet::MembershipChange { .. }),
                    })
                } else {
                    None
                },
                target,
                ciphertext: STANDARD.encode(ciphertext),
                stored: false,
                next: 0,
                failures: 0,
                discovery: false,
            },
        );
        Ok(())
    }
    pub(super) fn queue_response(
        &self,
        state: &mut Invitations,
        id: &str,
        request: &Packet,
        response: &Packet,
    ) -> Result<bool> {
        let (signed, candidate, _) = candidate(request, 0)?;
        if let Packet::Request { bundle, .. } = request {
            let body = shared::verify_request(&signed, &candidate)?;
            let (_, offer, _) = verify_bundle(bundle, 0)?;
            if let Some(target) = body.delivery {
                let original = offer
                    .delivery
                    .ok_or("The request has no delivery invitation.")?;
                if target.url != original.url
                    || target.signing_public_key != original.signing_public_key
                    || target.expires_at > original.expires_at
                {
                    return Err("The reply address does not match the invitation.".into());
                }
                let job_id =
                    if !offer.invitees.is_empty() && matches!(response, Packet::Grant { .. }) {
                        let index = self.incoming_scope(request, &json!({}))?;
                        let prefix = format!("reply:{id}:");
                        let job_id = format!(
                            "{prefix}{}",
                            self.authorities.0[index]
                                .head_id()
                                .ok_or("Missing configuration.")?
                        );
                        // A newer snapshot includes earlier selected-person approvals.
                        // Supersede older work without ever changing ciphertext at an ID.
                        state
                            .jobs
                            .retain(|key, _| !key.starts_with(&prefix) || key == &job_id);
                        job_id
                    } else {
                        format!("reply:{id}")
                    };
                self.queue_packet(state, &job_id, response, target, &candidate.recipient())?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(in crate::app) fn invitation_summary(&self) -> Result<Value> {
        let state = self.invitation_state()?;
        let pending = state
            .incoming
            .values()
            .filter(|e| e.status == "pending")
            .count();
        let received = self.received_offer_activity(&state)?.len();
        let responses = state.responses.values().filter(|e| !e.seen).count() + received;
        let actionable = pending
            + received
            + state
                .responses
                .values()
                .filter(|e| !e.joined && matches!(e.packet, Packet::Grant { .. }))
                .count();
        let notifications = self
            .membership_notices(&state)?
            .iter()
            .filter(|e| e["seen"] == false)
            .count()
            + state
                .responses
                .values()
                .filter(|e| !e.seen && matches!(e.packet, Packet::Declined { .. }))
                .count();
        let time = now()?.as_millis() as u64;
        let enabled = self.discovery_enabled()
            || state.mailboxes.iter().any(|(id, m)| {
                m.child.expires_at > time
                    && (state.offers.get(id).is_some_and(|e| e.active)
                        || self.awaiting_invitation_response(&state, id))
            })
            || state
                .jobs
                .values()
                .any(|j| !j.stored && j.target.expires_at > time);
        Ok(
            json!({"enabled":enabled,"pending":pending,"responses":responses,"actionable":actionable,"notifications":notifications}),
        )
    }
    /// These notices come from verified authority, never an untrusted transport status.
    pub(super) fn membership_notices(&self, state: &Invitations) -> Result<Vec<Value>> {
        let mut notices = Vec::new();
        for (pin, authority) in self.pins.iter().zip(&self.authorities.0) {
            let head = authority.head()?;
            if head
                .members
                .iter()
                .any(|member| member.identity_id == self.session.identity_id())
            {
                continue;
            }
            let mut cursor = authority.head_id().ok_or("Missing configuration.")?;
            loop {
                let config = authority.config(cursor)?;
                let Some(previous) = config.previous_config_id else {
                    break;
                };
                let old = authority.config(previous)?;
                if old
                    .members
                    .iter()
                    .any(|m| m.identity_id == self.session.identity_id())
                    && !config
                        .members
                        .iter()
                        .any(|m| m.identity_id == self.session.identity_id())
                {
                    let id = format!("removed:{cursor}");
                    notices.push(json!({"id":id,"kind":"removed","name":pin.name,"stream":pin.stream,"seen":state.seen_notices.contains(&id)}));
                    break;
                }
                cursor = previous;
            }
        }
        Ok(notices)
    }
    pub(super) fn invitation_activity(&self, state: &Invitations) -> Result<Value> {
        let mut outgoing = Vec::new();
        for (id, packet) in &state.outgoing {
            let Packet::Request { bundle, .. } = packet else {
                continue;
            };
            let (_, offer, _) = verify_bundle(bundle, 0)?;
            let response = state.responses.get(id);
            // Older clients imported the grant without a response-journal entry.
            // Recover that status from verified authority, never from the name.
            let locally_joined = self.authorities.0.iter().any(|a| {
                a.space() == bundle.space
                    && a.stream() == bundle.stream
                    && id
                        .parse()
                        .is_ok_and(|reference| a.has_membership_approval(reference))
                    && a.head().is_ok_and(|h| {
                        h.members.iter().any(|m| {
                            m.identity_id == self.session.identity_id()
                                && m.credential_ids.contains(&self.session.credential().id())
                        })
                    })
            });
            let time = now()?.as_millis() as u64;
            let status = if locally_joined {
                "joined"
            } else if let Some(response) = response {
                if response.joined {
                    "joined"
                } else if matches!(response.packet, Packet::Declined { .. }) {
                    "declined"
                } else {
                    "approved"
                }
            } else if offer.expires_at <= time {
                "expired"
            } else if let Some(job) = state.jobs.get(id) {
                if job.stored { "waiting" } else { "queued" }
            } else {
                "manual"
            };
            outgoing.push(json!({"id":id,"name":offer.name,"stream":bundle.stream,"status":status,
                "seen":response.is_none_or(|r|r.seen),"link":response.map(|r|encode(&r.packet)).transpose()?,"request_link":encode(packet)?}));
        }
        let mut incoming = Vec::new();
        for (id, entry) in &state.incoming {
            if entry.status != "pending" {
                continue;
            }
            let (_, _, name) = candidate(&entry.packet, 0)?;
            incoming.push(json!({"id":id,"name":name,"space":entry.space,"stream":entry.stream}));
        }
        Ok(
            json!({"outgoing":outgoing,"incoming":incoming,"received":self.received_offer_activity(state)?,"notices":self.membership_notices(state)?}),
        )
    }
    /// A pass is bounded in mailboxes, objects, jobs and network time. It can be
    /// cancelled between any awaits: uploaded ciphertext and capabilities already
    /// exist in the encrypted journal, so retries retain their exact identity.
    pub(in crate::app) async fn sync_invitations(
        &mut self,
        force: bool,
        foreground: bool,
    ) -> Result<Value> {
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(if foreground { 3 } else { 12 });
        let team_changed = self.sync_team(force, foreground).await.unwrap_or(false);
        let time = now()?.as_millis() as u64;
        let mut state = self.invitation_state()?;
        self.resume_committed_additions(&mut state)?;
        self.resume_committed_removals(&mut state)?;
        let mut report = Report::default();
        let before = serde_json::to_vec(&self.invitation_activity(&state)?)?;
        let mut due: Vec<_> = state
            .mailboxes
            .iter()
            .filter(|(id, m)| {
                (force || m.next <= time)
                    && m.child.expires_at > time
                    && (state.offers.get(*id).is_some_and(|e| e.active)
                        || self.awaiting_invitation_response(&state, id))
            })
            .map(|(id, m)| (id.clone(), m.next))
            .collect();
        due.sort_by_key(|(_, next)| *next);
        for (id, _) in due.into_iter().take(4) {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let mut mailbox = state.mailboxes[&id].clone();
            let result = tokio::time::timeout_at(
                deadline.min(tokio::time::Instant::now() + Duration::from_secs(4)),
                self.poll_invitation_mailbox(&id, &mut mailbox, &mut state, &mut report),
            )
            .await;
            if matches!(result, Ok(Ok(()))) {
                mailbox.failures = 0;
                mailbox.next = time + POLL_MS;
            } else {
                report.retry += 1;
                mailbox.next = retry_at(time, &mut mailbox.failures);
            }
            state.mailboxes.insert(id, mailbox);
            self.save_invitations(&state)?;
        }
        self.deliver_jobs(&mut state, &mut report, force, false, time, deadline)
            .await?;
        let discovery = self.discover_offers(&mut state, force, deadline).await?;
        report.received += discovery.received;
        report.retry += discovery.retry;
        report.more |= discovery.more;
        report.progressed = discovery.progressed || report.stored > 0;
        // A bounded upload pass may also leave ready envelopes behind.
        report.more |= state.jobs.iter().any(|(id, job)| {
            !job.stored
                && job.next <= time
                && job.target.expires_at > time
                && state.mailboxes.get(id).is_none_or(|m| m.ready)
        });
        let changed = team_changed
            || before != serde_json::to_vec(&self.invitation_activity(&state)?)?
            || report.received > 0
            || report.stored > 0
            || self.invitation_summary()?["enabled"] == false;
        Ok(json!({"delivery":report,"view":if changed { Some(self.view().await?) } else { None }}))
    }
    /// The administrator has an outbound-only transport path. It never discovers
    /// invitations, imports personal chats, or fetches message ciphertext.
    pub async fn deliver_team_memberships(&self) -> Result<()> {
        self.team_scope()?;
        self.queue_team_memberships()?;
        let mut state = self.invitation_state()?;
        self.deliver_jobs(
            &mut state,
            &mut Report::default(),
            false,
            true,
            now()?.as_millis() as u64,
            tokio::time::Instant::now() + Duration::from_secs(12),
        )
        .await
    }
    async fn deliver_jobs(
        &self,
        state: &mut Invitations,
        report: &mut Report,
        force: bool,
        team_only: bool,
        time: u64,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let mut due: Vec<_> = state
            .jobs
            .iter()
            .filter(|(id, j)| {
                (!team_only || id.starts_with("team:"))
                    && !j.stored
                    && (force || j.next <= time)
                    && j.target.expires_at > time
                    && state.mailboxes.get(*id).is_none_or(|m| m.ready)
            })
            .map(|(id, j)| (id.clone(), j.next))
            .collect();
        due.sort_by_key(|(_, next)| *next);
        for (id, _) in due.into_iter().take(8) {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let job = state.jobs.get_mut(&id).ok_or("Missing delivery job.")?;
            let bytes = STANDARD.decode(&job.ciphertext)?;
            let peer = Peer::new(job.target.descriptor(), self.allow_loopback)?
                .with_identity(&self.session);
            let result = tokio::time::timeout_at(
                deadline.min(tokio::time::Instant::now() + Duration::from_secs(4)),
                peer.post(
                    ObjectId::of_ciphertext(&bytes),
                    bytes,
                    if job.discovery {
                        TransferHint::Lazy
                    } else {
                        TransferHint::Eager
                    },
                ),
            )
            .await;
            if matches!(result, Ok(Ok(_))) {
                job.stored = true;
                report.stored += 1;
            } else {
                report.retry += 1;
                job.next = retry_at(time, &mut job.failures);
            }
            self.save_invitations(state)?;
        }
        if !team_only && self.push_endpoint.is_some() {
            let due: Vec<_> = state
                .jobs
                .iter()
                .filter(|(_, j)| {
                    j.stored && j.notification.as_ref().is_some_and(|n| n.next <= time)
                })
                .map(|(id, _)| id.clone())
                .take(8)
                .collect();
            for id in due {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                let notification = state.jobs[&id]
                    .notification
                    .clone()
                    .ok_or("Missing notification")?;
                let completed = notification.expires <= time
                    || self
                        .notify_invitation(
                            state,
                            &notification.recipient,
                            &format!("invitation:{id}"),
                            notification.membership,
                            deadline,
                        )
                        .await
                        .unwrap_or(false);
                let job = state.jobs.get_mut(&id).ok_or("Missing delivery job")?;
                if completed {
                    job.notification = None;
                } else if let Some(n) = job.notification.as_mut() {
                    n.next = time + 30_000;
                }
                self.save_invitations(state)?;
            }
        }
        Ok(())
    }
    async fn poll_invitation_mailbox(
        &mut self,
        id: &str,
        mailbox: &mut Inbox,
        state: &mut Invitations,
        report: &mut Report,
    ) -> Result<()> {
        if !mailbox.ready {
            Peer::new(mailbox.parent.clone(), self.allow_loopback)?
                .with_identity(&self.session)
                .create_child(&mailbox.child)
                .await?;
            mailbox.ready = true;
        }
        let peer =
            Peer::new(mailbox.descriptor(), self.allow_loopback)?.with_identity(&self.session);
        let mut page = peer.inventory(mailbox.after).await?;
        if mailbox
            .generation
            .as_ref()
            .is_some_and(|g| g != &page.storage_generation)
            || page.head < mailbox.after
        {
            mailbox.after = 0;
            page = peer.inventory(0).await?;
        }
        mailbox.generation = Some(page.storage_generation);
        for item in page.entries.into_iter().take(16) {
            if item.size_bytes > MAX_ENVELOPE as u64 {
                report.rejected += 1;
                mailbox.after = item.arrival_seq;
                continue;
            }
            let bytes = peer.get(item.object_id, item.size_bytes).await?;
            let packet = crypto::open_bytes(&bytes, self.session.age_identity(), MAX_PACKET)
                .ok()
                .and_then(|p| {
                    let plain = Zeroizing::new(p);
                    record::strict_json(&plain, MAX_PACKET + 72).ok()
                })
                .and_then(|v| serde_json::from_value::<Packet>(v).ok());
            let accepted = packet.and_then(|p| self.checked_delivery(id, p, state).ok());
            if let Some(packet) = accepted {
                match &packet {
                    Packet::Request { bundle, .. } => {
                        let (signed, _, _) = candidate(&packet, 0)?;
                        let key = signed.id().to_string();
                        if !state.incoming.contains_key(&key) {
                            // A full journal must leave this object unacknowledged.
                            if state.incoming.len() >= MAX_ITEMS {
                                return Err("There are too many saved requests.".into());
                            }
                            state.incoming.insert(
                                key,
                                RequestEntry {
                                    space: bundle.space,
                                    stream: bundle.stream,
                                    packet,
                                    status: "pending".into(),
                                    grant: None,
                                    grant_head: None,
                                },
                            );
                            report.received += 1;
                        }
                    }
                    Packet::Grant { .. } | Packet::Declined { .. } => {
                        let previous = state.responses.get(id).cloned();
                        let newer = match &previous {
                            Some(entry)
                                if matches!(
                                    (&entry.packet, &packet),
                                    (Packet::Grant { .. }, Packet::Grant { .. })
                                ) =>
                            {
                                let old =
                                    self.preview_invitation(&entry.packet, state, &json!({}), 0)?;
                                let new = self.preview_invitation(&packet, state, &json!({}), 0)?;
                                new["sequence"].as_u64() > old["sequence"].as_u64()
                            }
                            None => true,
                            _ => false,
                        };
                        if newer {
                            let joined = if previous.as_ref().is_some_and(|entry| entry.joined) {
                                self.join_selected_dm_update(id, &packet, state).await?
                            } else {
                                false
                            };
                            state.responses.insert(
                                id.into(),
                                ResponseEntry {
                                    packet,
                                    joined,
                                    seen: joined,
                                },
                            );
                            report.received += 1;
                        }
                    }
                    _ => unreachable!(),
                }
                self.save_invitations(state)?;
            } else {
                report.rejected += 1;
            }
            mailbox.after = item.arrival_seq;
        }
        Ok(())
    }
    fn checked_delivery(&self, id: &str, packet: Packet, state: &Invitations) -> Result<Packet> {
        let time = now()?.as_millis() as u64;
        match &packet {
            Packet::Request { bundle, .. } => {
                if decode_record(&bundle.invitation)?.id().to_string() != id {
                    return Err("Wrong invitation mailbox.".into());
                }
                let i = self.incoming_scope(&packet, &json!({}))?;
                self.require_controller(&self.authorities.0[i])?;
                self.active_offer(state, bundle)?;
                let (_, c, _) = candidate(&packet, time)?;
                if self.authorities.0[i]
                    .head()?
                    .members
                    .iter()
                    .any(|m| m.identity_id == c.identity())
                {
                    return Err("This person is already a member.".into());
                }
            }
            Packet::Grant { reference, .. } | Packet::Declined { reference, .. } => {
                if reference.to_string() != id {
                    return Err("Wrong reply mailbox.".into());
                }
                self.preview_invitation(&packet, state, &json!({}), time)?;
            }
            _ => return Err("Unsupported delivered packet.".into()),
        }
        Ok(packet)
    }
    pub(super) fn dismiss_invitation(&self, state: &mut Invitations, id: &str) -> Result<()> {
        state
            .responses
            .get_mut(id)
            .ok_or("Response not found.")?
            .seen = true;
        Ok(())
    }
    pub(super) fn mark_invitation_joined(&self, state: &mut Invitations, packet: Packet) {
        if let Packet::Grant { reference, .. } = &packet {
            state.responses.insert(
                reference.to_string(),
                ResponseEntry {
                    packet,
                    joined: true,
                    seen: true,
                },
            );
        }
    }
}

//! Local invitation exchange. Links carry bounded signed proofs, never vault secrets.
//! Sharing/scanning and encrypted mailbox delivery move the same verified packets.
use super::*;
use crate::invite::shared;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};

const PREFIX: &str = "elo://exchange/v1#";
const MAX_PACKET: usize = 8 * 1024 * 1024;
const MAX_STATE: usize = 8 * 1024 * 1024;
const MAX_ITEMS: usize = record::MAX_CHAT_CREDENTIALS;
const MAX_PENDING_WAKE_ROUTES: usize = 128;
mod contacts;
mod delivery;
mod direct;
mod membership;
mod personal;
pub mod push;
mod removal;
pub mod team;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    space: SpaceId,
    stream: StreamId,
    root: String,
    invitation: String,
    genesis: String,
    controller: String,
    initial_controller: String,
    recovery: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Packet {
    Team {
        scope: team::TeamScope,
        ciphertext: String,
        contacts: Vec<Packet>,
    },
    MembershipChange {
        bundle: Bundle,
        ciphertext: String,
    },
    Members {
        bundle: Bundle,
        ciphertext: String,
    },
    Wake {
        record: String,
        credential: String,
    },
    Direct {
        bundle: Bundle,
        contact: Box<Packet>,
        ciphertext: String,
    },
    Invitation {
        bundle: Bundle,
    },
    Request {
        bundle: Bundle,
        request: String,
        credential: String,
    },
    Contact {
        card: String,
        credential: String,
    },
    Grant {
        reference: RecordId,
        space: SpaceId,
        stream: StreamId,
        root: String,
        name: String,
        ciphertext: String,
    },
    Declined {
        reference: RecordId,
        proof: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclineProof {
    v: u8,
    kind: String,
    reference: RecordId,
    invitation: RecordId,
    controller: RecordId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferEntry {
    bundle: Bundle,
    active: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEntry {
    packet: Packet,
    space: SpaceId,
    stream: StreamId,
    status: String,
    #[serde(default)]
    grant: Option<String>,
    #[serde(default)]
    grant_head: Option<RecordId>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitations {
    v: u8,
    #[serde(default)]
    additions: BTreeMap<String, membership::Addition>,
    #[serde(default)]
    removals: BTreeMap<String, removal::Removal>,
    #[serde(default)]
    contact_chats: BTreeMap<String, membership::Creation>,
    offers: BTreeMap<String, OfferEntry>,
    incoming: BTreeMap<String, RequestEntry>,
    outgoing: BTreeMap<String, Packet>,
    #[serde(default)]
    mailboxes: BTreeMap<String, delivery::Inbox>,
    #[serde(default)]
    jobs: BTreeMap<String, delivery::Job>,
    #[serde(default)]
    responses: BTreeMap<String, delivery::ResponseEntry>,
    #[serde(default)]
    direct: BTreeMap<String, direct::Draft>,
    #[serde(default)]
    received_offers: BTreeMap<String, direct::ReceivedOffer>,
    #[serde(default)]
    discovery: BTreeMap<String, direct::Cursor>,
    #[serde(default)]
    contacts: BTreeMap<String, Packet>,
    #[serde(default)]
    personal: BTreeMap<String, personal::PersonalDraft>,
    #[serde(default)]
    pending_direct: BTreeMap<String, personal::PendingDirect>,
    #[serde(default)]
    wake_routes: BTreeMap<String, push::Advertisement>,
    #[serde(default)]
    pending_wake_routes: BTreeMap<String, push::Advertisement>,
    #[serde(default)]
    own_wake: Option<push::Route>,
    #[serde(default)]
    seen_notices: Vec<String>,
}
fn packet_subjects(packet: &Packet) -> Result<Vec<IdentityId>> {
    Ok(match packet {
        Packet::Contact { credential: c, .. }
        | Packet::Request { credential: c, .. }
        | Packet::Wake { credential: c, .. } => vec![credential(c)?.identity()],
        Packet::Team { contacts, .. } => contacts
            .iter()
            .map(packet_subjects)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect(),
        Packet::Direct { contact, .. } => packet_subjects(contact)?,
        _ => vec![],
    })
}
impl ClientApp {
    pub(in crate::app) fn erase_service_contact(&self, identity: IdentityId) -> Result<()> {
        let mut state = self.invitation_state()?;
        let mut keys = Vec::new();
        for (key, packet) in &state.contacts {
            if packet_subjects(packet)?.contains(&identity) {
                keys.push(key.clone());
            }
        }
        for key in keys {
            state.contacts.remove(&key);
        }
        state
            .wake_routes
            .retain(|_, route| route.identity != identity);
        state
            .pending_wake_routes
            .retain(|_, route| route.identity != identity);
        // Already constructed membership packets may include the removed contact.
        // Rebuild them from the cleaned contact set and current membership.
        state.jobs.clear();
        self.save_invitations(&state)?;
        self.queue_team_memberships()?;
        Ok(())
    }
}
fn encode(packet: &Packet) -> Result<String> {
    let bytes = serde_json::to_vec(packet)?;
    if bytes.len() > MAX_PACKET {
        return Err(
            "This invitation exchange is too large. Use a configuration file instead.".into(),
        );
    }
    let mut zip = ZlibEncoder::new(Vec::new(), Compression::default());
    zip.write_all(&bytes)?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(zip.finish()?)))
}
fn decode(link: &str) -> Result<Packet> {
    let encoded = link
        .trim()
        .strip_prefix(PREFIX)
        .ok_or("This is not an elo invitation or response.")?;
    if encoded.len() > MAX_PACKET * 2 {
        return Err("This invitation is too large.".into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    let mut plain = Zeroizing::new(Vec::new());
    ZlibDecoder::new(bytes.as_slice())
        .take(MAX_PACKET as u64 + 1)
        .read_to_end(&mut plain)?;
    let value = record::strict_json(&plain, MAX_PACKET + 72)?;
    Ok(serde_json::from_value(value)?)
}
fn credential(encoded: &str) -> Result<VerifiedCredential> {
    let record = decode_record(encoded)?;
    Ok(VerifiedCredential::verify(
        record.bytes(),
        &root_key(field(record.body(), "root_public_key")?)?,
    )?)
}
fn verify_bundle(
    bundle: &Bundle,
    time: u64,
) -> Result<(SignedRecord, shared::Offer, VerifiedCredential)> {
    let controller = credential(&bundle.controller)?;
    let initial = credential(&bundle.initial_controller)?;
    let genesis = decode_record(&bundle.genesis)?;
    let a = Authority::new(
        genesis.bytes(),
        bundle.space,
        &root_key(&bundle.root)?,
        initial,
        bundle.stream,
    )?;
    if bundle.recovery.len() > 64 {
        return Err("Invitation recovery proof is too large.".into());
    }
    let recovery = bundle
        .recovery
        .iter()
        .map(|s| decode_record(s))
        .collect::<Result<Vec<_>>>()?;
    a.verify_controller_export(&recovery, &controller)?;
    let signed = decode_record(&bundle.invitation)?;
    let offer = shared::verify_offer(&signed, &controller, 0)?;
    if offer.expires_at <= time {
        return Err("This invitation has expired. Ask for a new one.".into());
    }
    if offer.space_id != bundle.space || offer.stream_id != bundle.stream {
        return Err("Invitation scope mismatch.".into());
    }
    Ok((signed, offer, controller))
}
fn candidate(packet: &Packet, time: u64) -> Result<(SignedRecord, VerifiedCredential, String)> {
    match packet {
        Packet::Request {
            bundle,
            request,
            credential: encoded,
        } => {
            let (signed, offer, _) = verify_bundle(bundle, time)?;
            let c = credential(encoded)?;
            let request = decode_record(request)?;
            let body = shared::verify_request(&request, &c)?;
            if body.invite_id != signed.id() {
                return Err("This request belongs to another invitation.".into());
            }
            if !offer.invitees.is_empty() && !offer.invitees.contains(&c.identity()) {
                return Err("This invitation is for someone else.".into());
            }
            if let Some(reply) = &body.delivery {
                let route = offer
                    .delivery
                    .ok_or("This invitation has no reply route.")?;
                if reply.url != route.url
                    || reply.signing_public_key != route.signing_public_key
                    || reply.expires_at > route.expires_at
                    || reply.mailbox_id == route.mailbox_id
                {
                    return Err("The reply address does not match the invitation.".into());
                }
            }
            Ok((request, c, body.name))
        }
        Packet::Contact {
            card,
            credential: encoded,
        } => {
            let c = credential(encoded)?;
            let signed = decode_record(card)?;
            let card = shared::verify_contact(&signed, &c, time)?;
            Ok((signed, c, card.name))
        }
        _ => Err("Scan a person's code or their join request.".into()),
    }
}
fn caps(v: &Value) -> Vec<Capability> {
    let mut caps = vec![Capability::Read];
    if v["post"] == true {
        caps.push(Capability::Post);
    }
    if v["share_history"] == true {
        caps.push(Capability::ShareHistory);
    }
    caps
}
impl ClientApp {
    fn invitation_state(&self) -> Result<Invitations> {
        let path = self.directory.join("invitations.age");
        if !path.exists() {
            return Ok(Invitations {
                v: 1,
                ..Invitations::default()
            });
        }
        let bytes = read_exchange(&path, MAX_STATE + 64 * 1024)?;
        let plain = Zeroizing::new(crypto::open_bytes(
            &bytes,
            self.session.age_identity(),
            MAX_STATE,
        )?);
        let mut state: Invitations = serde_json::from_slice(&plain)?;
        if state.v != 1
            || state.offers.len() > MAX_ITEMS
            || state.incoming.len() > MAX_ITEMS
            || state.outgoing.len() > MAX_ITEMS
            || state.mailboxes.len() > 2 * MAX_ITEMS
            || state.jobs.len() > 2 * MAX_ITEMS
            || state.responses.len() > MAX_ITEMS
            || state.direct.len() > MAX_ITEMS
            || state.received_offers.len() > MAX_ITEMS
            || state.discovery.len() > MAX_ITEMS
            || state.contacts.len() > MAX_ITEMS
            || state.personal.len() > MAX_ITEMS
            || state.pending_direct.len() > MAX_ITEMS
            || state.additions.len() > MAX_ITEMS
            || state.removals.len() > MAX_ITEMS
            || state.contact_chats.len() > MAX_ITEMS
            || state.wake_routes.len() > MAX_ITEMS
            || state.pending_wake_routes.len() > MAX_PENDING_WAKE_ROUTES
            || state.seen_notices.len() > MAX_ITEMS
        {
            return Err("Invalid invitation state.".into());
        }
        state.incoming.retain(|_, entry| {
            !candidate(&entry.packet, 0).is_ok_and(|(_, c, _)| self.blocked.contains(c.identity()))
        });
        state.received_offers.retain(|_, entry| {
            !verify_bundle(&entry.bundle, 0)
                .is_ok_and(|(_, _, c)| self.blocked.contains(c.identity()))
        });
        state.pending_direct.retain(|_, entry| {
            let identity = match &entry.packet {
                Packet::Direct { .. } => self
                    .verify_personal(&entry.packet)
                    .map(|(a, _, _)| a.controller().identity()),
                Packet::Members { .. } => self
                    .verified_membership(&entry.packet)
                    .map(|(a, _, _)| a.controller().identity()),
                _ => return true,
            };
            !identity.is_ok_and(|id| self.blocked.contains(id))
        });
        let blocked_outgoing = state
            .outgoing
            .iter()
            .filter_map(|(id, packet)| match packet {
                Packet::Request { bundle, .. }
                    if verify_bundle(bundle, 0)
                        .is_ok_and(|(_, _, c)| self.blocked.contains(c.identity())) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        state
            .outgoing
            .retain(|id, _| !blocked_outgoing.contains(id));
        state
            .responses
            .retain(|id, _| !blocked_outgoing.contains(id));
        Ok(state)
    }
    pub(super) fn dismiss_blocked_invitations(&self) -> Result<()> {
        self.save_invitations(&self.invitation_state()?)
    }
    fn save_invitations(&self, state: &Invitations) -> Result<()> {
        if state.offers.len() > MAX_ITEMS
            || state.incoming.len() > MAX_ITEMS
            || state.outgoing.len() > MAX_ITEMS
            || state.mailboxes.len() > 2 * MAX_ITEMS
            || state.jobs.len() > 2 * MAX_ITEMS
            || state.responses.len() > MAX_ITEMS
            || state.direct.len() > MAX_ITEMS
            || state.received_offers.len() > MAX_ITEMS
            || state.discovery.len() > MAX_ITEMS
            || state.contacts.len() > MAX_ITEMS
            || state.personal.len() > MAX_ITEMS
            || state.pending_direct.len() > MAX_ITEMS
            || state.additions.len() > MAX_ITEMS
            || state.removals.len() > MAX_ITEMS
            || state.contact_chats.len() > MAX_ITEMS
            || state.wake_routes.len() > MAX_ITEMS
            || state.pending_wake_routes.len() > MAX_PENDING_WAKE_ROUTES
            || state.seen_notices.len() > MAX_ITEMS
        {
            return Err("There are too many saved invitations. Remove an old entry first.".into());
        }
        let plain = Zeroizing::new(serde_json::to_vec(state)?);
        let sealed = crypto::seal_bytes(
            &plain,
            &[self.session.age_identity().to_public()],
            MAX_STATE,
        )?;
        vault::write_private(&self.directory.join("invitations.age"), &sealed, true)?;
        Ok(())
    }
    fn offer_bundle(&self, index: usize, v: &Value, duration_ms: u64) -> Result<Bundle> {
        let a = &self.authorities.0[index];
        self.require_controller(a)?;
        let p = &self.pins[index];
        let time = now()?.as_millis() as u64;
        let signed = shared::create(
            a,
            self.session.signing_key(),
            &p.name,
            caps(v),
            v["reusable"] != false,
            time + duration_ms,
        )?;
        Ok(Bundle {
            space: p.space,
            stream: p.stream,
            root: p.root.clone(),
            invitation: STANDARD.encode(signed.bytes()),
            genesis: STANDARD.encode(a.genesis().bytes()),
            controller: STANDARD.encode(a.controller().record().bytes()),
            initial_controller: STANDARD.encode(a.initial_controller().record().bytes()),
            recovery: a
                .controller_recovery_chain()?
                .iter()
                .map(|s| STANDARD.encode(s.bytes()))
                .collect(),
        })
    }
    fn incoming_scope(&self, packet: &Packet, v: &Value) -> Result<usize> {
        if candidate(packet, 0).is_ok_and(|(_, c, _)| self.blocked.contains(c.identity())) {
            return Err("Unblock this user before contacting them.".into());
        }
        match packet {
            Packet::Request { bundle, .. } => {
                self.authority_index(&json!({"space":bundle.space,"stream":bundle.stream}))
            }
            Packet::Contact { .. } => self.authority_index(v),
            _ => Err("This is not a join request.".into()),
        }
    }
    fn active_offer(&self, state: &Invitations, bundle: &Bundle) -> Result<()> {
        let id = decode_record(&bundle.invitation)?.id().to_string();
        if !state
            .offers
            .get(&id)
            .is_some_and(|e| e.active && e.bundle.invitation == bundle.invitation)
        {
            return Err("This invitation has been turned off or is not on this device.".into());
        }
        Ok(())
    }
    pub(super) async fn invitation_operation(&mut self, v: Value) -> Result<Value> {
        let op = field(&v, "op")?;
        let time = now()?.as_millis() as u64;
        let mut state = self.invitation_state()?;
        match op {
            "contact_add_members" => return self.add_contact_members(v, state).await,
            "contact_create_chat" => return self.create_contact_chat(v, state).await,
            "contact_preview" | "contact_add" => return self.contact_operation(v, state).await,
            "create_dm" => return self.create_dm(v, state).await,
            "contact_open" => return self.open_contact(v, state).await,
            "invitation_ignore" => {
                if let Some(entry) = state.pending_direct.get_mut(field(&v, "id")?) {
                    entry.dismissed = true;
                    self.save_invitations(&state)?;
                    return Ok(json!({"view":self.view().await?}));
                }
                let entry = state
                    .received_offers
                    .get_mut(field(&v, "id")?)
                    .ok_or("Invitation not found.")?;
                entry.dismissed = true;
                self.save_invitations(&state)?;
            }
            "invitation_sync" => {
                return self
                    .sync_invitations(v["force"] == true, v["foreground"] == true)
                    .await;
            }
            "invitation_activity" => return self.invitation_activity(&state),
            "invitation_notifications_seen" => {
                let ids: Vec<String> = serde_json::from_value(v["ids"].clone())?;
                if ids.len() > MAX_ITEMS {
                    return Err("Too many notifications.".into());
                }
                let notices = self.membership_notices(&state)?;
                state
                    .seen_notices
                    .retain(|id| notices.iter().any(|entry| entry["id"] == *id));
                for id in ids {
                    if notices.iter().any(|entry| entry["id"] == id) {
                        if !state.seen_notices.contains(&id) {
                            state.seen_notices.push(id);
                        }
                    } else if let Some(response) = state.responses.get_mut(&id)
                        && matches!(response.packet, Packet::Declined { .. })
                    {
                        response.seen = true;
                    }
                }
                self.save_invitations(&state)?;
            }
            "invitation_dismiss" => {
                self.dismiss_invitation(&mut state, field(&v, "id")?)?;
                self.save_invitations(&state)?;
            }
            "invitation_create" => {
                let i = self.authority_index(&v)?;
                let duration_ms = invitation_duration_ms(&v)?;
                self.ensure_chat_kind(i).await?;
                let mut bundle = self.offer_bundle(i, &v, duration_ms)?;
                let signed = decode_record(&bundle.invitation)?;
                let offer: shared::Offer = signed.decode()?;
                let mailbox = if v["automatic"] == false {
                    None
                } else {
                    self.offer_inbox(offer.expires_at)?
                };
                if let Some(mailbox) = &mailbox {
                    bundle.invitation = STANDARD.encode(
                        shared::with_delivery(
                            &signed,
                            self.session.signing_key(),
                            mailbox.route(),
                        )?
                        .bytes(),
                    );
                }
                bundle.invitation = STANDARD.encode(
                    self.attach_wake(&decode_record(&bundle.invitation)?, &state)?
                        .bytes(),
                );
                let id = decode_record(&bundle.invitation)?.id().to_string();
                if let Some(mailbox) = mailbox {
                    state.mailboxes.insert(id.clone(), mailbox);
                }
                let link = encode(&Packet::Invitation {
                    bundle: bundle.clone(),
                })?;
                state.offers.insert(
                    id.clone(),
                    OfferEntry {
                        bundle,
                        active: true,
                    },
                );
                self.save_invitations(&state)?;
                return Ok(json!({"id":id,"link":link,"view":self.view().await?}));
            }
            "invitation_list" => {
                let i = self.authority_index(&v)?;
                self.require_controller(&self.authorities.0[i])?;
                let p = &self.pins[i];
                let mut offers = Vec::new();
                for (id, e) in &state.offers {
                    if e.bundle.space != p.space || e.bundle.stream != p.stream {
                        continue;
                    }
                    let body: shared::Offer = decode_record(&e.bundle.invitation)?.decode()?;
                    offers.push(json!({"id":id,"active":e.active,"expires_at":body.expires_at,"reusable":body.reusable,"capabilities":body.capabilities,"link":encode(&Packet::Invitation{bundle:e.bundle.clone()})?}));
                }
                let mut requests = Vec::new();
                for (id, e) in &state.incoming {
                    if e.space != p.space || e.stream != p.stream {
                        continue;
                    }
                    // Expired entries remain visible for dismissal; approval revalidates time.
                    let (_, c, name) = candidate(&e.packet, 0)?;
                    let capabilities = match &e.packet {
                        Packet::Request { bundle, .. } => verify_bundle(bundle, 0)?.1.capabilities,
                        _ => vec![Capability::Read, Capability::Post, Capability::ShareHistory],
                    };
                    requests.push(json!({"id":id,"identity":c.identity(),"name":name,"status":e.status,"grant":e.grant,"capabilities":capabilities}));
                }
                return Ok(json!({"offers":offers,"requests":requests}));
            }
            "invitation_disable" => {
                let i = self.authority_index(&v)?;
                self.require_controller(&self.authorities.0[i])?;
                let e = state
                    .offers
                    .get_mut(field(&v, "id")?)
                    .ok_or("Invitation not found.")?;
                if e.bundle.space != self.pins[i].space || e.bundle.stream != self.pins[i].stream {
                    return Err("Invitation scope mismatch.".into());
                }
                e.active = false;
                self.save_invitations(&state)?;
            }
            "contact_create" => {
                let c = self.session.credential();
                let name = field(&v, "name")?.trim();
                // Reopening My code reuses a still-valid signed card, without
                // consuming another outgoing slot or invalidating shared links.
                for packet in state.outgoing.values() {
                    if let Packet::Contact { card, .. } = packet {
                        let signed = decode_record(card)?;
                        if let Ok(card) = shared::verify_contact(&signed, c, time)
                            && card.name == name
                            && card.wake == state.own_wake
                        {
                            return Ok(json!({"link":encode(packet)?}));
                        }
                    }
                }
                let card = shared::contact(c, self.session.signing_key(), name, time + 86_400_000)?;
                let card = self.attach_wake(&card, &state)?;
                let packet = Packet::Contact {
                    card: STANDARD.encode(card.bytes()),
                    credential: STANDARD.encode(c.record().bytes()),
                };
                state.outgoing.insert(card.id().to_string(), packet.clone());
                self.save_invitations(&state)?;
                return Ok(json!({"link":encode(&packet)?}));
            }
            "invitation_preview" => {
                let packet = decode(field(&v, "link")?)?;
                return self.preview_invitation(&packet, &state, &v, time);
            }
            "invitation_request" => {
                let Packet::Invitation { bundle } = decode(field(&v, "link")?)? else {
                    return Err("Open an invitation first.".into());
                };
                let (signed, offer, controller) = verify_bundle(&bundle, time)?;
                if self.blocked.contains(controller.identity()) {
                    return Err("Unblock this user before contacting them.".into());
                }
                if field(&v, "confirmed_invitation")? != signed.id().to_string()
                    || v["trusted"] != true
                {
                    return Err("Confirm who invited you first.".into());
                }
                // Retrying the same invitation reuses the signed request.
                let existing = state.outgoing.values().find(|packet| matches!(packet,Packet::Request { bundle:b,.. } if b.invitation==bundle.invitation));
                if let Some(packet) = existing {
                    return Ok(
                        json!({"link":encode(packet)?,"name":offer.name,"automatic":offer.delivery.is_some(),"view":self.view().await?}),
                    );
                }
                let mut request = shared::request(
                    &signed,
                    &controller,
                    self.session.credential(),
                    self.session.signing_key(),
                    field(&v, "name")?,
                    time,
                )?;
                if let Some(mailbox) = self.reply_inbox(&offer)? {
                    request = shared::with_delivery(
                        &request,
                        self.session.signing_key(),
                        mailbox.route(),
                    )?;
                    request = self.attach_wake(&request, &state)?;
                    state.mailboxes.insert(request.id().to_string(), mailbox);
                }
                let packet = Packet::Request {
                    bundle,
                    request: STANDARD.encode(request.bytes()),
                    credential: STANDARD.encode(self.session.credential().record().bytes()),
                };
                let link = encode(&packet)?;
                if let Some(target) = offer.delivery.clone() {
                    self.queue_packet(
                        &mut state,
                        &request.id().to_string(),
                        &packet,
                        target,
                        &controller.recipient(),
                    )?;
                }
                state.outgoing.insert(request.id().to_string(), packet);
                self.save_invitations(&state)?;
                return Ok(
                    json!({"link":link,"name":offer.name,"automatic":offer.delivery.is_some(),"view":self.view().await?}),
                );
            }
            "invitation_receive" => {
                let packet = decode(field(&v, "link")?)?;
                let i = self.incoming_scope(&packet, &v)?;
                self.require_controller(&self.authorities.0[i])?;
                if let Packet::Request { bundle, .. } = &packet {
                    self.active_offer(&state, bundle)?;
                }
                let (signed, c, _) = candidate(&packet, time)?;
                if self.authorities.0[i]
                    .head()?
                    .members
                    .iter()
                    .any(|m| m.identity_id == c.identity())
                {
                    return Err("This person is already a member.".into());
                }
                let id = if matches!(packet, Packet::Contact { .. }) {
                    format!("{}:{}", self.pins[i].stream, signed.id())
                } else {
                    signed.id().to_string()
                };
                state.incoming.entry(id.clone()).or_insert(RequestEntry {
                    packet,
                    space: self.pins[i].space,
                    stream: self.pins[i].stream,
                    status: "pending".into(),
                    grant: None,
                    grant_head: None,
                });
                self.save_invitations(&state)?;
                return Ok(
                    json!({"id":id,"space":self.pins[i].space,"stream":self.pins[i].stream}),
                );
            }
            "invitation_decline" | "invitation_approve" => {
                let id = field(&v, "id")?.to_string();
                let mut entry = state.incoming.get(&id).ok_or("Request not found.")?.clone();
                let i =
                    self.authority_index(&json!({"space":entry.space,"stream":entry.stream}))?;
                self.require_controller(&self.authorities.0[i])?;
                if op == "invitation_decline" {
                    if entry.status != "pending" {
                        return Err("This request has already been handled.".into());
                    }
                    entry.status = "declined".into();
                    if let Packet::Request { bundle, .. } = &entry.packet {
                        let reference = candidate(&entry.packet, 0)?.0.id();
                        let proof = SignedRecord::sign(
                            &serde_json::to_vec(&DeclineProof {
                                v: 1,
                                kind: "space.join.declined".into(),
                                reference,
                                invitation: decode_record(&bundle.invitation)?.id(),
                                controller: self.session.credential().id(),
                            })?,
                            self.session.signing_key(),
                        )?;
                        let response = Packet::Declined {
                            reference,
                            proof: STANDARD.encode(proof.bytes()),
                        };
                        self.queue_response(&mut state, &id, &entry.packet, &response)?;
                    }
                    state.incoming.insert(id, entry);
                    self.save_invitations(&state)?;
                } else {
                    if entry.status == "declined" {
                        return Err("This request was declined.".into());
                    }
                    if let Some(link) = entry.grant {
                        return Ok(
                            json!({"link":link,"automatic":state.jobs.keys().any(|key|key == &format!("reply:{id}") || key.starts_with(&format!("reply:{id}:"))),"view":self.view().await?}),
                        );
                    }
                    let (signed, c, name) = candidate(&entry.packet, time)?;
                    if field(&v, "confirmed_identity")? != c.identity().to_string()
                        || v["confirmed"] != true
                    {
                        return Err("Confirm the person before approving.".into());
                    }
                    self.ensure_chat_kind(i).await?;
                    let a = &self.authorities.0[i];
                    let already = a.head()?.members.iter().any(|m| {
                        m.identity_id == c.identity() && m.credential_ids.contains(&c.id())
                    });
                    // Recover the response after a committed approval followed by a failed
                    // metadata write. Never silently enroll a removed identity on a retry.
                    let committed = a.has_membership_approval(signed.id());
                    if committed && !already {
                        return Err(
                            "This person was removed after approval. Create a new request.".into(),
                        );
                    }
                    if !committed {
                        match &entry.packet {
                            Packet::Request { bundle, .. } => {
                                self.active_offer(&state, bundle)?;
                                shared::approve(
                                    &mut self.authorities.0[i],
                                    &self.store,
                                    shared::Approval {
                                        offer: decode_record(&bundle.invitation)?,
                                        request: signed.clone(),
                                        credential: c.clone(),
                                        confirmed_identity: c.identity(),
                                        capabilities: caps(&v),
                                    },
                                    self.session.signing_key(),
                                    self.session.age_identity(),
                                    now()?,
                                )
                                .await?;
                            }
                            Packet::Contact { .. } => {
                                shared::enroll(
                                    &mut self.authorities.0[i],
                                    &self.store,
                                    shared::Enrollment {
                                        credential: c.clone(),
                                        confirmed_identity: c.identity(),
                                        capabilities: caps(&v),
                                        proof: signed.id(),
                                        consume: None,
                                    },
                                    self.session.signing_key(),
                                    self.session.age_identity(),
                                    now()?,
                                )
                                .await?;
                            }
                            _ => return Err("Invalid request.".into()),
                        }
                    }
                    let p = &self.pins[i];
                    let a = &self.authorities.0[i];
                    let grant = Packet::Grant {
                        reference: signed.id(),
                        space: p.space,
                        stream: p.stream,
                        root: p.root.clone(),
                        name: p.name.clone(),
                        ciphertext: STANDARD.encode(a.seal_snapshot(&c.recipient())?),
                    };
                    let link = encode(&grant)?;
                    let automatic = self.queue_response(&mut state, &id, &entry.packet, &grant)?;
                    if let Packet::Request { bundle, .. } = &entry.packet {
                        let offer_id = decode_record(&bundle.invitation)?.id().to_string();
                        if !verify_bundle(bundle, 0)?.1.reusable
                            && let Some(offer) = state.offers.get_mut(&offer_id)
                        {
                            offer.active = false;
                        }
                    }
                    entry.status = "approved".into();
                    entry.grant = Some(link.clone());
                    entry.grant_head = a.head_id();
                    state.incoming.insert(id, entry);
                    self.refresh_direct_grants(&mut state, i)?;
                    self.save_invitations(&state)?;
                    return Ok(
                        json!({"link":link,"name":name,"automatic":automatic,"view":self.view().await?}),
                    );
                }
            }
            "invitation_join" => {
                let packet = decode(field(&v, "link")?)?;
                self.join_invitation(packet.clone(), &state, &v).await?;
                self.mark_invitation_joined(&mut state, packet);
                self.save_invitations(&state)?;
                return Ok(json!({"view":self.view().await?}));
            }
            _ => return Err("Unknown invitation operation.".into()),
        }
        Ok(json!({"view":self.view().await?}))
    }
    fn preview_invitation(
        &self,
        packet: &Packet,
        state: &Invitations,
        v: &Value,
        time: u64,
    ) -> Result<Value> {
        match packet {
            Packet::Team { .. } => Err("Team enrollment is managed by the configured team.".into()),
            Packet::Direct { .. } => self.personal_preview(packet),
            Packet::Members { .. } => self.membership_preview(packet),
            Packet::Wake { .. } | Packet::MembershipChange { .. } => {
                Err("This is not an invitation or contact code.".into())
            }
            Packet::Invitation { bundle } => {
                let (signed, offer, controller) = verify_bundle(bundle, time)?;
                if self.blocked.contains(controller.identity()) {
                    return Err("Unblock this user before contacting them.".into());
                }
                if !offer.invitees.is_empty()
                    && !offer.invitees.contains(&self.session.identity_id())
                {
                    return Err("This invitation is for someone else.".into());
                }
                if let Some(p) = self.pins.iter().find(|p| p.space == bundle.space)
                    && p.root != bundle.root
                {
                    return Err("This invitation conflicts with the saved identity.".into());
                }
                Ok(
                    json!({"kind":"invitation","id":signed.id(),"name":offer.name,"identity":controller.identity(),"space":bundle.space,"stream":bundle.stream,"root":bundle.root,"capabilities":offer.capabilities,"expires_at":offer.expires_at,"reusable":offer.reusable,"automatic":offer.delivery.is_some()}),
                )
            }
            Packet::Contact { .. } if v["space"].is_null() => {
                let (signed, credential, name) = candidate(packet, time)?;
                if credential.identity() == self.session.identity_id() {
                    return Err("This is your own contact code.".into());
                }
                Ok(
                    json!({"kind":"contact","id":signed.id(),"identity":credential.identity(),"name":name}),
                )
            }
            Packet::Contact { .. } | Packet::Request { .. } => {
                let i = self.incoming_scope(packet, v)?;
                self.require_controller(&self.authorities.0[i])?;
                if let Packet::Request { bundle, .. } = packet {
                    self.active_offer(state, bundle)?;
                }
                let (signed, c, name) = candidate(packet, time)?;
                Ok(
                    json!({"kind":"request","id":signed.id(),"name":name,"identity":c.identity(),"space":self.pins[i].space,"stream":self.pins[i].stream}),
                )
            }
            Packet::Declined { reference, proof } => {
                let Some(Packet::Request { bundle, .. }) =
                    state.outgoing.get(&reference.to_string())
                else {
                    return Err("No matching request was found on this device.".into());
                };
                let (signed, offer, controller) = verify_bundle(bundle, 0)?;
                let proof = decode_record(proof)?;
                proof.verify_signature(controller.key())?;
                let body: DeclineProof = proof.decode()?;
                if body.v != 1
                    || body.kind != "space.join.declined"
                    || body.reference != *reference
                    || body.invitation != signed.id()
                    || body.controller != controller.id()
                {
                    return Err("This response does not match your request.".into());
                }
                Ok(
                    json!({"kind":"declined","id":reference,"name":offer.name,"identity":controller.identity(),"space":bundle.space,"stream":bundle.stream}),
                )
            }
            Packet::Grant {
                reference,
                space,
                stream,
                root,
                name,
                ciphertext,
            } => {
                let pending = state
                    .outgoing
                    .get(&reference.to_string())
                    .ok_or("No matching request was found on this device.")?;
                if let Packet::Request { bundle, .. } = pending
                    && (bundle.space != *space || bundle.stream != *stream || bundle.root != *root)
                {
                    return Err("This approval belongs to another invitation.".into());
                }
                let a = Authority::open_snapshot(
                    &STANDARD.decode(ciphertext)?,
                    self.session.age_identity(),
                    *space,
                    &root_key(root)?,
                    *stream,
                )?;
                if !a.has_membership_approval(*reference) {
                    return Err("This approval does not match your signed request.".into());
                }
                let member = a
                    .head()?
                    .members
                    .iter()
                    .find(|m| {
                        m.identity_id == self.session.identity_id()
                            && m.credential_ids.contains(&self.session.credential().id())
                    })
                    .ok_or("Your device is not in this approval.")?;
                if let Packet::Request { bundle, .. } = pending {
                    let (_, offer, controller) = verify_bundle(bundle, 0)?;
                    if controller.id() != a.controller().id()
                        || !member
                            .capabilities
                            .iter()
                            .all(|cap| offer.capabilities.contains(cap))
                    {
                        return Err(
                            "This approval does not match the invitation permissions.".into()
                        );
                    }
                }
                Ok(
                    json!({"kind":"grant","id":reference,"name":name,"identity":a.controller().identity(),"space":space,"stream":stream,"root":root,"capabilities":member.capabilities,"sequence":a.head()?.sequence,"configuration":a.head_id()}),
                )
            }
        }
    }
    async fn join_invitation(
        &mut self,
        packet: Packet,
        state: &Invitations,
        v: &Value,
    ) -> Result<()> {
        let preview = self.preview_invitation(&packet, state, v, now()?.as_millis() as u64)?;
        if preview["kind"] != "grant"
            || v["trusted"] != true
            || v["confirmed_reference"] != preview["id"]
        {
            return Err("Confirm the approved chat first.".into());
        }
        if matches!(packet, Packet::Direct { .. } | Packet::Members { .. }) {
            return self.import_personal(&packet).await;
        }
        let Packet::Grant {
            space,
            stream,
            root,
            name,
            ciphertext,
            ..
        } = packet
        else {
            return Err("Open an approval first.".into());
        };
        if name.is_empty() || name.len() > 120 {
            return Err("Invalid chat name.".into());
        }
        let bytes = STANDARD.decode(ciphertext)?;
        let incoming = Authority::open_snapshot(
            &bytes,
            self.session.age_identity(),
            space,
            &root_key(&root)?,
            stream,
        )?;
        let index = self
            .pins
            .iter()
            .position(|p| p.space == space && p.stream == stream);
        if incoming.recovery_id().is_some()
            && index.and_then(|i| self.authorities.0[i].recovery_id()) != incoming.recovery_id()
        {
            Self::confirm_recovery_import(v, &bytes, &incoming)?;
        }
        let a = incoming
            .merge_into_store(
                index.map(|i| &self.authorities.0[i]),
                &self.store,
                self.session.age_identity(),
                now()?,
            )
            .await?;
        if let Some(i) = index {
            self.authorities.0[i] = a;
        } else {
            self.pins.push(Pin {
                chat_kind: Some(chats::imported_kind(&a, self.session.identity_id())?),
                name,
                space,
                stream,
                root,
                group: None,
                created_at: now()?.as_millis(),
            });
            self.authorities.0.push(a);
        }
        self.persist_workspace()?;
        Ok(())
    }
}

// Older clients may still request the original whole-day durations.
fn invitation_duration_ms(v: &Value) -> Result<u64> {
    match (v.get("lifetime"), v.get("days")) {
        (None, None) => Ok(86_400_000),
        (Some(value), None) => match value.as_str() {
            Some("1m") => Ok(60_000),
            Some("10m") => Ok(600_000),
            Some("30m") => Ok(1_800_000),
            Some("1h") => Ok(3_600_000),
            Some("24h") => Ok(86_400_000),
            Some("100y") => Ok(36_525 * 86_400_000),
            _ => Err("invalid invitation duration".into()),
        },
        (None, Some(value)) => value
            .as_u64()
            .filter(|days| [1, 7, 30].contains(days))
            .map(|days| days * 86_400_000)
            .ok_or_else(|| "invalid invitation duration".into()),
        _ => Err("invalid invitation duration".into()),
    }
}

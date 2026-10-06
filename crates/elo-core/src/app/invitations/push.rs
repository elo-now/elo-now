//! Signed, recipient-bound wake routes travel inside the existing encrypted discovery exchange.
use super::*;
use crate::ids::ObjectId;
use crate::invite::shared::DeliveryAddress;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::Duration;

pub use crate::invite::shared::WakeRoute as Route;

#[derive(Default, Serialize)]
pub(in crate::app) struct SessionNoticeAttempt {
    pub notified: bool,
    pub retry: bool,
}

/// Capability rotation is needed for revocation, not new members or mute toggles.
pub fn policy_requires_rotation(previous: &Value, next: &Value) -> bool {
    let strings = |value: &Value| -> BTreeSet<String> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    if !strings(&next["blocked_senders"]).is_subset(&strings(&previous["blocked_senders"])) {
        return true;
    }
    previous["scopes"].as_array().into_iter().flatten().any(|old| {
        let current = next["scopes"].as_array().into_iter().flatten().find(|s| s["scope"] == old["scope"]);
        !strings(&old["senders"]).is_subset(&current.map(|s| strings(&s["senders"])).unwrap_or_default())
            // Replace capabilities originally advertised without device restrictions.
            || old.get("senders").is_none()
    })
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Advertisement {
    v: u8,
    kind: String,
    issuer: RecordId,
    pub(super) identity: IdentityId,
    recipient: RecordId,
    issued_at: u64,
    expires_at: u64,
    route: Route,
}
pub fn endpoint(value: &str, allow_loopback: bool) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value)?;
    let local = url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || !(url.scheme() == "https" || (allow_loopback && local && url.scheme() == "http"))
    {
        return Err("Invalid notification service address.".into());
    }
    Ok(url)
}
fn valid_route(route: &Route, expected: &str, allow_loopback: bool) -> Result<()> {
    if endpoint(&route.endpoint, allow_loopback)? != endpoint(expected, allow_loopback)? {
        return Err("The notification service does not match this application.".into());
    }
    record::hex::<16>(&route.id)?;
    record::hex::<32>(&route.notify_key)?;
    record::hex::<32>(&route.scope_key)?;
    if route.since == 0 {
        return Err("Invalid notification route.".into());
    }
    Ok(())
}
impl ClientApp {
    pub(in crate::app) async fn notify_ringing_session(
        &self,
        authority: &Authority,
        call: &Value,
        only: Option<IdentityId>,
    ) -> Result<SessionNoticeAttempt> {
        let now_ms = now()?.as_millis() as u64;
        let time = now_ms / 1000;
        let hosting = self
            .call_host
            .as_ref()
            .ok_or("Session unavailable.")?
            .scope
            .space;
        let call_id = field(call, "call_id")?;
        record::hex::<16>(call_id)?;
        let mut state = self.invitation_state()?;
        state.session_notices.retain(|_, until| *until > now_ms);
        let routes = self.wake_candidates(&state, None)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .build()?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut notified = false;
        for (route, credential, _) in routes {
            let recipient = credential.identity();
            if recipient == self.identity_id()
                || only.is_some_and(|id| id != recipient)
                || self.blocked.contains(recipient)
                || crate::calls::require_member(authority, credential.id()).is_err()
            {
                continue;
            }
            let invitation = &call["invitations"][recipient.to_string()];
            let Some(invitation_id) = invitation["invitation_id"].as_str() else {
                continue;
            };
            let Some(expires) = invitation["expires_at"]
                .as_u64()
                .filter(|until| *until > time && *until <= time + 60)
            else {
                continue;
            };
            if invitation["invited_by"] != json!(self.identity_id()) {
                continue;
            }
            let event = format!("ring:{}:{invitation_id}", route.id);
            if state.session_notices.contains_key(&event) || state.session_notices.len() >= 256 {
                continue;
            }
            state.session_notices.insert(event.clone(), now_ms + 8_000);
            let target = crate::calls::ring::RingTarget {
                v: 1,
                hosting_space_id: hosting,
                scope: crate::calls::CallScope {
                    space_id: authority.space(),
                    stream_id: authority.stream(),
                },
                recipient,
                call_id: call_id.into(),
                invitation_id: invitation_id.into(),
                expires,
            };
            let cipher = crate::calls::ring::seal(&route.scope_key, &route.id, &target, time)?;
            let mut wake = json!({"event":keyed(&route,"elo.notification.event.v1",&event)?,
                "scope":session_scope(&route,authority.space(),authority.stream())?,"target":cipher,
                "category":"call_ring","expires":expires});
            super::super::push_sender::sign(&self.session, &route.id, &mut wake)?;
            let url = endpoint(&route.endpoint, self.push_allow_loopback)?
                .join(&format!("v1/routes/{}/ring", route.id))?;
            if let Ok(Ok(response)) = tokio::time::timeout_at(
                deadline,
                client
                    .post(url)
                    .bearer_auth(&route.notify_key)
                    .json(&json!({"wake":wake,"call_id":call_id,"invitation_id":invitation_id}))
                    .send(),
            )
            .await
            {
                notified |= response.status().is_success();
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        self.save_invitations(&state)?;
        Ok(SessionNoticeAttempt {
            notified,
            retry: true,
        })
    }
    pub fn configure_push(&mut self, value: &str, allow_loopback: bool) -> Result<()> {
        self.push_endpoint = Some(endpoint(value, allow_loopback)?.to_string());
        self.push_allow_loopback = allow_loopback;
        self.refresh_default_hosting_context();
        Ok(())
    }
    /// Only connected Spaces contribute endpoints. Importing a hosting catalog
    /// entry alone must not disclose this installation to that service.
    pub fn notification_endpoints(&self) -> Vec<String> {
        self.spaces
            .as_ref()
            .map(|spaces| spaces.clients(self))
            .unwrap_or_else(|| vec![self])
            .into_iter()
            .filter_map(|client| client.notification_push_endpoint())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    pub fn advertise_wake_route(&self, route: Option<Route>) -> Result<()> {
        if let Some(spaces) = &self.spaces {
            for client in spaces.clients(self) {
                if route.as_ref().is_none_or(|route| {
                    client.notification_push_endpoint().as_deref() == Some(route.endpoint.as_str())
                }) {
                    client.advertise_wake_route_local(route.clone())?;
                } else if client
                    .invitation_state()?
                    .own_wake
                    .as_ref()
                    .is_some_and(|old| {
                        client.notification_push_endpoint().as_deref()
                            != Some(old.endpoint.as_str())
                    })
                {
                    client.advertise_wake_route_local(None)?;
                }
            }
            return Ok(());
        }
        self.advertise_wake_route_local(route)
    }
    pub fn withdraw_wake_route(&self, endpoint: &str) -> Result<()> {
        for client in self
            .spaces
            .as_ref()
            .map(|spaces| spaces.clients(self))
            .unwrap_or_else(|| vec![self])
        {
            if client.notification_push_endpoint().as_deref() == Some(endpoint) {
                client.advertise_wake_route_local(None)?;
            }
        }
        Ok(())
    }
    fn advertise_wake_route_local(&self, route: Option<Route>) -> Result<()> {
        let mut state = self.invitation_state()?;
        let time = now()?.as_millis() as u64;
        let route_changed = state.own_wake != route;
        state.own_wake = route.clone();
        let before = state.jobs.len();
        let known = if route.is_some() {
            self.known_people()?
        } else {
            BTreeMap::new()
        };
        let recipients: BTreeSet<_> = known.values().flat_map(|c| c.keys().copied()).collect();
        state.jobs.retain(|id, job| {
            !id.starts_with("wake:")
                || (!route_changed
                    && job.target.expires_at > time
                    && id
                        .split(':')
                        .nth(1)
                        .and_then(|c| c.parse::<RecordId>().ok())
                        .is_some_and(|c| recipients.contains(&c)))
        });
        let Some(route) = route else {
            state.jobs.retain(|id, _| !id.starts_with("wake:"));
            if route_changed || before != state.jobs.len() {
                self.save_invitations(&state)?;
            }
            return Ok(());
        };
        valid_route(
            &route,
            self.notification_push_endpoint()
                .as_deref()
                .ok_or("Notifications are not configured.")?,
            self.push_allow_loopback,
        )?;
        let day = time / 86_400_000;
        let mut changed = route_changed || before != state.jobs.len();
        for credentials in known.values() {
            for recipient in credentials.values() {
                for peer in self
                    .session
                    .peers()
                    .iter()
                    .filter(|p| p.write_token.is_some())
                {
                    let prefix = format!(
                        "wake:{}:{}:{}:",
                        recipient.id(),
                        peer.signing_public_key,
                        peer.mailbox_id
                    );
                    // Include the capability version so an in-place rotation is
                    // advertised immediately, including after an interrupted save.
                    let version = ObjectId::of_ciphertext(route.notify_key.as_bytes());
                    let id = format!("{prefix}{}:{version}:{day}", route.id);
                    if state.jobs.contains_key(&id) {
                        continue;
                    }
                    state.jobs.retain(|old, _| !old.starts_with(&prefix));
                    if state.jobs.len() >= 2 * 128 {
                        continue;
                    }
                    let advert = Advertisement {
                        v: 1,
                        kind: "device.wake.route".into(),
                        issuer: self.session.credential().id(),
                        identity: self.session.identity_id(),
                        recipient: recipient.id(),
                        issued_at: time,
                        expires_at: time + 30 * 86_400_000,
                        route: route.clone(),
                    };
                    let signed = SignedRecord::sign(
                        &serde_json::to_vec(&advert)?,
                        self.session.signing_key(),
                    )?;
                    let packet = Packet::Wake {
                        record: STANDARD.encode(signed.bytes()),
                        credential: STANDARD.encode(self.session.credential().record().bytes()),
                    };
                    self.queue_packet(
                        &mut state,
                        &id,
                        &packet,
                        DeliveryAddress {
                            url: peer.url.clone(),
                            signing_public_key: peer.signing_public_key.clone(),
                            mailbox_id: peer.mailbox_id,
                            write_token: peer
                                .write_token
                                .clone()
                                .ok_or("Missing delivery permission.")?,
                            expires_at: advert.expires_at,
                        },
                        &recipient.recipient(),
                    )?;
                    state
                        .jobs
                        .get_mut(&id)
                        .ok_or("Missing route delivery.")?
                        .discovery = true;
                    changed = true;
                }
            }
        }
        if changed {
            self.save_invitations(&state)?;
        }
        Ok(())
    }
    pub(super) fn receive_wake_route(
        &self,
        signed: &str,
        encoded_credential: &str,
        state: &mut Invitations,
        known: &BTreeMap<IdentityId, BTreeMap<RecordId, VerifiedCredential>>,
    ) -> Result<()> {
        let signed = decode_record(signed)?;
        let credential = credential(encoded_credential)?;
        let advert: Advertisement = signed.decode()?;
        let time = now()?.as_millis() as u64;
        if advert.v != 1
            || advert.kind != "device.wake.route"
            || advert.issuer != credential.id()
            || advert.identity != credential.identity()
            || advert.recipient != self.session.credential().id()
            || advert.route.since > advert.issued_at
            || advert.expires_at <= time
            || advert.issued_at > time + 120_000
            || advert.expires_at.saturating_sub(advert.issued_at) > 30 * 86_400_000
        {
            return Err("Invalid notification route.".into());
        }
        signed.verify_signature(credential.key())?;
        valid_route(
            &advert.route,
            self.push_endpoint
                .as_deref()
                .ok_or("Notifications are not configured.")?,
            self.push_allow_loopback,
        )?;
        state.wake_routes.retain(|_, r| r.expires_at > time);
        state.pending_wake_routes.retain(|_, r| r.expires_at > time);
        let key = format!("{}:{}", advert.issuer, advert.route.id);
        let trusted = known
            .get(&advert.identity)
            .is_some_and(|creds| creds.contains_key(&advert.issuer));
        if state
            .wake_routes
            .get(&key)
            .into_iter()
            .chain(state.pending_wake_routes.get(&key))
            .any(|old| old.issued_at >= advert.issued_at)
        {
            return Ok(());
        }
        // A signed, recipient-bound route can arrive before its membership
        // envelope. Retain a small separate waiting set; it is never used until
        // the normal current-membership/contact check succeeds in wake_candidates.
        let routes = if trusted {
            &mut state.wake_routes
        } else {
            &mut state.pending_wake_routes
        };
        let limit = if trusted {
            MAX_ITEMS
        } else {
            MAX_PENDING_WAKE_ROUTES
        };
        if routes.len() >= limit && !routes.contains_key(&key) {
            return Err("Too many notification routes.".into());
        }
        routes.insert(key.clone(), advert);
        if trusted {
            state.pending_wake_routes.remove(&key);
        } else {
            state.wake_routes.remove(&key);
        }
        self.save_invitations(state)
    }
    pub(super) fn attach_wake(
        &self,
        signed: &SignedRecord,
        state: &Invitations,
    ) -> Result<SignedRecord> {
        let Some(route) = state
            .own_wake
            .as_ref()
            .filter(|_| self.push_endpoint.is_some())
        else {
            return Ok(signed.clone());
        };
        signed.verify_signature(self.session.credential().key())?;
        valid_route(
            route,
            self.push_endpoint
                .as_deref()
                .ok_or("Notifications are not configured.")?,
            self.push_allow_loopback,
        )?;
        let mut body = signed.body().clone();
        body["wake"] = serde_json::to_value(route)?;
        Ok(SignedRecord::sign(
            &serde_json::to_vec(&body)?,
            self.session.signing_key(),
        )?)
    }
    /// All routes are bound either to an explicitly reviewed contact, a verified
    /// invitation exchange, or a signed recipient-bound advertisement.
    pub(super) fn wake_candidates(
        &self,
        state: &Invitations,
        context: Option<&Packet>,
    ) -> Result<Vec<(Route, VerifiedCredential, u64)>> {
        let Some(expected) = &self.push_endpoint else {
            return Ok(Vec::new());
        };
        let time = now()?.as_millis() as u64;
        let mut routes = BTreeMap::new();
        let mut add = |route: Option<Route>, credential: VerifiedCredential, expires: u64| {
            if let Some(route) = route
                && expires > time
                && route.since <= time
                && valid_route(&route, expected, self.push_allow_loopback).is_ok()
            {
                routes.insert(
                    format!("{}:{}", credential.id(), route.id),
                    (route, credential, expires),
                );
            }
        };
        for packet in state
            .contacts
            .values()
            .chain(state.incoming.values().map(|e| &e.packet))
            .chain(state.outgoing.values())
            .chain(context)
        {
            if let Ok((signed, c, _)) = candidate(packet, 0) {
                let route = serde_json::from_value::<Option<Route>>(signed.body()["wake"].clone())
                    .unwrap_or(None);
                let expires = signed.body()["expires_at"]
                    .as_u64()
                    .unwrap_or(time + 86_400_000);
                add(route, c, expires);
            }
            if let Packet::Request { bundle, .. } = packet
                && let Ok((_, offer, c)) = verify_bundle(bundle, 0)
            {
                add(offer.wake, c, offer.expires_at);
            }
        }
        let known = self.known_people()?;
        for advert in state
            .pending_wake_routes
            .values()
            .chain(state.wake_routes.values())
        {
            if let Some(c) = known
                .get(&advert.identity)
                .and_then(|cs| cs.get(&advert.issuer))
            {
                add(Some(advert.route.clone()), c.clone(), advert.expires_at);
            }
        }
        Ok(routes.into_values().collect())
    }
    pub(super) async fn notify_invitation(
        &self,
        state: &Invitations,
        recipient: &str,
        event: &str,
        membership: bool,
        chat: Option<InvitationChat>,
        deadline: tokio::time::Instant,
    ) -> Result<bool> {
        let time = now()?.as_millis() as u64;
        let routes = self.wake_candidates(state, None)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()?;
        let mut found = false;
        let mut complete = true;
        for (route, c, _) in routes.into_iter().filter(|(_, c, _)| {
            c.recipient().to_string() == recipient && c.identity() != self.session.identity_id()
        }) {
            found = true;
            let target = Target {
                v: 1,
                identity: c.identity(),
                category: if membership {
                    "membership"
                } else {
                    "invitation"
                }
                .into(),
                space: self.call_host.as_ref().map(|host| host.scope.space),
                space_context: None,
                stream: None,
                chat: chat.clone(),
                record: None,
                thread: None,
                call_id: None,
                expires: time + 86_400_000,
            };
            let mut body = wake_request(&route, None, event, &target, &c.recipient())?;
            super::super::push_sender::sign(&self.session, &route.id, &mut body)?;
            let url = endpoint(&route.endpoint, self.push_allow_loopback)?
                .join(&format!("v1/routes/{}/wake", route.id))?;
            let response = tokio::time::timeout_at(
                deadline,
                client
                    .post(url)
                    .bearer_auth(&route.notify_key)
                    .json(&body)
                    .send(),
            )
            .await;
            complete &= matches!(response,Ok(Ok(r)) if r.status().is_success() || matches!(r.status().as_u16(),403|404|410));
        }
        Ok(found && complete)
    }
    /// Opaque scope identifiers expose neither chat names nor signed record IDs.
    pub fn notification_policy(&self, route: &Route) -> Result<Value> {
        if !self.notification_endpoints().contains(&route.endpoint) {
            return Err("Notifications are not configured for this hosting.".into());
        }
        let blocked = self
            .blocked
            .entries()?
            .keys()
            .map(|id| super::super::push_sender::sender_tag(&route.id, *id))
            .collect::<Vec<_>>();
        if let Some(spaces) = &self.spaces {
            let mut scopes = BTreeMap::new();
            let mut introductions = BTreeSet::new();
            for client in spaces.clients(self).into_iter().filter(|client| {
                client.notification_push_endpoint().as_deref() == Some(route.endpoint.as_str())
            }) {
                for value in client.notification_policy_local(route)?["scopes"]
                    .as_array()
                    .ok_or("Invalid notification policy.")?
                {
                    if value["allow_unknown"] == true {
                        for tag in value["senders"]
                            .as_array()
                            .ok_or("Invalid notification policy.")?
                        {
                            introductions.insert(
                                tag.as_str()
                                    .ok_or("Invalid notification policy.")?
                                    .to_owned(),
                            );
                        }
                        continue;
                    }
                    scopes.insert(field(value, "scope")?.to_owned(), value.clone());
                }
            }
            scopes.insert(scope(route, None)?, json!({"scope":scope(route,None)?,"enabled":true,"alert_once":true,"allow_unknown":true,"senders":introductions}));
            return Ok(
                json!({"introductions":true,"scopes":scopes.into_values().collect::<Vec<_>>(),"authenticated_senders":true,"blocked_senders":blocked}),
            );
        }
        let mut policy = self.notification_policy_local(route)?;
        policy["authenticated_senders"] = json!(true);
        policy["blocked_senders"] = json!(blocked);
        Ok(policy)
    }
    fn notification_policy_local(&self, route: &Route) -> Result<Value> {
        let mut scopes = Vec::new();
        // A private chat may not yet have incorporated a General device change.
        // Intersect its members with the current hosting roster before authorizing wakes.
        let active = self
            .call_host
            .as_ref()
            .map(|host| {
                self.authorities
                    .0
                    .iter()
                    .find(|a| a.space() == host.scope.space && a.stream() == host.scope.stream)
                    .map(|a| {
                        a.head().map(|h| {
                            h.members
                                .iter()
                                .flat_map(|m| m.credential_ids.iter().copied())
                                .collect::<BTreeSet<_>>()
                        })
                    })
                    .transpose()
                    .map(|v| v.unwrap_or_default())
            })
            .transpose()?;
        for (pin, a) in self.pins.iter().zip(&self.authorities.0) {
            let member = self.authorities.space_ready(a)
                && a.head()?.members.iter().any(|m| {
                    m.identity_id == self.session.identity_id()
                        && m.capabilities.contains(&Capability::Read)
                        && m.credential_ids.contains(&self.session.credential().id())
                        && active
                            .as_ref()
                            .is_none_or(|ids| ids.contains(&self.session.credential().id()))
                });
            let senders: BTreeSet<_> = a
                .head()?
                .members
                .iter()
                .filter(|m| {
                    member
                        && !self.blocked.contains(m.identity_id)
                        && m.capabilities.contains(&Capability::Read)
                        && m.capabilities.contains(&Capability::Post)
                })
                .flat_map(|m| m.credential_ids.iter())
                .filter(|id| active.as_ref().is_none_or(|ids| ids.contains(id)))
                .map(|id| super::super::push_sender::credential_tag(&route.id, *id))
                .collect();
            scopes.push(json!({"scope":scope(route,Some((pin.space,pin.stream)))?,"enabled":member && !self.read.muted_streams.contains(&pin.stream),"senders":senders}));
            scopes.push(json!({"scope":session_scope(route,pin.space,pin.stream)?,
                "enabled":member && !self.read.muted_streams.contains(&pin.stream),"senders":senders,"alert_once":false}));
        }
        let introductions: BTreeSet<_> = self
            .known_people()?
            .values()
            .flat_map(|c| {
                c.keys()
                    .map(|id| super::super::push_sender::credential_tag(&route.id, *id))
            })
            .collect();
        scopes.push(json!({"scope":scope(route,None)?,"enabled":true,"alert_once":true,"allow_unknown":true,"senders":introductions}));
        Ok(json!({"introductions":true,"scopes":scopes}))
    }
    fn notification_target(&self, encoded: &str) -> Result<Target> {
        if encoded.len() > 2048 {
            return Err("Invalid notification.".into());
        }
        let cipher = URL_SAFE_NO_PAD.decode(encoded)?;
        let plain = crypto::open_bytes(&cipher, self.session.age_identity(), 2048)?;
        let target: Target = serde_json::from_slice(&plain)?;
        if target.v != 1
            || !matches!(
                target.category.as_str(),
                "message" | "invitation" | "membership" | "session_start"
            )
            || target.expires > now()?.as_millis() as u64 + 86_520_000
            || target.identity != self.session.identity_id()
        {
            return Err("This notification is no longer available.".into());
        }
        if target.category == "session_start"
            && (target.space.is_none()
                || target.space_context.is_none()
                || target.stream.is_none()
                || target
                    .call_id
                    .as_deref()
                    .is_none_or(|id| record::hex::<16>(id).is_err())
                || target.expires > now()?.as_millis() as u64 + 60_000)
        {
            return Err("This notification is no longer available.".into());
        }
        Ok(target)
    }
    pub fn open_notification(&self, encoded: &str) -> Result<Value> {
        let target = self.notification_target(encoded)?;
        if target.expires < now()?.as_millis() as u64 {
            return Err("This notification is no longer available.".into());
        }
        if target.category == "session_start" {
            let clients = self
                .spaces
                .as_ref()
                .map(|spaces| spaces.clients(self))
                .unwrap_or_else(|| vec![self]);
            let current = clients.into_iter().any(|client| {
                if client.call_host.as_ref().map(|host| host.scope.space) != target.space_context {
                    return false;
                }
                client.authorities.0.iter().any(|authority| {
                    Some(authority.space()) == target.space
                        && Some(authority.stream()) == target.stream
                        && client.authorities.space_ready(authority)
                        && !client.read.muted_streams.contains(&authority.stream())
                        && crate::calls::require_member(authority, client.session.credential().id())
                            .is_ok()
                })
            });
            if !current {
                return Err("This notification is no longer available.".into());
            }
        }
        Ok(serde_json::to_value(target)?)
    }
    /// Reconcile late delivered alerts with verified local state, without
    /// treating a message that has not arrived as read or exposing its target.
    pub async fn notification_delivered_read_receipts(
        &self,
        route: &Route,
        delivered: &[Value],
    ) -> Result<Vec<Value>> {
        if delivered.len() > 64 {
            return Err("Too many delivered notifications.".into());
        }
        let clients = self
            .spaces
            .as_ref()
            .map(|spaces| spaces.clients(self))
            .unwrap_or_else(|| vec![self])
            .into_iter()
            .filter(|client| {
                client.notification_push_endpoint().as_deref() == Some(route.endpoint.as_str())
            })
            .collect::<Vec<_>>();
        let mut receipts = Vec::new();
        let mut pending = BTreeMap::<_, Vec<(RecordId, Value)>>::new();
        for value in delivered {
            let Some(encoded) = value["target"].as_str() else {
                continue;
            };
            let Ok(target) = self.notification_target(encoded) else {
                continue;
            };
            if target.category != "message" || target.chat.is_some() {
                continue;
            }
            let (Some(space), Some(stream), Some(record)) =
                (target.space, target.stream, target.record)
            else {
                continue;
            };
            let receipt = json!({"scope":scope(route,Some((space,stream)))?,
                "event":keyed(route,"elo.notification.event.v1",&record.to_string())?});
            if value["scope"] != receipt["scope"] || value["event"] != receipt["event"] {
                continue;
            }
            let Some((index, client)) = clients.iter().enumerate().find(|(_, client)| {
                client
                    .pins
                    .iter()
                    .any(|pin| pin.space == space && pin.stream == stream)
            }) else {
                continue;
            };
            let id = record.to_string();
            let stream_key = stream.to_string();
            if client
                .read
                .unread
                .get(&stream_key)
                .is_some_and(|ids| ids.contains(&id))
            {
                continue;
            }
            if client
                .read
                .seen
                .get(&stream_key)
                .is_some_and(|ids| ids.contains(&id))
            {
                receipts.push(receipt);
            } else {
                pending
                    .entry((index, space, stream))
                    .or_default()
                    .push((record, receipt));
            }
        }
        for ((index, space, stream), candidates) in pending {
            let client = clients[index];
            let Some(authority) = client
                .authorities
                .0
                .iter()
                .find(|a| a.space() == space && a.stream() == stream)
            else {
                continue;
            };
            let mut sources = Vec::new();
            for (record, _) in &candidates {
                sources.extend(
                    client
                        .store
                        .action_sources(space, stream, Some(*record))
                        .await?,
                );
            }
            if sources.is_empty() {
                continue;
            }
            // Decrypt only the delivered candidates plus existing verified
            // action/root context, not the chat's complete message history.
            let originals = client.originals_from(authority, sources).await?;
            let projection = super::super::message_actions::Projection::new(&originals);
            for (id, receipt) in candidates {
                if originals.iter().any(|(record, _)| {
                    record.id() == id
                        && matches!(
                            record.body()["kind"].as_str(),
                            Some("chat.message" | "file.shared")
                        )
                        && projection.is_deleted(record)
                }) {
                    receipts.push(receipt);
                }
            }
        }
        Ok(receipts)
    }
    /// Produce opaque relay receipts only for messages already verified and
    /// marked read by a successful local operation, including connected Spaces.
    pub fn notification_read_receipts(&self, route: &Route, request: &Value) -> Result<Vec<Value>> {
        if matches!(
            request["op"].as_str(),
            Some("invitation_activity_seen" | "invitation_notifications_seen")
        ) {
            let clients = self
                .spaces
                .as_ref()
                .map(|spaces| spaces.clients(self))
                .unwrap_or_else(|| vec![self]);
            let mut receipts = Vec::new();
            for client in clients.into_iter().filter(|client| {
                client.notification_push_endpoint().as_deref() == Some(route.endpoint.as_str())
            }) {
                let state = client.invitation_state()?;
                let ids = request["ids"].as_array().ok_or("Invalid read receipt.")?;
                for id in ids.iter().filter_map(Value::as_str) {
                    let event = if request["op"] == "invitation_activity_seen" {
                        state
                            .seen_activity
                            .contains(&id.to_owned())
                            .then(|| id.to_owned())
                    } else {
                        if state.seen_notices.iter().any(|seen| seen == id) {
                            id.strip_prefix("removed:")
                                .and_then(|id| id.parse::<RecordId>().ok())
                                .and_then(|id| {
                                    client.authorities.0.iter().find_map(|a| {
                                        a.config(id)
                                            .ok()?
                                            .previous_config_id
                                            .map(|previous| format!("membership:{previous}"))
                                    })
                                })
                        } else {
                            state
                                .responses
                                .get(id)
                                .filter(|r| r.seen && matches!(r.packet, Packet::Declined { .. }))
                                .map(|_| format!("declined:{id}"))
                        }
                    };
                    if let Some(event) = event {
                        receipts.push(json!({"scope":scope(route,None)?,"event":keyed(route,"elo.notification.event.v1",&event)?}));
                    }
                }
            }
            return Ok(receipts);
        }
        if let Some(spaces) = &self.spaces {
            for client in spaces.clients(self) {
                if client.pins.iter().any(|p| {
                    json!(p.space) == request["space"] && json!(p.stream) == request["stream"]
                }) {
                    return if client.notification_push_endpoint().as_deref()
                        == Some(route.endpoint.as_str())
                    {
                        client.notification_read_receipts_local(route, request)
                    } else {
                        Ok(Vec::new())
                    };
                }
            }
            return Err("Chat unavailable.".into());
        }
        if self.notification_push_endpoint().as_deref() != Some(route.endpoint.as_str()) {
            return Ok(Vec::new());
        }
        self.notification_read_receipts_local(route, request)
    }
    fn notification_read_receipts_local(
        &self,
        route: &Route,
        request: &Value,
    ) -> Result<Vec<Value>> {
        let index = self.authority_index(request)?;
        let pin = &self.pins[index];
        let seen = self.read.seen.get(&pin.stream.to_string());
        let ids = request["records"]
            .as_array()
            .ok_or("Invalid read receipt.")?;
        if ids.len() > 1000 {
            return Err("Invalid read receipt.".into());
        }
        let mut receipts = Vec::new();
        for id in ids {
            let id = id.as_str().ok_or("Invalid read receipt.")?;
            if seen.is_some_and(|seen| seen.iter().any(|r| r == id)) {
                receipts.push(json!({"scope":scope(route,Some((pin.space,pin.stream)))?,
                    "event":keyed(route,"elo.notification.event.v1",id)?}));
            }
        }
        Ok(receipts)
    }
    pub(in crate::app) async fn send_wakes(&self) {
        let Some(expected) = &self.push_endpoint else {
            return;
        };
        let (Ok(state), Ok(time)) = (self.invitation_state(), now()) else {
            return;
        };
        let Ok(pending) = self.store.pending_notifications(time).await else {
            return;
        };
        let Ok(routes) = self.wake_candidates(&state, None) else {
            return;
        };
        let Ok(client) = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
        else {
            return;
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut message_projections = BTreeMap::new();
        for (id, object, stored_at) in pending {
            let result:Result<bool>=async {
                let bytes=self.store.get_object(object).await?.ok_or("Missing message")?;
                let record=crypto::open_object(&bytes,self.session.age_identity())?;
                if record.id()!=id {return Err("Invalid message".into());}
                let chat=record.chat()?;
                let current = time.as_millis() as u64;
                let a=self.authorities.for_record(&record)?;
                a.verify_historical(&record)?;
                let scope = (chat.space_id, chat.stream_id);
                if let std::collections::btree_map::Entry::Vacant(slot) = message_projections.entry(scope) {
                    slot.insert(super::super::message_actions::Projection::new(&self.originals(a).await?));
                }
                let projection = &message_projections[&scope];
                if projection.is_deleted(&record) { return Ok(true); }
                let expires = projection.body(&record)["payload"]["expires_at_ms"].as_u64();
                let mut found=false;
                let mut complete=true;
                for (route,credential,_) in routes.iter().filter(|(r,c,_)| c.identity()!=self.session.identity_id() && chat.audience.contains(&c.identity()) && r.since<=stored_at as u64) {
                    if !a.head()?.members.iter().any(|m|m.identity_id==credential.identity() && m.credential_ids.contains(&credential.id()) && m.capabilities.contains(&Capability::Read)) {continue;}
                    let target=Target{chat:None,v:1,identity:credential.identity(),category:"message".into(),space:Some(chat.space_id),space_context:None,stream:Some(chat.stream_id),record:Some(id),thread:chat.payload.thread_root,call_id:None,expires:expires.unwrap_or(current + 86_400_000).min(current + 86_400_000)};
                    let mut request=wake_request(route,Some((chat.space_id,chat.stream_id)),&id.to_string(),&target,&credential.recipient())?;
                    super::super::push_sender::sign(&self.session, &route.id, &mut request)?;
                    found=true;
                    let url=endpoint(expected,self.push_allow_loopback)?.join(&format!("v1/routes/{}/wake",route.id))?;
                    let sent=tokio::time::timeout_at(deadline,client.post(url).bearer_auth(&route.notify_key).json(&request).send()).await;
                    if !matches!(sent,Ok(Ok(r)) if r.status().is_success() || matches!(r.status().as_u16(),403|404|410)) {complete=false;}
                }
                Ok(found && complete)
            }.await;
            // The queue lives in the receipt transaction, so a crash between
            // upload and this call cannot lose the notification handoff.
            let _ = self
                .store
                .notification_attempted(id, result.unwrap_or(false), time)
                .await;
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
    }

    pub(in crate::app) async fn notify_ready_session(
        &self,
        authority: &Authority,
        call_id: &str,
        expires: u64,
    ) -> Result<SessionNoticeAttempt> {
        record::hex::<16>(call_id)?;
        crate::calls::require_member(authority, self.session.credential().id())?;
        let hosting = self
            .call_host
            .as_ref()
            .ok_or("Session unavailable.")?
            .scope
            .space;
        let time = now()?.as_millis() as u64;
        if expires <= time || expires > time + 60_000 {
            return Ok(SessionNoticeAttempt::default());
        }
        let has_recipient = authority.head()?.members.iter().any(|member| {
            member.identity_id != self.identity_id()
                && !self.blocked.contains(member.identity_id)
                && member
                    .credential_ids
                    .iter()
                    .any(|id| crate::calls::require_member(authority, *id).is_ok())
        });
        if !has_recipient {
            return Ok(SessionNoticeAttempt::default());
        }
        let mut state = self.invitation_state()?;
        state.session_notices.retain(|_, expires| *expires > time);
        let event = format!(
            "session:{}:{}:{call_id}",
            authority.space(),
            authority.stream()
        );
        if state.session_notices.contains_key(&event) || state.session_notices.len() >= 128 {
            return Ok(SessionNoticeAttempt {
                notified: false,
                retry: true,
            });
        }
        let routes = self.wake_candidates(&state, None)?;
        // 202 also hides unknown/muted scopes, so it is not a delivery receipt.
        // Throttle repeated callbacks durably, but retry the identical event
        // while the original ready deadline remains valid. The relay deduplicates
        // accepted events, including retries after a newly discovered DM is allowed.
        state
            .session_notices
            .insert(event.clone(), expires.min(time + 8_000));
        self.save_invitations(&state)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut notified = false;
        for (route, credential, _) in routes {
            if credential.identity() == self.identity_id()
                || self.blocked.contains(credential.identity())
                || crate::calls::require_member(authority, credential.id()).is_err()
            {
                continue;
            }
            let target = Target {
                v: 1,
                identity: credential.identity(),
                category: "session_start".into(),
                space: Some(authority.space()),
                space_context: Some(hosting),
                stream: Some(authority.stream()),
                chat: None,
                record: None,
                thread: None,
                call_id: Some(call_id.into()),
                expires,
            };
            let mut body = wake_request(
                &route,
                Some((authority.space(), authority.stream())),
                &event,
                &target,
                &credential.recipient(),
            )?;
            body["scope"] = json!(session_scope(
                &route,
                authority.space(),
                authority.stream()
            )?);
            body["expires"] = json!(expires / 1000);
            super::super::push_sender::sign(&self.session, &route.id, &mut body)?;
            let url = endpoint(&route.endpoint, self.push_allow_loopback)?
                .join(&format!("v1/routes/{}/wake", route.id))?;
            if let Ok(Ok(response)) = tokio::time::timeout_at(
                deadline,
                client
                    .post(url)
                    .bearer_auth(&route.notify_key)
                    .json(&body)
                    .send(),
            )
            .await
            {
                notified |= response.status().is_success();
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        Ok(SessionNoticeAttempt {
            notified,
            retry: true,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    v: u8,
    identity: IdentityId,
    category: String,
    space: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    space_context: Option<SpaceId>,
    stream: Option<StreamId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chat: Option<InvitationChat>,
    record: Option<RecordId>,
    thread: Option<RecordId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    call_id: Option<String>,
    expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InvitationChat {
    pub space: SpaceId,
    pub stream: StreamId,
    pub invitation: RecordId,
}
pub fn scope(route: &Route, chat: Option<(SpaceId, StreamId)>) -> Result<String> {
    keyed(
        route,
        "elo.notification.scope.v1",
        &chat
            .map(|(space, stream)| format!("{space}:{stream}"))
            .unwrap_or_else(|| "invitations".into()),
    )
}
fn session_scope(route: &Route, space: SpaceId, stream: StreamId) -> Result<String> {
    keyed(
        route,
        "elo.notification.session.scope.v1",
        &format!("{space}:{stream}"),
    )
}
fn keyed(route: &Route, domain: &str, value: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&record::hex::<32>(&route.scope_key)?)
        .map_err(|_| "Invalid notification key")?;
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(value.as_bytes());
    Ok(record::encode_hex(&mac.finalize().into_bytes()))
}
fn wake_request(
    route: &Route,
    chat: Option<(SpaceId, StreamId)>,
    event: &str,
    target: &Target,
    recipient: &age::x25519::Recipient,
) -> Result<Value> {
    let cipher = crypto::seal_bytes(
        &serde_json::to_vec(target)?,
        std::slice::from_ref(recipient),
        2048,
    )?;
    Ok(
        json!({"event":keyed(route,"elo.notification.event.v1",event)?,"scope":scope(route,chat)?,"target":URL_SAFE_NO_PAD.encode(cipher),"category":target.category}),
    )
}

#[cfg(test)]
#[path = "push_delivered_tests.rs"]
mod delivered_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn session_targets_are_encrypted_scoped_expiring_and_recheck_local_mute() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic session wake password".into(),
                "General",
            )
            .await
            .unwrap();
        app.configure_push("https://notifications.example.test/", false)
            .unwrap();
        let authority = app.authorities.0[0].clone();
        let hosting = SpaceId::from_bytes([0x77; 32]);
        let mut hosting_scope = app.team_scope().unwrap();
        hosting_scope.space = hosting;
        app.call_host = Some(space_service::SpaceAddress {
            service_credential: None,
            url: "https://api.example.test/team/v1/spaces".into(),
            scope: hosting_scope,
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
        });
        assert_ne!(hosting, authority.space());
        let route = Route {
            endpoint: "https://notifications.example.test/".into(),
            id: "11".repeat(16),
            notify_key: "22".repeat(32),
            scope_key: "33".repeat(32),
            since: 1,
        };
        let session = session_scope(&route, authority.space(), authority.stream()).unwrap();
        assert_ne!(
            session,
            scope(&route, Some((authority.space(), authority.stream()))).unwrap()
        );
        let call_id = "44".repeat(16);
        let expires = now().unwrap().as_millis() as u64 + 60_000;
        let target = Target {
            v: 1,
            identity: app.identity_id(),
            category: "session_start".into(),
            space: Some(authority.space()),
            space_context: Some(hosting),
            stream: Some(authority.stream()),
            chat: None,
            record: None,
            thread: None,
            call_id: Some(call_id.clone()),
            expires,
        };
        let body = wake_request(
            &route,
            Some((authority.space(), authority.stream())),
            "session-event",
            &target,
            &app.session.credential().recipient(),
        )
        .unwrap();
        assert!(!body.to_string().contains(&call_id));
        assert!(!body.to_string().contains(&authority.space().to_string()));
        assert!(!body.to_string().contains(&hosting.to_string()));
        let encoded = body["target"].as_str().unwrap();
        let opened = app.open_notification(encoded).unwrap();
        assert_eq!(opened["call_id"], call_id);
        assert_eq!(opened["space"], json!(authority.space()));
        assert_eq!(opened["space_context"], json!(hosting));
        // Identical chat authority in another hosting Space must not authorize
        // this target or supply that other Space's mute state.
        app.call_host.as_mut().unwrap().scope.space = authority.space();
        assert!(app.open_notification(encoded).is_err());
        app.call_host.as_mut().unwrap().scope.space = hosting;
        app.read.muted_streams.insert(authority.stream());
        assert!(app.open_notification(encoded).is_err());
        let policy = app.notification_policy(&route).unwrap();
        assert_eq!(
            policy["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["scope"] == session)
                .unwrap()["enabled"],
            false
        );
        app.read.muted_streams.remove(&authority.stream());
        assert!(app.open_notification(encoded).is_ok());
        // This self-only fixture has nobody to notify and does not start retries.
        assert!(
            !app.notify_ready_session(&authority, &call_id, expires)
                .await
                .unwrap()
                .retry
        );
        assert!(
            !app.notify_ready_session(&authority, &call_id, expires)
                .await
                .unwrap()
                .retry
        );
        assert!(app.invitation_state().unwrap().session_notices.is_empty());
        let expired = Target {
            expires: 1,
            ..target
        };
        let body = wake_request(
            &route,
            None,
            "expired-session",
            &expired,
            &app.session.credential().recipient(),
        )
        .unwrap();
        assert!(
            app.open_notification(body["target"].as_str().unwrap())
                .is_err()
        );
        app.close().await.unwrap();
    }
    #[tokio::test]
    async fn session_handoff_retries_missing_routes_and_rejections_with_durable_throttle() {
        use std::sync::{Arc, Mutex};
        let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
        let observed = requests.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let router = axum::Router::new().route(
            "/v1/routes/{id}/wake",
            axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
                let mut requests = observed.lock().unwrap();
                requests.push(body);
                let status = if requests.len() == 1 {
                    axum::http::StatusCode::FORBIDDEN
                } else {
                    axum::http::StatusCode::ACCEPTED
                };
                async move { status }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                dir.path().join("profile"),
                "synthetic session retry password".into(),
                "General",
            )
            .await
            .unwrap();
        app.configure_push(&url, true).unwrap();
        app.call_host = Some(space_service::SpaceAddress {
            service_credential: None,
            url: "https://api.example.test/team/v1/spaces".into(),
            scope: app.team_scope().unwrap(),
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
        });
        let peer = Session::create().unwrap().0;
        let mut authority = app.authorities.0[0].clone();
        authority.add_credential(peer.credential().clone());
        let mut config = authority.head().unwrap().clone();
        config.members.push(crate::authority::Member {
            identity_id: peer.identity_id(),
            identity_type: "HUMAN".into(),
            root_public_key: field(peer.credential().record().body(), "root_public_key")
                .unwrap()
                .into(),
            capabilities: vec![Capability::Read, Capability::Post],
            credential_ids: vec![peer.credential().id()],
            external: false,
        });
        config.members.sort_by_key(|m| m.identity_id);
        config.sequence += 1;
        config.previous_config_id = authority.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.action.operation = "replace".into();
        authority
            .apply_config(config.sign(app.session.signing_key()).unwrap())
            .unwrap();
        let call_id = "42".repeat(16);
        let expires = now().unwrap().as_millis() as u64 + 60_000;
        let first = app
            .notify_ready_session(&authority, &call_id, expires)
            .await
            .unwrap();
        assert!(!first.notified && first.retry);
        assert!(requests.lock().unwrap().is_empty());
        let state = app.invitation_state().unwrap();
        assert_eq!(state.session_notices.len(), 1);
        assert!(*state.session_notices.values().next().unwrap() < expires);
        let route = Route {
            endpoint: url,
            id: "11".repeat(16),
            notify_key: "22".repeat(32),
            scope_key: "33".repeat(32),
            since: 1,
        };
        let mut card = shared::contact(
            peer.credential(),
            peer.signing_key(),
            "Synthetic peer",
            expires + 1000,
        )
        .unwrap()
        .body()
        .clone();
        card["wake"] = serde_json::to_value(route).unwrap();
        let card =
            SignedRecord::sign(&serde_json::to_vec(&card).unwrap(), peer.signing_key()).unwrap();
        let mut state = app.invitation_state().unwrap();
        state.contacts.insert(
            peer.credential().id().to_string(),
            Packet::Contact {
                card: STANDARD.encode(card.bytes()),
                credential: STANDARD.encode(peer.credential().record().bytes()),
            },
        );
        app.save_invitations(&state).unwrap();
        assert!(
            app.notify_ready_session(&authority, &call_id, expires)
                .await
                .unwrap()
                .retry
        );
        assert!(
            requests.lock().unwrap().is_empty(),
            "saved cooldown survives a new invocation"
        );
        let expire_throttle = || {
            let mut state = app.invitation_state().unwrap();
            for due in state.session_notices.values_mut() {
                *due = 0;
            }
            app.save_invitations(&state).unwrap();
        };
        expire_throttle();
        let rejected = app
            .notify_ready_session(&authority, &call_id, expires)
            .await
            .unwrap();
        assert!(!rejected.notified && rejected.retry);
        assert_eq!(requests.lock().unwrap().len(), 1);
        expire_throttle();
        let accepted = app
            .notify_ready_session(&authority, &call_id, expires)
            .await
            .unwrap();
        assert!(
            accepted.notified && accepted.retry,
            "202 cannot reveal scope authorization or delivery"
        );
        assert!(
            app.notify_ready_session(&authority, &call_id, expires)
                .await
                .unwrap()
                .retry
        );
        {
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 2, "repeated callbacks are throttled");
            assert_eq!(requests[0]["event"], requests[1]["event"]);
            assert_eq!(requests[0]["scope"], requests[1]["scope"]);
            assert_eq!(requests[0]["expires"], requests[1]["expires"]);
        }
        assert!(
            !app.notify_ready_session(&authority, &call_id, 1)
                .await
                .unwrap()
                .retry
        );
        server.abort();
        app.close().await.unwrap();
    }
    #[tokio::test]
    async fn synchronized_policy_removes_blocked_read_only_and_retired_devices() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = crate::app::ProfileDraft::new()
            .unwrap()
            .save(
                dir.path().join("profile"),
                "synthetic notification password".into(),
                "General",
            )
            .await
            .unwrap();
        app.configure_push("https://notifications.example/", false)
            .unwrap();
        let (peer, recovery) = Session::create().unwrap();
        let replacement = Session::recover(&recovery, peer.identity_id()).unwrap();
        let route = Route {
            endpoint: "https://notifications.example/".into(),
            id: "a".repeat(32),
            notify_key: "b".repeat(64),
            scope_key: "c".repeat(64),
            since: 1,
        };
        let mut authority = app.authorities.0[0].clone();
        authority.add_credential(peer.credential().clone());
        authority.add_credential(replacement.credential().clone());
        let mut config = authority.head().unwrap().clone();
        config.members.push(crate::authority::Member {
            identity_id: peer.identity_id(),
            identity_type: "HUMAN".into(),
            root_public_key: field(peer.credential().record().body(), "root_public_key")
                .unwrap()
                .into(),
            capabilities: vec![Capability::Read, Capability::Post],
            credential_ids: vec![peer.credential().id()],
            external: false,
        });
        config.members.sort_by_key(|m| m.identity_id);
        let install = |app: &mut ClientApp,
                       authority: &mut Authority,
                       config: &mut crate::authority::StreamConfig| {
            config.sequence += 1;
            config.previous_config_id = authority.head_id();
            config.nonce = record::random_hex::<16>().unwrap();
            config.action.operation = "replace".into();
            authority
                .apply_config(config.sign(app.session.signing_key()).unwrap())
                .unwrap();
            app.authorities.0 = vec![authority.clone()].into();
        };
        install(&mut app, &mut authority, &mut config);
        let chat_scope = scope(&route, Some((authority.space(), authority.stream()))).unwrap();
        let tags = |app: &ClientApp| -> Value {
            app.notification_policy(&route).unwrap()["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["scope"] == chat_scope)
                .unwrap()["senders"]
                .clone()
        };
        let old = json!(crate::app::push_sender::credential_tag(
            &route.id,
            peer.credential().id()
        ));
        let new = json!(crate::app::push_sender::credential_tag(
            &route.id,
            replacement.credential().id()
        ));
        assert!(tags(&app).as_array().unwrap().contains(&old));
        assert!(!tags(&app).as_array().unwrap().contains(&new));
        let block = |enabled| json!({"expected_identity":app.identity_id(),"identity":peer.identity_id(),"name":"Synthetic peer","blocked":enabled});
        let on = block(true);
        let off = block(false);
        app.update_block(&on).unwrap();
        assert!(!tags(&app).as_array().unwrap().contains(&old));
        app.update_block(&off).unwrap();
        assert!(tags(&app).as_array().unwrap().contains(&old));
        let peer_index = config
            .members
            .iter()
            .position(|m| m.identity_id == peer.identity_id())
            .unwrap();
        config.members[peer_index].capabilities = vec![Capability::Read];
        install(&mut app, &mut authority, &mut config);
        assert!(!tags(&app).as_array().unwrap().contains(&old));
        config.members[peer_index]
            .capabilities
            .push(Capability::Post);
        config.members[peer_index].credential_ids = vec![replacement.credential().id()];
        install(&mut app, &mut authority, &mut config);
        assert!(!tags(&app).as_array().unwrap().contains(&old));
        assert!(tags(&app).as_array().unwrap().contains(&new));
        config.members.remove(peer_index);
        install(&mut app, &mut authority, &mut config);
        assert!(!tags(&app).as_array().unwrap().contains(&new));
        app.close().await.unwrap();
    }
    #[test]
    fn capability_rotation_follows_revocations_not_additions_or_mute() {
        let original = json!({"scopes":[{"scope":"chat","enabled":true,"senders":["device-a","device-b"]}],"blocked_senders":[]});
        assert!(!policy_requires_rotation(&Value::Null, &original));
        assert!(!policy_requires_rotation(&original, &original));
        let mut added = original.clone();
        added["scopes"][0]["senders"] = json!(["device-a", "device-b", "device-c"]);
        assert!(!policy_requires_rotation(&original, &added));
        added["scopes"][0]["enabled"] = json!(false);
        assert!(!policy_requires_rotation(&original, &added));
        let mut removed = original.clone();
        removed["scopes"][0]["senders"] = json!(["device-b"]);
        assert!(policy_requires_rotation(&original, &removed));
        assert!(policy_requires_rotation(&original, &json!({"scopes":[]})));
        let mut blocked = original.clone();
        blocked["blocked_senders"] = json!(["identity"]);
        assert!(policy_requires_rotation(&original, &blocked));
        assert!(!policy_requires_rotation(&blocked, &original));
    }
    #[tokio::test]
    async fn encrypted_targets_and_recipient_policy_are_bound_to_the_profile() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = crate::app::ProfileDraft::new()
            .unwrap()
            .save(
                dir.path().join("profile"),
                "synthetic notification password".into(),
                "General",
            )
            .await
            .unwrap();
        app.configure_push("https://notifications.example/", false)
            .unwrap();
        let route = Route {
            endpoint: "https://notifications.example/".into(),
            id: "a".repeat(32),
            notify_key: "b".repeat(64),
            scope_key: "c".repeat(64),
            since: 1,
        };
        let pin = app.pins[0].clone();
        let before = app.notification_policy(&route).unwrap();
        let scope = scope(&route, Some((pin.space, pin.stream))).unwrap();
        let tag = super::super::super::push_sender::credential_tag(
            &route.id,
            app.session.credential().id(),
        );
        assert_eq!(
            before["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["scope"] == scope)
                .unwrap()["senders"],
            json!([tag])
        );
        assert!(
            !before
                .to_string()
                .contains(&app.session.credential().id().to_string())
        );
        assert!(
            !serde_json::to_string(&before)
                .unwrap()
                .contains(&pin.stream.to_string())
        );
        app.operate(
            json!({"op":"set_chat_muted","space":pin.space,"stream":pin.stream,"muted":true}),
        )
        .await
        .unwrap();
        let policy = app.notification_policy(&route).unwrap();
        assert_eq!(
            policy["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["scope"] == scope)
                .unwrap()["enabled"],
            false
        );
        let target = Target {
            v: 1,
            identity: app.session.identity_id(),
            category: "message".into(),
            space: Some(pin.space),
            space_context: None,
            stream: Some(pin.stream),
            chat: None,
            record: Some(RecordId::from_bytes([5; 32])),
            thread: None,
            call_id: None,
            expires: now().unwrap().as_millis() as u64 + 60000,
        };
        let body = wake_request(
            &route,
            Some((pin.space, pin.stream)),
            "synthetic event",
            &target,
            &app.session.credential().recipient(),
        )
        .unwrap();
        let wire = serde_json::to_string(&body).unwrap();
        assert!(!wire.contains(&app.session.identity_id().to_string()));
        assert!(!wire.contains("synthetic event"));
        let encoded = body["target"].as_str().unwrap();
        assert_eq!(
            app.open_notification(encoded).unwrap()["record"],
            json!(target.record)
        );
        let other = age::x25519::Identity::generate();
        assert!(
            crypto::open_bytes(&URL_SAFE_NO_PAD.decode(encoded).unwrap(), &other, 2048).is_err()
        );
        let mut cipher = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let last = cipher.len() - 1;
        cipher[last] ^= 1;
        assert!(
            app.open_notification(&URL_SAFE_NO_PAD.encode(cipher))
                .is_err()
        );
        let expired = Target {
            expires: 1,
            ..target
        };
        let body = wake_request(
            &route,
            None,
            "expired",
            &expired,
            &app.session.credential().recipient(),
        )
        .unwrap();
        assert!(
            app.open_notification(body["target"].as_str().unwrap())
                .is_err()
        );
        let sent = app
            .operate(json!({"op":"send","space":pin.space,"stream":pin.stream,
            "text":"Synthetic read receipt","created_at":"2026-09-13T12:00:00Z"}))
            .await
            .unwrap();
        let id = sent["view"]["streams"][0]["rows"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["id"]
            .clone();
        let request =
            json!({"op":"mark_read","space":pin.space,"stream":pin.stream,"records":[id]});
        assert!(
            app.notification_read_receipts(&route, &request)
                .unwrap()
                .is_empty()
        );
        app.operate(request.clone()).await.unwrap();
        let receipts = app.notification_read_receipts(&route, &request).unwrap();
        assert_eq!(
            receipts,
            vec![
                json!({"scope":scope,"event":keyed(&route,"elo.notification.event.v1",id.as_str().unwrap()).unwrap()})
            ]
        );
        assert!(
            !serde_json::to_string(&receipts)
                .unwrap()
                .contains(id.as_str().unwrap())
        );
        app.enable_spaces().await.unwrap();
        assert_eq!(
            app.notification_read_receipts(&route, &request).unwrap(),
            receipts
        );
        let mut wrong = request.clone();
        wrong["stream"] = json!(StreamId::from_bytes([99; 16]));
        assert!(app.notification_read_receipts(&route, &wrong).is_err());
        app.advertise_wake_route(Some(route.clone())).unwrap();
        let result = app
            .operate(json!({"op":"contact_create","name":"Synthetic"}))
            .await
            .unwrap();
        let packet = decode(result["link"].as_str().unwrap()).unwrap();
        let (signed, c, _) = candidate(&packet, now().unwrap().as_millis() as u64).unwrap();
        let card = shared::verify_contact(&signed, &c, 0).unwrap();
        assert!(card.wake == Some(route));
        app.advertise_wake_route(None).unwrap();
        let result = app
            .operate(json!({"op":"contact_create","name":"Synthetic"}))
            .await
            .unwrap();
        let (signed, _, _) =
            candidate(&decode(result["link"].as_str().unwrap()).unwrap(), 0).unwrap();
        assert!(signed.body().get("wake").is_none());
        app.close().await.unwrap();
    }
}

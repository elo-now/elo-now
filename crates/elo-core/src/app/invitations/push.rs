//! Signed, recipient-bound wake routes travel inside the existing encrypted discovery exchange.
use super::*;
use crate::invite::shared::DeliveryAddress;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::Duration;

pub use crate::invite::shared::WakeRoute as Route;
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
    pub fn configure_push(&mut self, value: &str, allow_loopback: bool) -> Result<()> {
        self.push_endpoint = Some(endpoint(value, allow_loopback)?.to_string());
        self.push_allow_loopback = allow_loopback;
        Ok(())
    }
    pub fn advertise_wake_route(&self, route: Option<Route>) -> Result<()> {
        if let Some(spaces) = &self.spaces {
            for client in spaces.clients(self) {
                client.advertise_wake_route_local(route.clone())?;
            }
            return Ok(());
        }
        self.advertise_wake_route_local(route)
    }
    fn advertise_wake_route_local(&self, route: Option<Route>) -> Result<()> {
        let mut state = self.invitation_state()?;
        let time = now()?.as_millis() as u64;
        let route_changed = state.own_wake != route;
        state.own_wake = route.clone();
        let before = state.jobs.len();
        state
            .jobs
            .retain(|id, job| !id.starts_with("wake:") || job.target.expires_at > time);
        let Some(route) = route else {
            state.jobs.retain(|id, _| !id.starts_with("wake:"));
            if route_changed || before != state.jobs.len() {
                self.save_invitations(&state)?;
            }
            return Ok(());
        };
        valid_route(
            &route,
            self.push_endpoint
                .as_deref()
                .ok_or("Notifications are not configured.")?,
            self.push_allow_loopback,
        )?;
        let day = time / 86_400_000;
        let mut changed = route_changed || before != state.jobs.len();
        for credentials in self.known_people()?.values() {
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
                    // Republish once after the same-page membership discovery fix.
                    // Older clients may have consumed an advertisement before
                    // refreshing their verified member set. The signed wire stays v1.
                    let id = format!("{prefix}membership-aware:{}:{day}", route.id);
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
                space: None,
                stream: None,
                record: None,
                thread: None,
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
        let blocked = self
            .blocked
            .entries()?
            .keys()
            .map(|id| super::super::push_sender::sender_tag(&route.id, *id))
            .collect::<Vec<_>>();
        if let Some(spaces) = &self.spaces {
            let mut scopes = BTreeMap::new();
            for client in spaces.clients(self) {
                for value in client.notification_policy_local(route)?["scopes"]
                    .as_array()
                    .ok_or("Invalid notification policy.")?
                {
                    scopes.insert(field(value, "scope")?.to_owned(), value.clone());
                }
            }
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
        for (pin, a) in self.pins.iter().zip(&self.authorities.0) {
            let member = a.head()?.members.iter().any(|m| {
                m.identity_id == self.session.identity_id()
                    && m.capabilities.contains(&Capability::Read)
            });
            scopes.push(json!({"scope":scope(route,Some((pin.space,pin.stream)))?,"enabled":member && !self.read.muted_streams.contains(&pin.stream)}));
        }
        scopes.push(json!({"scope":scope(route,None)?,"enabled":true,"alert_once":false}));
        Ok(json!({"introductions":true,"scopes":scopes}))
    }
    /// Recipient-created call contexts stay encrypted until the profile unlocks.
    /// They only identify a chat; current signed call admission is still required.
    pub fn notification_call_subscriptions(&self, route: &Route) -> Result<Vec<Value>> {
        let clients = self
            .spaces
            .as_ref()
            .map(|spaces| spaces.clients(self))
            .unwrap_or_else(|| vec![self]);
        let mut result = Vec::new();
        for client in clients {
            let Some(host) = &client.call_host else {
                continue;
            };
            for (pin, authority) in client.pins.iter().zip(&client.authorities.0) {
                if authority.head()?.chat_kind != Some(ChatKind::Direct)
                    || !client.authorities.space_ready(authority)
                    || crate::calls::require_member(authority, client.session.credential().id())
                        .is_err()
                    || client.read.muted_streams.contains(&pin.stream)
                    || authority
                        .head()?
                        .members
                        .iter()
                        .any(|m| self.blocked.contains(m.identity_id))
                {
                    continue;
                }
                let target = Target {
                    v: 1,
                    identity: self.session.identity_id(),
                    category: "call_context".into(),
                    space: Some(pin.space),
                    stream: Some(pin.stream),
                    record: None,
                    thread: None,
                    expires: now()?.as_millis() as u64 + 30 * 86_400_000,
                };
                let encrypted = crypto::seal_bytes(
                    &serde_json::to_vec(&target)?,
                    &[self.session.credential().recipient()],
                    2048,
                )?;
                result.push(json!({"call_scope":crate::calls::wake::scope(host.scope.space, crate::calls::CallScope {space_id:pin.space,stream_id:pin.stream}),
                    "notification_scope":scope(route,Some((pin.space,pin.stream)))?,
                    "credential":client.session.credential().id(),"head":authority.head_id(),"target":URL_SAFE_NO_PAD.encode(encrypted)}));
            }
        }
        Ok(result)
    }
    pub fn open_call_notification(&self, encoded: &str) -> Result<Value> {
        if encoded.len() > 2048 {
            return Err("Invalid call notification.".into());
        }
        let plain = crypto::open_bytes(
            &URL_SAFE_NO_PAD.decode(encoded)?,
            self.session.age_identity(),
            2048,
        )?;
        let target: Target = serde_json::from_slice(&plain)?;
        let now = now()?.as_millis() as u64;
        if target.v != 1
            || target.category != "call_context"
            || target.identity != self.session.identity_id()
            || target.expires <= now
            || target.expires > now + 30 * 86_400_000
            || target.record.is_some()
            || target.thread.is_some()
        {
            return Err("This call is no longer available.".into());
        }
        let clients = self
            .spaces
            .as_ref()
            .map(|spaces| spaces.clients(self))
            .unwrap_or_else(|| vec![self]);
        for client in clients {
            for (pin, authority) in client.pins.iter().zip(&client.authorities.0) {
                if Some(pin.space) == target.space && Some(pin.stream) == target.stream {
                    if authority.head()?.chat_kind != Some(ChatKind::Direct)
                        || !client.authorities.space_ready(authority)
                        || client.read.muted_streams.contains(&pin.stream)
                        || authority
                            .head()?
                            .members
                            .iter()
                            .any(|m| self.blocked.contains(m.identity_id))
                    {
                        return Err("This call is no longer available.".into());
                    }
                    crate::calls::require_member(authority, client.session.credential().id())?;
                    return Ok(serde_json::to_value(target)?);
                }
            }
        }
        Err("This call is no longer available.".into())
    }
    pub fn open_notification(&self, encoded: &str) -> Result<Value> {
        if encoded.len() > 2048 {
            return Err("Invalid notification.".into());
        }
        let cipher = URL_SAFE_NO_PAD.decode(encoded)?;
        let plain = crypto::open_bytes(&cipher, self.session.age_identity(), 2048)?;
        let target: Target = serde_json::from_slice(&plain)?;
        if target.v != 1
            || !matches!(
                target.category.as_str(),
                "message" | "invitation" | "membership"
            )
            || target.expires > now()?.as_millis() as u64 + 86_520_000
            || target.identity != self.session.identity_id()
            || target.expires < now()?.as_millis() as u64
        {
            return Err("This notification is no longer available.".into());
        }
        Ok(serde_json::to_value(target)?)
    }
    /// Produce opaque relay receipts only for messages already verified and
    /// marked read by a successful local operation, including connected Spaces.
    pub fn notification_read_receipts(&self, route: &Route, request: &Value) -> Result<Vec<Value>> {
        if let Some(spaces) = &self.spaces {
            for client in spaces.clients(self) {
                if client.pins.iter().any(|p| {
                    json!(p.space) == request["space"] && json!(p.stream) == request["stream"]
                }) {
                    return client.notification_read_receipts_local(route, request);
                }
            }
            return Err("Chat unavailable.".into());
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
        for (id, object, stored_at) in pending {
            let result:Result<bool>=async {
                let bytes=self.store.get_object(object).await?.ok_or("Missing message")?;
                let record=crypto::open_object(&bytes,self.session.age_identity())?;
                if record.id()!=id {return Err("Invalid message".into());}
                let chat=record.chat()?;
                let a=self.authorities.for_record(&record)?;
                a.verify_historical(&record)?;
                let mut found=false;
                let mut complete=true;
                for (route,credential,_) in routes.iter().filter(|(r,c,_)| c.identity()!=self.session.identity_id() && chat.audience.contains(&c.identity()) && r.since<=stored_at as u64) {
                    if !a.head()?.members.iter().any(|m|m.identity_id==credential.identity() && m.credential_ids.contains(&credential.id()) && m.capabilities.contains(&Capability::Read)) {continue;}
                    let target=Target{v:1,identity:credential.identity(),category:"message".into(),space:Some(chat.space_id),stream:Some(chat.stream_id),record:Some(id),thread:chat.payload.thread_root,expires:time.as_millis() as u64+86_400_000};
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
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    v: u8,
    identity: IdentityId,
    category: String,
    space: Option<SpaceId>,
    stream: Option<StreamId>,
    record: Option<RecordId>,
    thread: Option<RecordId>,
    expires: u64,
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
        json!({"event":keyed(route,"elo.notification.event.v1",event)?,"scope":scope(route,chat)?,"target":URL_SAFE_NO_PAD.encode(cipher)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
            stream: Some(pin.stream),
            record: Some(RecordId::from_bytes([5; 32])),
            thread: None,
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

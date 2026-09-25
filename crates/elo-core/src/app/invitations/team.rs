//! Explicit, build-provisioned General enrollment. The administrator's key is
//! pinned by the client; mailbox access alone never authorizes an arbitrary chat.
use super::*;
use std::time::Duration;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamScope {
    pub space: SpaceId,
    pub stream: StreamId,
    pub root: String,
    pub controller: RecordId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamDescriptor {
    pub v: u8,
    pub url: String,
    pub token: String,
    pub scope: TeamScope,
    pub message_lifetime_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub v: u8,
    pub contact: String,
    pub proof: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentReply {
    pub v: u8,
    pub packet: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinProof {
    v: u8,
    kind: String,
    space: SpaceId,
    stream: StreamId,
    controller: RecordId,
    contact: RecordId,
}
impl TeamDescriptor {
    pub fn validate(&self, allow_loopback: bool) -> Result<()> {
        let url = reqwest::Url::parse(&self.url)?;
        let local = url
            .host_str()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if self.v != 1
            || url.host_str().is_none()
            || url.username() != ""
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || !(url.scheme() == "https" || (allow_loopback && local && url.scheme() == "http"))
            || !crate::app::space_service::service_path(url.path(), "enroll")
            || crate::app::space_service::validate_message_lifetime(self.message_lifetime_seconds)
                .is_err()
        {
            return Err("Invalid team enrollment address.".into());
        }
        record::hex::<32>(&self.token)?;
        if root_key(&self.scope.root)?.is_weak() {
            return Err("Invalid team key.".into());
        }
        Ok(())
    }
}

impl ClientApp {
    pub(in crate::app) fn space_applicant(
        &self,
        request: &EnrollmentRequest,
    ) -> Result<(IdentityId, RecordId, String)> {
        let packet = decode(&request.contact)?;
        if request.v != 1 || !matches!(packet, Packet::Contact { .. }) {
            return Err("Invalid Space join request.".into());
        }
        let (contact, candidate, name) = candidate(&packet, now()?.as_millis() as u64)?;
        let proof = decode_record(&request.proof)?;
        proof.verify_signature(candidate.key())?;
        let body: JoinProof = proof.decode()?;
        let scope = self.team_scope()?;
        if body.v != 1
            || body.kind != "team.join"
            || body.space != scope.space
            || body.stream != scope.stream
            || body.controller != scope.controller
            || body.contact != contact.id()
        {
            return Err("This request belongs to another Space.".into());
        }
        Ok((candidate.identity(), candidate.id(), name))
    }
    pub(in crate::app) async fn accept_space_enrollment(
        &mut self,
        reply: EnrollmentReply,
    ) -> Result<()> {
        if reply.v != 1 {
            return Err("Unsupported Space enrollment.".into());
        }
        self.import_team(&decode(&reply.packet)?).await?;
        Ok(())
    }
    /// Called only with the privately provisioned build descriptor, never IPC input.
    pub fn configure_team(&mut self, descriptor: TeamDescriptor) -> Result<()> {
        descriptor.validate(self.allow_loopback)?;
        self.team = Some(descriptor);
        self.team_next = 0;
        Ok(())
    }
    pub fn team_scope(&self) -> Result<TeamScope> {
        let authority = self
            .authorities
            .0
            .first()
            .ok_or("General is unavailable.")?;
        self.require_controller(authority)?;
        Ok(TeamScope {
            space: authority.space(),
            stream: authority.stream(),
            root: self.pins[0].root.clone(),
            controller: authority.controller().id(),
        })
    }
    pub(super) fn team_joined(&self) -> bool {
        self.team.as_ref().is_none_or(|team| {
            self.authorities.0.iter().any(|a| {
                a.space() == team.scope.space
                    && a.stream() == team.scope.stream
                    && a.controller().id() == team.scope.controller
                    && a.head().is_ok_and(|h| {
                        h.members.iter().any(|m| {
                            m.identity_id == self.session.identity_id()
                                && m.credential_ids.contains(&self.session.credential().id())
                        })
                    })
            })
        })
    }
    pub(super) async fn sync_team(&mut self, force: bool, foreground: bool) -> Result<bool> {
        if self.team_joined() {
            return Ok(false);
        }
        let time = now()?.as_millis() as u64;
        if !force && self.team_next > time {
            return Ok(false);
        }
        self.team_next = time + 10_000;
        let team = self.team.clone().ok_or("Team unavailable.")?;
        let request = self.team_enrollment_request(&team.scope)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(if foreground { 2 } else { 8 }))
            .build()?;
        let mut response = client
            .post(&team.url)
            .bearer_auth(&team.token)
            .json(&request)
            .send()
            .await
            .map_err(|_| "General is waiting for a connection.")?;
        if !response.status().is_success() {
            return Err("Could not join General yet.".into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Could not read General enrollment.")?
        {
            if bytes.len() + chunk.len() > MAX_PACKET * 2 {
                return Err("General response is too large.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let reply: EnrollmentReply = serde_json::from_slice(&bytes)?;
        if reply.v != 1 {
            return Err("Unsupported General enrollment.".into());
        }
        let packet = decode(&reply.packet)?;
        self.import_team(&packet).await
    }

    pub fn team_enrollment_request(&self, scope: &TeamScope) -> Result<EnrollmentRequest> {
        let time = now()?.as_millis() as u64;
        let name = self
            .profile_details
            .as_ref()
            .map(|p| p.name.as_str())
            .unwrap_or("Member");
        let contact = shared::contact(
            self.session.credential(),
            self.session.signing_key(),
            name,
            time + 86_400_000,
        )?;
        let proof = JoinProof {
            v: 1,
            kind: "team.join".into(),
            space: scope.space,
            stream: scope.stream,
            controller: scope.controller,
            contact: contact.id(),
        };
        let signed = SignedRecord::sign(&serde_json::to_vec(&proof)?, self.session.signing_key())?;
        Ok(EnrollmentRequest {
            v: 1,
            contact: encode(&Packet::Contact {
                card: STANDARD.encode(contact.bytes()),
                credential: STANDARD.encode(self.session.credential().record().bytes()),
            })?,
            proof: STANDARD.encode(signed.bytes()),
        })
    }
    /// The service validates a self-signed contact before granting Read/Post.
    /// No old message or history grant is copied. Replays and new device credentials
    /// for the same root are idempotent; previously removed identities stay removed.
    pub async fn enroll_team_member(
        &mut self,
        request: EnrollmentRequest,
    ) -> Result<EnrollmentReply> {
        self.enroll_member(request, false).await
    }
    pub(in crate::app) async fn enroll_approved_space_member(
        &mut self,
        request: EnrollmentRequest,
    ) -> Result<EnrollmentReply> {
        self.enroll_member(request, true).await
    }
    async fn enroll_member(
        &mut self,
        request: EnrollmentRequest,
        approved: bool,
    ) -> Result<EnrollmentReply> {
        if request.v != 1 {
            return Err("Unsupported enrollment.".into());
        }
        let packet = decode(&request.contact)?;
        if !matches!(packet, Packet::Contact { .. }) {
            return Err("A signed contact is required.".into());
        }
        let (signed, candidate, _) = candidate(&packet, now()?.as_millis() as u64)?;
        let scope = self.team_scope()?;
        let proof = decode_record(&request.proof)?;
        proof.verify_signature(candidate.key())?;
        let body: JoinProof = proof.decode()?;
        if body.v != 1
            || body.kind != "team.join"
            || body.space != scope.space
            || body.stream != scope.stream
            || body.controller != scope.controller
            || body.contact != signed.id()
        {
            return Err("This enrollment was not signed for this team.".into());
        }
        let own = self.session.identity_id();
        if candidate.identity() == own {
            return Err("The administrator cannot enroll itself.".into());
        }
        let mut config = self.authorities.0[0].head()?.clone();
        let member = config
            .members
            .iter_mut()
            .find(|m| m.identity_id == candidate.identity());
        let changed = if let Some(member) = member {
            if member.capabilities != vec![Capability::Read, Capability::Post] {
                return Err("Unexpected team permissions.".into());
            }
            if member.credential_ids.contains(&candidate.id()) {
                false
            } else {
                member.credential_ids.push(candidate.id());
                member.credential_ids.sort();
                true
            }
        } else {
            let authority = &self.authorities.0[0];
            let mut cursor = authority.head_id();
            while let Some(id) = cursor {
                let old = authority.config(id)?;
                if !approved
                    && old
                        .members
                        .iter()
                        .any(|m| m.identity_id == candidate.identity())
                {
                    return Err("This identity was removed from General.".into());
                }
                cursor = old.previous_config_id;
            }
            if config.members.len() >= record::MAX_CHAT_MEMBERS {
                return Err("General member limit reached.".into());
            }
            config.members.push(Member {
                identity_id: candidate.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: field(candidate.record().body(), "root_public_key")?.into(),
                capabilities: vec![Capability::Read, Capability::Post],
                credential_ids: vec![candidate.id()],
                external: true,
            });
            config.members.sort_by_key(|m| m.identity_id);
            true
        };
        if config
            .members
            .iter()
            .map(|m| m.credential_ids.len())
            .sum::<usize>()
            > record::MAX_CHAT_CREDENTIALS
        {
            return Err("General device limit reached.".into());
        }
        let mut state = self.invitation_state()?;
        state.contacts.insert(candidate.id().to_string(), packet);
        self.save_invitations(&state)?;
        if changed {
            self.authorities.0[0].add_credential(candidate.clone());
            config.sequence += 1;
            config.previous_config_id = self.authorities.0[0].head_id();
            config.nonce = record::random_hex::<16>()?;
            config.chat_kind = Some(ChatKind::Chat);
            config.action = ConfigAction {
                operation: "invite.approved".into(),
                actor_identity: own,
                request_record_id: Some(signed.id()),
            };
            self.authorities.0[0]
                .commit_update(
                    &self.store,
                    config.sign(self.session.signing_key())?,
                    self.session.age_identity(),
                    now()?,
                )
                .await?;
        }
        // Publishing derives its durable jobs from the committed head. A restart
        // in this gap regenerates them without repeating a membership change.
        self.queue_team_memberships()?;
        Ok(EnrollmentReply {
            v: 1,
            packet: encode(&self.team_packet(&scope, &candidate.recipient())?)?,
        })
    }
    fn team_packet(&self, scope: &TeamScope, recipient: &age::x25519::Recipient) -> Result<Packet> {
        let authority = &self.authorities.0[0];
        let contacts = self
            .invitation_state()?
            .contacts
            .values()
            .filter_map(|p| {
                let (_, c, _) = candidate(p, 0).ok()?;
                authority
                    .head()
                    .ok()?
                    .members
                    .iter()
                    .any(|m| m.credential_ids.contains(&c.id()))
                    .then(|| p.clone())
            })
            .collect();
        Ok(Packet::Team {
            scope: scope.clone(),
            ciphertext: STANDARD
                .encode(authority.seal_snapshot_signed(recipient, self.session.signing_key())?),
            contacts,
        })
    }
    pub fn queue_team_memberships(&self) -> Result<()> {
        let scope = self.team_scope()?;
        let authority = &self.authorities.0[0];
        let prefix = format!(
            "team:{}:",
            authority.head_id().ok_or("General unavailable.")?
        );
        let mut state = self.invitation_state()?;
        let previous_jobs = state.jobs.len();
        let mut changed = false;
        state
            .jobs
            .retain(|id, _| !id.starts_with("team:") || id.starts_with(&prefix));
        for peer in self
            .session
            .peers()
            .iter()
            .filter(|p| p.write_token.is_some())
        {
            for id in authority
                .head()?
                .members
                .iter()
                .flat_map(|m| &m.credential_ids)
            {
                if *id == self.session.credential().id() {
                    continue;
                }
                let key = format!("{prefix}{id}:{}", peer.mailbox_id);
                if state.jobs.contains_key(&key) {
                    continue;
                }
                changed = true;
                let recipient = authority.credential(*id)?.recipient();
                self.queue_packet(
                    &mut state,
                    &key,
                    &self.team_packet(&scope, &recipient)?,
                    shared::DeliveryAddress {
                        url: peer.url.clone(),
                        signing_public_key: peer.signing_public_key.clone(),
                        mailbox_id: peer.mailbox_id,
                        write_token: peer.write_token.clone().ok_or("Missing delivery access.")?,
                        expires_at: now()?.as_millis() as u64 + 365 * 86_400_000,
                    },
                    &recipient,
                )?;
                state
                    .jobs
                    .get_mut(&key)
                    .ok_or("Missing team delivery.")?
                    .discovery = true;
            }
        }
        if changed || previous_jobs != state.jobs.len() {
            self.save_invitations(&state)?;
        }
        Ok(())
    }
    pub(super) async fn import_team(&mut self, packet: &Packet) -> Result<bool> {
        let Packet::Team {
            scope,
            ciphertext,
            contacts,
        } = packet
        else {
            return Err("Invalid team response.".into());
        };
        let team = self.team.as_ref().ok_or("No team was configured.")?;
        if scope.space != team.scope.space
            || scope.stream != team.scope.stream
            || scope.root != team.scope.root
            || scope.controller != team.scope.controller
        {
            return Err("This configuration belongs to another team.".into());
        }
        let incoming = Authority::open_snapshot(
            &STANDARD.decode(ciphertext)?,
            self.session.age_identity(),
            scope.space,
            &root_key(&scope.root)?,
            scope.stream,
        )?;
        let genesis: SpaceGenesis = incoming.genesis().decode()?;
        if incoming.is_forked()
            || incoming.recovery_id().is_some()
            || incoming.controller().id() != scope.controller
            || incoming.initial_controller().id() != scope.controller
            || genesis.owners.len() != 1
            || genesis.owners[0].identity_id != incoming.controller().identity()
            || incoming.head()?.chat_kind != Some(ChatKind::Chat)
            || incoming.head()?.members.iter().any(|m| {
                m.identity_id != incoming.controller().identity()
                    && m.capabilities != vec![Capability::Read, Capability::Post]
            })
        {
            return Err("Invalid General permissions.".into());
        }
        let index = self
            .pins
            .iter()
            .position(|p| p.space == scope.space && p.stream == scope.stream);
        if !incoming.head()?.members.iter().any(|m| {
            m.identity_id == self.session.identity_id()
                && m.credential_ids.contains(&self.session.credential().id())
        }) {
            return Err("This General enrollment is for another device.".into());
        }
        if let Some(i) = index {
            if self.authorities.0[i]
                .config(incoming.head_id().ok_or("Missing configuration.")?)
                .is_ok()
            {
                return Ok(false);
            }
            // Require extension of our own head. An unrelated branch is never a replacement.
            let mut cursor = incoming.head_id();
            while cursor != self.authorities.0[i].head_id() {
                cursor = incoming
                    .config(cursor.ok_or("Unrelated General configuration.")?)?
                    .previous_config_id;
            }
        }
        let mut state = self.invitation_state()?;
        if contacts.len() > record::MAX_CHAT_CREDENTIALS {
            return Err("Too many General contact cards.".into());
        }
        for contact in contacts {
            if !matches!(contact, Packet::Contact { .. }) {
                return Err("Invalid General contact.".into());
            }
            let (_, c, _) = candidate(contact, 0)?;
            if !incoming
                .head()?
                .members
                .iter()
                .any(|m| m.credential_ids.contains(&c.id()))
            {
                return Err("Unrelated General contact.".into());
            }
            if c.identity() != self.session.identity_id() {
                state.contacts.insert(c.id().to_string(), contact.clone());
            }
        }
        let merged = incoming
            .merge_into_store(
                index.map(|i| &self.authorities.0[i]),
                &self.store,
                self.session.age_identity(),
                now()?,
            )
            .await?;
        if let Some(i) = index {
            self.authorities.0[i] = merged;
        } else {
            self.pins.push(Pin {
                personal_seed: Some(false),
                name: "General".into(),
                space: scope.space,
                stream: scope.stream,
                root: scope.root.clone(),
                chat_kind: Some(ChatKind::Chat),
                group: None,
                created_at: now()?.as_millis(),
            });
            self.authorities.0.push(merged);
        }
        self.persist_workspace()?;
        self.save_invitations(&state)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ObjectId;
    const PASSWORD: &str = "synthetic team profile password";
    async fn profile(path: &Path, name: &str) -> ClientApp {
        ProfileDraft::new()
            .unwrap()
            .save_named(path.join(name), PASSWORD.into(), "General", name)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        ClientApp::open(path.join(name), PASSWORD.into(), true)
            .await
            .unwrap()
    }
    async fn request(client: &mut ClientApp) -> EnrollmentRequest {
        client
            .team_enrollment_request(&client.team.as_ref().unwrap().scope)
            .unwrap()
    }
    async fn send(client: &mut ClientApp, scope: &TeamScope, text: &str) -> Vec<u8> {
        client.operate(json!({"op":"send","space":scope.space,"stream":scope.stream,"text":text,"created_at":"2026-09-11T20:00:00Z"})).await.unwrap();
        let rows = client
            .store
            .display_sources(scope.space, scope.stream)
            .await
            .unwrap();
        for source in rows {
            let bytes = client
                .store
                .get_object(source.object)
                .await
                .unwrap()
                .unwrap();
            if crypto::open_object(&bytes, client.session.age_identity())
                .unwrap()
                .body()["payload"]["text"]
                == text
            {
                return bytes;
            }
        }
        panic!("Sent message was not stored")
    }
    #[tokio::test]
    async fn same_page_general_membership_enables_the_new_members_wake_route() {
        general_wake_discovery(false).await;
    }

    #[tokio::test]
    async fn early_general_wake_route_waits_for_verified_membership_across_restart() {
        general_wake_discovery(true).await;
    }

    async fn general_wake_discovery(route_first: bool) {
        let dir = tempfile::tempdir().unwrap();
        let mut server = profile(dir.path(), "Administrator").await;
        let mut alex = profile(dir.path(), "Alex").await;
        let mut maya = profile(dir.path(), "Maya").await;
        let replica = crate::replica::ReplicaStore::open(dir.path().join("replica"))
            .await
            .unwrap();
        let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
        let listener = crate::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
            .await
            .unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let peer = PeerDescriptor {
            url,
            signing_public_key: record::encode_hex(replica.key().as_bytes()),
            mailbox_id: mailbox.mailbox_id,
            read_token: Some(mailbox.read_token),
            write_token: Some(mailbox.write_token.clone()),
        };
        let descriptor = TeamDescriptor {
            v: 1,
            url: "http://127.0.0.1:9/team/v1/enroll".into(),
            token: "ab".repeat(32),
            scope: server.team_scope().unwrap(),
            message_lifetime_seconds: 86_400,
        };
        for client in [&mut server, &mut alex, &mut maya] {
            client.ensure_peer(peer.clone()).unwrap();
            client
                .configure_push("https://notifications.example/", false)
                .unwrap();
        }
        alex.configure_team(descriptor.clone()).unwrap();
        maya.configure_team(descriptor.clone()).unwrap();
        let reply = server
            .enroll_team_member(request(&mut alex).await)
            .await
            .unwrap();
        alex.import_team(&decode(&reply.packet).unwrap())
            .await
            .unwrap();
        let reply = server
            .enroll_team_member(request(&mut maya).await)
            .await
            .unwrap();
        maya.import_team(&decode(&reply.packet).unwrap())
            .await
            .unwrap();
        assert!(
            !alex
                .known_people()
                .unwrap()
                .contains_key(&maya.identity_id())
        );

        // Admission and the new member's route occupy one inventory page.
        // The receiver must refresh trust before consuming the following object.
        let packet = server
            .team_packet(&descriptor.scope, &alex.session.age_identity().to_public())
            .unwrap();
        let bytes = crypto::seal_bytes(
            &serde_json::to_vec(&packet).unwrap(),
            &[alex.session.age_identity().to_public()],
            MAX_PACKET,
        )
        .unwrap();
        let admission = bytes;
        if !route_first {
            replica
                .post(
                    mailbox.mailbox_id,
                    mailbox.write_token.clone(),
                    ObjectId::of_ciphertext(&admission),
                    admission.clone(),
                    crate::replica::TransferHint::Lazy,
                )
                .await
                .unwrap();
        }
        let route = push::Route {
            endpoint: "https://notifications.example/".into(),
            id: "a".repeat(32),
            notify_key: "b".repeat(64),
            scope_key: "c".repeat(64),
            since: 1,
        };
        maya.advertise_wake_route(Some(route)).unwrap();
        for job in serde_json::to_value(&maya.invitation_state().unwrap().jobs)
            .unwrap()
            .as_object()
            .unwrap()
            .values()
        {
            let bytes = STANDARD
                .decode(job["ciphertext"].as_str().unwrap())
                .unwrap();
            replica
                .post(
                    mailbox.mailbox_id,
                    mailbox.write_token.clone(),
                    ObjectId::of_ciphertext(&bytes),
                    bytes,
                    crate::replica::TransferHint::Lazy,
                )
                .await
                .unwrap();
        }
        let transport = Peer::new(peer.clone(), true).unwrap();
        let http = tokio::spawn(async move {
            {
                let origin = format!("http://{}", listener.local_addr().unwrap());
                axum::serve(listener, crate::http::router(replica, &origin))
            }
            .await
            .unwrap()
        });
        let mut state = alex.invitation_state().unwrap();
        if route_first {
            alex.discover_offers(
                &mut state,
                true,
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
            assert!(
                !alex
                    .known_people()
                    .unwrap()
                    .contains_key(&maya.identity_id())
            );
            assert!(state.wake_routes.is_empty());
            assert_eq!(state.pending_wake_routes.len(), 1);
            assert!(
                alex.wake_candidates(&state, None).unwrap().is_empty(),
                "an early route grants no trust or membership"
            );
            alex.close().await.unwrap();
            alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
                .await
                .unwrap();
            alex.configure_team(descriptor.clone()).unwrap();
            alex.configure_push("https://notifications.example/", false)
                .unwrap();
            state = alex.invitation_state().unwrap();
            transport
                .post(
                    ObjectId::of_ciphertext(&admission),
                    admission,
                    crate::replica::TransferHint::Lazy,
                )
                .await
                .unwrap();
        }
        let report = alex
            .discover_offers(
                &mut state,
                true,
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert_eq!(report.retry, 0);
        assert!(
            alex.known_people()
                .unwrap()
                .contains_key(&maya.identity_id())
        );
        assert_eq!(alex.wake_candidates(&state, None).unwrap().len(), 1);
        assert_eq!(
            state.wake_routes.len() + state.pending_wake_routes.len(),
            1,
            "admission must not discard the new member's push route"
        );
        alex.close().await.unwrap();
        alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
            .await
            .unwrap();
        let saved = alex.invitation_state().unwrap();
        assert_eq!(saved.wake_routes.len() + saved.pending_wake_routes.len(), 1);
        alex.close().await.unwrap();
        maya.close().await.unwrap();
        server.close().await.unwrap();
        http.abort();
    }

    #[tokio::test]
    async fn automatic_general_is_pinned_idempotent_private_before_join_and_persistent() {
        let dir = tempfile::tempdir().unwrap();
        let mut server = profile(dir.path(), "General administrator").await;
        let mut alex = profile(dir.path(), "Alex").await;
        let mut maya = profile(dir.path(), "Maya").await;
        let replica = crate::replica::ReplicaStore::open(dir.path().join("replica"))
            .await
            .unwrap();
        let mailbox = replica.create_mailbox(8 * 1024 * 1024).await.unwrap();
        let peer = PeerDescriptor {
            url: "http://127.0.0.1:9/".into(),
            signing_public_key: record::encode_hex(replica.key().as_bytes()),
            mailbox_id: mailbox.mailbox_id,
            read_token: Some(mailbox.read_token),
            write_token: Some(mailbox.write_token),
        };
        server.ensure_peer(peer.clone()).unwrap();
        alex.ensure_peer(peer.clone()).unwrap();
        maya.ensure_peer(peer).unwrap();
        let scope = server.team_scope().unwrap();
        let descriptor = TeamDescriptor {
            v: 1,
            url: "http://127.0.0.1:9/team/v1/enroll".into(),
            token: "ab".repeat(32),
            scope: scope.clone(),
            message_lifetime_seconds: 86_400,
        };
        assert!(descriptor.validate(false).is_err());
        alex.configure_team(descriptor.clone()).unwrap();
        maya.configure_team(descriptor.clone()).unwrap();
        assert!(
            alex.view().await.unwrap()["streams"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let mut forged_request = request(&mut alex).await;
        forged_request.proof = request(&mut maya).await.proof;
        assert!(
            server.enroll_team_member(forged_request).await.is_err(),
            "one person cannot consent for another"
        );
        let r = server
            .enroll_team_member(request(&mut alex).await)
            .await
            .unwrap();
        let first = decode(&r.packet).unwrap();
        assert!(alex.import_team(&first).await.unwrap());
        assert!(!alex.import_team(&first).await.unwrap());
        assert!(
            maya.import_team(&first).await.is_err(),
            "another recipient cannot open enrollment"
        );
        let old = send(&mut alex, &scope, "before Maya joined").await;
        let head = server.authorities.0[0].head_id();
        server
            .enroll_team_member(request(&mut alex).await)
            .await
            .unwrap();
        assert_eq!(head, server.authorities.0[0].head_id());
        let r = server
            .enroll_team_member(request(&mut maya).await)
            .await
            .unwrap();
        let grant = decode(&r.packet).unwrap();
        assert!(maya.import_team(&grant).await.unwrap());
        assert!(
            crypto::open_object(&old, maya.session.age_identity()).is_err(),
            "joining must not expose old posts"
        );
        let updated = server
            .team_packet(&scope, &alex.session.age_identity().to_public())
            .unwrap();
        alex.import_team(&updated).await.unwrap();
        let new = send(&mut alex, &scope, "after Maya joined").await;
        assert!(crypto::open_object(&new, maya.session.age_identity()).is_ok());
        assert!(
            !alex.import_team(&first).await.unwrap(),
            "stale replies never roll membership back"
        );
        let mut forged = descriptor.clone();
        forged.scope.controller = alex.session.credential().id();
        maya.configure_team(forged).unwrap();
        assert!(
            maya.import_team(&grant).await.is_err(),
            "pin changes cannot accept another issuer"
        );
        maya.configure_team(descriptor.clone()).unwrap();
        let jobs = serde_json::to_value(&server.invitation_state().unwrap().jobs).unwrap();
        server.close().await.unwrap();
        server = ClientApp::open(
            dir.path().join("General administrator"),
            PASSWORD.into(),
            true,
        )
        .await
        .unwrap();
        server.queue_team_memberships().unwrap();
        assert_eq!(
            jobs,
            serde_json::to_value(&server.invitation_state().unwrap().jobs).unwrap(),
            "restart preserves ciphertext identities"
        );
        alex.close().await.unwrap();
        alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
            .await
            .unwrap();
        alex.configure_team(descriptor).unwrap();
        assert!(alex.team_joined());
        let view = alex.view().await.unwrap();
        assert_eq!(
            view["streams"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|s| s["name"] == "General")
                .count(),
            1
        );
        assert_eq!(view["streams"][0]["members"].as_array().unwrap().len(), 3);
        let removed = maya.session.identity_id();
        server.operate(json!({"op":"remove_member","space":scope.space,"stream":scope.stream,"fingerprint":removed})).await.unwrap();
        assert!(
            server
                .enroll_team_member(request(&mut maya).await)
                .await
                .is_err(),
            "removed members cannot automatically rejoin"
        );
        alex.close().await.unwrap();
        maya.close().await.unwrap();
        server.close().await.unwrap();
        drop(replica);
    }
}

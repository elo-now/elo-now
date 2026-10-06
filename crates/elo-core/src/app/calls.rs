use super::*;
use crate::calls::{self, Operation, SignalPayload};
mod notifications;

fn call_audience(
    profile: Option<&crate::hosting_profile::HostingProfile>,
    fallback: &str,
) -> Result<Option<reqwest::Url>> {
    if let Some(profile) = profile {
        return profile
            .call_url
            .as_deref()
            .map(reqwest::Url::parse)
            .transpose()
            .map_err(Into::into);
    }
    let mut endpoint = reqwest::Url::parse(fallback)?;
    endpoint.set_path("/calls/v1");
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    Ok(Some(endpoint))
}

impl ClientApp {
    /// Rust-only protected-storage enrollment. Never expose these limited private
    /// keys through operate or WebView IPC. Runtime recipients must validate the
    /// signed public proof and certificate again before using a restored bundle.
    pub async fn call_delegate_bindings(
        &self,
        time: u64,
        previous: Vec<calls::delegation::CallDelegateBinding>,
    ) -> Result<Vec<calls::delegation::CallDelegateBinding>> {
        let mut previous = previous
            .into_iter()
            .map(|binding| {
                (
                    (
                        binding.space_context.clone(),
                        binding.hosting_space_id,
                        binding.scope.space_id,
                        binding.scope.stream_id,
                    ),
                    binding,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let clients = self
            .spaces
            .as_ref()
            .map(|spaces| spaces.history_clients(self).1)
            .unwrap_or_else(|| vec![(String::new(), self)]);
        let mut bindings = Vec::new();
        for (context, client) in clients {
            let Some(host) = &client.call_host else {
                continue;
            };
            let profile = self
                .spaces
                .as_ref()
                .and_then(|spaces| spaces.call_profile_for_space(&context))
                .or_else(|| {
                    self.spaces
                        .is_none()
                        .then_some(client.hosting_services.active.as_ref())
                        .flatten()
                });
            let Some(endpoint) = call_audience(profile, &host.url)? else {
                continue;
            };
            if endpoint.scheme() != "https" {
                continue;
            }
            for (index, authority) in client.authorities.0.iter().enumerate() {
                if !client.authorities.space_ready(authority)
                    || calls::require_member(authority, client.session.credential().id()).is_err()
                    || client.is_notes_authority(authority)
                    || client.pins[index].personal_seed == Some(true)
                    || client
                        .store
                        .local_chat_state(authority.space(), authority.stream())
                        .await?
                        .hidden
                    || (authority.head()?.chat_kind == Some(ChatKind::Direct)
                        && authority
                            .head()?
                            .members
                            .iter()
                            .any(|member| client.blocked.contains(member.identity_id)))
                {
                    continue;
                }
                let credential = client.session.credential().id();
                let config_id = authority
                    .head_id()
                    .ok_or("Call authorization is unavailable.")?;
                let proof = authority.call_proof_signed(client.session.signing_key())?;
                // Reuse only after current local membership, deletion and block
                // checks above. Import validates the certificate and both private
                // keys against this current authority, never the cached proof.
                let reusable = previous
                    .remove(&(
                        context.clone(),
                        host.scope.space,
                        authority.space(),
                        authority.stream(),
                    ))
                    .and_then(|mut old| {
                        if old.identity != client.identity_id()
                            || old.credential != credential
                            || old.audience != endpoint.as_str()
                            || old.config_id != config_id
                        {
                            return None;
                        }
                        let delegate = calls::delegation::CallDelegate::import(
                            &old.delegate,
                            authority,
                            host.scope.space,
                            endpoint.as_str(),
                            time,
                        )
                        .ok()?;
                        if delegate.body().issuer_credential != credential
                            || delegate.body().expires_at <= time.saturating_add(5 * 60)
                        {
                            return None;
                        }
                        Some(std::mem::take(&mut old.delegate))
                    });
                let delegate = match reusable {
                    Some(delegate) => delegate,
                    None => calls::delegation::CallDelegate::create(
                        authority,
                        &client.session,
                        host.scope.space,
                        endpoint.as_str(),
                        time,
                    )?
                    .export()?
                    .to_vec(),
                };
                bindings.push(calls::delegation::CallDelegateBinding {
                    identity: client.identity_id(),
                    credential,
                    space_context: context.clone(),
                    name: client.pins[index].name.clone(),
                    audience: endpoint.to_string(),
                    push_endpoint: profile
                        .map(|profile| profile.push_url.clone())
                        .unwrap_or_else(|| client.push_endpoint.clone()),
                    hosting_space_id: host.scope.space,
                    scope: calls::CallScope {
                        space_id: authority.space(),
                        stream_id: authority.stream(),
                    },
                    config_id,
                    proof,
                    delegate,
                });
            }
        }
        Ok(bindings)
    }
    /// New content requires a recent, nonce-bound signed answer from the pinned
    /// host. Local evidence of unknown permissions always overrides that lease.
    pub(super) async fn require_fresh_membership(&self, authority: &Authority) -> Result<()> {
        if self
            .invalidate_membership_from_waiting(Some(authority))
            .await?
        {
            return Err("Chat permissions need to be refreshed.".into());
        }
        self.check_host_membership(authority).await
    }

    pub(super) async fn invalidate_membership_from_waiting(
        &self,
        selected: Option<&Authority>,
    ) -> Result<bool> {
        // A valid signature from a known participant referring to an unknown
        // config is a reason to stop, even before the host's head check.
        let authorities = selected.map_or(self.authorities.0.as_slice(), std::slice::from_ref);
        let mut after = String::new();
        for page in 0..128 {
            let waiting = self.store.waiting_objects(after).await?;
            for (_, bytes) in &waiting {
                if let Ok(record) = crypto::open_object(bytes, self.session.age_identity()) {
                    let body = record.body();
                    if let Some(authority) = authorities.iter().find(|authority| {
                        body["space_id"] == json!(authority.space())
                            && body["stream_id"] == json!(authority.stream())
                    }) && let (Some(issuer), Some(config)) = (
                        body["issuer_credential"]
                            .as_str()
                            .and_then(|id| id.parse().ok()),
                        body["config_id"].as_str().and_then(|id| id.parse().ok()),
                    ) && authority.config(config).is_err()
                        && authority
                            .credential(issuer)
                            .is_ok_and(|c| record.verify_signature(c.key()).is_ok())
                    {
                        self.invalidate_membership_checks().await;
                        return Ok(true);
                    }
                }
            }
            if waiting.is_empty() {
                break;
            }
            if page == 127 {
                self.invalidate_membership_checks().await;
                return Ok(true);
            }
            after = waiting.last().unwrap().0.to_string();
        }
        Ok(false)
    }
    /// Permission changes must reach the host before local delivery can expose
    /// them. Call admission never bootstraps a private head from a caller's proof.
    pub(super) async fn publish_call_update(
        &self,
        authority: &Authority,
        record: &SignedRecord,
    ) -> Result<()> {
        let Some(address) = &self.call_host else {
            return Ok(());
        };
        if authority.space() == address.scope.space && authority.stream() == address.scope.stream {
            return Ok(());
        }
        let mut next = authority.clone();
        next.apply_config(record.clone())?;
        let response = self
            .call_space(
                address,
                "call_head_publish",
                json!({
                    "space":next.space(), "stream":next.stream(), "proof":next.call_proof_signed(self.session.signing_key())?
                }),
            )
            .await?;
        if response["head"] != json!(next.head_id()) {
            return Err("Could not confirm this chat's permissions. Try again.".into());
        }
        Ok(())
    }
    pub(super) fn call_operation(&self, request: &Value) -> Result<Value> {
        if request
            .get("expected_identity")
            .is_some_and(|identity| identity != &json!(self.session.identity_id()))
        {
            return Err("The open profile has changed".into());
        }
        let index = self.authority_index(request)?;
        let authority = &self.authorities.0[index];
        if !self.authorities.space_ready(authority) {
            return Err("Call authorization is no longer current.".into());
        }
        calls::require_member(authority, self.session.credential().id())?;
        if authority.head()?.chat_kind == Some(ChatKind::Direct)
            && authority
                .head()?
                .members
                .iter()
                .any(|person| self.blocked.contains(person.identity_id))
        {
            return Err("Unblock this user before contacting them.".into());
        }
        let time = now()?.as_millis() as u64 / 1000;
        match field(request, "op")? {
            "call_authorization" => {
                let operation: Operation = serde_json::from_value(request["operation"].clone())?;
                let signed = calls::sign_command(
                    authority,
                    &self.session,
                    field(request, "hosting_space_id")?.parse()?,
                    field(request, "audience")?,
                    operation,
                    time,
                )?;
                Ok(json!({"command":STANDARD.encode(signed.bytes()),
                    "proof":if request["include_proof"] == true { Some(authority.call_proof_signed(self.session.signing_key())?) } else { None }}))
            }
            "call_encrypt_signal" => {
                let payload: SignalPayload = serde_json::from_value(request["payload"].clone())?;
                let recipient: RecordId = field(request, "to")?.parse()?;
                if self
                    .blocked
                    .contains(authority.credential(recipient)?.identity())
                {
                    return Err("Unblock this user before contacting them.".into());
                }
                let ciphertext = if let Some(certificate) = request["recipient_delegation"].as_str()
                {
                    let certificate = calls::delegation::decode_certificate(certificate)?;
                    let host = self
                        .call_host
                        .as_ref()
                        .ok_or("Call hosting is unavailable.")?;
                    let audience = call_audience(self.hosting_services.active.as_ref(), &host.url)?
                        .ok_or("This hosting service does not provide audio or video sessions.")?;
                    calls::delegation::seal_signal(
                        authority,
                        calls::delegation::SignalKeys::Device(&self.session),
                        calls::delegation::SignalContext {
                            audience: audience.as_str(),
                            hosting_space_id: host.scope.space,
                            call_id: field(request, "call_id")?,
                            epoch: request["epoch"].as_u64().ok_or("Invalid session epoch.")?,
                        },
                        recipient,
                        Some(&certificate),
                        payload,
                        time,
                    )?
                } else {
                    calls::seal_signal(
                        authority,
                        &self.session,
                        field(request, "call_id")?,
                        request["epoch"].as_u64().ok_or("Invalid session epoch.")?,
                        recipient,
                        payload,
                        time,
                    )?
                };
                Ok(json!({"ciphertext":ciphertext}))
            }
            "call_open_signal" => {
                let signal = if let Some(certificate) = request["sender_delegation"].as_str() {
                    let certificate = calls::delegation::decode_certificate(certificate)?;
                    let host = self
                        .call_host
                        .as_ref()
                        .ok_or("Call hosting is unavailable.")?;
                    let audience = call_audience(self.hosting_services.active.as_ref(), &host.url)?
                        .ok_or("This hosting service does not provide audio or video sessions.")?;
                    calls::delegation::open_signal(
                        authority,
                        calls::delegation::SignalKeys::Device(&self.session),
                        calls::delegation::SignalContext {
                            audience: audience.as_str(),
                            hosting_space_id: host.scope.space,
                            call_id: field(request, "call_id")?,
                            epoch: request["epoch"].as_u64().ok_or("Invalid session epoch.")?,
                        },
                        field(request, "ciphertext")?,
                        Some(&certificate),
                        time,
                    )?
                } else {
                    calls::open_signal(
                        authority,
                        &self.session,
                        field(request, "call_id")?,
                        request["epoch"].as_u64().ok_or("Invalid session epoch.")?,
                        field(request, "ciphertext")?,
                        time,
                    )?
                };
                if self
                    .blocked
                    .contains(authority.credential(signal.from)?.identity())
                {
                    return Err("This user is blocked.".into());
                }
                Ok(json!({"signal":signal}))
            }
            _ => Err("Unknown call operation.".into()),
        }
    }
}

#[cfg(test)]
mod freshness_tests {
    use super::*;
    use crate::ids::ObjectId;
    use crate::replica::{InventoryEntry, TransferHint};

    #[tokio::test]
    async fn enrollment_reuses_current_keys_refreshes_proof_and_rotates_before_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic enrollment password".into(),
                "General",
            )
            .await
            .unwrap();
        app.call_host = Some(space_service::SpaceAddress {
            service_credential: None,
            url: "https://api.example.test/team/v1/spaces".into(),
            scope: app.team_scope().unwrap(),
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
        });
        let time = 1_800_000_000;
        app.spaces = None;
        app.pins[0].personal_seed = Some(false);
        let mut initial = app.call_delegate_bindings(time, vec![]).await.unwrap();
        assert_eq!(initial.len(), 1);
        let key = Zeroizing::new(initial[0].delegate.clone());
        // A stale cached proof must not survive merely because its metadata is
        // unchanged. The certificate is checked using the current authority.
        initial[0].proof.genesis = "invalid cached proof".into();
        app.pins[0].name = "Renamed chat".into();
        app.push_endpoint = Some("https://new-wake.example.test/".into());
        let fresh = app.call_delegate_bindings(time + 1, initial).await.unwrap();
        assert_eq!(fresh[0].delegate.as_slice(), key.as_slice());
        assert_eq!(fresh[0].name, "Renamed chat");
        assert_eq!(
            fresh[0].push_endpoint.as_deref(),
            Some("https://new-wake.example.test/")
        );
        assert!(
            fresh[0]
                .proof
                .verify(fresh[0].scope.space_id, fresh[0].scope.stream_id)
                .is_ok()
        );
        let until_rotation = time + calls::delegation::MAX_DELEGATION_TTL - 301;
        let fresh = app
            .call_delegate_bindings(until_rotation, fresh)
            .await
            .unwrap();
        assert_eq!(fresh[0].delegate.as_slice(), key.as_slice());
        let fresh = app
            .call_delegate_bindings(until_rotation + 1, fresh)
            .await
            .unwrap();
        assert_ne!(fresh[0].delegate.as_slice(), key.as_slice());
        let rotated = Zeroizing::new(fresh[0].delegate.clone());
        app.call_host.as_mut().unwrap().url =
            "https://other-api.example.test/team/v1/spaces".into();
        let fresh = app
            .call_delegate_bindings(until_rotation + 2, fresh)
            .await
            .unwrap();
        assert_ne!(fresh[0].delegate.as_slice(), rotated.as_slice());
        assert_eq!(fresh[0].audience, "https://other-api.example.test/calls/v1");
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn enrollment_never_reuses_a_delegate_after_local_or_membership_revocation() {
        use crate::authority::{ConfigAction, Member};
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic revoked enrollment password".into(),
                "General",
            )
            .await
            .unwrap();
        app.call_host = Some(space_service::SpaceAddress {
            service_credential: None,
            url: "https://api.example.test/team/v1/spaces".into(),
            scope: app.team_scope().unwrap(),
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
        });
        let time = 1_800_000_000;
        app.spaces = None;
        app.pins[0].personal_seed = Some(false);
        let peer = Session::create().unwrap().0;
        let source = &app.authorities.0[0];
        let mut authority = Authority::new(
            source.genesis().bytes(),
            source.space(),
            &root_key(&app.pins[0].root).unwrap(),
            app.session.credential().clone(),
            source.stream(),
        )
        .unwrap();
        authority.add_credential(peer.credential().clone());
        let mut config = source.head().unwrap().clone();
        config.chat_kind = Some(ChatKind::Direct);
        config.members.push(Member {
            identity_id: peer.identity_id(),
            identity_type: "HUMAN".into(),
            root_public_key: peer.credential().record().body()["root_public_key"]
                .as_str()
                .unwrap()
                .into(),
            capabilities: vec![Capability::Read, Capability::Post],
            credential_ids: vec![peer.credential().id()],
            external: false,
        });
        config.members.sort_by_key(|member| member.identity_id);
        config.action = ConfigAction {
            operation: "replace".into(),
            actor_identity: app.session.identity_id(),
            request_record_id: None,
        };
        authority
            .apply_config(config.sign(app.session.signing_key()).unwrap())
            .unwrap();
        app.authorities.0[0] = authority;
        app.pins[0].chat_kind = Some(ChatKind::Direct);
        let initial = app.call_delegate_bindings(time, vec![]).await.unwrap();
        let first_key = Zeroizing::new(initial[0].delegate.clone());
        let authority = &mut app.authorities.0[0];
        let mut config = authority.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = authority.head_id();
        config.nonce = crate::record::random_hex::<16>().unwrap();
        authority
            .apply_config(config.sign(app.session.signing_key()).unwrap())
            .unwrap();
        let fresh = app.call_delegate_bindings(time + 1, initial).await.unwrap();
        assert_ne!(
            fresh[0].delegate.as_slice(),
            first_key.as_slice(),
            "A new head requires a new certificate"
        );
        let saved = Zeroizing::new(serde_json::to_vec(&fresh).unwrap());
        app.update_block(&json!({"expected_identity":app.identity_id(),"identity":peer.identity_id(),"blocked":true,"name":"Synthetic peer"})).unwrap();
        assert!(
            app.call_delegate_bindings(time + 2, fresh)
                .await
                .unwrap()
                .is_empty()
        );
        app.update_block(&json!({"expected_identity":app.identity_id(),"identity":peer.identity_id(),"blocked":false,"name":"Synthetic peer"})).unwrap();
        let authority = &app.authorities.0[0];
        app.store
            .delete_chat_local(authority.space(), authority.stream(), now().unwrap())
            .await
            .unwrap();
        assert!(
            app.call_delegate_bindings(time + 3, serde_json::from_slice(&saved).unwrap())
                .await
                .unwrap()
                .is_empty()
        );
        app.store
            .reveal_local_chat(authority.space(), authority.stream())
            .await
            .unwrap();
        // Revoke a non-owner member: owners must retain their mandatory caps.
        let owner_session = std::mem::replace(&mut app.session, peer);
        let member_binding = app.call_delegate_bindings(time + 4, vec![]).await.unwrap();
        assert_eq!(member_binding.len(), 1);
        let authority = &mut app.authorities.0[0];
        let mut config = authority.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = authority.head_id();
        config.nonce = crate::record::random_hex::<16>().unwrap();
        config
            .members
            .iter_mut()
            .find(|member| member.identity_id == app.session.identity_id())
            .unwrap()
            .capabilities
            .retain(|capability| *capability != Capability::Post);
        authority
            .apply_config(config.sign(owner_session.signing_key()).unwrap())
            .unwrap();
        assert!(
            app.call_delegate_bindings(time + 5, member_binding)
                .await
                .unwrap()
                .is_empty()
        );
        app.session = owner_session;
        app.close().await.unwrap();
    }

    #[test]
    fn delegated_calls_use_the_pinned_call_service_and_respect_disabled_services() {
        let mut profile = crate::app::hosting_services::test_profile(1);
        profile.call_url = Some("https://separate-calls.example.test/calls/v1".into());
        assert_eq!(
            call_audience(Some(&profile), "https://api.example.test/team/v1/spaces")
                .unwrap()
                .unwrap()
                .as_str(),
            "https://separate-calls.example.test/calls/v1"
        );
        profile.call_url = None;
        assert!(
            call_audience(Some(&profile), "https://api.example.test/team/v1/spaces")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            call_audience(
                None,
                "https://public.example.test:9443/spaces/abcd/team/v1/spaces"
            )
            .unwrap()
            .unwrap()
            .as_str(),
            "https://public.example.test:9443/calls/v1"
        );
    }

    #[tokio::test]
    async fn authenticated_unknown_config_stops_sending_without_creating_content() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic freshness password".into(),
                "General",
            )
            .await
            .unwrap();
        let authority = app.authorities.0[0].clone();
        let body = json!({"v":1,"kind":"chat.message","space_id":authority.space(),"stream_id":authority.stream(),"config_id":"ef".repeat(32),"issuer_credential":app.session.credential().id()});
        let unknown = crate::identity::generate_signing_key().unwrap();
        let scope = realtime::Scope {
            space_context: String::new(),
            space: authority.space(),
            stream: authority.stream(),
        };
        let mut live = None;
        for (seq, key) in [(1, &unknown), (2, app.session.signing_key())] {
            let record = SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), key).unwrap();
            let cipher =
                crypto::seal_record(&record, &[app.session.age_identity().to_public()]).unwrap();
            let entry = InventoryEntry {
                arrival_seq: seq,
                object_id: ObjectId::of_ciphertext(&cipher),
                size_bytes: cipher.len() as u64,
                transfer_hint: TransferHint::Eager,
            };
            app.store
                .stage_inbox(
                    "ab".repeat(32).parse().unwrap(),
                    "cd".repeat(32).parse().unwrap(),
                    "12".repeat(32),
                    entry,
                    Some(cipher),
                    now().unwrap(),
                )
                .await
                .unwrap();
            let item = app.store.pending_inbox(1).await.unwrap().remove(0);
            app.store.defer_inbox(item, false).await.unwrap();
            if seq == 1 {
                app.call_host = Some(space_service::SpaceAddress {
                    service_credential: None,
                    url: "http://127.0.0.1:9/team/v1/spaces".into(),
                    scope: app.team_scope().unwrap(),
                    message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
                });
                let probe = app.membership_probe().unwrap();
                app.accept_membership_probe(
                    probe,
                    &json!({"chat_heads":[{"head":authority.head_id()}]}),
                )
                .await
                .unwrap();
                assert!(
                    app.require_fresh_membership(&authority).await.is_ok(),
                    "an untrusted signature must not claim a config update"
                );
                assert!(!app.invalidate_membership_from_waiting(None).await.unwrap());
                let snapshot = app.realtime_snapshot();
                assert!(
                    snapshot
                        .seal(&scope, realtime::Payload::Typing { active: true }, 1_000)
                        .is_ok()
                );
                live = Some(snapshot);
            }
        }
        assert!(app.invalidate_membership_from_waiting(None).await.unwrap());
        assert!(
            live.unwrap()
                .seal(&scope, realtime::Payload::Typing { active: true }, 1_000)
                .is_err(),
            "verified pending config evidence invalidates already captured live snapshots"
        );
        let before = app.store.stats().await.unwrap();
        let error=app.operate(json!({"op":"send","space":authority.space(),"stream":authority.stream(),"text":"Must not encrypt","created_at":"2026-09-23T10:00:00Z"})).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("permissions need to be refreshed")
        );
        assert_eq!(app.store.stats().await.unwrap().records, before.records);
        app.close().await.unwrap();
    }
}

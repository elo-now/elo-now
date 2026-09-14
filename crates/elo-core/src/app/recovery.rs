use super::*;
use crate::ids::ObjectId;

impl ClientApp {
    fn recovery_input(&self, v: &Value) -> Result<(Vec<u8>, Authority, Pin)> {
        let mut p = Pin {
            chat_kind: None,
            space: field(v, "space")?.parse()?,
            stream: field(v, "stream")?.parse()?,
            root: field(v, "root")?.into(),
            name: field(v, "name")?.into(),
            group: None,
            created_at: now()?.as_millis(),
        };
        if p.name.is_empty() || p.name.len() > 120 {
            return Err("invalid channel name".into());
        }
        let bytes = read_exchange(Path::new(field(v, "path")?), MAX_EXCHANGE)?;
        let a = Authority::open_snapshot(
            &bytes,
            self.session.age_identity(),
            p.space,
            &root_key(&p.root)?,
            p.stream,
        )?;
        p.chat_kind = Some(chats::imported_kind(&a, self.session.identity_id())?);
        Ok((bytes, a, p))
    }
    pub(super) fn confirm_recovery_import(v: &Value, bytes: &[u8], a: &Authority) -> Result<()> {
        if v["confirmed_recovery"] != true
            || v["expected_proof"] != json!(ObjectId::of_ciphertext(bytes))
            || v["expected_config"] != json!(a.head_id())
            || v["expected_recovery"] != json!(a.recovery_id())
        {
            return Err(
                "review and explicitly confirm this exact recovery checkpoint and member list"
                    .into(),
            );
        }
        Ok(())
    }
    pub(super) async fn recovery_operation(&mut self, v: Value) -> Result<Value> {
        match field(&v, "op")? {
            "device_export" => {
                write_export(
                    Path::new(field(&v, "output")?),
                    self.session.credential().record().bytes(),
                )?;
            }
            "recovery_export" => {
                let i = self.authority_index(&v)?;
                let a = &self.authorities.0[i];
                let own = self.session.credential();
                if !self.authorities.space_ready(a)
                    || !a.has(a.head_id().ok_or("head")?, own.identity(), Capability::Read)
                    || !a
                        .head()?
                        .members
                        .iter()
                        .any(|m| m.credential_ids.contains(&own.id()))
                {
                    return Err("current reader proof required".into());
                }
                let bytes = read_exchange(Path::new(field(&v, "path")?), record::MAX_RECORD)?;
                let candidate = VerifiedCredential::verify(
                    &bytes,
                    &root_key(field(
                        a.initial_controller().record().body(),
                        "root_public_key",
                    )?)?,
                )?;
                if candidate.identity() != a.initial_controller().identity()
                    || v["credential"] != json!(candidate.id())
                {
                    return Err("confirm the recovered owner's new device fingerprint".into());
                }
                // Only configuration proofs are exported. This does not enroll
                // the candidate or disclose messages or device secrets.
                write_export(
                    Path::new(field(&v, "output")?),
                    &a.seal_snapshot(&candidate.recipient())?,
                )?;
            }
            "recovery_preview" | "config_preview" => {
                let (bytes, a, _) = self.recovery_input(&v)?;
                if field(&v, "op")? == "recovery_preview"
                    && self.session.identity_id() != a.initial_controller().identity()
                {
                    return Err("recovery belongs to the original controller owner".into());
                }
                let local = self
                    .authorities
                    .0
                    .iter()
                    .find(|p| p.space() == a.space() && p.stream() == a.stream());
                return Ok(
                    json!({"expected_proof":ObjectId::of_ciphertext(&bytes),"expected_config":a.head_id(),"expected_recovery":a.recovery_id(),"controller":a.controller().id(),"new_device":self.session.credential().id(),"members":a.head()?.members,"forked":a.is_forked(),"local_head":local.and_then(Authority::head_id),"warning_code":"recovery_requires_review","warning":"Check the members and permissions with surviving participants. This file does not prove global freshness. Recovery replaces all devices of the controlling owner; old keys and history are not recovered. Offline clients may not know about the change."}),
                );
            }
            "controller_recover" => {
                let (bytes, mut incoming, pin) = self.recovery_input(&v)?;
                Self::confirm_recovery_import(&v, &bytes, &incoming)?;
                if incoming.is_forked()
                    || incoming.initial_controller().identity() != self.session.identity_id()
                {
                    return Err("conflicting proof or wrong recovery owner".into());
                }
                let card_bytes =
                    Zeroizing::new(vault::read_private(Path::new(field(&v, "recovery_card")?))?);
                let card: RecoveryCard = serde_json::from_slice(&card_bytes)?;
                let root = card.recover_root(self.session.identity_id())?;
                let existing = if let Some(cipher) =
                    self.store.authority_snapshot(pin.space, pin.stream).await?
                {
                    Some(Authority::open_snapshot(
                        &cipher,
                        self.session.age_identity(),
                        pin.space,
                        &root_key(&pin.root)?,
                        pin.stream,
                    )?)
                } else {
                    None
                };
                let index = self
                    .pins
                    .iter()
                    .position(|p| p.space == pin.space && p.stream == pin.stream);
                // Resume after a crash between SQLite, workspace and vault
                // writes. Never sign a second certificate for the same retry.
                let a = if let Some(saved) = existing.as_ref().filter(|a| {
                    a.controller().id() == self.session.credential().id()
                        && a.recovery_id().is_some()
                }) {
                    let chain = saved.controller_recovery_chain()?;
                    let last = chain.last().ok_or("recovery proof")?;
                    let body: crate::authority::ControllerRecovery = last.decode()?;
                    let mut c = saved.head()?;
                    while c.recovery.is_none() {
                        c = saved.config(c.previous_config_id.ok_or("recovery checkpoint")?)?;
                    }
                    if !self.authorities.space_ready(saved)
                        || body.previous_recovery_id != incoming.recovery_id()
                        || c.previous_config_id != incoming.head_id()
                    {
                        return Err("a different recovery is already installed; load its current configuration".into());
                    }
                    saved.clone()
                } else {
                    if let Some(local) = &existing
                        && (local.is_forked()
                            || local
                                .head_id()
                                .is_some_and(|id| incoming.config(id).is_err()))
                    {
                        return Err(
                            "checkpoint omits known local changes; obtain current proofs".into(),
                        );
                    }
                    incoming.add_credential(self.session.credential().clone());
                    // The same Space certificate is reused across its Streams.
                    let reuse = self
                        .authorities
                        .0
                        .iter()
                        .filter(|a| a.space() == pin.space)
                        .map(Authority::controller_recovery_chain)
                        .collect::<record::Result<Vec<_>>>()?
                        .into_iter()
                        .flatten()
                        .find(|r| {
                            r.decode::<crate::authority::ControllerRecovery>()
                                .is_ok_and(|b| {
                                    b.controller_credential_id == self.session.credential().id()
                                        && b.previous_recovery_id == incoming.recovery_id()
                                })
                        });
                    let cert = match reuse {
                        Some(r) => r,
                        None => {
                            if !self.authorities.space_ready(&incoming) {
                                return Err("Space already has a newer or conflicting recovery; obtain its proof".into());
                            }
                            incoming.sign_recovery(self.session.credential(), &root)?
                        }
                    };
                    let recovered = incoming.prepare_recovery(&cert, self.session.signing_key())?;
                    let mut approved = incoming.clone();
                    approved.apply_config(recovered.clone())?;
                    if !self.authorities.space_ready(&approved) {
                        return Err("Space has a newer or conflicting controller recovery".into());
                    }
                    let mut a = incoming
                        .merge_into_store(
                            existing.as_ref(),
                            &self.store,
                            self.session.age_identity(),
                            now()?,
                        )
                        .await?;
                    a.commit_update(&self.store, recovered, self.session.age_identity(), now()?)
                        .await?;
                    a
                };
                if let Some(i) = index {
                    self.authorities.0[i] = a;
                } else {
                    self.pins.push(pin);
                    self.authorities.0.push(a);
                }
                self.persist_workspace()?;
                let i = self.authority_index(&v)?;
                let before = self.session.controller_mode;
                let previous_spaces = self.session.controller_spaces.clone();
                self.session
                    .activate_recovered_controller(&self.authorities.0[i])?;
                if let Err(e) = self.persist_vault() {
                    self.session.controller_mode = before;
                    self.session.controller_spaces = previous_spaces;
                    return Err(e);
                }
            }
            _ => return Err("unsupported recovery operation".into()),
        }
        Ok(json!({"view":self.view().await?,"result":{"status":"completed"}}))
    }
}

//! Explicit, bounded recovery exchanges for native pickers; no renderer paths.
use super::*;

const REQUEST_PREFIX: &str = "elo-control:1:";
pub const MAX_CONTROL_PACKAGE: usize = 12 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    v: u8,
    kind: String,
    space: SpaceId,
    stream: StreamId,
    root: String,
    hosting_space: Option<SpaceId>,
    name: String,
    ciphertext: String,
}

pub fn parse_package(bytes: &[u8]) -> Result<Value> {
    record::strict_json(bytes, MAX_CONTROL_PACKAGE)
        .map_err(|_| "Invalid management recovery file.".into())
}

impl ClientApp {
    pub fn control_recovery_device(&self) -> RecordId {
        self.session.credential().id()
    }

    pub fn control_recovery_request(&self) -> String {
        format!(
            "{REQUEST_PREFIX}{}",
            STANDARD.encode(self.session.credential().record().bytes())
        )
    }

    fn recovery_candidate(&self, request: &str) -> Result<VerifiedCredential> {
        if request.len() > 16 * 1024 {
            return Err("Invalid management recovery request.".into());
        }
        let bytes = STANDARD.decode(
            request
                .strip_prefix(REQUEST_PREFIX)
                .ok_or("Invalid management recovery request.")?,
        )?;
        let record = SignedRecord::parse(&bytes)?;
        Ok(VerifiedCredential::verify(
            &bytes,
            &root_key(field(record.body(), "root_public_key")?)?,
        )?)
    }

    pub async fn control_recovery_choices(&self, request: &str) -> Result<Value> {
        let client = self.selected_space_client()?;
        client.control_recovery_choices_local(request).await
    }

    async fn control_recovery_choices_local(&self, request: &str) -> Result<Value> {
        let candidate = self.recovery_candidate(request)?;
        let mut chats = Vec::new();
        for (a, p) in self.authorities.0.iter().zip(&self.pins).filter(|(a, _)| {
            a.initial_controller().identity() == candidate.identity()
                && a.controller().id() != candidate.id()
                && self.authorities.space_ready(a)
                && a.head().is_ok_and(|c| {
                    c.members.iter().any(|m| {
                        m.credential_ids.contains(&self.session.credential().id())
                            && m.capabilities.contains(&Capability::Read)
                    })
                })
        }) {
            if self.is_personal_seed(p, a)? && self.originals(a).await?.is_empty() {
                continue;
            }
            chats.push(json!({"space":a.space(),"stream":a.stream(),"name":p.name}));
        }
        Ok(json!({"identity":candidate.identity(),"device":candidate.id(),"chats":chats}))
    }

    pub async fn control_recovery_export(
        &self,
        request: &str,
        space: SpaceId,
        stream: StreamId,
        confirmed_device: RecordId,
    ) -> Result<Value> {
        self.selected_space_client()?
            .control_recovery_export_local(request, space, stream, confirmed_device)
            .await
    }

    async fn control_recovery_export_local(
        &self,
        request: &str,
        space: SpaceId,
        stream: StreamId,
        confirmed_device: RecordId,
    ) -> Result<Value> {
        let candidate = self.recovery_candidate(request)?;
        if candidate.id() != confirmed_device {
            return Err("Confirm the recovery device first.".into());
        }
        let i = self.authority_index(&json!({"space":space,"stream":stream}))?;
        let authority = &self.authorities.0[i];
        if self.is_personal_seed(&self.pins[i], authority)?
            && self.originals(authority).await?.is_empty()
        {
            return Err("This profile cannot help recover management of this chat.".into());
        }
        if authority.initial_controller().identity() != candidate.identity()
            || !self.authorities.space_ready(authority)
            || !authority.head()?.members.iter().any(|m| {
                m.credential_ids.contains(&self.session.credential().id())
                    && m.capabilities.contains(&Capability::Read)
            })
        {
            return Err("This profile cannot help recover management of this chat.".into());
        }
        self.control_package(
            i,
            "recover",
            authority.seal_snapshot_signed(&candidate.recipient(), self.session.signing_key())?,
        )
    }

    fn control_package(&self, i: usize, kind: &str, ciphertext: Vec<u8>) -> Result<Value> {
        let p = &self.pins[i];
        Ok(serde_json::to_value(Package {
            v: 1,
            kind: kind.into(),
            space: p.space,
            stream: p.stream,
            root: p.root.clone(),
            hosting_space: self.call_host.as_ref().map(|h| h.scope.space),
            name: p.name.clone(),
            ciphertext: STANDARD.encode(ciphertext),
        })?)
    }

    fn control_package_request(&self, package: &Value) -> Result<Value> {
        let p: Package = serde_json::from_value(package.clone())?;
        if p.v != 1
            || !["recover", "adopt"].contains(&p.kind.as_str())
            || p.name.is_empty()
            || p.name.len() > 120
            || p.name.chars().any(record::unsafe_display_character)
            || p.ciphertext.len() > MAX_CONTROL_PACKAGE
        {
            return Err("Invalid management recovery file.".into());
        }
        if p.hosting_space != self.call_host.as_ref().map(|h| h.scope.space) {
            return Err("Open the original Space before recovering this chat.".into());
        }
        if let Some(pin) = self
            .pins
            .iter()
            .find(|pin| pin.space == p.space && pin.stream == p.stream)
        {
            if pin.root != p.root {
                return Err("The recovery file belongs to a different Space.".into());
            }
        }
        Ok(
            json!({"space":p.space,"stream":p.stream,"root":p.root,"name":p.name,"ciphertext":p.ciphertext,"kind":p.kind}),
        )
    }

    pub async fn control_recovery_preview(&mut self, package: &Value) -> Result<Value> {
        self.selected_space_client_mut()?
            .control_recovery_preview_local(package)
            .await
    }

    async fn control_recovery_preview_local(&mut self, package: &Value) -> Result<Value> {
        let mut request = self.control_package_request(package)?;
        request["op"] = if request["kind"] == "recover" {
            "recovery_preview"
        } else {
            "config_preview"
        }
        .into();
        let mut preview = self.recovery_operation(request.clone()).await?;
        preview["name"] = request["name"].clone();
        preview["space"] = request["space"].clone();
        preview["stream"] = request["stream"].clone();
        preview["kind"] = request["kind"].clone();
        preview["package_id"] = crate::ids::ObjectId::of_ciphertext(&serde_json::to_vec(package)?)
            .to_string()
            .into();
        let i = self.pins.iter().position(|p| {
            json!(p.space) == request["space"] && json!(p.stream) == request["stream"]
        });
        preview["known_chat"] = i.is_some().into();
        if request["kind"] == "recover" {
            // Show the exact resulting device set, not the superseded owner's devices.
            for member in preview["members"]
                .as_array_mut()
                .ok_or("Invalid recovery members.")?
            {
                if member["identity_id"] == json!(self.session.identity_id()) {
                    member["credential_ids"] = json!([self.session.credential().id()]);
                }
            }
        }

        Ok(preview)
    }

    pub async fn control_recovery_confirm(
        &mut self,
        package: &Value,
        confirmation: &Value,
        words: &str,
    ) -> Result<Value> {
        self.selected_space_client_mut()?
            .control_recovery_confirm_local(package, confirmation, words)
            .await
    }

    async fn control_recovery_confirm_local(
        &mut self,
        package: &Value,
        confirmation: &Value,
        words: &str,
    ) -> Result<Value> {
        let preview = self.control_recovery_preview_local(package).await?;
        for key in [
            "package_id",
            "expected_proof",
            "expected_config",
            "expected_recovery",
        ] {
            if preview[key] != confirmation[key] {
                return Err("The recovery file changed. Review it again.".into());
            }
        }
        if confirmation["confirmed"] != true {
            return Err("Review the members and confirm recovery first.".into());
        }
        let mut request = self.control_package_request(package)?;
        request["confirmed_recovery"] = true.into();
        for key in ["expected_proof", "expected_config", "expected_recovery"] {
            request[key] = preview[key].clone();
        }
        if request["kind"] == "recover" {
            request["op"] = "controller_recover".into();
            request["recovery_words"] = words.into();
            self.recovery_operation(request).await
        } else {
            request["op"] = "import_stream".into();
            self.operate_local(request).await
        }
    }

    pub fn control_recovery_share(&self, space: SpaceId, stream: StreamId) -> Result<Value> {
        self.selected_space_client()?
            .control_recovery_share_local(space, stream)
    }

    fn control_recovery_share_local(&self, space: SpaceId, stream: StreamId) -> Result<Value> {
        let i = self.authority_index(&json!({"space":space,"stream":stream}))?;
        let a = &self.authorities.0[i];
        self.require_controller(a)?;
        if a.recovery_id().is_none() {
            return Err("Recover management before sharing the change.".into());
        }
        let recipients = a
            .head()?
            .members
            .iter()
            .filter(|m| m.capabilities.contains(&Capability::Read))
            .flat_map(|m| m.credential_ids.iter())
            .map(|id| a.credential(*id).map(|c| c.recipient()))
            .collect::<record::Result<Vec<_>>>()?;
        let mut signed = a.clone();
        signed.accept_cached_checkpoint(a.sign_checkpoint(self.session.signing_key())?)?;
        self.control_package(
            i,
            "adopt",
            signed.seal_snapshot_for_recipients(&recipients)?,
        )
    }
}

#[cfg(test)]
pub(super) mod tests;

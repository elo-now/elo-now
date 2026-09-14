//! Read-only expert projection. Signed history and local diagnostics are distinct.
use super::*;

impl ClientApp {
    pub(super) async fn message_debug(&self, request: &Value) -> Result<Value> {
        let index = self.authority_index(request)?;
        let authority = &self.authorities.0[index];
        let id: RecordId = field(request, "record")?.parse()?;
        let records = self.originals(authority).await?;
        let (message, state) = records
            .iter()
            .find(|(r, _)| {
                r.id() == id
                    && matches!(
                        r.body()["kind"].as_str(),
                        Some("chat.message" | "file.shared")
                    )
            })
            .ok_or("This message is not available in this chat.")?;
        let mut names = BTreeMap::<String, String>::new();
        for (r, _) in &records {
            if let (Some(identity), Some(name)) = (
                r.body()["issuer_identity"].as_str(),
                r.body()["payload"]["sender_name"].as_str(),
            ) {
                names.insert(identity.into(), name.into());
            }
        }
        if let Some(profile) = &self.profile_details {
            names.insert(self.session.identity_id().to_string(), profile.name.clone());
        }
        let mut actions = Vec::new();
        for (r, _) in &records {
            if r.body()["kind"] != "chat.action" {
                continue;
            }
            let chat = r.chat()?;
            let Some(action) = chat.payload.action.filter(|a| a.target() == id) else {
                continue;
            };
            let actor = chat.issuer_identity.to_string();
            actions.push(json!({"id":r.id(),"actor":actor,"name":names.get(&actor),"at":chat.created_at,"action":action}));
        }
        let actions_total = actions.len();
        if actions.len() > 200 {
            actions.drain(..actions.len() - 200);
        }
        let mut result = self.store.message_audit(id).await?;
        if let Some(targets) = result["targets"].as_array_mut() {
            for target in targets {
                if let Some(peer) =
                    self.session
                        .peers()
                        .iter()
                        .zip(&self.peers)
                        .find(|(descriptor, peer)| {
                            target["peer"] == json!(peer.id())
                                && target["mailbox"] == json!(descriptor.mailbox_id)
                        })
                {
                    // Peer enrollment forbids userinfo, query, fragments and hidden paths.
                    target["endpoint"] = json!(
                        reqwest::Url::parse(&peer.0.url)?
                            .origin()
                            .ascii_serialization()
                    );
                }
            }
        }
        let author = message.body()["issuer_identity"]
            .as_str()
            .unwrap_or_default();
        result["record"] = json!(id);
        result["state"] = json!(state);
        result["author"] = json!(author);
        result["author_name"] = json!(names.get(author));
        result["credential"] = message.body()["issuer_credential"].clone();
        result["created_at"] = message.body()["created_at"].clone();
        result["config"] = message.body()["config_id"].clone();
        result["actions"] = json!(actions);
        result["actions_total"] = json!(actions_total);
        Ok(result)
    }
}

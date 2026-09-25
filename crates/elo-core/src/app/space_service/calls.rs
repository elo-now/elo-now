//! Durable conversation authorization, with current device sets and pinned heads.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublishedHead {
    pub head: RecordId,
    sequence: u64,
    recovery: Option<RecordId>,
    #[serde(default)]
    pub credentials: Vec<RecordId>,
}

impl ClientApp {
    pub(super) fn publish_space_call_head(
        &self,
        state: &mut ServiceState,
        credential: &VerifiedCredential,
        body: &Value,
    ) -> Result<Value> {
        let general = self.authorities.0.first().ok_or("Space unavailable.")?;
        if crate::calls::require_member(general, credential.id()).ok()
            != Some(credential.identity())
            || !state
                .applicants
                .values()
                .any(|a| a.identity == credential.identity() && a.status == "approved")
        {
            return Err("This device cannot publish chat permissions.".into());
        }
        let space: SpaceId = field(body, "space")?.parse()?;
        let stream: StreamId = field(body, "stream")?.parse()?;
        if space == general.space() && stream == general.stream() {
            return Err("General permissions are managed by the Space.".into());
        }
        let proof: crate::authority::CallAuthorityProof =
            serde_json::from_value(body["proof"].clone())?;
        let authority = proof.verify(space, stream)?;
        let head = authority.head_id().ok_or("Chat permissions unavailable.")?;
        let sequence = authority.head()?.sequence;
        let key = format!("{space}:{stream}");
        if let Some(previous) = state.call_heads.get(&key) {
            if !authority.proves_recovery_ancestor(previous.recovery) {
                return Err("Chat permissions have changed. Sync before trying again.".into());
            }
            if previous.head != head
                && (sequence <= previous.sequence
                    || !authority.proves_config_at(previous.head, previous.sequence))
            {
                return Err("Chat permissions have changed. Sync before trying again.".into());
            }
        } else {
            // Register before the first invitation. A removed member's old proof
            // and a recovered backup can never establish an unknown call scope.
            if sequence != 1 || authority.controller().id() != credential.id() {
                return Err("This chat has no registered call permissions.".into());
            }
            if state.call_heads.len() >= 4096 {
                return Err("Space call permission limit reached.".into());
            }
        }
        let credentials = authority
            .head()?
            .members
            .iter()
            .flat_map(|m| m.credential_ids.iter().copied())
            .collect();
        state.call_heads.insert(
            key,
            PublishedHead {
                head,
                sequence,
                recovery: authority.recovery_id(),
                credentials,
            },
        );
        self.save_service_state(state)?;
        Ok(json!({"head":head}))
    }

    pub(super) fn check_space_chat_head(
        &self,
        state: &ServiceState,
        credential: &VerifiedCredential,
        body: &Value,
    ) -> Result<Value> {
        let general = self.authorities.0.first().ok_or("Space unavailable.")?;
        if state.erased_accounts.contains(&credential.identity()) {
            return Err("This account was deleted from this service.".into());
        }
        crate::calls::require_member(general, credential.id())?;
        let space: SpaceId = field(body, "space")?.parse()?;
        let stream: StreamId = field(body, "stream")?.parse()?;
        let expected: RecordId = field(body, "head")?.parse()?;
        let (head, credentials) = if general.space() == space && general.stream() == stream {
            (
                general.head_id().ok_or("Chat permissions unavailable.")?,
                general
                    .head()?
                    .members
                    .iter()
                    .flat_map(|m| m.credential_ids.iter().copied())
                    .collect::<Vec<_>>(),
            )
        } else {
            let published = state
                .call_heads
                .get(&format!("{space}:{stream}"))
                .ok_or("Chat permissions need to be refreshed.")?;
            (published.head, published.credentials.clone())
        };
        if head != expected || !credentials.contains(&credential.id()) {
            return Err("Chat permissions need to be refreshed.".into());
        }
        let current: std::collections::BTreeSet<_> = general
            .head()?
            .members
            .iter()
            .flat_map(|m| m.credential_ids.iter().copied())
            .collect();
        if credentials.iter().any(|id| !current.contains(id)) {
            return Err("Chat devices have changed. The chat owner needs to update access.".into());
        }
        Ok(json!({"head":head,"checked_at":time()?}))
    }
}

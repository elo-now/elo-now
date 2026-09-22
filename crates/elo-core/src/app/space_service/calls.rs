//! Durable private-conversation authorization. Only opaque heads are retained.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublishedHead {
    pub head: RecordId,
    sequence: u64,
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
            if previous.head == head {
                return Ok(json!({"head":head}));
            }
            if sequence <= previous.sequence || authority.config(previous.head).is_err() {
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
        state
            .call_heads
            .insert(key, PublishedHead { head, sequence });
        self.save_service_state(state)?;
        Ok(json!({"head":head}))
    }
}

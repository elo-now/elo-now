//! Bounded, durable first-writer selection under the hosting Space mutex.
use super::*;

impl PublicSpaceService {
    pub(super) fn notes_command(
        &self,
        state: &mut ServiceState,
        credential: &VerifiedCredential,
        body: &Value,
    ) -> Result<Value> {
        let general = &self.authorities.0[0];
        if body["general_head"] != json!(general.head_id())
            || state.revoked.contains(&credential.id())
            || state.erased_accounts.contains(&credential.identity())
            || crate::calls::require_member(general, credential.id())? != credential.identity()
        {
            return Err("General permissions have changed. Refresh and try again.".into());
        }
        let identity = credential.identity();
        let stored = state.notes.get(&identity).cloned();
        if let Some(value) = body.get("proof").filter(|value| !value.is_null()) {
            if serde_json::to_vec(value)?.len() > crate::notes::MAX_PROOF {
                return Err("Notes authority is too large.".into());
            }
            let proof: CallAuthorityProof = serde_json::from_value(value.clone())?;
            let next = crate::notes::verify(&proof, general, identity)?;
            if next.controller().id() != credential.id() {
                return Err("Only the Notes controller can update its devices.".into());
            }
            if let Some(previous) = &stored {
                let genesis = decode_record(&previous.genesis)?;
                let prior = previous.verify(
                    SpaceId::from_bytes(*genesis.id().as_bytes()),
                    crate::notes::stream(general.space(), general.stream(), identity),
                )?;
                // A competing initial creation loses without registering an
                // orphan chat. The caller must verify and use the winner.
                if next.space() != prior.space() {
                    return Ok(json!({"proof":previous,"general_head":general.head_id()}));
                }
                if next.head_id() == prior.head_id() {
                    return Ok(json!({"proof":previous,"general_head":general.head_id()}));
                }
                if body["expected_head"] != json!(prior.head_id())
                    || !next.proves_config_at(
                        prior.head_id().ok_or("Missing Notes head.")?,
                        prior.head()?.sequence,
                    )
                    || !next.proves_recovery_ancestor(prior.recovery_id())
                {
                    return Err("Notes have changed. Refresh and try again.".into());
                }
            } else if !body["expected_head"].is_null()
                || next.head()?.sequence != 1
                || state.notes.len() >= 1000
            {
                return Err("Notes cannot be registered.".into());
            }
            // Existing call-head admission enforces ancestry and publishes the
            // exact device set used by normal sends and attachment operations.
            self.record_space_call_head(
                state,
                credential,
                &json!({
                    "space":next.space(),"stream":next.stream(),"proof":proof
                }),
            )?;
            state.notes.insert(identity, proof);
            self.save_service_state(state)?;
        }
        Ok(json!({"proof":state.notes.get(&identity),"general_head":general.head_id()}))
    }
}

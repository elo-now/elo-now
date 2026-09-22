use super::*;
use crate::calls::{self, Operation, SignalPayload};

impl ClientApp {
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
                    "space":next.space(), "stream":next.stream(), "proof":next.call_proof()?
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
                    "proof":if request["include_proof"] == true { Some(authority.call_proof()?) } else { None }}))
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
                let ciphertext = calls::seal_signal(
                    authority,
                    &self.session,
                    field(request, "call_id")?,
                    recipient,
                    payload,
                    time,
                )?;
                Ok(json!({"ciphertext":ciphertext}))
            }
            "call_open_signal" => {
                let signal = calls::open_signal(
                    authority,
                    &self.session,
                    field(request, "call_id")?,
                    field(request, "ciphertext")?,
                    time,
                )?;
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

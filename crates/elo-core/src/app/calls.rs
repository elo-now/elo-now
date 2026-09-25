use super::*;
use crate::calls::{self, Operation, SignalPayload};

impl ClientApp {
    /// New content requires a recent, nonce-bound signed answer from the pinned
    /// host. Local evidence of unknown permissions always overrides that lease.
    pub(super) async fn require_fresh_membership(&self, authority: &Authority) -> Result<()> {
        // A valid signature from a known participant referring to an unknown
        // config is a reason to stop, even before the host's head check.
        let mut after = String::new();
        for page in 0..128 {
            let waiting = self.store.waiting_objects(after).await?;
            for (_, bytes) in &waiting {
                if let Ok(record) = crypto::open_object(bytes, self.session.age_identity()) {
                    let body = record.body();
                    if body["space_id"] == json!(authority.space())
                        && body["stream_id"] == json!(authority.stream())
                        && let (Some(issuer), Some(config)) = (
                            body["issuer_credential"]
                                .as_str()
                                .and_then(|id| id.parse().ok()),
                            body["config_id"].as_str().and_then(|id| id.parse().ok()),
                        )
                        && authority.config(config).is_err()
                        && authority
                            .credential(issuer)
                            .is_ok_and(|c| record.verify_signature(c.key()).is_ok())
                    {
                        self.invalidate_membership_checks().await;
                        return Err("Chat permissions need to be refreshed.".into());
                    }
                }
            }
            if waiting.is_empty() {
                break;
            }
            if page == 127 {
                self.invalidate_membership_checks().await;
                return Err("Chat permissions need to be refreshed.".into());
            }
            after = waiting.last().unwrap().0.to_string();
        }
        self.check_host_membership(authority).await
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

#[cfg(test)]
mod freshness_tests {
    use super::*;
    use crate::ids::ObjectId;
    use crate::replica::{InventoryEntry, TransferHint};

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
                    url: "http://127.0.0.1:9/team/v1/spaces".into(),
                    scope: app.team_scope().unwrap(),
                    message_lifetime_seconds: 86400,
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
            }
        }
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

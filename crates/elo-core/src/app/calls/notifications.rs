//! Recipient-encrypted session and ringing hints. A native read of current
//! signed call authorization precedes every notification handoff.
use super::*;
use std::time::Duration;

const TTL: u64 = 60;

fn ready_expiry(
    call: &Value,
    authority: &Authority,
    hosting: SpaceId,
    identity: IdentityId,
    credential: RecordId,
    call_id: &str,
    time: u64,
) -> Result<Option<u64>> {
    record::hex::<16>(call_id)?;
    let ready_at = call["ready_at"].as_u64().unwrap_or(0);
    if call["call_id"] != call_id
        || call["scope"]["hosting_space_id"] != json!(hosting)
        || call["scope"]["conversation"]["space_id"] != json!(authority.space())
        || call["scope"]["conversation"]["stream_id"] != json!(authority.stream())
        || call["config_id"] != json!(authority.head_id())
        || call["started_by"] != json!(identity)
        || call["ready"] != true
        || call["participants"][identity.to_string()]["credential_id"] != json!(credential)
        || call["participants"][identity.to_string()]["ready"] != true
        || ready_at == 0
        || ready_at > time
        || time >= ready_at.saturating_add(TTL)
    {
        return Ok(None);
    }
    Ok(Some((ready_at + TTL) * 1000))
}

impl ClientApp {
    pub(in crate::app) async fn notify_call_ready(&self, request: &Value) -> Result<Value> {
        if self.push_endpoint.is_none() {
            return Ok(json!({"notified":false}));
        }
        let host = self.call_host.as_ref().ok_or("Session unavailable.")?;
        let hosting: SpaceId = field(request, "hosting_space_id")?.parse()?;
        if hosting != host.scope.space {
            return Err("Call Space authorization mismatch.".into());
        }
        let index = self.authority_index(request)?;
        let authority = &self.authorities.0[index];
        self.require_fresh_membership(authority).await?;
        let Some(mut endpoint) = call_audience(self.hosting_services.active.as_ref(), &host.url)?
        else {
            return Ok(json!({"notified":false}));
        };
        let mut authorization = request.clone();
        authorization["op"] = json!("call_authorization");
        authorization["audience"] = json!(endpoint.as_str());
        authorization["operation"] = json!({"type":"subscribe"});
        authorization["include_proof"] = json!(true);
        let body = self.call_operation(&authorization)?;
        endpoint.set_path(&format!("{}/state", endpoint.path().trim_end_matches('/')));
        let mut response = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()?
            .post(endpoint)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err("Session status is unavailable.".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > 512 * 1024 {
                return Err("Invalid session status.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let response: Value = serde_json::from_slice(&bytes)?;
        let call_id = field(request, "call_id")?;
        let call = &response["call"];
        let time = now()?.as_millis() as u64 / 1000;
        let explicit = request["invitation_id"].is_string();
        let matches_scope = call["call_id"] == call_id
            && call["scope"]["hosting_space_id"] == json!(hosting)
            && call["scope"]["conversation"]["space_id"] == json!(authority.space())
            && call["scope"]["conversation"]["stream_id"] == json!(authority.stream())
            && call["config_id"] == json!(authority.head_id());
        if explicit {
            let to: IdentityId = field(request, "to")?.parse()?;
            let invitation = &call["invitations"][to.to_string()];
            if !matches_scope
                || invitation["invitation_id"] != request["invitation_id"]
                || invitation["invited_by"] != json!(self.identity_id())
                || invitation["expires_at"]
                    .as_u64()
                    .is_none_or(|until| until <= time || until > time + TTL)
                || call["participants"][self.identity_id().to_string()]["credential_id"]
                    != json!(self.session.credential().id())
            {
                return Ok(json!({"notified":false}));
            }
            return Ok(serde_json::to_value(
                self.notify_ringing_session(authority, call, Some(to))
                    .await?,
            )?);
        }
        let Some(expires) = ready_expiry(
            &response["call"],
            authority,
            hosting,
            self.identity_id(),
            self.session.credential().id(),
            call_id,
            now()?.as_millis() as u64 / 1000,
        )?
        else {
            return Ok(json!({"notified":false}));
        };
        if call["kind"] == "direct" {
            return Ok(serde_json::to_value(
                self.notify_ringing_session(authority, call, None).await?,
            )?);
        }
        Ok(serde_json::to_value(
            self.notify_ready_session(authority, call_id, expires)
                .await?,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn only_the_current_ready_initiator_can_notify_before_the_original_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic session notification password".into(),
                "General",
            )
            .await
            .unwrap();
        let authority = &app.authorities.0[0];
        let identity = app.identity_id();
        let credential = app.session.credential().id();
        let call_id = "42".repeat(16);
        let valid = json!({"call_id":call_id,"scope":{"hosting_space_id":authority.space(),
            "conversation":{"space_id":authority.space(),"stream_id":authority.stream()}},
            "config_id":authority.head_id(),"started_by":identity,"ready":true,"ready_at":1000,
            "participants":{identity.to_string():{"credential_id":credential,"ready":true}}});
        let check = |call: &Value, time| {
            ready_expiry(
                call,
                authority,
                authority.space(),
                identity,
                credential,
                &call_id,
                time,
            )
            .unwrap()
        };
        assert_eq!(check(&valid, 1001), Some(1_060_000));
        assert_eq!(check(&valid, 1059), Some(1_060_000));
        assert_eq!(check(&valid, 1060), None);
        assert_eq!(check(&valid, 999), None);
        assert_eq!(check(&Value::Null, 1001), None);
        for field in [
            "call_id",
            "config_id",
            "started_by",
            "ready",
            "ready_at",
            "participants",
            "scope",
        ] {
            let mut invalid = valid.clone();
            invalid[field] = Value::Null;
            assert_eq!(check(&invalid, 1001), None, "{field}");
        }
        let mut other_device = valid.clone();
        other_device["participants"][identity.to_string()]["credential_id"] =
            json!(RecordId::from_bytes([99; 32]));
        assert_eq!(check(&other_device, 1001), None);
        app.close().await.unwrap();
    }
}

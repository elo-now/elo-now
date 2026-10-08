//! Call-only background execution. No profile unlock, store handle or history
//! decryption key is reachable from this runtime.
#![cfg_attr(
    not(all(mobile, feature = "mobile-push")),
    allow(dead_code, unused_imports)
)]
use base64::{Engine, engine::general_purpose::STANDARD};
use elo_core::{
    authority::Authority,
    calls::{
        self, Operation,
        delegation::{CallDelegate, CallDelegateBinding, SignalContext, SignalKeys},
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

fn time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct Prepared {
    binding: CallDelegateBinding,
    authority: Authority,
    delegate: CallDelegate,
}
impl Prepared {
    fn load(binding: CallDelegateBinding, now: u64) -> Result<Self, &'static str> {
        let authority = match &binding.witness {
            Some(pin) => {
                binding
                    .proof
                    .verify_witnessed(binding.scope.space_id, binding.scope.stream_id, pin)
            }
            None => binding
                .proof
                .verify(binding.scope.space_id, binding.scope.stream_id),
        }
        .map_err(|_| "unauthorized")?;
        let delegate = CallDelegate::import(
            &binding.delegate,
            &authority,
            binding.hosting_space_id,
            &binding.audience,
            now,
        )
        .map_err(|_| "unauthorized")?;
        if calls::require_member(&authority, binding.credential).map_err(|_| "unauthorized")?
            != binding.identity
            || delegate.body().issuer_credential != binding.credential
            || delegate.body().config_id != binding.config_id
        {
            return Err("unauthorized");
        }
        Ok(Self {
            binding,
            authority,
            delegate,
        })
    }
    fn signed(&self, operation: Operation, now: u64) -> Result<Value, &'static str> {
        let command = self
            .delegate
            .sign_command(&self.authority, operation, now)
            .map_err(|_| "unauthorized")?;
        Ok(
            json!({"command":STANDARD.encode(command.bytes()),"proof":self.binding.proof,
            "delegation":STANDARD.encode(self.delegate.certificate().bytes())}),
        )
    }
    fn validate(
        &self,
        call: &Value,
        target: &calls::ring::RingTarget,
        pending: bool,
    ) -> Result<(), &'static str> {
        if target.recipient != self.binding.identity
            || target.hosting_space_id != self.binding.hosting_space_id
            || target.scope != self.binding.scope
        {
            return Err("unauthorized");
        }
        if call["call_id"] != target.call_id
            || call["scope"]["hosting_space_id"] != json!(self.binding.hosting_space_id)
            || call["scope"]["conversation"]["space_id"] != json!(self.binding.scope.space_id)
            || call["scope"]["conversation"]["stream_id"] != json!(self.binding.scope.stream_id)
            || call["config_id"] != json!(self.binding.config_id)
        {
            return Err("unauthorized");
        }
        let kind = self.authority.head().map_err(|_| "unauthorized")?.chat_kind;
        if call["kind"]
            != match kind {
                Some(elo_core::authority::ChatKind::Direct) => "direct",
                _ => "group",
            }
        {
            return Err("unauthorized");
        }
        let identity = self.binding.identity.to_string();
        if pending {
            let invitation = &call["invitations"][&identity];
            if invitation["invitation_id"] != target.invitation_id
                || invitation["expires_at"].as_u64() != Some(target.expires)
                || target.expires <= time()
                || call["participants"][&identity].is_object()
            {
                return Err("ended");
            }
        }
        for (identity, participant) in call["participants"].as_object().ok_or("invalid")? {
            let credential = participant["credential_id"]
                .as_str()
                .ok_or("invalid")?
                .parse()
                .map_err(|_| "invalid")?;
            if calls::require_member(&self.authority, credential)
                .map_err(|_| "unauthorized")?
                .to_string()
                != *identity
            {
                return Err("unauthorized");
            }
            if let Some(encoded) = participant["delegation"].as_str() {
                let cert =
                    calls::delegation::decode_certificate(encoded).map_err(|_| "unauthorized")?;
                let verified = calls::delegation::verify(
                    &self.authority,
                    &cert,
                    self.binding.hosting_space_id,
                    &self.binding.audience,
                    time(),
                )
                .map_err(|_| "unauthorized")?;
                if verified.body.issuer_credential != credential {
                    return Err("unauthorized");
                }
            }
        }
        Ok(())
    }
    fn context(&self) -> Value {
        let mut members = json!({});
        if let Ok(head) = self.authority.head() {
            for member in &head.members {
                members[member.identity_id.to_string()] = json!(member.credential_ids);
            }
        }
        json!({"expected_identity":self.binding.identity,"target_space":self.binding.space_context,
            "hosting_space_id":self.binding.hosting_space_id,"space":self.binding.scope.space_id,"stream":self.binding.scope.stream_id,
            "kind":match self.authority.head().ok().and_then(|head|head.chat_kind) {Some(elo_core::authority::ChatKind::Direct)=>"direct",_=>"group"},
            "audience":self.binding.audience,"credential":self.binding.credential,"config_id":self.binding.config_id,"members":members})
    }
    fn operation(&self, op: &str, fields: Value, call: &Value) -> Result<Value, &'static str> {
        if op == "call_authorization" {
            return self.signed(
                serde_json::from_value(fields["operation"].clone()).map_err(|_| "invalid")?,
                time(),
            );
        }
        let epoch = fields["epoch"].as_u64().ok_or("invalid")?;
        let call_id = fields["call_id"].as_str().ok_or("invalid")?;
        let context = SignalContext {
            audience: &self.binding.audience,
            hosting_space_id: self.binding.hosting_space_id,
            call_id,
            epoch,
        };
        let peer = if op == "call_encrypt_signal" {
            fields["to"].as_str()
        } else {
            fields["from"].as_str()
        }
        .ok_or("invalid")?;
        let participant = call["participants"]
            .as_object()
            .and_then(|p| p.values().find(|p| p["credential_id"] == peer))
            .ok_or("unauthorized")?;
        let certificate = participant["delegation"]
            .as_str()
            .map(calls::delegation::decode_certificate)
            .transpose()
            .map_err(|_| "unauthorized")?;
        if op == "call_encrypt_signal" {
            let ciphertext = calls::delegation::seal_signal(
                &self.authority,
                SignalKeys::Delegate(&self.delegate),
                context,
                peer.parse().map_err(|_| "invalid")?,
                certificate.as_ref(),
                serde_json::from_value(fields["payload"].clone()).map_err(|_| "invalid")?,
                time(),
            )
            .map_err(|_| "unauthorized")?;
            return Ok(json!({"ciphertext":ciphertext}));
        }
        if op == "call_open_signal" {
            let signal = calls::delegation::open_signal(
                &self.authority,
                SignalKeys::Delegate(&self.delegate),
                context,
                fields["ciphertext"].as_str().ok_or("invalid")?,
                certificate.as_ref(),
                time(),
            )
            .map_err(|_| "unauthorized")?;
            return Ok(json!({"signal":signal}));
        }
        Err("invalid")
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    bindings: Vec<CallDelegateBinding>,
    routes: Vec<RingRoute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_leaves: Vec<PendingLeave>,
}

/// A timed-out Leave may still reach the server. This bounded fence survives a
/// process restart without retaining profile keys or extending command validity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingLeave {
    call_id: String,
    credential: elo_core::ids::RecordId,
    request_id: String,
    until: u64,
}
impl Enrollment {
    fn prune_leaves(&mut self, now: u64) {
        self.pending_leaves.retain(|leave| leave.until > now);
    }
    fn leave_pending(&self, call_id: &str, credential: elo_core::ids::RecordId, now: u64) -> bool {
        self.pending_leaves.iter().any(|leave| {
            leave.call_id == call_id && leave.credential == credential && leave.until > now
        })
    }
    fn begin_leave(&mut self, leave: PendingLeave, now: u64) -> Result<(), &'static str> {
        self.prune_leaves(now);
        if leave.until <= now
            || leave.until > now.saturating_add(calls::COMMAND_TTL)
            || self.pending_leaves.len() >= 32
            || self.leave_pending(&leave.call_id, leave.credential, now)
        {
            return Err("unavailable");
        }
        self.pending_leaves.push(leave);
        Ok(())
    }
    fn acknowledge_leave(&mut self, request_id: &str) {
        self.pending_leaves
            .retain(|leave| leave.request_id != request_id);
    }
}

/// Only the incoming target decryption capability belongs in protected call
/// storage. In particular it must not retain the authority to send wake notices.
#[derive(Serialize)]
struct RingRoute {
    endpoint: String,
    id: String,
    scope_key: String,
}
impl Drop for RingRoute {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scope_key.zeroize();
    }
}
impl From<elo_core::app::push::Route> for RingRoute {
    fn from(route: elo_core::app::push::Route) -> Self {
        use zeroize::Zeroize;
        let elo_core::app::push::Route {
            endpoint,
            id,
            scope_key,
            mut notify_key,
            ..
        } = route;
        notify_key.zeroize();
        Self {
            endpoint,
            id,
            scope_key,
        }
    }
}
impl<'de> Deserialize<'de> for RingRoute {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            endpoint: String,
            id: String,
            scope_key: String,
            // Accept old enrollment without allocating its discarded secrets.
            #[serde(default, rename = "notify_key")]
            _notify_key: serde::de::IgnoredAny,
            #[serde(default, rename = "since")]
            _since: serde::de::IgnoredAny,
        }
        let stored = Stored::deserialize(deserializer)?;
        Ok(Self {
            endpoint: stored.endpoint,
            id: stored.id,
            scope_key: stored.scope_key,
        })
    }
}

#[cfg(all(target_os = "android", feature = "mobile-push"))]
mod android;
#[cfg(all(mobile, feature = "mobile-push"))]
mod mobile;
#[cfg(any(test, all(mobile, feature = "mobile-push")))]
mod presentation;
#[cfg(any(test, all(mobile, feature = "mobile-push")))]
mod transport;
#[cfg(all(mobile, feature = "mobile-push"))]
pub(crate) use mobile::*;
#[cfg(all(mobile, feature = "mobile-push"))]
pub(crate) use transport::send_signed;

#[cfg(not(all(mobile, feature = "mobile-push")))]
#[derive(Default)]
pub(crate) struct Incoming;

#[tauri::command]
pub(crate) async fn native_call_incoming(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::State>,
    identity: String,
    op: String,
) -> Result<Value, String> {
    let runtime = state.lock().await;
    if runtime
        .client
        .as_ref()
        .is_none_or(|client| client.identity_id().to_string() != identity)
    {
        return Err("unauthorized".into());
    }
    if op != "status" {
        return Err("invalid".into());
    }
    #[cfg(all(mobile, feature = "mobile-push"))]
    return mobile::status(&app, &identity).await;
    #[cfg(not(all(mobile, feature = "mobile-push")))]
    {
        let _ = app;
        Ok(json!({"active":null,"presented":[]}))
    }
}

#[cfg(test)]
mod tests;

//! Shared call-only transport for the running app and Android's bounded worker.
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

pub(super) fn lookup(
    enrollment: Enrollment,
    event: &Value,
    now: u64,
) -> Result<(Prepared, calls::ring::RingTarget), &'static str> {
    let registration = event["registration"].as_str().ok_or("invalid")?;
    let encoded = event["target"].as_str().ok_or("invalid")?;
    let route = enrollment
        .routes
        .iter()
        .find(|route| route.id == registration)
        .ok_or("unauthorized")?;
    let endpoint =
        elo_core::app::push::endpoint(&route.endpoint, false).map_err(|_| "unauthorized")?;
    let target =
        calls::ring::open(&route.scope_key, &route.id, encoded, now).map_err(|_| "unauthorized")?;
    if event["callId"] != target.call_id
        || event["invitationId"] != target.invitation_id
        || event["expires"].as_u64() != Some(target.expires)
    {
        return Err("unauthorized");
    }
    let binding = enrollment
        .bindings
        .into_iter()
        .find(|binding| {
            binding.identity == target.recipient
                && binding.hosting_space_id == target.hosting_space_id
                && binding.scope == target.scope
                && binding.push_endpoint.as_deref().is_some_and(|pinned| {
                    elo_core::app::push::endpoint(pinned, false)
                        .is_ok_and(|pinned| pinned == endpoint)
                })
        })
        .ok_or("unauthorized")?;
    Ok((Prepared::load(binding, now)?, target))
}

pub(super) fn socket_url(prepared: &Prepared) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&prepared.binding.audience).map_err(|_| "invalid")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("unauthorized".into());
    }
    url.set_scheme("wss").map_err(|_| "invalid")?;
    url.set_path(&format!("{}/connect", url.path().trim_end_matches('/')));
    Ok(url.to_string())
}

pub(super) async fn command(prepared: &Prepared, operation: Operation) -> Result<Value, String> {
    let signed = prepared.signed(operation, time()).map_err(str::to_owned)?;
    send_signed(socket_url(prepared)?, signed).await
}

/// Send an already authorized call command through its pinned control socket.
/// The state endpoint accepts Subscribe only; mutations always use this transport.
pub(crate) async fn send_signed(socket_url: String, signed: Value) -> Result<Value, String> {
    let url = reqwest::Url::parse(&socket_url).map_err(|_| "invalid")?;
    if url.scheme() != "wss"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("unauthorized".into());
    }
    tokio::time::timeout(Duration::from_secs(8), async {
        let config = WebSocketConfig::default()
            .max_message_size(Some(2 * 1024 * 1024))
            .max_frame_size(Some(2 * 1024 * 1024));
        let (mut socket, _) = connect_async_with_config(socket_url, Some(config), true)
            .await
            .map_err(|_| "unavailable")?;
        socket
            .send(Message::Text(signed.to_string().into()))
            .await
            .map_err(|_| "unavailable")?;
        let mut frames = 0usize;
        while let Some(event) = socket.next().await {
            frames += 1;
            if frames > 32 {
                return Err("unavailable".into());
            }
            match event.map_err(|_| "unavailable")? {
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(&text).map_err(|_| "invalid")?;
                    if value["type"] == "result" {
                        return Ok(value);
                    }
                    if matches!(value["type"].as_str(), Some("error" | "access_revoked")) {
                        return Err("ended".into());
                    }
                }
                Message::Ping(bytes) => {
                    socket
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(|_| "unavailable")?;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        Err("unavailable".into())
    })
    .await
    .map_err(|_| "unavailable".to_string())?
}

#[cfg(any(test, target_os = "android"))]
pub(super) async fn decline(enrollment: Enrollment, event: Value) -> bool {
    if event["action"] != "decline" {
        return false;
    }
    matches!(tokio::time::timeout(Duration::from_secs(7), async {
        let (prepared, target) = lookup(enrollment, &event, time())?;
        let current = command(&prepared, Operation::Subscribe).await.map_err(|_| "unavailable")?;
        prepared.validate(&current["call"], &target, true)?;
        let response = command(&prepared, Operation::Decline { call_id: target.call_id.clone(), invitation_id: target.invitation_id.clone() }).await.map_err(|_| "unavailable")?;
        // A group decline consumes only this invitation. A direct decline ends
        // the whole ringing attempt. Neither operation joins or captures media.
        if response["call"].is_null() { return Ok::<(), &'static str>(()); }
        prepared.validate(&response["call"], &target, false)?;
        if response["call"]["kind"] != "group" || response["call"]["invitations"][prepared.binding.identity.to_string()]["invitation_id"] == target.invitation_id {
            return Err("unavailable");
        }
        Ok(())
    }).await, Ok(Ok(())))
}

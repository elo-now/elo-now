//! Incoming-call delivery is opt-in per proved installation and per known chat.
//! Invitation/introduction permissions never permit ringing an unknown scope.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    provider: String,
    token: Option<String>,
    #[serde(default)]
    sandbox: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ring {
    wake: Wake,
    call_id: String,
    invitation_id: String,
}

pub(super) async fn bind(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Binding>,
) -> Result<StatusCode> {
    let owner = auth(&headers)?;
    if !hex(&id, 16)
        || !matches!(input.provider.as_str(), "fcm" | "apns")
        || (input.provider == "apns"
            && input.token.as_deref().is_none_or(|token| {
                token.len() < 32
                    || token.len() > 256
                    || !token
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }))
        || (input.provider == "fcm" && (input.token.is_some() || input.sandbox))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let _gate = relay.delivery_gate.lock().await;
    relay.db.call(move |db| {
        let time = now()?;
        let saved = row(db,&id)?.ok_or(StatusCode::NOT_FOUND)?;
        if !saved.active || saved.expires <= time || !matches(&saved.owner,&owner) { return Err(StatusCode::FORBIDDEN); }
        let token = input.token.unwrap_or(saved.token);
        let provider = if input.provider == "apns" && input.sandbox { "apns_sandbox" } else { &input.provider };
        db.execute("INSERT INTO incoming_bindings(route,provider,token,expires,next_send) VALUES(?1,?2,?3,?4,0) ON CONFLICT(route) DO UPDATE SET provider=excluded.provider,token=excluded.token,expires=excluded.expires",
            params![id,provider,token,time+86400]).map_err(db_error)?;
        Ok(StatusCode::NO_CONTENT)
    }).await
}

pub(super) async fn unbind(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let owner = auth(&headers)?;
    let _gate = relay.delivery_gate.lock().await;
    relay
        .db
        .call(move |db| {
            if let Some(saved) = row(db, &id)? {
                if !matches(&saved.owner, &owner) {
                    return Err(StatusCode::FORBIDDEN);
                }
                db.execute("DELETE FROM incoming_bindings WHERE route=?", [id])
                    .map_err(db_error)?;
            }
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

pub(super) async fn ring(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Ring>,
) -> Result<StatusCode> {
    let key = auth(&headers)?;
    let time = now()?;
    let wake = &input.wake;
    if !hex(&id, 16)
        || !hex(&input.call_id, 16)
        || !hex(&input.invitation_id, 16)
        || wake.category != "call_ring"
        || !hex(&wake.event, 32)
        || !hex(&wake.scope, 32)
        || !(64..=2048).contains(&wake.target.len())
        || URL_SAFE_NO_PAD.decode(&wake.target).is_err()
        || wake
            .expires
            .is_none_or(|until| until <= time as u64 || until > time as u64 + 60)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sender = elo_core::app::push_sender::verify_sender(
        &id,
        &serde_json::to_value(wake).map_err(|_| StatusCode::BAD_REQUEST)?,
        time as u64,
    )
    .map_err(|_| StatusCode::FORBIDDEN)?;
    // Serializing with policy/removal prevents a wake admitted under an obsolete
    // policy from being handed to the provider after opt-out completes.
    let _gate = relay.delivery_gate.lock().await;
    let route = id.clone();
    let event = wake.event.clone();
    let scope = wake.scope.clone();
    let expiry = wake.expires.unwrap();
    let binding = relay.db.call(move |db| {
        let saved = row(db,&route)?.ok_or(StatusCode::NOT_FOUND)?;
        if !saved.active || saved.expires <= time || !matches(&saved.notify,&key) { return Err(StatusCode::FORBIDDEN); }
        let sender_tag = elo_core::app::push_sender::sender_tag(&route,sender.identity);
        let credential = elo_core::app::push_sender::credential_tag(&route,sender.credential);
        let allowed: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM scopes s JOIN scope_senders a ON a.route=s.route AND a.scope=s.scope JOIN sender_policy p ON p.route=s.route WHERE s.route=?1 AND s.scope=?2 AND s.enabled=1 AND p.authenticated=1 AND a.credential=?3) AND NOT EXISTS(SELECT 1 FROM blocked_senders WHERE route=?1 AND sender=?4) AND NOT EXISTS(SELECT 1 FROM erased_accounts WHERE identity=?5)",
            params![route,scope,credential,sender_tag,sender.identity.to_string()],|r|r.get(0)).map_err(db_error)?;
        if !allowed { return Ok(None); }
        let binding: Option<(String,String,i64)> = db.query_row("SELECT provider,token,next_send FROM incoming_bindings WHERE route=?1 AND expires>?2",params![route,time],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db_error)?;
        let Some((provider,token,next)) = binding else { return Ok(None); };
        db.execute("DELETE FROM events WHERE expires<=?",[time]).map_err(db_error)?;
        if db.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE route=?1 AND event=?2)",params![route,event],|r|r.get::<_,bool>(0)).map_err(db_error)? { return Ok(None); }
        if next > time || !event_capacity(db,&route)? { return Err(StatusCode::TOO_MANY_REQUESTS); }
        db.execute("INSERT INTO events VALUES(?1,?2,?3)",params![route,event,expiry as i64+120]).map_err(db_error)?;
        db.execute("UPDATE incoming_bindings SET next_send=?1 WHERE route=?2",params![time+2,route]).map_err(db_error)?;
        Ok(Some((provider,token)))
    }).await?;
    let Some((provider, token)) = binding else {
        return Ok(StatusCode::ACCEPTED);
    };
    let notice = Notice::Ring {
        registration: id.clone(),
        call_id: input.call_id,
        invitation_id: input.invitation_id,
        target: input.wake.target,
        expires: expiry,
        voip: matches!(provider.as_str(), "apns" | "apns_sandbox"),
        apns_sandbox: provider == "apns_sandbox",
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        relay.provider.send(token, notice),
    )
    .await;
    if !matches!(result, Ok(Ok(()))) {
        let event = input.wake.event;
        let invalid_token = matches!(result, Ok(Err(fcm::Error::Unregistered)));
        relay
            .db
            .call(move |db| {
                db.execute(
                    "DELETE FROM events WHERE route=?1 AND event=?2",
                    params![id, event],
                )
                .map_err(db_error)?;
                if invalid_token {
                    db.execute("DELETE FROM incoming_bindings WHERE route=?1", [id])
                        .map_err(db_error)?;
                }
                Ok(())
            })
            .await?;
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(StatusCode::ACCEPTED)
}

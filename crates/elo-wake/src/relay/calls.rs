//! Recipient-owned native call delivery. Only the private call-control listener
//! can enqueue a ring; route possession alone never authorizes an incoming call.
use super::*;
use elo_core::calls::wake::Notice as CallEvent;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Subscription {
    pub call_scope: String,
    pub notification_scope: String,
    pub credential: String,
    pub head: String,
    pub target: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registration {
    pub enabled: bool,
    pub platform: String,
    pub token: String,
    pub subscriptions: Vec<Subscription>,
}

pub(super) fn schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS call_devices(route TEXT PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE, platform TEXT NOT NULL, token TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS call_subscriptions(route TEXT NOT NULL REFERENCES call_devices(route) ON DELETE CASCADE, call_scope TEXT NOT NULL, scope TEXT NOT NULL, credential TEXT NOT NULL, head TEXT NOT NULL, target TEXT NOT NULL, PRIMARY KEY(route,call_scope));
        CREATE TABLE IF NOT EXISTS call_declines(call_id TEXT PRIMARY KEY, identity TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS call_events(call_id TEXT PRIMARY KEY, terminal INTEGER NOT NULL, expires INTEGER NOT NULL, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS call_queue(route TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE, call_id TEXT NOT NULL REFERENCES call_events(call_id) ON DELETE CASCADE, scope TEXT NOT NULL, sender TEXT NOT NULL, target TEXT NOT NULL, ticket TEXT NOT NULL, expires INTEGER NOT NULL, video INTEGER NOT NULL, next INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(route,call_id));")
}

pub(super) async fn register(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Registration>,
) -> Result<StatusCode> {
    let owner = auth(&headers)?;
    let _gate = relay.delivery_gate.lock().await;
    let mut db = relay.database()?;
    let saved = row(&db, &id)?.ok_or(StatusCode::NOT_FOUND)?;
    if !matches(&saved.owner, &owner) || !saved.active || saved.expires <= now()? {
        return Err(StatusCode::FORBIDDEN);
    }
    if input.subscriptions.len() > 4096
        || !["android", "ios"].contains(&input.platform.as_str())
        || input.token.len() > 4096
        || (input.enabled && input.token.len() < 16)
        || (input.platform == "ios"
            && input.enabled
            && (!input.token.bytes().all(|b| b.is_ascii_hexdigit()) || input.token.len() % 2 != 0))
        || input.subscriptions.iter().any(|s| {
            !hex(&s.call_scope, 32)
                || !hex(&s.notification_scope, 32)
                || !hex(&s.credential, 32)
                || !hex(&s.head, 32)
                || s.target.len() > 2048
                || URL_SAFE_NO_PAD
                    .decode(&s.target)
                    .map_or(true, |b| b.len() < 64)
        })
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.enabled && input.platform == "android" && input.token != saved.token {
        return Err(StatusCode::FORBIDDEN);
    }
    if input.enabled
        && input.platform == "ios"
        && !voip_ownership::verified(&db, &id, &input.token)?
    {
        return Err(StatusCode::FORBIDDEN);
    }
    if input
        .subscriptions
        .iter()
        .map(|s| &s.call_scope)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != input.subscriptions.len()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.enabled
        && (relay.call_key.is_none() || (input.platform == "ios" && relay.apns.is_none()))
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let tx = db.transaction().map_err(db_error)?;
    tx.execute("DELETE FROM call_devices WHERE route=?", [&id])
        .map_err(db_error)?;
    if input.enabled {
        tx.execute(
            "INSERT INTO call_devices VALUES(?,?,?)",
            params![id, input.platform, input.token],
        )
        .map_err(db_error)?;
        for s in input.subscriptions {
            tx.execute(
                "INSERT INTO call_subscriptions VALUES(?,?,?,?,?,?)",
                params![
                    id,
                    s.call_scope,
                    s.notification_scope,
                    s.credential,
                    s.head,
                    s.target
                ],
            )
            .map_err(db_error)?;
        }
    }
    // A changed policy cannot revive a queued notification for a removed scope.
    tx.execute("DELETE FROM call_queue WHERE route=?1 AND NOT EXISTS(SELECT 1 FROM call_subscriptions s WHERE s.route=?1 AND s.scope=call_queue.scope)",[&id]).map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn event(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Json(input): Json<CallEvent>,
) -> Result<StatusCode> {
    let key = auth(&headers)?;
    if !relay
        .call_key
        .as_ref()
        .is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(key.as_bytes())))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let time = now()?;
    if !input.valid(time as u64) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let _gate = relay.delivery_gate.lock().await;
    let mut db = relay.database()?;
    let tx = db.transaction().map_err(db_error)?;
    tx.execute("DELETE FROM call_events WHERE expires<=?", [time])
        .map_err(db_error)?;
    let body = URL_SAFE_NO_PAD.encode(Sha256::digest(
        serde_json::to_vec(&input).map_err(|_| StatusCode::BAD_REQUEST)?,
    ));
    let call_id = input.call_id().to_owned();
    let previous: Option<(bool, String)> = tx
        .query_row(
            "SELECT terminal,body FROM call_events WHERE call_id=?",
            [&call_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    if let Some((terminal, previous)) = &previous {
        if *terminal || *previous == body {
            return Ok(StatusCode::ACCEPTED);
        }
        if matches!(input, CallEvent::Ring { .. }) {
            return Err(StatusCode::CONFLICT);
        }
    }
    let count: i64 = tx
        .query_row("SELECT count(*) FROM call_events", [], |r| r.get(0))
        .map_err(db_error)?;
    if count >= 8192 && previous.is_none() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    match input {
        CallEvent::End { .. } => {
            tx.execute("INSERT INTO call_events VALUES(?,1,?,'') ON CONFLICT(call_id) DO UPDATE SET terminal=1,expires=excluded.expires,body=''",params![call_id,time+300]).map_err(db_error)?;
            tx.execute("DELETE FROM call_queue WHERE call_id=?", [&call_id])
                .map_err(db_error)?;
        }
        CallEvent::Ring {
            scope,
            head,
            caller,
            recipients,
            expires,
            video,
            ..
        } => {
            tx.execute(
                "INSERT INTO call_events VALUES(?,0,?,?)",
                params![call_id, time + 300, body],
            )
            .map_err(db_error)?;
            for recipient in recipients {
                let candidates = {
                    let mut q=tx.prepare("SELECT s.route,s.scope,s.target FROM call_subscriptions s JOIN route_accounts a ON a.route=s.route JOIN routes r ON r.id=s.route WHERE a.identity=?1 AND s.credential=?2 AND s.head=?3 AND s.call_scope=?4 AND r.active=1 AND r.expires>?5").map_err(db_error)?;
                    q.query_map(
                        params![
                            recipient.identity.to_string(),
                            recipient.credential.to_string(),
                            head.to_string(),
                            scope,
                            time
                        ],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, String>(2)?,
                            ))
                        },
                    )
                    .map_err(db_error)?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(db_error)?
                };
                for (route, scope, target) in candidates {
                    let sender = elo_core::app::push_sender::sender_tag(&route, caller);
                    if !allowed(&tx, &route, &scope, &sender, time)? {
                        continue;
                    }
                    tx.execute("INSERT OR IGNORE INTO call_queue(route,call_id,scope,sender,target,ticket,expires,video,next) VALUES(?,?,?,?,?,?,?,?,?)",params![route,call_id,scope,sender,target,random_ticket()?,expires as i64,video,time]).map_err(db_error)?;
                }
            }
        }
    }
    tx.commit().map_err(db_error)?;
    Ok(StatusCode::ACCEPTED)
}

fn allowed(db: &Connection, route: &str, scope: &str, sender: &str, time: i64) -> Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM routes r JOIN call_devices d ON d.route=r.id JOIN scopes s ON s.route=r.id JOIN route_accounts a ON a.route=r.id WHERE r.id=?1 AND r.active=1 AND r.expires>?4 AND ((d.platform='android' AND d.token=r.token) OR (d.platform='ios' AND EXISTS(SELECT 1 FROM voip_bindings v WHERE v.route=r.id AND v.token=d.token))) AND s.scope=?2 AND s.enabled=1 AND NOT EXISTS(SELECT 1 FROM blocked_senders b WHERE b.route=r.id AND b.sender=?3) AND NOT EXISTS(SELECT 1 FROM erased_accounts e WHERE e.identity=a.identity))",params![route,scope,sender,time],|r|r.get(0)).map_err(db_error)
}

pub(super) async fn deliver(relay: &Relay) -> Result<bool> {
    let _gate = relay.delivery_gate.lock().await;
    let time = now()?;
    let item = {
        let db = relay.database()?;
        db.execute("DELETE FROM call_events WHERE expires<=?", [time])
            .map_err(db_error)?;
        db.execute("DELETE FROM call_declines WHERE expires<=?", [time])
            .map_err(db_error)?;
        db.execute("DELETE FROM call_queue WHERE expires<=?", [time])
            .map_err(db_error)?;
        db.query_row("SELECT q.route,q.call_id,q.scope,q.sender,q.target,q.expires,q.video,d.platform,d.token,q.attempts,q.ticket FROM call_queue q JOIN call_devices d ON d.route=q.route JOIN call_events e ON e.call_id=q.call_id WHERE q.sent=0 AND q.next<=? AND e.terminal=0 ORDER BY q.next LIMIT 1",[time],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?,r.get::<_,bool>(6)?,r.get::<_,String>(7)?,r.get::<_,String>(8)?,r.get::<_,i64>(9)?,r.get::<_,String>(10)?))).optional().map_err(db_error)?
    };
    let Some((
        route,
        call_id,
        scope,
        sender,
        target,
        expires,
        video,
        platform,
        token,
        attempts,
        ticket,
    )) = item
    else {
        return Ok(false);
    };
    let permitted = {
        let db = relay.database()?;
        allowed(&db, &route, &scope, &sender, time)?
    };
    if !permitted {
        relay
            .database()?
            .execute(
                "DELETE FROM call_queue WHERE route=? AND call_id=?",
                params![route, call_id],
            )
            .map_err(db_error)?;
        return Ok(true);
    }
    let (sent, retryable) = if platform == "ios" {
        if let Some(apns) = &relay.apns {
            let result = apns.incoming(&token,&json!({"aps":{},"elo_call":"1","elo_ticket":ticket,"elo_registration":route,"elo_call_id":call_id,"elo_scope":scope,"elo_target":target,"elo_expires":expires.to_string(),"elo_video":if video{"1"}else{"0"}})).await;
            let retryable = matches!(
                &result,
                Err(crate::apns::Error::Delivery | crate::apns::Error::TokenExpired)
            );
            (result.is_ok(), retryable)
        } else {
            (false, false)
        }
    } else {
        (
            relay
                .provider
                .send(
                    token,
                    Notice::Call {
                        registration: route.clone(),
                        call_id: call_id.clone(),
                        scope,
                        target,
                        expires: expires as u64,
                        video,
                        ticket,
                    },
                )
                .await
                .is_ok(),
            true,
        )
    };
    let db = relay.database()?;
    if sent || !retryable || attempts >= 2 {
        db.execute(
            "UPDATE call_queue SET sent=1 WHERE route=? AND call_id=?",
            params![route, call_id],
        )
        .map_err(db_error)?;
    } else {
        db.execute(
            "UPDATE call_queue SET next=?,attempts=attempts+1 WHERE route=? AND call_id=?",
            params![time + 2, route, call_id],
        )
        .map_err(db_error)?;
    }
    Ok(true)
}

fn random_ticket() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
/// A short-lived capability reveals only whether this specific ring is current.
/// It never grants account, chat, media or notification-route access.
pub(super) async fn status(
    State(relay): State<Arc<Relay>>,
    Path((route, call_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let ticket = auth(&headers)?;
    let db = relay.database()?;
    let candidate:Option<(String,String,String,i64,bool)>=db.query_row("SELECT q.ticket,q.scope,q.sender,q.expires,e.terminal FROM call_queue q JOIN call_events e ON e.call_id=q.call_id WHERE q.route=? AND q.call_id=?",params![route,call_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(db_error)?;
    let Some((expected, scope, sender, expires, terminal)) = candidate else {
        return Err(StatusCode::GONE);
    };
    if !bool::from(expected.as_bytes().ct_eq(ticket.as_bytes())) {
        return Err(StatusCode::GONE);
    }
    Ok(Json(
        json!({"ringing":!terminal && expires>now()? && allowed(&db,&route,&scope,&sender,now()?)?}),
    ))
}

pub(super) async fn decline(
    State(relay): State<Arc<Relay>>,
    Path((route, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let ticket = auth(&headers)?;
    let _gate = relay.delivery_gate.lock().await;
    let mut db = relay.database()?;
    let tx = db.transaction().map_err(db_error)?;
    let candidate:Option<(String,String,String,String,i64,bool)>=tx.query_row("SELECT q.ticket,q.scope,q.sender,a.identity,q.expires,e.terminal FROM call_queue q JOIN route_accounts a ON a.route=q.route JOIN call_events e ON e.call_id=q.call_id WHERE q.route=? AND q.call_id=?",params![route,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(db_error)?;
    let Some((expected, scope, sender, identity, expires, terminal)) = candidate else {
        return Err(StatusCode::GONE);
    };
    if !bool::from(expected.as_bytes().ct_eq(ticket.as_bytes()))
        || terminal
        || expires <= now()?
        || !allowed(&tx, &route, &scope, &sender, now()?)?
    {
        return Err(StatusCode::GONE);
    }
    tx.execute("DELETE FROM call_declines WHERE expires<=?", [now()?])
        .map_err(db_error)?;
    tx.execute(
        "INSERT OR IGNORE INTO call_declines VALUES(?,?,?)",
        params![id, identity, expires],
    )
    .map_err(db_error)?;
    tx.execute("UPDATE call_events SET terminal=1 WHERE call_id=?", [&id])
        .map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}
pub(super) async fn declined(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let key = auth(&headers)?;
    if !relay
        .call_key
        .as_ref()
        .is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(key.as_bytes())))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let db = relay.database()?;
    db.execute("DELETE FROM call_declines WHERE expires<=?", [now()?])
        .map_err(db_error)?;
    let mut query = db
        .prepare("SELECT call_id,identity FROM call_declines LIMIT 128")
        .map_err(db_error)?;
    let rows = query
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    Ok(Json(json!({"declined":rows})))
}

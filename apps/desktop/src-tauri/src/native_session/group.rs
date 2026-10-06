//! Native SFU sessions use the same encrypted epoch-key exchange as the web
//! client. Provider credentials never carry the media key.
use super::*;
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct State {
    epoch: u64,
    people: Vec<String>,
    key: Option<Zeroizing<String>>,
    nonces: BTreeMap<String, u64>,
}

fn participants(call: &Value) -> Result<Vec<String>> {
    let mut ids = call["participants"]
        .as_object()
        .ok_or("invalid")?
        .values()
        .map(|p| {
            p["credential_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or("invalid")
        })
        .collect::<Result<Vec<_>>>()?;
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("unauthorized");
    }
    Ok(ids)
}

pub(super) async fn maintain(
    driver: &mut impl Driver,
    target: &Target,
    control: &mut Control,
    initial: Value,
    state: &mut State,
) -> Result<()> {
    target.validate(&initial)?;
    let local = target.context["credential"].as_str().ok_or("invalid")?;
    let mut call = initial;
    let mut epoch = 0;
    let mut started = false;
    let mut people = Vec::new();
    let mut pending = VecDeque::<(String, Value)>::new();
    let mut last_media = Value::Null;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut poll = tokio::time::interval(Duration::from_millis(200));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut key_requested = tokio::time::Instant::now();
    let mut epoch_started = tokio::time::Instant::now();
    let mut disconnected = None;
    loop {
        if !driver.live() {
            return Ok(());
        }
        let next_epoch = call["key_epoch"].as_u64().ok_or("invalid")?;
        if epoch != next_epoch {
            target.validate(&call)?;
            driver.changed(&call, false).await?;
            // Revoke the old room/key before admitting new tracks.
            driver.media(json!({"op":"group_reset"})).await?;
            epoch = next_epoch;
            people = participants(&call)?;
            started = false;
            if epoch < state.epoch || (epoch == state.epoch && people != state.people) {
                return Err("unauthorized");
            }
            if epoch != state.epoch {
                state.epoch = epoch;
                state.people = people.clone();
                state.key = None;
                state.nonces.clear();
            }
            pending.clear();
            disconnected = None;
            epoch_started = tokio::time::Instant::now();
            if people.first().map(String::as_str) == Some(local) {
                if state.key.is_none() {
                    state.key = Some(Zeroizing::new(
                        elo_core::record::random_hex::<32>().map_err(|_| "unavailable")?,
                    ));
                }
                let secret = state.key.as_ref().ok_or("invalid")?;
                for peer in &people {
                    if peer != local {
                        pending.push_back((
                            peer.clone(),
                            json!({"type":"media_key","epoch":epoch,"key":**secret}),
                        ));
                    }
                }
            } else if state.key.is_none() {
                pending.push_back((
                    people.first().ok_or("ended")?.clone(),
                    json!({"type":"request_key","epoch":epoch}),
                ));
                key_requested = tokio::time::Instant::now();
            }
        }
        if !started && let Some(secret) = state.key.as_ref() {
            let result = control
                .command(
                    driver,
                    json!({"type":"connect_media","call_id":target.call_id}),
                )
                .await?;
            target.validate(&result["call"])?;
            if result["call"]["key_epoch"] != epoch {
                call = result["call"].clone();
                continue;
            }
            if participants(&result["call"])? != people {
                return Err("unauthorized");
            }
            call = result["call"].clone();
            driver.changed(&call, false).await?;
            let access = &result["media"];
            if access["provider"] != "livekit" || access["epoch"] != epoch {
                return Err("unauthorized");
            }
            driver.media(json!({"op":"group_start","url":access["url"],"token":access["token"],"key":**secret,
                "epoch":epoch,"participants":people,"credential":local})).await?;
            started = true;
            driver.media(json!({"op":"update","state":call["participants"][target.context["expected_identity"].as_str().ok_or("invalid")?]["media"],"speaker_muted":false})).await?;
        }
        if epoch_started.elapsed() > Duration::from_secs(30) && !started {
            return Err("unavailable");
        }
        let event = tokio::select! {
            biased;
            _=heartbeat.tick()=> {
                let result=control.command(driver,json!({"type":"heartbeat","call_id":target.call_id})).await?;
                Some(json!({"type":"presence","call":result["call"]}))
            },
            _=poll.tick()=> {
                if !started {
                    if key_requested.elapsed()>Duration::from_secs(3) && state.key.is_none() {
                        if pending.len()>=QUEUE_LIMIT {return Err("overflow");}
                        pending.push_back((people.first().ok_or("ended")?.clone(),json!({"type":"request_key","epoch":epoch})));
                        key_requested=tokio::time::Instant::now();
                    }
                    None
                } else {
                    let snapshot=driver.media(json!({"op":"poll"})).await?;
                    if snapshot["error"].is_string() || snapshot["encryption_error"]==true {return Err("encryption_unavailable");}
                    if snapshot["connection"]=="connected" {disconnected=None;driver.changed(&call,true).await?;}
                    else {
                        let since=disconnected.get_or_insert(tokio::time::Instant::now());
                        if since.elapsed()>Duration::from_secs(15) {return Err("unavailable");}
                    }
                    if snapshot["media"].is_object() && snapshot["media"]!=last_media {
                        let result=control.command(driver,json!({"type":"media","call_id":target.call_id,"state":snapshot["media"]})).await?;
                        last_media=snapshot["media"].clone();
                        Some(json!({"type":"presence","call":result["call"]}))
                    } else {None}
                }
            },
            _=std::future::ready(()), if !control.pending.is_empty()=>control.pop(),
            event=control.receive()=>Some(event?),
            _=std::future::ready(()), if !pending.is_empty()=> {
                let (peer,payload)=pending.pop_front().ok_or("invalid")?;
                let result=control.signal(driver,target,epoch,&peer,payload).await?;
                Some(json!({"type":"presence","call":result["call"]}))
            },
        };
        let Some(event) = event else {
            continue;
        };
        match event["type"].as_str() {
            Some("ended")
                if event["scope"] == target.scope() && event["call_id"] == target.call_id =>
            {
                return Ok(());
            }
            Some("error" | "access_revoked") => return Err("unauthorized"),
            Some("presence") if event["call"]["scope"] == target.scope() => {
                let next = &event["call"];
                if next["key_epoch"]
                    .as_u64()
                    .is_some_and(|value| value < epoch)
                {
                    continue;
                }
                target.validate(next)?;
                if next["key_epoch"] == epoch && participants(next)? != people {
                    return Err("unauthorized");
                }
                call = next.clone();
                driver.changed(&call, false).await?;
            }
            Some("signal")
                if event["scope"] == target.scope()
                    && event["call_id"] == target.call_id
                    && event["epoch"] == epoch =>
            {
                let from = event["from"].as_str().ok_or("invalid")?;
                if from == local || !people.iter().any(|p| p == from) {
                    continue;
                }
                let opened=driver.operation("call_open_signal",json!({"call_id":target.call_id,"epoch":epoch,"from":from,"ciphertext":event["ciphertext"]})).await?;
                let signal = &opened["signal"];
                if signal["from"] != from
                    || signal["to"] != local
                    || signal["call_id"] != target.call_id
                    || signal["epoch"] != epoch
                    || signal["config_id"] != target.context["config_id"]
                {
                    return Err("unauthorized");
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "invalid")?
                    .as_secs();
                let expires = signal["expires_at"]
                    .as_u64()
                    .filter(|expiry| *expiry > now)
                    .ok_or("invalid")?;
                let nonce = signal["nonce"]
                    .as_str()
                    .filter(|nonce| !nonce.is_empty() && nonce.len() <= 128)
                    .ok_or("invalid")?
                    .to_string();
                state.nonces.retain(|_, expiry| *expiry > now);
                if state.nonces.contains_key(&nonce) {
                    continue;
                }
                if state.nonces.len() >= 2048 {
                    return Err("overflow");
                }
                state.nonces.insert(nonce, expires);
                let payload = &signal["payload"];
                if payload["epoch"] != epoch {
                    continue;
                }
                if payload["type"] == "media_key"
                    && people.first().map(String::as_str) == Some(from)
                {
                    let secret = payload["key"].as_str().ok_or("invalid")?;
                    if secret.len() != 64
                        || !secret
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err("invalid");
                    }
                    if state
                        .key
                        .as_ref()
                        .is_some_and(|known| known.as_str() != secret)
                    {
                        return Err("unauthorized");
                    }
                    state.key = Some(Zeroizing::new(secret.into()));
                } else if payload["type"] == "request_key"
                    && people.first().map(String::as_str) == Some(local)
                    && let Some(secret) = state.key.as_ref()
                {
                    if pending.len() >= QUEUE_LIMIT {
                        return Err("overflow");
                    }
                    pending.push_back((
                        from.into(),
                        json!({"type":"media_key","epoch":epoch,"key":**secret}),
                    ));
                }
            }
            _ => {}
        }
    }
}

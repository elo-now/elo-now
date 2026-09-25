//! Incoming direct-call signaling owned by Rust, independent of WebView timers.
//! The driver uses only an unlocked in-memory profile; no key is persisted here.
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    time::Duration,
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type Result<T> = std::result::Result<T, &'static str>;
pub(crate) trait Driver: Send {
    fn cancellation(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        None
    }
    fn operation(&mut self, op: &str, fields: Value) -> impl Future<Output = Result<Value>> + Send;
    fn media(&mut self, request: Value) -> impl Future<Output = Result<Value>> + Send;
    fn changed(&mut self, call: &Value, connected: bool)
    -> impl Future<Output = Result<()>> + Send;
    fn live(&self) -> bool;
}

pub(crate) struct Target {
    pub url: String,
    pub call_id: String,
    pub context: Value,
}
impl Target {
    fn scope(&self) -> Value {
        json!({"hosting_space_id":self.context["hosting_space_id"],"conversation":{
            "space_id":self.context["space"],"stream_id":self.context["stream"]}})
    }
    fn validate(&self, call: &Value, joined: bool) -> Result<()> {
        if call["call_id"] != self.call_id
            || call["scope"] != self.scope()
            || call["kind"] != "direct"
            || call["config_id"] != self.context["config_id"]
        {
            return Err("unauthorized");
        }
        let people = call["participants"].as_object().ok_or("invalid")?;
        if people.len() != if joined { 2 } else { 1 } {
            return Err("ended");
        }
        for (identity, participant) in people {
            if participant["identity_id"] != *identity
                || !self.context["members"][identity]
                    .as_array()
                    .is_some_and(|ids| ids.contains(&participant["credential_id"]))
            {
                return Err("unauthorized");
            }
        }
        let identity = self.context["expected_identity"]
            .as_str()
            .ok_or("invalid")?;
        if joined {
            if people.get(identity).map(|p| &p["credential_id"])
                != Some(&self.context["credential"])
            {
                return Err("unauthorized");
            }
        } else if call["ringing"] != true || people.contains_key(identity) {
            return Err("ended");
        }
        Ok(())
    }
    fn remote(&self, call: &Value) -> Result<String> {
        call["participants"]
            .as_object()
            .ok_or("invalid")?
            .values()
            .find_map(|p| {
                (p["credential_id"] != self.context["credential"])
                    .then(|| p["credential_id"].as_str().map(str::to_owned))
                    .flatten()
            })
            .ok_or("ended")
    }
    fn leader(&self, remote: &str) -> bool {
        self.context["credential"]
            .as_str()
            .is_some_and(|local| local < remote)
    }
}
struct Control {
    socket: Socket,
    pending: VecDeque<Value>,
}
impl Control {
    async fn receive(&mut self) -> Result<Value> {
        loop {
            match self
                .socket
                .next()
                .await
                .ok_or("unavailable")?
                .map_err(|_| "unavailable")?
            {
                Message::Text(text) => return serde_json::from_str(&text).map_err(|_| "invalid"),
                Message::Ping(bytes) => self.send(Message::Pong(bytes)).await?,
                Message::Pong(_) => {}
                _ => return Err("unavailable"),
            }
        }
    }
    async fn send(&mut self, message: Message) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(4), self.socket.send(message))
            .await
            .map_err(|_| "unavailable")?
            .map_err(|_| "unavailable")
    }
    async fn signed(&mut self, signed: Value) -> Result<Value> {
        self.send(Message::Text(
            json!({"command":signed["command"],"proof":signed["proof"]})
                .to_string()
                .into(),
        ))
        .await?;
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let event = self.receive().await?;
                match event["type"].as_str() {
                    Some("result") => return Ok(event),
                    Some("error" | "access_revoked") => return Err("unauthorized"),
                    _ => {
                        if self.pending.len() >= 256 {
                            return Err("unavailable");
                        }
                        self.pending.push_back(event);
                    }
                }
            }
        })
        .await
        .map_err(|_| "unavailable")?
    }
    async fn command(&mut self, driver: &mut impl Driver, operation: Value) -> Result<Value> {
        let signed = driver
            .operation(
                "call_authorization",
                json!({"include_proof":true,"operation":operation}),
            )
            .await?;
        self.signed(signed).await
    }
    async fn signal(
        &mut self,
        driver: &mut impl Driver,
        target: &Target,
        remote: &str,
        payload: Value,
    ) -> Result<()> {
        let sealed = driver
            .operation(
                "call_encrypt_signal",
                json!({"call_id":target.call_id,"to":remote,"payload":payload}),
            )
            .await?;
        self.command(driver, json!({"type":"signal","call_id":target.call_id,"to":remote,"ciphertext":sealed["ciphertext"]})).await?;
        Ok(())
    }
}

/// The caller always tears down the native peer/CallKit state, on success or error.
pub(crate) async fn run(driver: &mut impl Driver, target: &Target) -> Result<()> {
    let signed = driver
        .operation(
            "call_authorization",
            json!({"include_proof":true,"operation":{"type":"subscribe"}}),
        )
        .await?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(2 * 1024 * 1024))
        .max_frame_size(Some(2 * 1024 * 1024));
    let (socket, _) = tokio::time::timeout(
        Duration::from_secs(8),
        connect_async_with_config(&target.url, Some(config), true),
    )
    .await
    .map_err(|_| "unavailable")?
    .map_err(|_| "unavailable")?;
    let mut control = Control {
        socket,
        pending: VecDeque::new(),
    };
    let mut cancellation = driver.cancellation();
    let result = tokio::select! {
        biased;
        _ = async {
            let Some(cancelled) = cancellation.as_mut() else {
                return std::future::pending::<()>().await;
            };
            while !*cancelled.borrow_and_update() {
                if cancelled.changed().await.is_err() { return; }
            }
        } => Ok(()),
        result = answer(driver, target, &mut control, signed) => result,
    };
    // A local stop must also remove the participant when WebKit cannot run.
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        control.command(driver, json!({"type":"leave","call_id":target.call_id})),
    )
    .await;
    result
}
async fn answer(
    driver: &mut impl Driver,
    target: &Target,
    control: &mut Control,
    signed: Value,
) -> Result<()> {
    let known = control.signed(signed).await?;
    target.validate(&known["call"], false)?;
    // Permission and all signed admission happen before microphone capture.
    driver
        .media(json!({"op":"permissions","video":false}))
        .await?;
    let joined = control
        .command(driver, json!({"type":"join","call_id":target.call_id}))
        .await?;
    target.validate(&joined["call"], true)?;
    let mut call = joined["call"].clone();
    let epoch = call["key_epoch"].as_u64().ok_or("invalid")?;
    let remote = target.remote(&call)?;
    let initial = json!({"audio_muted":false,"video_published":false,"screen_published":false});
    let mut last_media = initial.clone();
    control
        .command(
            driver,
            json!({"type":"media","call_id":target.call_id,"state":initial}),
        )
        .await?;
    let access = control
        .command(
            driver,
            json!({"type":"connect_media","call_id":target.call_id}),
        )
        .await?;
    if access["media"]["provider"] != "p2p" || access["media"]["epoch"] != epoch {
        return Err("invalid");
    }
    driver
        .media(json!({"op":"start","ice_servers":access["media"]["ice_servers"]}))
        .await?;
    driver.media(json!({"op":"update","state":initial})).await?;
    driver.changed(&call, false).await?;
    if target.leader(&remote) {
        driver.media(json!({"op":"offer"})).await?;
    } else {
        control
            .signal(driver, target, &remote, json!({"type":"request_offer"}))
            .await?;
    }
    let mut nonces = BTreeSet::new();
    let mut poll = tokio::time::interval(Duration::from_millis(150));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut connected = false;
    let started = tokio::time::Instant::now();
    let mut disconnected = None;
    loop {
        if !driver.live() {
            return Ok(());
        }
        if !connected && started.elapsed() > Duration::from_secs(30) {
            return Err("unavailable");
        }
        let event = if let Some(event) = control.pending.pop_front() {
            Some(event)
        } else {
            tokio::select! {
                event = control.receive() => Some(event?),
                _ = poll.tick() => {
                    let state = driver.media(json!({"op":"poll"})).await?;
                    if state["media"].is_object() && state["media"] != last_media {
                        control.command(driver, json!({"type":"media","call_id":target.call_id,"state":state["media"]})).await?;
                        last_media = state["media"].clone();
                    }
                    match state["connection"].as_str() {
                        Some("connected") => {
                            disconnected = None;
                            if !connected { connected = true; driver.changed(&call, true).await?; }
                        },
                        Some("failed" | "closed") => return Err("unavailable"),
                        Some("disconnected") => {
                            let since = disconnected.get_or_insert_with(tokio::time::Instant::now);
                            if since.elapsed() > Duration::from_secs(10) { return Err("unavailable"); }
                        },
                        _ => {},
                    }
                    for payload in state["signals"].as_array().ok_or("invalid")? {
                        control.signal(driver, target, &remote, payload.clone()).await?;
                    }
                    None
                },
                _ = heartbeat.tick() => {
                    let result = control.command(driver, json!({"type":"heartbeat","call_id":target.call_id})).await?;
                    Some(json!({"type":"presence","call":result["call"]}))
                },
            }
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
            Some("access_revoked") if event["scope"] == target.scope() => {
                return Err("unauthorized");
            }
            Some("error") => return Err("unauthorized"),
            Some("presence") if event["call"]["scope"] == target.scope() => {
                let next = &event["call"];
                if next["call_id"] != target.call_id {
                    return Err("ended");
                }
                if next["key_epoch"]
                    .as_u64()
                    .is_some_and(|value| value < epoch)
                {
                    continue;
                }
                target.validate(next, true)?;
                if next["key_epoch"] != epoch {
                    return Err("unauthorized");
                }
                call = next.clone();
                driver.changed(&call, connected).await?;
            }
            Some("signal")
                if event["scope"] == target.scope()
                    && event["call_id"] == target.call_id
                    && event["from"] == remote =>
            {
                let opened = driver
                    .operation(
                        "call_open_signal",
                        json!({"call_id":target.call_id,"ciphertext":event["ciphertext"]}),
                    )
                    .await?;
                let signal = &opened["signal"];
                if accept_signal(target, &remote, signal, &mut nonces)? {
                    driver
                        .media(json!({"op":"signal","signal":signal["payload"]}))
                        .await?;
                }
            }
            _ => {}
        }
    }
}
fn accept_signal(
    target: &Target,
    remote: &str,
    signal: &Value,
    nonces: &mut BTreeSet<String>,
) -> Result<bool> {
    if signal["from"] != remote
        || signal["to"] != target.context["credential"]
        || signal["config_id"] != target.context["config_id"]
    {
        return Err("unauthorized");
    }
    let kind = signal["payload"]["type"].as_str().ok_or("invalid")?;
    if !matches!(kind, "offer" | "answer" | "ice" | "request_offer") {
        return Err("invalid");
    }
    if ((kind == "answer" || kind == "request_offer") && !target.leader(remote))
        || (kind == "offer" && target.leader(remote))
    {
        return Err("unauthorized");
    }
    let nonce = signal["nonce"].as_str().ok_or("invalid")?;
    if nonces.contains(nonce) {
        return Ok(false);
    }
    if nonces.len() >= 2048 {
        return Err("unavailable");
    }
    nonces.insert(nonce.to_owned());
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> Target {
        Target {
            url: String::new(),
            call_id: "call".into(),
            context: json!({
            "expected_identity":"me","credential":"a","config_id":"head",
            "hosting_space_id":"host","space":"space","stream":"chat",
            "members":{"me":["a"],"them":["b"]}}),
        }
    }
    fn call(joined: bool) -> Value {
        let mut people = json!({"them":{"identity_id":"them","credential_id":"b"}});
        if joined {
            people["me"] = json!({"identity_id":"me","credential_id":"a"});
        }
        json!({"call_id":"call","scope":target().scope(),"kind":"direct","config_id":"head",
            "participants":people,"ringing":!joined,"key_epoch":if joined {2} else {1}})
    }
    #[test]
    fn native_answer_rejects_other_calls_heads_scopes_and_devices() {
        let target = target();
        assert!(target.validate(&call(false), false).is_ok());
        assert!(target.validate(&call(true), true).is_ok());
        for (field, value) in [
            ("call_id", json!("other")),
            ("config_id", json!("old")),
            ("scope", json!({})),
            ("kind", json!("group")),
            (
                "participants",
                json!({"me":{"identity_id":"me","credential_id":"stolen"},"them":{"identity_id":"them","credential_id":"b"}}),
            ),
        ] {
            let mut invalid = call(true);
            invalid[field] = value;
            assert!(target.validate(&invalid, true).is_err(), "{field}");
        }
        assert!(target.validate(&call(true), false).is_err());
        assert!(target.validate(&call(false), true).is_err());
    }
    #[test]
    fn native_signaling_binds_sender_recipient_head_leader_and_nonce() {
        let target = target();
        let signal = json!({"from":"b","to":"a","config_id":"head","nonce":"one","payload":{"type":"answer","sdp":"test"}});
        let mut nonces = BTreeSet::new();
        assert_eq!(accept_signal(&target, "b", &signal, &mut nonces), Ok(true));
        assert_eq!(accept_signal(&target, "b", &signal, &mut nonces), Ok(false));
        for (field, value) in [
            ("from", json!("unknown")),
            ("to", json!("other")),
            ("config_id", json!("old")),
            ("payload", json!({"type":"offer"})),
            ("payload", json!({"type":"media_key"})),
        ] {
            let mut invalid = signal.clone();
            invalid[field] = value;
            assert!(accept_signal(&target, "b", &invalid, &mut BTreeSet::new()).is_err());
        }
    }
    struct TestDriver {
        locked: bool,
        media: Vec<Value>,
        connected: bool,
        cancellation: Option<tokio::sync::watch::Receiver<bool>>,
    }
    impl Driver for TestDriver {
        fn cancellation(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
            self.cancellation.clone()
        }
        async fn operation(&mut self, op: &str, fields: Value) -> Result<Value> {
            if self.locked {
                return Err("unauthorized");
            }
            assert_eq!(op, "call_authorization");
            Ok(json!({"command":fields["operation"],"proof":"verified"}))
        }
        async fn media(&mut self, request: Value) -> Result<Value> {
            self.media.push(request.clone());
            Ok(if request["op"] == "poll" {
                json!({"connection":"connected","signals":[]})
            } else {
                json!({})
            })
        }
        async fn changed(&mut self, _call: &Value, connected: bool) -> Result<()> {
            self.connected |= connected;
            Ok(())
        }
        fn live(&self) -> bool {
            true
        }
    }
    #[tokio::test]
    async fn a_locked_profile_never_opens_network_or_media() {
        let mut driver = TestDriver {
            locked: true,
            media: vec![],
            connected: false,
            cancellation: None,
        };
        assert_eq!(run(&mut driver, &target()).await, Err("unauthorized"));
        assert!(driver.media.is_empty());
    }
    #[tokio::test]
    async fn an_obsolete_call_never_requests_microphone_access_or_starts_media() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = target();
        target.url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut obsolete = call(false);
            obsolete["config_id"] = json!("previous-head");
            for expected in ["subscribe", "leave"] {
                let request: Value = serde_json::from_str(
                    &socket.next().await.unwrap().unwrap().into_text().unwrap(),
                )
                .unwrap();
                assert_eq!(request["command"]["type"], expected);
                socket
                    .send(Message::Text(
                        json!({"type":"result","call":obsolete}).to_string().into(),
                    ))
                    .await
                    .unwrap();
            }
        });
        let mut driver = TestDriver {
            locked: false,
            media: vec![],
            connected: false,
            cancellation: None,
        };
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), run(&mut driver, &target))
                .await
                .unwrap(),
            Err("unauthorized")
        );
        assert!(driver.media.is_empty());
        assert!(!driver.connected);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn answers_and_maintains_audio_without_any_webview_then_receives_remote_end() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = target();
        target.url = format!("ws://{}", listener.local_addr().unwrap());
        let scope = target.scope();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut beats = 0;
            loop {
                let request: Value = serde_json::from_str(
                    &socket.next().await.unwrap().unwrap().into_text().unwrap(),
                )
                .unwrap();
                let op = request["command"]["type"].as_str().unwrap();
                let mut result = json!({"type":"result","call":call(op != "subscribe")});
                if op == "connect_media" {
                    result["media"] = json!({"provider":"p2p","epoch":2,"ice_servers":[]});
                }
                socket
                    .send(Message::Text(result.to_string().into()))
                    .await
                    .unwrap();
                if op == "heartbeat" {
                    beats += 1;
                    if beats == 2 {
                        socket
                            .send(Message::Text(
                                json!({"type":"ended","scope":scope,"call_id":"call"})
                                    .to_string()
                                    .into(),
                            ))
                            .await
                            .unwrap();
                    }
                }
                if op == "leave" {
                    break;
                }
            }
        });
        let mut driver = TestDriver {
            locked: false,
            media: vec![],
            connected: false,
            cancellation: None,
        };
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), run(&mut driver, &target))
                .await
                .unwrap(),
            Ok(())
        );
        assert!(driver.connected);
        assert_eq!(driver.media[0], json!({"op":"permissions","video":false}));
        assert!(driver.media.iter().any(|m| m["op"] == "start"));
        assert!(driver.media.iter().any(|m| m["op"] == "update"
            && m["state"]["audio_muted"] == false
            && m["state"]["video_published"] == false));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn system_hangup_interrupts_pending_media_admission_and_sends_signed_leave() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = target();
        target.url = format!("ws://{}", listener.local_addr().unwrap());
        let (cancel, cancellation) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            for expected in ["subscribe", "join", "media", "connect_media", "leave"] {
                let request: Value = serde_json::from_str(
                    &socket.next().await.unwrap().unwrap().into_text().unwrap(),
                )
                .unwrap();
                assert_eq!(request["command"]["type"], expected);
                assert_eq!(request["proof"], "verified");
                if expected == "connect_media" {
                    // No response: system End must preempt the 12-second wait.
                    cancel.send(true).unwrap();
                    continue;
                }
                socket
                    .send(Message::Text(
                        json!({"type":"result","call":call(expected != "subscribe")})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
        });
        let mut driver = TestDriver {
            locked: false,
            media: vec![],
            connected: false,
            cancellation: Some(cancellation),
        };
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), run(&mut driver, &target))
                .await
                .unwrap(),
            Ok(())
        );
        assert!(!driver.media.iter().any(|m| m["op"] == "start"));
        server.await.unwrap();
    }
}

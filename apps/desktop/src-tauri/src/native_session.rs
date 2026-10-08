//! Direct mobile sessions share one native signaling owner per admitted call.
use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    time::Duration,
};
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type Result<T> = std::result::Result<T, &'static str>;

// Tokio's string-address connect tries DNS answers sequentially. A mobile
// network may advertise IPv6 without a working route, so race complete TLS and
// WebSocket handshakes while retaining the original hostname for verification.
async fn connect_control_socket(url: &str, config: WebSocketConfig) -> Result<Socket> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "invalid")?;
    // The protocol harness uses a local in-process peer. This branch is absent
    // from application builds, which always require authenticated TLS below.
    #[cfg(test)]
    if parsed.scheme() == "ws" && parsed.host_str() == Some("127.0.0.1") {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], parsed.port().ok_or("invalid")?));
        return connect_control_addresses(url, config, [address]).await;
    }
    if parsed.scheme() != "wss"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("unauthorized");
    }
    let host = parsed.host_str().ok_or("invalid")?;
    let port = parsed.port_or_known_default().ok_or("invalid")?;
    diagnostic(c"socket:before_dns");
    let addresses = tokio::net::lookup_host((host, port)).await.map_err(|_| {
        diagnostic(c"socket:dns_failed");
        "unavailable"
    })?;
    let addresses = addresses.take(8).collect::<Vec<_>>();
    diagnostic(c"socket:after_dns");
    connect_control_addresses(url, config, addresses).await
}

async fn connect_control_addresses(
    url: &str,
    config: WebSocketConfig,
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
) -> Result<Socket> {
    let mut attempts = FuturesUnordered::new();
    for address in addresses {
        let request = url.to_owned();
        attempts.push(async move {
            diagnostic(if address.is_ipv4() {
                c"socket:before_tcp_v4"
            } else {
                c"socket:before_tcp_v6"
            });
            let stream = tokio::net::TcpStream::connect(address).await.map_err(|_| {
                diagnostic(c"socket:tcp_failed");
                "unavailable"
            })?;
            diagnostic(c"socket:after_tcp");
            stream.set_nodelay(true).map_err(|_| "unavailable")?;
            let (socket, _) = client_async_tls_with_config(request, stream, Some(config), None)
                .await
                .map_err(|error| {
                    use tokio_tungstenite::tungstenite::Error;
                    diagnostic(match error {
                        Error::Tls(_) => c"socket:tls_failed",
                        Error::Http(_) => c"socket:http_failed",
                        Error::Io(_) => c"socket:io_failed",
                        _ => c"socket:handshake_failed",
                    });
                    "unavailable"
                })?;
            diagnostic(c"socket:after_handshake");
            Ok::<Socket, &'static str>(socket)
        });
    }
    while let Some(result) = attempts.next().await {
        if let Ok(socket) = result {
            return Ok(socket);
        }
    }
    Err("unavailable")
}
const QUEUE_LIMIT: usize = 128;
const QUEUE_BYTES: usize = 2 * 1024 * 1024;
mod group;

pub(crate) fn diagnostic(stage: &'static std::ffi::CStr) {
    crate::diagnostics::event("event", "session", &stage.to_string_lossy(), None);
}

pub(crate) trait Driver: Send {
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
    fn validate(&self, call: &Value) -> Result<()> {
        if call["call_id"] != self.call_id
            || call["scope"] != self.scope()
            || call["kind"] != self.context.get("kind").unwrap_or(&json!("direct")).clone()
            || call["config_id"] != self.context["config_id"]
            || call["key_epoch"].as_u64().is_none_or(|epoch| epoch == 0)
        {
            return Err("unauthorized");
        }
        let people = call["participants"].as_object().ok_or("invalid")?;
        let maximum = if call["kind"] == "group" { 64 } else { 2 };
        if !(1..=maximum).contains(&people.len()) {
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
        if people.get(identity).map(|p| &p["credential_id"]) != Some(&self.context["credential"]) {
            return Err("unauthorized");
        }
        Ok(())
    }
    fn remote(&self, call: &Value) -> Option<String> {
        call["participants"].as_object()?.values().find_map(|p| {
            (p["credential_id"] != self.context["credential"])
                .then(|| p["credential_id"].as_str().map(str::to_owned))
                .flatten()
        })
    }
    fn leader(&self, remote: &str) -> bool {
        self.context["credential"]
            .as_str()
            .is_some_and(|local| local < remote)
    }
}
/// Derive a public, immutable admission context from a fresh operation of the
/// currently unlocked profile. `signed` must be the fresh Rust core operation
/// result, including its independently pinned witness. IPC supplies routing only,
/// never membership or witness trust.
pub(crate) fn verified_context(context: &Value, signed: &Value) -> Result<Value> {
    use elo_core::{
        authority::{CallAuthorityProof, ChatKind},
        calls,
    };
    let command = command_record(signed)?;
    let proof: CallAuthorityProof =
        serde_json::from_value(signed["proof"].clone()).map_err(|_| "invalid")?;
    let space = context["space"]
        .as_str()
        .ok_or("invalid")?
        .parse()
        .map_err(|_| "invalid")?;
    let stream = context["stream"]
        .as_str()
        .ok_or("invalid")?
        .parse()
        .map_err(|_| "invalid")?;
    let pin: Option<elo_core::authority::WitnessPin> =
        serde_json::from_value(signed["trusted_witness"].clone()).map_err(|_| "invalid")?;
    let authority = match pin.as_ref() {
        Some(pin) => proof.verify_witnessed(space, stream, pin),
        None => proof.verify(space, stream),
    }
    .map_err(|_| "unauthorized")?;
    let credential = command.body()["credential_id"]
        .as_str()
        .ok_or("invalid")?
        .parse()
        .map_err(|_| "invalid")?;
    let identity = calls::require_member(&authority, credential).map_err(|_| "unauthorized")?;
    let head = authority.head().map_err(|_| "unauthorized")?;
    if !matches!(head.chat_kind, Some(ChatKind::Direct | ChatKind::Chat))
        || (head.chat_kind == Some(ChatKind::Direct) && head.members.len() != 2)
        || context["expected_identity"] != json!(identity)
    {
        return Err("unauthorized");
    }
    command
        .verify_signature(
            authority
                .credential(credential)
                .map_err(|_| "unauthorized")?
                .key(),
        )
        .map_err(|_| "unauthorized")?;
    let mut result = context.clone();
    result["credential"] = json!(credential);
    result["kind"] = json!(if head.chat_kind == Some(ChatKind::Direct) {
        "direct"
    } else {
        "group"
    });
    result["config_id"] = json!(authority.head_id().ok_or("unauthorized")?);
    result["members"] = json!({});
    for member in &head.members {
        let credentials: Vec<_> = member
            .credential_ids
            .iter()
            .filter(|id| calls::require_member(&authority, **id).is_ok())
            .collect();
        result["members"][member.identity_id.to_string()] = json!(credentials);
    }
    validate_command(&result, signed)?;
    Ok(result)
}
fn command_record(signed: &Value) -> Result<elo_core::record::SignedRecord> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(signed["command"].as_str().ok_or("invalid")?)
        .map_err(|_| "invalid")?;
    elo_core::record::SignedRecord::parse(&bytes).map_err(|_| "invalid")
}
pub(crate) fn validate_command(context: &Value, signed: &Value) -> Result<()> {
    let record = command_record(signed)?;
    let command = record.body();
    if command["config_id"] != context["config_id"]
        || command["credential_id"] != context["credential"]
        || command["hosting_space_id"] != context["hosting_space_id"]
        || command["audience"] != context["audience"]
        || command["scope"]["space_id"] != context["space"]
        || command["scope"]["stream_id"] != context["stream"]
    {
        return Err("unauthorized");
    }
    Ok(())
}
fn command_envelope(signed: &Value) -> Value {
    let mut envelope = json!({"command":signed["command"],"proof":signed["proof"]});
    if let Some(delegation) = signed.get("delegation") {
        envelope["delegation"] = delegation.clone();
    }
    envelope
}

struct Control {
    socket: Socket,
    pending: VecDeque<Value>,
    bytes: usize,
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
    fn pop(&mut self) -> Option<Value> {
        let value = self.pending.pop_front()?;
        self.bytes = self.bytes.saturating_sub(value.to_string().len());
        Some(value)
    }
    async fn signed(&mut self, signed: Value) -> Result<Value> {
        self.send(Message::Text(command_envelope(&signed).to_string().into()))
            .await?;
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let event = self.receive().await?;
                match event["type"].as_str() {
                    Some("result") => return Ok(event),
                    Some("error" | "access_revoked") => {
                        diagnostic(c"command:server_error");
                        return Err("unauthorized");
                    }
                    _ => {
                        let size = event.to_string().len();
                        if self.pending.len() >= QUEUE_LIMIT
                            || self.bytes.saturating_add(size) > QUEUE_BYTES
                        {
                            return Err("overflow");
                        }
                        self.bytes += size;
                        self.pending.push_back(event);
                    }
                }
            }
        })
        .await
        .map_err(|_| "unavailable")?
    }
    async fn command(&mut self, driver: &mut impl Driver, operation: Value) -> Result<Value> {
        tokio::time::timeout(Duration::from_secs(12), async {
            diagnostic(c"command:before_sign");
            let signed = driver
                .operation(
                    "call_authorization",
                    json!({"include_proof":false,"operation":operation}),
                )
                .await?;
            diagnostic(c"command:after_sign");
            self.signed(signed).await
        })
        .await
        .map_err(|_| "unavailable")?
    }
    async fn signal(
        &mut self,
        driver: &mut impl Driver,
        target: &Target,
        epoch: u64,
        remote: &str,
        payload: Value,
    ) -> Result<Value> {
        let sealed = driver
            .operation(
                "call_encrypt_signal",
                json!({"call_id":target.call_id,"epoch":epoch,"to":remote,"payload":payload}),
            )
            .await?;
        // A peer may leave between local encryption and admission. A fresh signed
        // heartbeat distinguishes that race from revoked access without replaying SDP.
        match self.command(driver, json!({"type":"signal","call_id":target.call_id,"epoch":epoch,"to":remote,"ciphertext":sealed["ciphertext"]})).await {
            Err("unauthorized") => self.command(driver, json!({"type":"heartbeat","call_id":target.call_id})).await,
            result => result,
        }
    }
}

/// Reconnect within the participant lease. An evicted device never joins again
/// automatically: the fresh heartbeat must still admit the exact same device.
pub(crate) async fn run(driver: &mut impl Driver, target: &Target) -> Result<()> {
    let mut failures = 0;
    let mut group_state = group::State::default();
    loop {
        if !driver.live() {
            return Ok(());
        }
        let started = tokio::time::Instant::now();
        let result = connected(driver, target, &mut group_state).await;
        if result != Err("unavailable") || !driver.live() {
            return result;
        }
        if started.elapsed() > Duration::from_secs(30) {
            failures = 0;
        }
        failures += 1;
        if failures >= 2 {
            return result;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
async fn connected(
    driver: &mut impl Driver,
    target: &Target,
    group_state: &mut group::State,
) -> Result<()> {
    diagnostic(c"connected:entered");
    // A reconnect must complete before the server's 30-second participant
    // lease expires. Signing, TLS and first admission share one deadline.
    let (mut control, first) = tokio::time::timeout(Duration::from_secs(12), async {
        diagnostic(c"connected:before_sign");
        let signed = driver
            .operation(
                "call_authorization",
                json!({"include_proof":true,
            "operation":{"type":"heartbeat","call_id":target.call_id}}),
            )
            .await?;
        diagnostic(c"connected:after_sign");
        let config = WebSocketConfig::default()
            .max_message_size(Some(QUEUE_BYTES))
            .max_frame_size(Some(QUEUE_BYTES));
        diagnostic(c"connected:before_socket");
        let socket = connect_control_socket(&target.url, config).await?;
        diagnostic(c"connected:after_socket");
        let mut control = Control {
            socket,
            pending: VecDeque::new(),
            bytes: 0,
        };
        let first = control.signed(signed).await?;
        diagnostic(c"connected:after_first");
        Ok::<_, &'static str>((control, first))
    })
    .await
    .map_err(|_| "unavailable")??;
    diagnostic(c"connected:before_maintain");
    let result = maintain(
        driver,
        target,
        &mut control,
        first["call"].clone(),
        group_state,
    )
    .await;
    // Best effort terminal cleanup; transport failure retains the short server
    // lease for reconnection, and never signs leave on behalf of a successor.
    if result != Err("unavailable") && driver.live() {
        // Permission loss stops capture before any best-effort network cleanup.
        let _ = driver.media(json!({"op":"stop"})).await;
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            control.command(driver, json!({"type":"leave","call_id":target.call_id})),
        )
        .await;
    }
    result
}
async fn maintain(
    driver: &mut impl Driver,
    target: &Target,
    control: &mut Control,
    initial: Value,
    group_state: &mut group::State,
) -> Result<()> {
    if initial["kind"] == "group" {
        return group::maintain(driver, target, control, initial, group_state).await;
    }
    target.validate(&initial)?;
    let mut call = initial;
    let mut epoch = 0;
    let mut remote = None;
    let mut nonces = BTreeMap::new();
    let mut outbound = VecDeque::<Value>::new();
    let mut last_media = Value::Null;
    let mut poll = tokio::time::interval(Duration::from_millis(150));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut disconnected = None;
    let mut retry_at = None;
    let mut negotiation_started = None;
    loop {
        if !driver.live() {
            return Ok(());
        }
        let next_epoch = call["key_epoch"].as_u64().ok_or("invalid")?;
        if next_epoch != epoch {
            target.validate(&call)?;
            epoch = next_epoch;
            remote = target.remote(&call);
            outbound.clear();
            nonces.clear();
            disconnected = None;
            retry_at = None;
            negotiation_started = None;
            let servers = if remote.is_some() {
                let access = control
                    .command(
                        driver,
                        json!({"type":"connect_media","call_id":target.call_id}),
                    )
                    .await?;
                target.validate(&access["call"])?;
                if access["call"]["key_epoch"] != epoch {
                    call = access["call"].clone();
                    epoch = 0;
                    continue;
                }
                if access["media"]["provider"] != "p2p" || access["media"]["epoch"] != epoch {
                    return Err("invalid");
                }
                access["media"]["ice_servers"].clone()
            } else {
                json!([])
            };
            driver
                .media(json!({"op":"reset","ice_servers":servers}))
                .await?;
            driver.changed(&call, false).await?;
            if let Some(peer) = remote.as_deref() {
                if target.leader(peer) {
                    driver.media(json!({"op":"offer"})).await?;
                } else {
                    outbound.push_back(json!({"type":"request_offer"}));
                }
                retry_at = Some(tokio::time::Instant::now());
                negotiation_started = retry_at;
            }
        }
        let event = tokio::select! {
            biased;
            _ = heartbeat.tick() => {
                let result = control.command(driver, json!({"type":"heartbeat","call_id":target.call_id})).await?;
                Some(json!({"type":"presence","call":result["call"]}))
            },
            _ = poll.tick() => {
                let state = driver.media(json!({"op":"poll"})).await?;
                let signals = state["signals"].as_array().ok_or("invalid")?;
                if remote.is_some() {
                    if outbound.len() + signals.len() > 256 || signals.iter().map(|s| s.to_string().len()).sum::<usize>()
                        + outbound.iter().map(|s| s.to_string().len()).sum::<usize>() > QUEUE_BYTES { return Err("overflow"); }
                    outbound.extend(signals.iter().cloned());
                    let now = tokio::time::Instant::now();
                    match state["connection"].as_str() {
                        Some("connected") => { disconnected = None; retry_at = None; negotiation_started = None; },
                        Some("closed") => return Err("unavailable"),
                        Some("disconnected" | "failed") => { disconnected.get_or_insert(now); },
                        _ => {},
                    }
                    let since = disconnected.or(negotiation_started);
                    if since.is_some_and(|start| start.elapsed() > Duration::from_secs(30)) { return Err("unavailable"); }
                    if since.is_some_and(|start| start.elapsed() > Duration::from_secs(5))
                        && retry_at.is_none_or(|start| start.elapsed() > Duration::from_secs(5)) {
                        if target.leader(remote.as_deref().unwrap()) { driver.media(json!({"op":"offer","restart":true})).await?; }
                        else { outbound.push_back(json!({"type":"request_offer"})); }
                        retry_at = Some(now);
                    }
                }
                driver.changed(&call, remote.is_some() && state["connection"] == "connected").await?;
                if state["media"].is_object() && !state["media"].as_object().unwrap().is_empty() && state["media"] != last_media {
                    let result = control.command(driver, json!({"type":"media","call_id":target.call_id,"state":state["media"]})).await?;
                    last_media = state["media"].clone();
                    Some(json!({"type":"presence","call":result["call"]}))
                } else { None }
            },
            _ = std::future::ready(()), if !control.pending.is_empty() => control.pop(),
            event = control.receive() => Some(event?),
            _ = std::future::ready(()), if !outbound.is_empty() && remote.is_some() => {
                let payload = outbound.pop_front().unwrap();
                let result = control.signal(driver, target, epoch, remote.as_deref().unwrap(), payload).await?;
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
                target.validate(next)?;
                if next["key_epoch"] == epoch && target.remote(next) != remote {
                    return Err("unauthorized");
                }
                call = next.clone();
            }
            Some("signal")
                if event["scope"] == target.scope()
                    && event["call_id"] == target.call_id
                    && event["epoch"] == epoch
                    && remote.as_deref().is_some_and(|peer| event["from"] == peer) =>
            {
                let opened = driver.operation("call_open_signal", json!({"call_id":target.call_id,"epoch":epoch,"from":event["from"],"ciphertext":event["ciphertext"]})).await?;
                if accept_signal(
                    target,
                    epoch,
                    remote.as_deref().unwrap(),
                    &opened["signal"],
                    &mut nonces,
                )? {
                    driver
                        .media(json!({"op":"signal","signal":opened["signal"]["payload"]}))
                        .await?;
                }
            }
            _ => {}
        }
    }
}
fn accept_signal(
    target: &Target,
    epoch: u64,
    remote: &str,
    signal: &Value,
    nonces: &mut BTreeMap<String, u64>,
) -> Result<bool> {
    if signal["from"] != remote
        || signal["to"] != target.context["credential"]
        || signal["config_id"] != target.context["config_id"]
        || signal["epoch"] != epoch
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "invalid")?
        .as_secs();
    nonces.retain(|_, expiry| *expiry > now);
    let nonce = signal["nonce"]
        .as_str()
        .filter(|n| n.len() <= 128)
        .ok_or("invalid")?;
    if nonces.contains_key(nonce) {
        return Ok(false);
    }
    if nonces.len() >= 2048 {
        return Err("overflow");
    }
    // Core already verifies signature, recipient and signed lifetime.
    nonces.insert(
        nonce.to_owned(),
        signal["expires_at"].as_u64().ok_or("invalid")?,
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn control_socket_uses_working_address_when_another_handshake_stalls() {
        let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ready = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stalled_address = stalled.local_addr().unwrap();
        let ready_address = ready.local_addr().unwrap();
        let stalled_task = tokio::spawn(async move {
            let (_stream, _) = stalled.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
        let ready_task = tokio::spawn(async move {
            let (stream, _) = ready.accept().await.unwrap();
            let _socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        });
        let url = format!("ws://localhost:{}/calls/v1/connect", ready_address.port());
        let connected = tokio::time::timeout(
            Duration::from_secs(2),
            connect_control_addresses(
                &url,
                WebSocketConfig::default(),
                [stalled_address, ready_address],
            ),
        )
        .await;
        assert!(matches!(connected, Ok(Ok(_))));
        stalled_task.abort();
        ready_task.abort();
    }

    fn target() -> Target {
        Target {
            url: String::new(),
            call_id: "session".into(),
            context: json!({
                "expected_identity":"me","credential":"a","config_id":"head",
                "hosting_space_id":"host","space":"space","stream":"chat",
                "members":{"me":["a"],"them":["b"]}
            }),
        }
    }
    fn call(epoch: u64, paired: bool) -> Value {
        let mut people = json!({"me":{"identity_id":"me","credential_id":"a"}});
        if paired {
            people["them"] = json!({"identity_id":"them","credential_id":"b"});
        }
        json!({"call_id":"session","scope":target().scope(),"kind":"direct","config_id":"head", "participants":people,"key_epoch":epoch})
    }
    #[test]
    fn solo_and_paired_require_the_exact_scope_head_and_joined_device() {
        let target = target();
        assert!(target.validate(&call(1, false)).is_ok());
        assert!(target.validate(&call(2, true)).is_ok());
        for (field, value) in [
            ("call_id", json!("other")),
            ("config_id", json!("old")),
            ("scope", json!({})),
            ("kind", json!("group")),
            ("key_epoch", json!(0)),
            (
                "participants",
                json!({"me":{"identity_id":"me","credential_id":"other"}}),
            ),
            (
                "participants",
                json!({"them":{"identity_id":"them","credential_id":"b"}}),
            ),
            (
                "participants",
                json!({"me":{"identity_id":"me","credential_id":"a"},"stranger":{"identity_id":"stranger","credential_id":"b"}}),
            ),
        ] {
            let mut invalid = call(2, true);
            invalid[field] = value;
            assert!(target.validate(&invalid).is_err(), "{field}");
        }
    }
    fn signal(epoch: u64) -> Value {
        json!({"from":"b","to":"a","config_id":"head","epoch":epoch,"nonce":"one",
            "expires_at":u64::MAX,"payload":{"type":"answer","sdp":"synthetic"}})
    }
    #[test]
    fn signed_signals_bind_epoch_audience_role_and_replay_nonce() {
        let target = target();
        let mut nonces = BTreeMap::new();
        assert_eq!(
            accept_signal(&target, 4, "b", &signal(4), &mut nonces),
            Ok(true)
        );
        assert_eq!(
            accept_signal(&target, 4, "b", &signal(4), &mut nonces),
            Ok(false)
        );
        assert_eq!(
            accept_signal(&target, 4, "b", &signal(2), &mut BTreeMap::new()),
            Err("unauthorized")
        );
        for (field, value) in [
            ("from", json!("other")),
            ("to", json!("other")),
            ("config_id", json!("old")),
            ("payload", json!({"type":"offer"})),
        ] {
            let mut invalid = signal(4);
            invalid[field] = value;
            assert!(accept_signal(&target, 4, "b", &invalid, &mut BTreeMap::new()).is_err());
        }
    }
    #[test]
    fn command_context_cannot_follow_a_new_head_or_changed_route() {
        use base64::Engine;
        let key = elo_core::identity::generate_signing_key().unwrap();
        let context = json!({"config_id":"head","credential":"a","hosting_space_id":"host","space":"space","stream":"chat","audience":"https://call.example"});
        let body = json!({"v":1,"kind":"call.command","config_id":"head","credential_id":"a","hosting_space_id":"host","scope":{"space_id":"space","stream_id":"chat"},"audience":"https://call.example"});
        let signed = |body: Value| {
            let record =
                elo_core::record::SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &key)
                    .unwrap();
            json!({"command":base64::engine::general_purpose::STANDARD.encode(record.bytes())})
        };
        assert!(validate_command(&context, &signed(body.clone())).is_ok());
        for (field, value) in [
            ("config_id", json!("new-head")),
            ("credential_id", json!("other")),
            ("hosting_space_id", json!("other")),
            ("audience", json!("https://other.example")),
            ("scope", json!({"space_id":"space","stream_id":"other"})),
        ] {
            let mut invalid = body.clone();
            invalid[field] = value;
            assert_eq!(
                validate_command(&context, &signed(invalid)),
                Err("unauthorized")
            );
        }
    }
    #[test]
    fn forged_membership_from_ipc_is_never_a_native_context() {
        assert!(
            verified_context(
                &target().context,
                &json!({"command":"not-a-signed-record","proof":{"members":{"me":["a"]}}})
            )
            .is_err()
        );
    }
    #[test]
    fn witnessed_general_requires_the_independent_core_pin() {
        use base64::Engine;
        use elo_core::{authority::*, ids::StreamId, record, vault::Session};
        let (owner, recovery) = Session::create().unwrap();
        let root = recovery.recover_root(owner.identity_id()).unwrap();
        let root_key = record::encode_hex(root.verifying_key().as_bytes());
        let witness = elo_core::identity::generate_signing_key().unwrap();
        let pin = WitnessPin {
            url: "https://witness.example.test/witness/v1".into(),
            public_key: record::encode_hex(witness.verifying_key().as_bytes()),
            key_generation: 1,
        };
        let genesis = record::SignedRecord::sign(
            &serde_json::to_vec(&SpaceGenesis {
                v: 4,
                kind: "space.genesis".into(),
                nonce: record::random_hex::<16>().unwrap(),
                issuer_identity: owner.identity_id(),
                owners: vec![Owner {
                    identity_id: owner.identity_id(),
                    root_public_key: root_key.clone(),
                }],
                controller_credential_id: owner.credential().id(),
                witness: Some(pin.clone()),
            })
            .unwrap(),
            owner.signing_key(),
        )
        .unwrap();
        let mut authority = Authority::new(
            genesis.bytes(),
            genesis.id().to_string().parse().unwrap(),
            &root.verifying_key(),
            owner.credential().clone(),
            StreamId::from_bytes([7; 16]),
        )
        .unwrap();
        let config = StreamConfig {
            v: 4,
            kind: "stream.config".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: owner.credential().id(),
            members: vec![Member {
                identity_id: owner.identity_id(),
                identity_type: "HUMAN".into(),
                root_public_key: root_key,
                capabilities: vec![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ],
                credential_ids: vec![owner.credential().id()],
                external: false,
            }],
            owner_credential_ids: vec![owner.credential().id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: owner.identity_id(),
                request_record_id: None,
            },
            chat_kind: Some(ChatKind::Chat),
            recovery: None,
            witness_evidence: None,
        };
        authority
            .apply_config(config.sign(owner.signing_key()).unwrap())
            .unwrap();
        let context = json!({"expected_identity":owner.identity_id(), "space":authority.space(),
            "stream":authority.stream(), "hosting_space_id":authority.space(), "audience":"https://calls.example.test/calls/v1"});
        let command = elo_core::calls::sign_command(
            &authority,
            &owner,
            authority.space(),
            "https://calls.example.test/calls/v1",
            elo_core::calls::Operation::Subscribe,
            1_800_000_000,
        )
        .unwrap();
        let mut signed = json!({"command":base64::engine::general_purpose::STANDARD.encode(command.bytes()),
            "proof":authority.call_proof().unwrap(), "trusted_witness":pin});
        let verified = verified_context(&context, &signed).unwrap();
        assert_eq!(verified["kind"], "group");
        assert_eq!(verified["credential"], json!(owner.credential().id()));
        signed["trusted_witness"]["key_generation"] = json!(2);
        assert_eq!(verified_context(&context, &signed), Err("unauthorized"));
        signed["trusted_witness"] = Value::Null;
        let mut forged_ipc = context;
        forged_ipc["trusted_witness"] = json!(pin);
        assert_eq!(verified_context(&forged_ipc, &signed), Err("unauthorized"));
    }
    struct TestDriver {
        locked: bool,
        media: Vec<Value>,
        opened: Vec<u64>,
        changes: tokio::sync::mpsc::Sender<u64>,
        last_epoch: u64,
    }
    impl Driver for TestDriver {
        async fn operation(&mut self, op: &str, fields: Value) -> Result<Value> {
            if self.locked {
                return Err("unauthorized");
            }
            Ok(match op {
                "call_authorization" => json!({"command":fields["operation"],"proof":"synthetic"}),
                "call_open_signal" => {
                    let epoch = fields["epoch"].as_u64().unwrap();
                    self.opened.push(epoch);
                    json!({"signal":signal(epoch)})
                }
                "call_encrypt_signal" => json!({"ciphertext":"synthetic-encrypted-signal"}),
                _ => panic!("Unexpected operation"),
            })
        }
        async fn media(&mut self, request: Value) -> Result<Value> {
            self.media.push(request.clone());
            if request["op"] == "signal" {
                self.changes.send(100).await.unwrap();
            }
            Ok(if request["op"] == "poll" {
                json!({"connection":"connected","signals":[],"media":{}})
            } else {
                json!({})
            })
        }
        async fn changed(&mut self, call: &Value, connected: bool) -> Result<()> {
            if call["participants"].as_object().unwrap().len() == 1 {
                assert!(
                    !connected,
                    "A direct call without its recipient is still waiting"
                );
            }
            let epoch = call["key_epoch"].as_u64().unwrap();
            if self.last_epoch != epoch {
                self.last_epoch = epoch;
                self.changes.send(epoch).await.unwrap();
            }
            Ok(())
        }
        fn live(&self) -> bool {
            true
        }
    }
    #[tokio::test]
    async fn locked_profile_never_connects_or_touches_capture() {
        let (changes, _) = tokio::sync::mpsc::channel(8);
        let mut driver = TestDriver {
            locked: true,
            media: vec![],
            opened: vec![],
            changes,
            last_epoch: 0,
        };
        assert_eq!(run(&mut driver, &target()).await, Err("unauthorized"));
        assert!(driver.media.is_empty());
    }
    #[tokio::test]
    async fn native_owner_handles_solo_join_leave_rejoin_without_webview_and_ignores_old_sdp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = target();
        target.url = format!("ws://{}", listener.local_addr().unwrap());
        let scope = target.scope();
        let (changes, mut changed) = tokio::sync::mpsc::channel(8);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut current = call(1, false);
            loop {
                tokio::select! {
                    request = socket.next() => {
                        let request: Value = serde_json::from_str(&request.unwrap().unwrap().into_text().unwrap()).unwrap();
                        let op = &request["command"];
                        let media = if op["type"] == "connect_media" { json!({"provider":"p2p","epoch":current["key_epoch"],"ice_servers":[{"urls":["stun:example.test"]}]}) } else { Value::Null };
                        socket.send(Message::Text(json!({"type":"result","call":current,"media":media}).to_string().into())).await.unwrap();
                        if op["type"] == "leave" { break; }
                    },
                    change = changed.recv() => {
                        match change.unwrap() {
                            1 => current = call(2, true),
                            2 => current = call(3, false),
                            3 => current = call(4, true),
                            4 => {
                                for epoch in [2, 4] {
                                    socket.send(Message::Text(json!({"type":"signal","scope":scope,"call_id":"session","epoch":epoch,"from":"b","to":"a","ciphertext":"synthetic"}).to_string().into())).await.unwrap();
                                }
                                continue;
                            },
                            100 => {
                                socket.send(Message::Text(json!({"type":"ended","scope":scope,"call_id":"session"}).to_string().into())).await.unwrap();
                                continue;
                            },
                            _ => panic!("Unexpected epoch"),
                        }
                        socket.send(Message::Text(json!({"type":"presence","call":current}).to_string().into())).await.unwrap();
                    }
                }
            }
        });
        let mut driver = TestDriver {
            locked: false,
            media: vec![],
            opened: vec![],
            changes,
            last_epoch: 0,
        };
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), run(&mut driver, &target))
                .await
                .unwrap(),
            Ok(())
        );
        assert_eq!(driver.opened, vec![4]);
        let resets: Vec<_> = driver
            .media
            .iter()
            .filter(|request| request["op"] == "reset")
            .collect();
        assert_eq!(resets.len(), 4);
        assert_eq!(
            resets
                .iter()
                .map(|request| request["ice_servers"].as_array().unwrap().len())
                .collect::<Vec<_>>(),
            vec![0, 1, 0, 1]
        );
        assert_eq!(
            driver
                .media
                .iter()
                .filter(|request| request["op"] == "offer")
                .count(),
            2
        );
        assert_eq!(
            driver
                .media
                .iter()
                .filter(|request| request["op"] == "signal")
                .count(),
            1
        );
        server.await.unwrap();
    }
}

#[cfg(test)]
mod delegation_transport_tests {
    use super::*;
    #[test]
    fn retains_call_only_certificate_without_forwarding_unrelated_secrets() {
        assert_eq!(
            command_envelope(
                &json!({"command":"signed","proof":null,"delegation":"certificate","secret":"never-forward"})
            ),
            json!({"command":"signed","proof":null,"delegation":"certificate"})
        );
        assert_eq!(
            command_envelope(&json!({"command":"signed","proof":"proof"})),
            json!({"command":"signed","proof":"proof"})
        );
    }
}

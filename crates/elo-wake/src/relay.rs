//! Device possession, recipient-owned scope policy and durable FCM delivery.
//! Routes are random capabilities; signed account bindings enable account erasure.
use crate::fcm::{self, Fcm, Notice};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::Path as FilePath,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
mod calls;

type Result<T> = std::result::Result<T, StatusCode>;
pub trait Provider: Send + Sync {
    fn send(
        &self,
        token: String,
        notice: Notice,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), fcm::Error>> + Send + '_>>;
}
impl Provider for Fcm {
    fn send(
        &self,
        token: String,
        notice: Notice,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), fcm::Error>> + Send + '_>> {
        Box::pin(async move { Fcm::send(self, &token, &notice).await })
    }
}

pub struct Relay {
    db: Mutex<Connection>,
    provider: Arc<dyn Provider>,
    delivery_gate: tokio::sync::Mutex<()>,
    endpoint: String,
    call_key: Option<zeroize::Zeroizing<String>>,
    apns: Option<crate::apns::Apns>,
}
struct Route {
    owner: Vec<u8>,
    notify: Vec<u8>,
    token: String,
    challenge: String,
    active: bool,
    expires: i64,
    next_send: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    token: String,
    notify_key: String,
    binding: elo_core::app::account_deletion::Request,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    challenge: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Wake {
    event: String,
    scope: String,
    target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sender: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadReceipts {
    events: Vec<ReadReceipt>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadReceipt {
    scope: String,
    event: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    revision: i64,
    #[serde(default)]
    introductions: bool,
    scopes: Vec<Scope>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    authenticated_senders: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    blocked_senders: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    scope: String,
    enabled: bool,
    #[serde(default = "default_alert_once", skip_serializing_if = "is_true")]
    alert_once: bool,
}
fn default_alert_once() -> bool {
    true
}
fn is_true(value: &bool) -> bool {
    *value
}

fn hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}
fn secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs() as i64)
}
fn auth(headers: &HeaderMap) -> Result<String> {
    let key = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|h| hex(h, 32))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(key.to_owned())
}
fn matches(expected: &[u8], key: &str) -> bool {
    bool::from(expected.ct_eq(&hash(key)))
}
fn db_error(_: rusqlite::Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}
fn row(db: &Connection, id: &str) -> Result<Option<Route>> {
    db.query_row(
        "SELECT owner,notify,token,challenge,active,expires,next_send FROM routes WHERE id=?",
        [id],
        |row| {
            Ok(Route {
                owner: row.get(0)?,
                notify: row.get(1)?,
                token: row.get(2)?,
                challenge: row.get(3)?,
                active: row.get(4)?,
                expires: row.get(5)?,
                next_send: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(db_error)
}
impl Relay {
    pub fn open(
        path: &FilePath,
        provider: Arc<dyn Provider>,
    ) -> std::result::Result<Arc<Self>, &'static str> {
        let parent = path.parent().ok_or("Invalid private relay directory")?;
        std::fs::create_dir_all(parent).map_err(|_| "Cannot create relay directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            if std::fs::symlink_metadata(parent)
                .map_err(|_| "Invalid relay directory")?
                .file_type()
                .is_symlink()
            {
                return Err("Relay directory must not be a symbolic link");
            }
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "Cannot protect relay directory")?;
            if path.exists() {
                let meta = std::fs::symlink_metadata(path).map_err(|_| "Invalid relay database")?;
                if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
                    return Err("Relay database must be private");
                }
            } else {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|_| "Cannot create relay database")?;
            }
        }
        let db = Connection::open(path).map_err(|_| "Cannot open relay database")?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS routes (
                id TEXT PRIMARY KEY, owner BLOB NOT NULL, notify BLOB NOT NULL,
                token TEXT NOT NULL, challenge TEXT NOT NULL, active INTEGER NOT NULL,
                expires INTEGER NOT NULL,last_event TEXT,next_send INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS route_token ON routes(token);
            CREATE TABLE IF NOT EXISTS policy_versions(route TEXT PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE, revision INTEGER NOT NULL, introductions INTEGER NOT NULL, digest BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS scopes(route TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE, scope TEXT NOT NULL, enabled INTEGER NOT NULL, PRIMARY KEY(route,scope));
            CREATE TABLE IF NOT EXISTS events(route TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE, event TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(route,event));
            CREATE INDEX IF NOT EXISTS event_expiry ON events(expires);
            CREATE TABLE IF NOT EXISTS attention(route TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE, scope TEXT NOT NULL, event TEXT NOT NULL, PRIMARY KEY(route,scope));
            CREATE TABLE IF NOT EXISTS repeat_alerts(route TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE, scope TEXT NOT NULL, PRIMARY KEY(route,scope));
            CREATE TABLE IF NOT EXISTS queue(route TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE, scope TEXT NOT NULL, event TEXT NOT NULL, target TEXT NOT NULL, next INTEGER NOT NULL, expires INTEGER NOT NULL, failures INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(route,scope));",
        )
        .map_err(|_| "Cannot initialize relay database")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS sender_policy(route TEXT PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE, authenticated INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS blocked_senders(route TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE, sender TEXT NOT NULL, PRIMARY KEY(route,sender));").map_err(|_| "Cannot initialize sender policy")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS route_accounts(route TEXT PRIMARY KEY REFERENCES routes(id) ON DELETE CASCADE, identity TEXT NOT NULL); CREATE INDEX IF NOT EXISTS route_accounts_identity ON route_accounts(identity); CREATE TABLE IF NOT EXISTS erased_accounts(identity TEXT PRIMARY KEY, request_id TEXT NOT NULL, completed INTEGER NOT NULL);").map_err(|_| "Cannot initialize account erasure")?;
        let has_sender: bool = db
            .prepare("PRAGMA table_info(queue)")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(|_| "Cannot read queue schema")?
            .iter()
            .any(|column| column == "sender");
        if !has_sender {
            db.execute("ALTER TABLE queue ADD COLUMN sender TEXT", [])
                .map_err(|_| "Cannot migrate notification queue")?;
        }
        calls::schema(&db).map_err(|_| "Cannot initialize call delivery")?;
        Ok(Arc::new(Self {
            db: Mutex::new(db),
            provider,
            delivery_gate: tokio::sync::Mutex::new(()),
            endpoint: "https://api.elo.now".into(),
            call_key: None,
            apns: None,
        }))
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route(
                elo_core::app::account_deletion::WAKE_PATH,
                post(erase_account),
            )
            .route("/v1/routes/{id}", post(register).delete(remove))
            .route("/v1/routes/{id}/confirm", post(confirm))
            .route("/v1/routes/{id}/wake", post(wake))
            .route("/v1/routes/{id}/policy", put(policy))
            .route("/v1/routes/{id}/read", post(read))
            .route("/v1/routes/{id}/calls", put(calls::register))
            .route(
                "/v1/routes/{id}/calls/{call_id}",
                get(calls::status).delete(calls::decline),
            )
            .route("/wake/health", get(|| async { StatusCode::NO_CONTENT }))
            .layer(DefaultBodyLimit::max(1024 * 1024))
            .with_state(self)
    }
    pub fn with_calls(
        mut self: Arc<Self>,
        key: zeroize::Zeroizing<String>,
        apns: Option<crate::apns::Apns>,
    ) -> std::result::Result<Arc<Self>, &'static str> {
        if !hex(&key, 32) {
            return Err("Invalid call-delivery service key");
        }
        let this =
            Arc::get_mut(&mut self).ok_or("Configure call delivery before starting the relay")?;
        this.call_key = Some(key);
        this.apns = apns;
        Ok(self)
    }
    /// Bind separately to loopback. Never merge this into the public router.
    pub fn private_call_router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/internal/calls/event", post(calls::event))
            .route("/internal/calls/declined", post(calls::declined))
            .layer(DefaultBodyLimit::max(32 * 1024))
            .with_state(self)
    }
    pub fn with_endpoint(
        mut self: Arc<Self>,
        endpoint: &str,
    ) -> std::result::Result<Arc<Self>, &'static str> {
        let url = elo_core::app::push::endpoint(endpoint, false)
            .map_err(|_| "Invalid public relay URL")?;
        Arc::get_mut(&mut self)
            .ok_or("Configure the relay before starting it")?
            .endpoint = url.origin().ascii_serialization();
        Ok(self)
    }
    fn database(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

async fn erase_account(
    State(relay): State<Arc<Relay>>,
    Json(request): Json<elo_core::app::account_deletion::Request>,
) -> Result<Json<elo_core::app::account_deletion::Response>> {
    use elo_core::app::account_deletion::{self as protocol, Action, Outcome, Status};
    let endpoint = format!("{}{}", relay.endpoint, protocol::WAKE_PATH);
    let time = now()? as u64 * 1000;
    let (command, credential) =
        protocol::verify(&request, &endpoint, time).map_err(|_| StatusCode::BAD_REQUEST)?;
    let identity = credential.identity().to_string();
    let _gate = relay.delivery_gate.lock().await;
    let mut db = relay.database()?;
    let previous: Option<(String, u64)> = db
        .query_row(
            "SELECT request_id,completed FROM erased_accounts WHERE identity=?1",
            [&identity],
            |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
        )
        .optional()
        .map_err(db_error)?;
    let completed = if let Some(previous) = previous {
        Some(previous)
    } else if command.action == Action::Submit {
        let id = secret()?;
        db.execute_batch("PRAGMA secure_delete=ON;")
            .map_err(db_error)?;
        let tx = db.transaction().map_err(db_error)?;
        tx.execute(
            "INSERT INTO erased_accounts VALUES(?1,?2,?3)",
            params![identity, id, time as i64],
        )
        .map_err(db_error)?;
        tx.execute(
            "DELETE FROM routes WHERE id IN(SELECT route FROM route_accounts WHERE identity=?1)",
            [&identity],
        )
        .map_err(db_error)?;
        tx.execute("DELETE FROM call_declines WHERE identity=?", [&identity])
            .map_err(db_error)?;
        let routes = {
            let mut q = tx.prepare("SELECT id FROM routes").map_err(db_error)?;
            q.query_map([], |r| r.get::<_, String>(0))
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?
        };
        for route in routes {
            let tag = elo_core::app::push_sender::sender_tag(&route, credential.identity());
            tx.execute(
                "DELETE FROM call_queue WHERE route=?1 AND sender=?2",
                params![route, tag],
            )
            .map_err(db_error)?;
            tx.execute("DELETE FROM attention WHERE (route,scope) IN(SELECT route,scope FROM queue WHERE route=?1 AND sender=?2)",params![route,tag]).map_err(db_error)?;
            tx.execute("DELETE FROM events WHERE (route,event) IN(SELECT route,event FROM queue WHERE route=?1 AND sender=?2)",params![route,tag]).map_err(db_error)?;
            tx.execute(
                "DELETE FROM queue WHERE route=?1 AND sender=?2",
                params![route, tag],
            )
            .map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(db_error)?;
        Some((id, time))
    } else {
        None
    };
    let outcome = if let Some((id, time)) = completed {
        Outcome {
            status: Status::Completed,
            owned_spaces: vec![],
            request_id: Some(id),
            requested_at: Some(time),
            completed_at: Some(time),
            receipts: Vec::new(),
        }
    } else {
        Outcome {
            status: Status::Ready,
            owned_spaces: vec![],
            request_id: None,
            requested_at: None,
            completed_at: None,
            receipts: Vec::new(),
        }
    };
    protocol::seal(&command, &credential, &outcome)
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

async fn register(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Registration>,
) -> Result<Json<Value>> {
    let _gate = relay.delivery_gate.lock().await;
    let identity = elo_core::app::account_deletion::verify_route_binding(
        &input.binding,
        &relay.endpoint,
        &id,
        &input.token,
        now()? as u64 * 1000,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?
    .identity()
    .to_string();
    let owner = auth(&headers)?;
    if !hex(&id, 16)
        || !hex(&input.notify_key, 32)
        || input.token.len() < 16
        || input.token.len() > 4096
        || !input
            .token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let time = now()?;
    let challenge = {
        let db = relay.database()?;
        if db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM erased_accounts WHERE identity=?1)",
                [&identity],
                |r| r.get::<_, bool>(0),
            )
            .map_err(db_error)?
        {
            return Err(StatusCode::GONE);
        }
        db.execute("DELETE FROM routes WHERE expires<=?", [time])
            .map_err(db_error)?;
        if let Some(saved) = row(&db, &id)? {
            let bound: Option<String> = db
                .query_row(
                    "SELECT identity FROM route_accounts WHERE route=?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db_error)?;
            if bound.as_deref() != Some(&identity) {
                return Err(StatusCode::FORBIDDEN);
            }
            if !matches(&saved.owner, &owner)
                || !matches(&saved.notify, &input.notify_key)
                || saved.token != input.token
            {
                return Err(StatusCode::FORBIDDEN);
            }
            if saved.active {
                db.execute(
                    "UPDATE routes SET expires=? WHERE id=?",
                    params![time + 30 * 86400, id],
                )
                .map_err(db_error)?;
                return Ok(Json(json!({"active":true})));
            }
            if saved.next_send > time {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            db.execute(
                "UPDATE routes SET next_send=? WHERE id=?",
                params![time + 10, id],
            )
            .map_err(db_error)?;
            saved.challenge
        } else {
            let total: i64 = db
                .query_row("SELECT count(*) FROM routes", [], |r| r.get(0))
                .map_err(db_error)?;
            let same: i64 = db
                .query_row(
                    "SELECT count(*) FROM routes WHERE token=?",
                    [&input.token],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if total >= 10000 || same >= 8 {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            let challenge = secret()?;
            db.execute("INSERT INTO routes(id,owner,notify,token,challenge,active,expires,next_send) VALUES(?,?,?,?,?,0,?,?)",
                params![id,hash(&owner),hash(&input.notify_key),input.token,challenge,time+600,time+10]).map_err(db_error)?;
            db.execute(
                "INSERT INTO route_accounts VALUES(?1,?2)",
                params![id, identity],
            )
            .map_err(db_error)?;
            challenge
        }
    };
    relay
        .provider
        .send(
            input.token,
            Notice::Challenge {
                registration: id,
                challenge,
            },
        )
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(json!({"active":false})))
}
async fn confirm(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Confirmation>,
) -> Result<Json<Value>> {
    let owner = auth(&headers)?;
    let time = now()?;
    let db = relay.database()?;
    let saved = row(&db, &id)?.ok_or(StatusCode::NOT_FOUND)?;
    if !matches(&saved.owner, &owner)
        || saved.expires <= time
        || !hex(&input.challenge, 32)
        || !bool::from(saved.challenge.as_bytes().ct_eq(input.challenge.as_bytes()))
    {
        return Err(StatusCode::FORBIDDEN);
    }
    db.execute(
        "UPDATE routes SET active=1,expires=?,next_send=0 WHERE id=?",
        params![time + 30 * 86400, id],
    )
    .map_err(db_error)?;
    Ok(Json(json!({"active":true})))
}
async fn remove(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let owner = auth(&headers)?;
    let _gate = relay.delivery_gate.lock().await;
    let db = relay.database()?;
    if let Some(saved) = row(&db, &id)? {
        if !matches(&saved.owner, &owner) {
            return Err(StatusCode::FORBIDDEN);
        }
        db.execute("DELETE FROM routes WHERE id=?", [id])
            .map_err(db_error)?;
    }
    Ok(StatusCode::NO_CONTENT)
}
// Replacing the allowlist also deletes queued notifications for muted/removed
// scopes. Once this operation acknowledges, no worker can start their delivery.
async fn policy(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Policy>,
) -> Result<StatusCode> {
    let owner = auth(&headers)?;
    if input.revision < 1
        || input.scopes.len() > 4096
        || input.blocked_senders.len() > 4096
        || input.blocked_senders.iter().any(|s| !hex(s, 32))
        || (!input.blocked_senders.is_empty() && !input.authenticated_senders)
        || input.scopes.iter().any(|s| !hex(&s.scope, 32))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let distinct = input
        .scopes
        .iter()
        .map(|s| &s.scope)
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() != input.scopes.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let _gate = relay.delivery_gate.lock().await;
    let mut db = relay.database()?;
    let saved = row(&db, &id)?.ok_or(StatusCode::NOT_FOUND)?;
    if !matches(&saved.owner, &owner) || !saved.active || saved.expires <= now()? {
        return Err(StatusCode::FORBIDDEN);
    }
    let revision: i64 = db
        .query_row(
            "SELECT revision FROM policy_versions WHERE route=?",
            [&id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?
        .unwrap_or(0);
    if input.revision < revision {
        return Err(StatusCode::CONFLICT);
    }
    let digest = hash(&serde_json::to_string(&input).map_err(|_| StatusCode::BAD_REQUEST)?);
    if input.revision == revision {
        let previous: Vec<u8> = db
            .query_row(
                "SELECT digest FROM policy_versions WHERE route=?",
                [&id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        return if previous == digest {
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(StatusCode::CONFLICT)
        };
    }
    let tx = db.transaction().map_err(db_error)?;
    tx.execute("INSERT INTO sender_policy VALUES(?,?) ON CONFLICT(route) DO UPDATE SET authenticated=excluded.authenticated", params![id,input.authenticated_senders]).map_err(db_error)?;
    tx.execute("DELETE FROM blocked_senders WHERE route=?", [&id])
        .map_err(db_error)?;
    for sender in &input.blocked_senders {
        tx.execute(
            "INSERT OR IGNORE INTO blocked_senders VALUES(?,?)",
            params![id, sender],
        )
        .map_err(db_error)?;
    }
    tx.execute("DELETE FROM queue WHERE route=? AND ((sender IS NULL AND ?=1) OR EXISTS(SELECT 1 FROM blocked_senders b WHERE b.route=queue.route AND b.sender=queue.sender))", params![id,input.authenticated_senders]).map_err(db_error)?;
    tx.execute("UPDATE scopes SET enabled=0 WHERE route=?", [&id])
        .map_err(db_error)?;
    tx.execute("DELETE FROM repeat_alerts WHERE route=?", [&id])
        .map_err(db_error)?;
    for scope in input.scopes {
        if !scope.alert_once {
            tx.execute(
                "INSERT OR IGNORE INTO repeat_alerts VALUES(?,?)",
                params![id, scope.scope],
            )
            .map_err(db_error)?;
            tx.execute(
                "DELETE FROM attention WHERE route=? AND scope=?",
                params![id, scope.scope],
            )
            .map_err(db_error)?;
        }
        tx.execute("INSERT INTO scopes(route,scope,enabled) VALUES(?,?,?) ON CONFLICT(route,scope) DO UPDATE SET enabled=excluded.enabled",params![id,scope.scope,scope.enabled]).map_err(db_error)?;
    }
    tx.execute("INSERT INTO policy_versions VALUES(?,?,?,?) ON CONFLICT(route) DO UPDATE SET revision=excluded.revision,introductions=excluded.introductions,digest=excluded.digest",params![id,input.revision,input.introductions,digest]).map_err(db_error)?;
    tx.execute("DELETE FROM queue WHERE route=? AND (EXISTS(SELECT 1 FROM scopes s WHERE s.route=queue.route AND s.scope=queue.scope AND s.enabled=0) OR (NOT EXISTS(SELECT 1 FROM scopes s WHERE s.route=queue.route AND s.scope=queue.scope) AND NOT EXISTS(SELECT 1 FROM policy_versions p WHERE p.route=queue.route AND p.introductions=1)))",[&id]).map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}
// Only the device owner can re-arm a conversation. Reading an older alert must
// not re-arm a newer, still unread one; retries and delayed senders are harmless.
async fn read(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ReadReceipts>,
) -> Result<StatusCode> {
    let owner = auth(&headers)?;
    if input.events.is_empty()
        || input.events.len() > 32
        || input
            .events
            .iter()
            .any(|r| !hex(&r.scope, 32) || !hex(&r.event, 32))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let _gate = relay.delivery_gate.lock().await;
    let mut db = relay.database()?;
    let saved = row(&db, &id)?.ok_or(StatusCode::NOT_FOUND)?;
    let time = now()?;
    if !matches(&saved.owner, &owner) || !saved.active || saved.expires <= time {
        return Err(StatusCode::FORBIDDEN);
    }
    let tx = db.transaction().map_err(db_error)?;
    tx.execute("DELETE FROM events WHERE expires<=?", [time])
        .map_err(db_error)?;
    for receipt in input.events {
        // A read can arrive before its sender's delayed wake. Remember it using
        // the same bounded dedup ledger, with no message or identity information.
        let count: i64 = tx
            .query_row("SELECT count(*) FROM events WHERE route=?", [&id], |r| {
                r.get(0)
            })
            .map_err(db_error)?;
        let total: i64 = tx
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .map_err(db_error)?;
        if count < 4096 && total < 250_000 {
            tx.execute(
                "INSERT OR IGNORE INTO events VALUES(?,?,?)",
                params![id, receipt.event, time + 86400],
            )
            .map_err(db_error)?;
        }
        tx.execute(
            "DELETE FROM attention WHERE route=? AND scope=? AND event=?",
            params![id, receipt.scope, receipt.event],
        )
        .map_err(db_error)?;
        tx.execute(
            "DELETE FROM queue WHERE route=? AND scope=? AND event=?",
            params![id, receipt.scope, receipt.event],
        )
        .map_err(db_error)?;
    }
    tx.commit().map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn wake(
    State(relay): State<Arc<Relay>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Wake>,
) -> Result<StatusCode> {
    let key = auth(&headers)?;
    if !hex(&input.event, 32)
        || !hex(&input.scope, 32)
        || input.target.len() > 2048
        || input.target.len() < 64
        || URL_SAFE_NO_PAD.decode(&input.target).is_err()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let time = now()?;
    let mut db = relay.database()?;
    let saved = row(&db, &id)?.ok_or(StatusCode::NOT_FOUND)?;
    if !saved.active || saved.expires <= time || !matches(&saved.notify, &key) {
        return Err(StatusCode::FORBIDDEN);
    }
    let authenticated: bool = db
        .query_row(
            "SELECT authenticated FROM sender_policy WHERE route=?",
            [&id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?
        .unwrap_or(false);
    let sender_identity = input
        .sender
        .as_ref()
        .map(|_| {
            elo_core::app::push_sender::verify_identity(
                &id,
                &serde_json::to_value(&input).map_err(|_| StatusCode::BAD_REQUEST)?,
                time as u64,
            )
            .map_err(|_| StatusCode::FORBIDDEN)
        })
        .transpose()?;
    if let Some(identity) = sender_identity
        && db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM erased_accounts WHERE identity=?1)",
                [identity.to_string()],
                |r| r.get::<_, bool>(0),
            )
            .map_err(db_error)?
    {
        return Ok(StatusCode::ACCEPTED);
    }
    let sender =
        sender_identity.map(|identity| elo_core::app::push_sender::sender_tag(&id, identity));
    if authenticated && sender.is_none() {
        return Ok(StatusCode::ACCEPTED);
    }
    if let Some(sender) = &sender {
        let blocked: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM blocked_senders WHERE route=? AND sender=?)",
                params![id, sender],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if blocked {
            return Ok(StatusCode::ACCEPTED);
        }
    }
    let enabled = db
        .query_row(
            "SELECT enabled FROM scopes WHERE route=? AND scope=?",
            params![id, input.scope],
            |r| r.get::<_, bool>(0),
        )
        .optional()
        .map_err(db_error)?;
    // Unknown/muted scopes are acknowledged without exposing preference state.
    let introductions = db
        .query_row(
            "SELECT introductions FROM policy_versions WHERE route=?",
            [&id],
            |r| r.get::<_, bool>(0),
        )
        .optional()
        .map_err(db_error)?
        .unwrap_or(false);
    if enabled == Some(false) || (enabled.is_none() && !introductions) {
        return Ok(StatusCode::ACCEPTED);
    }
    let existing: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE route=? AND event=?)",
            params![id, input.event],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if existing {
        return Ok(StatusCode::ACCEPTED);
    }
    let queued: i64 = db
        .query_row("SELECT count(*) FROM queue WHERE route=?", [&id], |r| {
            r.get(0)
        })
        .map_err(db_error)?;
    if queued >= 64 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let tx = db.transaction().map_err(db_error)?;
    tx.execute("DELETE FROM events WHERE expires<=?", [time])
        .map_err(db_error)?;
    let count: i64 = tx
        .query_row("SELECT count(*) FROM events WHERE route=?", [&id], |r| {
            r.get(0)
        })
        .map_err(db_error)?;
    let total: i64 = tx
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .map_err(db_error)?;
    if count >= 4096 || total >= 250_000 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if tx
        .execute(
            "INSERT OR IGNORE INTO events VALUES(?,?,?)",
            params![id, input.event, time + 86400],
        )
        .map_err(db_error)?
        == 0
    {
        return Ok(StatusCode::ACCEPTED);
    }
    // A burst replaces the pending preview, but the dedup ledger remembers all events.
    tx.execute("INSERT INTO queue(route,scope,event,target,next,expires,sender) VALUES(?,?,?,?,?,?,?) ON CONFLICT(route,scope) DO UPDATE SET event=excluded.event,target=excluded.target,expires=excluded.expires,sender=excluded.sender",params![id,input.scope,input.event,input.target,time+2,time+86400,sender]).map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(StatusCode::ACCEPTED)
}
impl Relay {
    /// One bounded delivery; no mutex guard is held over a provider network call.
    pub async fn deliver_due(&self) -> Result<bool> {
        let _gate = self.delivery_gate.lock().await;
        let time = now()?;
        let item = {
            let db = self.database()?;
            db.execute("DELETE FROM routes WHERE expires<=?", [time])
                .map_err(db_error)?;
            db.execute("DELETE FROM queue WHERE expires<=?", [time])
                .map_err(db_error)?;
            db.query_row("SELECT q.route,q.scope,q.event,q.target,r.token,q.failures FROM queue q JOIN routes r ON q.route=r.id JOIN policy_versions p ON p.route=q.route LEFT JOIN scopes s ON s.route=q.route AND s.scope=q.scope WHERE r.active=1 AND NOT EXISTS(SELECT 1 FROM blocked_senders b WHERE b.route=q.route AND b.sender=q.sender) AND NOT (q.sender IS NULL AND EXISTS(SELECT 1 FROM sender_policy sp WHERE sp.route=q.route AND sp.authenticated=1)) AND (s.enabled=1 OR (s.scope IS NULL AND p.introductions=1)) AND q.next<=? AND r.next_send<=? ORDER BY q.next,q.route LIMIT 1",params![time,time],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,u32>(5)?))).optional().map_err(db_error)?
        };
        let Some((route, scope, event, target, token, failures)) = item else {
            return Ok(false);
        };
        // Updated clients declare a repeatable introduction scope and acknowledge
        // reads. Legacy policies cannot re-arm alerts, so keep their periodic alerts.
        let quiet = self
            .database()?
            .query_row(
            "SELECT EXISTS(SELECT 1 FROM attention WHERE route=?1 AND scope=?2) AND EXISTS(SELECT 1 FROM repeat_alerts WHERE route=?1) AND NOT EXISTS(SELECT 1 FROM repeat_alerts WHERE route=?1 AND scope=?2)",
                params![route, scope],
                |r| r.get::<_, bool>(0),
            )
            .map_err(db_error)?;
        let result = self
            .provider
            .send(
                token,
                Notice::Wake {
                    registration: route.clone(),
                    scope: scope.clone(),
                    target,
                    quiet,
                },
            )
            .await;
        let db = self.database()?;
        match result {
            Ok(()) => {
                db.execute("INSERT INTO attention VALUES(?,?,?) ON CONFLICT(route,scope) DO UPDATE SET event=excluded.event",
                    params![route,scope,event]).map_err(db_error)?;
                db.execute(
                    "DELETE FROM queue WHERE route=? AND scope=? AND event=?",
                    params![route, scope, event],
                )
                .map_err(db_error)?;
                db.execute(
                    "UPDATE routes SET next_send=? WHERE id=?",
                    params![time + 5, route],
                )
                .map_err(db_error)?;
            }
            Err(fcm::Error::Unregistered) => {
                db.execute("DELETE FROM routes WHERE id=?", [route])
                    .map_err(db_error)?;
            }
            Err(_) => {
                db.execute("UPDATE queue SET failures=failures+1,next=? WHERE route=? AND scope=? AND event=?",params![time+(5_i64 * 2_i64.pow(failures.min(6))).min(300),route,scope,event]).map_err(db_error)?;
            }
        }
        Ok(true)
    }
    pub async fn run(self: Arc<Self>) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            for _ in 0..32 {
                if !matches!(calls::deliver(&self).await, Ok(true)) {
                    break;
                }
            }
            for _ in 0..32 {
                if !matches!(self.deliver_due().await, Ok(true)) {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

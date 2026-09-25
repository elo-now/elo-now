//! Persistent authorization fences and replay admission. No media or signal
//! plaintext is persisted; active calls deliberately end on service restart.
use crate::registry::{ActiveCall, CallError, Event, Limits, Registry, Scope};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use elo_core::{
    authority::{Authority, CallAuthorityProof},
    calls::{self, Command},
    ids::{IdentityId, RecordId},
    record::SignedRecord,
};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::Arc};

type Result<T> = std::result::Result<T, CallError>;
const MAX_SCOPES: usize = 4096;
const MAX_CACHED_PROOFS: usize = 64 * 1024 * 1024;
pub const MAX_FRAME: usize = 9 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub command: String,
    pub proof: Option<CallAuthorityProof>,
}

pub struct Preparation {
    request: Request,
    signed: SignedRecord,
    scope: Scope,
    audience: String,
    cached: Option<Arc<Authority>>,
}
impl Preparation {
    pub fn authenticate(&self, now: u64) -> Result<(Command, IdentityId)> {
        let command: Command = self.signed.decode().map_err(|_| CallError::Invalid)?;
        let credential = match &self.request.proof {
            Some(proof) => proof.credential(command.credential_id),
            None => self
                .cached
                .as_ref()
                .ok_or(CallError::Unauthorized)?
                .credential(command.credential_id)
                .cloned(),
        }
        .map_err(|_| CallError::Unauthorized)?;
        let command =
            calls::verify_command_authorship(&credential, &self.signed, &self.audience, now)
                .map_err(|_| CallError::Unauthorized)?;
        Ok((command, credential.identity()))
    }
    /// CPU-bound proof verification runs without the shared engine lock.
    pub fn verify(self, now: u64) -> Result<Prepared> {
        let authority = match &self.request.proof {
            Some(proof) => Arc::new(
                proof
                    .verify(
                        self.scope.conversation.space_id,
                        self.scope.conversation.stream_id,
                    )
                    .map_err(|_| CallError::Unauthorized)?,
            ),
            None => self.cached.ok_or(CallError::Unauthorized)?,
        };
        let command = calls::verify_command(&authority, &self.signed, &self.audience, now)
            .map_err(|_| CallError::Unauthorized)?;
        let identity = calls::require_member(&authority, command.credential_id)
            .map_err(|_| CallError::Unauthorized)?;
        Ok(Prepared {
            command,
            identity,
            request_id: self.signed.id(),
            authority,
            proof: self.request.proof,
        })
    }
}

pub struct Prepared {
    pub command: Command,
    pub identity: IdentityId,
    pub request_id: RecordId,
    authority: Arc<Authority>,
    proof: Option<CallAuthorityProof>,
}
pub struct Applied {
    pub request_id: RecordId,
    pub scope: Scope,
    pub call: Option<ActiveCall>,
    pub events: Vec<Event>,
    pub duplicate: bool,
}
struct Fence {
    head: RecordId,
    recovery: Option<RecordId>,
    sequence: u64,
    authority: Option<Arc<Authority>>,
    proof_bytes: usize,
    last_used: u64,
    blocked: bool,
}
pub struct Engine {
    _lock: std::fs::File,
    db: Connection,
    audience: String,
    fences: BTreeMap<Scope, Fence>,
    pending: Vec<Event>,
    pub registry: Registry,
}
fn scope_key(scope: Scope) -> String {
    format!(
        "{}:{}:{}",
        scope.hosting_space_id, scope.conversation.space_id, scope.conversation.stream_id
    )
}
impl Engine {
    pub fn open(
        path: &Path,
        audience: String,
        limits: Limits,
    ) -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if path.exists() && std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err("Unsafe call database.".into());
        }
        let lock_path = path.with_extension("lock");
        if lock_path.exists()
            && std::fs::symlink_metadata(&lock_path)?
                .file_type()
                .is_symlink()
        {
            return Err("Unsafe call database lock.".into());
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock_exclusive()?;
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            PRAGMA max_page_count=65536;
            CREATE TABLE IF NOT EXISTS fences(scope TEXT PRIMARY KEY, head TEXT NOT NULL, sequence INTEGER NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, recovery TEXT);
            CREATE TABLE IF NOT EXISTS receipts(credential TEXT NOT NULL, nonce TEXT NOT NULL, request_id TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(credential, nonce));
            CREATE INDEX IF NOT EXISTS receipt_expiry ON receipts(expires);")?;
        // Load rollback floors on demand. Historic chats do not consume the
        // bounded live proof cache, and their persisted fences are never erased.
        let fences = BTreeMap::new();
        Ok(Self {
            _lock: lock,
            db,
            audience,
            fences,
            pending: vec![],
            registry: Registry::new(limits)?,
        })
    }

    /// This does not grant access. The caller must ask the configured hosting
    /// authority about `identity` and `hosting_space_id` before execute.
    pub fn prepare(
        &self,
        request: Request,
        device: Option<RecordId>,
        now: u64,
    ) -> Result<Prepared> {
        self.preparation(request, device)?.verify(now)
    }
    fn stored_fence(&self, scope: Scope) -> Result<Option<Fence>> {
        let row = self
            .db
            .query_row(
                "SELECT head, sequence, blocked, recovery FROM fences WHERE scope=?1",
                [scope_key(scope)],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, bool>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| CallError::Unavailable)?;
        row.map(|(head, sequence, blocked, recovery)| {
            if sequence <= 0 {
                return Err(CallError::Unavailable);
            }
            Ok(Fence {
                head: head.parse().map_err(|_| CallError::Unavailable)?,
                recovery: recovery
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|_| CallError::Unavailable)?,
                sequence: sequence as u64,
                blocked,
                authority: None,
                proof_bytes: 0,
                last_used: 0,
            })
        })
        .transpose()
    }
    pub fn preparation(&self, request: Request, device: Option<RecordId>) -> Result<Preparation> {
        if request.command.len() > 192 * 1024 {
            return Err(CallError::Invalid);
        }
        let bytes = STANDARD
            .decode(&request.command)
            .map_err(|_| CallError::Invalid)?;
        let signed = SignedRecord::parse(&bytes).map_err(|_| CallError::Invalid)?;
        let unverified: Command = signed.decode().map_err(|_| CallError::Invalid)?;
        if device.is_some_and(|device| device != unverified.credential_id) {
            return Err(CallError::Unauthorized);
        }
        let scope = Scope::from(&unverified);
        if self.fences.get(&scope).is_some_and(|fence| fence.blocked) {
            return Err(CallError::Unauthorized);
        }
        if self.stored_fence(scope)?.is_some_and(|f| f.blocked) {
            return Err(CallError::Unauthorized);
        }
        Ok(Preparation {
            request,
            signed,
            scope,
            audience: self.audience.clone(),
            cached: self.fences.get(&scope).and_then(|f| f.authority.clone()),
        })
    }

    pub fn execute(&mut self, prepared: Prepared, now: u64) -> Result<Applied> {
        let Prepared {
            command,
            identity: _,
            request_id,
            authority,
            proof,
        } = prepared;
        if command.expires_at <= now {
            return Err(CallError::Unauthorized);
        }
        let scope = Scope::from(&command);
        if !self.fences.contains_key(&scope) {
            if self.fences.len() >= MAX_SCOPES {
                let idle = self
                    .fences
                    .iter()
                    .filter(|(key, fence)| {
                        self.registry.presence(key).is_none()
                            && now.saturating_sub(fence.last_used) >= 120
                    })
                    .min_by_key(|(_, fence)| fence.last_used)
                    .map(|(key, _)| *key);
                if let Some(idle) = idle {
                    self.fences.remove(&idle);
                } else {
                    return Err(CallError::Unavailable);
                }
            }
            if let Some(fence) = self.stored_fence(scope)? {
                self.fences.insert(scope, fence);
            }
        }
        let proof_bytes = proof
            .as_ref()
            .map(|proof| {
                proof.genesis.len()
                    + proof.checkpoint.as_ref().map_or(0, String::len)
                    + proof
                        .credentials
                        .iter()
                        .chain(&proof.configs)
                        .map(String::len)
                        .sum::<usize>()
            })
            .or_else(|| self.fences.get(&scope).map(|fence| fence.proof_bytes))
            .unwrap_or_default();
        let other_bytes = self
            .fences
            .iter()
            .filter(|(key, _)| **key != scope)
            .map(|(_, fence)| fence.proof_bytes)
            .sum::<usize>();
        if proof_bytes.saturating_add(other_bytes) > MAX_CACHED_PROOFS {
            return Err(CallError::Unavailable);
        }
        let mut events = vec![];
        let changed = match self.fences.get(&scope) {
            Some(old) => {
                if old.blocked {
                    return Err(CallError::Unauthorized);
                }
                if !authority.proves_recovery_ancestor(old.recovery) {
                    return Err(CallError::Unauthorized);
                }
                let old_id = old.head;
                if old_id == command.config_id {
                    false
                } else if authority.proves_config_at(old_id, old.sequence) {
                    true
                } else if authority
                    .head()
                    .map_err(|_| CallError::Unauthorized)?
                    .sequence
                    < old.sequence
                {
                    return Err(CallError::Unauthorized);
                } else {
                    self.db
                        .execute(
                            "UPDATE fences SET blocked=1 WHERE scope=?1",
                            [scope_key(scope)],
                        )
                        .map_err(|_| CallError::Unavailable)?;
                    self.fences.get_mut(&scope).unwrap().blocked = true;
                    self.pending.extend(
                        self.registry
                            .configuration_changed(scope, command.config_id),
                    );
                    return Err(CallError::Unauthorized);
                }
            }
            None => {
                if self.fences.len() >= MAX_SCOPES {
                    return Err(CallError::Unavailable);
                }
                true
            }
        };
        // Current public membership proofs only live in memory. The disk fence
        // contains an opaque head hash and sequence, not past member rosters.
        if !changed {
            let fence = self.fences.get_mut(&scope).ok_or(CallError::Unauthorized)?;
            fence.authority = Some(authority.clone());
            fence.proof_bytes = proof_bytes;
            fence.last_used = now;
        }
        let duplicate = self
            .db
            .query_row(
                "SELECT request_id FROM receipts WHERE credential=?1 AND nonce=?2",
                params![command.credential_id.to_string(), command.nonce],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| CallError::Unavailable)?;
        if let Some(previous) = duplicate {
            if previous != request_id.to_string() {
                return Err(CallError::Unauthorized);
            }
            return Ok(Applied {
                request_id,
                scope,
                call: self.registry.presence(&scope).cloned(),
                events,
                duplicate: true,
            });
        }
        // Admission fences commit independently of an individual operation. An
        // expired call must not prevent a legitimate newer authority being saved.
        if changed {
            proof.as_ref().ok_or(CallError::Unauthorized)?;
            let sequence = authority
                .head()
                .map_err(|_| CallError::Unauthorized)?
                .sequence;
            self.db.execute("INSERT INTO fences(scope,head,sequence,recovery) VALUES(?1,?2,?3,?4) ON CONFLICT(scope) DO UPDATE SET head=excluded.head, sequence=excluded.sequence, recovery=excluded.recovery",
                params![scope_key(scope), command.config_id.to_string(), i64::try_from(sequence).map_err(|_| CallError::Invalid)?, authority.recovery_id().map(|id|id.to_string())]).map_err(|_| CallError::Unavailable)?;
            self.fences.insert(
                scope,
                Fence {
                    head: command.config_id,
                    recovery: authority.recovery_id(),
                    sequence,
                    authority: Some(authority.clone()),
                    proof_bytes,
                    last_used: now,
                    blocked: false,
                },
            );
            self.pending.extend(
                self.registry
                    .configuration_changed(scope, command.config_id),
            );
        }
        let mut next = self.registry.clone();
        let outcome = next.apply(&authority, &command, now)?;
        let transaction = self.db.transaction().map_err(|_| CallError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM receipts WHERE expires<=?1",
                [i64::try_from(now).map_err(|_| CallError::Invalid)?],
            )
            .map_err(|_| CallError::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO receipts(credential,nonce,request_id,expires) VALUES(?1,?2,?3,?4)",
                params![
                    command.credential_id.to_string(),
                    command.nonce,
                    request_id.to_string(),
                    i64::try_from(command.expires_at).map_err(|_| CallError::Invalid)?
                ],
            )
            .map_err(|_| CallError::Unavailable)?;
        transaction.commit().map_err(|_| CallError::Unavailable)?;
        events.extend(outcome);
        self.registry = next;
        Ok(Applied {
            request_id,
            scope,
            call: self.registry.presence(&scope).cloned(),
            events,
            duplicate: false,
        })
    }
    pub fn authorized(&self, scope: Scope, credential: RecordId) -> bool {
        self.fences.get(&scope).is_some_and(|fence| {
            !fence.blocked
                && fence
                    .authority
                    .as_ref()
                    .is_some_and(|authority| calls::require_member(authority, credential).is_ok())
        })
    }
    pub fn authorized_head(
        &mut self,
        scope: Scope,
        credential: RecordId,
        now: u64,
    ) -> Option<RecordId> {
        if !self.authorized(scope, credential) {
            return None;
        }
        let fence = self.fences.get_mut(&scope)?;
        // Admission checks are live uses of the proof. An idle listener must
        // keep receiving calls without sending periodic signed commands.
        fence.last_used = now;
        Some(fence.head)
    }
    pub fn wake_recipients(&self, call: &ActiveCall) -> Vec<calls::wake::Recipient> {
        let Some(fence) = self.fences.get(&call.scope) else {
            return vec![];
        };
        if fence.blocked || fence.head != call.config_id {
            return vec![];
        }
        let Some(authority) = &fence.authority else {
            return vec![];
        };
        let Ok(head) = authority.head() else {
            return vec![];
        };
        let recipients: Vec<_> = head
            .members
            .iter()
            .filter(|m| m.identity_id != call.started_by)
            .flat_map(|m| {
                m.credential_ids.iter().filter_map(|id| {
                    calls::require_member(authority, *id).ok().map(|identity| {
                        calls::wake::Recipient {
                            identity,
                            credential: *id,
                        }
                    })
                })
            })
            .collect();
        if recipients.len() > 16 {
            vec![]
        } else {
            recipients
        }
    }
    pub fn background_decline(&mut self, id: &str, recipient: IdentityId) -> Vec<Event> {
        let scope = self.fences.keys().find_map(|scope| {
            let call = self.registry.presence(scope)?;
            (call.call_id == id
                && call.kind == calls::CallKind::Direct
                && call.ringing
                && self
                    .wake_recipients(call)
                    .iter()
                    .any(|r| r.identity == recipient))
            .then_some(*scope)
        });
        scope
            .and_then(|scope| self.registry.end(scope))
            .into_iter()
            .collect()
    }
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.pending)
    }
    pub fn maintain(&mut self, now: u64) -> Result<Vec<Event>> {
        self.db
            .execute(
                "DELETE FROM receipts WHERE expires<=?1",
                [i64::try_from(now).map_err(|_| CallError::Invalid)?],
            )
            .map_err(|_| CallError::Unavailable)?;
        let events = self.registry.tick(now);
        for (scope, fence) in &mut self.fences {
            if now.saturating_sub(fence.last_used) >= 120 && self.registry.presence(scope).is_none()
            {
                fence.authority = None;
                fence.proof_bytes = 0;
            }
        }
        Ok(events)
    }
}

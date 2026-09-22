use elo_core::{
    authority::{Authority, ChatKind},
    calls::{CallKind, CallScope, Command, InitialMedia, MediaState, Operation, require_member},
    ids::{IdentityId, RecordId, SpaceId},
    record,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Scope {
    pub hosting_space_id: SpaceId,
    pub conversation: CallScope,
}
impl From<&Command> for Scope {
    fn from(command: &Command) -> Self {
        Self {
            hosting_space_id: command.hosting_space_id,
            conversation: command.scope,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub participants: usize,
    pub cameras: usize,
    pub screens: usize,
    pub participant_ttl: u64,
    pub empty_grace: u64,
    pub ring_timeout: u64,
    pub max_duration: u64,
    pub rooms: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            participants: 25,
            cameras: 12,
            screens: 1,
            participant_ttl: 30,
            empty_grace: 15,
            ring_timeout: 45,
            max_duration: 12 * 3600,
            rooms: 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Participant {
    pub identity_id: IdentityId,
    pub credential_id: RecordId,
    pub media: MediaState,
    #[serde(skip)]
    last_seen: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActiveCall {
    pub call_id: String,
    pub scope: Scope,
    pub kind: CallKind,
    pub initial_media: InitialMedia,
    pub started_at: u64,
    pub started_by: IdentityId,
    pub config_id: RecordId,
    pub participants: BTreeMap<IdentityId, Participant>,
    pub ringing: bool,
    pub key_epoch: u64,
    #[serde(skip)]
    empty_since: Option<u64>,
}

#[derive(Clone, Copy, Debug, Error, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallError {
    #[error("Call authorization is no longer current.")]
    Unauthorized,
    #[error("This call has ended.")]
    Ended,
    #[error("This person is already in a call.")]
    AlreadyJoined,
    #[error("This call has reached its participant limit.")]
    Full,
    #[error("The media limit has been reached.")]
    MediaLimit,
    #[error("Call capacity is temporarily unavailable.")]
    Unavailable,
    #[error("This call operation is not valid.")]
    Invalid,
}
pub type Result<T> = std::result::Result<T, CallError>;

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Presence {
        call: ActiveCall,
    },
    Ended {
        scope: Scope,
        call_id: String,
    },
    Signal {
        scope: Scope,
        call_id: String,
        from: RecordId,
        to: RecordId,
        ciphertext: String,
    },
}

/// Access and signature validation precede this state machine. The service holds
/// one lock across authorization update, command admission and these transitions.
#[derive(Clone)]
pub struct Registry {
    pub limits: Limits,
    rooms: BTreeMap<Scope, ActiveCall>,
}
impl Registry {
    pub fn new(limits: Limits) -> Result<Self> {
        if !(2..=1000).contains(&limits.participants)
            || limits.cameras > limits.participants
            || limits.screens > limits.participants
            || limits.participant_ttl < 10
            || limits.empty_grace == 0
            || limits.ring_timeout == 0
            || limits.max_duration == 0
            || limits.rooms == 0
        {
            return Err(CallError::Invalid);
        }
        Ok(Self {
            limits,
            rooms: BTreeMap::new(),
        })
    }
    pub fn presence(&self, scope: &Scope) -> Option<&ActiveCall> {
        self.rooms.get(scope)
    }

    pub fn apply(
        &mut self,
        authority: &Authority,
        command: &Command,
        now: u64,
    ) -> Result<Vec<Event>> {
        let identity = require_member(authority, command.credential_id)
            .map_err(|_| CallError::Unauthorized)?;
        let scope = Scope::from(command);
        if authority.space() != scope.conversation.space_id
            || authority.stream() != scope.conversation.stream_id
            || authority.head_id() != Some(command.config_id)
        {
            return Err(CallError::Unauthorized);
        }
        match &command.operation {
            Operation::Subscribe => {
                return Ok(self
                    .rooms
                    .get(&scope)
                    .map(|call| Event::Presence { call: call.clone() })
                    .into_iter()
                    .collect());
            }
            Operation::Start {
                kind,
                initial_media,
            } => {
                let head = authority.head().map_err(|_| CallError::Unauthorized)?;
                let expected =
                    if head.chat_kind == Some(ChatKind::Direct) && head.members.len() == 2 {
                        CallKind::Direct
                    } else {
                        CallKind::Group
                    };
                if *kind != expected {
                    return Err(CallError::Invalid);
                }
                if let Some(call) = self.rooms.get(&scope) {
                    let mut join = command.clone();
                    join.operation = Operation::Join {
                        call_id: call.call_id.clone(),
                    };
                    return self.apply(authority, &join, now);
                }
                if self.rooms.len() >= self.limits.rooms {
                    return Err(CallError::Unavailable);
                }
                self.ensure_free(command.credential_id, &scope)?;
                let participant = Participant {
                    identity_id: identity,
                    credential_id: command.credential_id,
                    media: MediaState {
                        audio_muted: true,
                        ..MediaState::default()
                    },
                    last_seen: now,
                };
                self.rooms.insert(
                    scope,
                    ActiveCall {
                        call_id: record::random_hex::<16>().map_err(|_| CallError::Unavailable)?,
                        scope,
                        kind: *kind,
                        initial_media: *initial_media,
                        started_at: now,
                        started_by: identity,
                        config_id: command.config_id,
                        participants: BTreeMap::from([(identity, participant)]),
                        ringing: *kind == CallKind::Direct,
                        key_epoch: 1,
                        empty_since: None,
                    },
                );
            }
            _ => {
                if matches!(command.operation, Operation::Join { .. }) {
                    self.ensure_free(command.credential_id, &scope)?;
                }
                let call = self.rooms.get_mut(&scope).ok_or(CallError::Ended)?;
                if command.operation.call_id() != Some(call.call_id.as_str()) {
                    return Err(CallError::Ended);
                }
                if call.config_id != command.config_id {
                    return Err(CallError::Unauthorized);
                }
                match &command.operation {
                    Operation::Join { .. } => {
                        if let Some(joined) = call.participants.get_mut(&identity) {
                            if joined.credential_id != command.credential_id {
                                return Err(CallError::AlreadyJoined);
                            }
                            joined.last_seen = now;
                        } else {
                            if call.participants.len() >= self.limits.participants {
                                return Err(CallError::Full);
                            }
                            if call.kind == CallKind::Direct
                                && (!call.ringing || identity == call.started_by)
                            {
                                return Err(CallError::Ended);
                            }
                            call.participants.insert(
                                identity,
                                Participant {
                                    identity_id: identity,
                                    credential_id: command.credential_id,
                                    media: MediaState {
                                        audio_muted: true,
                                        ..MediaState::default()
                                    },
                                    last_seen: now,
                                },
                            );
                            call.key_epoch += 1;
                            if call.kind == CallKind::Direct {
                                call.ringing = false;
                            }
                        }
                        call.empty_since = None;
                    }
                    Operation::Decline { .. } => {
                        if call.kind != CallKind::Direct
                            || !call.ringing
                            || identity == call.started_by
                        {
                            return Err(CallError::Invalid);
                        }
                        return Ok(vec![self.end(scope).ok_or(CallError::Ended)?]);
                    }
                    Operation::Leave { .. } => {
                        Self::participant(call, identity, command.credential_id)?;
                        call.participants.remove(&identity);
                        call.key_epoch += 1;
                        if call.kind == CallKind::Direct {
                            return Ok(vec![self.end(scope).ok_or(CallError::Ended)?]);
                        }
                        if call.participants.is_empty() {
                            return Ok(vec![self.end(scope).ok_or(CallError::Ended)?]);
                        }
                    }
                    Operation::Heartbeat { .. } | Operation::ConnectMedia { .. } => {
                        Self::participant(call, identity, command.credential_id)?.last_seen = now;
                        return Ok(vec![]);
                    }
                    Operation::Media { state, .. } => {
                        Self::participant(call, identity, command.credential_id)?;
                        if state.video_published
                            && call
                                .participants
                                .values()
                                .filter(|p| p.identity_id != identity && p.media.video_published)
                                .count()
                                >= self.limits.cameras
                            || state.screen_published
                                && call
                                    .participants
                                    .values()
                                    .filter(|p| {
                                        p.identity_id != identity && p.media.screen_published
                                    })
                                    .count()
                                    >= self.limits.screens
                        {
                            return Err(CallError::MediaLimit);
                        }
                        let participant = call
                            .participants
                            .get_mut(&identity)
                            .ok_or(CallError::Unauthorized)?;
                        participant.media = *state;
                        participant.last_seen = now;
                    }
                    Operation::Signal { to, ciphertext, .. } => {
                        Self::participant(call, identity, command.credential_id)?;
                        if *to == command.credential_id
                            || !call.participants.values().any(|p| p.credential_id == *to)
                        {
                            return Err(CallError::Unauthorized);
                        }
                        return Ok(vec![Event::Signal {
                            scope,
                            call_id: call.call_id.clone(),
                            from: command.credential_id,
                            to: *to,
                            ciphertext: ciphertext.clone(),
                        }]);
                    }
                    _ => return Err(CallError::Invalid),
                }
            }
        }
        Ok(vec![Event::Presence {
            call: self.rooms.get(&scope).ok_or(CallError::Ended)?.clone(),
        }])
    }

    fn ensure_free(&self, credential: RecordId, scope: &Scope) -> Result<()> {
        if self.rooms.iter().any(|(other, room)| {
            other != scope
                && room
                    .participants
                    .values()
                    .any(|participant| participant.credential_id == credential)
        }) {
            Err(CallError::AlreadyJoined)
        } else {
            Ok(())
        }
    }
    fn participant(
        call: &mut ActiveCall,
        identity: IdentityId,
        credential: RecordId,
    ) -> Result<&mut Participant> {
        call.participants
            .get_mut(&identity)
            .filter(|p| p.credential_id == credential)
            .ok_or(CallError::Unauthorized)
    }
    pub(crate) fn end(&mut self, scope: Scope) -> Option<Event> {
        self.rooms.remove(&scope).map(|room| Event::Ended {
            scope,
            call_id: room.call_id,
        })
    }

    /// Membership changes end the room until a fresh media-key negotiation is
    /// available. Fail closed instead of claiming that a token expiry revokes media.
    pub fn configuration_changed(&mut self, scope: Scope, head: RecordId) -> Vec<Event> {
        if self
            .rooms
            .get(&scope)
            .is_some_and(|room| room.config_id != head)
        {
            self.end(scope).into_iter().collect()
        } else {
            vec![]
        }
    }
    pub fn revoke_space(&mut self, space: SpaceId) -> Vec<Event> {
        let scopes = self
            .rooms
            .keys()
            .filter(|scope| scope.hosting_space_id == space)
            .copied()
            .collect::<Vec<_>>();
        scopes
            .into_iter()
            .filter_map(|scope| self.end(scope))
            .collect()
    }
    pub fn revoke_member(&mut self, scope: Scope, identity: IdentityId) -> Vec<Event> {
        if self
            .rooms
            .get(&scope)
            .is_some_and(|room| room.participants.contains_key(&identity))
        {
            self.end(scope).into_iter().collect()
        } else {
            vec![]
        }
    }
    pub fn tick(&mut self, now: u64) -> Vec<Event> {
        let mut events = vec![];
        let mut ended = vec![];
        for (scope, room) in &mut self.rooms {
            let count = room.participants.len();
            room.participants.retain(|_, participant| {
                now.saturating_sub(participant.last_seen) < self.limits.participant_ttl
            });
            if room.participants.len() != count {
                room.key_epoch += 1;
            }
            if room.participants.is_empty() {
                room.empty_since.get_or_insert(now);
            }
            if now.saturating_sub(room.started_at) >= self.limits.max_duration
                || room.ringing && now.saturating_sub(room.started_at) >= self.limits.ring_timeout
                || room.kind == CallKind::Direct && room.participants.len() < count
                || room
                    .empty_since
                    .is_some_and(|since| now.saturating_sub(since) >= self.limits.empty_grace)
            {
                ended.push(*scope);
            } else if room.participants.len() != count {
                events.push(Event::Presence { call: room.clone() });
            }
        }
        events.extend(ended.into_iter().filter_map(|scope| self.end(scope)));
        events
    }
}

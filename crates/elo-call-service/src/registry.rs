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
    pub ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<String>,
    #[serde(skip)]
    last_seen: u64,
    #[serde(skip)]
    delegation_expires_at: Option<u64>,
    #[serde(skip)]
    accepted_invitation_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Ringing,
    Active,
}

#[derive(Clone, Debug, Serialize)]
pub struct Invitation {
    pub invitation_id: String,
    pub invited_by: IdentityId,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    Cancelled,
    Declined,
    Ended,
    Unanswered,
    Expired,
    Unauthorized,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActiveCall {
    pub call_id: String,
    pub scope: Scope,
    pub kind: CallKind,
    pub initial_media: InitialMedia,
    pub started_at: u64,
    pub started_by: IdentityId,
    pub phase: Phase,
    pub ring_expires_at: u64,
    pub answered_at: Option<u64>,
    pub invitations: BTreeMap<IdentityId, Invitation>,
    pub ready: bool,
    pub ready_at: Option<u64>,
    pub config_id: RecordId,
    pub participants: BTreeMap<IdentityId, Participant>,
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
        reason: EndReason,
    },
    Signal {
        scope: Scope,
        call_id: String,
        epoch: u64,
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

    /// The engine has verified this certificate and current device membership.
    pub fn apply_with_delegation(
        &mut self,
        authority: &Authority,
        command: &Command,
        now: u64,
        delegation: Option<&str>,
    ) -> Result<Vec<Event>> {
        let scope = Scope::from(command);
        if let Some(participant) = self.rooms.get(&scope).and_then(|call| {
            call.participants
                .values()
                .find(|participant| participant.credential_id == command.credential_id)
        })
            && participant.delegation.as_deref() != delegation
                && !matches!(
                    command.operation,
                    Operation::Subscribe | Operation::Decline { .. }
                )
                // The original device may control its own capture and invitations
                // after foreground adoption, without replacing the admitted
                // delegate or gaining a second signaling/media transport.
                && !(delegation.is_none()
                    && matches!(
                        command.operation,
                        Operation::End { .. }
                            | Operation::Cancel { .. }
                            | Operation::Leave { .. }
                            | Operation::Media { .. }
                            | Operation::Invite { .. }
                    ))
        {
            return Err(CallError::AlreadyJoined);
        }
        let delegation_expires_at = delegation
            .map(|encoded| {
                let signed = elo_core::calls::delegation::decode_certificate(encoded)
                    .map_err(|_| CallError::Unauthorized)?;
                let verified = elo_core::calls::delegation::verify(
                    authority,
                    &signed,
                    command.hosting_space_id,
                    &command.audience,
                    now,
                )
                .map_err(|_| CallError::Unauthorized)?;
                Ok::<_, CallError>(verified.body.expires_at)
            })
            .transpose()?;
        let mut events = self.apply(authority, command, now)?;
        if matches!(
            command.operation,
            Operation::Start { .. } | Operation::Join { .. }
        ) {
            if let Some(participant) = self.rooms.get_mut(&scope).and_then(|call| {
                call.participants
                    .values_mut()
                    .find(|participant| participant.credential_id == command.credential_id)
            }) {
                participant.delegation = delegation.map(str::to_owned);
                participant.delegation_expires_at = delegation_expires_at;
            }
            for event in &mut events {
                if let Event::Presence { call } = event
                    && let Some(current) = self.rooms.get(&scope)
                {
                    *call = current.clone();
                }
            }
        }
        Ok(events)
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
        if self.rooms.get(&scope).is_some_and(|call| {
            call.kind == CallKind::Direct
                && call.phase == Phase::Ringing
                && now >= call.ring_expires_at
        }) {
            return Ok(vec![
                self.end_with_reason(scope, EndReason::Unanswered)
                    .ok_or(CallError::Ended)?,
            ]);
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
                let expected = if head.chat_kind == Some(ChatKind::Direct) {
                    CallKind::Direct
                } else {
                    CallKind::Group
                };
                if *kind != expected || (expected == CallKind::Direct && head.members.len() != 2) {
                    return Err(CallError::Invalid);
                }
                if let Some(call) = self.rooms.get(&scope) {
                    let mut join = command.clone();
                    join.operation = Operation::Join {
                        call_id: call.call_id.clone(),
                        invitation_id: None,
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
                    ready: false,
                    media: MediaState {
                        audio_muted: true,
                        ..MediaState::default()
                    },
                    last_seen: now,
                    delegation_expires_at: None,
                    accepted_invitation_id: None,
                    delegation: None,
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
                        phase: if *kind == CallKind::Direct {
                            Phase::Ringing
                        } else {
                            Phase::Active
                        },
                        ring_expires_at: now.saturating_add(elo_core::calls::RING_TTL),
                        answered_at: None,
                        invitations: if *kind == CallKind::Direct {
                            let recipient = head
                                .members
                                .iter()
                                .find(|member| member.identity_id != identity)
                                .ok_or(CallError::Invalid)?
                                .identity_id;
                            BTreeMap::from([(
                                recipient,
                                Invitation {
                                    invitation_id: record::random_hex::<16>()
                                        .map_err(|_| CallError::Unavailable)?,
                                    invited_by: identity,
                                    expires_at: now.saturating_add(elo_core::calls::RING_TTL),
                                },
                            )])
                        } else {
                            BTreeMap::new()
                        },
                        ready: false,
                        ready_at: None,
                        config_id: command.config_id,
                        participants: BTreeMap::from([(identity, participant)]),
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
                    Operation::Join { invitation_id, .. } => {
                        if let Some(expected) = invitation_id {
                            let pending = call.invitations.get(&identity).is_some_and(|invite| {
                                invite.invitation_id == *expected && invite.expires_at > now
                            });
                            let joined =
                                call.participants.get(&identity).is_some_and(|participant| {
                                    participant.credential_id == command.credential_id
                                        && participant.accepted_invitation_id.as_ref()
                                            == Some(expected)
                                });
                            if !pending && !joined {
                                return Err(CallError::Ended);
                            }
                        }
                        if let Some(joined) = call.participants.get_mut(&identity) {
                            if joined.credential_id != command.credential_id {
                                return Err(CallError::AlreadyJoined);
                            }
                            joined.last_seen = now;
                        } else {
                            if call.participants.len() >= self.limits.participants {
                                return Err(CallError::Full);
                            }
                            call.participants.insert(
                                identity,
                                Participant {
                                    identity_id: identity,
                                    credential_id: command.credential_id,
                                    ready: false,
                                    media: MediaState {
                                        audio_muted: true,
                                        ..MediaState::default()
                                    },
                                    last_seen: now,
                                    delegation_expires_at: None,
                                    accepted_invitation_id: None,
                                    delegation: None,
                                },
                            );
                            call.key_epoch += 1;
                        }
                        if let Some(joined) = call.participants.get_mut(&identity)
                            && invitation_id.is_some()
                        {
                            joined.accepted_invitation_id.clone_from(invitation_id);
                        }
                        call.invitations.remove(&identity);
                        if call.kind == CallKind::Direct && identity != call.started_by {
                            call.phase = Phase::Active;
                            call.answered_at.get_or_insert(now);
                            call.invitations.clear();
                        }
                        call.empty_since = None;
                    }
                    Operation::Decline { invitation_id, .. } => {
                        if call
                            .invitations
                            .get(&identity)
                            .is_some_and(|invite| invite.invitation_id != *invitation_id)
                        {
                            return Err(CallError::Ended);
                        }
                        if call.kind == CallKind::Direct {
                            if call.phase != Phase::Ringing
                                || identity == call.started_by
                                || call.participants.contains_key(&identity)
                            {
                                return Err(CallError::Invalid);
                            }
                            return Ok(vec![
                                self.end_with_reason(scope, EndReason::Declined)
                                    .ok_or(CallError::Ended)?,
                            ]);
                        }
                        // Declining a group invitation never removes participants.
                        call.invitations.remove(&identity);
                    }
                    Operation::Cancel { .. } => {
                        if call.kind != CallKind::Direct
                            || call.phase != Phase::Ringing
                            || identity != call.started_by
                        {
                            return Err(CallError::Invalid);
                        }
                        Self::participant(call, identity, command.credential_id)?;
                        return Ok(vec![
                            self.end_with_reason(scope, EndReason::Cancelled)
                                .ok_or(CallError::Ended)?,
                        ]);
                    }
                    Operation::End { .. } => {
                        if call.kind != CallKind::Direct {
                            return Err(CallError::Invalid);
                        }
                        Self::participant(call, identity, command.credential_id)?;
                        return Ok(vec![
                            self.end_with_reason(scope, EndReason::Ended)
                                .ok_or(CallError::Ended)?,
                        ]);
                    }
                    Operation::Invite { to, .. } => {
                        if call.kind != CallKind::Group
                            || *to == identity
                            || call.participants.contains_key(to)
                        {
                            return Err(CallError::Invalid);
                        }
                        Self::participant(call, identity, command.credential_id)?;
                        let member = authority
                            .head()
                            .map_err(|_| CallError::Unauthorized)?
                            .members
                            .iter()
                            .find(|member| member.identity_id == *to)
                            .ok_or(CallError::Unauthorized)?;
                        if !member
                            .credential_ids
                            .iter()
                            .any(|credential| require_member(authority, *credential).is_ok())
                        {
                            return Err(CallError::Unauthorized);
                        }
                        // Retries cannot extend an existing ringing window or ring
                        // the same recipient's other devices a second time.
                        if !call
                            .invitations
                            .get(to)
                            .is_some_and(|invite| invite.expires_at > now)
                        {
                            call.invitations.insert(
                                *to,
                                Invitation {
                                    invitation_id: record::random_hex::<16>()
                                        .map_err(|_| CallError::Unavailable)?,
                                    invited_by: identity,
                                    expires_at: now.saturating_add(elo_core::calls::RING_TTL),
                                },
                            );
                        }
                    }
                    Operation::Leave { .. } => {
                        Self::participant(call, identity, command.credential_id)?;
                        if call.kind == CallKind::Direct {
                            return Ok(vec![
                                self.end_with_reason(scope, EndReason::Ended)
                                    .ok_or(CallError::Ended)?,
                            ]);
                        }
                        call.participants.remove(&identity);
                        call.key_epoch += 1;
                        if call.participants.is_empty() {
                            return Ok(vec![
                                self.end_with_reason(scope, EndReason::Ended)
                                    .ok_or(CallError::Ended)?,
                            ]);
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
                        participant.ready = true;
                        participant.last_seen = now;
                        if identity == call.started_by && !call.ready {
                            call.ready = true;
                            call.ready_at = Some(now);
                        }
                    }
                    Operation::Signal {
                        epoch,
                        to,
                        ciphertext,
                        ..
                    } => {
                        Self::participant(call, identity, command.credential_id)?;
                        if *epoch != call.key_epoch
                            || *to == command.credential_id
                            || !call.participants.values().any(|p| p.credential_id == *to)
                        {
                            return Err(CallError::Unauthorized);
                        }
                        return Ok(vec![Event::Signal {
                            scope,
                            call_id: call.call_id.clone(),
                            epoch: call.key_epoch,
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
        self.end_with_reason(scope, EndReason::Unauthorized)
    }
    fn end_with_reason(&mut self, scope: Scope, reason: EndReason) -> Option<Event> {
        self.rooms.remove(&scope).map(|room| Event::Ended {
            scope,
            call_id: room.call_id,
            reason,
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
                    && participant
                        .delegation_expires_at
                        .is_none_or(|expires| now < expires)
            });
            let invitations = room.invitations.len();
            room.invitations
                .retain(|_, invitation| invitation.expires_at > now);
            if room.participants.len() != count {
                room.key_epoch += 1;
            }
            if room.kind == CallKind::Direct
                && room.phase == Phase::Ringing
                && now >= room.ring_expires_at
            {
                ended.push((*scope, EndReason::Unanswered));
                continue;
            }
            if room.kind == CallKind::Direct && room.participants.len() != count {
                ended.push((*scope, EndReason::Expired));
                continue;
            }
            if room.participants.is_empty() {
                room.empty_since.get_or_insert(now);
            }
            if now.saturating_sub(room.started_at) >= self.limits.max_duration
                || room
                    .empty_since
                    .is_some_and(|since| now.saturating_sub(since) >= self.limits.empty_grace)
            {
                ended.push((*scope, EndReason::Expired));
            } else if room.participants.len() != count || invitations != room.invitations.len() {
                events.push(Event::Presence { call: room.clone() });
            }
        }
        events.extend(
            ended
                .into_iter()
                .filter_map(|(scope, reason)| self.end_with_reason(scope, reason)),
        );
        events
    }
}

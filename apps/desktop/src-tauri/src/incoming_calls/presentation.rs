//! UI ownership is independent of network admission and cannot grant media access.
use super::*;

#[derive(Clone)]
pub(super) struct Ticket {
    generation: u64,
    key: (String, String),
    expires: u64,
}

#[derive(Default)]
pub(super) struct Fence {
    generation: u64,
    suspended: bool,
    revision: u64,
    terminal: BTreeMap<(String, String), u64>,
    answered: BTreeMap<(String, String), u64>,
    dismissed: BTreeMap<(String, String), Value>,
}

impl Fence {
    /// Called in native callback order, before handlers can wait on the network.
    pub(super) fn observe(&mut self, event: &Value, now: u64) -> Option<Ticket> {
        let field = |name: &str| {
            event[name]
                .as_str()
                .filter(|value| {
                    value.len() == 32
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .map(str::to_owned)
        };
        let key = (field("callId")?, field("invitationId")?);
        for entries in [&mut self.terminal, &mut self.answered] {
            entries.retain(|_, until| *until > now);
        }
        match event["action"].as_str() {
            Some("decline" | "end" | "ended") => {
                self.terminal.insert(key.clone(), now.saturating_add(120));
                self.answered.remove(&key);
                // Automatic native failure/end releases presentation ownership so
                // the foreground UI can still offer the live invitation.
                let user_dismissed = matches!(
                    (event["action"].as_str(), event["reason"].as_str()),
                    (Some("decline"), None | Some("declined"))
                        | (Some("end"), None | Some("local"))
                );
                if user_dismissed
                    && event["expires"]
                        .as_u64()
                        .is_some_and(|expires| expires > now && expires <= now.saturating_add(75))
                    && field("registration").is_some()
                    && event["target"]
                        .as_str()
                        .is_some_and(|target| (64..=4096).contains(&target.len()))
                {
                    let hint = json!({"callId":event["callId"],"invitationId":event["invitationId"],
                        "registration":event["registration"],"target":event["target"],"expires":event["expires"]});
                    if self.dismissed.get(&key) != Some(&hint) {
                        self.dismissed.insert(key.clone(), hint);
                        self.revision += 1;
                    }
                }
            }
            Some("answer") => {
                self.answered.insert(key.clone(), now.saturating_add(120));
            }
            _ => {}
        }
        self.dismissed.retain(|_, hint| {
            hint["expires"]
                .as_u64()
                .is_some_and(|expires| expires > now)
        });
        while self.dismissed.len() > 32 {
            let oldest = self
                .dismissed
                .iter()
                .min_by_key(|(_, hint)| hint["expires"].as_u64())
                .map(|(key, _)| key.clone())?;
            self.dismissed.remove(&oldest);
        }
        for entries in [&mut self.terminal, &mut self.answered] {
            while entries.len() > 128 {
                let oldest = entries
                    .iter()
                    .min_by_key(|(_, until)| **until)
                    .map(|(key, _)| key.clone())?;
                entries.remove(&oldest);
            }
        }
        Some(Ticket {
            generation: self.generation,
            key,
            expires: event["expires"].as_u64()?,
        })
    }

    pub(super) fn permits(&self, ticket: &Ticket, now: u64) -> bool {
        self.current(ticket, now)
            && !self
                .terminal
                .get(&ticket.key)
                .is_some_and(|until| *until > now)
    }

    pub(super) fn current(&self, ticket: &Ticket, now: u64) -> bool {
        !self.suspended
            && ticket.generation == self.generation
            && ticket.expires > now
            && ticket.expires <= now.saturating_add(75)
    }

    pub(super) fn ringing(&self, ticket: &Ticket, now: u64) -> bool {
        self.permits(ticket, now)
            && !self
                .answered
                .get(&ticket.key)
                .is_some_and(|until| *until > now)
    }

    pub(super) fn epoch(&self) -> u64 {
        self.generation
    }

    pub(super) fn snapshot(&self) -> Option<(u64, u64)> {
        (!self.suspended).then_some((self.generation, self.revision))
    }

    pub(super) fn dismissed(&self, now: u64) -> Vec<Value> {
        self.dismissed
            .values()
            .filter(|hint| {
                hint["expires"]
                    .as_u64()
                    .is_some_and(|expires| expires > now)
            })
            .cloned()
            .collect()
    }

    pub(super) fn suspend(&mut self) {
        self.generation += 1;
        self.suspended = true;
    }

    pub(super) fn resume(&mut self, generation: u64) {
        if self.suspended && self.generation == generation {
            self.generation += 1;
            self.suspended = false;
        }
    }
}

/// Only the live native snapshot is considered, never its pending event queue.
/// Local route decryption, identity, scope and delegated authority checks are
/// sufficient for hiding a duplicate UI; Subscribe still gates every Offer.
pub(super) fn verified_hints(
    bytes: &[u8],
    snapshot: &Value,
    identity: &str,
    now: u64,
) -> Vec<Value> {
    snapshot["presentationHints"]
        .as_array()
        .into_iter()
        .flatten()
        .take(36)
        .filter_map(|hint| {
            let enrollment = serde_json::from_slice(bytes).ok()?;
            let (prepared, target) = super::transport::lookup(enrollment, hint, now).ok()?;
            (prepared.binding.identity.to_string() == identity).then(|| {
                json!({
                    "call_id": target.call_id, "invitation_id": target.invitation_id,
                })
            })
        })
        .collect()
}

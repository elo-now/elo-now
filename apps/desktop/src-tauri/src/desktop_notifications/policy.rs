//! Pure privacy, destination and rate-limit policy shared by native adapters.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
pub(super) const TTL: Duration = Duration::from_secs(3600);
const LIMIT: usize = 128;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub(super) identity: String,
    pub(super) space: String,
    pub(super) stream: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) space_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) call_id: Option<String>,
    pub(super) category: Category,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Category {
    Message,
    Session,
}
#[derive(Clone, Copy, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Sound {
    #[default]
    Default,
    Soft,
    EloMale,
    EloFemale,
    None,
}
impl Sound {
    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    pub(super) fn file(self) -> Option<&'static str> {
        match self {
            Self::Default => Some("default.wav"),
            Self::Soft => Some("soft.wav"),
            Self::EloMale => Some("elo-male.wav"),
            Self::EloFemale => Some("elo-female.wav"),
            Self::None => None,
        }
    }
}
pub(super) struct Entry {
    pub(super) target: Target,
    pub(super) expires: Instant,
}
#[derive(Default)]
pub(super) struct Registry {
    pub(super) enabled: bool,
    pub(super) entries: BTreeMap<String, Entry>,
    pub(super) opened: Option<String>,
    pub(super) last_alert: [Option<Instant>; 2],
}
impl Registry {
    pub(super) fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, e| e.expires > now);
        if self
            .opened
            .as_ref()
            .is_some_and(|id| !self.entries.contains_key(id))
        {
            self.opened = None;
        }
    }
    pub(super) fn insert(&mut self, target: Target, now: Instant) -> Option<String> {
        self.prune(now);
        let lane = usize::from(target.category == Category::Session);
        if !self.enabled
            || self.entries.values().any(|e| e.target == target)
            || self.last_alert[lane]
                .is_some_and(|time| now.duration_since(time) < Duration::from_secs(3))
        {
            return None;
        }
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).ok()?;
        let id = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if self.entries.len() >= LIMIT {
            let oldest = self
                .entries
                .iter()
                .filter(|(id, _)| self.opened.as_ref() != Some(id))
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            id.clone(),
            Entry {
                target,
                expires: now + TTL,
            },
        );
        self.last_alert[lane] = Some(now);
        Some(id)
    }
}
fn chat_matches(chat: &Value, target: &Target, active: Option<&str>) -> bool {
    chat["space"] == target.space
        && chat["stream"] == target.stream
        && chat["space_context"].as_str().or(active) == target.space_context.as_deref().or(active)
}
/// Apply a verified page only to its exact profile and Space compartment.
pub(super) fn apply_history_page(view: &mut Value, target: &Target, page: &Value) -> bool {
    let active = view["active_space"].as_str().map(str::to_owned);
    let context = target.space_context.as_deref().or(active.as_deref());
    let history = &page["history"];
    if history["identity"] != target.identity
        || history["space"] != target.space
        || history["stream"] != target.stream
        || history["space_context"].as_str() != context
        || !history["rows"].is_array()
    {
        return false;
    }
    let key = if view.get("all_streams").is_some() {
        "all_streams"
    } else {
        "streams"
    };
    if let Some(chats) = view[key].as_array_mut() {
        for chat in chats {
            if chat_matches(chat, target, active.as_deref()) {
                chat["rows"] = history["rows"].clone();
                return true;
            }
        }
    }
    false
}
pub(super) fn valid_target(view: &Value, target: &Target, arriving: bool) -> bool {
    if view["identity"].as_str() != Some(&target.identity) {
        return false;
    }
    let Some(chat) = view
        .get("all_streams")
        .unwrap_or(&view["streams"])
        .as_array()
        .and_then(|chats| {
            chats
                .iter()
                .find(|chat| chat_matches(chat, target, view["active_space"].as_str()))
        })
    else {
        return false;
    };
    if chat["forked"] == true
        || (arriving && chat["muted"] == true)
        || !chat["members"].as_array().is_some_and(|members| {
            members.iter().any(|m| {
                m["identity_id"] == target.identity
                    && view["credential"].as_str().is_some_and(|credential| {
                        m["credential_ids"]
                            .as_array()
                            .is_some_and(|ids| ids.iter().any(|id| id == credential))
                    })
                    && m["capabilities"]
                        .as_array()
                        .is_some_and(|caps| caps.iter().any(|c| c == "READ"))
            })
        })
    {
        return false;
    }
    if target.category == Category::Session {
        return target.record.is_none()
            && target
                .call_id
                .as_ref()
                .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    if target.call_id.is_some() {
        return false;
    }
    let Some(record) = &target.record else {
        return false;
    };
    chat["rows"].as_array().is_some_and(|rows| {
        rows.iter().any(|row| {
            row["id"] == *record
                && row["body"]["kind"] == "chat.message"
                && (!arriving
                    || (row["unread"] == true && row["body"]["issuer_identity"] != target.identity))
        })
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

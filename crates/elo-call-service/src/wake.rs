//! A bounded, short-lived outbox. Provider delivery never delays media control.
use crate::{registry::Scope, server::Admission};
use elo_core::calls::wake::Notice;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub url: String,
    pub key_file: PathBuf,
}
#[derive(Clone)]
struct Pending {
    notice: Notice,
    scope: Scope,
    deadline: u64,
    terminal: bool,
    sent: bool,
    last_attempt: u64,
}
pub struct Delivery {
    client: reqwest::Client,
    url: String,
    key: Zeroizing<String>,
    pending: Mutex<BTreeMap<String, Pending>>,
}
// At most one notice per Space per round, with unsent work before retries.
// A permanently unavailable recipient cannot hold all delivery slots.
fn delivery_batch(pending: &mut BTreeMap<String, Pending>, now: u64) -> Vec<(String, Pending)> {
    let mut candidates = pending
        .iter()
        .filter(|(_, item)| !item.sent)
        .map(|(id, item)| (id.clone(), item.clone()))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(id, item)| (item.last_attempt, !item.terminal, id.clone()));
    let mut spaces = std::collections::BTreeSet::new();
    candidates.retain(|(_, item)| spaces.insert(item.scope.hosting_space_id));
    candidates.truncate(8);
    for (id, _) in &candidates {
        if let Some(item) = pending.get_mut(id) {
            item.last_attempt = now;
        }
    }
    candidates
}

fn can_enqueue(pending: &BTreeMap<String, Pending>, scope: Scope, notice: &Notice) -> bool {
    if pending.contains_key(notice.call_id()) {
        return true;
    }
    if pending.len() >= 4096
        || pending
            .values()
            .filter(|item| item.scope.hosting_space_id == scope.hosting_space_id)
            .count()
            >= 32
    {
        return false;
    }
    let Notice::Ring {
        caller, recipients, ..
    } = notice
    else {
        return true;
    };
    let same_caller = pending
        .values()
        .filter(
            |item| matches!(&item.notice, Notice::Ring { caller: other, .. } if caller == other),
        )
        .count();
    same_caller < 8
        && recipients.iter().all(|recipient| {
            pending
                .values()
                .filter(|item| {
                    matches!(&item.notice, Notice::Ring { recipients: others, .. }
                if others.iter().any(|other| other.identity == recipient.identity))
                })
                .count()
                < 8
        })
}

impl Delivery {
    pub fn new(config: Config) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let url = reqwest::Url::parse(&config.url)?;
        if url.scheme() != "http"
            || !url
                .host_str()
                .and_then(|h| h.parse::<std::net::IpAddr>().ok())
                .is_some_and(|h| h.is_loopback())
            || url.path() != "/internal/calls/event"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("Use the private loopback call-delivery endpoint.".into());
        }
        let key = Zeroizing::new(String::from_utf8(elo_core::vault::read_private(
            &config.key_file,
        )?)?);
        if key.len() != 64
            || !key
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("Invalid call-delivery key.".into());
        }
        Ok(Arc::new(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(1))
                .timeout(Duration::from_secs(3))
                .build()?,
            url: config.url,
            key,
            pending: Mutex::new(BTreeMap::new()),
        }))
    }
    pub async fn enqueue(&self, scope: Scope, notice: Notice, now: u64) {
        let mut pending = self.pending.lock().await;
        pending.retain(|_, item| item.deadline > now);
        let id = notice.call_id().to_owned();
        let terminal = matches!(notice, Notice::End { .. });
        if pending
            .get(&id)
            .is_some_and(|item| item.terminal || !terminal)
        {
            return;
        }
        if !can_enqueue(&pending, scope, &notice) {
            return;
        }
        let deadline = if let Notice::Ring { expires, .. } = &notice {
            *expires
        } else {
            now + 60
        };
        pending.insert(
            id,
            Pending {
                notice,
                scope,
                deadline,
                terminal,
                sent: false,
                last_attempt: 0,
            },
        );
    }
    pub async fn declined(&self) -> Vec<(String, elo_core::ids::IdentityId)> {
        let url = self.url.trim_end_matches("event").to_owned() + "declined";
        let Ok(mut response) = self
            .client
            .post(url)
            .bearer_auth(self.key.as_str())
            .send()
            .await
        else {
            return vec![];
        };
        if !response.status().is_success() {
            return vec![];
        }
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if bytes.len() + chunk.len() <= 32 * 1024 => {
                    bytes.extend_from_slice(&chunk)
                }
                Ok(None) => break,
                _ => return vec![],
            }
        }
        #[derive(Deserialize)]
        struct Reply {
            declined: Vec<(String, elo_core::ids::IdentityId)>,
        }
        serde_json::from_slice::<Reply>(&bytes)
            .map(|r| r.declined)
            .unwrap_or_default()
    }
    pub async fn deliver(&self, admission: &dyn Admission, now: u64) {
        let items = {
            let mut pending = self.pending.lock().await;
            pending.retain(|_, item| item.deadline > now);
            delivery_batch(&mut pending, now)
        };
        for (id, item) in items {
            let mut notice = item.notice.clone();
            if let Notice::Ring {
                head, recipients, ..
            } = &mut notice
            {
                let mut allowed = Vec::new();
                for recipient in recipients.iter() {
                    if admission
                        .device_allowed(
                            item.scope.hosting_space_id,
                            recipient.identity,
                            recipient.credential,
                            item.scope.conversation,
                            *head,
                        )
                        .await
                        .unwrap_or(false)
                    {
                        allowed.push(recipient.clone());
                    }
                }
                if allowed.is_empty() {
                    continue;
                }
                *recipients = allowed;
            }
            if !notice.valid(crate::server::now()) {
                continue;
            }
            if self
                .pending
                .lock()
                .await
                .get(&id)
                .is_none_or(|current| current.terminal != item.terminal)
            {
                continue;
            }
            if let Ok(response) = self
                .client
                .post(&self.url)
                .bearer_auth(self.key.as_str())
                .json(&notice)
                .send()
                .await
            {
                if response.status().is_success() || response.status().is_client_error() {
                    if let Some(current) = self.pending.lock().await.get_mut(&id)
                        && current.terminal == item.terminal
                    {
                        current.sent = true;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elo_core::ids::{IdentityId, SpaceId, StreamId};

    fn scope(number: u8) -> Scope {
        Scope {
            hosting_space_id: SpaceId::from_bytes([number; 32]),
            conversation: elo_core::calls::CallScope {
                space_id: SpaceId::from_bytes([number; 32]),
                stream_id: StreamId::from_bytes([number; 16]),
            },
        }
    }
    fn pending(number: u8, call: u8) -> Pending {
        Pending {
            notice: Notice::End {
                call_id: format!("{call:032x}"),
            },
            scope: scope(number),
            deadline: 1000,
            terminal: true,
            sent: false,
            last_attempt: 0,
        }
    }
    #[test]
    fn failed_delivery_retries_cannot_starve_other_spaces() {
        let mut queue = BTreeMap::new();
        for number in 0..12 {
            let item = pending(number, number);
            queue.insert(item.notice.call_id().to_owned(), item);
        }
        let first = delivery_batch(&mut queue, 1);
        assert_eq!(first.len(), 8);
        let second = delivery_batch(&mut queue, 2);
        for number in 8..12 {
            assert!(second.iter().any(|(_, item)| item.scope == scope(number)));
        }
        // Backlog in one Space receives a single slot in each round.
        for number in 12..32 {
            let item = pending(0, number);
            queue.insert(item.notice.call_id().to_owned(), item);
        }
        assert_eq!(
            delivery_batch(&mut queue, 3)
                .iter()
                .filter(|(_, item)| item.scope == scope(0))
                .count(),
            1
        );
    }
    #[test]
    fn per_space_pressure_preserves_other_spaces_and_terminal_updates() {
        let mut queue = BTreeMap::new();
        for number in 0..32 {
            let item = pending(1, number);
            queue.insert(item.notice.call_id().to_owned(), item);
        }
        assert!(!can_enqueue(&queue, scope(1), &pending(1, 33).notice));
        assert!(can_enqueue(&queue, scope(2), &pending(2, 33).notice));
        assert!(can_enqueue(&queue, scope(1), &pending(1, 0).notice));
    }
    #[test]
    fn caller_quota_is_shared_across_spaces() {
        let mut queue = BTreeMap::new();
        let caller = IdentityId::from_bytes([1; 32]);
        for number in 0..8 {
            let mut item = pending(number, number);
            item.notice = Notice::Ring {
                call_id: format!("{number:032x}"),
                scope: "1".repeat(64),
                head: "2".repeat(64).parse().unwrap(),
                caller,
                recipients: vec![],
                expires: 1000,
                video: false,
            };
            queue.insert(item.notice.call_id().to_owned(), item);
        }
        let mut notice = queue.values().next().unwrap().notice.clone();
        if let Notice::Ring { call_id, .. } = &mut notice {
            *call_id = format!("{:032x}", 9);
        }
        assert!(!can_enqueue(&queue, scope(9), &notice));
    }
}

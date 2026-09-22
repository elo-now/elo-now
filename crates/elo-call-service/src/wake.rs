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
}
pub struct Delivery {
    client: reqwest::Client,
    url: String,
    key: Zeroizing<String>,
    pending: Mutex<BTreeMap<String, Pending>>,
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
        if !pending.contains_key(&id) && pending.len() >= 4096 {
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
            pending
                .iter()
                .filter(|(_, item)| !item.sent)
                .take(8)
                .map(|(id, item)| (id.clone(), item.clone()))
                .collect::<Vec<_>>()
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

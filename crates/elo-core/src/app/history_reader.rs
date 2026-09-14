//! Read-only access to encrypted local history while the live client awaits I/O.
//! The snapshot contains no password, signing key or transport credentials.
use super::*;
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

/// Cheap immutable snapshots; the live owner copies only when it mutates state.
pub(super) struct Shared<T>(Arc<T>);
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> From<T> for Shared<T> {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}
impl<T> Deref for Shared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Clone> DerefMut for Shared<T> {
    fn deref_mut(&mut self) -> &mut T {
        Arc::make_mut(&mut self.0)
    }
}
impl<'a, T> IntoIterator for &'a Shared<Vec<T>> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<T: Serialize> Serialize for Shared<T> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.deref().serialize(serializer)
    }
}

struct HistoryContext {
    identity: IdentityId,
    credential: RecordId,
    age: age::x25519::Identity,
    store: ClientStore,
    authorities: Authorities,
    read: Shared<ReadState>,
    presentation: Arc<presentation::Presentation>,
}
impl HistoryContext {
    fn new(client: &ClientApp) -> Self {
        Self {
            identity: client.identity_id(),
            credential: client.session.credential().id(),
            age: client.session.age_identity().clone(),
            store: client.store.clone(),
            authorities: client.authorities.clone(),
            read: client.read.clone(),
            presentation: client.presentation.clone(),
        }
    }
    fn view(&self) -> HistoryView<'_> {
        HistoryView {
            identity: self.identity,
            credential: self.credential,
            age: &self.age,
            store: &self.store,
            authorities: &self.authorities,
            read: &self.read,
            presentation: &self.presentation,
        }
    }
}

/// An ephemeral capability to read joined compartments through the existing
/// SQLite worker and the same signature/authority/source checks as the live UI.
/// The native host must revoke it on lock and when its background pass ends.
pub struct HistorySnapshot {
    identity: IdentityId,
    active: Option<String>,
    scoped: bool,
    contexts: BTreeMap<Option<String>, HistoryContext>,
}
impl ClientApp {
    pub fn history_snapshot(&self) -> HistorySnapshot {
        let (active, contexts) = if let Some(spaces) = &self.spaces {
            let (active, clients) = spaces.history_clients(self);
            (
                active,
                clients
                    .into_iter()
                    .map(|(id, client)| (Some(id), HistoryContext::new(client)))
                    .collect(),
            )
        } else {
            (
                None,
                [(None, HistoryContext::new(self))].into_iter().collect(),
            )
        };
        HistorySnapshot {
            identity: self.identity_id(),
            active,
            scoped: self.spaces.is_some(),
            contexts,
        }
    }
    pub(super) fn history_view(&self) -> HistoryView<'_> {
        HistoryView {
            identity: self.identity_id(),
            credential: self.session.credential().id(),
            age: self.session.age_identity(),
            store: &self.store,
            authorities: &self.authorities,
            read: &self.read,
            presentation: &self.presentation,
        }
    }
}
impl HistorySnapshot {
    pub fn identity_id(&self) -> IdentityId {
        self.identity
    }
    pub async fn history_page(&self, request: &Value) -> Result<Value> {
        if request["op"] != "history_page" || request["expected_identity"] != json!(self.identity) {
            return Err("The open profile has changed.".into());
        }
        if self.scoped && request["expected_space"] != json!(self.active) {
            return Err("The selected Space has changed. Try again.".into());
        }
        let target = if self.scoped {
            request["target_space"]
                .as_str()
                .map(str::to_owned)
                .or(self.active.clone())
        } else {
            None
        };
        let context = self.contexts.get(&target).ok_or("Space unavailable.")?;
        let mut result = context.view().history_page(request).await?;
        if self.scoped {
            result["history"]["space_context"] = json!(target);
        }
        Ok(result)
    }
}

pub(super) struct HistoryView<'a> {
    identity: IdentityId,
    credential: RecordId,
    age: &'a age::x25519::Identity,
    store: &'a ClientStore,
    authorities: &'a Authorities,
    read: &'a ReadState,
    presentation: &'a presentation::Presentation,
}
impl HistoryView<'_> {
    fn identity_id(&self) -> IdentityId {
        self.identity
    }
    fn authority_index(&self, v: &Value) -> Result<usize> {
        let space: SpaceId = field(v, "space")?.parse()?;
        let stream: StreamId = field(v, "stream")?.parse()?;
        self.authorities
            .0
            .iter()
            .position(|a| a.space() == space && a.stream() == stream)
            .ok_or_else(|| "unknown pinned stream".into())
    }
    pub(super) async fn originals(&self, a: &Authority) -> Result<Vec<(SignedRecord, String)>> {
        self.originals_from(a, self.store.display_sources(a.space(), a.stream()).await?)
            .await
    }
    pub(super) async fn originals_from(
        &self,
        a: &Authority,
        mut sources: Vec<crate::store::DisplaySource>,
    ) -> Result<Vec<(SignedRecord, String)>> {
        sources.extend(
            self.store
                .action_sources(a.space(), a.stream(), None)
                .await?,
        );
        let mut rows = self.open_sources(a, sources).await?;
        let projection = message_actions::Projection::new(&rows);
        let mut targets = projection.pinned();
        targets.extend(
            self.read
                .reminders
                .iter()
                .filter(|r| r.stream == a.stream())
                .map(|r| r.record),
        );
        for target in targets {
            if !rows.iter().any(|(r, _)| r.id() == target) {
                rows.extend(
                    self.open_sources(
                        a,
                        self.store
                            .action_sources(a.space(), a.stream(), Some(target))
                            .await?,
                    )
                    .await?,
                );
            }
        }
        rows.sort_by_key(|(r, _)| {
            (
                r.body()["logical_time"].as_u64().unwrap_or(0),
                r.body()["issuer_credential"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                r.id(),
            )
        });
        Ok(rows)
    }
    pub(super) async fn open_sources(
        &self,
        a: &Authority,
        sources: Vec<crate::store::DisplaySource>,
    ) -> Result<Vec<(SignedRecord, String)>> {
        let mut unique = BTreeMap::new();
        for source in sources {
            if unique.contains_key(&source.record) {
                continue;
            }
            if let Some(record) = self.presentation.cached(a, &source) {
                unique.insert(record.id(), (record, source.status));
                continue;
            }
            let cipher = self
                .store
                .get_object(source.object)
                .await?
                .ok_or("stored source unavailable")?;
            let outer = crypto::open_object(&cipher, self.age)?;
            let r = if source.index < 0 {
                outer
            } else {
                let grant: history::HistoryGrant = outer.decode()?;
                outer.verify_signature(a.credential(grant.issuer_credential)?.key())?;
                let selected = grant
                    .selection
                    .get(source.index as usize)
                    .ok_or("history source index")?;
                decode_record(&selected.signed_record_base64)?
            };
            if r.id() != source.record {
                return Err("stored record/source mismatch".into());
            }
            if matches!(
                r.body()["kind"].as_str(),
                Some("chat.message" | "chat.action")
            ) {
                a.verify_historical(&r)?;
            } else {
                crate::files::VerifiedFileShare::verify(&r, a, self.credential, true)?;
            }
            self.presentation.remember(a, &source, &r);
            unique.insert(r.id(), (r, source.status));
        }
        let mut rows = unique.into_values().collect::<Vec<_>>();
        rows.sort_by(|(left, _), (right, _)| {
            (
                left.body()["logical_time"].as_u64().unwrap_or(0),
                left.body()["issuer_credential"].as_str().unwrap_or(""),
                left.id(),
            )
                .cmp(&(
                    right.body()["logical_time"].as_u64().unwrap_or(0),
                    right.body()["issuer_credential"].as_str().unwrap_or(""),
                    right.id(),
                ))
        });
        Ok(rows)
    }
    pub(super) async fn history_page(&self, v: &Value) -> Result<Value> {
        let index = self.authority_index(v)?;
        let a = &self.authorities.0[index];
        let mut before = v
            .get("before")
            .filter(|v| !v.is_null())
            .map(|v| -> Result<RecordId> {
                Ok(v.as_str().ok_or("Invalid history cursor.")?.parse()?)
            })
            .transpose()?;
        let query = v["query"].as_str().unwrap_or("").trim().to_lowercase();
        if query.len() > 1024 {
            return Err("Search is too long.".into());
        }
        let thread = v
            .get("thread")
            .filter(|v| !v.is_null())
            .map(|v| -> Result<RecordId> { Ok(v.as_str().ok_or("Invalid thread.")?.parse()?) })
            .transpose()?;
        let forward = v["forward"] == true;
        let mut newer = None;
        let mut rows = Vec::new();
        let refresh = v.get("records").is_some();
        if refresh {
            let ids: Vec<RecordId> = serde_json::from_value(v["records"].clone())?;
            rows = self
                .open_sources(
                    a,
                    self.store
                        .message_sources_by_ids(a.space(), a.stream(), ids)
                        .await?,
                )
                .await?;
        }
        if !refresh
            && before.is_none()
            && query.is_empty()
            && let Some(id) = v.get("around").and_then(Value::as_str)
        {
            let id: RecordId = id.parse()?;
            if Some(id) != thread {
                // A jump to the latest message has no forward page. Do not
                // render a Load newer control merely because a target exists.
                if !self
                    .store
                    .message_sources_page(a.space(), a.stream(), Some(id), 1, true)
                    .await?
                    .0
                    .is_empty()
                {
                    newer = Some(id);
                }
                rows = self
                    .open_sources(
                        a,
                        self.store
                            .action_sources(a.space(), a.stream(), Some(id))
                            .await?,
                    )
                    .await?;
                if rows.is_empty() {
                    return Err("This message is not available in this chat.".into());
                }
                before = Some(id);
            }
        }
        let mut scanned = 0;
        if !refresh {
            loop {
                let (sources, next) = self
                    .store
                    .message_sources_page(a.space(), a.stream(), before, 50 - rows.len(), forward)
                    .await?;
                let batch = self.open_sources(a, sources).await?;
                scanned += batch.len();
                rows.extend(batch.into_iter().filter(|(r, _)| {
                    let matching_thread = thread.is_none_or(|root| {
                        r.id() == root || r.body()["payload"]["thread_root"] == json!(root)
                    });
                    let matching_query = query.is_empty()
                        || r.body()["payload"]["text"]
                            .as_str()
                            .or_else(|| r.body()["filename"].as_str())
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&query);
                    matching_thread && matching_query
                }));
                before = next;
                if before.is_none()
                    || scanned >= 1000
                    || rows.len() >= 50
                    || (query.is_empty() && thread.is_none())
                {
                    break;
                }
            }
        }
        let actions = self
            .open_sources(
                a,
                self.store
                    .action_sources(a.space(), a.stream(), None)
                    .await?,
            )
            .await?;
        let projection = message_actions::Projection::new(&actions);
        let mut context = Vec::new();
        let mut roots = rows
            .iter()
            .filter_map(|(r, _)| {
                r.body()["payload"]["thread_root"]
                    .as_str()
                    .and_then(|id| id.parse::<RecordId>().ok())
            })
            .collect::<BTreeSet<_>>();
        if let Some(root) = thread {
            roots.insert(root);
        }
        for root in roots {
            if !rows.iter().any(|(r, _)| r.id() == root) {
                context.extend(
                    self.open_sources(
                        a,
                        self.store
                            .action_sources(a.space(), a.stream(), Some(root))
                            .await?,
                    )
                    .await?,
                );
            }
        }
        // Preserve the existing reply summaries for the recent activity window.
        // Opening a thread searches older local history independently.
        let mut reply_counts = BTreeMap::<String, usize>::new();
        if query.is_empty() && thread.is_none() {
            for (record, _) in self.originals(a).await? {
                if let Some(root) = record.body()["payload"]["thread_root"].as_str() {
                    *reply_counts.entry(root.into()).or_default() += 1;
                }
            }
        }
        let project = |(r, state): (SignedRecord, String)| {
            let id = r.id().to_string();
            let marked = self
                .read
                .unread
                .get(&a.stream().to_string())
                .is_some_and(|ids| ids.binary_search(&id).is_ok());
            let seen = self
                .read
                .seen
                .get(&a.stream().to_string())
                .is_some_and(|ids| ids.binary_search(&id).is_ok());
            json!({"reply_count":reply_counts.get(&id),"id":id,"body":r.body(),"state":state,"unread":marked || (!seen && r.body()["issuer_identity"]!=json!(self.identity_id())),"marked_unread":marked,"pinned":projection.is_pinned(r.id()),"reactions":projection.reactions(r.id(),self.identity_id())})
        };
        Ok(
            json!({"history":{"identity":self.identity_id(),"space":a.space(),"stream":a.stream(),"rows":rows.into_iter().map(project).collect::<Vec<_>>(),"context":context.into_iter().map(project).collect::<Vec<_>>(),"next":before,"newer":newer,"query":query,"thread":thread}}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_preserves_verified_history_and_copies_read_state_only_on_write() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = super::super::performance::profile(tmp.path().join("profile")).await;
        let view = app.view().await.unwrap();
        let chat = &view["streams"][0];
        let sent = app
            .operate(json!({"op":"send", "space":chat["space"],
            "stream":chat["stream"], "text":"Snapshot fixture",
            "created_at":"2026-09-13T12:00:00Z"}))
            .await
            .unwrap();
        let request = json!({"op":"history_page", "expected_identity":app.identity_id(),
            "space":chat["space"], "stream":chat["stream"]});
        let snapshot = app.history_snapshot();
        let context = &snapshot.contexts[&None];
        assert!(Arc::ptr_eq(&context.read.0, &app.read.0));
        assert!(Arc::ptr_eq(&context.authorities.0.0, &app.authorities.0.0));
        assert!(Arc::ptr_eq(&context.presentation, &app.presentation));
        let original = snapshot.history_page(&request).await.unwrap();
        assert_eq!(original, app.operate(request.clone()).await.unwrap());
        assert_eq!(
            original["history"]["rows"].as_array().unwrap().len(),
            1,
            "{sent}"
        );
        let id = &original["history"]["rows"][0]["id"];
        app.operate(json!({"op":"mark_unread", "space":chat["space"],
            "stream":chat["stream"], "records":[id]}))
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&context.read.0, &app.read.0));
        assert_eq!(snapshot.history_page(&request).await.unwrap(), original);
        assert_eq!(
            app.operate(request.clone()).await.unwrap()["history"]["rows"][0]["marked_unread"],
            true
        );
        // Persisted JSON stays identical to the previous owned representation.
        assert_eq!(
            serde_json::to_value(&app.read).unwrap(),
            serde_json::to_value(&*app.read).unwrap()
        );
        app.operate(json!({"op":"create_chat", "name":"Added after snapshot"}))
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&context.authorities.0.0, &app.authorities.0.0));
        let updated = app.view().await.unwrap();
        let added = updated["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "Added after snapshot")
            .unwrap();
        let new_chat = json!({"op":"history_page", "expected_identity":app.identity_id(),
            "space":added["space"], "stream":added["stream"]});
        assert!(snapshot.history_page(&new_chat).await.is_err());
        assert!(app.operate(new_chat).await.is_ok());
        assert_eq!(snapshot.history_page(&request).await.unwrap(), original);
        let mut invalid = request.clone();
        invalid["expected_identity"] = Value::Null;
        assert!(snapshot.history_page(&invalid).await.is_err());
        invalid = request.clone();
        invalid["stream"] = json!("unknown stream");
        assert!(snapshot.history_page(&invalid).await.is_err());
        invalid = request;
        invalid["op"] = json!("send");
        assert!(snapshot.history_page(&invalid).await.is_err());
        drop(snapshot);
        app.close().await.unwrap();
    }
}

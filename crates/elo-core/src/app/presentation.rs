//! Ephemeral, bounded verified-record cache and independently requested history.
//! Nothing here writes decrypted content or changes canonical record ordering.
use super::*;
use crate::ids::ObjectId;
use crate::store::DisplaySource;
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

type CacheKey = (SpaceId, StreamId, Option<RecordId>, RecordId, ObjectId, i64);
#[derive(Default)]
pub(super) struct Presentation {
    enabled: AtomicBool,
    records: Mutex<RecordCache>,
    defer: Arc<AtomicBool>,
}

pub(super) struct DeferredView(Arc<AtomicBool>, bool);
impl Drop for DeferredView {
    fn drop(&mut self) {
        self.0.store(self.1, Ordering::Relaxed);
    }
}
#[derive(Default)]
struct RecordCache {
    records: BTreeMap<CacheKey, SignedRecord>,
    order: VecDeque<CacheKey>,
    bytes: usize,
}
impl Presentation {
    pub(super) fn member_names(&self, a: &Authority) -> BTreeMap<String, String> {
        let cache = self.records.lock().expect("record cache");
        let mut names = BTreeMap::<String, (u64, String)>::new();
        for ((space, stream, head, _, _, _), record) in &cache.records {
            if *space != a.space() || *stream != a.stream() || *head != a.head_id() {
                continue;
            }
            if let (Some(id), Some(name)) = (
                record.body()["issuer_identity"].as_str(),
                record.body()["payload"]["sender_name"].as_str(),
            ) {
                let version = record.body()["logical_time"].as_u64().unwrap_or(0);
                if names.get(id).is_none_or(|(old, _)| version >= *old) {
                    names.insert(id.into(), (version, name.into()));
                }
            }
        }
        names
            .into_iter()
            .map(|(id, (_, name))| (id, name))
            .collect()
    }
    pub(super) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    pub(super) fn deferred(&self) -> bool {
        self.defer.load(Ordering::Relaxed)
    }
    pub(super) fn defer_view(&self) -> DeferredView {
        let previous = self.defer.swap(self.enabled(), Ordering::Relaxed);
        DeferredView(self.defer.clone(), previous)
    }
    fn key(a: &Authority, s: &DisplaySource) -> CacheKey {
        (
            a.space(),
            a.stream(),
            a.head_id(),
            s.record,
            s.object,
            s.index,
        )
    }
    pub(super) fn cached(&self, a: &Authority, s: &DisplaySource) -> Option<SignedRecord> {
        self.records
            .lock()
            .expect("record cache")
            .records
            .get(&Self::key(a, s))
            .cloned()
    }
    pub(super) fn remember(&self, a: &Authority, s: &DisplaySource, r: &SignedRecord) {
        // Account for both canonical bytes and the decoded JSON representation.
        let size = r.bytes().len().saturating_mul(4);
        let budget = 8 * 1024 * 1024;
        if size > budget {
            return;
        }
        let key = Self::key(a, s);
        let mut cache = self.records.lock().expect("record cache");
        if cache.records.contains_key(&key) {
            return;
        }
        while cache.bytes + size > budget || cache.records.len() >= 2048 {
            let Some(old) = cache.order.pop_front() else {
                break;
            };
            if let Some(record) = cache.records.remove(&old) {
                cache.bytes -= record.bytes().len() * 4;
            }
        }
        cache.bytes += size;
        cache.order.push_back(key);
        cache.records.insert(key, r.clone());
    }
}

impl ClientApp {
    /// Native UI uses summaries/activity, requesting the open history separately.
    /// CLI/protocol callers retain the existing complete projection contract.
    pub fn enable_paged_views(&self) {
        self.presentation.enabled.store(true, Ordering::Relaxed);
        if let Some(spaces) = &self.spaces {
            for child in spaces.children().values() {
                child.enable_paged_views();
            }
        }
    }
    pub(super) async fn message_record(&self, a: &Authority, id: RecordId) -> Result<SignedRecord> {
        self.open_sources(
            a,
            self.store
                .action_sources(a.space(), a.stream(), Some(id))
                .await?,
        )
        .await?
        .into_iter()
        .find(|(r, _)| r.id() == id)
        .map(|(r, _)| r)
        .ok_or_else(|| "This message is not available in this chat.".into())
    }
    pub(super) async fn history_page(&self, v: &Value) -> Result<Value> {
        self.history_view().history_page(v).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::performance::{message, profile};
    #[tokio::test]
    #[ignore = "opt-in release measurement on a disposable encrypted profile"]
    async fn measure_paged_ui_history() {
        let count = std::env::var("ELO_PERF_MESSAGES")
            .unwrap_or_else(|_| "10000".into())
            .parse::<u64>()
            .unwrap();
        assert!((1000..=500000).contains(&count));
        let tmp = tempfile::tempdir().unwrap();
        let mut app = profile(tmp.path().join("profile")).await;
        for n in 1..32 {
            app.create_chat(&format!("Chat {n}"), None, ChatKind::Chat)
                .await
                .unwrap();
        }
        let generation = std::time::Instant::now();
        for n in 1..=count {
            insert(&app, ((n - 1) % 32) as usize, n).await;
            if n % 10000 == 0 {
                println!(
                    "ELO_PERF {}",
                    json!({"case":"paged_generation","messages":n,"elapsed_ms":generation.elapsed().as_millis()})
                );
            }
        }
        app.enable_spaces().await.unwrap();
        app.enable_paged_views();
        let start = std::time::Instant::now();
        let summary = app.view().await.unwrap();
        let cold = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(summary["streams"].as_array().unwrap().len(), 32);
        assert_eq!(
            summary["streams"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["rows"].as_array().unwrap().len())
                .sum::<usize>(),
            32
        );
        let bytes = serde_json::to_vec(&summary).unwrap().len();
        let mut warm = Vec::new();
        for _ in 0..5 {
            let start = std::time::Instant::now();
            app.view().await.unwrap();
            warm.push(start.elapsed().as_secs_f64() * 1000.);
        }
        warm.sort_by(f64::total_cmp);
        let chat = app.pins[0].clone();
        let start = std::time::Instant::now();
        let page=app.operate(json!({"op":"history_page","expected_space":summary["active_space"],"space":chat.space,"stream":chat.stream})).await.unwrap();
        let first = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(page["history"]["rows"].as_array().unwrap().len(), 50);
        let start = std::time::Instant::now();
        app.operate(json!({"op":"history_page","space":chat.space,"stream":chat.stream,"before":page["history"]["next"]})).await.unwrap();
        let older = start.elapsed().as_secs_f64() * 1000.;
        let start = std::time::Instant::now();
        let sent=app.operate(json!({"op":"send","space":chat.space,"stream":chat.stream,"text":"Measured scoped send","created_at":"2026-09-13T14:00:00Z"})).await.unwrap();
        let send = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(sent["view"]["partial"], true);
        assert_eq!(sent["view"]["streams"].as_array().unwrap().len(), 1);
        println!(
            "ELO_PERF {}",
            json!({"case":"paged_ui","messages":count,"chats":32,"cold_summary_ms":cold,"warm_summary_p50_ms":warm[2],"first_50_ms":first,"older_50_ms":older,"scoped_send_ms":send,"summary_bytes":bytes,"history_bytes":serde_json::to_vec(&page).unwrap().len(),"send_bytes":serde_json::to_vec(&sent).unwrap().len(),"fixture":"own encrypted messages, no unread backlog or actions"})
        );
        app.close().await.unwrap();
    }
    async fn insert(app: &ClientApp, index: usize, sequence: u64) -> RecordId {
        let a = &app.authorities.0[index];
        let record = message(app, index, sequence);
        let recipients = record
            .chat()
            .unwrap()
            .recipient_credentials
            .iter()
            .map(|id| a.credential(*id).unwrap().clone())
            .collect::<Vec<_>>();
        let cipher = crypto::seal_chat(&record, &recipients).unwrap();
        app.store
            .commit_local_record_with_outbox(
                PreparedLocalRecord::new(
                    record.id(),
                    cipher,
                    RecordMetadata::new(
                        "chat.message",
                        Some(a.space()),
                        Some(a.stream()),
                        a.head_id(),
                    )
                    .unwrap(),
                    vec![],
                    LocalTime::from_millis(sequence / 3 + 1).unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        record.id()
    }
    #[tokio::test]
    async fn paged_history_keeps_cursors_scoped_and_old_records_actionable() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = profile(tmp.path().join("profile")).await;
        app.create_chat("Other", None, ChatKind::Chat)
            .await
            .unwrap();
        let mut expected = BTreeSet::new();
        let mut oldest = None;
        for n in 1..=1205 {
            let id = insert(&app, 0, n).await;
            expected.insert(id.to_string());
            oldest.get_or_insert(id);
        }
        let oldest = oldest.unwrap();
        let foreign = insert(&app, 1, 1300).await;
        app.enable_paged_views();
        let summary = app.view().await.unwrap();
        assert_eq!(summary["streams"].as_array().unwrap().len(), 2);
        assert_eq!(summary["streams"][0]["rows"].as_array().unwrap().len(), 1);
        assert_eq!(
            app.presentation.records.lock().unwrap().records.len(),
            2,
            "chat summaries must not decrypt read/local histories"
        );
        let pin = app.pins[0].clone();
        let mut request = json!({"op":"history_page","space":pin.space,"stream":pin.stream});
        let first = app.operate(request.clone()).await.unwrap()["history"].clone();
        assert_eq!(first["rows"].as_array().unwrap().len(), 50);
        let mut ids = first["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        let sent=app.operate(json!({"op":"send","space":pin.space,"stream":pin.stream,"text":"A concurrent arrival","created_at":"2026-09-13T13:00:00Z"})).await.unwrap();
        assert_eq!(sent["view"]["partial"], true);
        assert_eq!(sent["view"]["streams"].as_array().unwrap().len(), 1);
        request["before"] = first["next"].clone();
        while !request["before"].is_null() {
            let page = app.operate(request.clone()).await.unwrap()["history"].clone();
            assert!(page["rows"].as_array().unwrap().len() <= 50);
            for row in page["rows"].as_array().unwrap() {
                assert!(
                    ids.insert(row["id"].as_str().unwrap().to_owned()),
                    "duplicate between pages"
                );
            }
            request["before"] = page["next"].clone();
        }
        assert_eq!(ids, expected);
        request["before"] = json!(foreign);
        assert!(app.operate(request.clone()).await.is_err());
        request.as_object_mut().unwrap().remove("before");
        request["records"] = json!([foreign]);
        assert!(app.operate(request.clone()).await.is_err());
        request.as_object_mut().unwrap().remove("records");
        request["query"] = json!("performance message 1:");
        let mut found = Vec::new();
        loop {
            let page = app.operate(request.clone()).await.unwrap()["history"].clone();
            found.extend(page["rows"].as_array().unwrap().iter().cloned());
            request["before"] = page["next"].clone();
            if request["before"].is_null() {
                break;
            }
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["id"], json!(oldest));
        for chunk in expected.into_iter().collect::<Vec<_>>().chunks(1000) {
            app.operate(
                json!({"op":"mark_read","space":pin.space,"stream":pin.stream,"records":chunk}),
            )
            .await
            .unwrap();
        }
        assert_eq!(app.read.seen[&pin.stream.to_string()].len(), 1205);
        app.operate(
            json!({"op":"mark_unread","space":pin.space,"stream":pin.stream,"records":[oldest]}),
        )
        .await
        .unwrap();
        let unread = app.view().await.unwrap();
        assert_eq!(unread["streams"][0]["unread_count"], 1);
        assert!(
            unread["streams"][0]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == json!(oldest) && r["marked_unread"] == true)
        );
        app.operate(json!({"op":"message_action","space":pin.space,"stream":pin.stream,"action":{"type":"pin","target":oldest,"active":true},"created_at":"2026-09-13T13:00:01Z"})).await.unwrap();
        let updated=app.operate(json!({"op":"history_page","space":pin.space,"stream":pin.stream,"records":[oldest]})).await.unwrap();
        assert_eq!(updated["history"]["rows"][0]["pinned"], true);
        app.operate(json!({"op":"send","space":pin.space,"stream":pin.stream,"reply_to":oldest,"text":"Reply to old history","created_at":"2026-09-13T13:00:02Z"})).await.unwrap();
        let thread=app.operate(json!({"op":"history_page","space":pin.space,"stream":pin.stream,"thread":oldest,"around":oldest})).await.unwrap();
        assert!(
            thread["history"]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["body"]["payload"]["text"] == "Reply to old history")
        );
        assert_eq!(thread["history"]["context"][0]["id"], json!(oldest));
        let jump = app
            .operate(
                json!({"op":"history_page","space":pin.space,"stream":pin.stream,"around":oldest}),
            )
            .await
            .unwrap();
        assert_eq!(jump["history"]["newer"], json!(oldest));
        let latest = app
            .store
            .message_sources_page(pin.space, pin.stream, None, 1, false)
            .await
            .unwrap()
            .0[0]
            .record;
        let latest_jump = app
            .operate(
                json!({"op":"history_page","space":pin.space,"stream":pin.stream,"around":latest}),
            )
            .await
            .unwrap();
        assert!(latest_jump["history"]["newer"].is_null());
        assert!(
            latest_jump["history"]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == json!(latest))
        );
        let newer=app.operate(json!({"op":"history_page","space":pin.space,"stream":pin.stream,"before":oldest,"forward":true})).await.unwrap();
        assert_eq!(newer["history"]["rows"].as_array().unwrap().len(), 50);
        assert!(
            !newer["history"]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == json!(oldest))
        );
        app.enable_spaces().await.unwrap();
        let space_view = app.view().await.unwrap();
        assert!(space_view["active_space"].is_string());
        let mut guarded = json!({"op":"history_page","space":pin.space,"stream":pin.stream,"expected_space":"another-space"});
        assert!(app.operate(guarded.clone()).await.is_err());
        guarded["expected_space"] = space_view["active_space"].clone();
        let scoped = app.operate(guarded).await.unwrap();
        assert_eq!(
            scoped["history"]["space_context"],
            space_view["active_space"]
        );
        assert!(scoped.get("view").is_none());
        let sent=app.operate(json!({"op":"send","space":pin.space,"stream":pin.stream,"text":"Space scoped","created_at":"2026-09-13T14:00:00Z"})).await.unwrap();
        assert_eq!(sent["view"]["partial"], true);
        assert_eq!(sent["view"]["active_space"], space_view["active_space"]);
        assert_eq!(sent["view"]["all_streams"].as_array().unwrap().len(), 1);
        assert_eq!(
            app.view().await.unwrap()["streams"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        app.close().await.unwrap();
        let reopened = ClientApp::open(
            tmp.path().join("profile"),
            "synthetic performance password".into(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(reopened.read.seen[&pin.stream.to_string()].len(), 1204);
        reopened.close().await.unwrap();
    }

    #[tokio::test]
    async fn summaries_keep_verified_incoming_activity_and_mute_without_loading_read_history() {
        use crate::identity::DeviceCredential;
        use crate::ids::{MailboxId, PeerId};
        use crate::replica::{InventoryEntry, TransferHint};
        let tmp = tempfile::tempdir().unwrap();
        let mut app = profile(tmp.path().join("profile")).await;
        let root = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
        let age = age::x25519::Identity::generate();
        let credential =
            DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
        let a = &mut app.authorities.0[0];
        a.add_credential(credential.clone());
        let mut config = a.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = a.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.action.operation = "replace".into();
        config.members.push(Member {
            identity_id: credential.identity(),
            identity_type: "HUMAN".into(),
            root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            capabilities: vec![Capability::Read, Capability::Post],
            credential_ids: vec![credential.id()],
            external: false,
        });
        config.members.sort_by_key(|m| m.identity_id);
        a.commit_update(
            &app.store,
            config.sign(app.session.signing_key()).unwrap(),
            app.session.age_identity(),
            now().unwrap(),
        )
        .await
        .unwrap();
        let a = &app.authorities.0[0];
        let mut body = message(&app, 0, 1).chat().unwrap();
        body.issuer_identity = credential.identity();
        body.issuer_credential = credential.id();
        body.payload.sender_name = Some("Guest".into());
        let record = a.prepare_chat(body, &key).unwrap();
        let recipients = record
            .chat()
            .unwrap()
            .recipient_credentials
            .iter()
            .map(|id| a.credential(*id).unwrap().clone())
            .collect::<Vec<_>>();
        let cipher = crypto::seal_chat(&record, &recipients).unwrap();
        let object = ObjectId::of_ciphertext(&cipher);
        let peer = PeerId::from_bytes([34; 32]);
        let mailbox = MailboxId::from_bytes([35; 32]);
        app.store
            .stage_inbox(
                peer,
                mailbox,
                "36".repeat(32),
                InventoryEntry {
                    arrival_seq: 1,
                    object_id: object,
                    size_bytes: cipher.len() as u64,
                    transfer_hint: TransferHint::Eager,
                },
                Some(cipher),
                LocalTime::from_millis(1).unwrap(),
            )
            .await
            .unwrap();
        let item = app.store.pending_inbox(1).await.unwrap().remove(0);
        app.store
            .finish_inbox(
                item,
                Some(a.verify(&record, app.session.credential().id()).unwrap()),
                LocalTime::from_millis(1).unwrap(),
            )
            .await
            .unwrap();
        for n in 2..=120 {
            insert(&app, 0, n).await;
        }
        app.enable_paged_views();
        let pin = app.pins[0].clone();
        let summary = app.view().await.unwrap();
        assert_eq!(summary["streams"][0]["rows"].as_array().unwrap().len(), 2);
        assert_eq!(summary["streams"][0]["unread_count"], 1);
        assert_eq!(
            summary["streams"][0]["member_names"]
                [record.body()["issuer_identity"].as_str().unwrap()],
            "Guest"
        );
        app.operate(
            json!({"op":"set_chat_muted","space":pin.space,"stream":pin.stream,"muted":true}),
        )
        .await
        .unwrap();
        assert_eq!(app.view().await.unwrap()["streams"][0]["muted"], true);
        app.operate(
            json!({"op":"mark_read","space":pin.space,"stream":pin.stream,"records":[record.id()]}),
        )
        .await
        .unwrap();
        let read = app.view().await.unwrap();
        assert_eq!(read["streams"][0]["unread_count"], 0);
        assert_eq!(read["streams"][0]["rows"].as_array().unwrap().len(), 1);
        app.close().await.unwrap();
    }
}

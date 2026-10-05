//! Chat-wide actions use the existing signed/encrypted transport. Personal read
//! markers and reminders share the encrypted, backup-covered read-state file.
use super::*;
use crate::record::MessageAction;
use std::collections::BTreeSet;

type Version = (u64, RecordId);
type Expiry = (Option<u64>, Option<u8>);
#[derive(Clone)]
struct ExpirySource {
    id: RecordId,
    author: IdentityId,
    clock: u64,
    deadline: Option<u64>,
}
impl ExpirySource {
    fn initial_expiry(&self) -> Expiry {
        let hours = self.deadline.and_then(|deadline| {
            let duration = deadline.saturating_sub(self.clock);
            [1u8, 12, 24]
                .into_iter()
                .find(|hours| duration.abs_diff(u64::from(*hours) * 3_600_000) < 1000)
        });
        (self.deadline, hours)
    }
    fn from_record(record: &SignedRecord) -> Option<Self> {
        let body = record.body();
        Some(Self {
            id: if body["kind"] == "chat.locator" {
                body["locator"]["message_record_id"]
                    .as_str()?
                    .parse()
                    .ok()?
            } else {
                record.id()
            },
            author: body["issuer_identity"].as_str()?.parse().ok()?,
            clock: body["logical_time"].as_u64().unwrap_or(0),
            deadline: body["payload"]["expires_at_ms"].as_u64(),
        })
    }
}
#[derive(Default)]
pub(super) struct Projection {
    now_ms: u64,
    reactions: BTreeMap<(RecordId, String, IdentityId), (Version, bool)>,
    pins: BTreeMap<RecordId, (Version, bool)>,
    deletions: BTreeSet<(RecordId, IdentityId)>,
    edits: BTreeMap<(RecordId, IdentityId), BTreeMap<Version, (String, Vec<IdentityId>)>>,
    expiry: BTreeMap<(RecordId, IdentityId), BTreeMap<Version, Option<u8>>>,
}
impl Projection {
    /// Call only with records whose signatures and historical authority passed.
    pub(super) fn new(records: &[(SignedRecord, String)]) -> Self {
        Self::at(
            records,
            now().map(|time| time.as_millis() as u64).unwrap_or(0),
        )
    }
    fn at(records: &[(SignedRecord, String)], now_ms: u64) -> Self {
        let mut state = Self {
            now_ms,
            ..Self::default()
        };
        for (record, _) in records {
            if record.body()["kind"] != "chat.action" {
                continue;
            }
            let Ok(chat) = record.chat() else { continue };
            if !record::current_message_time_is_valid(chat.logical_time) {
                continue;
            }
            let version = (chat.logical_time, record.id());
            match chat.payload.action {
                Some(MessageAction::Reaction {
                    target,
                    emoji,
                    active,
                }) => {
                    let slot = state
                        .reactions
                        .entry((target, emoji, chat.issuer_identity))
                        .or_insert((version, active));
                    if version > slot.0 {
                        *slot = (version, active);
                    }
                }
                Some(MessageAction::Pin { target, active }) => {
                    let slot = state.pins.entry(target).or_insert((version, active));
                    if version > slot.0 {
                        *slot = (version, active);
                    }
                }
                Some(MessageAction::Delete { target }) => {
                    state.deletions.insert((target, chat.issuer_identity));
                }
                Some(MessageAction::Expiry { target, hours }) => {
                    state
                        .expiry
                        .entry((target, chat.issuer_identity))
                        .or_default()
                        .insert(version, hours);
                }
                Some(MessageAction::Edit {
                    target,
                    text,
                    mentions,
                }) => {
                    state
                        .edits
                        .entry((target, chat.issuer_identity))
                        .or_default()
                        .insert(version, (text, mentions));
                }
                None => {}
            }
        }
        state
    }
    /// A signed deletion is effective only for the original author's record.
    /// Retain claims received before the body/locator; delivery order is irrelevant.
    pub(super) fn is_deleted(&self, record: &SignedRecord) -> bool {
        if self.is_expired(record) {
            return true;
        }
        let body = record.body();
        let target = if body["kind"] == "chat.locator" {
            body["locator"]["message_record_id"]
                .as_str()
                .and_then(|id| id.parse().ok())
        } else if matches!(body["kind"].as_str(), Some("chat.message" | "file.shared")) {
            Some(record.id())
        } else {
            None
        };
        let author = body["issuer_identity"]
            .as_str()
            .and_then(|id| id.parse().ok());
        target
            .zip(author)
            .is_some_and(|key| self.deletions.contains(&key))
    }
    pub(super) fn body(&self, record: &SignedRecord) -> Value {
        let body = record.body();
        if self.is_deleted(record) {
            // Keep timeline/thread position, but no text, file keys or capabilities.
            json!({"kind":"deleted", "expired":self.is_expired(record), "issuer_identity":body["issuer_identity"],
                "issuer_credential":body["issuer_credential"],
                "created_at":body["created_at"], "logical_time":history_reader::record_presentation_time(record),
                "deleted_record_id":if body["kind"] == "chat.locator" { body["locator"]["message_record_id"].clone() } else { json!(record.id()) },
                "payload":{"thread_root":body["payload"]["thread_root"]}})
        } else {
            let mut projected = if body["kind"] == "chat.locator" {
                json!({"kind":"unavailable", "issuer_identity":body["issuer_identity"],
                "issuer_credential":body["issuer_credential"], "created_at":body["created_at"],
                "logical_time":body["logical_time"], "payload":{"thread_root":body["payload"]["thread_root"],"expires_at_ms":body["payload"]["expires_at_ms"]},
                "locator":body["locator"]})
            } else {
                body.clone()
            };
            if matches!(body["kind"].as_str(), Some("chat.message" | "chat.locator")) {
                let (deadline, hours) = self.expiry(record);
                projected["payload"]["expires_at_ms"] = json!(deadline);
                projected["payload"]["expiry_hours"] = json!(hours);
            }
            if body["kind"] == "chat.message" {
                let author = record.chat().map(|chat| chat.issuer_identity).ok();
                if let Some(events) =
                    author.and_then(|author| self.edits.get(&(record.id(), author)))
                {
                    let original_time = body["logical_time"].as_u64().unwrap_or(0);
                    for ((changed_at, _), (text, mentions)) in events {
                        if *changed_at <= original_time {
                            continue;
                        }
                        let source = ExpirySource::from_record(record).expect("validated message");
                        // An edit cannot resurrect content that had expired when signed.
                        let mut past = source.initial_expiry().0;
                        if let Some(expiry) = self.expiry.get(&(source.id, source.author)) {
                            for ((at, _), hours) in expiry {
                                if *at <= source.clock {
                                    continue;
                                }
                                if *at > *changed_at || past.is_some_and(|deadline| *at >= deadline)
                                {
                                    break;
                                }
                                past = hours.map(|h| at.saturating_add(u64::from(h) * 3_600_000));
                            }
                        }
                        if past.is_some_and(|deadline| *changed_at >= deadline) {
                            continue;
                        }
                        projected["payload"]["text"] = json!(text);
                        projected["payload"]["mentions"] = json!(mentions);
                        projected["payload"]["edited_at_ms"] = json!(changed_at);
                    }
                }
            }
            projected
        }
    }
    /// Only the author can change a deadline. Replay in signed order, including
    /// events delivered before the message, and never accept edits after expiry.
    pub(super) fn expiry(&self, record: &SignedRecord) -> (Option<u64>, Option<u8>) {
        ExpirySource::from_record(record)
            .map(|source| self.own_expiry(&source))
            .unwrap_or_default()
    }
    fn own_expiry(&self, source: &ExpirySource) -> Expiry {
        let (mut deadline, mut hours) = source.initial_expiry();
        if let Some(events) = self.expiry.get(&(source.id, source.author)) {
            for ((changed_at, _), choice) in events {
                if *changed_at <= source.clock {
                    continue;
                }
                if deadline.is_some_and(|expires| *changed_at >= expires) {
                    break;
                }
                hours = *choice;
                deadline = hours.map(|h| changed_at.saturating_add(u64::from(h) * 3_600_000));
            }
        }
        (deadline, hours)
    }
    fn is_expired(&self, record: &SignedRecord) -> bool {
        matches!(
            record.body()["kind"].as_str(),
            Some("chat.message" | "chat.locator")
        ) && self
            .expiry(record)
            .0
            .is_some_and(|expires| expires <= self.now_ms)
    }
    pub(super) fn pinned(&self) -> BTreeSet<RecordId> {
        self.pins
            .iter()
            .filter(|(_, (_, active))| *active)
            .map(|(id, _)| *id)
            .collect()
    }
    pub(super) fn is_pinned(&self, target: RecordId) -> bool {
        self.pins.get(&target).is_some_and(|(_, active)| *active)
    }
    pub(super) fn reactions(&self, target: RecordId, own: IdentityId) -> Vec<Value> {
        record::reaction_choices().iter().filter_map(|emoji| {
            let people: Vec<_> = self.reactions.iter().filter(|((id,e,_),(_,active))|*id==target && e==emoji && *active).map(|((_,_,person),_)|*person).collect();
            (!people.is_empty()).then(||json!({"emoji":emoji,"count":people.len(),"mine":people.contains(&own),"people":people}))
        }).collect()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reminder {
    pub(super) stream: StreamId,
    pub(super) record: RecordId,
    pub(super) due_at: i64,
    #[serde(default)]
    pub(super) system_notification: bool,
}
impl ClientApp {
    pub(super) async fn message_action(&mut self, v: &Value) -> Result<()> {
        let index = self.authority_index(v)?;
        let authority = &self.authorities.0[index];
        if !self.authorities.space_ready(authority) {
            return Err("This chat needs to finish syncing first.".into());
        }
        let action: MessageAction = serde_json::from_value(v["action"].clone())?;
        let originals = self.originals(authority).await?;
        let target = self.message_record(authority, action.target()).await?;
        if matches!(action, MessageAction::Edit { .. }) {
            if target.body()["issuer_identity"] != json!(self.session.identity_id())
                || target.body()["kind"] != "chat.message"
            {
                return Err("Only the author can edit this message.".into());
            }
            if Projection::new(&originals).is_deleted(&target) {
                return Err("This message is no longer available to edit.".into());
            }
        } else if matches!(action, MessageAction::Expiry { .. }) {
            if target.body()["issuer_identity"] != json!(self.session.identity_id())
                || target.body()["kind"] != "chat.message"
            {
                return Err("message_expiry_author_only".into());
            }
            if let MessageAction::Expiry {
                hours: Some(hours), ..
            } = &action
                && !matches!(hours, 1 | 12 | 24)
            {
                return Err("message_expiry_invalid".into());
            }
            let projection = Projection::new(&originals);
            if projection.is_deleted(&target) {
                return Err("message_expiry_unavailable".into());
            }
        } else if matches!(action, MessageAction::Delete { .. }) {
            if target.body()["issuer_identity"] != json!(self.session.identity_id())
                || !matches!(
                    target.body()["kind"].as_str(),
                    Some("chat.message" | "file.shared")
                )
            {
                return Err("Only the author can delete this message.".into());
            }
        } else if Projection::new(&originals).is_deleted(&target) {
            return Err("This message was deleted.".into());
        }
        let time = now()?;
        let highest = originals
            .iter()
            .filter_map(|(r, _)| r.body()["logical_time"].as_u64())
            .max()
            .unwrap_or(0)
            .max(target.body()["logical_time"].as_u64().unwrap_or(0));
        let logical_time = record::next_message_time(highest, u64::try_from(time.as_millis())?);
        if matches!(
            action,
            MessageAction::Expiry { .. } | MessageAction::Edit { .. }
        ) && Projection::at(&originals, logical_time).is_deleted(&target)
        {
            return Err("message_expiry_unavailable".into());
        }
        let signed = authority.prepare_chat(
            ChatMessage {
                v: 1,
                kind: "chat.action".into(),
                nonce: record::random_hex::<16>()?,
                space_id: authority.space(),
                stream_id: authority.stream(),
                issuer_identity: self.session.identity_id(),
                issuer_credential: self.session.credential().id(),
                config_id: authority.head_id().ok_or("Missing configuration.")?,
                audience: vec![],
                recipient_credentials: vec![],
                logical_time,
                created_at: field(v, "created_at")?.into(),
                parents: vec![],
                payload: TextPayload {
                    mentions: vec![],
                    text: String::new(),
                    expires_at_ms: None,
                    sender_name: None,
                    thread_root: None,
                    action: Some(action),
                },
                locator: None,
                access: None,
            },
            self.session.signing_key(),
        )?;
        let recipients = signed
            .chat()?
            .recipient_credentials
            .iter()
            .map(|id| authority.credential(*id).cloned())
            .collect::<record::Result<Vec<_>>>()?;
        self.require_fresh_membership(authority).await?;
        let cipher = crypto::seal_chat(&signed, &recipients)?;
        let cipher = crate::erasure::wrap(
            cipher,
            self.session.credential(),
            self.session.signing_key(),
        )?;
        self.store
            .commit_local_record_with_outbox(PreparedLocalRecord::new(
                signed.id(),
                cipher,
                RecordMetadata::new(
                    "chat.action",
                    Some(authority.space()),
                    Some(authority.stream()),
                    authority.head_id(),
                )?,
                self.targets(),
                time,
            )?)
            .await?;
        Ok(())
    }
    pub(super) async fn update_reminder(&mut self, v: &Value) -> Result<()> {
        let index = self.authority_index(v)?;
        let stream = self.pins[index].stream;
        let record: RecordId = field(v, "record")?.parse()?;
        let mut read = (*self.read).clone();
        read.reminders
            .retain(|r| r.stream != stream || r.record != record);
        if field(v, "op")? == "remind" {
            let due = v["due_at"].as_i64().ok_or("Choose a reminder time.")?;
            let time = now()?.as_millis();
            if due <= time || due > time + 366 * 24 * 60 * 60 * 1000 {
                return Err("Choose a time within the next year.".into());
            }
            if read.reminders.len() >= 100 {
                return Err("Finish a reminder before adding another.".into());
            }
            let authority = &self.authorities.0[index];
            let message = self.message_record(authority, record).await?;
            if Projection::new(&self.originals(authority).await?).is_deleted(&message) {
                return Err("This message was deleted.".into());
            }
            read.reminders.push(Reminder {
                stream,
                record,
                due_at: due,
                system_notification: v
                    .get("system_notification")
                    .map(|value| {
                        value
                            .as_bool()
                            .ok_or("Choose whether to send a system notification.")
                    })
                    .transpose()?
                    .unwrap_or(false),
            });
            read.reminders
                .sort_by_key(|r| (r.due_at, r.stream, r.record));
        }
        self.write_read_state(&read)?;
        self.read = read.into();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expiry_message(clock: u64, deadline: Option<u64>, root: Option<RecordId>) -> SignedRecord {
        let mut chat = SignedRecord::parse(include_bytes!(
            "../../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap()
        .chat()
        .unwrap();
        chat.logical_time = clock;
        chat.nonce = format!("{clock:032x}");
        chat.payload.expires_at_ms = deadline;
        chat.payload.thread_root = root;
        chat.sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]))
            .unwrap()
    }
    fn expiry_edit(target: &SignedRecord, clock: u64, hours: Option<u8>) -> (SignedRecord, String) {
        let mut chat = target.chat().unwrap();
        chat.kind = "chat.action".into();
        chat.logical_time = clock;
        chat.nonce = format!("{clock:032x}");
        chat.payload.text.clear();
        chat.payload.expires_at_ms = None;
        chat.payload.thread_root = None;
        chat.payload.action = Some(MessageAction::Expiry {
            target: target.id(),
            hours,
        });
        (
            chat.sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]))
                .unwrap(),
            "ACCEPTED".into(),
        )
    }
    #[test]
    fn replies_keep_their_own_deadlines_after_parent_expiry_and_changes() {
        let root = expiry_message(1, Some(10_000), None);
        let reply = expiry_message(100, Some(20_000), Some(root.id()));
        let permanent = expiry_message(101, None, Some(root.id()));
        let original_bytes = reply.bytes().to_vec();
        for records in [
            vec![],
            vec![(root.clone(), "ACCEPTED".into())],
            vec![
                (root.clone(), "ACCEPTED".into()),
                expiry_edit(&root, 500, Some(24)),
            ],
            vec![
                (root.clone(), "ACCEPTED".into()),
                expiry_edit(&root, 500, None),
            ],
        ] {
            let projection = Projection::at(&records, 10_000);
            assert_eq!(projection.expiry(&reply).0, Some(20_000));
            assert!(!projection.is_deleted(&reply));
            assert!(!projection.is_deleted(&permanent));
            assert_eq!(projection.body(&reply)["kind"], "chat.message");
            assert!(Projection::at(&records, 20_000).is_expired(&reply));
            assert!(!Projection::at(&records, 20_000).is_expired(&permanent));
        }
        assert_eq!(reply.bytes(), original_bytes);
        assert!(Projection::at(&[], 10_000).is_expired(&root));
    }
    #[test]
    fn reply_author_can_edit_its_deadline_independently_of_parent_policy() {
        let root = expiry_message(1, Some(10_000), None);
        let reply = expiry_message(100, Some(20_000), Some(root.id()));
        let change = expiry_edit(&reply, 500, Some(12));
        let cancel_parent = expiry_edit(&root, 600, None);
        let records = vec![(root.clone(), "ACCEPTED".into()), change, cancel_parent];
        for records in [records.clone(), records.into_iter().rev().collect()] {
            let projection = Projection::at(&records, 30_000);
            assert_eq!(projection.expiry(&reply).0, Some(43_200_500));
            assert!(!projection.is_expired(&reply));
        }
        let mut foreign = expiry_edit(&reply, 501, None).0.chat().unwrap();
        foreign.issuer_identity = IdentityId::from_bytes([99; 32]);
        let foreign = foreign
            .sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]))
            .unwrap();
        assert!(Projection::at(&[(foreign, "ACCEPTED".into())], 20_000).is_expired(&reply));
        let late_cancel = expiry_edit(&reply, 20_000, None);
        assert!(Projection::at(&[late_cancel], 20_001).is_expired(&reply));
    }
    fn event(
        identity: u8,
        clock: u64,
        active: bool,
        pin: bool,
        nonce: u8,
    ) -> (SignedRecord, String) {
        let target = RecordId::from_bytes([8; 32]);
        let mut message = SignedRecord::parse(include_bytes!(
            "../../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap()
        .chat()
        .unwrap();
        message.kind = "chat.action".into();
        message.payload.text.clear();
        message.issuer_identity = IdentityId::from_bytes([identity; 32]);
        message.logical_time = clock;
        message.nonce = format!("{nonce:032x}");
        message.payload.action = Some(if pin {
            MessageAction::Pin { target, active }
        } else {
            MessageAction::Reaction {
                target,
                emoji: "👍".into(),
                active,
            }
        });
        (
            message
                .sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]))
                .unwrap(),
            "ACCEPTED".into(),
        )
    }
    fn deletion(record: &SignedRecord, author: IdentityId) -> (SignedRecord, String) {
        let mut action = event(1, 10, true, true, 9).0.chat().unwrap();
        action.issuer_identity = author;
        action.payload.action = Some(MessageAction::Delete {
            target: record.id(),
        });
        (
            action
                .sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]))
                .unwrap(),
            "ACCEPTED".into(),
        )
    }
    fn text_edit(
        record: &SignedRecord,
        author: IdentityId,
        clock: u64,
        text: &str,
        nonce: u8,
    ) -> (SignedRecord, String) {
        let mut edit = event(1, clock, true, true, nonce).0.chat().unwrap();
        edit.issuer_identity = author;
        edit.payload.action = Some(MessageAction::Edit {
            target: record.id(),
            text: text.into(),
            mentions: vec![],
        });
        (
            edit.sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]))
                .unwrap(),
            "ACCEPTED".into(),
        )
    }
    #[test]
    fn text_edits_are_author_only_ordered_and_do_not_restore_expired_or_deleted_text() {
        let mut chat = SignedRecord::parse(include_bytes!(
            "../../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap()
        .chat()
        .unwrap();
        chat.logical_time = 100;
        chat.payload.expires_at_ms = Some(1000);
        let author = chat.issuer_identity;
        let original = chat
            .sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]))
            .unwrap();
        let early = text_edit(&original, author, 200, "First correction", 1);
        let later = text_edit(&original, author, 300, "Final correction", 2);
        let foreign = text_edit(
            &original,
            IdentityId::from_bytes([88; 32]),
            400,
            "Forged correction",
            3,
        );
        let expired = text_edit(&original, author, 1000, "Too late", 4);
        let before = text_edit(&original, author, 99, "Predates original", 5);
        for events in [
            vec![
                early.clone(),
                later.clone(),
                foreign.clone(),
                expired.clone(),
                before.clone(),
            ],
            vec![expired, later.clone(), foreign, early, before, later],
        ] {
            let body = Projection::at(&events, 999).body(&original);
            assert_eq!(body["payload"]["text"], "Final correction");
            assert_eq!(body["payload"]["edited_at_ms"], 300);
            let expired = Projection::at(&events, 1000).body(&original);
            assert_eq!(expired["kind"], "deleted");
            assert!(expired["payload"]["text"].is_null());
            let mut deleted = events;
            deleted.push(deletion(&original, author));
            assert!(Projection::at(&deleted, 999).body(&original)["payload"]["text"].is_null());
        }
        assert_ne!(original.body()["payload"]["text"], "Final correction");
    }
    #[tokio::test]
    async fn text_edit_survives_restart_and_updates_search_without_rewriting_signed_message() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("profile");
        let mut app = super::super::performance::profile(path.clone()).await;
        let chat = app.view().await.unwrap()["streams"][0].clone();
        let sent=app.operate(json!({"op":"send","space":chat["space"],"stream":chat["stream"],"text":"Initial text fixture","created_at":"2026-10-05T12:00:00Z"})).await.unwrap();
        let id = sent["sent"]["id"].clone();
        let mut edit = json!({"op":"message_action","space":chat["space"],"stream":chat["stream"],"created_at":"2026-10-05T12:01:00Z","action":{"type":"edit","target":id,"text":"Updated text fixture"}});
        app.operate(edit.clone()).await.unwrap();
        for invalid in ["".to_owned(), "   ".to_owned(), "a".repeat(16385)] {
            edit["action"]["text"] = json!(invalid);
            assert!(app.operate(edit.clone()).await.is_err());
        }
        let originals = app.originals(&app.authorities.0[0]).await.unwrap();
        assert_eq!(
            originals
                .iter()
                .find(|(r, _)| json!(r.id()) == id)
                .unwrap()
                .0
                .body()["payload"]["text"],
            "Initial text fixture"
        );
        app.close().await.unwrap();
        let mut app = ClientApp::open(path, "synthetic performance password".into(), false)
            .await
            .unwrap();
        let mut search = json!({"op":"history_page","space":chat["space"],"stream":chat["stream"],"query":"Updated text fixture"});
        let found = app.operate(search.clone()).await.unwrap();
        assert_eq!(found["history"]["rows"][0]["id"], id);
        assert!(found["history"]["rows"][0]["body"]["payload"]["edited_at_ms"].is_number());
        search["query"] = json!("Initial text fixture");
        assert!(
            app.operate(search).await.unwrap()["history"]["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn explicit_history_disclosure_previews_and_imports_the_current_edited_text() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = super::super::performance::profile(tmp.path().join("profile")).await;
        let chat = app.view().await.unwrap()["streams"][0].clone();
        let sent = app.operate(json!({"op":"send", "space":chat["space"], "stream":chat["stream"], "text":"Superseded history text", "created_at":"2026-10-05T12:00:00Z"})).await.unwrap();
        let id = sent["sent"]["id"].clone();
        app.operate(json!({"op":"message_action", "space":chat["space"], "stream":chat["stream"], "created_at":"2026-10-05T12:01:00Z", "action":{"type":"edit","target":id,"text":"Current history text"}})).await.unwrap();
        let authority = &app.authorities.0[0];
        let request = history::create_request(
            authority,
            app.session.credential().id(),
            1,
            None,
            app.session.signing_key(),
        )
        .unwrap();
        let path = tmp.path().join("history-request.elo");
        write_export(&path, request.bytes()).unwrap();
        let preview = app.operate(json!({"op":"history_preview","space":chat["space"],"stream":chat["stream"],"path":path})).await.unwrap();
        assert_eq!(preview["selection"][0]["text"], "Current history text");
        let output = tmp.path().join("history-grant.elo");
        app.operate(json!({"op":"history_approve", "space":chat["space"],"stream":chat["stream"],"path":path,"expected_request":request.id(),"selection":[id],"output":output})).await.unwrap();
        let cipher = read_exchange(&output, history::MAX_BUNDLE).unwrap();
        let bundle = history::VerifiedBundle::open(
            &cipher,
            app.session.age_identity(),
            app.session.credential().id(),
            &app.authorities.0[0],
            &request,
        )
        .unwrap();
        assert_eq!(bundle.grant().related_actions.len(), 1);
        let records = bundle
            .originals()
            .iter()
            .map(|r| (r.clone(), "ACCEPTED".into()))
            .collect::<Vec<_>>();
        assert_eq!(
            records[0].0.body()["payload"]["text"],
            "Superseded history text"
        );
        assert_eq!(
            Projection::new(&records).body(&records[0].0)["payload"]["text"],
            "Current history text"
        );
        // Exercise the actual encrypted source-index reader after importing into
        // a fresh store, without the original individual action objects.
        let clean_store = ClientStore::open(tmp.path().join("recipient.sqlite"))
            .await
            .unwrap();
        clean_store
            .import_history(bundle, now().unwrap())
            .await
            .unwrap();
        let old_store = std::mem::replace(&mut app.store, clean_store);
        let page = app
            .operate(json!({"op":"history_page", "space":chat["space"],"stream":chat["stream"]}))
            .await
            .unwrap();
        assert_eq!(
            page["history"]["rows"][0]["body"]["payload"]["text"],
            "Current history text"
        );
        old_store.close().await.unwrap();
        app.close().await.unwrap();
    }

    #[test]
    fn expiry_edits_are_author_only_ordered_and_cannot_reopen_an_expired_message() {
        let mut chat = SignedRecord::parse(include_bytes!(
            "../../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap()
        .chat()
        .unwrap();
        chat.payload.expires_at_ms = Some(10_000);
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let original = chat.sign(&key).unwrap();
        let edit = |clock, author, hours| {
            let mut action = chat.clone();
            action.kind = "chat.action".into();
            action.logical_time = clock;
            action.issuer_identity = author;
            action.payload.text.clear();
            action.payload.expires_at_ms = None;
            action.payload.action = Some(MessageAction::Expiry {
                target: original.id(),
                hours,
            });
            (action.sign(&key).unwrap(), "ACCEPTED".into())
        };
        let foreign = edit(900, IdentityId::from_bytes([99; 32]), None);
        assert!(Projection::at(std::slice::from_ref(&foreign), 10_000).is_deleted(&original));
        let extend = edit(1000, chat.issuer_identity, Some(12));
        let shorten = edit(2000, chat.issuer_identity, Some(1));
        let cancel = edit(3000, chat.issuer_identity, None);
        for events in [
            vec![
                extend.clone(),
                shorten.clone(),
                cancel.clone(),
                foreign.clone(),
            ],
            vec![
                cancel.clone(),
                foreign,
                shorten.clone(),
                extend.clone(),
                cancel.clone(),
            ],
        ] {
            let projection = Projection::at(&events, 99_999_999);
            assert!(!projection.is_deleted(&original));
            assert!(projection.body(&original)["payload"]["expires_at_ms"].is_null());
            // A locator must get the same edited deadline as the full message.
            let mut locator = original.body().clone();
            locator["kind"] = json!("chat.locator");
            locator["locator"] = json!({"message_record_id":original.id()});
            let locator = SignedRecord::sign(&serde_json::to_vec(&locator).unwrap(), &key).unwrap();
            assert_eq!(projection.body(&locator)["kind"], "unavailable");
            assert!(projection.body(&locator)["payload"]["expires_at_ms"].is_null());
        }
        let projection = Projection::at(&[shorten.clone(), extend], 3000);
        assert_eq!(
            projection.body(&original)["payload"]["expires_at_ms"],
            3_602_000
        );
        assert_eq!(projection.body(&original)["payload"]["expiry_hours"], 1);
        let too_late = edit(10_000, chat.issuer_identity, None);
        assert!(Projection::at(&[too_late], 10_000).is_deleted(&original));
        let too_late = edit(3_602_000, chat.issuer_identity, None);
        assert!(Projection::at(&[shorten, too_late], 3_602_000).is_deleted(&original));
        assert!(
            Projection::at(&[cancel, deletion(&original, chat.issuer_identity)], 4000)
                .is_deleted(&original)
        );
    }

    #[tokio::test]
    async fn editing_expiry_persists_cancellation_and_rejects_invalid_choices() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("profile");
        let mut app = super::super::performance::profile(path.clone()).await;
        let chat = app.view().await.unwrap()["streams"][0].clone();
        let mut request = json!({"op":"send", "space":chat["space"], "stream":chat["stream"],
            "text":"Keep after cancelling expiry", "created_at":"2026-10-01T12:00:00Z", "expires_in_hours":1});
        let sent = app.operate(request.clone()).await.unwrap();
        let id = sent["sent"]["id"].clone();
        request["op"] = json!("message_action");
        request["action"] = json!({"type":"expiry", "target":id, "hours":2});
        assert_eq!(
            app.operate(request.clone()).await.unwrap_err().to_string(),
            "message_expiry_invalid"
        );
        for choice in [json!(12), json!(24), Value::Null] {
            request["action"]["hours"] = choice.clone();
            let response = app.operate(request.clone()).await.unwrap();
            let rows = response["view"]["streams"][0]["rows"].as_array().unwrap();
            let row = rows.iter().find(|row| row["id"] == id).unwrap();
            assert_eq!(row["body"]["payload"]["expiry_hours"], choice);
            if choice.is_null() {
                assert!(row["body"]["payload"]["expires_at_ms"].is_null());
            } else {
                assert!(
                    row["body"]["payload"]["expires_at_ms"].as_u64().unwrap()
                        > sent["sent"]["expires_at_ms"].as_u64().unwrap()
                );
            }
        }
        let originals = app.originals(&app.authorities.0[0]).await.unwrap();
        let original = originals
            .iter()
            .find(|(record, _)| json!(record.id()) == id)
            .unwrap();
        assert!(
            original.0.body()["payload"]["expires_at_ms"].is_number(),
            "Never rewrite the signed original"
        );
        app.close().await.unwrap();
        let mut app = ClientApp::open(path, "synthetic performance password".into(), false)
            .await
            .unwrap();
        let page = app
            .operate(json!({"op":"history_page", "space":chat["space"], "stream":chat["stream"]}))
            .await
            .unwrap();
        let rows = page["history"]["rows"].as_array().unwrap();
        let row = rows.iter().find(|row| row["id"] == id).unwrap();
        assert_eq!(
            row["body"]["payload"]["text"],
            "Keep after cancelling expiry"
        );
        assert!(row["body"]["payload"]["expires_at_ms"].is_null());
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn replies_sign_independent_deadlines_and_survive_parent_changes_after_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("profile");
        let mut app = super::super::performance::profile(path.clone()).await;
        let chat = app.view().await.unwrap()["streams"][0].clone();
        let request = json!({"op":"send", "space":chat["space"], "stream":chat["stream"],
            "text":"Thread root", "created_at":"2026-10-02T12:00:00Z", "expires_in_hours":1});
        let root = app.operate(request.clone()).await.unwrap()["sent"].clone();
        let mut reply_request = request.clone();
        reply_request["reply_to"] = root["id"].clone();
        reply_request["text"] = json!("Independent reply");
        reply_request["expires_in_hours"] = json!(24);
        let reply = app.operate(reply_request.clone()).await.unwrap()["sent"].clone();
        assert!(reply["expires_at_ms"].as_u64().unwrap() > root["expires_at_ms"].as_u64().unwrap());
        let signed_reply = app
            .message_record(
                &app.authorities.0[0],
                reply["id"].as_str().unwrap().parse().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            signed_reply.body()["payload"]["expires_at_ms"],
            reply["expires_at_ms"]
        );
        let reply_bytes = signed_reply.bytes().to_vec();
        reply_request
            .as_object_mut()
            .unwrap()
            .remove("expires_in_hours");
        let permanent = app.operate(reply_request.clone()).await.unwrap()["sent"].clone();
        assert!(permanent["expires_at_ms"].is_null());
        let mut edit = json!({"op":"message_action", "space":chat["space"], "stream":chat["stream"],
            "created_at":"2026-10-02T12:00:00Z", "action":{"type":"expiry", "target":root["id"], "hours":12}});
        for hours in [json!(12), Value::Null] {
            edit["action"]["hours"] = hours;
            let changed = app.operate(edit.clone()).await.unwrap();
            let rows = changed["view"]["streams"][0]["rows"].as_array().unwrap();
            let reply_row = rows.iter().find(|r| r["id"] == reply["id"]).unwrap();
            assert_eq!(
                reply_row["body"]["payload"]["expires_at_ms"],
                reply["expires_at_ms"]
            );
            assert!(rows.iter().find(|r| r["id"] == permanent["id"]).unwrap()["body"]["payload"]["expires_at_ms"].is_null());
        }
        edit["action"]["target"] = reply["id"].clone();
        edit["action"]["hours"] = json!(12);
        let changed = app.operate(edit).await.unwrap();
        let reply_deadline = changed["view"]["streams"][0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == reply["id"])
            .unwrap()["body"]["payload"]["expires_at_ms"]
            .clone();
        assert!(reply_deadline.as_u64().unwrap() < reply["expires_at_ms"].as_u64().unwrap());
        reply_request["reply_to"] = reply["id"].clone();
        let nested = app.operate(reply_request).await.unwrap()["sent"].clone();
        let nested_record = app
            .message_record(
                &app.authorities.0[0],
                nested["id"].as_str().unwrap().parse().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nested_record.body()["payload"]["thread_root"], root["id"]);
        app.close().await.unwrap();
        let mut app = ClientApp::open(path, "synthetic performance password".into(), false)
            .await
            .unwrap();
        let page = app.operate(json!({"op":"history_page", "space":chat["space"], "stream":chat["stream"], "thread":root["id"]})).await.unwrap();
        let rows = page["history"]["rows"].as_array().unwrap();
        let reply_row = rows.iter().find(|r| r["id"] == reply["id"]).unwrap();
        assert_eq!(reply_row["body"]["payload"]["text"], "Independent reply");
        assert_eq!(
            reply_row["body"]["payload"]["expires_at_ms"],
            reply_deadline
        );
        assert!(rows.iter().find(|r| r["id"] == permanent["id"]).unwrap()["body"]["payload"]["expires_at_ms"].is_null());
        assert_eq!(
            app.message_record(
                &app.authorities.0[0],
                reply["id"].as_str().unwrap().parse().unwrap()
            )
            .await
            .unwrap()
            .bytes(),
            reply_bytes
        );
        // Store an already expired, correctly signed parent without waiting.
        let mut expired = super::super::performance::message(&app, 0, 1)
            .chat()
            .unwrap();
        expired.payload.expires_at_ms = Some(1);
        let signed = app.authorities.0[0]
            .prepare_chat(expired, app.session.signing_key())
            .unwrap();
        app.store
            .commit_local_record_with_outbox(
                PreparedLocalRecord::new(
                    signed.id(),
                    crypto::seal_chat(&signed, &[app.session.credential().clone()]).unwrap(),
                    RecordMetadata::new(
                        "chat.message",
                        Some(app.authorities.0[0].space()),
                        Some(app.authorities.0[0].stream()),
                        app.authorities.0[0].head_id(),
                    )
                    .unwrap(),
                    vec![],
                    now().unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let mut after_expiry = request;
        after_expiry["reply_to"] = json!(signed.id());
        after_expiry["text"] = json!("Reply outlives its parent");
        after_expiry
            .as_object_mut()
            .unwrap()
            .remove("expires_in_hours");
        let sent = app.operate(after_expiry).await.unwrap()["sent"].clone();
        assert!(sent["expires_at_ms"].is_null());
        let page = app.operate(json!({"op":"history_page", "space":chat["space"], "stream":chat["stream"], "thread":signed.id()})).await.unwrap();
        let rows = page["history"]["rows"].as_array().unwrap();
        assert_eq!(
            rows.iter().find(|r| r["id"] == json!(signed.id())).unwrap()["body"]["kind"],
            "deleted"
        );
        assert_eq!(
            rows.iter().find(|r| r["id"] == sent["id"]).unwrap()["body"]["payload"]["text"],
            "Reply outlives its parent"
        );
        app.close().await.unwrap();
    }

    #[test]
    fn expiry_hides_content_on_every_reader_without_an_online_sender() {
        let original = SignedRecord::parse(include_bytes!(
            "../../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap();
        let mut chat = original.chat().unwrap();
        chat.payload.expires_at_ms = Some(10_000);
        let signed = chat
            .sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]))
            .unwrap();
        assert!(!Projection::at(&[], 9_999).is_deleted(&signed));
        for current in [10_000, 100_000] {
            let projection = Projection::at(&[], current);
            assert!(projection.is_deleted(&signed));
            let body = projection.body(&signed);
            assert_eq!(body["kind"], "deleted");
            assert_eq!(body["expired"], true);
            assert!(body["payload"]["text"].is_null());
            assert!(body["access"].is_null());
            assert_eq!(body["issuer_identity"], original.body()["issuer_identity"]);
        }
        assert!(!Projection::at(&[], 100_000).is_deleted(&original));
        let mut locator = signed.body().clone();
        locator["kind"] = json!("chat.locator");
        locator["payload"]["text"] = json!("");
        locator["locator"] = json!({"message_record_id":signed.id()});
        let locator = SignedRecord::sign(
            &serde_json::to_vec(&locator).unwrap(),
            &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap();
        assert_eq!(
            Projection::at(&[], 9_999).body(&locator)["payload"]["expires_at_ms"],
            10_000
        );
        let expired = Projection::at(&[], 10_000).body(&locator);
        assert_eq!(expired["expired"], true);
        assert!(expired["locator"].is_null());
        assert_eq!(expired["deleted_record_id"], json!(signed.id()));
    }

    #[test]
    fn author_deletion_is_irreversible_and_projects_text_files_and_locators_without_content() {
        let original = SignedRecord::parse(include_bytes!(
            "../../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap();
        let author: IdentityId = original.body()["issuer_identity"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let other = IdentityId::from_bytes([99; 32]);
        let foreign = deletion(&original, other);
        assert!(!Projection::new(std::slice::from_ref(&foreign)).is_deleted(&original));
        let own = deletion(&original, author);
        // A deletion can arrive before the original and cannot be undone by a replay.
        for events in [
            vec![foreign.clone(), own.clone()],
            vec![own.clone(), foreign, own.clone()],
        ] {
            let projected = Projection::new(&events);
            assert!(projected.is_deleted(&original));
            let body = projected.body(&original);
            assert_eq!(body["kind"], "deleted");
            assert!(body["payload"]["text"].is_null());
            let mut locator = original.body().clone();
            locator["kind"] = json!("chat.locator");
            locator["locator"] =
                json!({"message_record_id":original.id(),"body_object_id":"secret locator"});
            let locator = SignedRecord::sign(
                &serde_json::to_vec(&locator).unwrap(),
                &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
            )
            .unwrap();
            assert!(projected.is_deleted(&locator));
            assert_eq!(
                projected.body(&locator)["deleted_record_id"],
                json!(original.id())
            );
            assert!(projected.body(&locator)["locator"].is_null());
        }
        let mut file = original.body().clone();
        file["kind"] = json!("file.shared");
        file["filename"] = json!("private.pdf");
        file["attachment"] = json!({"key":"private-key", "created_at_ms":1000});
        let file = SignedRecord::sign(
            &serde_json::to_vec(&file).unwrap(),
            &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap();
        let projected = Projection::new(&[deletion(&file, author)]);
        let body = projected.body(&file);
        assert_eq!(body["kind"], "deleted");
        assert!(body["filename"].is_null());
        assert!(body["attachment"].is_null());
    }
    #[tokio::test]
    async fn deletion_survives_restart_and_removes_search_unread_and_pin_content() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("profile");
        let mut app = super::super::performance::profile(path.clone()).await;
        let view = app.view().await.unwrap();
        let chat = &view["streams"][0];
        let scope = json!({"space":chat["space"], "stream":chat["stream"]});
        let mut send = scope.clone();
        send["op"] = json!("send");
        send["text"] = json!("Unique private deletion fixture");
        send["created_at"] = json!("2026-09-21T12:00:00Z");
        app.operate(send).await.unwrap();
        let id = app.view().await.unwrap()["streams"][0]["rows"][0]["id"].clone();
        let mut action = scope.clone();
        action["op"] = json!("message_action");
        action["created_at"] = json!("2026-09-21T12:01:00Z");
        action["action"] = json!({"type":"pin","target":id,"active":true});
        app.operate(action.clone()).await.unwrap();
        let mut unread = scope.clone();
        unread["op"] = json!("mark_unread");
        unread["records"] = json!([id]);
        app.operate(unread).await.unwrap();
        action["action"] = json!({"type":"delete","target":id});
        app.operate(action.clone()).await.unwrap();
        app.operate(action).await.unwrap();
        let mut page = scope;
        page["op"] = json!("history_page");
        let assert_deleted = |view: &Value| {
            let row = &view["streams"][0]["rows"][0];
            assert_eq!(row["id"], id);
            assert_eq!(row["body"]["kind"], "deleted");
            assert_eq!(row["unread"], false);
            assert_eq!(row["pinned"], false);
            assert!(!view.to_string().contains("Unique private deletion fixture"));
        };
        assert_deleted(&app.view().await.unwrap());
        assert_eq!(
            app.operate(page.clone()).await.unwrap()["history"]["rows"][0]["body"]["kind"],
            "deleted"
        );
        page["query"] = json!("Unique private deletion fixture");
        assert!(
            app.operate(page.clone()).await.unwrap()["history"]["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        app.close().await.unwrap();
        let mut app = ClientApp::open(path, "synthetic performance password".into(), false)
            .await
            .unwrap();
        assert_deleted(&app.view().await.unwrap());
        assert!(
            app.operate(page).await.unwrap()["history"]["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        app.close().await.unwrap();
    }
    #[test]
    fn delayed_replays_and_equal_clocks_converge_by_identity_and_record_id() {
        let own = IdentityId::from_bytes([1; 32]);
        let target = RecordId::from_bytes([8; 32]);
        let a = event(1, 1, true, false, 1);
        let b = event(1, 3, false, false, 2);
        let c = event(2, 2, true, false, 3);
        let pin = event(1, 4, true, true, 4);
        let unpin = event(2, 5, false, true, 5);
        let ordered = vec![a.clone(), b.clone(), c.clone(), pin.clone(), unpin.clone()];
        let delayed = vec![unpin, pin, c, b, a.clone(), a];
        let left = Projection::new(&ordered);
        let right = Projection::new(&delayed);
        assert_eq!(left.reactions(target, own), right.reactions(target, own));
        assert_eq!(left.reactions(target, own)[0]["count"], 1);
        assert_eq!(left.reactions(target, own)[0]["mine"], false);
        assert!(!left.is_pinned(target));
        assert!(!right.is_pinned(target));
        let x = event(1, 8, true, true, 8);
        let y = event(2, 8, false, true, 9);
        assert_eq!(
            Projection::new(&[x.clone(), y.clone()]).is_pinned(target),
            Projection::new(&[y, x]).is_pinned(target)
        );
    }
}

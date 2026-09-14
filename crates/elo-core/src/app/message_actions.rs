//! Chat-wide actions use the existing signed/encrypted transport. Personal read
//! markers and reminders share the encrypted, backup-covered read-state file.
use super::*;
use crate::record::MessageAction;
use std::collections::BTreeSet;

type Version = (u64, RecordId);
#[derive(Default)]
pub(super) struct Projection {
    reactions: BTreeMap<(RecordId, String, IdentityId), (Version, bool)>,
    pins: BTreeMap<RecordId, (Version, bool)>,
}
impl Projection {
    /// Call only with records whose signatures and historical authority passed.
    pub(super) fn new(records: &[(SignedRecord, String)]) -> Self {
        let mut state = Self::default();
        for (record, _) in records {
            if record.body()["kind"] != "chat.action" {
                continue;
            }
            let Ok(chat) = record.chat() else { continue };
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
                None => {}
            }
        }
        state
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
        self.message_record(authority, action.target()).await?;
        let time = now()?;
        let highest = originals
            .iter()
            .filter_map(|(r, _)| r.body()["logical_time"].as_u64())
            .max()
            .unwrap_or(0);
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
                logical_time: highest
                    .checked_add(1)
                    .ok_or("logical time overflow")?
                    .max(u64::try_from(time.as_millis())?),
                created_at: field(v, "created_at")?.into(),
                parents: vec![],
                payload: TextPayload {
                    text: String::new(),
                    sender_name: None,
                    thread_root: None,
                    action: Some(action),
                },
            },
            self.session.signing_key(),
        )?;
        let recipients = signed
            .chat()?
            .recipient_credentials
            .iter()
            .map(|id| authority.credential(*id).cloned())
            .collect::<record::Result<Vec<_>>>()?;
        let cipher = crypto::seal_chat(&signed, &recipients)?;
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
            self.message_record(&self.authorities.0[index], record)
                .await?;
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

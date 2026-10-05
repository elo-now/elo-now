//! Private, account-owned state carried by the approved Notes conversation.
//! Replica storage sees ciphertext; other chat members receive no read receipts.
use super::*;

const KIND: &str = "chat.private-settings";
const MAX_BATCH: usize = 32;
const CHECKPOINT_INTERVAL_MS: u64 = 6 * 60 * 60 * 1000;

mod encoding;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Field {
    Unread,
    Follow,
    Participation,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    clock: u64,
    device: RecordId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    field: Field,
    space: SpaceId,
    stream: StreamId,
    record: RecordId,
    stamp: Stamp,
    active: bool,
}

impl Entry {
    fn key(&self) -> String {
        let field = match self.field {
            Field::Unread => "unread",
            Field::Follow => "follow",
            Field::Participation => "participation",
        };
        format!("{field}:{}:{}:{}", self.space, self.stream, self.record)
    }

    fn newer_than(&self, previous: &Self) -> bool {
        // Equal clocks from concurrent devices are ordered consistently. The
        // final boolean also makes a copied device's conflicting writes converge.
        (&self.stamp, self.active) > (&previous.stamp, previous.active)
    }
}

#[derive(Clone)]
pub(super) struct State {
    v: u8,
    clock: u64,
    values: BTreeMap<String, Entry>,
    pending: BTreeSet<String>,
    checkpoint: BTreeSet<String>,
    baseline_initialized: bool,
    cursor: i64,
    last_checkpoint_ms: u64,
    checkpoint_head: Option<RecordId>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            v: 1,
            clock: 0,
            values: BTreeMap::new(),
            pending: BTreeSet::new(),
            checkpoint: BTreeSet::new(),
            baseline_initialized: false,
            cursor: 0,
            last_checkpoint_ms: 0,
            checkpoint_head: None,
        }
    }
}

impl State {
    pub(super) fn cursor(&self) -> i64 {
        self.cursor
    }

    #[cfg(test)]
    pub(super) fn reset_cursor_for_test(&mut self) {
        self.cursor = 0;
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.v != 1
            || self.clock > record::MAX_INTEGER
            || self.cursor < 0
            || self
                .values
                .iter()
                .any(|(key, value)| key != &value.key() || value.stamp.clock > self.clock)
            || self
                .pending
                .iter()
                .chain(&self.checkpoint)
                .any(|key| !self.values.contains_key(key))
        {
            return Err("invalid private settings".into());
        }
        Ok(())
    }

    fn batch_keys(&self) -> Vec<String> {
        // Interactive changes never wait behind a potentially large checkpoint.
        self.pending
            .iter()
            .chain(
                self.checkpoint
                    .iter()
                    .filter(|key| !self.pending.contains(*key)),
            )
            .take(MAX_BATCH)
            .cloned()
            .collect()
    }

    fn local(
        &mut self,
        field: Field,
        space: SpaceId,
        stream: StreamId,
        record: RecordId,
        active: bool,
        stamp: Stamp,
    ) -> Result<Option<Entry>> {
        let mut entry = Entry {
            field,
            space,
            stream,
            record,
            stamp,
            active,
        };
        let key = entry.key();
        if self
            .values
            .get(&key)
            .is_some_and(|previous| previous.active == active)
        {
            return Ok(None);
        }
        self.clock = record::next_message_time(self.clock, entry.stamp.clock);
        entry.stamp.clock = self.clock;
        self.values.insert(key.clone(), entry.clone());
        self.pending.insert(key);
        Ok(Some(entry))
    }

    fn merge(&mut self, entry: Entry) -> bool {
        self.clock = self.clock.max(entry.stamp.clock);
        let key = entry.key();
        if self
            .values
            .get(&key)
            .is_some_and(|old| !entry.newer_than(old))
        {
            return false;
        }
        self.values.insert(key, entry);
        true
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    v: u8,
    identity: IdentityId,
    hosting_space: SpaceId,
    hosting_stream: StreamId,
    entries: Vec<Entry>,
}

fn apply_read(read: &mut ReadState, entry: &Entry) {
    if entry.field != Field::Unread {
        return;
    }
    let stream = entry.stream.to_string();
    let id = entry.record.to_string();
    let (insert, remove) = if entry.active {
        (&mut read.unread, &mut read.seen)
    } else {
        (&mut read.seen, &mut read.unread)
    };
    let ids = insert.entry(stream.clone()).or_default();
    if let Err(position) = ids.binary_search(&id) {
        ids.insert(position, id.clone());
    }
    if let Some(ids) = remove.get_mut(&stream) {
        ids.retain(|value| value != &id);
    }
}

impl ClientApp {
    fn bootstrap_private_settings(&self, read: &mut ReadState) -> Result<bool> {
        if read
            .private_settings
            .as_ref()
            .is_some_and(|state| state.baseline_initialized)
        {
            return Ok(false);
        }
        let state = read.private_settings.get_or_insert_with(State::default);
        // Historical local markers have no trustworthy action time. Give them
        // baseline clocks below every new action; explicit historical unread
        // beats historical seen, but can never replace a fresh remote action.
        for (active, streams) in [(false, &read.seen), (true, &read.unread)] {
            for (stream, records) in streams {
                let stream: StreamId = stream.parse()?;
                let Some(pin) = self.pins.iter().find(|pin| pin.stream == stream) else {
                    continue;
                };
                for record in records {
                    let entry = Entry {
                        field: Field::Unread,
                        space: pin.space,
                        stream,
                        record: record.parse()?,
                        stamp: Stamp {
                            clock: u64::from(active),
                            device: self.session.credential().id(),
                        },
                        active,
                    };
                    let key = entry.key();
                    if state
                        .values
                        .get(&key)
                        .is_none_or(|old| entry.newer_than(old))
                    {
                        state.clock = state.clock.max(entry.stamp.clock);
                        state.values.insert(key.clone(), entry);
                        state.checkpoint.insert(key);
                    }
                }
            }
        }
        state.baseline_initialized = true;
        state.validate()?;
        Ok(true)
    }

    pub(super) fn set_private_read_markers(
        &mut self,
        space: SpaceId,
        stream: StreamId,
        records: Vec<RecordId>,
        unread: bool,
    ) -> Result<()> {
        let mut read = (*self.read).clone();
        self.bootstrap_private_settings(&mut read)?;
        let time = now()?.as_millis() as u64;
        for record in records {
            let changed = read
                .private_settings
                .get_or_insert_with(State::default)
                .local(
                    Field::Unread,
                    space,
                    stream,
                    record,
                    unread,
                    Stamp {
                        clock: time,
                        device: self.session.credential().id(),
                    },
                )?;
            if let Some(entry) = changed {
                apply_read(&mut read, &entry);
            }
        }
        self.write_read_state(&read)?;
        self.read = read.into();
        Ok(())
    }

    pub(super) async fn set_private_thread_follow(&mut self, request: &Value) -> Result<()> {
        let index = self.authority_index(request)?;
        let authority = &self.authorities.0[index];
        let record = self
            .message_record(authority, field(request, "message")?.parse()?)
            .await?;
        let root = record.body()["payload"]["thread_root"]
            .as_str()
            .map(str::parse)
            .transpose()?
            .unwrap_or(record.id());
        let active = request["followed"]
            .as_bool()
            .ok_or("invalid thread follow state")?;
        self.set_private_thread_value(
            Field::Follow,
            authority.space(),
            authority.stream(),
            root,
            active,
        )
    }

    fn set_private_thread_value(
        &mut self,
        field: Field,
        space: SpaceId,
        stream: StreamId,
        root: RecordId,
        active: bool,
    ) -> Result<()> {
        let mut read = (*self.read).clone();
        let initialized = self.bootstrap_private_settings(&mut read)?;
        let changed = read
            .private_settings
            .get_or_insert_with(State::default)
            .local(
                field,
                space,
                stream,
                root,
                active,
                Stamp {
                    clock: now()?.as_millis() as u64,
                    device: self.session.credential().id(),
                },
            )?;
        if changed.is_some() || initialized {
            self.write_read_state(&read)?;
            self.read = read.into();
        }
        Ok(())
    }

    pub(super) fn note_private_participation(
        &mut self,
        space: SpaceId,
        stream: StreamId,
        root: RecordId,
    ) -> Result<()> {
        self.set_private_thread_value(Field::Participation, space, stream, root, true)
    }

    pub(super) fn private_thread_follows(&self, stream: StreamId, followed: bool) -> Vec<RecordId> {
        self.private_thread_values(stream, Field::Follow, followed)
    }

    pub(super) fn private_thread_participation(&self, stream: StreamId) -> Vec<RecordId> {
        self.private_thread_values(stream, Field::Participation, true)
    }

    fn private_thread_values(&self, stream: StreamId, field: Field, active: bool) -> Vec<RecordId> {
        self.read
            .private_settings
            .as_ref()
            .map(|state| {
                state
                    .values
                    .values()
                    .filter(|entry| {
                        entry.stream == stream && entry.field == field && entry.active == active
                    })
                    .map(|entry| entry.record)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Only the existing, approved one-identity Notes authority may carry data.
    /// An offline save never waits for this network path or implies delivery.
    pub(super) async fn prepare_private_settings_sync(&mut self) -> Result<bool> {
        if self.call_host.is_none() {
            return Ok(false);
        }
        let general = self.notes_general()?;
        let own = general
            .head()?
            .members
            .iter()
            .find(|member| member.identity_id == self.identity_id())
            .ok_or("This profile is no longer in the Space.")?;
        // No private traffic or empty Notes creation for a single-device account.
        if own.credential_ids.len() < 2 {
            return Ok(false);
        }
        if self
            .private_settings_retry
            .is_some_and(|retry| retry.elapsed() < std::time::Duration::from_secs(10))
        {
            return Ok(false);
        }
        self.private_settings_retry = Some(std::time::Instant::now());
        let current_notes = self
            .authorities
            .0
            .iter()
            .find(|authority| self.is_notes_authority(authority));
        if current_notes.is_none_or(|notes| {
            !notes.call_proof().is_ok_and(|proof| {
                crate::notes::verify(&proof, &general, self.identity_id()).is_ok()
            }) || notes
                .head()
                .is_ok_and(|head| head.members[0].credential_ids != own.credential_ids)
        }) {
            self.sync_notes(None, true).await?;
        }
        let notes = self
            .authorities
            .0
            .iter()
            .find(|authority| self.is_notes_authority(authority))
            .ok_or("Private settings transport is unavailable.")?
            .clone();
        crate::notes::verify(&notes.call_proof()?, &general, self.identity_id())?;
        let mut read = (*self.read).clone();
        let mut prepared_state_changed = self.bootstrap_private_settings(&mut read)?;
        let state = read.private_settings.get_or_insert_with(State::default);
        let time = now()?;
        let millis = time.as_millis() as u64;
        // Re-advertise current private values after retention or device changes.
        // Checkpoints merge, never replace state, so a late snapshot cannot undo
        // a newer offline action. Recipients remain the current approved devices.
        if state.checkpoint_head != notes.head_id()
            || millis.saturating_sub(state.last_checkpoint_ms) >= CHECKPOINT_INTERVAL_MS
        {
            state.checkpoint.extend(state.values.keys().cloned());
            prepared_state_changed = true;
            state.last_checkpoint_ms = millis;
            state.checkpoint_head = notes.head_id();
        }
        let keys = state.batch_keys();
        if keys.is_empty() {
            if prepared_state_changed {
                self.write_read_state(&read)?;
                self.read = read.into();
            }
            self.private_settings_retry = None;
            return Ok(false);
        }
        self.require_fresh_membership(&notes).await?;
        let batch = Batch {
            v: 1,
            identity: self.identity_id(),
            hosting_space: general.space(),
            hosting_stream: general.stream(),
            entries: keys.iter().map(|key| state.values[key].clone()).collect(),
        };
        let payload = serde_json::to_string(&batch)?;
        let signed = notes.prepare_chat(
            ChatMessage {
                v: 1,
                kind: KIND.into(),
                nonce: record::random_hex::<16>()?,
                space_id: notes.space(),
                stream_id: notes.stream(),
                issuer_identity: self.identity_id(),
                issuer_credential: self.session.credential().id(),
                config_id: notes.head_id().ok_or("head")?,
                audience: vec![],
                recipient_credentials: vec![],
                logical_time: millis,
                created_at: chrono::DateTime::from_timestamp_millis(millis as i64)
                    .ok_or("invalid settings time")?
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                parents: vec![],
                payload: TextPayload {
                    text: payload,
                    mentions: vec![],
                    expires_at_ms: None,
                    sender_name: None,
                    thread_root: None,
                    action: None,
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
            .map(|id| notes.credential(*id).cloned())
            .collect::<record::Result<Vec<_>>>()?;
        let cipher = crypto::seal_chat(&signed, &recipients)?;
        let cipher = crate::erasure::wrap_subjects(
            cipher,
            self.session.credential(),
            self.session.signing_key(),
            vec![],
        )?;
        self.store
            .commit_local_record_with_outbox(PreparedLocalRecord::new(
                signed.id(),
                cipher,
                RecordMetadata::new(
                    KIND,
                    Some(notes.space()),
                    Some(notes.stream()),
                    notes.head_id(),
                )?,
                self.targets(),
                time,
            )?)
            .await?;
        // A crash before this write may repeat equivalent values, never lose them.
        for key in keys {
            state.pending.remove(&key);
            state.checkpoint.remove(&key);
        }
        self.write_read_state(&read)?;
        self.read = read.into();
        self.private_settings_retry = None;
        Ok(true)
    }

    pub(super) async fn receive_private_settings(&mut self) -> Result<bool> {
        let cursor = self
            .read
            .private_settings
            .as_ref()
            .map_or(0, |state| state.cursor);
        let incoming = self.store.private_settings_sources(cursor).await?;
        if incoming.is_empty() {
            return Ok(false);
        }
        let mut read = (*self.read).clone();
        self.bootstrap_private_settings(&mut read)?;
        let mut changed = false;
        for (sequence, source) in incoming {
            let applied = self.open_private_settings(&source).await;
            if matches!(applied, Ok(None)) {
                // Authority discovery, configuration proof or the encrypted
                // object may arrive later. Keep this position pending.
                break;
            }
            if let Ok(Some(batch)) = applied {
                for entry in batch.entries {
                    let state = read.private_settings.get_or_insert_with(State::default);
                    if state.merge(entry.clone()) {
                        apply_read(&mut read, &entry);
                        changed = true;
                    }
                }
            }
            // Unknown schemas and invalid records stay in encrypted history for
            // diagnosis; they cannot replace known preferences or hold up peers.
            read.private_settings
                .get_or_insert_with(State::default)
                .cursor = sequence;
        }
        self.write_read_state(&read)?;
        self.read = read.into();
        Ok(changed)
    }

    #[cfg(test)]
    pub(super) async fn verify_private_settings_source(
        &self,
        source: &crate::store::DisplaySource,
    ) -> Result<()> {
        self.open_private_settings(source)
            .await?
            .map(|_| ())
            .ok_or_else(|| "Private settings evidence is not available yet.".into())
    }

    async fn open_private_settings(
        &self,
        source: &crate::store::DisplaySource,
    ) -> Result<Option<Batch>> {
        let Ok(general) = self.notes_general() else {
            return Ok(None);
        };
        let Some(notes) = self
            .authorities
            .0
            .iter()
            .find(|authority| self.is_notes_authority(authority))
        else {
            return Ok(None);
        };
        if !notes
            .call_proof()
            .is_ok_and(|proof| crate::notes::verify(&proof, &general, self.identity_id()).is_ok())
        {
            return Ok(None);
        }
        let Ok(Some(cipher)) = self.store.get_object(source.object).await else {
            return Ok(None);
        };
        let record = crypto::open_object(&cipher, self.session.age_identity())?;
        if record.id() != source.record {
            return Err("invalid private settings source".into());
        }
        let envelope = record.chat()?;
        if envelope.space_id != notes.space()
            || envelope.stream_id != notes.stream()
            || envelope.issuer_identity != self.identity_id()
            || envelope.kind != KIND
        {
            return Err("invalid private settings namespace".into());
        }
        if notes.config(envelope.config_id).is_err() {
            return Ok(None);
        }
        let chat = notes.verify_historical(&record)?;
        if chat.kind != KIND
            || chat.issuer_identity != self.identity_id()
            || !notes.head()?.members[0]
                .credential_ids
                .contains(&chat.issuer_credential)
            || !chat
                .recipient_credentials
                .contains(&self.session.credential().id())
        {
            return Err("invalid private settings authority".into());
        }
        let batch: Batch = serde_json::from_str(&chat.payload.text)?;
        if batch.v != 1
            || batch.identity != self.identity_id()
            || batch.hosting_space != general.space()
            || batch.hosting_stream != general.stream()
            || batch.entries.is_empty()
            || batch.entries.len() > MAX_BATCH
            || batch.entries.iter().any(|entry| {
                !record::current_message_time_is_valid(entry.stamp.clock)
                    || notes.credential(entry.stamp.device).is_err()
            })
        {
            return Err("invalid private settings batch".into());
        }
        Ok(Some(batch))
    }
}

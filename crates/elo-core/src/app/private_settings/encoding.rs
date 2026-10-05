//! Compact encrypted-profile representation. The signed network batch is unchanged.
use super::*;
use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};

const ENTRY_BYTES: usize = 47;
const MAX_DICTIONARY: usize = u16::MAX as usize + 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Compact {
    v: u8,
    data: String,
}

// Accept the first local representation when opening an in-progress profile.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    v: u8,
    clock: u64,
    values: BTreeMap<String, Entry>,
    pending: BTreeSet<String>,
    #[serde(default)]
    checkpoint: BTreeSet<String>,
    #[serde(default)]
    baseline_initialized: bool,
    cursor: i64,
    last_checkpoint_ms: u64,
    #[serde(default)]
    checkpoint_head: Option<RecordId>,
}

impl Serialize for State {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let bytes = self.encode_compact().map_err(S::Error::custom)?;
        Compact {
            v: 2,
            data: STANDARD.encode(bytes),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for State {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Compact(Compact),
            Legacy(Legacy),
        }
        let state = match Wire::deserialize(deserializer)? {
            Wire::Compact(value) => {
                if value.v != 2 || value.data.len() > MAX_READ_STATE {
                    return Err(D::Error::custom("invalid private settings encoding"));
                }
                let bytes = STANDARD.decode(value.data).map_err(D::Error::custom)?;
                State::decode_compact(&bytes).map_err(D::Error::custom)?
            }
            Wire::Legacy(old) => {
                let mut state = State {
                    v: old.v,
                    clock: old.clock,
                    values: BTreeMap::new(),
                    pending: BTreeSet::new(),
                    checkpoint: BTreeSet::new(),
                    baseline_initialized: old.baseline_initialized,
                    cursor: old.cursor,
                    last_checkpoint_ms: old.last_checkpoint_ms,
                    checkpoint_head: old.checkpoint_head,
                };
                for (key, entry) in old.values {
                    let canonical = entry.key();
                    let original = format!(
                        "{:?}:{}:{}:{}",
                        entry.field, entry.space, entry.stream, entry.record
                    );
                    if key != canonical && key != original {
                        return Err(D::Error::custom("invalid private settings key"));
                    }
                    if old.pending.contains(&key) {
                        state.pending.insert(canonical.clone());
                    }
                    if old.checkpoint.contains(&key) {
                        state.checkpoint.insert(canonical.clone());
                    }
                    if state.values.insert(canonical, entry).is_some() {
                        return Err(D::Error::custom("duplicate private settings key"));
                    }
                }
                if state.pending.len() != old.pending.len()
                    || state.checkpoint.len() != old.checkpoint.len()
                {
                    return Err(D::Error::custom("invalid private settings queue"));
                }
                state
            }
        };
        state.validate().map_err(D::Error::custom)?;
        Ok(state)
    }
}

impl State {
    fn encode_compact(&self) -> Result<Vec<u8>> {
        let spaces = dictionary(self.values.values().map(|entry| entry.space))?;
        let streams = dictionary(self.values.values().map(|entry| entry.stream))?;
        let devices = dictionary(self.values.values().map(|entry| entry.stamp.device))?;
        let capacity = (43usize
            + if self.checkpoint_head.is_some() {
                32
            } else {
                0
            })
        .checked_add(spaces.len() * 32 + streams.len() * 16 + devices.len() * 32)
        .and_then(|size| {
            self.values
                .len()
                .checked_mul(ENTRY_BYTES)
                .and_then(|entries| size.checked_add(entries))
        })
        .ok_or("private settings are too large")?;
        if capacity > MAX_READ_STATE / 4 * 3 {
            return Err("private settings are too large".into());
        }
        let mut bytes = Vec::with_capacity(capacity);
        bytes.push(1); // Binary layout, independently versioned from the JSON envelope.
        bytes.extend_from_slice(&self.clock.to_le_bytes());
        bytes.extend_from_slice(&self.cursor.to_le_bytes());
        bytes.extend_from_slice(&self.last_checkpoint_ms.to_le_bytes());
        bytes.push(u8::from(self.baseline_initialized));
        bytes.push(u8::from(self.checkpoint_head.is_some()));
        if let Some(head) = self.checkpoint_head {
            bytes.extend_from_slice(head.as_bytes());
        }
        bytes.extend_from_slice(&(spaces.len() as u32).to_le_bytes());
        for id in spaces.keys() {
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes.extend_from_slice(&(streams.len() as u32).to_le_bytes());
        for id in streams.keys() {
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes.extend_from_slice(&(devices.len() as u32).to_le_bytes());
        for id in devices.keys() {
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes.extend_from_slice(&(self.values.len() as u32).to_le_bytes());
        for (key, entry) in &self.values {
            bytes.extend_from_slice(entry.record.as_bytes());
            bytes.extend_from_slice(&entry.stamp.clock.to_le_bytes());
            bytes.extend_from_slice(&spaces[&entry.space].to_le_bytes());
            bytes.extend_from_slice(&streams[&entry.stream].to_le_bytes());
            bytes.extend_from_slice(&devices[&entry.stamp.device].to_le_bytes());
            let field = match entry.field {
                Field::Unread => 0,
                Field::Follow => 1,
                Field::Participation => 2,
            };
            bytes.push(
                field
                    | (u8::from(entry.active) << 2)
                    | (u8::from(self.pending.contains(key)) << 3)
                    | (u8::from(self.checkpoint.contains(key)) << 4),
            );
        }
        Ok(bytes)
    }

    fn decode_compact(bytes: &[u8]) -> Result<Self> {
        let mut input = Input { bytes };
        if input.take::<1>()?[0] != 1 {
            return Err("unsupported private settings layout".into());
        }
        let clock = u64::from_le_bytes(input.take()?);
        let cursor = i64::from_le_bytes(input.take()?);
        let last_checkpoint_ms = u64::from_le_bytes(input.take()?);
        let baseline = input.take::<1>()?[0];
        let head = input.take::<1>()?[0];
        if baseline > 1 || head > 1 {
            return Err("invalid private settings flags".into());
        }
        let checkpoint_head = if head == 1 {
            Some(RecordId::from_bytes(input.take()?))
        } else {
            None
        };
        let spaces = input.dictionary::<32>()?;
        let streams = input.dictionary::<16>()?;
        let devices = input.dictionary::<32>()?;
        let count = u32::from_le_bytes(input.take()?) as usize;
        if count.checked_mul(ENTRY_BYTES) != Some(input.bytes.len()) {
            return Err("invalid private settings length".into());
        }
        let mut state = State {
            v: 1,
            clock,
            cursor,
            last_checkpoint_ms,
            checkpoint_head,
            baseline_initialized: baseline == 1,
            values: BTreeMap::new(),
            pending: BTreeSet::new(),
            checkpoint: BTreeSet::new(),
        };
        for _ in 0..count {
            let record = RecordId::from_bytes(input.take()?);
            let clock = u64::from_le_bytes(input.take()?);
            let space = SpaceId::from_bytes(input.index(&spaces)?);
            let stream = StreamId::from_bytes(input.index(&streams)?);
            let device = RecordId::from_bytes(input.index(&devices)?);
            let flags = input.take::<1>()?[0];
            if flags & !31 != 0 {
                return Err("invalid private settings entry flags".into());
            }
            let field = match flags & 3 {
                0 => Field::Unread,
                1 => Field::Follow,
                2 => Field::Participation,
                _ => return Err("invalid private settings field".into()),
            };
            let entry = Entry {
                field,
                space,
                stream,
                record,
                stamp: Stamp { clock, device },
                active: flags & 4 != 0,
            };
            let key = entry.key();
            if flags & 8 != 0 {
                state.pending.insert(key.clone());
            }
            if flags & 16 != 0 {
                state.checkpoint.insert(key.clone());
            }
            if state.values.insert(key, entry).is_some() {
                return Err("duplicate private settings entry".into());
            }
        }
        state.validate()?;
        Ok(state)
    }
}

fn dictionary<T: Ord>(ids: impl Iterator<Item = T>) -> Result<BTreeMap<T, u16>> {
    let ids = ids.collect::<BTreeSet<_>>();
    if ids.len() > MAX_DICTIONARY {
        return Err("too many private settings contexts".into());
    }
    Ok(ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| (id, index as u16))
        .collect())
}

struct Input<'a> {
    bytes: &'a [u8],
}
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let value = self
            .bytes
            .get(..N)
            .ok_or("truncated private settings")?
            .try_into()?;
        self.bytes = &self.bytes[N..];
        Ok(value)
    }
    fn dictionary<const N: usize>(&mut self) -> Result<Vec<[u8; N]>> {
        let count = u32::from_le_bytes(self.take()?) as usize;
        if count > MAX_DICTIONARY || count > self.bytes.len() / N {
            return Err("invalid private settings dictionary length".into());
        }
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let id = self.take()?;
            if ids.last().is_some_and(|old| *old >= id) {
                return Err("duplicate or unordered private settings dictionary".into());
            }
            ids.push(id);
        }
        Ok(ids)
    }
    fn index<const N: usize>(&mut self, ids: &[[u8; N]]) -> Result<[u8; N]> {
        ids.get(usize::from(u16::from_le_bytes(self.take()?)))
            .copied()
            .ok_or_else(|| "invalid private settings dictionary index".into())
    }
}

// Private values already carry read/unread state. Serialize that projection only
// once; derive the familiar in-memory sets when opening the encrypted profile.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadWire {
    v: u8,
    seen: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    unread: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    reminders: Vec<message_actions::Reminder>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    muted_streams: BTreeSet<StreamId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_settings: Option<State>,
}

#[derive(Serialize)]
struct ReadRef<'a> {
    v: u8,
    seen: BTreeMap<String, Vec<String>>,
    unread: BTreeMap<String, Vec<String>>,
    reminders: &'a [message_actions::Reminder],
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    muted_streams: &'a BTreeSet<StreamId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_settings: Option<&'a State>,
}

impl Serialize for ReadState {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut seen = self.seen.clone();
        let mut unread = self.unread.clone();
        if let Some(state) = &self.private_settings {
            let mut represented: BTreeMap<StreamId, BTreeSet<RecordId>> = BTreeMap::new();
            for entry in state
                .values
                .values()
                .filter(|entry| entry.field == Field::Unread)
            {
                represented
                    .entry(entry.stream)
                    .or_default()
                    .insert(entry.record);
            }
            for (stream, records) in represented {
                let stream = stream.to_string();
                for collection in [&mut seen, &mut unread] {
                    if let Some(ids) = collection.get_mut(&stream) {
                        ids.retain(|id| {
                            !id.parse::<RecordId>().is_ok_and(|id| records.contains(&id))
                        });
                        if ids.is_empty() {
                            collection.remove(&stream);
                        }
                    }
                }
            }
        }
        ReadRef {
            v: self.v,
            seen,
            unread,
            reminders: &self.reminders,
            muted_streams: &self.muted_streams,
            private_settings: self.private_settings.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReadState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let wire = ReadWire::deserialize(deserializer)?;
        let mut read = Self {
            v: wire.v,
            seen: wire.seen,
            unread: wire.unread,
            reminders: wire.reminders,
            muted_streams: wire.muted_streams,
            private_settings: wire.private_settings,
        };
        read.validate().map_err(D::Error::custom)?;
        if let Some(state) = &read.private_settings {
            let mut changes: BTreeMap<StreamId, BTreeMap<String, bool>> = BTreeMap::new();
            for entry in state
                .values
                .values()
                .filter(|entry| entry.field == Field::Unread)
            {
                changes
                    .entry(entry.stream)
                    .or_default()
                    .insert(entry.record.to_string(), entry.active);
            }
            for (stream, entries) in changes {
                let stream = stream.to_string();
                for (active, target) in [(false, &mut read.seen), (true, &mut read.unread)] {
                    let ids = target.entry(stream.clone()).or_default();
                    ids.retain(|id| !entries.contains_key(id));
                    ids.extend(
                        entries
                            .iter()
                            .filter(|(_, value)| **value == active)
                            .map(|(id, _)| id.clone()),
                    );
                    ids.sort_unstable();
                    ids.dedup();
                }
            }
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_private_state_rejects_invalid_lengths_indices_flags_and_duplicate_keys() {
        let mut state = State::default();
        state
            .local(
                Field::Unread,
                SpaceId::from_bytes([1; 32]),
                StreamId::from_bytes([2; 16]),
                RecordId::from_bytes([3; 32]),
                true,
                RecordId::from_bytes([4; 32]),
                100,
            )
            .unwrap();
        let original = state.encode_compact().unwrap();
        assert_eq!(original.len(), 123 + ENTRY_BYTES);
        assert!(State::decode_compact(&original).is_ok());
        let mut cases = Vec::new();
        cases.push(original[..original.len() - 1].to_vec());
        let mut bytes = original.clone();
        bytes.push(0);
        cases.push(bytes);
        let mut bytes = original.clone();
        bytes[0] = 2;
        cases.push(bytes);
        let mut bytes = original.clone();
        bytes[25] = 2;
        cases.push(bytes);
        let mut bytes = original.clone();
        bytes[27..31].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(bytes);
        let mut bytes = original.clone();
        bytes[119..123].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(bytes);
        let mut bytes = original.clone();
        *bytes.last_mut().unwrap() |= 128;
        cases.push(bytes);
        let mut bytes = original.clone();
        *bytes.last_mut().unwrap() |= 3;
        cases.push(bytes);
        let mut bytes = original.clone();
        bytes[163..165].copy_from_slice(&1u16.to_le_bytes());
        cases.push(bytes);
        let mut bytes = original.clone();
        bytes[1..9].copy_from_slice(&0u64.to_le_bytes());
        cases.push(bytes);
        let mut bytes = original.clone();
        bytes[119..123].copy_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&original[123..]);
        cases.push(bytes);
        let mut bytes = original.clone();
        bytes[27..31].copy_from_slice(&2u32.to_le_bytes());
        bytes.splice(63..63, original[31..63].iter().copied());
        cases.push(bytes);
        for (index, bytes) in cases.iter().enumerate() {
            assert!(
                State::decode_compact(bytes).is_err(),
                "invalid case {index}"
            );
        }
    }
}

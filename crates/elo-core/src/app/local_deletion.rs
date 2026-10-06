//! Removing a conversation from one device preserves its signed membership.
use super::*;

impl ClientApp {
    pub(super) fn can_delete_chat_local(&self, index: usize) -> Result<bool> {
        let pin = &self.pins[index];
        let authority = &self.authorities.0[index];
        let general = self.team.as_ref().is_some_and(|team| {
            team.scope.space == pin.space
                && team.scope.stream == pin.stream
                && team.scope.root == pin.root
        });
        Ok(!general && !self.is_notes_authority(authority) && pin.personal_seed != Some(true))
    }

    /// An epoch for native asynchronous work; live SQLite also invalidates
    /// snapshots obtained before a deletion. Hidden chats still have an epoch.
    pub async fn local_chat_generation(&self, request: &Value) -> Result<u64> {
        if request["expected_identity"] != json!(self.identity_id())
            || request["expected_space"] != json!(self.active_space_id())
        {
            return Err("The selected Space has changed. Try again.".into());
        }
        let client = self.selected_space_client()?;
        let index = client.authority_index(request)?;
        let authority = &client.authorities.0[index];
        Ok(client
            .store
            .local_chat_state(authority.space(), authority.stream())
            .await?
            .generation)
    }

    pub(super) async fn delete_local_chat(&mut self, request: &Value) -> Result<Value> {
        let index = self.authority_index(request)?;
        if !self.can_delete_chat_local(index)? {
            return Err("This conversation cannot be removed from this device.".into());
        }
        let authority = &self.authorities.0[index];
        let (space, stream) = (authority.space(), authority.stream());
        let originals = self.history_view().local_file_shares(authority).await?;
        let has_attachments = originals
            .iter()
            .any(|(record, _)| record.body()["kind"] == "file.shared");
        let mut retained_cache = BTreeSet::new();
        if has_attachments {
            // The ciphertext cache is content-addressed across this compartment.
            // A forwarded descriptor or forged digest must not evict a different
            // conversation's only downloaded copy as a side effect of deletion.
            for other in &self.authorities.0 {
                if other.space() == space && other.stream() == stream {
                    continue;
                }
                for (record, _) in self.history_view().local_file_shares(other).await? {
                    if record.body()["kind"] == "file.shared" {
                        let share: crate::files::FileShared = record.decode()?;
                        if let Some(descriptor) = share.attachment {
                            retained_cache.insert(descriptor.encryption.ciphertext_sha256);
                        }
                    }
                }
            }
        }
        let mut attachment_records = Vec::new();
        let mut verified_file_objects = Vec::new();
        for (record, _) in &originals {
            if record.body()["kind"] == "file.shared" {
                let share: crate::files::FileShared = record.decode()?;
                attachment_records.push(record.id());
                if let Some(descriptor) = share.attachment
                    && !retained_cache.contains(&descriptor.encryption.ciphertext_sha256)
                {
                    crate::attachments::cache::remove(
                        &self.directory,
                        &descriptor.encryption.ciphertext_sha256,
                    )?;
                }
                if let Some(object) = share.object_id
                    && let Some(ciphertext) = self.store.get_object(object).await?
                {
                    let recipient = crypto::history_recipient(
                        record,
                        authority,
                        self.identity_id(),
                        self.session.age_identity(),
                    )?;
                    let verified = crate::files::VerifiedFileShare::verify(
                        record, authority, recipient, true,
                    )?;
                    // A signed file reference alone cannot authorize removing a
                    // different chat's object. Validate its complete body first.
                    if let Ok(file) = crate::files::open(
                        &ciphertext,
                        self.session.age_identity(),
                        recipient,
                        &verified,
                        authority,
                    ) {
                        let _clear = Zeroizing::new(file.bytes);
                        verified_file_objects.push(object);
                    }
                }
            }
        }
        let (state, database_cleanup_pending) = if verified_file_objects.is_empty() {
            self.store.delete_chat_local(space, stream, now()?).await?
        } else {
            self.store
                .delete_chat_local_with_objects(space, stream, now()?, verified_file_objects)
                .await?
        };
        self.presentation.forget_chat(space, stream);
        let mut read = (*self.read).clone();
        let read_ids = read
            .seen
            .values()
            .chain(read.unread.values())
            .flatten()
            .filter_map(|id| id.parse().ok())
            .chain(read.reminders.iter().map(|reminder| reminder.record))
            .collect();
        let removed = self.store.local_deleted_records(read_ids).await;
        let mut cleanup_pending = database_cleanup_pending || removed.is_err();
        let mut removed_reminders = Vec::new();
        if let Ok(removed) = removed {
            // Legacy read buckets use StreamId. Do not clear a different signed
            // namespace that happens to use the same stream identifier.
            for records in read.seen.values_mut().chain(read.unread.values_mut()) {
                records.retain(|id| id.parse().is_ok_and(|id| !removed.contains(&id)));
            }
            read.reminders.retain(|reminder| {
                if removed.contains(&reminder.record) {
                    removed_reminders.push(reminder.record);
                    false
                } else {
                    true
                }
            });
        }
        // This is a local cleanup, not a private-settings event to other devices.
        cleanup_pending |= self.write_read_state(&read).is_err();
        self.read = read.into();
        let view = self.view().await;
        let cleanup_pending = cleanup_pending || view.is_err();
        Ok(
            json!({"deleted_chat":{"space":space,"stream":stream,"history_generation":state.generation,"attachment_records":attachment_records},"removed_reminders":removed_reminders,"cleanup_pending":cleanup_pending,"view":view.unwrap_or(Value::Null)}),
        )
    }
}

#[cfg(test)]
mod tests;

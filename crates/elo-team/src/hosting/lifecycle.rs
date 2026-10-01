//! Isolate damaged Spaces and keep remote cleanup out of listener startup.
use super::*;

impl Host {
    pub(super) async fn expire_unpublished_reservations(&self) -> Result<()> {
        self.expire_reservations_at(current()?).await
    }

    pub(super) async fn expire_reservations_at(&self, now: u64) -> Result<()> {
        let Ok(_creation) = self.creation.try_lock() else {
            return Ok(());
        };
        for entry in std::fs::read_dir(self.config.root.join("spaces"))? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if id.parse::<ObjectId>().is_err()
                || self
                    .config
                    .root
                    .join("deleted")
                    .join(format!("{id}.json"))
                    .exists()
            {
                continue;
            }
            let path = entry.path();
            let reservation = vault::read_private(&path.join("reservation.json"))
                .ok()
                .and_then(|bytes| {
                    serde_json::from_slice::<Reservation>(&Zeroizing::new(bytes)).ok()
                });
            let Some(reservation) = reservation else {
                continue;
            };
            if (reservation.invitation.is_some() && !reservation.reclaim_if_unclaimed)
                || reservation.reserved_at == 0
                || now.saturating_sub(reservation.reserved_at) < 86_400_000
            {
                continue;
            }
            // Serialize against joins. Once even a pending join has been saved,
            // this Space is retained forever, including after members leave.
            let space = self.spaces.read().await.get(&id).cloned();
            if let Some(space) = space {
                let Ok(mut guard) = space.client.try_lock() else {
                    continue;
                };
                let Some(client) = guard.as_ref() else {
                    continue;
                };
                if !client.space_reservation_is_unused(now).unwrap_or(false) {
                    continue;
                }
                private_directory(&path)?;
                *space.serving.write().await = false;
                let client = guard.take().unwrap();
                client.close().await?;
                self.spaces.write().await.remove(&id);
            } else if reservation.invitation.is_some() {
                // Never infer emptiness from an unavailable or damaged service.
                continue;
            }
            private_directory(&path)?;
            std::fs::remove_dir_all(&path)?;
            self.allocations
                .lock()
                .map_err(|_| "Hosting allocation index unavailable.")?
                .remove(&id);
        }
        Ok(())
    }

    pub(super) fn save_service_recovery(
        &self,
        path: &FilePath,
        draft: &ProfileDraft,
    ) -> Result<()> {
        use std::io::Write;
        let Some(recipient) = &self.config.recovery_recipient else {
            return Ok(());
        };
        let recipient: age::x25519::Recipient = recipient.parse()?;
        let plain = Zeroizing::new(serde_json::to_vec(draft.card())?);
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext)?;
        writer.write_all(&plain)?;
        writer.finish()?;
        vault::write_private(&path.join("service-recovery.age"), &ciphertext, true)?;
        Ok(())
    }

    pub(super) async fn load_spaces(&self) -> Result<()> {
        for entry in std::fs::read_dir(self.config.root.join("spaces"))? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned();
            // A damaged reservation still consumes capacity. Never rebuild an
            // advertised Space with new keys just because its files are damaged.
            self.allocations
                .lock()
                .map_err(|_| "Hosting allocation index unavailable.")?
                .insert(id.clone(), None);
            if self.load_space(&id, &entry.path()).await.is_err() {
                eprintln!("Hosted Space {id} could not be opened; other Spaces remain available.");
            }
        }
        Ok(())
    }

    async fn load_space(&self, id: &str, path: &FilePath) -> Result<()> {
        let _: ObjectId = id.parse()?;
        private_directory(path)?;
        let marker = self.config.root.join("deleted").join(format!("{id}.json"));
        let deleting = marker.exists();
        if deleting {
            let deleted: Deleted = serde_json::from_slice(&vault::read_private(&marker)?)?;
            if deleted.cleanup_completed {
                // A restore may bring back old local files. Remote cleanup has
                // already finished, so remove these remnants without network I/O.
                self.finish_deletion(id).await?;
                return Ok(());
            }
            if !path.join("config.json").exists() {
                return Ok(());
            }
        }
        let reservation: Reservation = serde_json::from_slice(&Zeroizing::new(
            vault::read_private(&path.join("reservation.json"))?,
        ))?;
        if reservation
            .creator
            .is_some_and(|creator| reservation_id(creator, &reservation.request_id) != id)
        {
            return Err("Hosting reservation mismatch.".into());
        }
        self.allocations
            .lock()
            .map_err(|_| "Hosting allocation index unavailable.")?
            .insert(id.to_owned(), reservation.creator);
        if path.join("config.json").exists() {
            let space = self.open_ready(id, &reservation, None).await?;
            if deleting {
                *space.serving.write().await = false;
            }
            self.spaces.write().await.insert(id.to_owned(), space);
        }
        Ok(())
    }

    pub(super) async fn retry_deletions(&self) {
        let Ok(entries) = std::fs::read_dir(self.config.root.join("deleted")) else {
            eprintln!("Pending Space cleanup index unavailable.");
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|v| v.to_str()) else {
                continue;
            };
            if id.parse::<ObjectId>().is_err() {
                continue;
            }
            let complete = vault::read_private(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Deleted>(&bytes).ok())
                .is_some_and(|marker| marker.cleanup_completed);
            if !complete && self.finish_deletion(id).await.is_err() {
                eprintln!("Space {id} cleanup is pending; it will be retried in the background.");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_expired_unpublished_reservations_are_reclaimed() {
        let temp = tempfile::tempdir().unwrap();
        let config: HostConfig = serde_json::from_value(json!({
            "root":temp.path().join("host"), "public_url":"https://host.example.test",
            "max_spaces_per_identity":2, "mailbox_quota_bytes":150_000_000
        }))
        .unwrap();
        let host = Host::open(config, false).await.unwrap();
        for (index, issued, time) in [
            (1, false, 1),
            (2, true, 1),
            (3, false, 0),
            (4, false, current().unwrap()),
        ] {
            let id = format!("{index:064x}");
            let path = host.config.root.join("spaces").join(&id);
            private_directory(&path).unwrap();
            save(
                &path.join("reservation.json"),
                &Reservation {
                    creation_evidence: None,
                    authority: None,
                    creator: None,
                    request_id: "synthetic".into(),
                    name: "Unpublished".into(),
                    contact_email: None,
                    message_lifetime_seconds: 86400,
                    require_approval: true,
                    mailbox: MailboxDescriptor::random().unwrap(),
                    password: "synthetic".into(),
                    invitation: issued.then(|| "synthetic-issued-invite".into()),
                    invitation_issued: 0,
                    reserved_at: time,
                    creation_network: None,
                    reclaim_if_unclaimed: false,
                },
            )
            .unwrap();
            host.allocations.lock().unwrap().insert(id, None);
        }
        host.expire_unpublished_reservations().await.unwrap();
        assert!(
            !host
                .config
                .root
                .join("spaces")
                .join(format!("{:064x}", 1))
                .exists()
        );
        for index in 2..=4 {
            assert!(
                host.config
                    .root
                    .join("spaces")
                    .join(format!("{index:064x}"))
                    .exists()
            );
        }
        assert_eq!(host.allocations.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn startup_isolates_bad_reservations_and_never_contacts_attachment_storage() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("host");
        let config: HostConfig = serde_json::from_value(json!({
            "root":root, "public_url":"https://host.example.test",
            "max_spaces_per_identity":2, "mailbox_quota_bytes":150_000_000,
            "attachment_storage":{"provider":"mega_web_dav", "base_url":"http://127.0.0.1:1/unavailable"}
        })).unwrap();
        let host = Host::open(config.clone(), false).await.unwrap();
        // Recovery material is encrypted to a key that never belongs on the VPS.
        let identity = age::x25519::Identity::generate();
        let mut recovery_config = config.clone();
        recovery_config.recovery_recipient = Some(identity.to_public().to_string());
        let draft = ProfileDraft::new().unwrap();
        let recovery_host = Host::open(recovery_config, false).await.unwrap();
        recovery_host
            .save_service_recovery(temp.path(), &draft)
            .unwrap();
        let encrypted = vault::read_private(&temp.path().join("service-recovery.age")).unwrap();
        let mut reader = age::Decryptor::new(&encrypted[..])
            .unwrap()
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut plain = String::new();
        std::io::Read::read_to_string(&mut reader, &mut plain).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&plain).unwrap(),
            serde_json::to_value(draft.card()).unwrap()
        );
        assert!(!String::from_utf8_lossy(&encrypted).contains(&plain));
        drop(recovery_host);
        drop(host);
        let bad = root.join("spaces").join("11".repeat(32));
        private_directory(&bad).unwrap();
        vault::write_private(&bad.join("reservation.json"), b"{broken", false).unwrap();
        let id = "22".repeat(32);
        save(
            &root.join("deleted").join(format!("{id}.json")),
            &Deleted {
                receipt: DeletionReceipt {
                    record: "synthetic".into(),
                    credential: "synthetic".into(),
                },
                mailbox: MailboxDescriptor::random().unwrap().mailbox_id,
                attachment_objects: vec![],
                cleanup_completed: false,
            },
        )
        .unwrap();
        let host = tokio::time::timeout(Duration::from_secs(2), Host::open(config, false))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host.allocations.lock().unwrap().len(), 1);
        assert!(host.spaces.read().await.is_empty());
        assert!(host.finish_deletion(&id).await.is_err());
        assert!(root.join("deleted").join(format!("{id}.json")).exists());
        // A completed tombstone is a local receipt, even while MEGA is offline.
        let marker = root.join("deleted").join(format!("{id}.json"));
        let mut deleted: Deleted =
            serde_json::from_slice(&vault::read_private(&marker).unwrap()).unwrap();
        deleted.cleanup_completed = true;
        save(&marker, &deleted).unwrap();
        assert_eq!(host.finish_deletion(&id).await.unwrap().record, "synthetic");
    }
}

#[cfg(test)]
mod reservation_limits_tests {
    use super::*;

    #[tokio::test]
    async fn issued_unused_reservation_expires_only_after_all_invites() {
        let temp = tempfile::tempdir().unwrap();
        let config: HostConfig = serde_json::from_value(json!({
            "root":temp.path().join("host"), "public_url":"https://host.example.test",
            "max_spaces_per_identity":2, "mailbox_quota_bytes":150_000_000
        }))
        .unwrap();
        let host = Host::open(config, true).await.unwrap();
        let (command, creator, evidence) =
            super::super::tests::creation_command(&temp.path().join("creator"), "Never joined")
                .await;
        let (id, reservation) = host
            .provision_from_network_inner(&command, creator, None, Some(evidence))
            .await
            .unwrap();
        host.expire_reservations_at(reservation.invitation_issued + 86_399_000)
            .await
            .unwrap();
        assert!(host.spaces.read().await.contains_key(&id));
        host.expire_reservations_at(reservation.invitation_issued + 86_401_000)
            .await
            .unwrap();
        assert!(!host.spaces.read().await.contains_key(&id));
        assert!(!host.allocations.lock().unwrap().contains_key(&id));
        assert!(!host.config.root.join("spaces").join(id).exists());
        super::super::tests::close_host(host).await;
    }

    #[tokio::test]
    async fn active_network_limit_survives_restart_and_daily_reset() {
        let temp = tempfile::tempdir().unwrap();
        let config: HostConfig = serde_json::from_value(json!({
            "root":temp.path().join("host"), "public_url":"https://host.example.test",
            "max_spaces_per_identity":2, "mailbox_quota_bytes":150_000_000
        }))
        .unwrap();
        let host = Host::open(config.clone(), true).await.unwrap();
        let network = "synthetic-network".to_owned();
        for index in 1..=8 {
            let id = format!("{index:064x}");
            let path = config.root.join("spaces").join(&id);
            private_directory(&path).unwrap();
            save(
                &path.join("reservation.json"),
                &Reservation {
                    creation_evidence: None,
                    authority: None,
                    creator: None,
                    request_id: "synthetic".into(),
                    name: "Unclaimed".into(),
                    contact_email: None,
                    message_lifetime_seconds: 86400,
                    require_approval: true,
                    mailbox: MailboxDescriptor::random().unwrap(),
                    password: "synthetic".into(),
                    invitation: None,
                    invitation_issued: 0,
                    reserved_at: current().unwrap(),
                    creation_network: Some(network.clone()),
                    reclaim_if_unclaimed: true,
                },
            )
            .unwrap();
        }
        super::super::tests::close_host(host).await;
        let host = Host::open(config, true).await.unwrap();
        let (command, creator, _evidence) =
            super::super::tests::creation_command(&temp.path().join("creator"), "Capacity").await;
        assert_eq!(
            host.provision_from_network(&command, creator, Some(network))
                .await
                .err()
                .unwrap()
                .to_string(),
            "Hosting capacity reached."
        );
        super::super::tests::close_host(host).await;
    }
}

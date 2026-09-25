//! Profile-wide device management using the unlocked device's signing key.
use super::*;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    retry_after: u64,
    jobs: Vec<Job>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    proof: String,
    address: space_service::SpaceAddress,
}

impl ClientApp {
    fn device_names(&self) -> Result<BTreeMap<RecordId, String>> {
        let path = self.directory.join("device-names.age");
        if !path.try_exists()? {
            return Ok(BTreeMap::new());
        }
        let plain = Zeroizing::new(crypto::open_bytes(
            &vault::read_private(&path)?,
            self.session.age_identity(),
            32 * 1024,
        )?);
        let names: BTreeMap<RecordId, String> = serde_json::from_slice(&plain)?;
        if names.len() > 128 || names.values().any(|name| !record::valid_display_name(name)) {
            return Err("Invalid device names.".into());
        }
        Ok(names)
    }
    pub fn name_current_device(&self, name: &str) -> Result<()> {
        self.remember_device(self.session.credential(), name)
    }
    pub(super) fn remember_device(
        &self,
        credential: &VerifiedCredential,
        name: &str,
    ) -> Result<()> {
        if credential.identity() != self.identity_id() || !record::valid_display_name(name) {
            return Err("Invalid device name.".into());
        }
        let mut names = self.device_names()?;
        if names.get(&credential.id()).is_some_and(|old| old == name) {
            return Ok(());
        }
        if names.len() >= 128 && !names.contains_key(&credential.id()) {
            return Err("Too many saved devices.".into());
        }
        names.insert(credential.id(), name.into());
        vault::write_private(
            &self.directory.join("device-names.age"),
            &crypto::seal_bytes(
                &Zeroizing::new(serde_json::to_vec(&names)?),
                &[self.session.age_identity().to_public()],
                32 * 1024,
            )?,
            true,
        )?;
        Ok(())
    }
    fn pending_devices(&self) -> Result<Pending> {
        let path = self.directory.join("device-revocations.age");
        if !path.try_exists()? {
            return Ok(Pending::default());
        }
        let plain = Zeroizing::new(crypto::open_bytes(
            &vault::read_private(&path)?,
            self.session.age_identity(),
            128 * 1024,
        )?);
        let pending: Pending = serde_json::from_slice(&plain)?;
        if pending.jobs.len() > 128 {
            return Err("Too many pending device changes.".into());
        }
        Ok(pending)
    }
    fn save_pending_devices(&self, pending: &Pending) -> Result<()> {
        vault::write_private(
            &self.directory.join("device-revocations.age"),
            &crypto::seal_bytes(
                &Zeroizing::new(serde_json::to_vec(pending)?),
                &[self.session.age_identity().to_public()],
                128 * 1024,
            )?,
            true,
        )?;
        Ok(())
    }
    pub async fn linked_devices(&self) -> Result<Value> {
        let mut devices = BTreeMap::<RecordId, Value>::new();
        let names = self.device_names()?;
        let mut unavailable = 0;
        let addresses = self.device_addresses();
        for chunk in addresses.chunks(4) {
            let mut calls = Vec::with_capacity(chunk.len());
            for address in chunk {
                calls.push(self.call_space(address, "device_list", json!({})));
            }
            for result in futures_util::future::join_all(calls).await {
                match result {
                    Ok(value) => {
                        for device in value["devices"].as_array().ok_or("Invalid device list.")? {
                            let record = decode_record(field(device, "credential")?)?;
                            let credential = VerifiedCredential::verify(
                                record.bytes(),
                                &root_key(field(record.body(), "root_public_key")?)?,
                            )?;
                            if credential.identity() != self.identity_id()
                                || device["id"] != json!(credential.id())
                            {
                                return Err("Invalid device list.".into());
                            }
                            devices.insert(credential.id(), json!({"id":credential.id(),"credential":device["credential"],"name":names.get(&credential.id()),"current":credential.id()==self.session.credential().id()}));
                        }
                    }
                    Err(_) => unavailable += 1,
                }
            }
        }
        Ok(
            json!({"devices":devices.into_values().collect::<Vec<_>>(), "unavailable":unavailable,"pending":self.pending_devices()?.jobs.len(),"can_link":self.session.credential().authorizing_device().is_none()}),
        )
    }
    pub async fn revoke_linked_device(&self, encoded: &str) -> Result<Value> {
        let record = decode_record(encoded)?;
        let root = root_key(field(
            self.session.credential().record().body(),
            "root_public_key",
        )?)?;
        let target = VerifiedCredential::verify(record.bytes(), &root)?;
        if target.identity() != self.identity_id() || target.id() == self.session.credential().id()
        {
            return Err("Choose another device belonging to this profile.".into());
        }
        let proof = STANDARD.encode(
            crate::identity::DeviceRevocation::issue_from_device(
                self.session.credential(),
                self.session.signing_key(),
                &target,
            )?
            .bytes(),
        );
        let addresses = self.device_addresses();
        if addresses.is_empty() {
            return Err("Join a Space first.".into());
        }
        let mut pending = self.pending_devices()?;
        for address in addresses {
            let exists = pending.jobs.iter().any(|job| {
                job.address.url == address.url
                    && decode_record(&job.proof)
                        .ok()
                        .and_then(|r| crate::identity::DeviceRevocation::verify(&r).ok())
                        .is_some_and(|c| c.id() == target.id())
            });
            if !exists {
                if pending.jobs.len() >= 128 {
                    return Err("Too many pending device changes.".into());
                }
                pending.jobs.push(Job {
                    proof: proof.clone(),
                    address,
                });
            }
        }
        pending.retry_after = 0;
        self.save_pending_devices(&pending)?;
        self.invalidate_membership_checks().await;
        if let Some(spaces) = &self.spaces {
            for client in spaces.clients(self) {
                client.invalidate_membership_checks().await;
            }
        }
        self.retry_device_revocations(true).await?;
        self.linked_devices().await
    }
    pub(super) async fn retry_device_revocations(&self, immediate: bool) -> Result<()> {
        let mut pending = self.pending_devices()?;
        let current = now()?.as_millis() as u64;
        if pending.jobs.is_empty() || !immediate && pending.retry_after > current {
            return Ok(());
        }
        pending.retry_after = current + 30_000;
        self.save_pending_devices(&pending)?;
        // Bound foreground work even when several hosts are offline. Remaining
        // jobs stay durable and are retried by sync.
        let limit = if immediate {
            pending.jobs.len().min(2)
        } else {
            1
        };
        for _ in 0..limit {
            let job = pending.jobs.remove(0);
            self.invalidate_membership_checks().await;
            if let Some(spaces) = &self.spaces {
                for client in spaces.clients(self) {
                    client.invalidate_membership_checks().await;
                }
            }
            let target = crate::identity::DeviceRevocation::verify(&decode_record(&job.proof)?)?;
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(if immediate { 12 } else { 2 }),
                self.call_space(&job.address, "device_revoke", json!({"proof":job.proof})),
            )
            .await;
            if !matches!(result, Ok(Ok(ref result)) if result["revoked"] == json!(target.id())) {
                pending.jobs.push(job);
            }
            self.save_pending_devices(&pending)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn offline_revocation_stays_encrypted_and_pending_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profile");
        let draft = ProfileDraft::new().unwrap();
        let mut app = draft
            .save(
                path.clone(),
                "synthetic revocation password".into(),
                "General",
            )
            .await
            .unwrap();
        let retired = app.session.companion(draft.card()).unwrap();
        app.call_host = Some(space_service::SpaceAddress {
            url: "http://127.0.0.1:9/team/v1/spaces".into(),
            scope: app.team_scope().unwrap(),
            message_lifetime_seconds: 86400,
        });
        let encoded = STANDARD.encode(retired.credential().record().bytes());
        let result = app.revoke_linked_device(&encoded).await.unwrap();
        assert_eq!(result["pending"], 1);
        assert_eq!(result["unavailable"], 1);
        let bytes = std::fs::read(path.join("device-revocations.age")).unwrap();
        assert!(
            !bytes
                .windows(encoded.len())
                .any(|window| window == encoded.as_bytes())
        );
        let pending = app.pending_devices().unwrap();
        assert_eq!(pending.jobs.len(), 1);
        assert!(
            !serde_json::to_string(&pending)
                .unwrap()
                .contains(&draft.card().phrase)
        );
        app.close().await.unwrap();
        let reopened = ClientApp::open(path, "synthetic revocation password".into(), false)
            .await
            .unwrap();
        assert_eq!(reopened.pending_devices().unwrap().jobs.len(), 1);
        reopened.retry_device_revocations(true).await.unwrap();
        assert_eq!(reopened.pending_devices().unwrap().jobs.len(), 1);
        reopened.close().await.unwrap();
    }
}

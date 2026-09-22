//! Restartable automatic erasure, serialized with admission and role changes.
use super::*;
use elo_core::app::account_deletion::{self as protocol, Action, Outcome, OwnedSpace, Status};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    identity: IdentityId,
    id: String,
    requested_at: u64,
    completed_at: Option<u64>,
    spaces: Vec<String>,
}
impl Job {
    fn outcome(&self) -> Outcome {
        Outcome {
            status: if self.completed_at.is_some() {
                Status::Completed
            } else {
                Status::Pending
            },
            owned_spaces: vec![],
            request_id: Some(self.id.clone()),
            requested_at: Some(self.requested_at),
            completed_at: self.completed_at,
            receipts: Vec::new(),
        }
    }
}
impl Host {
    fn save_account_receipt(&self, job: &Job) -> Result<()> {
        protocol::validate_receipt(&job.id)?;
        let path = self
            .config
            .root
            .join("account-receipts")
            .join(format!("{}.json", job.id));
        let value = json!({"completed":job.completed_at.is_some()});
        if path.exists() && serde_json::from_slice::<Value>(&vault::read_private(&path)?)? == value
        {
            return Ok(());
        }
        save(&path, &value)
    }
    pub(super) fn account_scope_pending(&self, space: &str) -> Result<bool> {
        for entry in std::fs::read_dir(self.config.root.join("account-deletions"))? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let job: Job = serde_json::from_slice(&vault::read_private(&path)?)?;
            if job.completed_at.is_none() && job.spaces.iter().any(|id| id == space) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn account_path(&self, identity: IdentityId) -> PathBuf {
        self.config
            .root
            .join("account-deletions")
            .join(format!("{identity}.json"))
    }
    pub(super) fn account_requested(&self, identity: IdentityId) -> bool {
        self.account_path(identity).exists()
    }
    async fn account_scopes(&self, identity: IdentityId) -> Result<Vec<String>> {
        let spaces: Vec<_> = self
            .spaces
            .read()
            .await
            .iter()
            .map(|(id, s)| (id.clone(), s.clone()))
            .collect();
        let mut affected = Vec::new();
        for (id, space) in spaces {
            let guard = space.client.lock().await;
            let client = guard.as_ref().ok_or("Space unavailable.")?;
            let reservation: Reservation =
                serde_json::from_slice(&Zeroizing::new(vault::read_private(
                    &self
                        .config
                        .root
                        .join("spaces")
                        .join(&id)
                        .join("reservation.json"),
                )?))?;
            if client.account_membership(&space.config, identity)?["known"] == true
                || reservation.creator == Some(identity)
                || space.replica.has_account_content(identity).await?
            {
                affected.push(id);
            }
        }
        Ok(affected)
    }
    async fn account_inspect(&self, identity: IdentityId) -> Result<Outcome> {
        if self.account_requested(identity) {
            let job: Job =
                serde_json::from_slice(&vault::read_private(&self.account_path(identity))?)?;
            if job.identity != identity {
                return Err("Invalid account deletion record.".into());
            }
            return Ok(job.outcome());
        }
        let mut owned_spaces = Vec::new();
        for id in self.account_scopes(identity).await? {
            let space = self
                .spaces
                .read()
                .await
                .get(&id)
                .cloned()
                .ok_or("Space unavailable.")?;
            let guard = space.client.lock().await;
            let client = guard.as_ref().ok_or("Space unavailable.")?;
            let membership = client.account_membership(&space.config, identity)?;
            if membership["primary"] == true {
                owned_spaces.push(OwnedSpace {
                    name: space.config.name.clone(),
                    other_members: membership["other_members"] == true,
                });
            }
            if !space.replica.supports_account_erasure().await? {
                return Err(
                    "This service contains legacy data that cannot yet be erased automatically."
                        .into(),
                );
            }
        }
        Ok(Outcome {
            status: if owned_spaces.is_empty() {
                Status::Ready
            } else {
                Status::Blocked
            },
            owned_spaces,
            request_id: None,
            requested_at: None,
            completed_at: None,
            receipts: Vec::new(),
        })
    }
    pub(super) async fn process_account_deletions(&self) -> Result<()> {
        let Ok(_accounts) = self.accounts.try_lock() else {
            return Ok(());
        };
        for entry in std::fs::read_dir(self.config.root.join("account-deletions"))? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let mut job: Job = serde_json::from_slice(&vault::read_private(&entry.path())?)?;
            if entry.path() != self.account_path(job.identity) {
                return Err("Invalid account deletion path.".into());
            }
            if job.completed_at.is_some() {
                self.save_account_receipt(&job)?;
                continue;
            }
            if self.erase_account(&job).await.is_err() {
                eprintln!("Account erasure will retry; inspect service health.");
                continue;
            }
            job.completed_at = Some(current()?);
            job.spaces.clear();
            save(&entry.path(), &job)?;
            self.save_account_receipt(&job)?;
        }
        Ok(())
    }
    async fn erase_account(&self, job: &Job) -> Result<()> {
        let spaces: Vec<_> = self
            .spaces
            .read()
            .await
            .iter()
            .filter(|(id, _)| job.spaces.contains(id))
            .map(|(id, s)| (id.clone(), s.clone()))
            .collect();
        // Validate every scope before making any destructive change.
        for (_, space) in &spaces {
            let guard = space.client.lock().await;
            let client = guard.as_ref().ok_or("Space unavailable.")?;
            if client.account_membership(&space.config, job.identity)?["primary"] == true
                || !space.replica.supports_account_erasure().await?
            {
                return Err("Account erasure prerequisites changed.".into());
            }
        }
        for (id, space) in spaces {
            // Drain in-flight replica requests, then persist the refusal before cleanup.
            let mut guard = space.client.lock().await;
            let client = guard.as_mut().ok_or("Space unavailable.")?;
            client
                .erase_service_account(&space.config, job.identity)
                .await?;
            let _transport = space.serving.write().await;
            space
                .replica
                .erase_account_content(space.mailbox, job.identity)
                .await?;
            space
                .replica
                .set_space_members(space.mailbox, client.space_access_members()?)
                .await?;
            let path = self.config.root.join("spaces").join(&id);
            let reservation_path = path.join("reservation.json");
            let mut reservation: Reservation =
                serde_json::from_slice(&Zeroizing::new(vault::read_private(&reservation_path)?))?;
            if reservation.creator == Some(job.identity) {
                let membership = client.account_membership(&space.config, job.identity)?;
                reservation.creator = None;
                reservation.request_id.clear();
                reservation.invitation = None;
                reservation.contact_email = membership["contact_email"].as_str().map(str::to_owned);
                save(&reservation_path, &reservation)?;
                let mut config = space.config.clone();
                config.owners = vec![serde_json::from_value(
                    membership["primary_identity"].clone(),
                )?];
                config.contact_email = reservation.contact_email.clone();
                save(&path.join("config.json"), &config)?;
            }
            // Only the host's dedicated per-Space snapshots are in this contract.
            // User exports and backups on unrelated systems are never traversed.
            let backups = self.config.root.join("backups").join(&id);
            if backups.exists() {
                private_directory(&backups)?;
                std::fs::remove_dir_all(&backups)?;
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiptRequest {
    receipt: String,
}

/// A random receipt reveals only completion, never identity, membership or keys.
pub(super) async fn status(
    State(host): State<Arc<Host>>,
    Json(request): Json<ReceiptRequest>,
) -> std::result::Result<Json<Value>, StatusCode> {
    protocol::validate_receipt(&request.receipt).map_err(|_| StatusCode::BAD_REQUEST)?;
    let path = host
        .config
        .root
        .join("account-receipts")
        .join(format!("{}.json", request.receipt));
    let bytes = vault::read_private(&path).map_err(|_| StatusCode::NOT_FOUND)?;
    let value = serde_json::from_slice(&bytes).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(value))
}

pub(super) async fn request(
    State(host): State<Arc<Host>>,
    Json(request): Json<protocol::Request>,
) -> std::result::Result<Json<protocol::Response>, StatusCode> {
    let expected = protocol::endpoint(&host.config.public_url, host.allow_loopback)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (command, credential) = protocol::verify(
        &request,
        &expected,
        current().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let _accounts = host
        .accounts
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut result = host
        .account_inspect(credential.identity())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if command.action == Action::Submit && result.status == Status::Ready {
        let spaces = host
            .account_scopes(credential.identity())
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let time = current().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let job = Job {
            identity: credential.identity(),
            id: record::random_hex::<16>().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
            requested_at: time,
            completed_at: spaces.is_empty().then_some(time),
            spaces,
        };
        // Unknown identities have nothing to erase. Do not create arbitrary disk jobs.
        if !job.spaces.is_empty() {
            save(&host.account_path(job.identity), &job)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        result = job.outcome();
    }
    if result.status == Status::Pending {
        let job: Job = serde_json::from_slice(
            &vault::read_private(&host.account_path(credential.identity()))
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        host.save_account_receipt(&job)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    protocol::seal(&command, &credential, &result)
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{close_host, profile};
    use super::*;
    #[tokio::test]
    async fn automatic_account_deletion_survives_restart_and_preserves_other_accounts_and_spaces() {
        let temp = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let config = HostConfig {
            root: temp.path().join("host"),
            public_url: base.clone(),
            max_spaces_per_identity: 3,
            mailbox_quota_bytes: 32 * 1024 * 1024,
            operator_snapshot: None,
            call_admission_key: None,
            attachment_storage: None,
        };
        let host = Host::open(config.clone(), true).await.unwrap();
        let server = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
        let mut owner = profile(&temp.path().join("owner")).await;
        let mut member = profile(&temp.path().join("member")).await;
        let created = owner.operate(json!({"op":"space_create","host":format!("{base}/spaces/v1/create"),"contact_email":"owner@example.test","message_lifetime_seconds":86400,"name":"Family"})).await.unwrap();
        let space = created["view"]["active_space"].as_str().unwrap().to_owned();
        owner
            .operate(json!({"op":"space_setup_done"}))
            .await
            .unwrap();
        let invite = owner.operate(json!({"op":"space_invite","id":space,"body":{"lifetime":86400,"require_approval":false}})).await.unwrap()["result"]["link"].clone();
        let endpoint = protocol::endpoint(&base, true).unwrap();
        let sole = owner
            .call_account_deletion(&endpoint, Action::Inspect)
            .await
            .unwrap();
        assert_eq!(sole.status, Status::Blocked);
        assert!(!sole.owned_spaces[0].other_members);
        let joined = member
            .operate(json!({"op":"space_join","link":invite}))
            .await
            .unwrap();
        let chat = joined["view"]["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["is_general"] == true)
            .unwrap();
        member.operate(json!({"op":"send","space":chat["space"],"stream":chat["stream"],"text":"Delete this account's message","created_at":"2026-09-15T12:00:00Z"})).await.unwrap();
        member.operate(json!({"op":"sync"})).await.unwrap();
        owner.operate(json!({"op":"send","space":chat["space"],"stream":chat["stream"],"text":"Keep another member's message","created_at":"2026-09-15T12:00:01Z"})).await.unwrap();
        owner.operate(json!({"op":"sync"})).await.unwrap();
        let blocked = owner
            .call_account_deletion(&endpoint, Action::Submit)
            .await
            .unwrap();
        assert_eq!(blocked.status, Status::Blocked);
        assert!(blocked.owned_spaces[0].other_members);
        assert!(!host.account_requested(owner.identity_id()));
        let family_id = host.spaces.read().await.keys().next().unwrap().clone();
        owner.operate(json!({"op":"space_create","host":format!("{base}/spaces/v1/create"),"contact_email":"owner@example.test","message_lifetime_seconds":86400,"name":"Unrelated"})).await.unwrap();
        let other_id = host
            .spaces
            .read()
            .await
            .keys()
            .find(|id| **id != family_id)
            .unwrap()
            .clone();
        let backups = config.root.join("backups");
        private_directory(&backups).unwrap();
        for id in [&family_id, &other_id] {
            private_directory(&backups.join(id)).unwrap();
            vault::write_private(
                &backups.join(id).join("snapshot"),
                b"synthetic snapshot",
                false,
            )
            .unwrap();
        }
        assert_eq!(
            member
                .call_account_deletion(&endpoint, Action::Inspect)
                .await
                .unwrap()
                .status,
            Status::Ready
        );
        assert!(!host.account_requested(member.identity_id()));
        let accepted = member
            .call_account_deletion(&endpoint, Action::Submit)
            .await
            .unwrap();
        assert_eq!(accepted.status, Status::Pending);
        let receipt = protocol::Receipt {
            endpoint: format!("{base}{}", protocol::STATUS_PATH),
            id: accepted.request_id.clone().unwrap(),
        };
        assert!(!receipt.completed(true).await.unwrap());
        assert!(
            status(
                State(host.clone()),
                Json(ReceiptRequest {
                    receipt: "../config".into()
                })
            )
            .await
            .is_err()
        );
        assert!(
            status(
                State(host.clone()),
                Json(ReceiptRequest {
                    receipt: "ab".repeat(16)
                })
            )
            .await
            .is_err()
        );
        assert_eq!(
            member
                .call_account_deletion(&endpoint, Action::Submit)
                .await
                .unwrap()
                .request_id,
            accepted.request_id
        );
        assert!(
            member
                .operate(json!({"op":"space_join","link":invite}))
                .await
                .is_err()
        );
        server.abort();
        let _ = server.await;
        close_host(host).await;
        let host = Host::open(config.clone(), true).await.unwrap();
        tokio::time::timeout(Duration::from_secs(20), host.process_account_deletions())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            host.account_inspect(member.identity_id())
                .await
                .unwrap()
                .status,
            Status::Completed
        );
        let completion = status(
            State(host.clone()),
            Json(ReceiptRequest {
                receipt: receipt.id,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(completion, json!({"completed":true}));
        assert_eq!(host.spaces.read().await.len(), 2);
        let family = host.spaces.read().await.get(&family_id).unwrap().clone();
        assert!(
            !family
                .replica
                .has_account_content(member.identity_id())
                .await
                .unwrap()
        );
        assert!(
            family
                .replica
                .has_account_content(owner.identity_id())
                .await
                .unwrap()
        );
        assert!(
            family
                .replica
                .authorize_identity(family.mailbox, Some(member.identity_id()))
                .await
                .is_err()
        );
        assert!(!backups.join(&family_id).exists());
        assert_eq!(
            vault::read_private(&backups.join(&other_id).join("snapshot")).unwrap(),
            b"synthetic snapshot"
        );
        drop(family);
        member.close().await.unwrap();
        owner.close().await.unwrap();
        close_host(host).await;
    }
}

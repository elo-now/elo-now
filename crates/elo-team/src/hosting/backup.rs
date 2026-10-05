//! Loopback operator endpoints for complete, independently verifiable backups.
use super::*;
use subtle::ConstantTimeEq;

pub(super) fn load_key(path: Option<&FilePath>) -> Result<Option<Zeroizing<Vec<u8>>>> {
    path.map(|path| {
        let key = Zeroizing::new(vault::read_private(path)?);
        if key.len() != 64
            || !key
                .iter()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Invalid backup access key.".into());
        }
        Ok(key)
    })
    .transpose()
}

fn authorize(host: &Host, headers: &HeaderMap) -> std::result::Result<(), StatusCode> {
    let key = host
        .backup_access_key
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !bool::from(key.as_slice().ct_eq(presented.as_bytes())) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

pub(super) async fn inventory(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
) -> std::result::Result<Json<Value>, StatusCode> {
    authorize(&host, &headers)?;
    inventory_inner(&host).await
}

pub(super) async fn inventory_inner(host: &Host) -> std::result::Result<Json<Value>, StatusCode> {
    let _creation = host
        .creation
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let spaces = host.spaces.read().await;
    let allocated = host
        .allocations
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for id in allocated {
        if id.parse::<ObjectId>().is_err() {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        if spaces.contains_key(&id) {
            continue;
        }
        // Unpublished reservations have no attachment state to export. A
        // configured but unavailable Space still fails the complete snapshot.
        let path = host.config.root.join("spaces").join(&id);
        match std::fs::symlink_metadata(path.join("config.json")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
        }
        let reservation: Reservation = vault::read_private(&path.join("reservation.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&Zeroizing::new(bytes)).ok())
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        if reservation.invitation.is_some() || reservation.invitation_issued != 0 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    let mut result = BTreeMap::new();
    for (id, space) in spaces.iter() {
        if !*space.serving.read().await {
            continue;
        }
        let client = space
            .client
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let inventory = client
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            .attachment_backup_inventory()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        result.insert(id.clone(), inventory);
    }
    Ok(Json(json!({"version": 1, "spaces": result})))
}

pub(super) async fn download(
    State(host): State<Arc<Host>>,
    Path((id, object)): Path<(String, String)>,
    headers: HeaderMap,
) -> std::result::Result<axum::response::Response, StatusCode> {
    authorize(&host, &headers)?;
    download_inner(&host, &id, &object).await
}

pub(super) async fn download_inner(
    host: &Host,
    id: &str,
    object: &str,
) -> std::result::Result<axum::response::Response, StatusCode> {
    let _: ObjectId = id.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let _: elo_core::ids::AttachmentObjectId = object.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let space = host
        .spaces
        .read()
        .await
        .get(id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    if !*space.serving.read().await {
        return Err(StatusCode::GONE);
    }
    let size = {
        let client = space
            .client
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let inventory = client
            .as_ref()
            .ok_or(StatusCode::GONE)?
            .attachment_backup_inventory()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        inventory["objects"]
            .as_array()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            .iter()
            .find(|entry| entry["object"].as_str() == Some(object))
            .and_then(|entry| entry["size"].as_u64())
            .ok_or(StatusCode::NOT_FOUND)?
    };
    let storage = host
        .attachment_storage
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let stored = storage
        .get(id, object)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if stored.size != size {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Body::from_stream(stored.body),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn host(root: &FilePath, key: Option<&FilePath>) -> Arc<Host> {
        Host::open(
            serde_json::from_value(json!({
                "root": root, "public_url": "https://host.example.test",
                "max_spaces_per_identity": 2, "mailbox_quota_bytes": 150_000_000,
                "backup_access_key": key,
            }))
            .unwrap(),
            false,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn backup_endpoints_require_their_own_private_key() {
        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join("backup.key");
        vault::write_private(&key_path, "a".repeat(64).as_bytes(), false).unwrap();
        let enabled = host(&temp.path().join("enabled"), Some(&key_path)).await;
        assert_eq!(
            inventory(State(enabled.clone()), HeaderMap::new())
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            download(
                State(enabled.clone()),
                Path(("invalid".into(), "invalid".into())),
                HeaderMap::new()
            )
            .await
            .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "b".repeat(64)).parse().unwrap(),
        );
        assert_eq!(
            inventory(State(enabled.clone()), headers.clone())
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "a".repeat(64)).parse().unwrap(),
        );
        let Json(value) = inventory(State(enabled), headers).await.unwrap();
        assert_eq!(value, json!({"version": 1, "spaces": {}}));
        let disabled = host(&temp.path().join("disabled"), None).await;
        assert_eq!(
            inventory(State(disabled), HeaderMap::new())
                .await
                .unwrap_err(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn inventory_skips_only_unpublished_reservations_and_rejects_damaged_spaces() {
        let temp = tempfile::tempdir().unwrap();
        let host = host(&temp.path().join("host"), None).await;
        let id = "1".repeat(64);
        let directory = host.config.root.join("spaces").join(&id);
        private_directory(&directory).unwrap();
        let mut reservation = Reservation {
            creator: None,
            request_id: "synthetic".into(),
            name: "Unpublished".into(),
            contact_email: None,
            message_lifetime_seconds: 86_400,
            require_approval: true,
            mailbox: MailboxDescriptor::random().unwrap(),
            password: String::new(),
            authority: None,
            creation_evidence: None,
            invitation: None,
            invitation_issued: 0,
            reserved_at: 1,
            creation_network: None,
            reclaim_if_unclaimed: true,
        };
        save(&directory.join("reservation.json"), &reservation).unwrap();
        host.allocations.lock().unwrap().insert(id, None);
        assert!(inventory_inner(&host).await.is_ok());
        reservation.invitation = Some("already advertised".into());
        save(&directory.join("reservation.json"), &reservation).unwrap();
        assert_eq!(
            inventory_inner(&host).await.unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        reservation.invitation = None;
        save(&directory.join("reservation.json"), &reservation).unwrap();
        vault::write_private(&directory.join("config.json"), b"{damaged", false).unwrap();
        assert_eq!(
            inventory_inner(&host).await.unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}

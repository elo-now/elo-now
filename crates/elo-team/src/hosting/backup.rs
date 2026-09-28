//! Loopback operator endpoints for complete, independently verifiable backups.
use super::*;

pub(super) async fn inventory(
    State(host): State<Arc<Host>>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let _creation = host
        .creation
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let spaces = host.spaces.read().await;
    let allocated = host
        .allocations
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .len();
    // Missing or damaged services must not produce a falsely complete backup.
    if allocated != spaces.len() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
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
) -> std::result::Result<axum::response::Response, StatusCode> {
    let _: ObjectId = id.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let _: elo_core::ids::AttachmentObjectId = object.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let space = host
        .spaces
        .read()
        .await
        .get(&id)
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
            .find(|entry| entry["object"].as_str() == Some(&object))
            .and_then(|entry| entry["size"].as_u64())
            .ok_or(StatusCode::NOT_FOUND)?
    };
    let storage = host
        .attachment_storage
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let stored = storage
        .get(&id, &object)
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

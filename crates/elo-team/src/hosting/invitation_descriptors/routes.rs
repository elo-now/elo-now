use super::super::{Host, current};
use super::{Error, prepare};
use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use elo_core::ids::ObjectId;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::OwnedSemaphorePermit;

type HttpResult<T> = std::result::Result<T, StatusCode>;
fn status(error: Error) -> StatusCode {
    match error {
        Error::Invalid => StatusCode::BAD_REQUEST,
        Error::Unauthorized => StatusCode::FORBIDDEN,
        Error::Conflict => StatusCode::CONFLICT,
        Error::Missing => StatusCode::NOT_FOUND,
        Error::Limit => StatusCode::TOO_MANY_REQUESTS,
        Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}
fn source_ip(
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
) -> IpAddr {
    let ip = peer
        .map(|peer| peer.0.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    if ip.is_loopback() {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(ip)
    } else {
        ip
    }
}

pub(in crate::hosting) async fn upload(
    State(host): State<Arc<Host>>,
    Path(id): Path<String>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    request: Request,
) -> HttpResult<Response> {
    let store = host
        .invitation_store
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let gate = host.witness.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let pin = host.config.witness.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let id_value: ObjectId = id.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let ip = source_ip(peer, request.headers());
    let (_permit, request) = host
        .invitation_ingress
        .receive(ip, id_value, request)
        .await
        .map_err(status)?;
    let _accounts = host
        .accounts
        .try_read()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if host
        .account_scope_pending(&id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let space = host
        .spaces
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    let serving = space
        .serving
        .try_read()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !*serving {
        return Err(StatusCode::GONE);
    }
    let authority = {
        let guard = tokio::time::timeout(Duration::from_secs(2), space.client.lock())
            .await
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        guard
            .as_ref()
            .ok_or(StatusCode::GONE)?
            .witnessed_authority()
            .map_err(|_| StatusCode::FORBIDDEN)?
            .ok_or(StatusCode::FORBIDDEN)?
    };
    let lease = gate
        .require(&authority)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let expected = format!("{}/spaces/{id}/invitations/v1", host.config.public_url);
    let upload = prepare(
        request,
        &authority,
        pin,
        &expected,
        &lease,
        current().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    )
    .map_err(status)?;
    for (identity, credential) in [upload.uploader(), upload.policy_issuer()] {
        if host.account_requested(identity) {
            return Err(StatusCode::GONE);
        }
        if host
            .revocations
            .get(credential)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .is_some()
        {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    let guard = tokio::time::timeout(Duration::from_secs(2), space.client.lock())
        .await
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let client = guard.as_ref().ok_or(StatusCode::GONE)?;
    let authority = client
        .witnessed_authority()
        .map_err(|_| StatusCode::FORBIDDEN)?
        .ok_or(StatusCode::FORBIDDEN)?;
    let devices = client
        .space_access_devices()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !devices.contains(&upload.uploader().1) || !devices.contains(&upload.policy_issuer().1) {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut store = store.lock().await;
    gate.check(&authority, &lease)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let created = upload
        .commit(
            &mut store,
            &authority,
            &lease,
            current().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        )
        .map_err(status)?;
    Ok((if created {StatusCode::CREATED} else {StatusCode::OK},[(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"v":1,"ciphertext_id":upload.digest(),"ciphertext_expires_at_ms":upload.ciphertext_expires_at_ms()}))).into_response())
}

struct DownloadBytes {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for DownloadBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(in crate::hosting) async fn download(
    State(host): State<Arc<Host>>,
    Path(digest): Path<String>,
    peer: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> HttpResult<Response> {
    let store = host
        .invitation_store
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let digest: ObjectId = digest.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let permit = host
        .invitation_ingress
        .enter(source_ip(peer, &headers), None, Instant::now())
        .map_err(status)?;
    let bytes = {
        let mut store = store.lock().await;
        store
            .get(
                digest,
                current().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
            )
            .map_err(status)?
    };
    let length = bytes.len();
    // Retain admission until the final response buffer is released, including
    // slow clients; merely retaining it until the handler returns is insufficient.
    let bytes = bytes::Bytes::from_owner(DownloadBytes {
        bytes,
        _permit: permit,
    });
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&length.to_string()).expect("bounded content length"),
    );
    Ok(response)
}

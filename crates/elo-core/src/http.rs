//! Bounded local HTTP transport. TLS termination is required outside loopback.
use crate::{
    crypto::MAX_CIPHERTEXT,
    replica::{ReplicaError, ReplicaStore, TransferHint},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Extension, OriginalUri, Path, Query, Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
impl IntoResponse for ReplicaError {
    fn into_response(self) -> Response {
        if let Self::Pruned(ref proof) = self {
            return (
                StatusCode::GONE,
                [("content-type", "application/octet-stream")],
                proof.clone(),
            )
                .into_response();
        }
        let status = match self {
            Self::Pruned(_) => unreachable!(),
            Self::Expired => StatusCode::CONFLICT,
            Self::Unauthorized => StatusCode::FORBIDDEN,
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Quota => StatusCode::INSUFFICIENT_STORAGE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Storage | Self::Directory => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, self.to_string()).into_response()
    }
}
fn bearer(headers: &HeaderMap) -> Result<String, ReplicaError> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(ReplicaError::Unauthorized)?;
    if token.len() != 43 {
        return Err(ReplicaError::Unauthorized);
    }
    Ok(token.to_owned())
}
#[derive(Clone, Copy)]
struct AuthenticatedIdentity(Option<crate::ids::IdentityId>);
async fn authorize(
    State(store): State<ReplicaStore>,
    mut request: Request,
    next: Next,
) -> Response {
    let parts: Vec<_> = request.uri().path().split('/').collect();
    let mailbox = parts.get(3).and_then(|s| s.parse().ok());
    let result = match (mailbox, bearer(request.headers())) {
        (Some(id), Ok(token)) => {
            let identity = request
                .headers()
                .get("x-elo-identity")
                .map(|header| {
                    header.to_str().map_err(|_| ()).and_then(|value| {
                        crate::sync::access::verify(
                            value,
                            request.method().as_str(),
                            request
                                .extensions()
                                .get::<OriginalUri>()
                                .map(|original| &original.0)
                                .unwrap_or_else(|| request.uri())
                                .path_and_query()
                                .map(|p| p.as_str())
                                .unwrap_or(""),
                        )
                    })
                })
                .transpose();
            let identity = match identity {
                Ok(identity) => identity,
                Err(()) => return ReplicaError::Unauthorized.into_response(),
            };
            if let Err(error) = store.authorize_identity(id, identity).await {
                return error.into_response();
            }
            request
                .extensions_mut()
                .insert(AuthenticatedIdentity(identity));
            store
                .authorize(id, token, request.method() == Method::POST)
                .await
        }
        _ => Err(ReplicaError::Unauthorized),
    };
    match result {
        Ok(()) => next.run(request).await,
        Err(e) => e.into_response(),
    }
}
async fn bounded(State(slots): State<Arc<Semaphore>>, request: Request, next: Next) -> Response {
    let Ok(_permit) = slots.try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
        Ok(r) => r,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}
pub fn router(store: ReplicaStore) -> Router {
    let mailbox = Router::new()
        .route(
            "/v1/mailboxes/{mailbox}/objects/{object}",
            post(upload).get(download),
        )
        .route("/v1/mailboxes/{mailbox}/inventory", get(inventory))
        .route(
            "/v1/mailboxes/{mailbox}/messages/{object}/request",
            post(request_message).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/v1/mailboxes/{mailbox}/messages/{object}/accept",
            post(accept_message).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/v1/mailboxes/{mailbox}/children",
            post(create_child).layer(DefaultBodyLimit::max(4096)),
        )
        .route_layer(middleware::from_fn_with_state(store.clone(), authorize));
    Router::new()
        .merge(mailbox)
        .route("/v1/health", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_CIPHERTEXT))
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(8)),
            bounded,
        ))
        .with_state(store)
}

/// A stable per-Space namespace, including signed request paths. Nesting must
/// preserve OriginalUri so access proofs cannot be replayed in another Space.
pub fn space_router(store: ReplicaStore, reservation: crate::ids::ObjectId) -> Router {
    Router::new().nest(&format!("/spaces/{reservation}/replica"), router(store))
}
async fn create_child(
    State(store): State<ReplicaStore>,
    Path(mailbox): Path<String>,
    headers: HeaderMap,
    Json(child): Json<crate::replica::ChildMailbox>,
) -> Result<StatusCode, ReplicaError> {
    store
        .create_child(
            mailbox.parse().map_err(|_| ReplicaError::Invalid)?,
            bearer(&headers)?,
            child,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn upload(
    State(store): State<ReplicaStore>,
    Path((mailbox, object)): Path<(String, String)>,
    headers: HeaderMap,
    Extension(identity): Extension<AuthenticatedIdentity>,
    bytes: Bytes,
) -> Result<Response, ReplicaError> {
    let hint = match headers.get("x-elo-transfer").and_then(|h| h.to_str().ok()) {
        Some("eager") => TransferHint::Eager,
        Some("lazy") => TransferHint::Lazy,
        _ => return Err(ReplicaError::Invalid),
    };
    let message = match headers.get("x-elo-retention").map(|h| h.to_str()) {
        None | Some(Ok("retain")) => false,
        Some(Ok("message")) => true,
        _ => return Err(ReplicaError::Invalid),
    };
    let (inserted, receipt) = store
        .post_authenticated(
            mailbox.parse().map_err(|_| ReplicaError::Invalid)?,
            bearer(&headers)?,
            object.parse().map_err(|_| ReplicaError::Invalid)?,
            bytes.to_vec(),
            hint,
            message,
            identity.0,
        )
        .await?;
    Ok((
        if inserted {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        [("content-type", "application/octet-stream")],
        receipt,
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageControl {
    record_id: crate::ids::RecordId,
}
async fn request_message(
    State(store): State<ReplicaStore>,
    Path((mailbox, object)): Path<(String, String)>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Json(body): Json<MessageControl>,
) -> Result<StatusCode, ReplicaError> {
    store
        .request_message(
            mailbox.parse().map_err(|_| ReplicaError::Invalid)?,
            identity.0.ok_or(ReplicaError::Unauthorized)?,
            object.parse().map_err(|_| ReplicaError::Invalid)?,
            body.record_id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn accept_message(
    State(store): State<ReplicaStore>,
    Path((mailbox, object)): Path<(String, String)>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    Json(body): Json<MessageControl>,
) -> Result<StatusCode, ReplicaError> {
    store
        .accept_message(
            mailbox.parse().map_err(|_| ReplicaError::Invalid)?,
            identity.0.ok_or(ReplicaError::Unauthorized)?,
            object.parse().map_err(|_| ReplicaError::Invalid)?,
            body.record_id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn download(
    State(store): State<ReplicaStore>,
    Path((mailbox, object)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ReplicaError> {
    let bytes = store
        .get(
            mailbox.parse().map_err(|_| ReplicaError::Invalid)?,
            bearer(&headers)?,
            object.parse().map_err(|_| ReplicaError::Invalid)?,
        )
        .await?;
    Ok(([("content-type", "application/octet-stream")], bytes).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    #[serde(default)]
    after: u64,
    #[serde(default = "page_size")]
    limit: usize,
}
fn page_size() -> usize {
    128
}
async fn inventory(
    State(store): State<ReplicaStore>,
    Path(mailbox): Path<String>,
    Query(page): Query<Page>,
    headers: HeaderMap,
) -> Result<Json<crate::replica::Inventory>, ReplicaError> {
    Ok(Json(
        store
            .inventory(
                mailbox.parse().map_err(|_| ReplicaError::Invalid)?,
                bearer(&headers)?,
                page.after,
                page.limit,
            )
            .await?,
    ))
}
pub async fn local_listener(
    address: SocketAddr,
    allow_insecure_loopback: bool,
) -> Result<tokio::net::TcpListener, ReplicaError> {
    if !allow_insecure_loopback || !address.ip().is_loopback() {
        return Err(ReplicaError::Invalid);
    }
    Ok(tokio::net::TcpListener::bind(address).await?)
}
pub async fn serve(
    store: ReplicaStore,
    address: SocketAddr,
    allow_insecure_loopback: bool,
) -> Result<(), ReplicaError> {
    let listener = local_listener(address, allow_insecure_loopback).await?;
    axum::serve(listener, router(store))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

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
struct AuthenticatedIdentity(Option<crate::retention_access::Actor>);
async fn authorize(
    State((store, origin)): State<(ReplicaStore, String)>,
    mut request: Request,
    next: Next,
) -> Response {
    let parts: Vec<_> = request.uri().path().split('/').collect();
    let mailbox = parts.get(3).and_then(|s| s.parse().ok());
    let result = match (mailbox, bearer(request.headers())) {
        (Some(id), Ok(token)) => {
            // Reject random callers before parsing or verifying a public-key proof.
            if let Err(error) = store
                .authorize(id, token, request.method() == Method::POST)
                .await
            {
                return error.into_response();
            }
            let (parts, body) = request.into_parts();
            let bytes = match axum::body::to_bytes(body, MAX_CIPHERTEXT).await {
                Ok(bytes) => bytes,
                Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            };
            request = Request::from_parts(parts, axum::body::Body::from(bytes.clone()));
            let verified = request
                .headers()
                .get("x-elo-identity")
                .map(|header| {
                    let value = header.to_str().map_err(|_| ())?;
                    let context = crate::sync::access::RequestContext {
                        origin: &origin,
                        replica: store.key(),
                        method: request.method().as_str(),
                        path: request
                            .extensions()
                            .get::<OriginalUri>()
                            .map(|original| &original.0)
                            .unwrap_or_else(|| request.uri())
                            .path_and_query()
                            .map(|p| p.as_str())
                            .unwrap_or(""),
                        body: &bytes,
                        transfer: request
                            .headers()
                            .get("x-elo-transfer")
                            .map(|h| h.to_str())
                            .transpose()
                            .map_err(|_| ())?
                            .unwrap_or(""),
                        retention: request
                            .headers()
                            .get("x-elo-retention")
                            .map(|h| h.to_str())
                            .transpose()
                            .map_err(|_| ())?
                            .unwrap_or(""),
                    };
                    crate::sync::access::verify(value, &context)
                })
                .transpose();
            let verified = match verified {
                Ok(verified) => verified,
                Err(()) => return ReplicaError::Unauthorized.into_response(),
            };
            let actor = verified
                .as_ref()
                .map(|access| crate::retention_access::Actor {
                    identity: access.identity,
                    credential: access.credential,
                });
            let identity = actor.map(|actor| actor.identity);
            if let Some(access) = &verified {
                if access.companion {
                    if let Err(error) = store.require_admitted_companion(access.credential) {
                        return error.into_response();
                    }
                }
                if let Err(error) = store.require_active_device(access.credential) {
                    return error.into_response();
                }
            }
            if let Err(error) = store.authorize_identity(id, identity).await {
                return error.into_response();
            }
            if let Some(access) = verified {
                if let Err(error) = store.consume_access(access).await {
                    return error.into_response();
                }
            }
            request
                .extensions_mut()
                .insert(AuthenticatedIdentity(actor));
            Ok(())
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
/// The origin is operator configuration, never a Host or Forwarded header.
pub fn router(store: ReplicaStore, public_origin: &str) -> Router {
    let origin = reqwest::Url::parse(public_origin)
        .expect("validated replica public origin")
        .origin()
        .ascii_serialization();
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
        .route_layer(middleware::from_fn_with_state(
            (store.clone(), origin),
            authorize,
        ));
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
pub fn space_router(
    store: ReplicaStore,
    reservation: crate::ids::ObjectId,
    public_origin: &str,
) -> Router {
    Router::new().nest(
        &format!("/spaces/{reservation}/replica"),
        router(store, public_origin),
    )
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
use crate::retention_access::Control as MessageControl;
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
            body.proof,
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
            body.proof,
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
    public_origin: Option<String>,
) -> Result<(), ReplicaError> {
    let listener = local_listener(address, allow_insecure_loopback).await?;
    let origin = public_origin.unwrap_or(format!("http://{}", listener.local_addr()?));
    let parsed = reqwest::Url::parse(&origin).map_err(|_| ReplicaError::Invalid)?;
    if parsed.cannot_be_a_base()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || !(parsed.scheme() == "https"
            || allow_insecure_loopback
                && parsed.scheme() == "http"
                && matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")))
    {
        return Err(ReplicaError::Invalid);
    }
    axum::serve(listener, router(store, &origin))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

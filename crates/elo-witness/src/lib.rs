//! Independent authorization. Hosting is never an authority or freshness oracle.
pub mod engine;
pub mod journal;
pub mod server;
pub mod wire;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[error("Invalid witness request.")]
    Invalid,
    #[error("Witness authorization failed.")]
    Unauthorized,
    #[error("The witnessed state changed. Refresh and retry.")]
    Conflict,
    #[error("Witness limit reached.")]
    Limit,
    #[error("Witness record is unavailable.")]
    Missing,
    #[error("Witness recovery verification is required.")]
    RecoveryRequired,
    #[error("Witness is temporarily unavailable.")]
    Unavailable,
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}
impl From<elo_core::record::RecordError> for Error {
    fn from(_: elo_core::record::RecordError) -> Self {
        Self::Unauthorized
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let code = match self {
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::FORBIDDEN,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Limit => StatusCode::TOO_MANY_REQUESTS,
            Self::Missing => StatusCode::NOT_FOUND,
            Self::RecoveryRequired | Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (code, Json(serde_json::json!({"error":self}))).into_response()
    }
}
pub fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Unavailable)
}

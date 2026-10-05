//! Independent attachment broker. Provider credentials never enter elo-team.
pub mod engine;
mod freshness;
pub mod mega;
pub mod server;
pub mod storage;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[error("Invalid storage request.")]
    Invalid,
    #[error("Storage authorization failed.")]
    Unauthorized,
    #[error("Storage configuration changed. Refresh and retry.")]
    Conflict,
    #[error("Attachment storage is not configured.")]
    NotConfigured,
    #[error("Attachment storage limit reached.")]
    Limit,
    #[error("Attachment is unavailable.")]
    Missing,
    #[error("Attachment storage is temporarily unavailable.")]
    Unavailable,
}
pub type Result<T> = std::result::Result<T, Error>;
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::FORBIDDEN,
            Self::Conflict => StatusCode::CONFLICT,
            Self::NotConfigured => StatusCode::PRECONDITION_FAILED,
            Self::Limit => StatusCode::TOO_MANY_REQUESTS,
            Self::Missing => StatusCode::NOT_FOUND,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(serde_json::json!({"error": self}))).into_response()
    }
}
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

pub fn now() -> u64 {
    now_ms() / 1000
}
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

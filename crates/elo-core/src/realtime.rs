//! Opaque, bounded realtime hints. Durable mailbox synchronization remains authoritative.
use crate::{
    ids::{IdentityId, MailboxId, RecordId},
    replica::ReplicaStore,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, sync::Arc};

pub const HOST_PATH: &str = "/hosting/v1/realtime";
pub const PATH: &str = "/v1/realtime";
pub const MAX_FRAME: usize = 96 * 1024;
pub const MAX_ENVELOPE: usize = 64 * 1024;
pub const MAX_SUBSCRIPTIONS: usize = 64;

/// The proof signs this exact JSON serialization with method SUBSCRIBE,
/// the realtime endpoint path, and empty transfer/retention fields.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionRequest {
    pub id: String,
    pub replica: String,
    pub mailbox: MailboxId,
    pub read_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRequest {
    pub subscription: String,
    pub recipients: Vec<IdentityId>,
    pub envelope: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientFrame {
    Subscribe {
        request: SubscriptionRequest,
        proof: String,
    },
    Publish {
        request: PublicationRequest,
    },
    Unsubscribe {
        id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerFrame {
    Subscribed {
        id: String,
    },
    Changed {
        id: String,
    },
    Ephemeral {
        id: String,
        envelope: String,
        identity: IdentityId,
        credential: RecordId,
    },
    Revoked {
        id: String,
    },
    Error {
        code: String,
    },
}

/// Resolves a local replica namespace; implementations must never fetch a client URL.
pub trait Resolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        replica: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<ReplicaStore>> + Send + 'a>>;
}

mod server;
pub(crate) use server::Events;
pub use server::Server;

struct Standalone(ReplicaStore);
impl Resolver for Standalone {
    fn resolve<'a>(
        &'a self,
        replica: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<ReplicaStore>> + Send + 'a>> {
        Box::pin(async move { (replica == "/").then(|| self.0.clone()) })
    }
}

pub fn standalone(store: ReplicaStore, origin: &str) -> axum::Router {
    Server::new(origin, PATH, Arc::new(Standalone(store))).router()
}

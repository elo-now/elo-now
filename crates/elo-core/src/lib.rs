//! Local storage and bounded protocol primitives for the experimental elo.now profile.

pub mod identity;
pub mod ids;
pub mod record;
pub mod store;

pub mod crypto;
pub mod erasure;
pub mod message_retention;
pub mod retention_access;

pub mod client_policy;
pub mod hosting_profile;
pub mod http;
pub mod realtime;
pub mod replica;

pub mod sync;

pub mod demo;

pub mod authority;
pub mod calls;

pub mod invite;

pub mod history;

pub mod attachments;
pub mod files;

pub mod app;
pub mod vault;

pub(crate) mod notes;
pub mod owner_admission;
pub mod public_space;

pub mod witness;

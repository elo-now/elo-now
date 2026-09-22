//! Provider-independent attachment metadata and bounded client-side encryption.
pub mod crypto;
pub mod model;

pub use model::{
    ATTACHMENT_CHUNK_BYTES, AttachmentAvailability, AttachmentDescriptor, AttachmentEncryption,
    AttachmentPolicy, AttachmentRetention, MAX_ATTACHMENT_FILE_SIZE, MAX_SPACE_ATTACHMENT_STORAGE,
};

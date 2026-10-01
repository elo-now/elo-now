use crate::ids::{AttachmentId, RecordId};
use serde::Serialize;

/// Ephemeral upload activity for the current conversation's authorized readers.
/// Consumers must encrypt this metadata and treat delivery as best effort. The
/// attachment ID connects the temporary placeholder to the final file descriptor.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AttachmentActivity {
    Uploading {
        attachment_id: AttachmentId,
        name: String,
        size_bytes: u64,
        created_at_ms: u64,
    },
    Ready {
        attachment_id: AttachmentId,
        record: RecordId,
    },
    Cancelled {
        attachment_id: AttachmentId,
    },
    Interrupted {
        attachment_id: AttachmentId,
    },
}

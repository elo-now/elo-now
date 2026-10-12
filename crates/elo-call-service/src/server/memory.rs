//! Reserve worst-case transport storage before accepting a WebSocket upgrade.
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const DEFAULT_TRANSPORT_MEMORY_MIB: usize = 768;
// A 9 MiB wire limit can retain almost 18 MiB each in the growable frame
// buffer and fragmented-message collector. Allow the bounded typed request
// and socket bookkeeping too; verification/cache/event memory is separate.
pub const CONNECTION_MEMORY_MIB: usize = 48;
pub(super) const READ_BUFFER: usize = 8 * 1024;
pub(super) const WRITE_BUFFER: usize = 256 * 1024;

pub(super) struct Budget(Arc<Semaphore>);
impl Budget {
    pub(super) fn new(mib: usize) -> Result<Self, &'static str> {
        if !(CONNECTION_MEMORY_MIB..=65536).contains(&mib) {
            return Err("Call transport memory must be between 48 and 65536 MiB.");
        }
        Ok(Self(Arc::new(Semaphore::new(mib))))
    }
    pub(super) fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.0
            .clone()
            .try_acquire_many_owned(CONNECTION_MEMORY_MIB as u32)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservations_bound_fragment_buffers_across_identities_and_release_on_drop() {
        let budget = Budget::new(768).unwrap();
        let mut admitted = (0..16)
            .map(|_| budget.acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(budget.acquire().is_none());
        // Admission is global: changing profiles, IPs or authentication state
        // does not create another memory budget. Reconnect reuses freed storage.
        drop(admitted.pop());
        let replacement = budget.acquire().unwrap();
        assert!(budget.acquire().is_none());
        drop(admitted);
        drop(replacement);
        assert_eq!(budget.0.available_permits(), 768);
        assert!(Budget::new(47).is_err());
    }
}

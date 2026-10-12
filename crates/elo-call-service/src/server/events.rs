//! Filter before buffering so a noisy chat cannot disconnect unrelated calls.
use super::{Event, RecordId, Scope};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

pub(super) struct Events {
    next: AtomicU64,
    listeners: Mutex<BTreeMap<u64, Listener>>,
    bytes: Arc<Semaphore>,
}
const EVENT_MEMORY: usize = 64 * 1024 * 1024;
impl Default for Events {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(0),
            listeners: Mutex::new(BTreeMap::new()),
            bytes: Arc::new(Semaphore::new(EVENT_MEMORY)),
        }
    }
}
pub(super) struct BufferedEvent {
    event: Event,
    _memory: OwnedSemaphorePermit,
}
impl std::ops::Deref for BufferedEvent {
    type Target = Event;
    fn deref(&self) -> &Self::Target {
        &self.event
    }
}
// Count owned string allocations and conservatively allow node/allocator
// overhead for every entry. Subscribers share one event, never clone its maps.
fn event_bytes(event: &Event) -> usize {
    let owned = match event {
        Event::Signal {
            call_id,
            ciphertext,
            ..
        } => call_id.capacity() + ciphertext.capacity(),
        Event::Ended { call_id, .. } => call_id.capacity(),
        Event::Presence { call } => {
            call.call_id.capacity()
                + call.participants.len()
                    * (std::mem::size_of::<(elo_core::ids::IdentityId, crate::registry::Participant)>(
                    ) + 128)
                + call.invitations.len()
                    * (std::mem::size_of::<(elo_core::ids::IdentityId, crate::registry::Invitation)>(
                    ) + 128)
                + call
                    .participants
                    .values()
                    .map(|p| p.delegation.as_ref().map_or(0, String::capacity))
                    .sum::<usize>()
                + call
                    .invitations
                    .values()
                    .map(|i| i.invitation_id.capacity())
                    .sum::<usize>()
        }
    };
    owned.saturating_add(std::mem::size_of::<BufferedEvent>() + 256)
}
struct Listener {
    device: Option<RecordId>,
    scopes: BTreeSet<Scope>,
    sender: mpsc::Sender<Arc<BufferedEvent>>,
}
pub(super) struct Subscription {
    id: u64,
    bus: Arc<Events>,
    receiver: mpsc::Receiver<Arc<BufferedEvent>>,
}
impl Events {
    pub fn subscribe(self: &Arc<Self>) -> Subscription {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(64);
        self.listeners.lock().unwrap().insert(
            id,
            Listener {
                device: None,
                scopes: BTreeSet::new(),
                sender,
            },
        );
        Subscription {
            id,
            bus: self.clone(),
            receiver,
        }
    }
    pub fn send(&self, event: Event) {
        let scope = match &event {
            Event::Presence { call } => call.scope,
            Event::Ended { scope, .. } | Event::Signal { scope, .. } => *scope,
        };
        let size = event_bytes(&event);
        let mut listeners = self.listeners.lock().unwrap();
        let interested = |listener: &Listener| {
            listener.scopes.contains(&scope)
                && listener.device.is_some()
                && !matches!(&event, Event::Signal { to, .. } if Some(*to) != listener.device)
        };
        if !listeners.values().any(interested) {
            return;
        }
        let memory = u32::try_from(size)
            .ok()
            .and_then(|size| self.bytes.clone().try_acquire_many_owned(size).ok());
        let Some(memory) = memory else {
            // End only the affected subscriptions. Other chats keep capacity;
            // reconnecting readers request a fresh authenticated snapshot.
            listeners.retain(|_, listener| !interested(listener));
            return;
        };
        let event = Arc::new(BufferedEvent {
            event,
            _memory: memory,
        });
        listeners.retain(|_, listener| {
            if !listener.scopes.contains(&scope)
                || listener.device.is_none()
                || matches!(&**event, Event::Signal { to, .. } if Some(*to) != listener.device)
            {
                return true;
            }
            // Disconnect only the slow subscriber, which will fetch a snapshot.
            listener.sender.try_send(event.clone()).is_ok()
        });
    }
}
impl Subscription {
    pub fn update(&self, device: RecordId, scopes: &BTreeSet<Scope>) {
        if let Some(listener) = self.bus.listeners.lock().unwrap().get_mut(&self.id) {
            listener.device = Some(device);
            listener.scopes.clone_from(scopes);
        }
    }
    pub async fn recv(&mut self) -> Option<Arc<BufferedEvent>> {
        self.receiver.recv().await
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        self.bus.listeners.lock().unwrap().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope(byte: &str) -> Scope {
        Scope {
            hosting_space_id: byte.repeat(64).parse().unwrap(),
            conversation: elo_core::calls::CallScope {
                space_id: byte.repeat(64).parse().unwrap(),
                stream_id: "3".repeat(32).parse().unwrap(),
            },
        }
    }
    #[tokio::test]
    async fn saturation_is_isolated_to_subscribed_chats_and_connections_are_removed() {
        let bus = Arc::new(Events::default());
        let mut quiet = bus.subscribe();
        let mut noisy = bus.subscribe();
        let device = "4".repeat(64).parse().unwrap();
        quiet.update(device, &BTreeSet::from([scope("1")]));
        noisy.update(device, &BTreeSet::from([scope("2")]));
        for _ in 0..256 {
            bus.send(Event::Ended {
                scope: scope("2"),
                call_id: "a".repeat(32),
                reason: crate::registry::EndReason::Ended,
            });
        }
        bus.send(Event::Ended {
            scope: scope("1"),
            call_id: "b".repeat(32),
            reason: crate::registry::EndReason::Ended,
        });
        assert!(
            matches!(&**quiet.recv().await.unwrap(), Event::Ended { call_id, .. } if *call_id == "b".repeat(32))
        );
        for _ in 0..64 {
            assert!(noisy.recv().await.is_some());
        }
        assert!(noisy.recv().await.is_none());
        drop(quiet);
        assert!(bus.listeners.lock().unwrap().is_empty());
        assert_eq!(bus.bytes.available_permits(), EVENT_MEMORY);
    }

    #[tokio::test]
    async fn fanout_shares_one_allocation_until_every_consumer_releases_it() {
        let event = Event::Ended {
            scope: scope("1"),
            call_id: "a".repeat(32),
            reason: crate::registry::EndReason::Ended,
        };
        let cost = event_bytes(&event);
        let bus = Arc::new(Events {
            bytes: Arc::new(Semaphore::new(cost)),
            ..Events::default()
        });
        let mut first = bus.subscribe();
        let mut second = bus.subscribe();
        let device = "4".repeat(64).parse().unwrap();
        first.update(device, &BTreeSet::from([scope("1")]));
        second.update(device, &BTreeSet::from([scope("1")]));
        bus.send(event);
        assert_eq!(bus.bytes.available_permits(), 0);
        let a = first.recv().await.unwrap();
        let b = second.recv().await.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        drop(a);
        assert_eq!(bus.bytes.available_permits(), 0);
        drop(b);
        assert_eq!(bus.bytes.available_permits(), cost);
    }

    #[tokio::test]
    async fn byte_exhaustion_disconnects_only_the_affected_subscriptions() {
        let event = || Event::Signal {
            scope: scope("1"),
            call_id: "a".repeat(32),
            epoch: 1,
            from: "3".repeat(64).parse().unwrap(),
            to: "4".repeat(64).parse().unwrap(),
            ciphertext: "c".repeat(4096),
        };
        let cost = event_bytes(&event());
        let bus = Arc::new(Events {
            bytes: Arc::new(Semaphore::new(cost)),
            ..Events::default()
        });
        let mut noisy = bus.subscribe();
        let mut quiet = bus.subscribe();
        let device = "4".repeat(64).parse().unwrap();
        noisy.update(device, &BTreeSet::from([scope("1")]));
        quiet.update(device, &BTreeSet::from([scope("2")]));
        bus.send(event());
        bus.send(event());
        assert!(noisy.recv().await.is_some());
        assert!(noisy.recv().await.is_none());
        assert_eq!(bus.bytes.available_permits(), cost);
        bus.send(Event::Ended {
            scope: scope("2"),
            call_id: "b".repeat(32),
            reason: crate::registry::EndReason::Ended,
        });
        assert!(quiet.recv().await.is_some());
    }
}

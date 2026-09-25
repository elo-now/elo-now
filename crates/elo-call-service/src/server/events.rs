//! Filter before buffering so a noisy chat cannot disconnect unrelated calls.
use super::{Event, RecordId, Scope};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::mpsc;

#[derive(Default)]
pub(super) struct Events {
    next: AtomicU64,
    listeners: Mutex<BTreeMap<u64, Listener>>,
}
struct Listener {
    device: Option<RecordId>,
    scopes: BTreeSet<Scope>,
    sender: mpsc::Sender<Event>,
}
pub(super) struct Subscription {
    id: u64,
    bus: Arc<Events>,
    receiver: mpsc::Receiver<Event>,
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
        self.listeners.lock().unwrap().retain(|_, listener| {
            if !listener.scopes.contains(&scope)
                || listener.device.is_none()
                || matches!(&event, Event::Signal { to, .. } if Some(*to) != listener.device)
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
    pub async fn recv(&mut self) -> Option<Event> {
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
            });
        }
        bus.send(Event::Ended {
            scope: scope("1"),
            call_id: "b".repeat(32),
        });
        assert!(
            matches!(quiet.recv().await, Some(Event::Ended { call_id, .. }) if call_id == "b".repeat(32))
        );
        for _ in 0..64 {
            assert!(noisy.recv().await.is_some());
        }
        assert!(noisy.recv().await.is_none());
        drop(quiet);
        assert!(bus.listeners.lock().unwrap().is_empty());
    }
}

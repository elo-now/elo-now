//! Round-robin admission checks, with every active participant checked each turn.
use super::{RecordId, Scope, Service};
use elo_core::ids::IdentityId;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub(super) type Grants = BTreeMap<Scope, (RecordId, Instant)>;
pub(super) fn next_batch(
    scopes: &BTreeSet<Scope>,
    active: &BTreeSet<Scope>,
    cursor: &mut Option<Scope>,
) -> BTreeSet<Scope> {
    let mut selected = active.clone();
    let candidates = scopes
        .iter()
        .filter(|s| !active.contains(s))
        .copied()
        .collect::<Vec<_>>();
    let start = cursor
        .and_then(|last| candidates.iter().position(|scope| *scope > last))
        .unwrap_or(0);
    for offset in 0..32.min(candidates.len()) {
        let scope = candidates[(start + offset) % candidates.len()];
        selected.insert(scope);
        *cursor = Some(scope);
    }
    selected
}

pub(super) async fn admitted(
    service: &Service,
    grants: &mut Grants,
    scope: Scope,
    identity: IdentityId,
    device: RecordId,
    head: RecordId,
    force: bool,
) -> bool {
    if !force
        && grants.get(&scope).is_some_and(|(saved, checked)| {
            *saved == head && checked.elapsed() < Duration::from_secs(5)
        })
    {
        return true;
    }
    let started = Instant::now();
    let allowed = matches!(
        service
            .admission
            .device_allowed(
                scope.hosting_space_id,
                identity,
                device,
                scope.conversation,
                head
            )
            .await,
        Ok(true)
    );
    if allowed {
        grants.insert(scope, (head, started));
    } else {
        grants.remove(&scope);
    }
    allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope(n: u8) -> Scope {
        Scope {
            hosting_space_id: elo_core::ids::SpaceId::from_bytes([1; 32]),
            conversation: elo_core::calls::CallScope {
                space_id: elo_core::ids::SpaceId::from_bytes([2; 32]),
                stream_id: elo_core::ids::StreamId::from_bytes([n; 16]),
            },
        }
    }
    #[test]
    fn idle_checks_rotate_without_starving_an_active_call_or_later_chats() {
        let scopes = (0..100).map(scope).collect::<BTreeSet<_>>();
        let active = BTreeSet::from([scope(99)]);
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        for _ in 0..4 {
            let batch = next_batch(&scopes, &active, &mut cursor);
            assert!(batch.contains(&scope(99)));
            assert_eq!(batch.len(), 33);
            seen.extend(batch);
        }
        assert_eq!(seen, scopes);
        assert!(next_batch(&BTreeSet::new(), &BTreeSet::new(), &mut cursor).is_empty());
        assert_eq!(next_batch(&active, &active, &mut cursor), active);
    }
}

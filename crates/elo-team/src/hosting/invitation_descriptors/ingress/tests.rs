use super::*;
use axum::body::Body;
use std::sync::atomic::{AtomicUsize, Ordering};
fn ip(last: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, last))
}
fn observed_body(polled: Arc<AtomicUsize>) -> Body {
    Body::from_stream(futures_util::stream::poll_fn(move |_| {
        polled.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Pending::<Option<std::result::Result<bytes::Bytes, std::io::Error>>>
    }))
}
fn request(body: Body) -> Request {
    Request::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn occupied_slots_and_network_budget_reject_before_body_poll() {
    let ingress = Ingress::new();
    let now = Instant::now();
    let permits: Vec<_> = (0..4)
        .map(|i| ingress.enter(ip(i), None, now).unwrap())
        .collect();
    let polled = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        ingress
            .receive(
                ip(99),
                ObjectId::from_bytes([1; 32]),
                request(observed_body(polled.clone()))
            )
            .await,
        Err(Error::Limit)
    ));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    drop(permits);
    for _ in 0..30 {
        drop(ingress.enter(ip(200), None, now).unwrap());
    }
    assert!(matches!(
        ingress
            .receive(
                ip(200),
                ObjectId::from_bytes([1; 32]),
                request(observed_body(polled.clone()))
            )
            .await,
        Err(Error::Limit)
    ));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    assert!(ingress.enter(ip(99), None, now).is_ok());
}

#[tokio::test(start_paused = true)]
async fn oversized_and_stalled_bodies_are_bounded_and_release_the_slot() {
    let ingress = Ingress::new();
    let polled = Arc::new(AtomicUsize::new(0));
    let mut oversized = request(observed_body(polled.clone()));
    oversized.headers_mut().insert(
        header::CONTENT_LENGTH,
        (MAX_REQUEST_BYTES + 1).to_string().parse().unwrap(),
    );
    assert!(matches!(
        ingress
            .receive(ip(1), ObjectId::from_bytes([1; 32]), oversized)
            .await,
        Err(Error::Invalid)
    ));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        ingress
            .receive(
                ip(2),
                ObjectId::from_bytes([2; 32]),
                request(observed_body(polled))
            )
            .await,
        Err(Error::Invalid)
    ));
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert_eq!(ingress.slots.available_permits(), 4);
    let body = Body::from(vec![b'x'; MAX_REQUEST_BYTES + 1]);
    assert!(matches!(
        ingress
            .receive(ip(3), ObjectId::from_bytes([3; 32]), request(body))
            .await,
        Err(Error::Invalid)
    ));
    assert_eq!(ingress.slots.available_permits(), 4);
}

#[test]
fn ipv6_prefix_and_mapped_ipv4_cannot_bypass_network_limits() {
    assert_eq!(
        network("::ffff:198.51.100.2".parse().unwrap()),
        network(ip(2))
    );
    let ingress = Ingress::new();
    let now = Instant::now();
    for index in 0..30 {
        let peer = format!("2001:db8:1:2::{index:x}").parse().unwrap();
        drop(ingress.enter(peer, None, now).unwrap());
    }
    assert!(matches!(
        ingress.enter("2001:db8:1:2::ffff".parse().unwrap(), None, now),
        Err(Error::Limit)
    ));
    assert!(
        ingress
            .enter("2001:db8:1:3::1".parse().unwrap(), None, now)
            .is_ok()
    );
    assert!(
        ingress
            .enter(
                "2001:db8:1:2::ffff".parse().unwrap(),
                None,
                now + Duration::from_secs(60)
            )
            .is_ok()
    );
}

#[test]
fn rotating_networks_cannot_escape_global_or_space_budget() {
    let ingress = Ingress::new();
    let now = Instant::now();
    let space = ObjectId::from_bytes([1; 32]);
    for index in 0..30 {
        drop(ingress.enter(ip(index), Some(space), now).unwrap());
    }
    assert!(matches!(
        ingress.enter(ip(50), Some(space), now),
        Err(Error::Limit)
    ));
    let ingress = Ingress::new();
    for index in 0..240 {
        drop(ingress.enter(ip(index), None, now).unwrap());
    }
    assert!(matches!(
        ingress.enter(ip(250), None, now),
        Err(Error::Limit)
    ));
    assert!(ingress.budgets.lock().unwrap().networks.len() <= 240);
}

//! Bounded, opt-in live error delivery. No profile credentials or raw errors.
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch};

const CAPACITY: usize = 64;
const BREADCRUMBS: usize = 12;
const MAX_AGE: u64 = 7 * 24 * 3600;
const MAX_FILE: u64 = 256 * 1024;
static CLIENT: OnceLock<Client> = OnceLock::new();
struct Client {
    events: mpsc::Sender<Event>,
    choice: watch::Sender<Consent>,
}

#[derive(Clone, Copy)]
struct Consent {
    enabled: bool,
    purge: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Event {
    kind: String,
    source: String,
    code: String,
    elapsed_ms: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Report {
    id: String,
    created_at: u64,
    event: Event,
    breadcrumbs: Vec<Event>,
}
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Queue {
    reports: VecDeque<Report>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn valid_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn valid_event(e: &Event) -> bool {
    matches!(e.kind.as_str(), "error" | "event")
        && super::allowed(&e.source, &e.code)
        && e.elapsed_ms.is_none_or(|n| n <= 600_000)
}
impl Queue {
    fn prune(&mut self, time: u64) {
        self.reports.retain(|r| {
            valid_id(&r.id)
                && r.created_at <= time.saturating_add(300)
                && time.saturating_sub(r.created_at) <= MAX_AGE
                && r.event.kind == "error"
                && valid_event(&r.event)
                && r.breadcrumbs.len() <= BREADCRUMBS
                && r.breadcrumbs.iter().all(valid_event)
        });
        while self.reports.len() > CAPACITY {
            self.reports.pop_front();
        }
    }
    fn load(path: &std::path::Path, enabled: bool, time: u64) -> Self {
        if !enabled {
            let _ = std::fs::remove_file(path);
            return Self::default();
        }
        let mut queue = std::fs::metadata(path)
            .ok()
            .filter(|m| m.len() <= MAX_FILE)
            .and_then(|_| std::fs::read(path).ok())
            .and_then(|b| serde_json::from_slice::<Self>(&b).ok())
            .unwrap_or_default();
        queue.prune(time);
        queue
    }
    fn save(&self, path: &std::path::Path) {
        if self.reports.is_empty() {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(path.with_extension("tmp"));
            return;
        }
        let Ok(bytes) = serde_json::to_vec(self) else {
            return;
        };
        if bytes.len() as u64 > MAX_FILE {
            return;
        }
        let temporary = path.with_extension("tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if let Ok(mut file) = options.open(&temporary) {
            use std::io::Write;
            if file.write_all(&bytes).is_ok() && file.sync_all().is_ok() {
                let _ = std::fs::rename(&temporary, path);
            }
        }
    }
    fn push(&mut self, event: Event, breadcrumbs: &VecDeque<Event>) {
        let mut random = [0u8; 16];
        if getrandom::fill(&mut random).is_err() {
            return;
        }
        self.reports.push_back(Report {
            id: random.iter().map(|b| format!("{b:02x}")).collect(),
            created_at: now(),
            event,
            breadcrumbs: breadcrumbs.iter().cloned().collect(),
        });
        self.prune(now());
    }
}

fn endpoint() -> Option<&'static str> {
    let value = option_env!("ELO_LIVE_DIAGNOSTICS_URL")?;
    let url = reqwest::Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(value)
}
pub(super) fn available() -> bool {
    endpoint().is_some()
}
pub(super) fn configure(enabled: bool) {
    if let Some(client) = CLIENT.get() {
        client.choice.send_modify(|choice| {
            choice.enabled = enabled;
            if !enabled {
                choice.purge = choice.purge.wrapping_add(1);
            }
        });
    }
}
pub(super) fn record(value: &serde_json::Value) {
    let Some(client) = CLIENT.get() else {
        return;
    };
    if !client.choice.borrow().enabled {
        return;
    }
    if let Ok(event) = serde_json::from_value::<Event>(value.clone()) {
        if valid_event(&event) {
            let _ = client.events.try_send(event);
        }
    }
}
pub(super) fn setup(directory: PathBuf, enabled: bool, installation: String, version: String) {
    let Some(endpoint) = endpoint() else {
        return;
    };
    let (events, receiver) = mpsc::channel(CAPACITY);
    let (choice, changes) = watch::channel(Consent { enabled, purge: 0 });
    if CLIENT.set(Client { events, choice }).is_err() {
        return;
    }
    tauri::async_runtime::spawn(run(
        directory.join("beta-live-reports.json"),
        installation,
        version,
        endpoint.to_owned(),
        receiver,
        changes,
    ));
}

async fn run(
    path: PathBuf,
    installation: String,
    version: String,
    endpoint: String,
    mut events: mpsc::Receiver<Event>,
    mut choice: watch::Receiver<Consent>,
) {
    let Ok(http) = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return;
    };
    let mut consent = *choice.borrow_and_update();
    let mut queue = Queue::load(&path, consent.enabled && consent.purge == 0, now());
    let mut breadcrumbs = VecDeque::new();
    let mut retry = 2u64;
    let mut next = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { biased;
            changed = choice.changed() => {
                if changed.is_err() { return; }
                let updated = *choice.borrow_and_update();
                if !updated.enabled || updated.purge != consent.purge { queue.reports.clear(); breadcrumbs.clear(); while events.try_recv().is_ok() {} queue.save(&path); }
                consent = updated;
                retry = 2; next = tokio::time::Instant::now();
            }
            event = events.recv() => {
                let Some(event) = event else { return; };
                if !consent.enabled { continue; }
                if event.kind == "error" { queue.push(event, &breadcrumbs); queue.save(&path); }
                else { breadcrumbs.push_back(event); while breadcrumbs.len() > BREADCRUMBS { breadcrumbs.pop_front(); } }
            }
            _ = tick.tick(), if consent.enabled => {
                if queue.reports.is_empty() || tokio::time::Instant::now() < next { continue; }
                queue.prune(now());
                let Some(report) = queue.reports.front().cloned() else { queue.save(&path); continue; };
                let body = serde_json::json!({"schema":1,"installation":installation,
                    "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
                    "version":version,"build":option_env!("ELO_DIAGNOSTICS_BUILD").unwrap_or("unknown"),
                    "report":report});
                // Cancellation drops the request as soon as consent changes. A request
                // already received by the server cannot be recalled by turning Debug off.
                let response = tokio::select! { biased;
                    changed = choice.changed() => {
                        if changed.is_err() { return; }
                        let updated = *choice.borrow_and_update();
                        if !updated.enabled || updated.purge != consent.purge { queue.reports.clear(); breadcrumbs.clear(); while events.try_recv().is_ok() {} queue.save(&path); }
                        consent = updated;
                        continue;
                    }
                    result = http.post(&endpoint).json(&body).send() => result,
                };
                let acknowledged = response.as_ref().is_ok_and(|r| r.status() == reqwest::StatusCode::NO_CONTENT);
                let invalid = response.as_ref().is_ok_and(|r| matches!(r.status().as_u16(), 400 | 413 | 422));
                if acknowledged || invalid {
                    queue.reports.pop_front(); queue.save(&path); retry = 2;
                    next = tokio::time::Instant::now() + Duration::from_secs(1);
                } else {
                    next = tokio::time::Instant::now() + Duration::from_secs(retry);
                    retry = (retry * 2).min(300);
                }
                // Never report delivery failures through diagnostics itself.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> Event {
        Event {
            kind: "error".into(),
            source: "test".into(),
            code: "diagnostics_test".into(),
            elapsed_ms: None,
        }
    }
    #[test]
    fn offline_queue_is_bounded_survives_restart_and_is_removed_on_opt_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let mut q = Queue::default();
        for _ in 0..100 {
            q.push(event(), &VecDeque::new());
        }
        assert_eq!(q.reports.len(), CAPACITY);
        q.save(&path);
        assert_eq!(Queue::load(&path, true, now()).reports.len(), CAPACITY);
        assert!(Queue::load(&path, false, now()).reports.is_empty());
        assert!(!path.exists());
    }
    #[test]
    fn stale_and_tampered_reports_are_never_replayed() {
        let mut q = Queue::default();
        q.push(event(), &VecDeque::new());
        q.reports[0].created_at = 1;
        q.prune(MAX_AGE + 2);
        assert!(q.reports.is_empty());
        q.push(event(), &VecDeque::new());
        q.reports[0].event.code = "https://private.example/token".into();
        q.prune(now());
        assert!(q.reports.is_empty());
    }
    #[test]
    fn raw_payload_fields_and_corrupt_queues_are_rejected() {
        assert!(serde_json::from_value::<Event>(serde_json::json!({"kind":"error","source":"test","code":"diagnostics_test","elapsed_ms":null,"password":"secret"})).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        std::fs::write(&path, vec![b'x'; MAX_FILE as usize + 1]).unwrap();
        assert!(Queue::load(&path, true, now()).reports.is_empty());
    }
    #[tokio::test]
    async fn failed_upload_retries_and_delivers_without_restart() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut reports = Vec::new();
            for status in ["503 Service Unavailable", "204 No Content"] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut block = [0u8; 4096];
                loop {
                    let size = stream.read(&mut block).unwrap();
                    assert!(size > 0);
                    bytes.extend_from_slice(&block[..size]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                        let length: usize = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if bytes.len() >= end + 4 + length {
                            reports.push(
                                serde_json::from_slice::<serde_json::Value>(
                                    &bytes[end + 4..end + 4 + length],
                                )
                                .unwrap(),
                            );
                            break;
                        }
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
            reports
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let (tx, rx) = mpsc::channel(64);
        let (_control, choice) = watch::channel(Consent {
            enabled: true,
            purge: 0,
        });
        let worker = tokio::spawn(run(
            path.clone(),
            "a".repeat(32),
            "1.0.6".into(),
            endpoint,
            rx,
            choice,
        ));
        tx.send(event()).await.unwrap();
        let reports = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || server.join().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0]["report"]["id"], reports[1]["report"]["id"]);
        assert_eq!(reports[1]["report"]["event"]["code"], "diagnostics_test");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!path.exists());
        worker.abort();
    }
    #[tokio::test]
    async fn rapid_opt_out_and_back_in_does_not_replay_the_old_queue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let mut q = Queue::default();
        q.push(event(), &VecDeque::new());
        q.save(&path);
        let (_tx, rx) = mpsc::channel(64);
        let (control, choice) = watch::channel(Consent {
            enabled: true,
            purge: 0,
        });
        control.send_replace(Consent {
            enabled: false,
            purge: 1,
        });
        control.send_replace(Consent {
            enabled: true,
            purge: 1,
        });
        let worker = tokio::spawn(run(
            path.clone(),
            "a".repeat(32),
            "1.0.6".into(),
            "http://127.0.0.1:9".into(),
            rx,
            choice,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!path.exists());
        worker.abort();
    }
}

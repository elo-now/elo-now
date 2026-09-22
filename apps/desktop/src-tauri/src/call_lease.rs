//! A direct call's signed participant lease must outlive suspended WebView timers.
//! This socket carries no media and never authorizes an operation without a fresh
//! signature and the server's current admission check.
use futures_util::{Sink, SinkExt, StreamExt};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use std::{future::Future, time::Duration};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

pub(crate) trait Driver: Send {
    fn signed(&mut self, operation: &'static str)
    -> impl Future<Output = Result<Value, ()>> + Send;
    fn live(&mut self) -> impl Future<Output = bool> + Send;
    fn renewed(&mut self) -> impl Future<Output = ()> + Send {
        async {}
    }
    fn finished(&mut self, reason: &'static str) -> impl Future<Output = ()> + Send;
}

pub(crate) struct Target {
    pub url: String,
    pub call_id: String,
    pub scope: Value,
    pub identity: String,
}

impl Target {
    fn ended(&self, event: &Value) -> bool {
        match event["type"].as_str() {
            Some("ended") => event["scope"] == self.scope && event["call_id"] == self.call_id,
            Some("access_revoked") => event["scope"] == self.scope,
            Some("presence") => {
                let call = &event["call"];
                call["scope"] == self.scope
                    && call["call_id"] == self.call_id
                    && !self.admitted(call)
            }
            _ => false,
        }
    }
    fn admitted(&self, call: &Value) -> bool {
        call["call_id"] == self.call_id
            && call["scope"] == self.scope
            && call["kind"] == "direct"
            && call["participants"].as_object().is_some_and(|people| {
                people.len() == 2 && people.values().any(|p| p["identity_id"] == self.identity)
            })
    }
}

pub(crate) async fn run(mut driver: impl Driver, target: Target) {
    let result = maintain(
        &mut driver,
        &target,
        Duration::from_secs(5),
        Duration::from_secs(12),
    )
    .await;
    driver.finished(result.err().unwrap_or("local_end")).await;
}

async fn send(
    socket: &mut (impl Sink<Message> + Unpin),
    message: Message,
) -> Result<(), &'static str> {
    tokio::time::timeout(Duration::from_secs(4), socket.send(message))
        .await
        .map_err(|_| "send_timeout")?
        .map_err(|_| "unavailable")
}

async fn maintain(
    driver: &mut impl Driver,
    target: &Target,
    interval: Duration,
    deadline: Duration,
) -> Result<(), &'static str> {
    // Sign before connecting so a busy local profile cannot consume the socket's
    // unauthenticated deadline. There are no cached credentials or pre-signed leases.
    let first = tokio::time::timeout(deadline, driver.signed("heartbeat"))
        .await
        .map_err(|_| "sign_timeout")?
        .map_err(|_| "unauthorized")?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(2 * 1024 * 1024))
        .max_frame_size(Some(2 * 1024 * 1024));
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(8),
        connect_async_with_config(&target.url, Some(config), true),
    )
    .await
    .map_err(|_| "connect_timeout")?
    .map_err(|_| "unavailable")?;
    send(&mut socket, Message::Text(first.to_string().into())).await?;
    let timer = tokio::time::sleep(interval);
    tokio::pin!(timer);
    let health = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(health);
    let reply = tokio::time::sleep(deadline);
    tokio::pin!(reply);
    let mut waiting = true;
    loop {
        tokio::select! {
            message = socket.next() => {
                let message = message.ok_or("unavailable")?.map_err(|_| "unavailable")?;
                let event: Value = match message {
                    Message::Text(text) => serde_json::from_str(&text).map_err(|_| "invalid")?,
                    Message::Ping(bytes) => {
                        send(&mut socket, Message::Pong(bytes)).await?;
                        continue;
                    }
                    Message::Pong(_) => continue,
                    _ => return Err("unavailable"),
                };
                if target.ended(&event) { return Err("remote_end"); }
                if event["type"] == "error" { return Err("admission_failed"); }
                if event["type"] == "result" && waiting {
                    if !target.admitted(&event["call"]) { return Err("unauthorized"); }
                    driver.renewed().await;
                    waiting = false;
                    timer.as_mut().reset(tokio::time::Instant::now() + interval);
                }
                // The primary control socket continues to deliver encrypted
                // signaling to the shared controller; never log or buffer it here.
            }
            _ = &mut timer, if !waiting => {
                let signed = tokio::time::timeout(deadline, driver.signed("heartbeat")).await
                    .map_err(|_| "sign_timeout")?.map_err(|_| "unauthorized")?;
                send(&mut socket, Message::Text(signed.to_string().into())).await?;
                waiting = true;
                reply.as_mut().reset(tokio::time::Instant::now() + deadline);
            }
            _ = &mut reply, if waiting => return Err("heartbeat_timeout"),
            _ = &mut health => {
                let live = tokio::time::timeout(Duration::from_secs(3), driver.live()).await
                    .map_err(|_| "media_timeout")?;
                if !live {
                    // System End has already stopped capture. Relay the end even
                    // if the WebView cannot consume the native action yet.
                    if let Ok(Ok(signed)) = tokio::time::timeout(Duration::from_secs(2), driver.signed("leave")).await {
                        let _ = tokio::time::timeout(Duration::from_secs(2), socket.send(Message::Text(signed.to_string().into()))).await;
                    }
                    return Ok(());
                }
                health.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    struct TestDriver {
        live: Arc<AtomicBool>,
        signed: Arc<AtomicUsize>,
        finished: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl Driver for TestDriver {
        async fn signed(&mut self, operation: &'static str) -> Result<Value, ()> {
            self.signed.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"operation":operation}))
        }
        async fn live(&mut self) -> bool {
            self.live.load(Ordering::SeqCst)
        }
        async fn finished(&mut self, reason: &'static str) {
            self.finished.lock().unwrap().push(reason.into());
        }
    }
    fn target(url: String) -> Target {
        Target {
            url,
            call_id: "call".into(),
            identity: "self".into(),
            scope: json!({"scope":"one"}),
        }
    }
    fn call() -> Value {
        json!({"call_id":"call","scope":{"scope":"one"},"kind":"direct","participants":{
            "self":{"identity_id":"self"},"peer":{"identity_id":"peer"}
        }})
    }
    #[tokio::test]
    async fn native_lease_renews_without_ui_and_remote_end_finishes_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            for _ in 0..4 {
                let request = socket.next().await.unwrap().unwrap().into_text().unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&request).unwrap()["operation"],
                    "heartbeat"
                );
                socket
                    .send(Message::Text(
                        json!({"type":"result","call":call()}).to_string().into(),
                    ))
                    .await
                    .unwrap();
                socket
                    .send(Message::Text(
                        json!({"type":"ended","scope":{"scope":"unrelated"},"call_id":"other"})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
            socket
                .send(Message::Text(
                    json!({"type":"ended","scope":{"scope":"one"},"call_id":"call"})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
        });
        let count = Arc::new(AtomicUsize::new(0));
        let mut driver = TestDriver {
            live: Arc::new(AtomicBool::new(true)),
            signed: count.clone(),
            finished: Default::default(),
        };
        assert_eq!(
            maintain(
                &mut driver,
                &target(url),
                Duration::from_millis(20),
                Duration::from_secs(2)
            )
            .await,
            Err("remote_end")
        );
        assert_eq!(count.load(Ordering::SeqCst), 4);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn native_lease_fails_closed_when_admission_is_lost() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            socket.next().await.unwrap().unwrap();
            socket
                .send(Message::Text(
                    json!({"type":"error","code":"unauthorized"})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
        });
        let driver = TestDriver {
            live: Arc::new(AtomicBool::new(true)),
            signed: Arc::new(AtomicUsize::new(0)),
            finished: Default::default(),
        };
        let finished = driver.finished.clone();
        run(driver, target(url)).await;
        assert_eq!(*finished.lock().unwrap(), vec!["admission_failed"]);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn native_end_sends_leave_without_waiting_for_ui() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            socket.next().await.unwrap().unwrap();
            socket
                .send(Message::Text(
                    json!({"type":"result","call":call()}).to_string().into(),
                ))
                .await
                .unwrap();
            let request = socket.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&request).unwrap()["operation"],
                "leave"
            );
        });
        let mut driver = TestDriver {
            live: Arc::new(AtomicBool::new(false)),
            signed: Arc::new(AtomicUsize::new(0)),
            finished: Default::default(),
        };
        assert_eq!(
            maintain(
                &mut driver,
                &target(url),
                Duration::from_secs(5),
                Duration::from_secs(2)
            )
            .await,
            Ok(())
        );
        server.await.unwrap();
    }
}

use super::*;

#[derive(Clone, Copy, Debug)]
enum Scenario {
    LeaderRotate,
    FollowerKeys,
    LeaderKeySwap,
    Revoke,
    SameEpochMembership,
    InvalidProvider,
    EncryptionFailure,
    Reconnect,
}

fn target(local: &str) -> Target {
    Target {
        url: String::new(),
        call_id: "session".into(),
        context: json!({"kind":"group","expected_identity":local,"credential":local,
            "config_id":"head","hosting_space_id":"host","space":"space","stream":"chat",
            "members":{"a":["a"],"b":["b"],"c":["c"]}}),
    }
}
fn call(epoch: u64, members: &[&str]) -> Value {
    let mut people = json!({});
    for member in members {
        people[member] = json!({"identity_id":member,"credential_id":member,
            "media":{"audio_muted":true,"video_published":false,"screen_published":false}});
    }
    json!({"call_id":"session","scope":target("a").scope(),"kind":"group","config_id":"head",
        "participants":people,"key_epoch":epoch})
}
fn signal(from: &str, to: &str, epoch: u64, nonce: &str, key: &str) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let clear = json!({"from":from,"to":to,"config_id":"head","call_id":"session","epoch":epoch,
        "nonce":nonce,"expires_at":now+60,"payload":{"type":"media_key","epoch":epoch,"key":key}});
    json!({"type":"signal","scope":target("a").scope(),"call_id":"session","epoch":epoch,
        "from":from,"to":to,"ciphertext":clear.to_string()})
}
struct TestDriver {
    media: Vec<Value>,
    sealed: Vec<Value>,
    opened: Vec<Value>,
    starts: tokio::sync::mpsc::Sender<Value>,
    fail_encryption: bool,
}
impl Driver for TestDriver {
    async fn operation(&mut self, op: &str, fields: Value) -> Result<Value> {
        Ok(match op {
            "call_authorization" => json!({"command":fields["operation"],"proof":"synthetic"}),
            "call_encrypt_signal" => {
                self.sealed.push(fields.clone());
                json!({"ciphertext":fields["payload"].to_string()})
            }
            "call_open_signal" => {
                self.opened.push(fields.clone());
                json!({"signal":serde_json::from_str::<Value>(fields["ciphertext"].as_str().unwrap()).unwrap()})
            }
            _ => panic!("Unexpected operation"),
        })
    }
    async fn media(&mut self, request: Value) -> Result<Value> {
        self.media.push(request.clone());
        if request["op"] == "group_start" {
            self.starts.send(request.clone()).await.unwrap();
        }
        Ok(if request["op"] == "poll" {
            json!({"connection":"connected","media":{},"encryption_error":self.fail_encryption})
        } else {
            json!({})
        })
    }
    async fn changed(&mut self, _: &Value, _: bool) -> Result<()> {
        Ok(())
    }
    fn live(&self) -> bool {
        true
    }
}
async fn exercise(local: &str, scenario: Scenario) -> (Result<()>, TestDriver) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut target = target(local);
    target.url = format!("ws://{}", listener.local_addr().unwrap());
    let (starts, mut started) = tokio::sync::mpsc::channel::<Value>(8);
    let scope = target.scope();
    let local = local.to_string();
    let server = tokio::spawn(async move {
        let mut current = call(1, &["a", "b", "c"]);
        let mut signal_count = 0;
        let mut connection = 0;
        let mut revoked = false;
        loop {
            connection += 1;
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            loop {
                tokio::select! {
                    request = socket.next() => {
                        let Some(Ok(Message::Text(request))) = request else { break; };
                        let request: Value = serde_json::from_str(&request).unwrap();
                        let op = &request["command"];
                        // Revoke while a key signal is in flight. The worker
                        // verifies authorization again after a rejected signal;
                        // a real revoked scope also rejects that heartbeat.
                        if matches!(scenario, Scenario::Revoke) && op["type"] == "signal" {
                            revoked = true;
                        }
                        if revoked && op["type"] != "leave" {
                            socket.send(Message::Text(json!({"type":"access_revoked","scope":scope}).to_string().into())).await.unwrap();
                            continue;
                        }
                        let media = if op["type"] == "connect_media" {
                            json!({"provider":if matches!(scenario,Scenario::InvalidProvider) {"p2p"} else {"livekit"},
                                "epoch":current["key_epoch"],"url":"wss://media.example.test","token":"synthetic-provider-token"})
                        } else { Value::Null };
                        socket.send(Message::Text(json!({"type":"result","call":current,"media":media}).to_string().into())).await.unwrap();
                        if op["type"] == "leave" { return; }
                        if op["type"] == "signal" {
                            signal_count += 1;
                            if matches!(scenario,Scenario::LeaderRotate) {
                                if signal_count == 2 {
                                    current=call(2,&["a","b"]);
                                    socket.send(Message::Text(json!({"type":"presence","call":current}).to_string().into())).await.unwrap();
                                } else if signal_count == 3 {
                                    socket.send(Message::Text(json!({"type":"ended","scope":scope,"call_id":"session"}).to_string().into())).await.unwrap();
                                }
                            } else if matches!(scenario,Scenario::FollowerKeys|Scenario::LeaderKeySwap) && signal_count == 1 {
                                let good="11".repeat(32);
                                let bad="22".repeat(32);
                                for event in [signal("c",&local,1,"not-leader",&bad),
                                    signal("a",&local,0,"old-epoch",&bad),
                                    signal("a",&local,1,"first-key",&good),
                                    signal("a",&local,1,"first-key",&bad)] {
                                    socket.send(Message::Text(event.to_string().into())).await.unwrap();
                                }
                            }
                        }
                    },
                    start = started.recv() => {
                        let _start = start.unwrap();
                        let event = match scenario {
                            Scenario::LeaderRotate|Scenario::InvalidProvider|Scenario::EncryptionFailure => continue,
                            Scenario::FollowerKeys => json!({"type":"ended","scope":scope,"call_id":"session"}),
                            Scenario::LeaderKeySwap => signal("a",&local,1,"replacement-key",&"22".repeat(32)),
                            Scenario::Revoke => continue,
                            Scenario::SameEpochMembership => {
                                current=call(1,&["a","b"]);
                                json!({"type":"presence","call":current})
                            },
                            Scenario::Reconnect if connection == 1 => { socket.close(None).await.unwrap(); break; },
                            Scenario::Reconnect => json!({"type":"ended","scope":scope,"call_id":"session"}),
                        };
                        socket.send(Message::Text(event.to_string().into())).await.unwrap();
                    }
                }
            }
            if !matches!(scenario, Scenario::Reconnect) {
                return;
            }
        }
    });
    let mut driver = TestDriver {
        media: vec![],
        sealed: vec![],
        opened: vec![],
        starts,
        fail_encryption: matches!(scenario, Scenario::EncryptionFailure),
    };
    let result = tokio::time::timeout(
        Duration::from_secs(6),
        super::super::run(&mut driver, &target),
    )
    .await;
    if result.is_err() {
        server.abort();
    }
    let result =
        result.unwrap_or_else(|_| panic!("Native group worker did not terminate: {scenario:?}"));
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    (result, driver)
}
fn starts(driver: &TestDriver) -> Vec<&Value> {
    driver
        .media
        .iter()
        .filter(|event| event["op"] == "group_start")
        .collect()
}
#[tokio::test]
async fn leader_distributes_only_the_current_epoch_key_and_preserves_capture_preferences() {
    let (result, driver) = exercise("a", Scenario::LeaderRotate).await;
    assert_eq!(result, Ok(()));
    let starts = starts(&driver);
    assert_eq!(starts.len(), 2);
    assert_ne!(starts[0]["key"], starts[1]["key"]);
    assert_eq!(driver.sealed.len(), 3);
    assert_eq!(
        driver
            .sealed
            .iter()
            .map(|value| value["to"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["b", "c", "b"]
    );
    for (index, signal) in driver.sealed.iter().enumerate() {
        assert_eq!(
            signal["payload"]["key"],
            starts[usize::from(index == 2)]["key"]
        );
    }
    assert!(
        driver
            .media
            .iter()
            .filter(|value| value["op"] == "update")
            .all(|value| value["state"]["audio_muted"] == true)
    );
    assert_eq!(driver.media.last().unwrap()["op"], "stop");
}
#[tokio::test]
async fn follower_ignores_nonleader_old_epoch_and_replayed_media_keys() {
    let (result, driver) = exercise("b", Scenario::FollowerKeys).await;
    assert_eq!(result, Ok(()));
    let starts = starts(&driver);
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0]["key"], "11".repeat(32));
    assert_eq!(
        driver.opened.len(),
        3,
        "The old epoch never reaches decryption"
    );
    assert_eq!(driver.sealed[0]["payload"]["type"], "request_key");
}
#[tokio::test]
async fn a_replacement_key_without_a_new_epoch_fails_closed() {
    let (result, driver) = exercise("b", Scenario::LeaderKeySwap).await;
    assert_eq!(result, Err("unauthorized"));
    assert_eq!(starts(&driver).len(), 1);
    assert_eq!(driver.media.last().unwrap()["op"], "stop");
}
#[tokio::test]
async fn authorization_and_encryption_failures_stop_capture() {
    for (scenario, expected) in [
        (Scenario::Revoke, "unauthorized"),
        (Scenario::SameEpochMembership, "unauthorized"),
        (Scenario::InvalidProvider, "unauthorized"),
        (Scenario::EncryptionFailure, "encryption_unavailable"),
    ] {
        let (result, driver) = exercise("a", scenario).await;
        assert_eq!(result, Err(expected));
        assert_eq!(driver.media.last().unwrap()["op"], "stop");
        if matches!(scenario, Scenario::InvalidProvider) {
            assert!(starts(&driver).is_empty());
        }
    }
}
#[tokio::test]
async fn reconnect_retains_the_same_epoch_key_instead_of_replacing_it() {
    let (result, driver) = exercise("a", Scenario::Reconnect).await;
    assert_eq!(result, Ok(()));
    let starts = starts(&driver);
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[0]["epoch"], starts[1]["epoch"]);
    assert_eq!(starts[0]["key"], starts[1]["key"]);
}

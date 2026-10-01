//! Explicit deployment acceptance against an operator-owned HTTPS host.
//! Copy to elo-core/examples to run. Creates only disposable profiles and one
//! clearly named Space, then deletes that Space through its primary owner.
//! Build the example with --features tokio-tungstenite/rustls-tls-native-roots.
//! Audio checks authorize media access only; no microphone or media is captured.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use elo_core::{
    app::{
        AttachmentCancellation, ClientApp, ProfileDraft,
        pairing::{PairSource, PairTarget},
        space_service::SpaceInvitation,
    },
    record::SignedRecord,
    replica::{ChildMailbox, MailboxDescriptor},
    sync::{Peer, PeerDescriptor},
    vault::{self, Session},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

type CallSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PASSWORD: &str = "Disposable deployment acceptance password";

fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn general(view: &Value) -> Result<Value> {
    view["streams"]
        .as_array()
        .and_then(|streams| streams.iter().find(|stream| stream["is_general"] == true))
        .cloned()
        .ok_or_else(|| "Missing General".into())
}

async fn call_command(
    app: &mut ClientApp,
    socket: &mut CallSocket,
    space: &str,
    chat: &Value,
    audience: &str,
    operation: Value,
) -> Result<Value> {
    let signed = app
        .operate(json!({
            "op":"call_authorization", "target_space":space, "hosting_space_id":space,
            "space":chat["space"], "stream":chat["stream"], "audience":audience,
            "include_proof":true, "expected_identity":app.identity_id(), "operation":operation
        }))
        .await?;
    let record = SignedRecord::parse(
        &STANDARD.decode(signed["command"].as_str().ok_or("Missing call command")?)?,
    )?;
    let request_id = json!(record.id());
    let exchange = async {
        socket
            .send(Message::Text(
                json!({"command":signed["command"], "proof":signed["proof"]})
                    .to_string()
                    .into(),
            ))
            .await?;
        while let Some(message) = socket.next().await {
            match message? {
                Message::Text(text) => {
                    let response: Value = serde_json::from_str(&text)?;
                    if response["type"] == "error" {
                        return Err(format!(
                            "Call admission rejected: {}",
                            response["code"].as_str().unwrap_or("unknown")
                        )
                        .into());
                    }
                    if response["type"] == "result" && response["request_id"] == request_id {
                        return Ok(response);
                    }
                    if response["type"] == "access_revoked" {
                        return Err("Call authorization was revoked during acceptance".into());
                    }
                }
                Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
                Message::Close(_) => break,
                _ => {}
            }
        }
        Err("Call control closed before its response".into())
    };
    tokio::time::timeout(Duration::from_secs(20), exchange)
        .await
        .map_err(|_| "Call command timed out")?
}

async fn audio_admission(owner: &mut ClientApp, space: &str, chat: &Value) -> Result<()> {
    let endpoint = owner
        .operate(json!({"op":"call_endpoint", "target_space":space, "hosting_space_id":space}))
        .await?;
    let audience = endpoint["url"].as_str().ok_or("Missing call endpoint")?;
    let mut url = reqwest::Url::parse(audience)?;
    check(url.scheme() == "https", "Call endpoint must use HTTPS")?;
    url.set_scheme("wss")
        .map_err(|_| "Invalid call WebSocket scheme")?;
    url.set_path("/calls/v1/connect");
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async(url.as_str()),
    )
    .await
    .map_err(|_| "Call WebSocket connection timed out")??;
    call_command(
        owner,
        &mut socket,
        space,
        chat,
        audience,
        json!({"type":"subscribe"}),
    )
    .await?;
    let mut previous = None;
    for _ in 0..2 {
        let started = call_command(
            owner,
            &mut socket,
            space,
            chat,
            audience,
            json!({"type":"start", "kind":"group", "initial_media":"audio"}),
        )
        .await?;
        let call_id = started["call"]["call_id"]
            .as_str()
            .ok_or("Call session did not start")?
            .to_owned();
        // Always leave a started session, including when media authorization fails.
        let media_check: Result<()> = async {
            check(
                previous.as_ref() != Some(&call_id),
                "Restart reused a terminated call session",
            )?;
            let access = call_command(
                owner,
                &mut socket,
                space,
                chat,
                audience,
                json!({"type":"connect_media", "call_id":call_id}),
            )
            .await?;
            check(
                access["media"]["provider"] == "livekit",
                "General media provider was not authorized",
            )?;
            check(
                access["media"]["token"]
                    .as_str()
                    .is_some_and(|token| !token.is_empty()),
                "Missing short-lived media access token",
            )?;
            check(
                access["media"]["url"]
                    .as_str()
                    .is_some_and(|url| url.starts_with("wss://")),
                "Media endpoint must use WSS",
            )?;
            check(
                access["media"]["epoch"] == started["call"]["key_epoch"],
                "Media authorization belongs to another call generation",
            )?;
            check(
                access["media"]["ice_servers"]
                    .as_array()
                    .is_some_and(|servers| !servers.is_empty()),
                "Missing ICE server access",
            )?;
            Ok(())
        }
        .await;
        let left = call_command(
            owner,
            &mut socket,
            space,
            chat,
            audience,
            json!({"type":"leave", "call_id":call_id}),
        )
        .await;
        media_check?;
        check(
            left?["call"].is_null(),
            "Empty audio session remained active after leaving",
        )?;
        previous = Some(call_id);
    }
    socket.close(None).await?;
    println!(
        "PASS: General v2 audio session admission over WSS, media token issuance, leave and immediate restart (no audio capture)"
    );
    Ok(())
}

async fn profile(path: &Path) -> Result<ClientApp> {
    let draft = ProfileDraft::new()?;
    draft
        .save_named(path.into(), PASSWORD.into(), "General", "Deployment check")
        .await?
        .close()
        .await?;
    let mut app = ClientApp::open(path.into(), PASSWORD.into(), false).await?;
    app.begin_space_setup().await?;
    Ok(app)
}

async fn exercise(
    owner: &mut ClientApp,
    guest: &mut ClientApp,
    space: &str,
    temp: &Path,
    created_at: &str,
) -> Result<()> {
    owner.operate(json!({"op":"space_setup_done"})).await?;
    let initial = general(&owner.view().await?)?;
    check(
        initial["owner_managed"] == true,
        "General must use owner-managed v2",
    )?;
    let members = initial["members"]
        .as_array()
        .ok_or("Missing General members")?;
    let owners = initial["owners"]
        .as_array()
        .ok_or("Missing General owners")?;
    check(
        members.len() == 1 && owners.len() == 1,
        "Fresh General must contain only its real owner",
    )?;
    check(
        members[0]["identity_id"] == json!(owner.identity_id())
            && owners[0]["identity_id"] == json!(owner.identity_id()),
        "General belongs to a synthetic service identity",
    )?;
    let invite = owner.operate(json!({"op":"space_invite","id":space,"body":{"lifetime":3600,"require_approval":false}})).await?["result"]["link"].clone();
    let invitation =
        SpaceInvitation::parse(invite.as_str().ok_or("Missing invitation link")?, false)?;
    let signer = invitation
        .address
        .service_signer()?
        .ok_or("Missing separate host response signer")?;
    check(
        !members.iter().any(|member| {
            member["identity_id"] == json!(signer.identity())
                || member["credential_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.contains(&json!(signer.id())))
        }),
        "Host response signer must not read or manage General",
    )?;
    check(
        initial["controller"] != json!(signer.id()),
        "Host response signer must not control General",
    )?;
    println!(
        "PASS: owner-managed General v2, real profile ownership and a separate non-member host signer"
    );
    let joined = guest
        .operate(json!({"op":"space_join","link":invite}))
        .await?;
    check(
        joined["view"]["spaces"][0]["status"] == "pending",
        "A join must wait for an owner-signed membership commit",
    )?;
    // The host can accept the request, but only an owner device can grant General access.
    owner.operate(json!({"op":"space_refresh"})).await?;
    let joined = guest.operate(json!({"op":"space_refresh"})).await?;
    check(
        joined["view"]["spaces"][0]["status"] == "joined",
        "Owner-signed admission did not reach the guest",
    )?;
    let chat = general(&joined["view"])?;
    check(
        chat["owner_managed"] == true,
        "Guest did not import owner-managed General",
    )?;
    guest.operate(json!({"op":"send","space":chat["space"],"stream":chat["stream"],"text":"Deployment acceptance message","created_at":created_at})).await?;
    guest.operate(json!({"op":"sync"})).await?;
    owner.operate(json!({"op":"space_refresh"})).await?;
    owner.operate(json!({"op":"sync"})).await?;
    check(
        owner.view().await?["all_streams"]
            .to_string()
            .contains("Deployment acceptance message"),
        "General message did not reach the owner",
    )?;
    println!("PASS: owner-signed admission and General message delivery over HTTPS");
    audio_admission(owner, space, &chat).await?;
    let content = b"Disposable HTTPS attachment acceptance.\n".repeat(1600);
    let input = temp.join("attachment-check.txt");
    std::fs::write(&input, &content)?;
    let upload = guest
        .operate_attachment_transfer(
            json!({
                "op":"attachment_upload", "space":chat["space"], "stream":chat["stream"],
                "path":input, "name":"attachment-check.txt"
            }),
            AttachmentCancellation::default(),
            |_, _| {},
        )
        .await?;
    let record = upload["result"]["record"]
        .as_str()
        .ok_or("Missing attachment record")?;
    guest.operate(json!({"op":"sync"})).await?;
    owner.operate(json!({"op":"sync"})).await?;
    let output = temp.join("downloaded-check.txt");
    owner
        .operate(json!({"op":"attachment_download", "space":chat["space"],
        "stream":chat["stream"], "record":record, "output":output}))
        .await?;
    check(
        std::fs::read(output)? == content,
        "Downloaded attachment bytes changed",
    )?;
    println!("PASS: attachment upload and download by another member preserve every byte");

    let mut source = PairSource::new(guest).await?;
    let mut target = PairTarget::new(&source.link()?, "HTTPS companion", false)?;
    target.send().await?;
    let pending = source.poll().await?;
    let request = pending["requests"][0]["id"]
        .as_str()
        .ok_or("Missing device request")?;
    let comparison = target.summary()?["code"]
        .as_str()
        .ok_or("Missing comparison code")?
        .to_owned();
    check(
        comparison.split(' ').count() == 8,
        "Invalid device comparison code",
    )?;
    source.accept(guest, request).await?;
    check(
        target.poll().await?["ready"] == true,
        "Accepted device transfer is not ready",
    )?;
    let mut linked = target.finish_linked(temp.join("linked")).await?;
    linked.enable_spaces().await?;
    // Linking a guest proves its identity; the General owner still signs the new reader.
    linked.operate(json!({"op":"space_refresh"})).await?;
    owner.operate(json!({"op":"space_refresh"})).await?;
    linked.operate(json!({"op":"space_refresh"})).await?;
    guest.operate(json!({"op":"space_refresh"})).await?;
    check(
        linked.view().await?["spaces"][0]["status"] == "joined",
        "Linked guest was not admitted by the owner",
    )?;
    check(
        linked.identity_id() == guest.identity_id(),
        "Linked device changed profile identity",
    )?;
    check(
        linked.view().await?["credential"] != guest.view().await?["credential"],
        "Linked device reused the original credential",
    )?;
    check(
        linked
            .view()
            .await?
            .to_string()
            .contains("Deployment acceptance message"),
        "Linked device lost the copied history",
    )?;
    let linked_session = Session::open(
        &vault::read_private(&temp.join("linked/spaces").join(space).join("vault.age"))?,
        PASSWORD.into(),
        linked.identity_id(),
    )?;
    let linked_peer =
        Peer::new(linked_session.peers()[0].clone(), false)?.with_identity(&linked_session);
    linked_peer.inventory(0).await?;
    let roster = guest.linked_devices().await?;
    let retired = roster["devices"]
        .as_array()
        .ok_or("Missing device list")?
        .iter()
        .find(|d| d["current"] == false)
        .ok_or("Paired device missing")?;
    let revoked = guest
        .revoke_linked_device(
            retired["credential"]
                .as_str()
                .ok_or("Missing paired credential")?,
        )
        .await?;
    check(revoked["pending"] == 0, "Device revocation remains pending")?;
    check(
        linked_peer.inventory(0).await.is_err(),
        "Revoked device still has server access",
    )?;
    check(
        linked
            .view()
            .await?
            .to_string()
            .contains("Deployment acceptance message"),
        "Linked device lost the copied history",
    )?;
    linked.close().await?;
    // Commit the removal before granting another positive access lease.
    owner.operate(json!({"op":"space_refresh"})).await?;
    guest.operate(json!({"op":"space_refresh"})).await?;
    println!(
        "PASS: independent device keys, preserved history and immediate server denial after revocation"
    );
    let backup = guest.export_profile(PASSWORD.into()).await?;
    let session = Session::open(
        &vault::read_private(&temp.join("guest/spaces").join(space).join("vault.age"))?,
        PASSWORD.into(),
        guest.identity_id(),
    )?;
    let descriptor = session.peers()[0].clone();
    let peer = Peer::new(descriptor.clone(), false)?.with_identity(&session);
    peer.inventory(0).await?;
    check(
        Peer::new(descriptor.clone(), false)?
            .inventory(0)
            .await
            .is_err(),
        "Mailbox access without an identity proof was accepted",
    )?;
    let child = ChildMailbox {
        descriptor: MailboxDescriptor::random()?,
        quota_bytes: 1024 * 1024,
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64 + 600_000,
    };
    peer.create_child(&child).await?;
    let child_peer = Peer::new(
        PeerDescriptor {
            mailbox_id: child.descriptor.mailbox_id,
            read_token: Some(child.descriptor.read_token),
            write_token: Some(child.descriptor.write_token),
            ..descriptor
        },
        false,
    )?
    .with_identity(&session);
    child_peer.inventory(0).await?;
    let storage = owner
        .operate(json!({"op":"space_storage","id":space,"body":{"days":100}}))
        .await?["result"]
        .clone();
    check(
        storage["quota_bytes"] == 150_000_000,
        "Unexpected Space mailbox quota",
    )?;
    check(
        storage["used_bytes"]
            .as_u64()
            .is_some_and(|value| value > 0),
        "Storage usage does not include test data",
    )?;
    check(
        storage["removable_copies"] == 0,
        "Fresh records must not be removable by age",
    )?;
    check(
        guest
            .operate(json!({"op":"space_storage","id":space,"body":{"days":100}}))
            .await
            .is_err(),
        "Guest could inspect owner-only storage management",
    )?;
    check(guest.operate(json!({"op":"space_storage_prune","id":space,"body":{"days":100,"before_ms":0,"confirmed":true}})).await.is_err(), "Guest could prune Space storage")?;
    let clear=owner.operate(json!({"op":"space_storage_prune","id":space,"body":{"days":100,"before_ms":storage["before_ms"],"confirmed":true}})).await?;
    check(
        clear["result"]["removable_bytes"] == 0,
        "Empty age cleanup removed fresh records",
    )?;
    let restored = ClientApp::restore_profile(
        temp.join("allowed"),
        &backup,
        PASSWORD.into(),
        guest.identity_id(),
        PASSWORD.into(),
        false,
    )
    .await?;
    check(
        restored.view().await?["spaces"][0]["status"] == "joined",
        "Current-member restore did not regain access",
    )?;
    restored.close().await?;
    let management = owner
        .operate(json!({"op":"space_manage","id":space,"body":{}}))
        .await?;
    owner.operate(json!({"op":"space_role_change","id":space,"body":{"revision":management["result"]["roles_revision"],"kind":"remove_member","target":guest.identity_id()}})).await?;
    check(
        peer.inventory(0).await.is_err(),
        "Removed member still has mailbox access",
    )?;
    check(
        child_peer.inventory(0).await.is_err(),
        "Removed member still has child-mailbox access",
    )?;
    let denied = ClientApp::restore_profile(
        temp.join("denied"),
        &backup,
        PASSWORD.into(),
        guest.identity_id(),
        PASSWORD.into(),
        false,
    )
    .await?;
    check(
        denied.view().await?["spaces"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "Removed-member restore exposed a Space",
    )?;
    check(
        !temp.join("denied/spaces").join(space).exists(),
        "Removed-member restore retained Space files",
    )?;
    denied.close().await?;
    let rejoin = guest
        .operate(json!({"op":"space_join","link":invite}))
        .await?;
    check(
        rejoin["view"]["spaces"][0]["status"] == "pending",
        "Removed member bypassed fresh approval",
    )?;
    println!(
        "PASS: identity proofs, owner-only storage, backup restore, removal and descendant denial, approval-required rejoin"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let host = std::env::args()
        .nth(1)
        .ok_or("Pass the authorized HTTPS create endpoint.")?;
    check(
        host.starts_with("https://") && host.ends_with("/spaces/v1/create"),
        "Expected an HTTPS Space creation endpoint",
    )?;
    let created_at = std::env::args()
        .nth(2)
        .ok_or("Pass the current UTC timestamp in RFC 3339 format.")?;
    // Retain the synthetic owner only on failure so cleanup can be retried.
    let temp = tempfile::Builder::new()
        .prefix("elo-hosting-acceptance-")
        .tempdir()?
        .keep();
    eprintln!("Private synthetic working directory: {}", temp.display());
    let mut owner = profile(&temp.join("owner")).await?;
    let mut guest = profile(&temp.join("guest")).await?;
    let name = "Deployment acceptance - temporary";
    let created = owner
        .operate(
            json!({"op":"space_create","contact_email":"qa@example.test","host":host,"name":name,"message_lifetime_seconds":86400}),
        )
        .await?;
    let space = created["view"]["active_space"]
        .as_str()
        .ok_or("No active Space")?
        .to_owned();
    // This public ID lets the operator inspect the fresh on-disk layout while the test runs.
    println!("Disposable Space: {space}");
    let result = exercise(&mut owner, &mut guest, &space, &temp, &created_at).await;
    // Every failed check is a Result, so it cannot skip deletion of the disposable Space.
    let cleanup: Result<()> = async {
        let management = owner.operate(json!({"op":"space_manage","id":space,"body":{}})).await?;
        owner.operate(json!({"op":"space_delete","id":space,"body":{"revision":management["result"]["roles_revision"],"name":name,"confirmed":true}})).await?;
        println!("Temporary Space deleted through its primary owner.");
        Ok(())
    }.await;
    let owner_closed = owner.close().await;
    let guest_closed = guest.close().await;
    if let Err(error) = &result {
        eprintln!("Acceptance failed: {error}");
    }
    if let Err(error) = &cleanup {
        eprintln!("Temporary Space cleanup failed: {error}");
    }
    cleanup?;
    result?;
    owner_closed?;
    guest_closed?;
    std::fs::remove_dir_all(temp)?;
    println!("HTTPS owner-managed General acceptance passed.");
    Ok(())
}

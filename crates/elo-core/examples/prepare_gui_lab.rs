//! Creates ONLY new synthetic profiles for an interactive desktop QA session.
//! Does not perform controller recovery or replica repair: those are GUI steps.
use elo_core::{
    app::{ClientApp, Result},
    replica::ReplicaStore,
    store::ClientStore,
    vault::{self, Session},
};
use serde_json::{Value, json};
use std::path::Path;

const PASSWORD: &str = "elo public disposable GUI laboratory passphrase";

async fn profile(path: &Path, session: &Session) -> Result<Value> {
    let store = ClientStore::open(path).await?;
    let public =
        json!({"identity_id":session.identity_id(),"credential_id":session.credential().id()});
    vault::write_private(
        &path.join("profile.json"),
        &serde_json::to_vec(&public)?,
        false,
    )?;
    vault::write_private(
        &path.join("vault.age"),
        &session.seal(PASSWORD.into())?,
        false,
    )?;
    store.close().await?;
    Ok(public)
}
fn scope(view: &Value, op: &str) -> Value {
    let stream = &view["streams"][0];
    json!({"op":op,"space":stream["space"],"stream":stream["stream"]})
}

#[tokio::main]
async fn main() -> Result<()> {
    let arg = std::env::args_os()
        .nth(1)
        .ok_or("supply a NEW disposable lab directory")?;
    let directory = std::path::PathBuf::from(arg);
    // Refuse existing paths rather than adopting or overwriting a real profile.
    std::fs::create_dir(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let d = directory.canonicalize()?;
    let (owner_session, owner_card) = Session::create()?;
    let (reader_session, reader_card) = Session::create()?;
    let fresh_session = Session::recover(&owner_card, owner_session.identity_id())?;
    let owner_public = profile(&d.join("owner"), &owner_session).await?;
    let reader_public = profile(&d.join("reader"), &reader_session).await?;
    let fresh_public = profile(&d.join("fresh"), &fresh_session).await?;
    let card = d.join("owner-recovery.json");
    vault::write_private(&card, &serde_json::to_vec(&owner_card)?, false)?;
    vault::write_private(
        &d.join("reader-recovery.json"),
        &serde_json::to_vec(&reader_card)?,
        false,
    )?;
    let mut nodes = Vec::new();
    let mut reservations = Vec::new();
    for n in 1..=2 {
        let path = d.join(format!("replica-{n}"));
        let replica = ReplicaStore::open(&path).await?;
        let mailbox = replica.create_mailbox(64 * 1024 * 1024).await?;
        let listener = elo_core::http::local_listener("127.0.0.1:0".parse()?, true).await?;
        let bind = listener.local_addr()?;
        let descriptor = d.join(format!("peer-{n}.json"));
        let peer = json!({"url":format!("http://{bind}/"),"signing_public_key":elo_core::record::encode_hex(replica.key().as_bytes()),"mailbox_id":mailbox.mailbox_id,"read_token":mailbox.read_token,"write_token":mailbox.write_token});
        vault::write_private(&descriptor, &serde_json::to_vec(&peer)?, false)?;
        nodes.push(json!({"directory":path,"descriptor":descriptor,"bind":bind.to_string(),"peer":replica.peer_id()}));
        reservations.push(listener);
    }
    let mut owner = ClientApp::open(d.join("owner"), PASSWORD.into(), true).await?;
    let mut reader = ClientApp::open(d.join("reader"), PASSWORD.into(), true).await?;
    let mut fresh = ClientApp::open(d.join("fresh"), PASSWORD.into(), true).await?;
    for node in &nodes {
        for app in [&mut owner, &mut reader, &mut fresh] {
            app.operate(json!({"op":"add_peer","path":node["descriptor"]}))
                .await?;
        }
    }
    let initial = owner
        .operate(json!({"op":"create_space","name":"Recovery laboratory","recovery_card":card}))
        .await?["view"]
        .clone();
    let invite = d.join("invite.json");
    let mut request = scope(&initial, "invite_create");
    request["output"] = json!(invite);
    owner.operate(request).await?;
    let exchange: Value = serde_json::from_slice(&std::fs::read(&invite)?)?;
    let join = d.join("join.json");
    reader.operate(json!({"op":"invite_request","path":invite,"space":exchange["space"],"root":exchange["root"],"output":join})).await?;
    let config = d.join("reader-config.age");
    let mut approval = scope(&initial, "invite_approve");
    approval["path"] = json!(join);
    approval["fingerprint"] = reader_public["identity_id"].clone();
    approval["post"] = json!(true);
    approval["output"] = json!(config);
    owner.operate(approval).await?;
    reader.operate(json!({"op":"import_stream","path":config,"name":"Recovery laboratory","space":exchange["space"],"stream":exchange["stream"],"root":exchange["root"]})).await?;
    let mut message = scope(&initial, "send");
    message["text"] = json!("PUBLIC GUI BEFORE RECOVERY");
    message["created_at"] = json!("2026-09-09T12:00:00Z");
    owner.operate(message).await?;
    owner.close().await?;
    reader.close().await?;
    fresh.close().await?;
    let manifest = json!({"synthetic":true,"directory":d,"space":exchange["space"],"stream":exchange["stream"],"root":exchange["root"],"owner":owner_public,"reader":reader_public,"fresh":fresh_public,"nodes":nodes});
    vault::write_private(
        &d.join("lab.json"),
        &serde_json::to_vec_pretty(&manifest)?,
        false,
    )?;
    println!(
        "Prepared synthetic lab at {}. Profiles closed; Replica listeners released on exit. Start CLI Replica servers using lab.json. Recovery/repair have NOT run.",
        d.display()
    );
    drop(reservations);
    Ok(())
}

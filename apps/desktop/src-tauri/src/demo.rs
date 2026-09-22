//! Disposable, debug-only profiles built through the normal signed operations.
use elo_core::app::{ClientApp, ProfileDraft, Result};
use elo_core::{record, vault};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const PASSWORD: &str = "elo public demo workspace 2026";
const PEOPLE: [&str; 4] = ["Alex", "Maya", "Jules", "Sam"];
const FIXTURE: &str = include_str!("../fixtures/demo-chats.json");

fn private_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn scoped(scope: &Value, op: &str) -> Value {
    json!({"op":op,"space":scope["space"],"stream":scope["stream"]})
}

async fn transfer_history(
    apps: &mut [ClientApp],
    from: usize,
    to: usize,
    scope: &Value,
    exchange: &Path,
    label: &str,
) -> Result<()> {
    let request = exchange.join(format!("{label}.request"));
    let bundle = exchange.join(format!("{label}.age"));
    let mut operation = scoped(scope, "history_request");
    operation["count"] = json!(100);
    operation["output"] = json!(request);
    apps[to].operate(operation).await?;
    let mut operation = scoped(scope, "history_preview");
    operation["path"] = json!(request);
    let preview = apps[from].operate(operation.clone()).await?;
    let selected = preview["selection"]
        .as_array()
        .ok_or("Invalid demo history preview")?;
    if selected.is_empty() {
        return Ok(());
    }
    operation["op"] = json!("history_approve");
    operation["expected_request"] = preview["request_id"].clone();
    operation["selection"] = json!(selected.iter().map(|r| &r["id"]).collect::<Vec<_>>());
    operation["output"] = json!(bundle);
    apps[from].operate(operation).await?;
    let mut operation = scoped(scope, "history_import");
    operation["request"] = json!(request);
    operation["path"] = json!(bundle);
    apps[to].operate(operation).await?;
    Ok(())
}

async fn seed_channels(
    apps: &mut [ClientApp],
    channels: &[Value],
    card: &Path,
    exchange: &Path,
) -> Result<()> {
    let mut identities = Vec::new();
    for app in apps.iter() {
        identities.push(app.view().await?);
    }
    for (channel_index, channel) in channels.iter().enumerate() {
        let name = channel["name"].as_str().ok_or("Invalid demo channel")?;
        if channel_index != 0 {
            apps[0]
                .operate(json!({"op":"create_space","name":name,"recovery_card":card}))
                .await?;
        }
        let owner = apps[0].view().await?;
        let scope = owner["streams"]
            .as_array()
            .and_then(|streams| streams.iter().find(|s| s["name"] == name))
            .ok_or("Demo channel unavailable")?
            .clone();
        let channel_path = exchange.join(channel_index.to_string());
        private_directory(&channel_path)?;
        let root = scope["owners"][0]["root_public_key"].clone();
        for person in 1..PEOPLE.len() {
            let invitation = channel_path.join(format!("{person}.invitation.json"));
            let mut operation = scoped(&scope, "invite_create");
            operation["output"] = json!(invitation);
            apps[0].operate(operation).await?;
            let request = channel_path.join(format!("{person}.join"));
            apps[person]
                .operate(json!({"op":"invite_request","path":invitation,
                    "space":scope["space"],"root":root,"output":request}))
                .await?;
            let mut operation = scoped(&scope, "invite_approve");
            operation["path"] = json!(request);
            operation["fingerprint"] = identities[person]["identity"].clone();
            operation["post"] = json!(true);
            operation["share_history"] = json!(true);
            operation["output"] = json!(channel_path.join(format!("{person}.initial.age")));
            apps[0].operate(operation).await?;
        }
        // Everyone adopts the final membership before anybody posts.
        for person in 1..PEOPLE.len() {
            let config = channel_path.join(format!("{person}.config.age"));
            let mut operation = scoped(&scope, "export_config");
            operation["credential"] = identities[person]["credential"].clone();
            operation["output"] = json!(config);
            apps[0].operate(operation).await?;
            apps[person]
                .operate(json!({"op":"import_stream","path":config,
                    "space":scope["space"],"stream":scope["stream"],
                    "root":root,"name":name}))
                .await?;
        }
        for message in channel["messages"]
            .as_array()
            .ok_or("Invalid demo messages")?
        {
            let person = PEOPLE
                .iter()
                .position(|name| message["sender"] == *name)
                .ok_or("Unknown demo author")?;
            let mut operation = scoped(&scope, "send");
            operation["text"] = message["text"].clone();
            operation["created_at"] = message["created_at"].clone();
            apps[person].operate(operation).await?;
        }
        // Explicit verified history exchange works offline; no Replica is added.
        for person in 1..PEOPLE.len() {
            transfer_history(
                apps,
                person,
                0,
                &scope,
                &channel_path,
                &format!("collect-{person}"),
            )
            .await?;
        }
        for person in 1..PEOPLE.len() {
            transfer_history(
                apps,
                0,
                person,
                &scope,
                &channel_path,
                &format!("share-{person}"),
            )
            .await?;
        }
    }
    Ok(())
}

async fn build(directory: &Path) -> Result<()> {
    let fixture: Value = serde_json::from_str(FIXTURE)?;
    let channels = fixture.as_array().ok_or("Invalid demo fixture")?;
    let exchange = directory.join("seed-exchange");
    private_directory(&exchange)?;
    let mut apps = Vec::new();
    let mut names = serde_json::Map::new();
    let card_path = exchange.join("owner-recovery.json");
    let result: Result<()> = async {
        for (index, person) in PEOPLE.iter().enumerate() {
            let draft = ProfileDraft::new()?;
            if index == 0 {
                vault::write_private(&card_path, &serde_json::to_vec(draft.card())?, false)?;
            }
            let name = if index == 0 {
                channels[0]["name"]
                    .as_str()
                    .ok_or("Invalid initial demo channel")?
            } else {
                "Notes"
            };
            let app = draft
                .save(directory.join(person.to_lowercase()), PASSWORD.into(), name)
                .await?;
            let view = app.view().await?;
            names.insert(
                view["identity"]
                    .as_str()
                    .ok_or("Missing demo identity")?
                    .into(),
                json!(person),
            );
            apps.push(app);
        }
        seed_channels(&mut apps, channels, &card_path, &exchange).await?;
        vault::write_private(
            &directory.join("names.json"),
            &serde_json::to_vec(&names)?,
            false,
        )?;
        Ok(())
    }
    .await;
    let mut close_result = Ok(());
    for app in apps {
        if let Err(error) = app.close().await {
            close_result = Err(error);
        }
    }
    result?;
    close_result?;
    // Only files created above are removed, after all verified imports commit.
    std::fs::remove_dir_all(exchange)?;
    Ok(())
}

pub async fn open(base: &Path, person: &str) -> Result<(ClientApp, Value)> {
    let person = PEOPLE
        .iter()
        .find(|p| p.to_lowercase() == person)
        .ok_or("Choose a demo profile")?;
    let directory = base.join("demo-workspace-v1");
    match std::fs::symlink_metadata(&directory) {
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
            return Err("The demo workspace folder is unavailable".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let staging: PathBuf =
                base.join(format!("demo-building-{}", record::random_hex::<16>()?));
            private_directory(&staging)?;
            // Failed staging is retained for diagnosis. Never replace a profile.
            build(&staging).await?;
            std::fs::rename(staging, &directory)?;
        }
        Err(error) => return Err(error.into()),
    }
    let names = serde_json::from_slice(&vault::read_private(&directory.join("names.json"))?)?;
    let mut app = ClientApp::open(
        directory.join(person.to_lowercase()),
        PASSWORD.into(),
        false,
    )
    .await?;
    // Earlier demos kept names only in the frontend map. Signed outgoing
    // contact/message records need the same display name in the core.
    if app.view().await?["name"].as_str().is_none_or(str::is_empty) {
        app.operate(json!({"op":"set_profile_details","name":person,"avatar":null}))
            .await?;
    }
    Ok((app, names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signed_demo_profiles_share_history_and_reopen_without_reseeding() {
        let base = std::env::temp_dir().join(format!(
            "elo-demo-test-{}",
            record::random_hex::<16>().unwrap()
        ));
        private_directory(&base).unwrap();
        std::fs::write(base.join("existing-profile-sentinel"), b"keep me").unwrap();
        assert!(open(&base, "../profile").await.is_err());
        let (mut alex, names) = open(&base, "alex").await.unwrap();
        assert_eq!(names.as_object().unwrap().len(), 4);
        let view = alex.view().await.unwrap();
        assert_eq!(view["name"], "Alex");
        let streams = view["streams"].as_array().unwrap();
        assert_eq!(streams.len(), 6);
        assert!(view["replicas"].as_array().unwrap().is_empty());
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        for (stream, channel) in streams.iter().zip(fixture.as_array().unwrap()) {
            assert_eq!(stream["name"], channel["name"]);
            assert_eq!(
                stream["rows"].as_array().unwrap().len(),
                channel["messages"].as_array().unwrap().len()
            );
            assert_eq!(stream["members"].as_array().unwrap().len(), 4);
            for row in stream["rows"].as_array().unwrap() {
                assert!(
                    names
                        .get(row["body"]["issuer_identity"].as_str().unwrap())
                        .is_some()
                );
                let expected = channel["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|message| message["text"] == row["body"]["payload"]["text"])
                    .unwrap();
                assert_eq!(
                    names[row["body"]["issuer_identity"].as_str().unwrap()],
                    expected["sender"]
                );
                assert_eq!(row["body"]["created_at"], expected["created_at"]);
                assert_ne!(row["state"], "STORED");
            }
        }
        let mut send = scoped(&streams[0], "send");
        send["text"] = json!("Public demo persistence check");
        send["created_at"] = json!("2026-09-09T18:00:00Z");
        alex.operate(send).await.unwrap();
        let after_send = alex.view().await.unwrap();
        alex.close().await.unwrap();
        let (alex, reopened_names) = open(&base, "alex").await.unwrap();
        assert_eq!(reopened_names, names);
        assert_eq!(alex.view().await.unwrap(), after_send);
        alex.close().await.unwrap();
        let (maya, _) = open(&base, "maya").await.unwrap();
        let maya_view = maya.view().await.unwrap();
        assert_ne!(maya_view["identity"], view["identity"]);
        let team = maya_view["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "Team")
            .unwrap();
        let records = |rows: &Value| {
            rows.as_array()
                .unwrap()
                .iter()
                .map(|row| (row["id"].clone(), row["body"].clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(records(&team["rows"]), records(&view["streams"][0]["rows"]));
        maya.close().await.unwrap();
        assert_eq!(
            std::fs::read(base.join("existing-profile-sentinel")).unwrap(),
            b"keep me"
        );
        assert!(!base.join("demo-workspace-v1/seed-exchange").exists());
        std::fs::remove_dir_all(base).unwrap();
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=TAURI_ELO_WAKE_URL");
    if let Ok(url) = std::env::var("TAURI_ELO_WAKE_URL") {
        assert!(
            url.starts_with("https://")
                || (std::env::var("PROFILE").as_deref() == Ok("debug")
                    && url.starts_with("http://127.0.0.1:")),
            "Wake service requires HTTPS outside local debug checks"
        );
        println!("cargo:rustc-env=TAURI_ELO_WAKE_URL={url}");
    }
    configure_team_replica();
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "profile_environment",
            "profile_task",
            "open_demo",
            "prepare_profile",
            "cancel_profile",
            "create_profile",
            "unlock",
            "lock",
            "verify_password",
            "operate",
            "push_task",
            "choose_import",
            "prepare_export",
            "save_export",
            "invitation_qr",
        ]),
    ))
    .expect("application build configuration");
}

fn configure_team_replica() {
    println!("cargo:rerun-if-env-changed=TAURI_ELO_TEAM_REPLICA_DESCRIPTOR");
    if std::env::var_os("CARGO_FEATURE_TEAM_TEST_REPLICA").is_none() {
        return;
    }
    let path = std::path::PathBuf::from(
        std::env::var_os("TAURI_ELO_TEAM_REPLICA_DESCRIPTOR")
            .expect("team-test-replica requires TAURI_ELO_TEAM_REPLICA_DESCRIPTOR"),
    );
    assert!(
        path.is_absolute(),
        "Test Replica descriptor must use a private absolute path"
    );
    let metadata =
        std::fs::symlink_metadata(&path).expect("Private test Replica descriptor is missing");
    assert!(
        metadata.is_file() && metadata.len() <= 8192,
        "Invalid test Replica descriptor file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            metadata.permissions().mode() & 0o077,
            0,
            "Test Replica descriptor must be private"
        );
    }
    let bytes = std::fs::read(&path).expect("Cannot read private test Replica descriptor");
    // Require an explicit purpose marker: a normal private owner descriptor must
    // never be accepted as the input to a distributable team build.
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("Invalid test Replica descriptor"));
    assert!(
        value["purpose"] == "elo.now/team-test-replica/v1",
        "A dedicated team-test descriptor is required"
    );
    let team_output =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Build output directory"))
            .join("team-general.json");
    if let Some(team) = value.get("team") {
        assert!(
            team["v"] == 1
                && team["url"].as_str().is_some_and(
                    |url| url.starts_with("https://") && url.ends_with("/team/v1/enroll")
                )
                && team["token"].as_str().is_some_and(|s| s.len() == 64),
            "Invalid closed-team enrollment configuration"
        );
    }
    let mut team_options = std::fs::OpenOptions::new();
    team_options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        team_options.mode(0o600);
    }
    std::io::Write::write_all(
        &mut team_options
            .open(team_output)
            .expect("Cannot stage team enrollment"),
        &serde_json::to_vec(&value.get("team")).expect("Cannot encode team enrollment"),
    )
    .expect("Cannot stage team enrollment");
    let peer = &value["peer"];
    assert!(
        peer["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("https://"))
            && [
                "signing_public_key",
                "mailbox_id",
                "read_token",
                "write_token"
            ]
            .iter()
            .all(|key| peer[key].as_str().is_some_and(|v| !v.is_empty())),
        "Test Replica requires HTTPS, a public-key pin and read/write capabilities"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    let output =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Build output directory"))
            .join("team-replica.json");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(output)
        .expect("Cannot stage private test configuration")
        .write_all(&serde_json::to_vec(peer).expect("Test configuration encoding"))
        .expect("Cannot write private test configuration");
}

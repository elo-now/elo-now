mod ios_resources;
mod macos_diagnostics_resources;
mod service_endpoints;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        // Crashlytics NDK matches the installed ELF to its private symbols by ID.
        println!("cargo:rustc-link-arg-cdylib=-Wl,--build-id=sha1");
    }
    for name in [
        "ELO_API_URL",
        "TAURI_ELO_API_URL",
        "ELO_SPACE_HOST_URL",
        "TAURI_ELO_SPACE_HOST_URL",
        "TAURI_ELO_WAKE_URL",
        "ELO_STORAGE_URL",
        "TAURI_ELO_STORAGE_URL",
        "ELO_WITNESS_URL",
        "TAURI_ELO_WITNESS_URL",
        "ELO_WITNESS_PUBLIC_KEY",
        "TAURI_ELO_WITNESS_PUBLIC_KEY",
        "ELO_WITNESS_KEY_GENERATION",
        "TAURI_ELO_WITNESS_KEY_GENERATION",
        "ELO_DISTRIBUTION_CHANNEL",
        "TAURI_ELO_UNLOCK_TIMING",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let endpoints = service_endpoints::from_environment(
        |name| std::env::var(name).ok(),
        std::env::var("PROFILE").as_deref() == Ok("debug"),
    )
    .expect("Invalid API endpoint configuration");
    println!(
        "cargo:rustc-env=ELO_CONFIGURED_SPACE_HOST={}",
        endpoints.host
    );
    println!("cargo:rustc-env=ELO_CONFIGURED_WAKE={}", endpoints.wake);
    println!(
        "cargo:rustc-env=ELO_CONFIGURED_STORAGE={}",
        endpoints.storage.unwrap_or_default()
    );
    let witness = endpoints.witness.map(|(url, public_key, key_generation)| {
        serde_json::json!({"url":url,"public_key":public_key,"key_generation":key_generation})
    });
    println!(
        "cargo:rustc-env=ELO_CONFIGURED_WITNESS={}",
        witness.map(|pin| pin.to_string()).unwrap_or_default()
    );
    println!("cargo:rerun-if-env-changed=TAURI_ELO_LIVE_DIAGNOSTICS_URL");
    println!("cargo:rerun-if-env-changed=TAURI_ELO_DIAGNOSTICS_BUILD");
    if let Ok(value) = std::env::var("TAURI_ELO_LIVE_DIAGNOSTICS_URL") {
        let url = url::Url::parse(&value).expect("Invalid live diagnostics URL");
        assert!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "Live diagnostics requires a fixed HTTPS endpoint"
        );
        println!("cargo:rustc-env=ELO_LIVE_DIAGNOSTICS_URL={value}");
    }
    if let Ok(value) = std::env::var("TAURI_ELO_DIAGNOSTICS_BUILD") {
        assert!(
            !value.is_empty() && value.len() <= 16 && value.bytes().all(|b| b.is_ascii_digit()),
            "Invalid diagnostic build number"
        );
        println!("cargo:rustc-env=ELO_DIAGNOSTICS_BUILD={value}");
    }
    configure_team_replica();
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "diagnostic_task",
            "profile_environment",
            "profile_task",
            "control_task",
            "open_demo",
            "prepare_profile",
            "cancel_profile",
            "create_profile",
            "unlock",
            "lock",
            "verify_password",
            "attachment_transfer",
            "cancel_attachment_transfer",
            "operate",
            "hosting_catalog",
            "draft_load",
            "draft_save",
            "realtime_context",
            "push_task",
            "desktop_notification_task",
            "native_call_media",
            "native_call_incoming",
            "native_call_ringtone",
            "native_call_state",
            "native_call_audio",
            "choose_attachment",
            "stage_attachment",
            "discard_exchange",
            "prepare_export",
            "save_export",
            "attachment_preview",
            "share_cached_attachment",
            "open_mail_draft",
            "invitation_qr",
            "save_invitation_qr",
            "copy_recovery_code",
            "release_policy",
            "check_release_policy",
            "open_update",
        ]),
    ))
    .expect("application build configuration");
    macos_diagnostics_resources::stage().expect("macOS SDK privacy resources");
    ios_resources::stage().expect("iOS SDK privacy resources");
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

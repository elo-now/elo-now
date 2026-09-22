use serde_json::Value;
use std::process::{Command, Output};
use tempfile::TempDir;

fn elo(directory: &TempDir, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_elo"))
        .arg("--data-dir")
        .arg(directory.path().join("client"))
        .args(arguments)
        .output()
        .unwrap()
}

fn json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn insecure_demo_requires_explicit_opt_in_without_creating_a_database() {
    let directory = TempDir::new().unwrap();
    let output = elo(&directory, &["dev", "storage-demo"]);
    assert!(!output.status.success());
    assert!(!directory.path().join("client").exists());
}

#[test]
fn two_processes_reuse_one_record_and_two_targets() {
    let directory = TempDir::new().unwrap();
    let args = ["dev", "storage-demo", "--allow-insecure-fixtures"];
    let first = json(elo(&directory, &args));
    let second = json(elo(&directory, &args));
    assert_eq!(first["result"], "inserted");
    assert_eq!(second["result"], "already_present");
    assert_eq!(first["record_id"], second["record_id"]);
    let stats = json(elo(&directory, &["store", "stats"]));
    assert_eq!(stats["objects"], 1);
    assert_eq!(stats["records"], 1);
    assert_eq!(stats["pending"], 2);
    let jobs = json(elo(&directory, &["outbox", "list"]));
    assert_eq!(jobs.as_array().unwrap().len(), 2);
}

#[test]
fn help_does_not_require_a_data_directory() {
    let output = Command::new(env!("CARGO_BIN_EXE_elo"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("alpha gates are not complete"));
}

#[test]
fn invalid_directory_exits_with_failure() {
    let directory = TempDir::new().unwrap();
    std::fs::write(directory.path().join("client"), "not a directory").unwrap();
    assert!(!elo(&directory, &["store", "init"]).status.success());
}

#[test]
fn private_vault_backup_and_root_recovery_across_real_processes() {
    use std::{io::Write, process::Stdio};
    let directory = TempDir::new().unwrap();
    let run = |name: &str, args: &[&str], password: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_elo"))
            .arg("--data-dir")
            .arg(directory.path().join(name))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{password}\n").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!String::from_utf8_lossy(&output.stdout).contains(password));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(password));
        output
    };
    let password = "synthetic CLI integration passphrase";
    let recovery = directory.path().join("recovery.json");
    let backup = directory.path().join("backup.age");
    let first = json(run(
        "first",
        &[
            "identity",
            "create",
            "--recovery-out",
            recovery.to_str().unwrap(),
            "--password-stdin",
        ],
        password,
    ));
    let expected = first["identity_id"].as_str().unwrap();
    let card: Value = serde_json::from_slice(&std::fs::read(&recovery).unwrap()).unwrap();
    assert!(!first.to_string().contains(card["phrase"].as_str().unwrap()));
    assert!(
        !run(
            "first",
            &[
                "vault",
                "backup",
                "--output",
                backup.to_str().unwrap(),
                "--password-stdin"
            ],
            "incorrect passphrase for test"
        )
        .status
        .success()
    );
    assert!(!backup.exists());
    json(run(
        "first",
        &[
            "vault",
            "backup",
            "--output",
            backup.to_str().unwrap(),
            "--password-stdin",
        ],
        password,
    ));
    let restored = json(run(
        "restored",
        &[
            "vault",
            "restore",
            "--input",
            backup.to_str().unwrap(),
            "--expected-identity",
            expected,
            "--password-stdin",
        ],
        password,
    ));
    assert_eq!(restored, first);
    let recovered = json(run(
        "recovered",
        &[
            "identity",
            "recover",
            "--recovery-card",
            recovery.to_str().unwrap(),
            "--expected-identity",
            expected,
            "--password-stdin",
        ],
        password,
    ));
    assert_eq!(recovered["identity_id"], first["identity_id"]);
    assert_ne!(recovered["credential_id"], first["credential_id"]);
    assert!(
        !run(
            "first",
            &[
                "identity",
                "create",
                "--recovery-out",
                recovery.to_str().unwrap(),
                "--password-stdin"
            ],
            password
        )
        .status
        .success()
    );
    let still_first = json(run("first", &["identity", "show"], password));
    assert_eq!(still_first, first);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [recovery, backup, directory.path().join("first/vault.age")] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

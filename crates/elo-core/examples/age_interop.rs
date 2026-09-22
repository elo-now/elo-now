//! Explicit external reference check; requires Go age path as the sole argument.
use age::secrecy::ExposeSecret;
use elo_core::{
    crypto::{open_record, seal_record},
    record::SignedRecord,
};
use std::{
    error::Error,
    fs,
    io::Write,
    process::{Command, Stdio},
};
fn main() -> Result<(), Box<dyn Error>> {
    let age = std::env::args_os()
        .nth(1)
        .ok_or("expected Go age executable path")?;
    let version = Command::new(&age).arg("--version").output()?;
    if !version.status.success() {
        return Err("reference unavailable".into());
    }
    println!(
        "Go age: {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    let dir = tempfile::TempDir::new()?;
    let identity = age::x25519::Identity::generate();
    let path = dir.path().join("test-identity.txt");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    writeln!(file, "{}", identity.to_string().expose_secret())?;
    drop(file);
    let fixture = SignedRecord::parse(include_bytes!(
        "../../../protocol/fixtures/chat-message-v1.record.bin"
    ))?;
    let large = SignedRecord::sign(
        &serde_json::to_vec(
            &serde_json::json!({"v":1,"kind":"dev.interop","padding":"x".repeat(100_000)}),
        )?,
        &ed25519_dalek::SigningKey::from_bytes(&[42; 32]),
    )?;
    for record in [fixture, large] {
        let ciphertext = seal_record(&record, &[identity.to_public()])?;
        let c = dir.path().join("rust.age");
        fs::write(&c, &ciphertext)?;
        let result = Command::new(&age)
            .args(["-d", "-i"])
            .arg(&path)
            .arg(&c)
            .output()?;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, record.bytes());
        let mut child = Command::new(&age)
            .args(["-r", &identity.to_public().to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Keep writer concurrent with reading output for records larger than a pipe.
        let mut input = child.stdin.take().ok_or("missing stdin")?;
        let bytes = record.bytes().to_vec();
        let writer = std::thread::spawn(move || input.write_all(&bytes));
        let result = child.wait_with_output()?;
        writer.join().map_err(|_| "writer panicked")??;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            open_record(&result.stdout, &identity)?.bytes(),
            record.bytes()
        );
        assert!(open_record(&result.stdout[..result.stdout.len() - 1], &identity).is_err());
        println!(
            "PASS Rust -> Go and Go -> Rust: {} exact ELO1 bytes; truncated Go ciphertext rejected",
            record.bytes().len()
        );
    }
    Ok(())
}

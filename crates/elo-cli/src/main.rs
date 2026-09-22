use std::{
    error::Error,
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use elo_core::{
    ids::{MailboxId, PeerId, RecordId},
    store::{
        ClientStore, CommitDisposition, DeliveryTarget, LocalTime, PreparedLocalRecord,
        RecordMetadata, StoreStats,
    },
};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Parser)]
#[command(
    name = "elo",
    version,
    about = "elo.now experimental local-first communication; alpha gates are not complete"
)]
struct Cli {
    /// Explicit client directory. Use a disposable directory for the fixture demo.
    #[arg(long)]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Sync with an explicitly supplied synthetic fixture (T05 lab mode).
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    /// Ciphertext-only storage; always use a directory separate from clients.
    Replica {
        #[command(subcommand)]
        command: ReplicaCommand,
    },
    /// Initialize or inspect a local client database.
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
    /// Inspect pending deliveries. Does not send anything.
    Outbox {
        #[command(subcommand)]
        command: OutboxCommand,
    },
    /// Explicitly insecure development fixtures; never use with real data.
    Dev {
        #[command(subcommand)]
        command: DevCommand,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Creates fresh independent keys and a separate private recovery export.
    Create {
        #[arg(long)]
        recovery_out: PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Restores root only; creates a NEW device requiring fresh membership approval.
    Recover {
        #[arg(long)]
        recovery_card: PathBuf,
        #[arg(long)]
        expected_identity: elo_core::ids::IdentityId,
        #[arg(long)]
        password_stdin: bool,
    },
    Show,
}
#[derive(Subcommand)]
enum VaultCommand {
    Backup {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
    Restore {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        expected_identity: elo_core::ids::IdentityId,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum SyncCommand {
    Once {
        #[arg(long)]
        demo_config: PathBuf,
        #[arg(long)]
        allow_insecure_fixtures: bool,
    },
    Watch {
        #[arg(long)]
        demo_config: PathBuf,
        #[arg(long)]
        allow_insecure_fixtures: bool,
    },
}

#[derive(Subcommand)]
enum ReplicaCommand {
    Init,
    /// Reclaim free pages and enable incremental reclamation. Stop the service first.
    Compact,
    /// Emits fresh read/write tokens once; store the descriptor privately.
    MailboxCreate {
        #[arg(long, default_value_t = 67108864)]
        quota_bytes: u64,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: std::net::SocketAddr,
        #[arg(long)]
        allow_insecure_loopback: bool,
    },
}

#[derive(Subcommand)]
enum StoreCommand {
    Init,
    Stats,
}

#[derive(Subcommand)]
enum OutboxCommand {
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        at_ms: Option<u64>,
    },
}

#[derive(Subcommand)]
enum DevCommand {
    /// Store one public, UNENCRYPTED fixture plus two delivery targets.
    StorageDemo {
        #[arg(long)]
        allow_insecure_fixtures: bool,
    },
}

fn now() -> Result<LocalTime> {
    let millis = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    Ok(LocalTime::from_millis(millis)?)
}

fn stats_json(stats: StoreStats) -> Value {
    json!({
        "objects": stats.objects, "records": stats.records, "sources": stats.sources,
        "pending": stats.pending, "inflight": stats.inflight, "stored": stats.stored,
        "held": stats.held, "rejected": stats.rejected,
    })
}

async fn execute(store: &ClientStore, command: Command) -> Result<Value> {
    match command {
        Command::Identity { .. }
        | Command::Vault { .. }
        | Command::Sync { .. }
        | Command::Replica { .. } => Err("replica commands require separate storage".into()),
        Command::Store {
            command: StoreCommand::Init,
        } => Ok(json!({
            "status": "initialized", "schema_version": 3,
            "warning": "Local storage initialized; durability is not remote delivery.",
        })),
        Command::Store {
            command: StoreCommand::Stats,
        } => Ok(stats_json(store.stats().await?)),
        Command::Outbox {
            command: OutboxCommand::List { limit, at_ms },
        } => {
            let at = match at_ms {
                Some(value) => LocalTime::from_millis(value)?,
                None => now()?,
            };
            let rows = store.list_due(at, limit).await?;
            Ok(Value::Array(rows.into_iter().map(|row| json!({
                "record_id": row.record_id.to_string(), "object_id": row.object_id.to_string(),
                "peer_id": row.target.peer_id.to_string(), "mailbox_id": row.target.mailbox_id.to_string(),
                "attempts": row.attempts, "next_attempt_local_ms": row.next_attempt_local_ms,
            })).collect()))
        }
        Command::Dev {
            command: DevCommand::StorageDemo { .. },
        } => {
            let input = PreparedLocalRecord::new(
                RecordId::of_record_bytes(b"PUBLIC T01 STORAGE FIXTURE RECORD; NOT A SIGNED EVENT"),
                b"PUBLIC T01 OPAQUE FIXTURE BYTES; NOT ENCRYPTED; NEVER TRANSMIT".to_vec(),
                RecordMetadata::new("dev.storage_fixture", None, None, None)?,
                vec![
                    DeliveryTarget {
                        peer_id: PeerId::from_bytes([1; 32]),
                        mailbox_id: MailboxId::from_bytes([2; 32]),
                    },
                    DeliveryTarget {
                        peer_id: PeerId::from_bytes([3; 32]),
                        mailbox_id: MailboxId::from_bytes([4; 32]),
                    },
                ],
                now()?,
            )?;
            let result = store.commit_local_record_with_outbox(input).await?;
            Ok(json!({
                "warning": "UNENCRYPTED PUBLIC FIXTURE. No message was sent to anyone.",
                "result": match result.disposition {
                    CommitDisposition::Inserted => "inserted", CommitDisposition::AlreadyPresent => "already_present",
                },
                "record_id": result.record_id.to_string(), "object_id": result.object_id.to_string(),
                "initial_targets": result.target_count, "stats": stats_json(store.stats().await?),
            }))
        }
    }
}

fn vault_password(from_stdin: bool) -> Result<age::secrecy::SecretString> {
    if from_stdin {
        use std::io::{BufRead, IsTerminal};
        if std::io::stdin().is_terminal() {
            return Err(
                "--password-stdin requires piped input; omit it for a hidden prompt".into(),
            );
        }
        let mut line = zeroize::Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut line)?;
        while line.ends_with(['\n', '\r']) {
            line.pop();
        }
        Ok(line.to_string().into())
    } else {
        Ok(rpassword::prompt_password("Vault passphrase: ")?.into())
    }
}
fn save_profile(
    directory: &std::path::Path,
    session: &elo_core::vault::Session,
    ciphertext: &[u8],
) -> Result<()> {
    let public = json!({"identity_id":session.identity_id(),"credential_id":session.credential().id(),"root_public_key":session.credential().record().body()["root_public_key"]});
    elo_core::vault::write_private(&directory.join("vault.age"), ciphertext, false)?;
    elo_core::vault::write_private(
        &directory.join("profile.json"),
        &serde_json::to_vec(&public)?,
        false,
    )?;
    println!("{}", public);
    Ok(())
}
async fn run(cli: Cli) -> Result<()> {
    if let Command::Identity { command } = cli.command {
        use elo_core::vault::{RecoveryCard, Session};
        match command {
            IdentityCommand::Show => {
                let bytes = elo_core::vault::read_private(&cli.data_dir.join("profile.json"))?;
                let public: Value = serde_json::from_slice(&bytes)?;
                println!("{}", public);
            }
            IdentityCommand::Create {
                recovery_out,
                password_stdin,
            } => {
                let password = vault_password(password_stdin)?;
                let (session, card) = Session::create()?;
                let encrypted = session.seal(password)?;
                let store = ClientStore::open(&cli.data_dir).await?;
                if cli.data_dir.join("vault.age").exists()
                    || cli.data_dir.join("profile.json").exists()
                {
                    store.close().await?;
                    return Err("profile already exists".into());
                }
                let recovery_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&card)?);
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                use std::io::Write;
                let mut output = options.open(recovery_out)?;
                output.write_all(&recovery_bytes)?;
                output.sync_all()?;
                drop(output);
                let result = save_profile(&cli.data_dir, &session, &encrypted);
                store.close().await?;
                result?;
            }
            IdentityCommand::Recover {
                recovery_card,
                expected_identity,
                password_stdin,
            } => {
                let password = vault_password(password_stdin)?;
                let bytes = zeroize::Zeroizing::new(elo_core::vault::read_private(&recovery_card)?);
                let card: RecoveryCard =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid recovery card")?;
                let session = Session::recover(&card, expected_identity)?;
                let encrypted = session.seal(password)?;
                let store = ClientStore::open(&cli.data_dir).await?;
                let result = save_profile(&cli.data_dir, &session, &encrypted);
                store.close().await?;
                result?;
            }
        }
        return Ok(());
    }
    if let Command::Vault { command } = cli.command {
        use elo_core::vault::{Session, read_private, write_private};
        match command {
            VaultCommand::Backup {
                output,
                password_stdin,
            } => {
                let password = vault_password(password_stdin)?;
                let profile: Value =
                    serde_json::from_slice(&read_private(&cli.data_dir.join("profile.json"))?)?;
                let expected = serde_json::from_value(profile["identity_id"].clone())?;
                let bytes = read_private(&cli.data_dir.join("vault.age"))?;
                Session::open(&bytes, password, expected)?;
                write_private(&output, &bytes, false)?;
                println!("{}", json!({"status":"encrypted_device_backup_written"}));
            }
            VaultCommand::Restore {
                input,
                expected_identity,
                password_stdin,
            } => {
                let password = vault_password(password_stdin)?;
                let session = Session::restore_backup(
                    &read_private(&input)?,
                    password.clone(),
                    expected_identity,
                )?;
                let encrypted = session.seal(password)?;
                let store = ClientStore::open(&cli.data_dir).await?;
                let result = save_profile(&cli.data_dir, &session, &encrypted);
                store.close().await?;
                result?;
            }
        }
        return Ok(());
    }
    if let Command::Sync { command } = cli.command {
        let (path, allowed, watch) = match command {
            SyncCommand::Once {
                demo_config,
                allow_insecure_fixtures,
            } => (demo_config, allow_insecure_fixtures, false),
            SyncCommand::Watch {
                demo_config,
                allow_insecure_fixtures,
            } => (demo_config, allow_insecure_fixtures, true),
        };
        if !allowed {
            return Err(
                "synthetic sync requires --allow-insecure-fixtures; use desktop for protected profiles".into(),
            );
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 256 * 1024 {
            return Err("demo config too large".into());
        }
        let config: elo_core::demo::DemoConfig =
            serde_json::from_slice(&bytes).map_err(|_| "invalid synthetic config")?;
        let demo = config.load()?;
        let store = ClientStore::open(&cli.data_dir).await?;
        let client = elo_core::sync::SyncClient {
            store: &store,
            identity: &demo.identity,
            credential: demo.own_credential,
            authority: &demo.authority,
            peers: &demo.peers,
        };
        let result: Result<()> = async {
            loop {
                let report = client.once(now()?).await?;
                println!("{}", serde_json::to_string(&report)?);
                if !watch { break; }
                tokio::select! { _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}, _ = tokio::signal::ctrl_c() => break }
            }
            Ok(())
        }.await;
        store.close().await?;
        return result;
    }
    if let Command::Replica { command } = cli.command {
        let store = elo_core::replica::ReplicaStore::open(&cli.data_dir).await?;
        match command {
            ReplicaCommand::Init => println!(
                "{}",
                json!({"peer_id":store.peer_id(),"signing_public_key":elo_core::record::encode_hex(store.key().as_bytes())})
            ),
            ReplicaCommand::Compact => {
                store.compact_storage().await?;
                println!("{}", json!({"status":"replica_compacted"}));
            }
            ReplicaCommand::MailboxCreate { quota_bytes } => println!(
                "{}",
                serde_json::to_string(&store.create_mailbox(quota_bytes).await?)?
            ),
            ReplicaCommand::Serve {
                bind,
                allow_insecure_loopback,
            } => elo_core::http::serve(store, bind, allow_insecure_loopback).await?,
        }
        return Ok(());
    }
    // Fail before opening/creating a database when the insecure flag is missing.
    if matches!(
        &cli.command,
        Command::Dev {
            command: DevCommand::StorageDemo {
                allow_insecure_fixtures: false
            }
        }
    ) {
        return Err(
            "storage-demo requires --allow-insecure-fixtures and a disposable data directory"
                .into(),
        );
    }
    let store = ClientStore::open(&cli.data_dir).await?;
    let result = execute(&store, cli.command).await;
    let closed = store.close().await;
    let value = result?;
    closed?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("elo: {error}");
            ExitCode::FAILURE
        }
    }
}

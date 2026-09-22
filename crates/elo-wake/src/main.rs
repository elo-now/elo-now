use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "elo.now private FCM wake service")]
struct Args {
    #[arg(long)]
    service_account: PathBuf,
    /// Private APNs provider configuration for actual incoming iOS calls.
    #[arg(long, requires = "call_key")]
    apns_config: Option<PathBuf>,
    /// Private shared key file for the loopback call-control listener.
    #[arg(long)]
    call_key: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:8794")]
    call_listen: std::net::SocketAddr,
    /// Validate OAuth authentication without sending a notification.
    #[arg(long)]
    check_authentication: bool,
    #[arg(long)]
    database: Option<PathBuf>,
    /// HTTPS origin of the service, used to bind signed account operations.
    #[arg(long)]
    public_url: Option<String>,
    /// Bind behind a TLS reverse proxy; the public endpoint must use HTTPS.
    #[arg(long, default_value = "127.0.0.1:8788")]
    listen: std::net::SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let fcm = elo_wake::fcm::Fcm::load(&args.service_account)?;
    if args.check_authentication {
        fcm.check_authentication().await?;
        println!("Firebase authentication succeeded. No notification was sent.");
        return Ok(());
    }
    let database = args
        .database
        .ok_or("Provide --database in a private directory")?;
    let mut relay = elo_wake::relay::Relay::open(&database, std::sync::Arc::new(fcm))?
        .with_endpoint(args.public_url.as_deref().ok_or("Provide --public-url")?)?;
    let calls = if let Some(path) = args.call_key {
        if !args.call_listen.ip().is_loopback() {
            return Err("Call delivery must bind to loopback.".into());
        }
        let key =
            zeroize::Zeroizing::new(String::from_utf8(elo_core::vault::read_private(&path)?)?);
        let apns = args
            .apns_config
            .as_deref()
            .map(elo_wake::apns::Apns::load)
            .transpose()?;
        relay = relay.with_calls(key, apns)?;
        let listener = tokio::net::TcpListener::bind(args.call_listen).await?;
        let router = relay.clone().private_call_router();
        Some(tokio::spawn(
            async move { axum::serve(listener, router).await },
        ))
    } else {
        None
    };
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    let worker = tokio::spawn(relay.clone().run());
    axum::serve(listener, relay.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    worker.abort();
    if let Some(calls) = calls {
        calls.abort();
    }
    Ok(())
}

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "elo.now private FCM wake service")]
struct Args {
    #[arg(long)]
    service_account: PathBuf,
    /// Validate OAuth authentication without sending a notification.
    #[arg(long)]
    check_authentication: bool,
    #[arg(long)]
    database: Option<PathBuf>,
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
    let relay = elo_wake::relay::Relay::open(&database, std::sync::Arc::new(fcm))?;
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    let worker = tokio::spawn(relay.clone().run());
    axum::serve(listener, relay.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    worker.abort();
    Ok(())
}

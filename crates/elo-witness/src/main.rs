use clap::Parser;
use elo_core::authority::WitnessPin;
use elo_witness::{
    engine::Engine,
    journal::Journal,
    server::{self, Service},
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(about = "Independent, ordered authorization witness")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    bind: SocketAddr,
    pin: WitnessPin,
    data: PathBuf,
    signing_key: PathBuf,
    startup_file: PathBuf,
    activation_file: PathBuf,
    #[serde(default)]
    trusted_loopback_proxy: bool,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config: Config =
        serde_json::from_slice(&elo_core::vault::read_private(&Cli::parse().config)?)?;
    config.pin.validate()?;
    if !config.bind.ip().is_loopback()
        || !config.pin.url.starts_with("https://")
        || !config.pin.url.ends_with("/witness/v1")
        || config.activation_file.starts_with(&config.data)
        || config.startup_file.starts_with(&config.data)
        || config.startup_file == config.activation_file
    {
        return Err("Invalid witness service configuration.".into());
    }
    let journal = Journal::open(
        &config.data,
        &config.signing_key,
        config.pin,
        elo_witness::now_ms()?,
    )?;
    // Stale activations from previous processes are never accepted.
    if config.activation_file.exists() {
        std::fs::remove_file(&config.activation_file)?;
    }
    elo_core::vault::write_private(
        &config.startup_file,
        &serde_json::to_vec(&journal.startup()?)?,
        true,
    )?;
    let service = Service::new(
        Engine { journal },
        config.activation_file,
        config.trusted_loopback_proxy,
    );
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(
        listener,
        server::router(service).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

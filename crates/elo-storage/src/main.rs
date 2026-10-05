use clap::Parser;
use elo_storage::{
    engine::Engine,
    server::{self, Service},
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Independent device-authorized attachment broker")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    bind: SocketAddr,
    public_url: String,
    data: PathBuf,
    secret_key: PathBuf,
    witness: elo_core::authority::WitnessPin,
    #[serde(default = "max_spaces")]
    max_spaces: usize,
    #[serde(default)]
    trusted_loopback_proxy: bool,
}
fn max_spaces() -> usize {
    128
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config: Config = serde_json::from_slice(&Zeroizing::new(elo_core::vault::read_private(
        &Cli::parse().config,
    )?))?;
    let url = reqwest::Url::parse(&config.public_url)?;
    if !config.bind.ip().is_loopback()
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/storage/v1"
        || config.secret_key.starts_with(&config.data)
    {
        return Err("Invalid independent storage service configuration.".into());
    }
    let engine = Engine::open(
        &config.data,
        &config.secret_key,
        config.public_url.clone(),
        config.max_spaces,
    )?;
    let service = Service::new(engine, config.public_url, config.witness)?
        .trust_loopback_proxy(config.trusted_loopback_proxy);
    let worker = service.clone();
    let maintenance = tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(30));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            worker.maintain().await;
        }
    });
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(
        listener,
        server::router(service).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    maintenance.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn production_configuration_requires_an_explicit_witness_pin() {
        let config = serde_json::json!({
            "bind": "127.0.0.1:8093",
            "public_url": "https://storage.example.test/storage/v1",
            "data": "/var/lib/elo-storage",
            "secret_key": "/etc/elo-storage/key"
        });
        assert!(serde_json::from_value::<Config>(config).is_err());
    }
}

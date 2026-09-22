use clap::Parser;
use elo_call_service::{
    engine::Engine,
    registry::Limits,
    server::{self, HostingAdmission, Service},
};
use elo_core::vault;
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Authenticated realtime control for elo.now calls")]
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
    admission_url: String,
    admission_key: PathBuf,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    media: Option<elo_call_service::media::Config>,
    #[serde(default = "default_connections")]
    max_connections: usize,
    #[serde(default)]
    wake: Option<elo_call_service::wake::Config>,
}
fn default_connections() -> usize {
    128
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config: Config =
        serde_json::from_slice(&Zeroizing::new(vault::read_private(&Cli::parse().config)?))?;
    if !config.bind.ip().is_loopback() {
        return Err("Bind call control to loopback behind HTTPS.".into());
    }
    let public = reqwest::Url::parse(&config.public_url)?;
    if public.scheme() != "https"
        || public.host_str().is_none()
        || !public.username().is_empty()
        || public.password().is_some()
        || public.query().is_some()
        || public.fragment().is_some()
        || public.path() != "/calls/v1"
        || config.max_connections == 0
        || config.max_connections > 4096
    {
        return Err("Invalid call-control configuration.".into());
    }
    if config.data.exists() {
        let metadata = std::fs::symlink_metadata(&config.data)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("Unsafe call storage directory.".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("Call storage must be private.".into());
            }
        }
    } else {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&config.data)?;
    }
    let database = config.data.join("calls.sqlite");
    if database.exists() && !std::fs::symlink_metadata(&database)?.is_file() {
        return Err("Unsafe call database.".into());
    }
    let engine = Engine::open(&database, config.public_url, config.limits)?;
    let key = Zeroizing::new(String::from_utf8(vault::read_private(
        &config.admission_key,
    )?)?);
    let admission = HostingAdmission::new(&config.admission_url, key)?;
    let media = config
        .media
        .map(elo_call_service::media::Provider::new)
        .transpose()?
        .map(Arc::new);
    let mut service =
        Service::with_media(engine, Arc::new(admission), config.max_connections, media);
    if let Some(config) = config.wake {
        service = service.with_wake(elo_call_service::wake::Delivery::new(config)?);
    }
    let wake_worker = service.clone();
    let delivery = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            wake_worker.deliver_wakes().await;
        }
    });
    let worker = service.clone();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            worker.maintain().await;
        }
    });
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    let result = axum::serve(listener, server::app(service))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    task.abort();
    delivery.abort();
    let _ = task.await;
    result?;
    Ok(())
}

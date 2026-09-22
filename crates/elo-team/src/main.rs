use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use elo_core::{
    app::{
        ClientApp, ProfileDraft,
        space_service::{Request as SpaceRequest, Response as SpaceResponse, ServiceConfig},
        team::{EnrollmentReply, EnrollmentRequest, TeamDescriptor},
    },
    record, vault,
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
mod attachments;
mod hosting;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Serve isolated, self-service Spaces and their ciphertext replica.
    Host {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:18900")]
        bind: std::net::SocketAddr,
    },
    Init {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        peer: PathBuf,
        #[arg(long)]
        descriptor: PathBuf,
        #[arg(long)]
        recovery: PathBuf,
        #[arg(long)]
        url: String,
    },
    ConfigureSpace {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        peer: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, required = true)]
        owner: Vec<elo_core::ids::IdentityId>,
        #[arg(long)]
        invitation: Option<PathBuf>,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8790")]
        bind: std::net::SocketAddr,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    profile: PathBuf,
    password: String,
    team: TeamDescriptor,
    #[serde(default)]
    spaces: Option<ServiceConfig>,
}
struct Server {
    client: Mutex<ClientApp>,
    token: Zeroizing<String>,
    spaces: Option<ServiceConfig>,
}
async fn spaces(
    State(state): State<Arc<Server>>,
    Json(request): Json<SpaceRequest>,
) -> std::result::Result<Json<SpaceResponse>, StatusCode> {
    let config = state.spaces.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let mut client = state
        .client
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    client
        .serve_space(config, request)
        .await
        .map(Json)
        .map_err(|_| StatusCode::BAD_REQUEST)
}
async fn enroll(
    State(state): State<Arc<Server>>,
    headers: HeaderMap,
    Json(request): Json<EnrollmentRequest>,
) -> std::result::Result<Json<EnrollmentReply>, StatusCode> {
    let supplied = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if !bool::from(supplied.as_bytes().ct_eq(state.token.as_bytes())) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // Bounded admission: no unbounded queue of expensive operations.
    let mut client = state
        .client
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    client
        .enroll_team_member(request)
        .await
        .map(Json)
        .map_err(|_| StatusCode::BAD_REQUEST)
}
fn app(state: Arc<Server>) -> Router {
    Router::new()
        .route("/team/v1/health", get(|| async { StatusCode::OK }))
        .route("/team/v1/enroll", post(enroll))
        .route("/team/v1/spaces", post(spaces))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}
async fn operator_statistics(
    State(state): State<Arc<Server>>,
) -> std::result::Result<Json<serde_json::Value>, StatusCode> {
    let client = state
        .client
        .try_lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    client
        .space_service_statistics()
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
async fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Host { config, bind } => hosting::run(config, bind).await?,
        Command::Init {
            config,
            profile,
            peer,
            descriptor,
            recovery,
            url,
        } => {
            if config.exists() || descriptor.exists() || recovery.exists() || profile.exists() {
                return Err("Initialization requires new output paths.".into());
            }
            let peer: serde_json::Value =
                serde_json::from_slice(&Zeroizing::new(vault::read_private(&peer)?))?;
            let mut peer: elo_core::sync::PeerDescriptor =
                serde_json::from_value(peer.get("peer").unwrap_or(&peer).clone())?;
            peer.read_token = None;
            let password = Zeroizing::new(record::random_hex::<32>()?);
            let token = record::random_hex::<32>()?;
            let draft = ProfileDraft::new()?;
            vault::write_private(
                &recovery,
                &Zeroizing::new(serde_json::to_vec(draft.card())?),
                false,
            )?;
            let mut client = draft
                .save_named(
                    profile.clone(),
                    password.to_string().into(),
                    "General",
                    "elo.now",
                )
                .await?;
            client.ensure_peer(peer)?;
            let team = TeamDescriptor {
                v: 1,
                url,
                token,
                scope: client.team_scope()?,
                message_lifetime_seconds: 86_400,
            };
            team.validate(false)?;
            vault::write_private(
                &descriptor,
                &Zeroizing::new(serde_json::to_vec_pretty(&team)?),
                false,
            )?;
            let config_value = Config {
                profile,
                password: password.to_string(),
                team,
                spaces: None,
            };
            vault::write_private(
                &config,
                &Zeroizing::new(serde_json::to_vec(&config_value)?),
                false,
            )?;
            client.close().await?;
            println!("General initialized. Private configuration and recovery files were saved.");
        }
        Command::ConfigureSpace {
            config,
            peer,
            name,
            mut owner,
            invitation,
        } => {
            if !record::valid_display_name(&name) {
                return Err("Invalid Space name.".into());
            }
            owner.sort();
            owner.dedup();
            if owner.is_empty() || owner.len() > 16 {
                return Err("Choose between one and sixteen owners.".into());
            }
            if invitation.as_ref().is_some_and(|path| path.exists()) {
                return Err("Choose a new invitation output path.".into());
            }
            let mut value: Config =
                serde_json::from_slice(&Zeroizing::new(vault::read_private(&config)?))?;
            let peer: serde_json::Value =
                serde_json::from_slice(&Zeroizing::new(vault::read_private(&peer)?))?;
            let descriptor: elo_core::sync::PeerDescriptor =
                serde_json::from_value(peer.get("peer").unwrap_or(&peer).clone())?;
            if descriptor.read_token.is_none() || descriptor.write_token.is_none() {
                return Err("The Space needs its private read/write mailbox descriptor.".into());
            }
            let candidate = elo_core::sync::Peer::new(descriptor.clone(), false)?;
            let client =
                ClientApp::open(value.profile.clone(), value.password.clone().into(), false)
                    .await?;
            if !client.local_replica_descriptors().iter().any(|peer| {
                elo_core::sync::Peer::new(peer.clone(), false).is_ok_and(|peer| {
                    peer.id() == candidate.id() && peer.mailbox() == candidate.mailbox()
                })
            }) {
                return Err("The descriptor must match this service mailbox.".into());
            }
            let address = elo_core::app::space_service::SpaceAddress {
                url: value.team.url.replace("/team/v1/enroll", "/team/v1/spaces"),
                scope: client.team_scope()?,
                message_lifetime_seconds: value.team.message_lifetime_seconds,
            };
            address.validate(false)?;
            if let Some(path) = invitation {
                let link = client.bootstrap_space_invitation(&address)?;
                vault::write_private(&path, link.as_bytes(), false)?;
            }
            value.spaces = Some(ServiceConfig {
                name,
                address,
                owners: owner,
                contact_email: None,
                peer: descriptor,
            });
            vault::write_private(&config, &Zeroizing::new(serde_json::to_vec(&value)?), true)?;
            client.close().await?;
            println!("Space ownership configured. Any bootstrap invitation was saved privately.");
        }
        Command::Serve { config, bind } => {
            if !bind.ip().is_loopback() || bind.port() == 65535 {
                return Err("Bind to loopback behind the HTTPS proxy.".into());
            }
            let config: Config =
                serde_json::from_slice(&Zeroizing::new(vault::read_private(&config)?))?;
            config.team.validate(false)?;
            let client = ClientApp::open(config.profile, config.password.into(), false).await?;
            let scope = client.team_scope()?;
            if scope.space != config.team.scope.space
                || scope.stream != config.team.scope.stream
                || scope.root != config.team.scope.root
                || scope.controller != config.team.scope.controller
            {
                return Err("The General profile does not match its pinned configuration.".into());
            }
            let state = Arc::new(Server {
                client: Mutex::new(client),
                token: Zeroizing::new(config.team.token),
                spaces: config.spaces,
            });
            let worker = state.clone();
            let task = tokio::spawn(async move {
                let mut timer = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    timer.tick().await;
                    let client = worker.client.lock().await;
                    let _ = client.deliver_team_memberships().await;
                }
            });
            let listener = tokio::net::TcpListener::bind(bind).await?;
            // Private operator metadata on a separate loopback listener. Never
            // merge this endpoint into the public enrollment router.
            let operator_listener = tokio::net::TcpListener::bind(std::net::SocketAddr::new(
                bind.ip(),
                bind.port() + 1,
            ))
            .await?;
            let operator_router = Router::new()
                .route("/stats", get(operator_statistics))
                .with_state(state.clone());
            let operator_task =
                tokio::spawn(async move { axum::serve(operator_listener, operator_router).await });
            let result = axum::serve(listener, app(state.clone()))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await;
            task.abort();
            let _ = task.await;
            operator_task.abort();
            let _ = operator_task.await;
            let state = Arc::try_unwrap(state).map_err(|_| "Could not close General safely.")?;
            state.client.into_inner().close().await?;
            result?;
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Never log request bodies, transport tokens, contact cards or vault errors.
        eprintln!("General service failed. Check its private configuration and storage.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elo_core::replica::ReplicaStore;
    use serde_json::{Value, json};
    const PASSWORD: &str = "synthetic General HTTP test password";
    async fn profile(root: &std::path::Path, name: &str) -> ClientApp {
        ProfileDraft::new()
            .unwrap()
            .save_named(root.join(name), PASSWORD.into(), "General", name)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        ClientApp::open(root.join(name), PASSWORD.into(), true)
            .await
            .unwrap()
    }
    async fn sync(client: &mut ClientApp) {
        client.operate(json!({"op":"sync"})).await.unwrap();
    }
    fn general<'a>(view: &'a Value, descriptor: &TeamDescriptor) -> &'a Value {
        view["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stream"] == json!(descriptor.scope.stream))
            .unwrap()
    }
    async fn send(client: &mut ClientApp, descriptor: &TeamDescriptor, text: &str) {
        client.operate(json!({"op":"send","space":descriptor.scope.space,"stream":descriptor.scope.stream,"text":text,"created_at":"2026-09-12T00:00:00Z"})).await.unwrap();
        sync(client).await;
    }
    #[tokio::test]
    async fn http_enrollment_auth_scope_offline_delivery_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = profile(dir.path(), "Administrator").await;
        let mut alex = profile(dir.path(), "Alex").await;
        let mut maya = profile(dir.path(), "Maya").await;
        let replica = ReplicaStore::open(dir.path().join("replica"))
            .await
            .unwrap();
        let mailbox = replica.create_mailbox(64 * 1024 * 1024).await.unwrap();
        let replica_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = elo_core::sync::PeerDescriptor {
            url: format!("http://{}/", replica_listener.local_addr().unwrap()),
            signing_public_key: record::encode_hex(replica.key().as_bytes()),
            mailbox_id: mailbox.mailbox_id,
            read_token: Some(mailbox.read_token),
            write_token: Some(mailbox.write_token),
        };
        let replica_task = tokio::spawn(async move {
            axum::serve(replica_listener, elo_core::http::router(replica))
                .await
                .unwrap()
        });
        for client in [&mut alex, &mut maya] {
            client.ensure_peer(peer.clone()).unwrap();
        }
        owner
            .ensure_peer(elo_core::sync::PeerDescriptor {
                read_token: None,
                ..peer.clone()
            })
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let descriptor = TeamDescriptor {
            v: 1,
            url: format!("http://{}/team/v1/enroll", listener.local_addr().unwrap()),
            token: "fe".repeat(32),
            scope: owner.team_scope().unwrap(),
            message_lifetime_seconds: 86_400,
        };
        let state = Arc::new(Server {
            client: Mutex::new(owner),
            token: Zeroizing::new(descriptor.token.clone()),
            spaces: Some(ServiceConfig {
                name: "Demo".into(),
                address: elo_core::app::space_service::SpaceAddress {
                    url: descriptor.url.replace("/enroll", "/spaces"),
                    scope: descriptor.scope.clone(),
                    message_lifetime_seconds: descriptor.message_lifetime_seconds,
                },
                owners: vec![alex.identity_id()],
                contact_email: None,
                peer,
            }),
        });
        let router = app(state.clone());
        let service_task =
            tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let request = alex.team_enrollment_request(&descriptor.scope).unwrap();
        assert_eq!(
            http.post(&descriptor.url)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut wrong_scope = descriptor.scope.clone();
        wrong_scope.stream = record::random_hex::<16>().unwrap().parse().unwrap();
        let request = alex.team_enrollment_request(&wrong_scope).unwrap();
        assert_eq!(
            http.post(&descriptor.url)
                .bearer_auth(&descriptor.token)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            http.post(&descriptor.url)
                .bearer_auth(&descriptor.token)
                .json(&json!({"v":1,"contact":"x".repeat(70_000),"proof":"x"}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        alex.configure_team(descriptor.clone()).unwrap();
        sync(&mut alex).await;
        assert_eq!(
            general(&alex.view().await.unwrap(), &descriptor)["members"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        send(&mut alex, &descriptor, "Before Maya joined").await;
        alex.close().await.unwrap();
        maya.configure_team(descriptor.clone()).unwrap();
        sync(&mut maya).await;
        assert!(
            general(&maya.view().await.unwrap(), &descriptor)["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        state
            .client
            .lock()
            .await
            .deliver_team_memberships()
            .await
            .unwrap();
        // Existing members are offline; the new member can already send.
        send(&mut maya, &descriptor, "Hello Alex").await;
        maya.close().await.unwrap();
        let mut alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
            .await
            .unwrap();
        alex.configure_team(descriptor.clone()).unwrap();
        sync(&mut alex).await;
        let view = alex.view().await.unwrap();
        let chat = general(&view, &descriptor);
        assert_eq!(
            chat["members"].as_array().unwrap().len(),
            3,
            "existing members learn about new recipients through Replica"
        );
        assert!(
            chat["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["body"]["payload"]["text"] == "Hello Alex"),
            "offline sender delivery"
        );
        send(&mut alex, &descriptor, "Hello Maya").await;
        alex.close().await.unwrap();
        let mut maya = ClientApp::open(dir.path().join("Maya"), PASSWORD.into(), true)
            .await
            .unwrap();
        maya.configure_team(descriptor.clone()).unwrap();
        sync(&mut maya).await;
        let view = maya.view().await.unwrap();
        let rows = general(&view, &descriptor)["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .any(|r| r["body"]["payload"]["text"] == "Hello Alex")
        );
        assert!(
            rows.iter()
                .any(|r| r["body"]["payload"]["text"] == "Hello Maya")
        );
        assert!(
            !rows
                .iter()
                .any(|r| r["body"]["payload"]["text"] == "Before Maya joined")
        );
        assert_eq!(
            view["invitations"]["actionable"], 0,
            "General never asks for manual acceptance"
        );
        maya.close().await.unwrap();
        // Exercise the actual Space HTTP endpoint, including migration of the
        // existing owner and approval of a freshly registered profile.
        let mut alex = ClientApp::open(dir.path().join("Alex"), PASSWORD.into(), true)
            .await
            .unwrap();
        alex.configure_team(descriptor.clone()).unwrap();
        alex.enable_spaces().await.unwrap();
        let space_id = descriptor.scope.space.to_string();
        let offer = alex
            .operate(json!({"op":"space_invite", "id":space_id,
            "body":{"lifetime":86400,"require_approval":true}}))
            .await
            .unwrap();
        let link = offer["result"]["link"].as_str().unwrap();
        let mut newcomer = profile(dir.path(), "Newcomer").await;
        newcomer.begin_space_setup().await.unwrap();
        let preview = newcomer
            .operate(json!({"op":"space_preview","link":link}))
            .await
            .unwrap();
        assert_eq!(preview["preview"]["name"], "Demo");
        let joined = newcomer
            .operate(json!({"op":"space_join","link":link}))
            .await
            .unwrap();
        assert_eq!(joined["view"]["spaces"][0]["status"], "pending");
        assert!(joined["view"]["replicas"].as_array().unwrap().is_empty());
        let management = alex
            .operate(json!({"op":"space_manage","id":space_id,"body":{}}))
            .await
            .unwrap();
        alex.operate(json!({"op":"space_decide","id":space_id,"body":{
            "id":management["result"]["requests"][0]["id"],"approve":true
        }}))
        .await
        .unwrap();
        sync(&mut newcomer).await;
        let ready = newcomer.view().await.unwrap();
        assert_eq!(ready["spaces"][0]["status"], "joined");
        assert_eq!(ready["replicas"].as_array().unwrap().len(), 1);
        assert!(
            general(&ready, &descriptor)["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        newcomer.close().await.unwrap();
        alex.close().await.unwrap();
        service_task.abort();
        let _ = service_task.await;
        let state = Arc::try_unwrap(state).ok().unwrap();
        state.client.into_inner().close().await.unwrap();
        replica_task.abort();
        let _ = replica_task.await;
    }
}

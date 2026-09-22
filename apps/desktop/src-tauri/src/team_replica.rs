//! Opt-in team builds embed only a separately provisioned test mailbox.
//! Ordinary builds do not read or bundle a connection descriptor.
use elo_core::app::ClientApp;

pub fn demo_space_id() -> Option<String> {
    #[cfg(feature = "team-test-replica")]
    {
        let team: Option<elo_core::app::team::TeamDescriptor> = serde_json::from_slice(
            include_bytes!(concat!(env!("OUT_DIR"), "/team-general.json")),
        )
        .ok()?;
        team.map(|team| team.scope.space.to_string())
    }
    #[cfg(not(feature = "team-test-replica"))]
    None
}

pub async fn join_demo(client: &mut ClientApp) -> Result<(), String> {
    #[cfg(feature = "team-test-replica")]
    {
        let peer = serde_json::from_slice(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/team-replica.json"
        )))
        .map_err(|_| "The Demo connection is unavailable.")?;
        let team: Option<elo_core::app::team::TeamDescriptor> = serde_json::from_slice(
            include_bytes!(concat!(env!("OUT_DIR"), "/team-general.json")),
        )
        .map_err(|_| "The Demo connection is unavailable.")?;
        client
            .join_default_space(peer, team.ok_or("Demo is unavailable in this build.")?)
            .await
            .map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "team-test-replica"))]
    {
        let _ = client;
        Err("Demo is unavailable in this build.".into())
    }
}

pub fn configure(client: &mut ClientApp) -> Result<(), String> {
    #[cfg(feature = "team-test-replica")]
    {
        if !client
            .allows_default_space()
            .map_err(|_| "Could not read Spaces.")?
        {
            return Ok(());
        }
        let descriptor = serde_json::from_slice(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/team-replica.json"
        )))
        .map_err(|_| "The test connection is invalid. Rebuild this app.")?;
        // The same validation and encrypted vault commit used by Add Replica.
        // No network request, history rewrite or plaintext staging is needed.
        client
            .ensure_peer(descriptor)
            .map_err(|_| "Could not save the test connection. Try unlocking again.")?;
        let team: Option<elo_core::app::team::TeamDescriptor> = serde_json::from_slice(
            include_bytes!(concat!(env!("OUT_DIR"), "/team-general.json")),
        )
        .map_err(|_| "The team configuration is invalid. Rebuild this app.")?;
        if let Some(team) = team {
            client
                .configure_team(team)
                .map_err(|_| "Could not configure General.")?;
        }
    }
    #[cfg(not(feature = "team-test-replica"))]
    let _ = client;
    Ok(())
}

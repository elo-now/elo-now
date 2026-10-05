//! Only the compiled native configuration supplies the witness anchor.
use elo_core::app::ClientApp;

pub(crate) fn configure_client(client: &mut ClientApp) -> Result<(), String> {
    let value = env!("ELO_CONFIGURED_WITNESS");
    let pin = if value.is_empty() {
        None
    } else {
        Some(serde_json::from_str(value).map_err(|_| "Invalid witness configuration.")?)
    };
    client
        .configure_invitation_host(env!("ELO_CONFIGURED_SPACE_HOST"))
        .map_err(|error| error.to_string())?;
    client
        .configure_witness_pin(pin)
        .map_err(|error| error.to_string())
}

pub(crate) fn resumed(app: &tauri::AppHandle) {
    use tauri::Manager;
    // Stop live publication immediately, including while a foreground request
    // still owns the profile mutex. Reactivation uses invalidated lease state.
    crate::realtime::clear(app);
    let state = app.state::<crate::State>();
    if let Ok(state) = state.try_lock() {
        if let Some(client) = &state.client {
            client.invalidate_permission_leases();
            crate::realtime::activate(app, client);
        }
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<crate::State>();
        let state = state.lock().await;
        if let Some(client) = &state.client {
            client.invalidate_permission_leases();
            crate::realtime::activate(&app, client);
        }
    });
}

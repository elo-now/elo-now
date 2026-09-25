//! Always available iOS privacy APIs; no generic renderer-facing commands.
#[cfg(target_os = "ios")]
use tauri::Manager;
#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_elo_privacy);
#[cfg(target_os = "ios")]
pub struct Privacy(tauri::plugin::PluginHandle<tauri::Wry>);
#[cfg(target_os = "ios")]
impl Privacy {
    pub fn call(&self, method: &str, args: serde_json::Value) -> Result<(), String> {
        self.0
            .run_mobile_plugin::<serde_json::Value>(method, args)
            .map(|_| ())
            .map_err(|_| "Native privacy operation failed.".into())
    }
}
pub fn init() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("elo-privacy")
        .setup(|app, api| {
            #[cfg(target_os = "ios")]
            app.manage(Privacy(api.register_ios_plugin(init_plugin_elo_privacy)?));
            #[cfg(not(target_os = "ios"))]
            let _ = (app, api);
            Ok(())
        })
        .build()
}

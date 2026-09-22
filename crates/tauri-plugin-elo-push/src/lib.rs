//! Native FCM access is mediated by the application's Rust commands, never exposed to JS.
#[cfg(mobile)]
use tauri::Manager;
#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_elo_push);
#[cfg(mobile)]
pub struct Push<R: tauri::Runtime>(tauri::plugin::PluginHandle<R>);
#[cfg(mobile)]
impl<R: tauri::Runtime> Push<R> {
    pub fn call(&self, method: &str, args: serde_json::Value) -> Result<serde_json::Value, String> {
        self.0
            .run_mobile_plugin(method, args)
            .map_err(|_| "The notification operation failed".into())
    }
}
pub fn init<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("elo-push")
        .setup(|app, api| {
            #[cfg(mobile)]
            {
                #[cfg(target_os = "ios")]
                let handle = api.register_ios_plugin(init_plugin_elo_push)?;
                #[cfg(target_os = "android")]
                let handle = api.register_android_plugin("now.elo.push", "PushPlugin")?;
                app.manage(Push(handle));
            }
            #[cfg(not(mobile))]
            let _ = (app, api);
            Ok(())
        })
        .build()
}

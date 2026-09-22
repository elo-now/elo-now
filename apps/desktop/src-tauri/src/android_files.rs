//! Read metadata only for a document already selected in the native picker.
//! This adapter exposes no renderer commands or general storage permissions.
use tauri::Manager;

pub struct DocumentInfo(tauri::plugin::PluginHandle<tauri::Wry>);

#[derive(serde::Deserialize)]
struct DisplayName {
    name: Option<String>,
}

pub fn init() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("elo-document-info")
        .setup(|app, api| {
            let handle = api.register_android_plugin("now.elo", "AttachmentInfoPlugin")?;
            app.manage(DocumentInfo(handle));
            Ok(())
        })
        .build()
}

pub fn display_name(app: &tauri::AppHandle, file: &tauri_plugin_fs::FilePath) -> Option<String> {
    let tauri_plugin_fs::FilePath::Url(uri) = file else {
        return None;
    };
    if uri.scheme() != "content" {
        return None;
    }
    app.state::<DocumentInfo>()
        .0
        .run_mobile_plugin::<DisplayName>("displayName", serde_json::json!({"uri": uri.as_str()}))
        .ok()
        .and_then(|metadata| metadata.name)
}

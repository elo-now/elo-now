//! Friendly hardware model only; never a serial number or a personal device name.
use std::sync::OnceLock;

#[cfg(target_os = "ios")]
#[path = "ios_device_model.rs"]
mod ios_device_model;

pub fn current(app: &tauri::AppHandle) -> &'static str {
    static MODEL: OnceLock<String> = OnceLock::new();
    MODEL.get_or_init(|| detect(app).unwrap_or_else(|| fallback().to_owned()))
}

fn fallback() -> &'static str {
    match std::env::consts::OS {
        "macos" => "Mac",
        "ios" => "iPhone or iPad",
        "android" => "Android",
        "windows" => "Windows PC",
        "linux" => "Linux PC",
        _ => "Computer",
    }
}

fn display_name(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 120 && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

#[cfg(all(mobile, feature = "mobile-push"))]
fn detect(app: &tauri::AppHandle) -> Option<String> {
    use tauri::Manager;
    let info = app
        .state::<tauri_plugin_elo_push::Push<tauri::Wry>>()
        .call("deviceModel", serde_json::json!({}))
        .ok()?;
    let model = info["model"].as_str()?;
    #[cfg(target_os = "ios")]
    let model =
        ios_device_model::name(model).unwrap_or(info["fallback"].as_str().unwrap_or("iPhone"));
    display_name(model)
}

#[cfg(target_os = "macos")]
fn detect(_: &tauri::AppHandle) -> Option<String> {
    // Cached once per process. Read only the model family from the result.
    let output = std::process::Command::new("/usr/sbin/system_profiler")
        .args(["-json", "-detailLevel", "mini", "SPHardwareDataType"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let data: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    display_name(data["SPHardwareDataType"][0]["machine_name"].as_str()?)
}

#[cfg(target_os = "windows")]
fn detect(_: &tauri::AppHandle) -> Option<String> {
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile", "-NonInteractive", "-Command",
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; (Get-CimInstance Win32_ComputerSystem).Model",
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .ok()?;
    output.status.success().then_some(())?;
    display_name(std::str::from_utf8(&output.stdout).ok()?)
}

#[cfg(target_os = "linux")]
fn detect(_: &tauri::AppHandle) -> Option<String> {
    display_name(&std::fs::read_to_string("/sys/devices/virtual/dmi/id/product_name").ok()?)
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "windows",
    target_os = "linux",
    all(mobile, feature = "mobile-push")
)))]
fn detect(_: &tauri::AppHandle) -> Option<String> {
    None
}

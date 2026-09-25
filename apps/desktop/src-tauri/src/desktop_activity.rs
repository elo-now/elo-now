//! Desktop unread badges and synchronization while the main window is hidden.
//! Only aggregate counts are retained here; read state belongs to the profile.
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager};

#[derive(Default)]
struct Counts {
    identity: String,
    streams: BTreeMap<(String, String, String), u64>,
}

impl Counts {
    fn update(&mut self, view: &Value) -> Option<u64> {
        let identity = view["identity"].as_str()?;
        if identity != self.identity || view["partial"] != true {
            self.streams.clear();
            self.identity = identity.into();
        }
        // Use native unread summaries instead of only the loaded history page.
        // Their projection already excludes blocked authors and expired locators.
        let streams = view.get("all_streams").unwrap_or(&view["streams"]);
        for stream in streams.as_array().into_iter().flatten() {
            let key = (
                stream["space_context"].as_str().unwrap_or("").into(),
                stream["space"].as_str()?.into(),
                stream["stream"].as_str()?.into(),
            );
            let count = if stream["muted"] == true {
                0
            } else {
                stream["unread_count"].as_u64().unwrap_or(0)
            };
            self.streams.insert(key, count);
        }
        Some(
            self.streams
                .values()
                .fold(0u64, |sum, n| sum.saturating_add(*n)),
        )
    }
}

#[derive(Default)]
pub(crate) struct Activity {
    counts: Mutex<(Counts, Option<u64>)>,
    background: AtomicBool,
}

fn label(count: u64) -> Option<String> {
    match count {
        0 => None,
        1..=99 => Some(count.to_string()),
        _ => Some("99+".into()),
    }
}

pub(crate) fn update(app: &tauri::AppHandle, result: &Value) {
    let view = result.get("view").unwrap_or(result);
    if !view["streams"].is_array() {
        return;
    }
    let activity = app.state::<Activity>();
    let mut state = activity.counts.lock().expect("desktop activity");
    if let Some(count) = state.0.update(view) {
        if state.1 == Some(count) {
            return;
        }
        state.1 = Some(count);
        apply(app, count);
    }
}

pub(crate) fn clear(app: &tauri::AppHandle) {
    *app.state::<Activity>()
        .counts
        .lock()
        .expect("desktop activity") = (Counts::default(), Some(0));
    apply(app, 0);
}

fn apply(app: &tauri::AppHandle, count: u64) {
    if let Some(window) = app.get_webview_window("main") {
        #[cfg(target_os = "macos")]
        let _ = window.set_badge_label(label(count));
        #[cfg(target_os = "linux")]
        let _ = window.set_badge_count(Some(count.min(i64::MAX as u64) as i64));
        #[cfg(target_os = "windows")]
        let _ = window.set_overlay_icon(label(count).map(|text| badge_icon(&text)));
    }
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    if let Some(tray) = app.tray_by_id("elo-background") {
        let text = if let Some(label) = label(count) {
            catalog("desktop.tray.unread").replace("{count}", &label)
        } else {
            catalog("desktop.tray.idle").into()
        };
        let _ = tray.set_tooltip(Some(text));
        // A hidden Windows window has no taskbar button. Keep its tray badge
        // useful as well; Linux panels may not implement launcher counts.
        let icon = label(count)
            .map(|text| badge_icon(&text))
            .or_else(|| app.default_window_icon().cloned());
        let _ = tray.set_icon(icon);
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", test))]
fn badge_icon(text: &str) -> tauri::image::Image<'static> {
    // Tiny pixel glyphs remain legible at taskbar size without a bundled font.
    let glyphs: [[u8; 5]; 11] = [
        [7, 5, 5, 5, 7],
        [2, 6, 2, 2, 7],
        [7, 1, 7, 4, 7],
        [7, 1, 7, 1, 7],
        [5, 5, 7, 1, 1],
        [7, 4, 7, 1, 7],
        [7, 4, 7, 5, 7],
        [7, 1, 1, 1, 1],
        [7, 5, 7, 5, 7],
        [7, 5, 7, 1, 7],
        [0, 2, 7, 2, 0],
    ];
    let mut pixels = vec![0u8; 32 * 32 * 4];
    for y in 0i32..32 {
        for x in 0i32..32 {
            if (x * 2 - 31).pow(2) + (y * 2 - 31).pow(2) <= 31 * 31 {
                let i = ((y * 32 + x) * 4) as usize;
                pixels[i..i + 4].copy_from_slice(&[197, 49, 61, 255]);
            }
        }
    }
    let start = (32 - (text.len() * 8 - 2)) / 2;
    for (n, ch) in text.bytes().enumerate() {
        let glyph = glyphs[if ch == b'+' { 10 } else { (ch - b'0') as usize }];
        for (y, row) in glyph.into_iter().enumerate() {
            for x in 0..3 {
                if row & (1 << (2 - x)) == 0 {
                    continue;
                }
                for dy in 0..2 {
                    for dx in 0..2 {
                        let i = ((11 + y * 2 + dy) * 32 + start + n * 8 + x * 2 + dx) * 4;
                        pixels[i..i + 4].copy_from_slice(&[255; 4]);
                    }
                }
            }
        }
    }
    tauri::image::Image::new_owned(pixels, 32, 32)
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn catalog(key: &str) -> &'static str {
    static TEXT: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        serde_json::from_str(include_str!("../../src/locales/desktop.en.json"))
            .expect("desktop English catalog")
    })
    .get(key)
    .expect("desktop translation key")
}

pub(crate) fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub(crate) fn hidden(app: &tauri::AppHandle) -> bool {
    app.get_webview_window("main").is_some_and(|window| {
        !window.is_visible().unwrap_or(true) || window.is_minimized().unwrap_or(false)
    })
}

pub(crate) fn close(app: &tauri::AppHandle, api: &tauri::CloseRequestApi) {
    if let Some(window) = app.get_webview_window("main") {
        api.prevent_close();
        app.state::<Activity>()
            .background
            .store(true, Ordering::Relaxed);
        #[cfg(target_os = "macos")]
        let _ = window.hide();
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        if app.tray_by_id("elo-background").is_some() {
            let _ = window.hide();
        } else {
            // Panels without a tray must retain a way to reopen the window.
            let _ = window.minimize();
        }
    }
}

pub(crate) fn resume(app: &tauri::AppHandle) {
    if !app
        .state::<Activity>()
        .background
        .swap(false, Ordering::Relaxed)
    {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Hidden WebViews can defer events. Send an authoritative current view
        // on restore even if the next sync has no new transport changes.
        let state = app.state::<crate::State>();
        let state = state.lock().await;
        if let Some(client) = &state.client {
            if let Ok(view) = client.view().await {
                let mut result = json!({"view":view});
                crate::annotate_result(
                    &mut result,
                    Some(client.identity_id()),
                    state.view_revision,
                    state.demo_names.as_ref(),
                );
                update(&app, &result);
                let _ = app.emit("desktop-sync", result);
            }
        }
    });
}

pub(crate) fn setup(app: &tauri::AppHandle) {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    if let Err(error) = setup_tray(app) {
        eprintln!("Desktop tray unavailable: {error}");
    }
    clear(app);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut schedule = Schedule::new(Instant::now());
        let mut identity = String::new();
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if !hidden(&app) || crate::release_policy::required(&app) {
                schedule = Schedule::new(Instant::now());
                continue;
            }
            app.state::<Activity>()
                .background
                .store(true, Ordering::Relaxed);
            let state = app.state::<crate::State>();
            let current = match state.try_lock() {
                Ok(state) => state.client.as_ref().map(|c| c.identity_id().to_string()),
                Err(_) => continue, // Never queue behind foreground work.
            };
            let Some(current) = current else {
                continue;
            };
            if identity != current {
                identity = current;
                schedule = Schedule::new(Instant::now());
            }
            let Some(message) = schedule.due(Instant::now()) else {
                continue;
            };
            let op = if message {
                "sync_live"
            } else {
                "invitation_sync"
            };
            let result = crate::operate(
                app.clone(),
                state,
                json!({
                    "op":op, "foreground":true, "expected_identity":identity,
                    "receive_only":message && schedule.first_receive,
                    "_desktop_background":true,
                }),
            )
            .await;
            schedule.completed(message, result.as_ref().ok(), Instant::now());
            if let Ok(result) = result {
                let _ = app.emit("desktop-sync", result);
            }
        }
    });
}

struct Schedule {
    next: [Instant; 2],
    failures: [u32; 2],
    first_receive: bool,
}
impl Schedule {
    fn new(now: Instant) -> Self {
        Self {
            next: [now; 2],
            failures: [0; 2],
            first_receive: true,
        }
    }
    fn due(&self, now: Instant) -> Option<bool> {
        let message = self.first_receive || self.next[0] <= self.next[1];
        (self.next[usize::from(!message)] <= now).then_some(message)
    }
    fn completed(&mut self, message: bool, result: Option<&Value>, now: Instant) {
        let index = usize::from(!message);
        if message {
            self.first_receive = false;
        }
        let report = result.map(|r| &r[if message { "result" } else { "delivery" }]);
        let failed = report.is_none_or(|r| r["retry"].as_u64().unwrap_or(0) > 0);
        self.failures[index] = if failed {
            (self.failures[index] + 1).min(5)
        } else {
            0
        };
        let remaining = report.is_some_and(|r| r["remaining_spaces"] == true);
        let more = report.is_some_and(|r| r["more"] == true);
        let delay = if remaining || (more && !failed) {
            500
        } else if failed {
            (10_000 * (1u64 << self.failures[index].saturating_sub(1))).min(120_000)
        } else if message {
            20_000
        } else {
            30_000
        };
        self.next[index] = now + Duration::from_millis(delay);
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn setup_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::{
        menu::{Menu, MenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    };
    let open = MenuItem::with_id(
        app,
        "elo-open",
        catalog("desktop.tray.open"),
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(
        app,
        "elo-quit",
        catalog("desktop.tray.quit"),
        true,
        None::<&str>,
    )?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut tray = TrayIconBuilder::with_id("elo-background")
        .menu(&menu)
        .tooltip(catalog("desktop.tray.idle"))
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "elo-open" => show(app),
            "elo-quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stream(space: &str, count: u64, muted: bool) -> Value {
        json!({"space_context":space,"space":space,"stream":"general", "unread_count":count,"muted":muted,"rows":[]})
    }
    #[test]
    fn aggregate_counts_cover_other_spaces_and_paged_rows_without_double_counting() {
        let a = stream("a", 40, false);
        let mut counts = Counts::default();
        assert_eq!(
            counts.update(&json!({"identity":"alice","streams":[a.clone()],
            "all_streams":[a.clone(), a, stream("b",20,false), stream("muted",80,true)]})),
            Some(60)
        );
        // A partial read changes just one chat; other Space counts survive.
        assert_eq!(
            counts.update(&json!({"identity":"alice","partial":true,
            "all_streams":[stream("a",0,false)]})),
            Some(20)
        );
        assert_eq!(
            counts.update(&json!({"identity":"alice","streams":[],"all_streams":[]})),
            Some(0)
        );
    }
    #[test]
    fn switching_profiles_never_keeps_the_previous_count() {
        let mut counts = Counts::default();
        counts.update(&json!({"identity":"alice","streams":[stream("a",10,false)]}));
        assert_eq!(
            counts
                .update(&json!({"identity":"bob","partial":true,"streams":[stream("b",2,false)]})),
            Some(2)
        );
        assert_eq!(label(0), None);
        assert_eq!(label(99), Some("99".into()));
        assert_eq!(label(100), Some("99+".into()));
        for value in ["1", "99", "99+"] {
            let icon = badge_icon(value);
            assert_eq!(icon.rgba().len(), 32 * 32 * 4);
            assert!(icon.rgba().chunks_exact(4).any(|p| p == [255; 4]));
        }
    }
    #[test]
    fn background_rounds_drain_all_spaces_and_back_off_without_starving_discovery() {
        let now = Instant::now();
        let mut schedule = Schedule::new(now);
        assert_eq!(schedule.due(now), Some(true));
        schedule.completed(
            true,
            Some(&json!({"result":{"more":true,"remaining_spaces":true}})),
            now,
        );
        assert_eq!(schedule.due(now), Some(false));
        schedule.completed(false, Some(&json!({"delivery":{}})), now);
        assert_eq!(schedule.due(now), None);
        assert_eq!(schedule.due(now + Duration::from_millis(500)), Some(true));
        schedule.completed(true, None, now);
        assert_eq!(schedule.due(now + Duration::from_secs(9)), None);
        assert_eq!(schedule.due(now + Duration::from_secs(10)), Some(true));
        schedule.completed(true, None, now + Duration::from_secs(10));
        assert_eq!(schedule.due(now + Duration::from_secs(29)), None);
    }
}

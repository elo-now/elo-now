//! Opt-in local diagnostics containing only fixed stages and monotonic durations.
use std::{fmt::Write as _, io::Write as _, sync::Mutex, time::Instant};
use tauri::Manager;

const MAX_LOG_BYTES: u64 = 64 * 1024;
static LOG_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    Mutex,
    BiometricEnvelope,
    ProfileOpen,
    Configure,
    SpacesOpen,
    View,
    Activate,
    Complete,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Mutex => "mutex",
            Self::BiometricEnvelope => "biometric_envelope",
            Self::ProfileOpen => "profile_open",
            Self::Configure => "configure",
            Self::SpacesOpen => "spaces_open",
            Self::View => "view",
            Self::Activate => "activate",
            Self::Complete => "complete",
        }
    }
}

pub(crate) struct UnlockTiming(Option<Active>);

struct Active {
    app: tauri::AppHandle,
    started: Instant,
    previous: Instant,
    buffer: String,
    complete: bool,
}

impl UnlockTiming {
    pub(crate) fn new(app: &tauri::AppHandle) -> Self {
        if option_env!("TAURI_ELO_UNLOCK_TIMING") != Some("1") {
            return Self(None);
        }
        let started = Instant::now();
        Self(Some(Active {
            app: app.clone(),
            started,
            previous: started,
            buffer: String::with_capacity(1024),
            complete: false,
        }))
    }

    pub(crate) fn mark(&mut self, stage: Stage) {
        if let Some(active) = &mut self.0 {
            active.record(stage.label());
            active.complete = matches!(stage, Stage::Complete);
        }
    }
}

impl Active {
    fn record(&mut self, label: &'static str) {
        let now = Instant::now();
        let _ = writeln!(
            self.buffer,
            "unlock_timing {label} elapsed_ms={} total_ms={}",
            now.duration_since(self.previous).as_millis(),
            now.duration_since(self.started).as_millis(),
        );
        self.previous = now;
    }

    fn flush(&self) {
        let Ok(_guard) = LOG_LOCK.lock() else {
            return;
        };
        let Ok(directory) = self.app.path().app_cache_dir() else {
            return;
        };
        if self.buffer.len() as u64 > MAX_LOG_BYTES || std::fs::create_dir_all(&directory).is_err()
        {
            return;
        }
        let path = directory.join("unlock-timing.log");
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => return,
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return,
            _ => {}
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let Ok(mut file) = options.open(path) else {
            return;
        };
        let Ok(metadata) = file.metadata() else {
            return;
        };
        if metadata.len().saturating_add(self.buffer.len() as u64) > MAX_LOG_BYTES
            && file.set_len(0).is_err()
        {
            return;
        }
        let _ = file.write_all(self.buffer.as_bytes());
    }
}

impl Drop for UnlockTiming {
    fn drop(&mut self) {
        if let Some(active) = &mut self.0 {
            if !active.complete {
                active.record("incomplete");
            }
            // One bounded write after the measured work; diagnostics never alter
            // the command result, including early errors or cancellation.
            active.flush();
        }
    }
}

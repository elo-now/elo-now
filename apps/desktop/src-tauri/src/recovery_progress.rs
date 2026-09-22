//! Progress carries no recovery material, profile identifiers, paths or messages.
use elo_core::app::profile_backup::{RestoreProgress, RestoreStage};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tauri::{Emitter, Manager};
#[derive(Default)]
pub(crate) struct RecoveryJobs(Mutex<Option<(String, Arc<AtomicBool>)>>);
pub(crate) struct Job {
    app: tauri::AppHandle,
    id: String,
    pub progress: RestoreProgress,
}
impl Job {
    pub fn start(app: &tauri::AppHandle, id: &str) -> Result<Self, String> {
        if id.len() > 80
            || id.is_empty()
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid recovery request".into());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let state = app.state::<RecoveryJobs>();
        let mut active = state.0.lock().map_err(|_| "Recovery is unavailable")?;
        if active.is_some() {
            return Err("Recovery is already running".into());
        }
        *active = Some((id.into(), cancel.clone()));
        let emitter = app.clone();
        let request = id.to_owned();
        let progress = RestoreProgress::new(move |stage: RestoreStage, done, total| {
            let _ = emitter.emit(
                "recovery-progress",
                serde_json::json!({"request":request,"stage":stage,"done":done,"total":total}),
            );
            !cancel.load(Ordering::Relaxed)
        });
        Ok(Self {
            app: app.clone(),
            id: id.into(),
            progress,
        })
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        let state = self.app.state::<RecoveryJobs>();
        if let Ok(mut active) = state.0.lock()
            && active.as_ref().is_some_and(|(id, _)| id == &self.id)
        {
            *active = None;
        }
    }
}
pub(crate) fn pause(app: &tauri::AppHandle, id: &str) -> bool {
    let state = app.state::<RecoveryJobs>();
    if let Ok(active) = state.0.lock()
        && let Some((request, cancel)) = active.as_ref()
        && request == id
    {
        cancel.store(true, Ordering::Relaxed);
        return true;
    }
    false
}

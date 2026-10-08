//! Narrow, memory-safe caller interface to the synchronous Swift C bridge.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn elo_diagnostics_command(bytes: *const std::ffi::c_char);
}

pub fn command(json: &str) {
    if json.len() > 2048 {
        return;
    }
    #[cfg(target_os = "macos")]
    if let Ok(bytes) = std::ffi::CString::new(json) {
        // Swift copies the terminated string into owned Data before returning.
        // The pointer remains live for the entire call and cannot escape.
        unsafe {
            elo_diagnostics_command(bytes.as_ptr());
        }
    }
}

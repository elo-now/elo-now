fn main() {
    #[cfg(target_os = "macos")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        swift_rs::SwiftLinker::new("11.0")
            .with_package("EloDiagnostics", "../elo-diagnostics-apple")
            .link();
        println!(
            "cargo:resource_root={}/swift-rs/EloDiagnostics",
            std::env::var("OUT_DIR").unwrap()
        );
        // Swift uses this crate's debug-info setting. The app may keep Rust
        // line tables while this dependency still builds Swift in Release.
        let configuration = if std::env::var("DEBUG").as_deref() == Ok("true") {
            "Debug"
        } else {
            "Release"
        };
        println!("cargo:resource_configuration={configuration}");
    }
}

fn main() {
    tauri_plugin::Builder::new(&[])
        .android_path("android")
        .ios_path("ios")
        .build();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("ios") {
        // Pass the exact SwiftPM build tree to the application. Searching the
        // shared target directory could pick a stale SDK from another build.
        let root = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap())
            .join("swift-rs/tauri-plugin-elo-push");
        globalize_xcode_27_bridge_symbols(&root);
        link_webrtc(&root);
        println!("cargo:ios_resource_root={}", root.display());
    }
}

fn link_webrtc(root: &std::path::Path) {
    let simulator = std::env::var("TARGET")
        .is_ok_and(|target| target.ends_with("-sim") || target.starts_with("x86_64-"));
    let platform = if simulator {
        "iphonesimulator"
    } else {
        "iphoneos"
    };
    let configuration = if std::env::var("DEBUG").as_deref() == Ok("true") {
        "Debug"
    } else {
        "Release"
    };
    let products = format!("{configuration}-{platform}");
    let directory = [
        root.join("out/Products").join(&products),
        root.join("Products").join(&products),
    ]
    .into_iter()
    .find(|path| path.join("WebRTC.framework/WebRTC").is_file())
    .or_else(|| {
        let slice = if simulator {
            "ios-x86_64_arm64-simulator"
        } else {
            "ios-arm64"
        };
        let path = root
            .join("artifacts/webrtc/WebRTC/WebRTC.xcframework")
            .join(slice);
        path.join("WebRTC.framework/WebRTC")
            .is_file()
            .then_some(path)
    })
    .expect("the pinned WebRTC package did not produce the requested iOS framework");
    // Rust also links a cdylib during the Tauri build; Xcode embeds/signs the
    // same pinned SwiftPM framework in the final app bundle.
    println!("cargo:rustc-link-search=framework={}", directory.display());
    println!("cargo:rustc-link-lib=framework=WebRTC");
}

/// Xcode 27 internalizes the Swift package's `@_cdecl` bridge symbols when the
/// package has binary dependencies. Promote the five symbols used by this
/// plugin after SwiftPM has created the static archive. Older Xcode versions do
/// not need this and keep the symbols global already.
fn globalize_xcode_27_bridge_symbols(root: &std::path::Path) {
    let archive = root
        .join("out/Products/Release-iphoneos")
        .join("libtauri-plugin-elo-push.a");
    if !archive.exists() {
        return;
    }

    let output = std::process::Command::new("nm")
        .arg(&archive)
        .output()
        .expect("failed to inspect the iOS push plugin archive");
    let symbols = String::from_utf8_lossy(&output.stdout);
    let required = [
        "_init_plugin_elo_push",
        "_data_from_bytes",
        "_release_object",
        "_retain_object",
        "_string_from_bytes",
    ];
    let local = required
        .into_iter()
        .filter(|symbol| {
            symbols.lines().any(|line| {
                let mut fields = line.split_whitespace();
                matches!(
                    (fields.next(), fields.next(), fields.next()),
                    (Some(_), Some("t"), Some(name)) if name == *symbol
                )
            })
        })
        .collect::<Vec<_>>();
    if local.is_empty() {
        return;
    }

    let objcopy = rustup_llvm_objcopy()
        .expect("Xcode 27 requires rustup's llvm-tools component to link the iOS push plugin");
    let mut command = std::process::Command::new(objcopy);
    for symbol in local {
        command.arg(format!("--globalize-symbol={symbol}"));
    }
    let status = command
        .arg(&archive)
        .status()
        .expect("failed to run llvm-objcopy for the iOS push plugin");
    assert!(
        status.success(),
        "failed to export the iOS push bridge symbols"
    );
}

fn rustup_llvm_objcopy() -> Option<std::path::PathBuf> {
    let output = std::process::Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let host = format!("{}-apple-darwin", std::env::consts::ARCH);
    let path = std::path::PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin/llvm-objcopy");
    path.exists().then_some(path)
}

//! Preserve privacy manifests produced by the exact linked Swift packages.
use std::{env, fs, io, path::Path};

pub fn stage() -> io::Result<()> {
    println!("cargo:rerun-if-env-changed=DEP_TAURI_PLUGIN_ELO_PUSH_IOS_RESOURCE_ROOT");
    println!("cargo:rerun-if-env-changed=TAURI_IOS_PROJECT_PATH");
    println!("cargo:rerun-if-env-changed=TARGET_BUILD_DIR");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("ios") {
        return Ok(());
    }
    let Some(project) = env::var_os("TAURI_IOS_PROJECT_PATH") else {
        return Ok(());
    };
    let destination = Path::new(&project).join("PrivacyResources");
    // Another target/feature build can replace this shared Xcode input. Watching
    // it also invalidates a cached Cargo build when its resources were replaced.
    println!("cargo:rerun-if-changed={}", destination.display());
    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    fs::create_dir_all(&destination)?;
    if env::var_os("CARGO_FEATURE_MOBILE_PUSH").is_none() {
        return Ok(());
    }
    let root = env::var_os("DEP_TAURI_PLUGIN_ELO_PUSH_IOS_RESOURCE_ROOT")
        .ok_or_else(|| io::Error::other("Missing Firebase Swift resource build path"))?;
    let mut product_directories = Vec::new();
    // SwiftPM before Xcode 27 places resource bundles under
    // <triple>/<configuration>. Do not traverse checkouts, caches or symlinks
    // into other package builds.
    for triple in fs::read_dir(&root)? {
        let triple = triple?;
        if !triple.file_type()?.is_dir() {
            continue;
        }
        for configuration in ["debug", "release"] {
            let products = triple.path().join(configuration);
            if products.is_dir() {
                product_directories.push(products);
            }
        }
    }
    // Xcode 27 uses the native Swift build layout instead:
    // out/Products/{Debug,Release}-iphoneos. Restrict discovery to device
    // products in this exact plugin build tree.
    let xcode_products = Path::new(&root).join("out/Products");
    if xcode_products.is_dir() {
        for products in fs::read_dir(xcode_products)? {
            let products = products?;
            if products.file_type()?.is_dir()
                && products
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with("-iphoneos"))
            {
                product_directories.push(products.path());
            }
        }
    }
    let mut count = 0;
    for products in product_directories {
        for entry in fs::read_dir(products)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir()
                || entry.path().extension().is_none_or(|ext| ext != "bundle")
            {
                continue;
            }
            let manifest = entry.path().join("PrivacyInfo.xcprivacy");
            if !manifest.is_file() {
                continue;
            }
            let bundle = destination.join(entry.file_name());
            fs::create_dir_all(&bundle)?;
            let output = bundle.join("PrivacyInfo.xcprivacy");
            let bytes = fs::read(&manifest)?;
            if output.exists() && fs::read(&output)? != bytes {
                return Err(io::Error::other("Conflicting SDK privacy manifests"));
            }
            fs::write(output, bytes)?;
            println!("cargo:rerun-if-changed={}", manifest.display());
            count += 1;
        }
    }
    for name in [
        "Firebase_FirebaseCore",
        "Firebase_FirebaseMessaging",
        "Firebase_FirebaseInstallations",
        "GoogleDataTransport_GoogleDataTransport",
        "GoogleUtilities_GoogleUtilities-UserDefaults",
        "Promises_FBLPromises",
        "nanopb_nanopb",
    ] {
        if !destination
            .join(format!("{name}.bundle/PrivacyInfo.xcprivacy"))
            .is_file()
        {
            return Err(io::Error::other(format!(
                "Missing linked SDK privacy manifest: {name}"
            )));
        }
    }
    println!("cargo:warning=Staged {count} linked SDK privacy manifests");
    Ok(())
}

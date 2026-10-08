use std::{env, fs, io, path::Path};

/// Stage only bundles from the current linked Swift build, never a cache glob.
pub fn stage() -> io::Result<()> {
    println!("cargo:rerun-if-env-changed=DEP_ELO_DIAGNOSTICS_MACOS_RESOURCE_ROOT");
    println!("cargo:rerun-if-env-changed=DEP_ELO_DIAGNOSTICS_MACOS_RESOURCE_CONFIGURATION");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || env::var_os("CARGO_FEATURE_BETA_DIAGNOSTICS").is_none()
    {
        return Ok(());
    }
    let root = env::var_os("DEP_ELO_DIAGNOSTICS_MACOS_RESOURCE_ROOT")
        .ok_or_else(|| io::Error::other("Missing diagnostics SDK resource path"))?;
    let configuration = env::var("DEP_ELO_DIAGNOSTICS_MACOS_RESOURCE_CONFIGURATION")
        .map_err(|_| io::Error::other("Missing diagnostics SDK resource configuration"))?;
    if !matches!(configuration.as_str(), "Debug" | "Release") {
        return Err(io::Error::other(
            "Invalid diagnostics SDK resource configuration",
        ));
    }
    let products = Path::new(&root).join("out/Products").join(configuration);
    let destination = Path::new("macos/DiagnosticsResources");
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(products)? {
        let entry = entry?;
        if entry.path().extension().is_none_or(|s| s != "bundle") {
            continue;
        }
        let source = entry
            .path()
            .join("Contents/Resources/PrivacyInfo.xcprivacy");
        if !source.is_file() {
            continue;
        }
        let target = destination
            .join(entry.file_name())
            .join("Contents/Resources");
        fs::create_dir_all(&target)?;
        fs::copy(source, target.join("PrivacyInfo.xcprivacy"))?;
        let info = entry.path().join("Contents/Info.plist");
        if info.is_file() {
            fs::copy(info, target.parent().unwrap().join("Info.plist"))?;
        }
    }
    if !destination
        .join("Firebase_FirebaseCrashlytics.bundle/Contents/Resources/PrivacyInfo.xcprivacy")
        .exists()
    {
        return Err(io::Error::other("Missing Crashlytics privacy manifest"));
    }
    Ok(())
}

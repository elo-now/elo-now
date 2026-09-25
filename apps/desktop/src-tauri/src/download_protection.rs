//! Preserve the operating system's untrusted-download warning on saved files.
use std::path::Path;

pub(crate) fn mark(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_secs();
        rustix::fs::setxattr(
            path,
            "com.apple.quarantine",
            format!("0081;{stamp:x};elo.now;").as_bytes(),
            rustix::fs::XattrFlags::empty(),
        )?;
    }
    #[cfg(target_os = "windows")]
    {
        use std::io::Write;
        let mut zone = path.as_os_str().to_os_string();
        zone.push(":Zone.Identifier");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(zone)?;
        file.write_all(b"[ZoneTransfer]\r\nZoneId=3\r\n")?;
        file.sync_all()?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let _ = path;
    Ok(())
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    #[test]
    fn saved_attachment_keeps_its_bytes_and_gets_an_internet_zone() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attachment with spaces.txt");
        std::fs::write(&path, b"untrusted attachment").unwrap();
        super::mark(&path).unwrap();
        super::mark(&path).unwrap();
        let mut zone = path.as_os_str().to_os_string();
        zone.push(":Zone.Identifier");
        assert_eq!(
            std::fs::read(zone).unwrap(),
            b"[ZoneTransfer]\r\nZoneId=3\r\n"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"untrusted attachment");
        assert!(super::mark(&directory.path().join("missing").join("attachment.txt")).is_err());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #[test]
    fn a_saved_attachment_gets_quarantine_without_disclosing_its_sender() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attachment.txt");
        std::fs::write(&path, b"untrusted attachment").unwrap();
        super::mark(&path).unwrap();
        let mut buffer = [0u8; 256];
        let length = rustix::fs::getxattr(&path, "com.apple.quarantine", &mut buffer).unwrap();
        let value = &buffer[..length];
        assert!(value.starts_with(b"0081;"));
        assert!(value.ends_with(b";elo.now;"));
        assert_eq!(std::fs::read(path).unwrap(), b"untrusted attachment");
    }
}

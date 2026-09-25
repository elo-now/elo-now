//! A portable, bounded age/scrypt cost for user-created exports and vaults.
use age::secrecy::{ExposeSecret, SecretString};

/// Export passwords are assessed locally. Checking a bounded prefix prevents
/// quadratic pattern matching on arbitrarily large renderer input. Imports are
/// deliberately unaffected: this policy must not lock out an existing backup.
pub(crate) fn strong_export_secret(secret: &SecretString) -> bool {
    let text = secret.expose_secret();
    if text.chars().count() < 12 || text.len() > 1024 {
        return false;
    }
    let end = text
        .char_indices()
        .nth(72)
        .map_or(text.len(), |(offset, _)| offset);
    zxcvbn::zxcvbn(&text[..end], &["elo", "elo.now"]).score() >= zxcvbn::Score::Three
}

/// scrypt N=2^17, r=8, p=1 uses approximately 128 MiB on every device.
/// Calibration on a fast desktop must not produce a gigabyte-sized phone import.
pub(crate) const WORK_FACTOR: u8 = 17;
/// Untrusted imports may use up to 256 MiB; larger costs are rejected before KDF.
pub(crate) const IMPORT_MAX_WORK_FACTOR: u8 = 18;

pub(crate) fn recipient(secret: SecretString) -> age::scrypt::Recipient {
    let mut recipient = age::scrypt::Recipient::new(secret);
    recipient.set_work_factor(WORK_FACTOR);
    recipient
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn export_passwords_reject_predictable_patterns_without_composition_rules() {
        for weak in [
            "Password123456!",
            "abcdefghijklmnop",
            "qwertyuiop123456",
            "1111111111111111",
        ] {
            assert!(!strong_export_secret(&weak.into()));
        }
        assert!(!strong_export_secret(&"a".repeat(1024).into()));
        assert!(strong_export_secret(
            &"meadow tungsten orbit marzipan".into()
        ));
        assert!(strong_export_secret(&"7Nzq4pT9hK3sV6jF2yW8bR5m".into()));
    }

    #[test]
    fn exported_cost_is_portable_and_oversized_import_is_rejected() {
        let secret: SecretString = "Public test passphrase only".into();
        let recipient = recipient(secret.clone());
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .unwrap();
        let mut bytes = Vec::new();
        let mut writer = encryptor.wrap_output(&mut bytes).unwrap();
        writer.write_all(b"portable test").unwrap();
        writer.finish().unwrap();
        let header = String::from_utf8_lossy(&bytes[..bytes.len().min(100)]);
        assert!(
            header
                .lines()
                .any(|line| line.starts_with("-> scrypt ") && line.ends_with(" 17"))
        );
        let mut identity = age::scrypt::Identity::new(secret);
        identity.set_max_work_factor(IMPORT_MAX_WORK_FACTOR);
        let mut plain = Vec::new();
        age::Decryptor::new(bytes.as_slice())
            .unwrap()
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap()
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(plain, b"portable test");
        // Invalid authentication is irrelevant: cost must be rejected first.
        let expensive = bytes.windows(3).position(|s| s == b"17\n").unwrap();
        bytes[expensive..expensive + 2].copy_from_slice(b"21");
        assert!(matches!(
            age::Decryptor::new(bytes.as_slice())
                .unwrap()
                .decrypt(std::iter::once(&identity as &dyn age::Identity)),
            Err(age::DecryptError::ExcessiveWork { .. })
        ));
    }
}

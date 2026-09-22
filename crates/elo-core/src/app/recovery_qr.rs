//! Private recovery QR is an age-encrypted card, never a public contact packet.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub const PREFIX: &str = "elo recovery v1\n";

pub fn encode(card: &RecoveryCard, password: SecretString) -> Result<String> {
    if password.expose_secret().chars().count() < 12 || password.expose_secret().len() > 1024 {
        return Err("Use at least 12 characters for the recovery QR password".into());
    }
    card.recover_root(card.identity_id)?;
    let plain = Zeroizing::new(serde_json::to_vec(card)?);
    let encrypted = profile_backup::encrypt(&plain, password)?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(encrypted)))
}

pub fn decode(code: &str, password: SecretString) -> Result<ProfileDraft> {
    if code.len() > 4096 || !(12..=1024).contains(&password.expose_secret().len()) {
        return Err("Invalid recovery QR or password".into());
    }
    // Camera text actions and clipboard providers can replace the line break
    // with spaces or wrap the data across lines. Whitespace is not ciphertext.
    let encoded = if let Some(legacy) = code.trim().strip_prefix("elo-recovery:1:") {
        legacy.split_whitespace().collect::<String>()
    } else {
        let mut parts = code.split_whitespace();
        if parts.next() != Some("elo")
            || parts.next() != Some("recovery")
            || parts.next() != Some("v1")
        {
            return Err("Scan a recovery QR, not a contact or device code".into());
        }
        parts.collect::<String>()
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "Invalid recovery QR")?;
    let plain = profile_backup::decrypt(&bytes, password)
        .map_err(|_| "The recovery QR password is incorrect or the code is damaged")?;
    if plain.len() > 2048 {
        return Err("Invalid recovery QR".into());
    }
    let card: RecoveryCard = serde_json::from_slice(&plain).map_err(|_| "Invalid recovery QR")?;
    if card.format != "elo.now identity-recovery-v1" {
        return Err("Invalid recovery QR".into());
    }
    ProfileDraft::recover(&card.phrase, &card.identity_id.to_string())
}

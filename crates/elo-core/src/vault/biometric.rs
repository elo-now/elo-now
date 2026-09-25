//! OS biometric storage holds a random wrapping key, never the profile password.
//! The encrypted password is device-local and excluded from portable backups.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrapped {
    v: u8,
    identity: IdentityId,
    profile: String,
    password: String,
}
impl Drop for Wrapped {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub fn seal(
    password: SecretString,
    identity: IdentityId,
    profile: &str,
) -> Result<(Vec<u8>, SecretString)> {
    validate_passphrase(&password)?;
    if profile.is_empty() || profile.len() > 128 {
        return Err(VaultError::Invalid);
    }
    let key = age::x25519::Identity::generate();
    let plain = Zeroizing::new(
        serde_json::to_vec(&Wrapped {
            v: 1,
            identity,
            profile: profile.into(),
            password: password.expose_secret().into(),
        })
        .map_err(|_| VaultError::Invalid)?,
    );
    let bytes = crate::crypto::seal_bytes(&plain, &[key.to_public()], 4096)
        .map_err(|_| VaultError::Invalid)?;
    Ok((bytes, key.to_string()))
}

pub fn open(
    bytes: &[u8],
    key: SecretString,
    identity: IdentityId,
    profile: &str,
) -> Result<SecretString> {
    if bytes.len() > 8192 || key.expose_secret().len() > 256 {
        return Err(VaultError::Invalid);
    }
    let key: age::x25519::Identity = key
        .expose_secret()
        .parse()
        .map_err(|_| VaultError::Invalid)?;
    let plain = Zeroizing::new(
        crate::crypto::open_bytes(bytes, &key, 4096).map_err(|_| VaultError::Invalid)?,
    );
    let mut value: Wrapped = serde_json::from_slice(&plain).map_err(|_| VaultError::Invalid)?;
    if value.v != 1 || value.identity != identity || value.profile != profile {
        return Err(VaultError::Invalid);
    }
    Ok(std::mem::take(&mut value.password).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrapping_key_is_independent_and_bound_to_profile_and_identity() {
        let identity: IdentityId = "11".repeat(32).parse().unwrap();
        let other: IdentityId = "22".repeat(32).parse().unwrap();
        let password: SecretString = "Public test passphrase".into();
        let (bytes, key) = seal(password.clone(), identity, "profile").unwrap();
        let (_, other_key) = seal(password.clone(), identity, "profile").unwrap();
        assert_ne!(key.expose_secret(), password.expose_secret());
        assert!(
            !bytes
                .windows(password.expose_secret().len())
                .any(|part| part == password.expose_secret().as_bytes())
        );
        assert_eq!(
            open(&bytes, key.clone(), identity, "profile")
                .unwrap()
                .expose_secret(),
            password.expose_secret()
        );
        assert!(open(&bytes, key.clone(), identity, "profile-other").is_err());
        assert!(open(&bytes, key.clone(), other, "profile").is_err());
        assert!(open(&bytes, other_key, identity, "profile").is_err());
        let mut damaged = bytes;
        *damaged.last_mut().unwrap() ^= 1;
        assert!(open(&damaged, key, identity, "profile").is_err());
    }
}

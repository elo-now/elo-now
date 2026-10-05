//! Build-time service addresses. A private build supplies one API origin.
use url::Url;

pub struct Endpoints {
    pub host: String,
    pub wake: String,
    pub storage: Option<String>,
    pub witness: Option<(String, String, u64)>,
}

pub fn from_environment(
    mut read: impl FnMut(&str) -> Option<String>,
    debug: bool,
) -> Result<Endpoints, &'static str> {
    // Tauri forwards TAURI_* to Xcode/Gradle. Keep the plain Cargo aliases,
    // but fail rather than choose silently if both name different deployments.
    let mut setting = |name: &str| {
        let plain = read(name);
        let forwarded = read(&format!("TAURI_{name}"));
        if plain.is_some() && forwarded.is_some() && plain != forwarded {
            return Err("Conflicting API endpoint environment variables");
        }
        Ok(forwarded.or(plain))
    };
    let api = setting("ELO_API_URL")?;
    let host = setting("ELO_SPACE_HOST_URL")?;
    let storage = setting("ELO_STORAGE_URL")?;
    let witness_url = setting("ELO_WITNESS_URL")?;
    let witness_key = setting("ELO_WITNESS_PUBLIC_KEY")?;
    let witness_generation = setting("ELO_WITNESS_KEY_GENERATION")?;
    let wake = read("TAURI_ELO_WAKE_URL");
    let mut endpoints = resolve(api.as_deref(), host.as_deref(), wake.as_deref(), debug)?;
    // Storage credentials have a separate trust boundary. Never derive this
    // endpoint from the API host or silently enable a shared provider.
    endpoints.storage = storage
        .map(|value| address(&value, "/storage/v1", debug).map(String::from))
        .transpose()?;
    endpoints.witness = match (witness_url, witness_key, witness_generation) {
        (None, None, None) => None,
        (Some(url), Some(key), Some(generation)) => {
            // An independent production anchor is never inferred from hosting.
            let url = address(&url, "/witness/v1", false)?;
            let generation = generation
                .parse::<u64>()
                .map_err(|_| "Invalid witness key generation")?;
            if key.len() != 64
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || generation == 0
                || generation > (1_u64 << 53) - 1
            {
                return Err("Invalid witness signing-key pin");
            }
            Some((url.into(), key, generation))
        }
        _ => return Err("Witness URL, public key and key generation must be configured together"),
    };
    Ok(endpoints)
}

fn address(value: &str, path: &str, debug: bool) -> Result<Url, &'static str> {
    let url = Url::parse(value).map_err(|_| "Invalid service URL")?;
    let local = url
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    if value.trim() != value
        || value.chars().any(char::is_control)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != path
        || !(url.scheme() == "https" || (debug && local && url.scheme() == "http"))
    {
        return Err(
            "Service URLs require HTTPS and a canonical path without credentials, query or fragment",
        );
    }
    Ok(url)
}

pub fn resolve(
    api: Option<&str>,
    host: Option<&str>,
    wake: Option<&str>,
    debug: bool,
) -> Result<Endpoints, &'static str> {
    // Explicit endpoint overrides exist for local QA. Do not silently combine
    // a private API origin with an override pointing to a different deployment.
    if api.is_some() && (host.is_some() || wake.is_some()) {
        return Err("Use ELO_API_URL alone, or the explicit QA endpoint overrides");
    }
    let api = address(api.unwrap_or("https://api.elo.now"), "/", debug)?;
    let host = match host {
        Some(value) => address(value, "/spaces/v1/create", debug)?,
        None => api
            .join("spaces/v1/create")
            .map_err(|_| "Invalid hosting URL")?,
    };
    let wake = match wake {
        Some(value) => address(value, "/", debug)?,
        None => api,
    };
    Ok(Endpoints {
        host: host.into(),
        wake: wake.into(),
        storage: None,
        witness: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_configuration_requires_all_three_independent_native_pins() {
        assert!(from_environment(|_| None, false).unwrap().witness.is_none());
        assert!(
            from_environment(
                |name| (name == "ELO_WITNESS_URL")
                    .then(|| "https://witness.example.test/witness/v1".into()),
                false
            )
            .is_err()
        );
        let configuration = |name: &str| match name {
            "TAURI_ELO_WITNESS_URL" => Some("https://witness.example.test/witness/v1".into()),
            "TAURI_ELO_WITNESS_PUBLIC_KEY" => Some("12".repeat(32)),
            "TAURI_ELO_WITNESS_KEY_GENERATION" => Some("2".into()),
            _ => None,
        };
        let pin = from_environment(configuration, false)
            .unwrap()
            .witness
            .unwrap();
        assert_eq!(pin.2, 2);
        assert_eq!(pin.0, "https://witness.example.test/witness/v1");
        assert!(
            from_environment(
                |name| if name == "TAURI_ELO_WITNESS_URL" {
                    Some("http://127.0.0.1/witness/v1".into())
                } else {
                    configuration(name)
                },
                true
            )
            .is_err()
        );
        assert!(
            from_environment(
                |name| if name == "TAURI_ELO_WITNESS_KEY_GENERATION" {
                    Some("0".into())
                } else {
                    configuration(name)
                },
                false
            )
            .is_err()
        );
    }

    #[test]
    fn mobile_forwarded_configuration_and_conflicting_aliases() {
        let private = from_environment(
            |name| (name == "TAURI_ELO_API_URL").then(|| "https://chat.example.test".into()),
            false,
        )
        .unwrap();
        assert_eq!(private.host, "https://chat.example.test/spaces/v1/create");
        assert_eq!(private.wake, "https://chat.example.test/");
        assert!(
            from_environment(
                |name| match name {
                    "ELO_API_URL" => Some("https://one.example.test".into()),
                    "TAURI_ELO_API_URL" => Some("https://two.example.test".into()),
                    _ => None,
                },
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn independent_storage_endpoint_is_explicit_and_never_inferred_from_api() {
        let endpoints = from_environment(
            |name| match name {
                "TAURI_ELO_API_URL" => Some("https://api.example.test".into()),
                "TAURI_ELO_STORAGE_URL" => Some("https://storage.example.test/storage/v1".into()),
                _ => None,
            },
            false,
        )
        .unwrap();
        assert_eq!(
            endpoints.storage.as_deref(),
            Some("https://storage.example.test/storage/v1")
        );
        assert_eq!(endpoints.host, "https://api.example.test/spaces/v1/create");
        assert!(from_environment(|_| None, false).unwrap().storage.is_none());
        assert!(
            from_environment(
                |name| (name == "TAURI_ELO_STORAGE_URL").then(|| "https://api.example.test".into()),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn official_and_private_builds_resolve_one_stable_origin() {
        let official = resolve(None, None, None, false).unwrap();
        assert_eq!(official.host, "https://api.elo.now/spaces/v1/create");
        assert_eq!(official.wake, "https://api.elo.now/");
        let private = resolve(Some("https://chat.example.test:8443"), None, None, false).unwrap();
        assert_eq!(
            private.host,
            "https://chat.example.test:8443/spaces/v1/create"
        );
        assert_eq!(private.wake, "https://chat.example.test:8443/");
        assert!(
            resolve(
                Some("https://chat.example.test"),
                None,
                Some("https://other.example.test"),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_insecure_or_credential_bearing_deployment_configuration() {
        for value in [
            "http://example.test",
            "http://127.0.0.1:1435",
            "https://user:secret@example.test",
            "https://example.test/path",
            "https://example.test/?token=x",
            "https://example.test/#x",
            " https://example.test",
            "",
        ] {
            assert!(resolve(Some(value), None, None, false).is_err(), "{value}");
        }
        assert!(resolve(Some("http://127.0.0.1:1435"), None, None, true).is_ok());
        assert!(resolve(Some("http://[::1]:1435"), None, None, true).is_ok());
        assert!(resolve(Some("http://192.0.2.1:1435"), None, None, true).is_err());
        assert!(resolve(None, Some("https://example.test/wrong"), None, true).is_err());
    }
}

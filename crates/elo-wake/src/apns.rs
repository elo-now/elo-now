//! Direct APNs VoIP delivery. Ordinary FCM message notifications are unchanged.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub key_file: PathBuf,
    pub key_id: String,
    pub team_id: String,
    /// Older Apple accounts can have an App ID prefix different from Team ID.
    #[serde(default)]
    pub app_id_prefix: Option<String>,
    pub bundle_id: String,
    pub sandbox: bool,
}

pub struct Apns {
    client: reqwest::Client,
    key: EcdsaKeyPair,
    config: Config,
    authorization: Mutex<Option<(Zeroizing<String>, u64)>>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid private APNs configuration")]
    Configuration,
    #[error("APNs authentication failed")]
    Authentication,
    #[error("APNs provider token expired")]
    TokenExpired,
    #[error("APNs rate limit reached")]
    Throttled,
    #[error("APNs call delivery failed")]
    Delivery,
    #[error("The VoIP device registration is no longer valid")]
    Unregistered,
}

fn valid_id(value: &str) -> bool {
    value.len() == 10
        && value
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

#[derive(Deserialize)]
struct Rejection {
    reason: String,
}

impl Apns {
    pub(crate) fn app_id(&self) -> String {
        format!(
            "{}.{}",
            self.config
                .app_id_prefix
                .as_deref()
                .unwrap_or(&self.config.team_id),
            self.config.bundle_id
        )
    }
    pub fn load(path: &Path) -> Result<Self, Error> {
        let config: Config = serde_json::from_slice(&Zeroizing::new(
            elo_core::vault::read_private(path).map_err(|_| Error::Configuration)?,
        ))
        .map_err(|_| Error::Configuration)?;
        Self::new(config)
    }

    pub fn new(config: Config) -> Result<Self, Error> {
        if !valid_id(&config.key_id)
            || !valid_id(&config.team_id)
            || config
                .app_id_prefix
                .as_ref()
                .is_some_and(|prefix| !valid_id(prefix))
            || config.bundle_id.is_empty()
            || config.bundle_id.len() > 200
            || !config
                .bundle_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
        {
            return Err(Error::Configuration);
        }
        let pem = Zeroizing::new(
            String::from_utf8(
                elo_core::vault::read_private(&config.key_file)
                    .map_err(|_| Error::Configuration)?,
            )
            .map_err(|_| Error::Configuration)?,
        );
        let encoded = Zeroizing::new(
            pem.trim()
                .strip_prefix("-----BEGIN PRIVATE KEY-----")
                .and_then(|s| s.strip_suffix("-----END PRIVATE KEY-----"))
                .ok_or(Error::Configuration)?
                .split_whitespace()
                .collect::<String>(),
        );
        let der = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| Error::Configuration)?,
        );
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &SystemRandom::new())
                .map_err(|_| Error::Configuration)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            client,
            key,
            config,
            authorization: Mutex::new(None),
        })
    }

    async fn authorization(&self, now: u64) -> Result<Zeroizing<String>, Error> {
        let mut cached = self.authorization.lock().await;
        if let Some((token, issued)) = cached.as_ref()
            && now >= *issued
            && now - issued < 40 * 60
        {
            return Ok(token.clone());
        }
        let header =
            URL_SAFE_NO_PAD.encode(json!({"alg":"ES256", "kid":self.config.key_id}).to_string());
        let claims =
            URL_SAFE_NO_PAD.encode(json!({"iss":self.config.team_id, "iat":now}).to_string());
        let input = format!("{header}.{claims}");
        let signed = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|_| Error::Authentication)?;
        let token = Zeroizing::new(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signed.as_ref())
        ));
        *cached = Some((token.clone(), now));
        Ok(token)
    }

    /// Only an actual incoming call uses VoIP pushes. Cancellation travels over
    /// the call connection; stale calls expire locally and cannot be answered.
    pub async fn incoming(&self, token: &str, payload: &serde_json::Value) -> Result<(), Error> {
        if token.len() < 32
            || token.len() > 512
            || !token.len().is_multiple_of(2)
            || !token.bytes().all(|c| c.is_ascii_hexdigit())
            || payload.to_string().len() > 4096
        {
            return Err(Error::Configuration);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Authentication)?
            .as_secs();
        let host = if self.config.sandbox {
            "api.sandbox.push.apple.com"
        } else {
            "api.push.apple.com"
        };
        let authorization = self.authorization(now).await?;
        let mut response = self
            .client
            .post(format!("https://{host}/3/device/{token}"))
            .bearer_auth(authorization.as_str())
            .header("apns-push-type", "voip")
            .header("apns-priority", "10")
            .header("apns-expiration", "0")
            .header("apns-topic", format!("{}.voip", self.config.bundle_id))
            .json(payload)
            .send()
            .await
            .map_err(|_| Error::Delivery)?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        if status == 403 {
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Delivery)? {
                if body.len() + chunk.len() > 1024 {
                    return Err(Error::Authentication);
                }
                body.extend_from_slice(&chunk);
            }
        }
        let reason = serde_json::from_slice::<Rejection>(&body).ok();
        self.outcome(
            status,
            reason.as_ref().map(|value| value.reason.as_str()),
            &authorization,
            now,
        )
        .await
    }

    async fn outcome(
        &self,
        status: u16,
        reason: Option<&str>,
        used: &str,
        now: u64,
    ) -> Result<(), Error> {
        match status {
            200 => Ok(()),
            403 => {
                // A bad key/environment is not token expiry. Also ignore stale
                // responses to an older token after another request renewed it.
                if reason == Some("ExpiredProviderToken") {
                    let mut cached = self.authorization.lock().await;
                    if cached.as_ref().is_some_and(|(token, issued)| {
                        token.as_str() == used && now >= *issued && now - issued >= 20 * 60
                    }) {
                        *cached = None;
                        return Err(Error::TokenExpired);
                    }
                }
                Err(Error::Authentication)
            }
            410 => Err(Error::Unregistered),
            429 => Err(Error::Throttled),
            _ => Err(Error::Delivery),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn provider() -> Apns {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("auth.p8");
        let key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            base64::engine::general_purpose::STANDARD.encode(key.as_ref())
        );
        elo_core::vault::write_private(&path, pem.as_bytes(), false).unwrap();
        Apns::new(Config {
            key_file: path,
            key_id: "ABCDEFGHIJ".into(),
            team_id: "1234567890".into(),
            app_id_prefix: None,
            bundle_id: "now.elo".into(),
            sandbox: true,
        })
        .unwrap()
    }
    #[tokio::test]
    async fn provider_token_is_signed_cached_and_never_survives_clock_rollback() {
        use ring::signature::{ECDSA_P256_SHA256_FIXED, KeyPair, UnparsedPublicKey};
        let provider = provider();
        let token = provider.authorization(10000).await.unwrap();
        assert_eq!(
            token.as_str(),
            provider.authorization(10001).await.unwrap().as_str()
        );
        let parts: Vec<_> = token.split('.').collect();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, provider.key.public_key().as_ref())
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        let previous = provider.authorization(9999).await.unwrap();
        assert_ne!(previous.as_str(), token.as_str());
        assert!(provider.incoming("not-a-token", &json!({})).await.is_err());
    }

    #[tokio::test]
    async fn permanent_rejection_and_rate_limit_do_not_rotate_provider_tokens() {
        let provider = provider();
        let token = provider.authorization(10000).await.unwrap();
        for reason in [
            "BadEnvironmentKeyInToken",
            "BadEnvironmentKeyIdInToken",
            "InvalidProviderToken",
            "Forbidden",
            "MissingProviderToken",
        ] {
            assert!(matches!(
                provider.outcome(403, Some(reason), &token, 10001).await,
                Err(Error::Authentication)
            ));
            assert_eq!(
                provider.authorization(10002).await.unwrap().as_str(),
                token.as_str()
            );
        }
        assert!(matches!(
            provider.outcome(429, None, &token, 10003).await,
            Err(Error::Throttled)
        ));
        assert_eq!(
            provider.authorization(10004).await.unwrap().as_str(),
            token.as_str()
        );
    }

    #[tokio::test]
    async fn expiry_renews_only_the_rejected_token_and_respects_minimum_age() {
        let provider = provider();
        let old = provider.authorization(10000).await.unwrap();
        assert!(matches!(
            provider
                .outcome(403, Some("ExpiredProviderToken"), &old, 10001)
                .await,
            Err(Error::Authentication)
        ));
        assert_eq!(
            provider.authorization(10002).await.unwrap().as_str(),
            old.as_str()
        );
        assert!(matches!(
            provider
                .outcome(403, Some("ExpiredProviderToken"), &old, 11200)
                .await,
            Err(Error::TokenExpired)
        ));
        let fresh = provider.authorization(11201).await.unwrap();
        assert_ne!(fresh.as_str(), old.as_str());
        provider
            .outcome(403, Some("ExpiredProviderToken"), &old, 12402)
            .await
            .unwrap_err();
        assert_eq!(
            provider.authorization(12403).await.unwrap().as_str(),
            fresh.as_str()
        );
    }
}

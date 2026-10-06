//! Direct APNs VoIP delivery. The payload is an opaque call hint, never profile
//! credentials, conversation text, or a grant to activate capture.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::fcm::Error;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    team_id: String,
    key_id: String,
    bundle_id: String,
    private_key: String,
    // Kept readable for older operator configs; routing is per installation.
    #[serde(default, rename = "sandbox")]
    _legacy_sandbox: bool,
}

pub struct Apns {
    client: reqwest::Client,
    key: EcdsaKeyPair,
    team: String,
    key_id: String,
    topic: String,
    jwt: Mutex<Option<(Zeroizing<String>, u64)>>,
}

impl Apns {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| Error::Configuration)?;
        if !metadata.is_file() || metadata.len() > 16 * 1024 {
            return Err(Error::Configuration);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::Configuration);
            }
        }
        let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| Error::Configuration)?);
        let mut config: Config =
            serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
        let private = Zeroizing::new(std::mem::take(&mut config.private_key));
        if ![&config.team_id, &config.key_id].into_iter().all(|value| {
            value.len() == 10
                && value
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        }) || config.bundle_id.is_empty()
            || config.bundle_id.len() > 128
            || !config
                .bundle_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
        {
            return Err(Error::Configuration);
        }
        let pem = private
            .trim()
            .strip_prefix("-----BEGIN PRIVATE KEY-----")
            .and_then(|value| value.strip_suffix("-----END PRIVATE KEY-----"))
            .ok_or(Error::Configuration)?;
        let der = Zeroizing::new(
            STANDARD
                .decode(pem.split_whitespace().collect::<String>())
                .map_err(|_| Error::Configuration)?,
        );
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &SystemRandom::new())
                .map_err(|_| Error::Configuration)?;
        Ok(Self {
            client: reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(8))
                .build()
                .map_err(|_| Error::Configuration)?,
            key,
            team: config.team_id,
            key_id: config.key_id,
            topic: format!("{}.voip", config.bundle_id),
            jwt: Mutex::new(None),
        })
    }

    async fn token(&self, now: u64) -> Result<Zeroizing<String>, Error> {
        let mut cache = self.jwt.lock().await;
        if let Some((token, issued)) = &*cache
            && now >= *issued
            && now - issued < 50 * 60
        {
            return Ok(token.clone());
        }
        let header = URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":self.key_id}).to_string());
        let body = URL_SAFE_NO_PAD.encode(json!({"iss":self.team,"iat":now}).to_string());
        let unsigned = format!("{header}.{body}");
        let signature = self
            .key
            .sign(&SystemRandom::new(), unsigned.as_bytes())
            .map_err(|_| Error::Authentication)?;
        let token = Zeroizing::new(format!(
            "{unsigned}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ));
        *cache = Some((token.clone(), now));
        Ok(token)
    }

    pub async fn send(
        &self,
        device: &str,
        body: Value,
        expires: u64,
        sandbox: bool,
    ) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Delivery)?
            .as_secs();
        if expires <= now {
            return Ok(());
        }
        if device.len() < 32
            || device.len() > 256
            || !device
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || expires > now + 75
            || body.to_string().len() > 5120
        {
            return Err(Error::Delivery);
        }
        let host = host(sandbox);
        let token = self.token(now).await?;
        let response = self
            .client
            .post(format!("https://{host}/3/device/{device}"))
            .bearer_auth(token.as_str())
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "voip")
            .header("apns-priority", "10")
            // A queued ring is worse than a missed ring. The call service remains
            // the source of truth; APNs must not deliver it much later.
            .header("apns-expiration", "0")
            .json(&body)
            .send()
            .await
            .map_err(|_| Error::Delivery)?;
        match response.status().as_u16() {
            200 => Ok(()),
            410 => Err(Error::Unregistered),
            403 => Err(Error::Authentication),
            _ => Err(Error::Delivery),
        }
    }
}

fn host(sandbox: bool) -> &'static str {
    if sandbox {
        "api.sandbox.push.apple.com"
    } else {
        "api.push.apple.com"
    }
}

pub fn ring_payload(
    registration: &str,
    call: &str,
    invitation: &str,
    target: &str,
    expires: u64,
) -> Value {
    json!({"aps":{"content-available":1},"elo_ring":"1","elo_registration":registration,
        "elo_call_id":call,"elo_invitation_id":invitation,"elo_target":target,"elo_expires":expires.to_string()})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apns_endpoint_uses_each_delivery_environment() {
        let _: Config =
            serde_json::from_value(json!({"team_id":"ABCDEFGHIJ","key_id":"1234567890",
            "bundle_id":"test.elo","private_key":"not-used-in-this-test","sandbox":true}))
            .unwrap();
        assert_eq!(host(false), "api.push.apple.com");
        assert_eq!(host(true), "api.sandbox.push.apple.com");
        assert_eq!(host(false), "api.push.apple.com");
    }
    #[test]
    fn voip_payload_contains_no_alert_badge_or_profile_data() {
        let value = ring_payload("route", "call", "invitation", "ciphertext", 1060);
        assert_eq!(value["elo_invitation_id"], "invitation");
        assert_eq!(value["elo_expires"], "1060");
        assert!(value["aps"].get("alert").is_none());
        assert!(value["aps"].get("badge").is_none());
        assert!(value.get("identity").is_none());
        assert!(value.get("name").is_none());
    }
    #[tokio::test]
    async fn provider_token_has_fixed_es256_signature_and_bounded_reuse() {
        use ring::signature::{ECDSA_P256_SHA256_FIXED, KeyPair, UnparsedPublicKey};
        let der =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let provider = Apns {
            client: reqwest::Client::new(),
            key: EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                der.as_ref(),
                &SystemRandom::new(),
            )
            .unwrap(),
            team: "ABCDEFGHIJ".into(),
            key_id: "1234567890".into(),
            topic: "test.elo.voip".into(),
            jwt: Mutex::new(None),
        };
        let first = provider.token(1000).await.unwrap();
        assert_eq!(provider.token(3999).await.unwrap().as_str(), first.as_str());
        assert_ne!(provider.token(4000).await.unwrap().as_str(), first.as_str());
        let parts: Vec<_> = first.split('.').collect();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims, json!({"iss":"ABCDEFGHIJ","iat":1000}));
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, provider.key.public_key().as_ref())
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
            )
            .unwrap();
        // Wall-clock rollback must not reuse a future-issued provider token.
        assert_ne!(provider.token(999).await.unwrap().as_str(), first.as_str());
    }
}

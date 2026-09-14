//! FCM is the only provider. Neither endpoint nor message contents are caller-controlled.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid private Firebase service-account configuration")]
    Configuration,
    #[error("Firebase authentication failed")]
    Authentication,
    #[error("Firebase delivery failed")]
    Delivery,
    #[error("The device registration is no longer valid")]
    Unregistered,
}

#[derive(Deserialize)]
struct Account {
    #[serde(rename = "type")]
    kind: String,
    project_id: String,
    client_email: String,
    private_key_id: String,
    private_key: String,
    token_uri: String,
}

pub struct Fcm {
    client: reqwest::Client,
    project: String,
    email: String,
    key_id: String,
    key: RsaKeyPair,
    token: Mutex<Option<(Zeroizing<String>, Instant)>>,
}

#[derive(Clone, Debug)]
pub enum Notice {
    Challenge {
        registration: String,
        challenge: String,
    },
    Wake {
        registration: String,
        scope: String,
        target: String,
        quiet: bool,
    },
}

/// The provider never receives chat text, account IDs, mailbox capabilities or record IDs.
pub fn payload(token: &str, notice: &Notice) -> Value {
    let message = match notice {
        Notice::Challenge {
            registration,
            challenge,
        } => json!({
            "token": token,
            "data": {"elo_registration":registration, "elo_challenge":challenge},
            "android":{"priority":"HIGH", "ttl":"60s"},
            "apns":{"headers":{"apns-push-type":"alert","apns-priority":"10"},
                "payload":{"aps":{"alert":{"title":"elo.now","body":"Finish setting up notifications in elo.now."}}}}
        }),
        Notice::Wake {
            registration,
            scope,
            target,
            quiet,
        } => {
            let mut aps = json!({"thread-id":scope,"interruption-level":if *quiet {"passive"} else {"active"},
                "alert":{"title":"elo.now","body":"New messages"}});
            if !quiet {
                aps["sound"] = json!("default");
            }
            json!({
            "token":token,
            "data":{"elo_wake":"1", "elo_registration":registration, "elo_scope":scope, "elo_target":target, "elo_quiet":if *quiet {"1"} else {"0"}},
            "android":{"priority":"HIGH", "ttl":"86400s", "collapse_key":"elo-wake"},
            "apns":{"headers":{"apns-push-type":"alert","apns-priority":"10","apns-collapse-id":scope},
                "payload":{"aps":aps}}})
        }
    };
    json!({"message":message})
}

impl Fcm {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let meta = std::fs::symlink_metadata(path).map_err(|_| Error::Configuration)?;
        if !meta.is_file() || meta.len() > 32 * 1024 {
            return Err(Error::Configuration);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(Error::Configuration);
            }
        }
        let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| Error::Configuration)?);
        let mut account: Account =
            serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
        let pem = Zeroizing::new(std::mem::take(&mut account.private_key));
        if account.kind != "service_account"
            || account.token_uri != TOKEN_URL
            || account.project_id.is_empty()
            || account.project_id.len() > 128
            || !account
                .project_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !account.client_email.ends_with(".iam.gserviceaccount.com")
            || account.private_key_id.is_empty()
        {
            return Err(Error::Configuration);
        }
        let encoded = Zeroizing::new(
            pem.trim()
                .strip_prefix("-----BEGIN PRIVATE KEY-----")
                .and_then(|p| p.strip_suffix("-----END PRIVATE KEY-----"))
                .ok_or(Error::Configuration)?
                .split_whitespace()
                .collect::<String>(),
        );
        let der = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| Error::Configuration)?,
        );
        let key = RsaKeyPair::from_pkcs8(&der).map_err(|_| Error::Configuration)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            client,
            project: account.project_id,
            email: account.client_email,
            key_id: account.private_key_id,
            key,
            token: Mutex::new(None),
        })
    }

    async fn access_token(&self) -> Result<Zeroizing<String>, Error> {
        let mut saved = self.token.lock().await;
        if let Some((token, until)) = saved.as_ref()
            && *until > Instant::now()
        {
            return Ok(token.clone());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Authentication)?
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"alg":"RS256","typ":"JWT","kid":self.key_id}))
                .map_err(|_| Error::Authentication)?,
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss":self.email,"scope":"https://www.googleapis.com/auth/firebase.messaging",
                "aud":TOKEN_URL,"iat":now,"exp":now+3600
            }))
            .map_err(|_| Error::Authentication)?,
        );
        let signed = format!("{header}.{claims}");
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signed.as_bytes(),
                &mut signature,
            )
            .map_err(|_| Error::Authentication)?;
        let assertion = Zeroizing::new(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)));
        let response = self
            .client
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|_| Error::Authentication)?;
        if !response.status().is_success() {
            return Err(Error::Authentication);
        }
        let bytes = Zeroizing::new(bounded(response).await.map_err(|_| Error::Authentication)?);
        #[derive(Deserialize)]
        struct Token {
            access_token: String,
            expires_in: u64,
            token_type: String,
        }
        let data: Token = serde_json::from_slice(&bytes).map_err(|_| Error::Authentication)?;
        let token = Zeroizing::new(data.access_token);
        if data.token_type != "Bearer" || token.is_empty() || data.expires_in <= 60 {
            return Err(Error::Authentication);
        }
        *saved = Some((
            token.clone(),
            Instant::now() + Duration::from_secs(data.expires_in.min(3600) - 60),
        ));
        Ok(token)
    }

    pub async fn check_authentication(&self) -> Result<(), Error> {
        self.access_token().await.map(|_| ())
    }

    pub async fn send(&self, token: &str, notice: &Notice) -> Result<(), Error> {
        let access = self.access_token().await?;
        let response = self
            .client
            .post(format!(
                "https://fcm.googleapis.com/v1/projects/{}/messages:send",
                self.project
            ))
            .bearer_auth(access.as_str())
            .json(&payload(token, notice))
            .send()
            .await
            .map_err(|_| Error::Delivery)?;
        let status = response.status();
        if status.as_u16() == 401 {
            *self.token.lock().await = None;
        }
        let bytes = bounded(response).await?;
        if status.is_success() {
            return Ok(());
        }
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if value["error"]["details"]
            .as_array()
            .is_some_and(|details| details.iter().any(|d| d["errorCode"] == "UNREGISTERED"))
        {
            return Err(Error::Unregistered);
        }
        Err(Error::Delivery)
    }
}

async fn bounded(mut response: reqwest::Response) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Delivery)? {
        if bytes.len() + chunk.len() > 32 * 1024 {
            return Err(Error::Delivery);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unread_updates_are_passive_and_keep_the_same_system_notification() {
        let notice = |quiet| Notice::Wake {
            registration: "route".into(),
            scope: "scope".into(),
            target: "ciphertext".into(),
            quiet,
        };
        let first = payload("token", &notice(false));
        let next = payload("token", &notice(true));
        assert_eq!(
            first["message"]["apns"]["payload"]["aps"]["sound"],
            "default"
        );
        assert!(
            next["message"]["apns"]["payload"]["aps"]
                .get("sound")
                .is_none()
        );
        assert_eq!(
            next["message"]["apns"]["payload"]["aps"]["interruption-level"],
            "passive"
        );
        assert_eq!(next["message"]["data"]["elo_quiet"], "1");
        assert_eq!(
            first["message"]["apns"]["headers"]["apns-collapse-id"],
            next["message"]["apns"]["headers"]["apns-collapse-id"]
        );
    }
    #[test]
    fn wake_payload_has_no_caller_supplied_content() {
        let value = payload(
            "synthetic-device-token",
            &Notice::Wake {
                registration: "opaque-route".into(),
                scope: "opaque-scope".into(),
                target: "encrypted-target".into(),
                quiet: false,
            },
        );
        assert_eq!(
            value["message"]["data"],
            json!({"elo_wake":"1", "elo_registration":"opaque-route", "elo_scope":"opaque-scope", "elo_target":"encrypted-target", "elo_quiet":"0"})
        );
        assert_eq!(
            value["message"]["apns"]["payload"]["aps"]["alert"]["body"],
            "New messages"
        );
        assert!(value["message"].get("notification").is_none());
        assert_eq!(value["message"].as_object().unwrap().len(), 4);
        let challenge = payload(
            "synthetic",
            &Notice::Challenge {
                registration: "opaque".into(),
                challenge: "nonce".into(),
            },
        );
        assert!(challenge["message"].get("notification").is_none());
        assert_eq!(challenge["message"]["data"].as_object().unwrap().len(), 2);
    }
}

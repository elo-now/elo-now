//! Short-lived provider admission. Media keys never enter this module.
use crate::registry::{ActiveCall, CallError, Event, Participant};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use elo_core::{calls::CallKind, ids::RecordId};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{collections::BTreeMap, time::Duration};
use tokio::sync::Mutex;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub url: String,
    pub api_url: String,
    pub api_key: String,
    pub api_secret: String,
    pub turn_urls: Vec<String>,
    pub turn_secret: String,
}
#[derive(Serialize)]
pub struct Access {
    provider: &'static str,
    url: String,
    token: String,
    epoch: u64,
    ice_servers: Vec<Value>,
}
pub struct Provider {
    config: Config,
    client: reqwest::Client,
    rooms: Mutex<BTreeMap<String, String>>,
}
fn jwt(
    key: &str,
    secret: &str,
    subject: &str,
    grants: Value,
    now: u64,
) -> Result<String, CallError> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        json!({"iss":key,"sub":subject,"nbf":now.saturating_sub(5),"exp":now+60,"video":grants})
            .to_string(),
    );
    let input = format!("{header}.{claims}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| CallError::Unavailable)?;
    mac.update(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}
fn room(call: &ActiveCall) -> String {
    format!("{}-{}", call.call_id, call.key_epoch)
}
fn admin_grants(method: &str, name: &str) -> Result<Value, CallError> {
    match method {
        "DeleteRoom" => Ok(json!({"roomCreate":true})),
        "UpdateParticipant" => Ok(json!({"roomAdmin":true,"room":name})),
        _ => Err(CallError::Unauthorized),
    }
}
fn sources(participant: &Participant) -> Vec<&'static str> {
    let mut result = Vec::new();
    if !participant.media.audio_muted {
        result.push("microphone");
    }
    if participant.media.video_published {
        result.push("camera");
    }
    if participant.media.screen_published {
        result.extend(["screen_share", "screen_share_audio"]);
    }
    result
}
impl Provider {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let public = reqwest::Url::parse(&config.url)?;
        let private = reqwest::Url::parse(&config.api_url)?;
        if public.scheme() != "wss"
            || !public.username().is_empty()
            || public.password().is_some()
            || public.query().is_some()
            || public.fragment().is_some()
            || private.scheme() != "http"
            || !private
                .host_str()
                .and_then(|v| v.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback())
            || config.api_secret.len() < 32
            || config.turn_secret.len() < 32
            || config.api_key.is_empty()
            || config.turn_urls.is_empty()
            || config.turn_urls.len() > 4
            || config.turn_urls.iter().any(|url| {
                !(url.starts_with("turn:") || url.starts_with("turns:"))
                    || url.chars().any(char::is_whitespace)
            })
        {
            return Err("Invalid media provider configuration.".into());
        }
        Ok(Self {
            config,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            rooms: Mutex::new(BTreeMap::new()),
        })
    }
    pub fn access(
        &self,
        call: &ActiveCall,
        credential: RecordId,
        now: u64,
    ) -> Result<Access, CallError> {
        let participant = call
            .participants
            .values()
            .find(|p| p.credential_id == credential)
            .ok_or(CallError::Unauthorized)?;
        let username = format!("{}:{}", now + 600, credential);
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(self.config.turn_secret.as_bytes())
            .map_err(|_| CallError::Unavailable)?;
        mac.update(username.as_bytes());
        let ice_servers = vec![
            json!({"urls":self.config.turn_urls,"username":username,"credential":STANDARD.encode(mac.finalize().into_bytes())}),
        ];
        let token = if call.kind == CallKind::Group {
            jwt(
                &self.config.api_key,
                &self.config.api_secret,
                &credential.to_string(),
                json!({"roomJoin":true,"room":room(call),"canPublish":!sources(participant).is_empty(),"canPublishSources":sources(participant),"canSubscribe":true,"canPublishData":false,"canUpdateOwnMetadata":false}),
                now,
            )?
        } else {
            String::new()
        };
        Ok(Access {
            provider: if call.kind == CallKind::Group {
                "livekit"
            } else {
                "p2p"
            },
            url: self.config.url.clone(),
            token,
            epoch: call.key_epoch,
            ice_servers,
        })
    }
    async fn api(&self, method: &str, name: &str, body: Value, now: u64) -> Result<(), CallError> {
        let token = jwt(
            &self.config.api_key,
            &self.config.api_secret,
            "elo-call-control",
            admin_grants(method, name)?,
            now,
        )?;
        let status = self
            .client
            .post(format!(
                "{}/twirp/livekit.RoomService/{method}",
                self.config.api_url.trim_end_matches('/')
            ))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|_| CallError::Unavailable)?
            .status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(CallError::Unavailable)
        }
    }
    pub async fn reconcile(&self, events: &[Event], now: u64) -> Result<(), CallError> {
        let mut rooms = self.rooms.lock().await;
        for event in events {
            match event {
                Event::Presence { call } if call.kind == CallKind::Group => {
                    let next = room(call);
                    if let Some(old) = rooms.get(&call.call_id).filter(|old| *old != &next) {
                        self.api("DeleteRoom", old, json!({"room":old}), now)
                            .await?;
                    }
                    rooms.insert(call.call_id.clone(), next.clone());
                    for participant in call.participants.values() {
                        let allowed = sources(participant);
                        self.api("UpdateParticipant",&next,json!({"room":next,"identity":participant.credential_id,"permission":{"canSubscribe":true,"canPublish":!allowed.is_empty(),"canPublishSources":allowed.iter().map(|source|match *source {"camera"=>1,"microphone"=>2,"screen_share"=>3,_=>4}).collect::<Vec<_>>(),"canPublishData":false,"canUpdateMetadata":false}}),now).await?;
                    }
                }
                Event::Ended { call_id, .. } => {
                    if let Some(old) = rooms.get(call_id) {
                        self.api("DeleteRoom", old, json!({"room":old}), now)
                            .await?;
                        rooms.remove(call_id);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_administration_uses_method_specific_grants() {
        assert_eq!(
            admin_grants("DeleteRoom", "opaque-2").unwrap(),
            json!({"roomCreate":true})
        );
        assert_eq!(
            admin_grants("UpdateParticipant", "opaque-2").unwrap(),
            json!({"roomAdmin":true,"room":"opaque-2"})
        );
        assert!(admin_grants("CreateRoom", "opaque-2").is_err());
    }
    #[test]
    fn provider_token_is_bounded_and_contains_no_media_key() {
        let token = jwt(
            "provider",
            "secret",
            "device",
            json!({"roomJoin":true,"room":"opaque-2"}),
            100,
        )
        .unwrap();
        let parts: Vec<_> = token.split('.').collect();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["exp"], 160);
        assert_eq!(claims["video"]["room"], "opaque-2");
        assert!(claims.get("key").is_none());
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        mac.verify_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap())
            .unwrap();
    }
}

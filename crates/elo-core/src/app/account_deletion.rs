//! Explicit identity-authenticated deletion requests. Submission is not erasure.
use super::*;
use crate::ids::ObjectId;
use std::time::Duration;

pub const PATH: &str = "/accounts/v1/deletion";
pub const STATUS_PATH: &str = "/accounts/v1/deletion/status";
pub const WAKE_PATH: &str = "/wake/v1/account-deletion";
pub const LIMIT: usize = 512 * 1024;
pub const REQUEST_LIMIT: usize = 16 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deletion_proof_is_purpose_endpoint_time_and_device_bound() {
        let alice = Session::create().unwrap().0;
        let bob = Session::create().unwrap().0;
        let command = Command {
            v: 1,
            kind: "account.deletion".into(),
            endpoint: "https://service.example/accounts/v1/deletion".into(),
            nonce: "ab".repeat(16),
            issued: 1_000_000,
            action: Action::Submit,
            confirmed: true,
        };
        let request = Request {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), alice.signing_key())
                    .unwrap()
                    .bytes(),
            ),
            credential: STANDARD.encode(alice.credential().record().bytes()),
        };
        assert_eq!(
            verify(&request, &command.endpoint, 1_000_000)
                .unwrap()
                .1
                .identity(),
            alice.identity_id()
        );
        assert!(
            verify(
                &request,
                "https://another.example/accounts/v1/deletion",
                1_000_000
            )
            .is_err()
        );
        assert!(verify(&request, &command.endpoint, 1_120_001).is_err());
        let mut forged = request.clone();
        forged.credential = STANDARD.encode(bob.credential().record().bytes());
        assert!(verify(&forged, &command.endpoint, 1_000_000).is_err());
        let mut invalid = command.clone();
        invalid.confirmed = false;
        forged = request.clone();
        forged.record = STANDARD.encode(
            SignedRecord::sign(&serde_json::to_vec(&invalid).unwrap(), alice.signing_key())
                .unwrap()
                .bytes(),
        );
        assert!(verify(&forged, &command.endpoint, 1_000_000).is_err());
        assert!(
            verify_route_binding(
                &request,
                "https://service.example",
                "ab",
                "token",
                1_000_000
            )
            .is_err()
        );
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Inspect,
    Submit,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub record: String,
    pub credential: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub v: u8,
    pub kind: String,
    pub endpoint: String,
    pub nonce: String,
    pub issued: u64,
    pub action: Action,
    pub confirmed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub ciphertext: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedSpace {
    pub name: String,
    pub other_members: bool,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ready,
    Blocked,
    Pending,
    Completed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub status: Status,
    pub owned_spaces: Vec<OwnedSpace>,
    pub request_id: Option<String>,
    pub requested_at: Option<u64>,
    pub completed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Receipt>,
}

/// An opaque, read-only completion capability. It cannot authenticate a profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub endpoint: String,
    pub id: String,
}
pub fn validate_receipt(id: &str) -> Result<()> {
    record::hex::<16>(id)?;
    Ok(())
}
impl Receipt {
    pub async fn completed(&self, allow_loopback: bool) -> Result<bool> {
        validate_receipt(&self.id)?;
        if endpoint(&self.endpoint, allow_loopback)?.replace(PATH, STATUS_PATH) != self.endpoint {
            return Err("Invalid deletion receipt endpoint.".into());
        }
        let mut response = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?
            .post(&self.endpoint)
            .json(&json!({"receipt":self.id}))
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > 1024 {
                return Err("Invalid deletion receipt.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        value["completed"]
            .as_bool()
            .ok_or_else(|| "Invalid deletion receipt.".into())
    }
}

pub fn endpoint(origin: &str, allow_loopback: bool) -> Result<String> {
    let url = reqwest::Url::parse(origin)?;
    let host = format!("{}/spaces/v1/create", url.origin().ascii_serialization());
    space_host::validate_host(&host, allow_loopback)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Invalid account deletion service address.".into());
    }
    Ok(format!("{}{PATH}", url.origin().ascii_serialization()))
}
pub fn wake_endpoint(origin: &str, allow_loopback: bool) -> Result<String> {
    Ok(endpoint(origin, allow_loopback)?.replace(PATH, WAKE_PATH))
}

/// A separate, purpose-bound signature associates a push route with its account.
pub fn verify_route_binding(
    request: &Request,
    endpoint: &str,
    route: &str,
    token: &str,
    current: u64,
) -> Result<VerifiedCredential> {
    if request.record.len() + request.credential.len() > REQUEST_LIMIT {
        return Err("Invalid route binding.".into());
    }
    let raw = decode_record(&request.credential)?;
    let credential = VerifiedCredential::verify(
        raw.bytes(),
        &root_key(field(raw.body(), "root_public_key")?)?,
    )?;
    let signed = decode_record(&request.record)?;
    signed.verify_signature(credential.key())?;
    let body = signed.body();
    if body["v"] != 1
        || body["kind"] != "account.route"
        || body["endpoint"] != endpoint
        || body["route"] != route
        || body["token"] != json!(ObjectId::of_ciphertext(token.as_bytes()))
        || body["issued"]
            .as_u64()
            .is_none_or(|issued| current.abs_diff(issued) > 120_000)
    {
        return Err("Invalid route binding.".into());
    }
    Ok(credential)
}

pub fn verify(
    request: &Request,
    expected_endpoint: &str,
    current: u64,
) -> Result<(Command, VerifiedCredential)> {
    if request.record.len() + request.credential.len() > REQUEST_LIMIT {
        return Err("Account deletion request is too large.".into());
    }
    let raw = decode_record(&request.credential)?;
    let credential = VerifiedCredential::verify(
        raw.bytes(),
        &root_key(field(raw.body(), "root_public_key")?)?,
    )?;
    let signed = decode_record(&request.record)?;
    signed.verify_signature(credential.key())?;
    let command: Command = signed.decode()?;
    record::hex::<16>(&command.nonce)?;
    if command.v != 1
        || command.kind != "account.deletion"
        || command.endpoint != expected_endpoint
        || current.abs_diff(command.issued) > 120_000
        || command.confirmed != (command.action == Action::Submit)
    {
        return Err("Invalid or expired account deletion request.".into());
    }
    Ok((command, credential))
}

pub fn seal(
    command: &Command,
    credential: &VerifiedCredential,
    outcome: &Outcome,
) -> Result<Response> {
    let body = json!({"nonce":command.nonce,"endpoint":command.endpoint,"identity":credential.identity(),"outcome":outcome});
    Ok(Response {
        ciphertext: STANDARD.encode(crypto::seal_bytes(
            &Zeroizing::new(serde_json::to_vec(&body)?),
            &[credential.recipient()],
            LIMIT,
        )?),
    })
}

impl ClientApp {
    pub async fn delete_account(&self, host: &str, wake: &str, submit: bool) -> Result<Outcome> {
        let mut endpoints = self.account_hosts()?;
        endpoints.insert(endpoint(host, self.allow_loopback)?);
        let relay = wake_endpoint(wake, self.allow_loopback)?;
        endpoints.insert(relay.clone());
        if endpoints.len() > 64 {
            return Err("Too many account services.".into());
        }
        let mut owned_spaces = Vec::new();
        for url in &endpoints {
            owned_spaces.extend(
                self.call_account_deletion(url, Action::Inspect)
                    .await?
                    .owned_spaces,
            );
        }
        let mut result = Outcome {
            status: if owned_spaces.is_empty() {
                Status::Ready
            } else {
                Status::Blocked
            },
            owned_spaces,
            request_id: None,
            requested_at: None,
            completed_at: None,
            receipts: Vec::new(),
        };
        if submit && result.status == Status::Ready {
            // Remote acknowledgement means durable acceptance, not completed erasure.
            for url in &endpoints {
                let outcome = self.call_account_deletion(url, Action::Submit).await?;
                if outcome.status == Status::Blocked {
                    return Ok(outcome);
                }
                if !matches!(outcome.status, Status::Pending | Status::Completed) {
                    return Err(
                        "Deletion was not accepted. Your local profile has been kept.".into(),
                    );
                }
                if outcome.status == Status::Pending {
                    if url.ends_with(WAKE_PATH) {
                        return Err("Notification deletion has not completed.".into());
                    }
                    let id = outcome.request_id.ok_or("Missing deletion receipt.")?;
                    record::hex::<16>(&id)?;
                    result.receipts.push(Receipt {
                        endpoint: url.replace(PATH, STATUS_PATH),
                        id,
                    });
                }
            }
            result.status = Status::Pending;
        }
        Ok(result)
    }
    pub fn account_route_binding(
        &self,
        endpoint: &str,
        route: &str,
        token: &str,
    ) -> Result<Request> {
        record::hex::<16>(route)?;
        let origin = invitations::push::endpoint(endpoint, self.push_allow_loopback)?
            .origin()
            .ascii_serialization();
        let body = json!({"v":1,"kind":"account.route","endpoint":origin,"route":route,"token":ObjectId::of_ciphertext(token.as_bytes()),"issued":now()?.as_millis() as u64});
        Ok(Request {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&body)?, self.session.signing_key())?
                    .bytes(),
            ),
            credential: STANDARD.encode(self.session.credential().record().bytes()),
        })
    }
    pub fn account_deletion_request(&self, url: &str, action: Action) -> Result<Request> {
        if endpoint(url, self.allow_loopback)? != url
            && wake_endpoint(url, self.allow_loopback)? != url
        {
            return Err("Invalid account deletion service address.".into());
        }
        let command = Command {
            v: 1,
            kind: "account.deletion".into(),
            endpoint: url.into(),
            nonce: record::random_hex::<16>()?,
            issued: now()?.as_millis() as u64,
            action,
            confirmed: action == Action::Submit,
        };
        Ok(Request {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&command)?, self.session.signing_key())?
                    .bytes(),
            ),
            credential: STANDARD.encode(self.session.credential().record().bytes()),
        })
    }
    pub fn open_account_deletion_response(
        &self,
        request: &Request,
        response: Response,
    ) -> Result<Outcome> {
        let command: Command = decode_record(&request.record)?.decode()?;
        let value: Value = serde_json::from_slice(&Zeroizing::new(crypto::open_bytes(
            &STANDARD.decode(response.ciphertext)?,
            self.session.age_identity(),
            LIMIT,
        )?))?;
        if value["nonce"] != command.nonce
            || value["endpoint"] != command.endpoint
            || value["identity"] != json!(self.identity_id())
        {
            return Err("Unexpected account deletion response.".into());
        }
        let outcome: Outcome = serde_json::from_value(value["outcome"].clone())?;
        if outcome.owned_spaces.len() > 4096
            || (outcome.status == Status::Completed && outcome.completed_at.is_none())
            || (matches!(outcome.status, Status::Pending | Status::Completed)
                && (outcome.request_id.is_none() || outcome.requested_at.is_none()))
        {
            return Err("Invalid account deletion status.".into());
        }
        Ok(outcome)
    }
    pub async fn call_account_deletion(&self, url: &str, action: Action) -> Result<Outcome> {
        let request = self.account_deletion_request(url, action)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()?;
        let mut response = client.post(url).json(&request).send().await?;
        if !response.status().is_success() {
            return Err("Account deletion is unavailable on this service. Try again later.".into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > LIMIT * 2 {
                return Err("Account deletion response is too large.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        self.open_account_deletion_response(&request, serde_json::from_slice(&bytes)?)
    }
}

//! Identity-signed, retryable hosted Space creation. No client secret leaves the device.
use super::*;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const CREATE_LIMIT: usize = 64 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub record: String,
    pub credential: String,
    pub work: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_work_is_bound_to_the_signed_command_and_credential() {
        let mut request = CreateRequest {
            record: "synthetic signed command".into(),
            credential: "synthetic credential".into(),
            work: 0,
        };
        let start = std::time::Instant::now();
        request.solve_work().unwrap();
        eprintln!("Synthetic creation work: {:?}", start.elapsed());
        request.verify_work().unwrap();
        request.record.push('x');
        assert!(request.verify_work().is_err());
        request.record.pop();
        request.credential.push('x');
        assert!(request.verify_work().is_err());
        request.credential.pop();
        request.work = request.work.wrapping_add(1);
        assert!(request.verify_work().is_err());
    }
}

// Paid once per signed creation, never during chat synchronization. Verification
// costs one hash and precedes signature checks and profile/Argon2 provisioning.
const CREATE_WORK_BITS: u32 = 20;
impl CreateRequest {
    fn work_prefix(&self) -> Sha256 {
        let mut hash = Sha256::new();
        hash.update(b"elo.space.create.work.v1\0");
        hash.update(Sha256::digest(self.record.as_bytes()));
        hash.update(Sha256::digest(self.credential.as_bytes()));
        hash
    }
    fn valid_work(prefix: &Sha256, nonce: u64) -> bool {
        let mut hash = prefix.clone();
        hash.update(nonce.to_be_bytes());
        let result = hash.finalize();
        u32::from_be_bytes(result[..4].try_into().unwrap()).leading_zeros() >= CREATE_WORK_BITS
    }
    pub fn verify_work(&self) -> Result<()> {
        if self.record.len() + self.credential.len() > CREATE_LIMIT
            || !Self::valid_work(&self.work_prefix(), self.work)
        {
            return Err("Invalid Space creation proof.".into());
        }
        Ok(())
    }
    fn solve_work(&mut self) -> Result<()> {
        let prefix = self.work_prefix();
        for nonce in 0..64 * (1 << CREATE_WORK_BITS) {
            if Self::valid_work(&prefix, nonce) {
                self.work = nonce;
                return Ok(());
            }
        }
        Err("Space creation proof timed out.".into())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCommand {
    pub v: u8,
    pub kind: String,
    pub host: String,
    pub request_id: String,
    pub issued: u64,
    pub name: String,
    pub contact_email: String,
    pub message_lifetime_seconds: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateResponse {
    pub ciphertext: String,
}
pub fn validate_host(value: &str, allow_loopback: bool) -> Result<()> {
    let url = reqwest::Url::parse(value)?;
    let local = url
        .host_str()
        .and_then(|h| h.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/spaces/v1/create"
        || !(url.scheme() == "https" || (allow_loopback && local && url.scheme() == "http"))
    {
        return Err("Invalid Space hosting address.".into());
    }
    Ok(())
}
pub fn verify_create(
    request: &CreateRequest,
    expected_host: &str,
    current: u64,
) -> Result<(CreateCommand, VerifiedCredential)> {
    request.verify_work()?;
    if request.record.len() + request.credential.len() > CREATE_LIMIT {
        return Err("Space request is too large.".into());
    }
    let raw = decode_record(&request.credential)?;
    let credential = VerifiedCredential::verify(
        raw.bytes(),
        &root_key(field(raw.body(), "root_public_key")?)?,
    )?;
    let signed = decode_record(&request.record)?;
    signed.verify_signature(credential.key())?;
    let command: CreateCommand = signed.decode()?;
    record::hex::<16>(&command.request_id)?;
    if command.v != 1
        || command.kind != "space.create"
        || command.host != expected_host
        || current.abs_diff(command.issued) > 120_000
        || !record::valid_display_name(&command.name)
    {
        return Err("Invalid or expired Space creation request.".into());
    }
    space_service::validate_contact_email(&command.contact_email)?;
    space_service::validate_message_lifetime(command.message_lifetime_seconds)?;
    Ok((command, credential))
}
pub fn seal_creation(
    credential: &VerifiedCredential,
    command: &CreateCommand,
    invitation: &str,
) -> Result<CreateResponse> {
    let value = json!({"request_id":command.request_id,"host":command.host,"name":command.name,"contact_email":command.contact_email,"message_lifetime_seconds":command.message_lifetime_seconds,"invitation":invitation});
    Ok(CreateResponse {
        ciphertext: STANDARD.encode(crypto::seal_bytes(
            &Zeroizing::new(serde_json::to_vec(&value)?),
            &[credential.recipient()],
            CREATE_LIMIT,
        )?),
    })
}
impl ClientApp {
    pub fn hosted_create_request(
        &self,
        host: &str,
        request_id: &str,
        name: &str,
        contact_email: &str,
        message_lifetime_seconds: u64,
    ) -> Result<CreateRequest> {
        let mut request = self.hosted_create_payload(
            host,
            request_id,
            name,
            contact_email,
            message_lifetime_seconds,
        )?;
        request.solve_work()?;
        Ok(request)
    }
    fn hosted_create_payload(
        &self,
        host: &str,
        request_id: &str,
        name: &str,
        contact_email: &str,
        message_lifetime_seconds: u64,
    ) -> Result<CreateRequest> {
        validate_host(host, self.allow_loopback)?;
        record::hex::<16>(request_id)?;
        if !record::valid_display_name(name) {
            return Err("Enter a Space name.".into());
        }
        space_service::validate_contact_email(contact_email)?;
        space_service::validate_message_lifetime(message_lifetime_seconds)?;
        let command = CreateCommand {
            v: 1,
            kind: "space.create".into(),
            host: host.into(),
            request_id: request_id.into(),
            issued: now()?.as_millis() as u64,
            name: name.into(),
            contact_email: contact_email.into(),
            message_lifetime_seconds,
        };
        Ok(CreateRequest {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&command)?, self.session.signing_key())?
                    .bytes(),
            ),
            credential: STANDARD.encode(self.session.credential().record().bytes()),
            work: 0,
        })
    }
    pub(super) async fn create_hosted(
        &self,
        host: &str,
        request_id: &str,
        name: &str,
        contact_email: &str,
        message_lifetime_seconds: u64,
    ) -> Result<String> {
        let mut request = self.hosted_create_payload(
            host,
            request_id,
            name,
            contact_email,
            message_lifetime_seconds,
        )?;
        let request = tokio::task::spawn_blocking(move || -> Result<CreateRequest> {
            request.solve_work()?;
            Ok(request)
        })
        .await??;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()?;
        let mut response = client
            .post(host)
            .json(&request)
            .send()
            .await
            .map_err(space_service::space_transport_error)?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err("Space hosting is currently at capacity. Try again later or join an existing Space.".into());
        }
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err("Space hosting unavailable.".into());
        }
        if !response.status().is_success() {
            return Err(space_service::space_status_error(response.status()).into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(space_service::space_transport_error)?
        {
            if bytes.len() + chunk.len() > CREATE_LIMIT * 2 {
                return Err("Space hosting response is too large.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let response: CreateResponse =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid Space response.")?;
        let value: Value = serde_json::from_slice(&Zeroizing::new(crypto::open_bytes(
            &STANDARD.decode(response.ciphertext)?,
            self.session.age_identity(),
            CREATE_LIMIT,
        )?))?;
        if value["request_id"] != request_id
            || value["host"] != host
            || value["name"] != name
            || value["contact_email"] != contact_email
            || value["message_lifetime_seconds"] != message_lifetime_seconds
        {
            return Err("Unexpected Space hosting response.".into());
        }
        let link = field(&value, "invitation")?;
        let invite = space_service::SpaceInvitation::parse(link, self.allow_loopback)?;
        if reqwest::Url::parse(&invite.address.url)?.origin() != reqwest::Url::parse(host)?.origin()
        {
            return Err("Space hosting response changed server.".into());
        }
        Ok(link.into())
    }
}

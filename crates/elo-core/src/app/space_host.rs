//! Identity-signed, retryable hosted Space creation. No client secret leaves the device.
use super::*;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const CREATE_LIMIT: usize = 64 * 1024;
pub fn default_require_approval() -> bool {
    true
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub record: String,
    pub credential: String,
    pub work: u64,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn owner_creation() -> (Session, CreateCommand) {
        owner_creation_with_witness(None)
    }

    fn owner_creation_with_witness(
        witness: Option<crate::authority::WitnessPin>,
    ) -> (Session, CreateCommand) {
        let (owner, _) = Session::create().unwrap();
        let request_id = "ab".repeat(16);
        let root = field(owner.credential().record().body(), "root_public_key").unwrap();
        let version = if witness.is_some() { 4 } else { 2 };
        let genesis = SpaceGenesis {
            witness,
            v: version,
            kind: "space.genesis".into(),
            nonce: request_id.clone(),
            issuer_identity: owner.identity_id(),
            owners: vec![Owner {
                identity_id: owner.identity_id(),
                root_public_key: root.into(),
            }],
            controller_credential_id: owner.credential().id(),
        };
        let genesis =
            SignedRecord::sign(&serde_json::to_vec(&genesis).unwrap(), owner.signing_key())
                .unwrap();
        let mut authority = Authority::new(
            genesis.bytes(),
            genesis.id().to_string().parse().unwrap(),
            &root_key(root).unwrap(),
            owner.credential().clone(),
            StreamId::from_bytes(record::hex(&request_id).unwrap()),
        )
        .unwrap();
        let config = StreamConfig {
            witness_evidence: None,
            v: version,
            kind: "stream.config".into(),
            nonce: request_id.clone(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: owner.credential().id(),
            members: vec![Member {
                identity_id: owner.identity_id(),
                identity_type: "HUMAN".into(),
                root_public_key: root.into(),
                capabilities: vec![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ],
                credential_ids: vec![owner.credential().id()],
                external: false,
            }],
            owner_credential_ids: vec![owner.credential().id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: owner.identity_id(),
                request_record_id: None,
            },
            chat_kind: Some(ChatKind::Chat),
            recovery: None,
        };
        authority
            .apply_config(config.sign(owner.signing_key()).unwrap())
            .unwrap();
        let command = CreateCommand {
            v: 2,
            kind: "space.create".into(),
            host: "https://host.example.test/spaces/v1/create".into(),
            request_id,
            issued: 100,
            name: "Team".into(),
            contact_email: "owner@example.test".into(),
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
            require_approval: true,
            authority: Some(authority.call_proof().unwrap()),
        };
        (owner, command)
    }

    #[test]
    fn witnessed_creation_requires_the_independent_pin_and_rejects_downgrade() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[67; 32]);
        let pin = crate::authority::WitnessPin {
            url: "https://witness.example.test/witness/v1".into(),
            public_key: record::encode_hex(key.verifying_key().as_bytes()),
            key_generation: 1,
        };
        let (owner, command) = owner_creation_with_witness(Some(pin.clone()));
        assert!(verify_creation_authority(&command, owner.credential()).is_err());
        let authority =
            verify_creation_authority_with_witness(&command, owner.credential(), Some(&pin))
                .unwrap()
                .unwrap();
        assert_eq!(authority.witness_pin(), Some(&pin));
        let mut changed_pin = pin.clone();
        changed_pin.key_generation += 1;
        assert!(
            verify_creation_authority_with_witness(
                &command,
                owner.credential(),
                Some(&changed_pin)
            )
            .is_err()
        );
        let (legacy_owner, legacy) = owner_creation();
        assert!(
            verify_creation_authority_with_witness(&legacy, legacy_owner.credential(), Some(&pin))
                .is_err()
        );

        let directory = tempfile::tempdir().unwrap();
        let service = crate::public_space::PublicSpaceService::create_with_witness(
            directory.path().join("service"),
            command.authority.clone().unwrap(),
            &[owner.identity_id()],
            None,
            false,
            None,
            Some(pin.clone()),
        )
        .unwrap();
        assert_eq!(service.team_scope().unwrap().space, authority.space());
        drop(service);
        assert!(
            crate::public_space::PublicSpaceService::open(directory.path().join("service"), false)
                .is_err()
        );
        assert!(
            crate::public_space::PublicSpaceService::open_with_witness(
                directory.path().join("service"),
                false,
                Some(changed_pin)
            )
            .is_err()
        );
        crate::public_space::PublicSpaceService::open_with_witness(
            directory.path().join("service"),
            false,
            Some(pin),
        )
        .unwrap();
    }

    #[test]
    fn owner_creation_binds_version_device_request_and_initial_configuration() {
        let (owner, command) = owner_creation();
        let mut authority = verify_creation_authority(&command, owner.credential())
            .unwrap()
            .unwrap();
        let mut request = CreateRequest {
            record: STANDARD.encode(
                SignedRecord::sign(&serde_json::to_vec(&command).unwrap(), owner.signing_key())
                    .unwrap()
                    .bytes(),
            ),
            credential: STANDARD.encode(owner.credential().record().bytes()),
            work: 0,
        };
        request.solve_work().unwrap();
        verify_create(&request, &command.host, command.issued).unwrap();
        let (foreign, _) = Session::create().unwrap();
        assert!(verify_creation_authority(&command, foreign.credential()).is_err());
        let mut changed = command.clone();
        changed.request_id = "cd".repeat(16);
        assert!(verify_creation_authority(&changed, owner.credential()).is_err());
        changed = command.clone();
        changed.v = 1;
        assert!(verify_creation_authority(&changed, owner.credential()).is_err());
        changed.authority = None;
        assert!(
            verify_creation_authority(&changed, owner.credential())
                .unwrap()
                .is_none()
        );
        changed.v = 2;
        assert!(verify_creation_authority(&changed, owner.credential()).is_err());
        let mut next = authority.head().unwrap().clone();
        next.sequence += 1;
        next.previous_config_id = authority.head_id();
        next.nonce = "cd".repeat(16);
        authority
            .apply_config(next.sign(owner.signing_key()).unwrap())
            .unwrap();
        changed.authority = Some(authority.call_proof().unwrap());
        assert!(verify_creation_authority(&changed, owner.credential()).is_err());
    }

    #[test]
    fn creation_response_preserves_the_owner_scope_and_pins_a_separate_transport_signer() {
        let (owner, command) = owner_creation();
        let authority = verify_creation_authority(&command, owner.credential())
            .unwrap()
            .unwrap();
        let (transport, _) = Session::create().unwrap();
        let address = space_service::SpaceAddress {
            url: "https://host.example.test/team/v1/spaces".into(),
            scope: team::TeamScope {
                space: authority.space(),
                stream: authority.stream(),
                controller: owner.credential().id(),
                root: field(owner.credential().record().body(), "root_public_key")
                    .unwrap()
                    .into(),
            },
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
            service_credential: Some(STANDARD.encode(transport.credential().record().bytes())),
        };
        address.validate(false).unwrap();
        verify_created_address(&address, &authority).unwrap();
        for case in 0..6 {
            let mut changed = address.clone();
            match case {
                0 => changed.scope.space = SpaceId::from_bytes([1; 32]),
                1 => changed.scope.stream = StreamId::from_bytes([1; 16]),
                2 => changed.scope.controller = transport.credential().id(),
                3 => {
                    changed.scope.root =
                        field(transport.credential().record().body(), "root_public_key")
                            .unwrap()
                            .into()
                }
                4 => changed.service_credential = None,
                _ => {
                    changed.service_credential =
                        Some(STANDARD.encode(owner.credential().record().bytes()))
                }
            }
            assert!(
                verify_created_address(&changed, &authority).is_err(),
                "case {case}"
            );
        }
        let mut malformed = address;
        malformed.service_credential = Some("invalid".into());
        assert!(malformed.validate(false).is_err());
    }

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
    pub message_lifetime_seconds: crate::message_retention::MessageRetention,
    #[serde(default = "default_require_approval")]
    pub require_approval: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<crate::authority::CallAuthorityProof>,
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
    verify_create_with_witness(request, expected_host, current, None)
}

/// The deployment supplies this pin independently of the request. A witnessed
/// deployment rejects legacy creation rather than accepting a client downgrade.
pub fn verify_create_with_witness(
    request: &CreateRequest,
    expected_host: &str,
    current: u64,
    witness: Option<&crate::authority::WitnessPin>,
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
    if !matches!(
        (command.v, command.authority.is_some()),
        (1, false) | (2, true)
    ) || command.kind != "space.create"
        || command.host != expected_host
        || current.abs_diff(command.issued) > 120_000
        || !record::valid_display_name(&command.name)
    {
        return Err("Invalid or expired Space creation request.".into());
    }
    space_service::validate_contact_email(&command.contact_email)?;
    space_service::validate_message_lifetime(command.message_lifetime_seconds)?;
    verify_creation_authority_with_witness(&command, &credential, witness)?;
    Ok((command, credential))
}
pub(crate) fn verify_creation_authority(
    command: &CreateCommand,
    credential: &VerifiedCredential,
) -> Result<Option<Authority>> {
    verify_creation_authority_with_witness(command, credential, None)
}

pub fn verify_creation_authority_with_witness(
    command: &CreateCommand,
    credential: &VerifiedCredential,
    witness: Option<&crate::authority::WitnessPin>,
) -> Result<Option<Authority>> {
    if let Some(pin) = witness {
        pin.validate()?;
    }
    if !matches!(
        (command.v, command.authority.is_some()),
        (1, false) | (2, true)
    ) {
        return Err("Invalid Space creation authority version.".into());
    }
    let Some(proof) = &command.authority else {
        if witness.is_some() {
            return Err("Witnessed Space creation requires an updated app.".into());
        }
        return Ok(None);
    };
    let genesis = decode_record(&proof.genesis)?;
    let stream = StreamId::from_bytes(record::hex::<16>(&command.request_id)?);
    let space = genesis.id().to_string().parse()?;
    let authority = match witness {
        Some(pin) => proof.verify_witnessed(space, stream, pin)?,
        None => proof.verify(space, stream)?,
    };
    let body: SpaceGenesis = authority.genesis().decode()?;
    let head = authority.head()?;
    if !authority.is_owner_managed()
        || body.nonce != command.request_id
        || body.issuer_identity != credential.identity()
        || body.owners.len() != 1
        || body.owners[0].identity_id != credential.identity()
        || body.owners[0].root_public_key != field(credential.record().body(), "root_public_key")?
        || authority.initial_controller().id() != credential.id()
        || head.sequence != 1
        || head.controller_credential_id != credential.id()
        || head.members.len() != 1
        || head.members[0].identity_id != credential.identity()
        || head.members[0].credential_ids != vec![credential.id()]
    {
        return Err("Space creation authority does not match its owner and request.".into());
    }
    Ok(Some(authority))
}
fn verify_created_address(
    address: &space_service::SpaceAddress,
    authority: &Authority,
) -> Result<()> {
    if address.scope.space != authority.space()
        || address.scope.stream != authority.stream()
        || address.scope.controller != authority.initial_controller().id()
        || address.scope.root
            != field(
                authority.initial_controller().record().body(),
                "root_public_key",
            )?
    {
        return Err("Space hosting response changed General authority.".into());
    }
    let service = address
        .service_signer()?
        .ok_or("Space hosting response omitted its service credential.")?;
    if authority
        .head()?
        .members
        .iter()
        .any(|member| member.credential_ids.contains(&service.id()))
    {
        return Err("The Space hosting service cannot be a General participant.".into());
    }
    Ok(())
}
pub fn seal_creation(
    credential: &VerifiedCredential,
    command: &CreateCommand,
    invitation: &str,
) -> Result<CreateResponse> {
    let value = json!({"request_id":command.request_id,"host":command.host,"name":command.name,"contact_email":command.contact_email,"message_lifetime_seconds":command.message_lifetime_seconds,"require_approval":command.require_approval,"invitation":invitation});
    Ok(CreateResponse {
        ciphertext: STANDARD.encode(crypto::seal_bytes(
            &Zeroizing::new(serde_json::to_vec(&value)?),
            &[credential.recipient()],
            CREATE_LIMIT,
        )?),
    })
}
/// The witnessed bootstrap contains transport metadata, never an admission token.
pub fn seal_witnessed_creation(
    credential: &VerifiedCredential,
    command: &CreateCommand,
    address: &space_service::SpaceAddress,
) -> Result<CreateResponse> {
    let value = json!({"v":2,"kind":"space.created.witnessed","request_id":command.request_id,"host":command.host,"name":command.name,"contact_email":command.contact_email,"message_lifetime_seconds":command.message_lifetime_seconds,"require_approval":command.require_approval,"address":address});
    Ok(CreateResponse {
        ciphertext: STANDARD.encode(crypto::seal_bytes(
            &Zeroizing::new(serde_json::to_vec(&value)?),
            &[credential.recipient()],
            CREATE_LIMIT,
        )?),
    })
}

pub(super) enum HostedCreation {
    Legacy(String),
    Witnessed(space_service::SpaceAddress),
}

impl ClientApp {
    pub fn hosted_create_request(
        &self,
        host: &str,
        request_id: &str,
        name: &str,
        contact_email: &str,
        message_lifetime_seconds: crate::message_retention::MessageRetention,
        require_approval: bool,
    ) -> Result<CreateRequest> {
        let mut request = self.hosted_create_payload(
            host,
            request_id,
            name,
            contact_email,
            message_lifetime_seconds,
            require_approval,
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
        message_lifetime_seconds: crate::message_retention::MessageRetention,
        require_approval: bool,
    ) -> Result<CreateRequest> {
        validate_host(host, self.allow_loopback)?;
        record::hex::<16>(request_id)?;
        if !record::valid_display_name(name) {
            return Err("Enter a Space name.".into());
        }
        space_service::validate_contact_email(contact_email)?;
        space_service::validate_message_lifetime(message_lifetime_seconds)?;
        let command = CreateCommand {
            v: 2,
            kind: "space.create".into(),
            host: host.into(),
            request_id: request_id.into(),
            issued: now()?.as_millis() as u64,
            name: name.into(),
            contact_email: contact_email.into(),
            message_lifetime_seconds,
            require_approval,
            authority: Some(self.owner_general_creation(request_id)?),
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
        message_lifetime_seconds: crate::message_retention::MessageRetention,
        require_approval: bool,
    ) -> Result<HostedCreation> {
        let mut request = self.hosted_create_payload(
            host,
            request_id,
            name,
            contact_email,
            message_lifetime_seconds,
            require_approval,
        )?;
        let command: CreateCommand = decode_record(&request.record)?.decode()?;
        let authority = verify_creation_authority_with_witness(
            &command,
            self.session.credential(),
            self.witness_pin.as_ref(),
        )?
        .ok_or("Missing owner-managed Space authority.")?;
        if self.witness_pin.is_some() {
            self.require_invitation_origin(host)?;
            // Registration may have succeeded before a previous response was lost.
            // A full independently fresh Read reconciles that outcome.
            if self.witness_read_authority(&authority).await.is_err() {
                let registration = self.witness_register_authority(&authority).await;
                let observed = self.witness_read_authority(&authority).await;
                match (registration, observed) {
                    (_, Ok(current)) if current.head_id() == authority.head_id() => (),
                    (Err(error), _) => return Err(error),
                    (_, Err(error)) => return Err(error),
                    _ => return Err("Space creation authority changed.".into()),
                }
            }
        }
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
            || value["message_lifetime_seconds"] != serde_json::to_value(message_lifetime_seconds)?
            || value["require_approval"] != require_approval
        {
            return Err("Unexpected Space hosting response.".into());
        }
        if self.witness_pin.is_some() {
            if value["v"] != 2
                || value["kind"] != "space.created.witnessed"
                || value.get("invitation").is_some()
            {
                return Err("Invalid witnessed Space bootstrap.".into());
            }
            let address: space_service::SpaceAddress =
                serde_json::from_value(value["address"].clone())?;
            address.validate(self.allow_loopback)?;
            self.require_invitation_origin(&address.url)?;
            verify_created_address(&address, &authority)?;
            return Ok(HostedCreation::Witnessed(address));
        }
        let link = field(&value, "invitation")?;
        let invite = space_service::SpaceInvitation::parse(link, self.allow_loopback)?;
        if reqwest::Url::parse(&invite.address.url)?.origin() != reqwest::Url::parse(host)?.origin()
        {
            return Err("Space hosting response changed server.".into());
        }
        verify_created_address(&invite.address, &authority)?;
        Ok(HostedCreation::Legacy(link.into()))
    }
}

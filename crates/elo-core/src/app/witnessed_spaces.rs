//! Native-only short invitation transport and owner-side durable publication.
//! Public storage receives ciphertext and public signatures, never the URL seed.
use super::space_service::SpaceAddress;
use super::*;
use crate::authority::WitnessInvitationPolicy;
use crate::witness::link::{self, Descriptor, InvitationLink, InvitationSeed, VerifiedDescriptor};
use std::time::Duration;

const OFFERS_FILE: &str = "witness-invitations.age";
const OFFERS_BYTES: usize = 16 * 1024 * 1024;
const MAX_TTL_MS: u64 = 7 * 24 * 3_600_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    id: RecordId,
    address: SpaceAddress,
    link: String,
    policy: String,
    ciphertext: String,
    issued_at: u64,
    expires_at: u64,
    require_approval: bool,
    revoked: bool,
    published: bool,
    #[serde(default)]
    hosting_upgrade_pending: bool,
}

impl ClientApp {
    /// The native deployment chooses the endpoint; network invitations cannot.
    pub fn configure_invitation_host(&mut self, host: &str) -> Result<()> {
        super::space_host::validate_host(host, self.allow_loopback)?;
        let mut origin = reqwest::Url::parse(host)?;
        origin.set_path("/");
        self.invitation_api_origin = Some(origin.to_string());
        self.refresh_default_hosting_context();
        Ok(())
    }

    pub(super) fn require_invitation_origin(&self, value: &str) -> Result<()> {
        let expected = reqwest::Url::parse(self.invitation_origin()?)?;
        let actual = reqwest::Url::parse(value)?;
        if actual.origin() != expected.origin()
            || !actual.username().is_empty()
            || actual.password().is_some()
            || actual.fragment().is_some()
            || actual.query().is_some()
        {
            return Err("Invitation server does not match this app.".into());
        }
        Ok(())
    }

    pub(super) fn invitation_origin(&self) -> Result<&str> {
        self.invitation_api_origin
            .as_deref()
            .ok_or_else(|| "Invitation service is unavailable in this build.".into())
    }

    fn invitation_http(&self) -> Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()?)
    }

    pub(super) async fn open_witnessed_invitation(
        &self,
        value: &str,
    ) -> Result<VerifiedDescriptor> {
        let invitation = InvitationLink::parse(value)?;
        let pin = self
            .witness_pin
            .as_ref()
            .ok_or("Invitation service is unavailable in this build.")?;
        let ciphertext = self
            .fetch_witnessed_invitation(&invitation, self.invitation_origin()?)
            .await?;
        Ok(invitation.open(
            &ciphertext,
            self.invitation_origin()?,
            pin,
            now()?.as_millis() as u64,
        )?)
    }

    pub(super) async fn open_hosted_invitation(
        &self,
        invitation: &InvitationLink,
    ) -> Result<(VerifiedDescriptor, crate::hosting_profile::HostingProfile)> {
        let origin = invitation
            .hosting_origin()
            .ok_or("Invalid Space invitation.")?;
        let ciphertext = self.fetch_witnessed_invitation(invitation, origin).await?;
        Ok(invitation.open_with_embedded_hosting(&ciphertext, now()?.as_millis() as u64)?)
    }

    async fn fetch_witnessed_invitation(
        &self,
        invitation: &InvitationLink,
        origin: &str,
    ) -> Result<Vec<u8>> {
        // Only the ciphertext digest reaches the host. The seed, profile and
        // current user's credentials never accompany this unauthenticated GET.
        let endpoint = reqwest::Url::parse(origin)?
            .join(&format!("invitations/v1/{}", invitation.ciphertext_id()))?;
        let mut response = self
            .invitation_http()?
            .get(endpoint)
            .send()
            .await
            .map_err(super::space_service::space_transport_error)?;
        if !response.status().is_success() {
            return Err(super::space_service::space_status_error(response.status()).into());
        }
        let mut ciphertext = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if ciphertext.len().saturating_add(chunk.len()) > link::MAX_CIPHERTEXT_BYTES {
                return Err("Invitation is too large.".into());
            }
            ciphertext.extend_from_slice(&chunk);
        }
        Ok(ciphertext)
    }

    fn witnessed_offers(&self) -> Result<Vec<Offer>> {
        let path = self.directory.join(OFFERS_FILE);
        if !path.try_exists()? {
            return Ok(Vec::new());
        }
        let encrypted = read_exchange(&path, OFFERS_BYTES * 2)?;
        let plain = Zeroizing::new(crypto::open_bytes(
            &encrypted,
            self.session.age_identity(),
            OFFERS_BYTES,
        )?);
        let offers: Vec<Offer> = serde_json::from_slice(&plain)?;
        if offers.len() > 64 {
            return Err("Too many saved invitations.".into());
        }
        Ok(offers)
    }

    fn save_witnessed_offers(&self, offers: &[Offer]) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(offers)?);
        if offers.len() > 64 || plain.len() > OFFERS_BYTES {
            return Err("Too many saved invitations.".into());
        }
        let encrypted = crypto::seal_bytes(
            &plain,
            &[self.session.credential().recipient()],
            OFFERS_BYTES,
        )?;
        vault::write_private(&self.directory.join(OFFERS_FILE), &encrypted, true)?;
        Ok(())
    }

    pub(super) fn witnessed_offer_list(&self, address: &SpaceAddress) -> Result<Value> {
        let current = now()?.as_millis() as u64;
        Ok(json!(self.witnessed_offers()?.iter().filter(|offer| offer.address.scope.space == address.scope.space
            && offer.published && offer.expires_at > current).map(|offer| json!({
                "id":offer.id,"link":offer.link,"issued_at":offer.issued_at,
                "expires_at":offer.expires_at,"require_approval":offer.require_approval,"revoked":offer.revoked
            })).collect::<Vec<_>>()))
    }

    pub(super) async fn mint_witnessed_invitation(
        &mut self,
        authority: &Authority,
        address: &SpaceAddress,
        name: &str,
        lifetime: u64,
        require_approval: bool,
    ) -> Result<String> {
        self.require_invitation_origin(&address.url)?;
        let ttl = lifetime
            .checked_mul(1000)
            .filter(|ttl| *ttl > 0 && *ttl <= MAX_TTL_MS)
            .ok_or("Choose an invitation lifetime of at most 7 days.")?;
        let authority = self.witness_read_authority(authority).await?;
        let pin = self.trusted_witness(&authority)?.clone();
        let current = now()?.as_millis() as u64;
        let mut offers = self.witnessed_offers()?;
        offers.retain(|offer| offer.expires_at > current);
        // An uncertain publish outcome reuses its exact policy, seed and ciphertext.
        let pending = offers.iter().position(|offer| {
            !offer.published
                && !offer.revoked
                && offer.address.scope.space == address.scope.space
                && offer.require_approval == require_approval
                && offer.expires_at.saturating_sub(offer.issued_at) == ttl
        });
        let index = if let Some(index) = pending {
            index
        } else {
            if offers
                .iter()
                .filter(|offer| offer.address.scope.space == address.scope.space)
                .count()
                >= 8
            {
                return Err(
                    "Too many active invitations. Wait for an existing invitation to expire."
                        .into(),
                );
            }
            let seed = InvitationSeed::generate()?;
            let invitation_public_key =
                record::encode_hex(seed.invitation_public_key()?.as_bytes());
            let policy = WitnessInvitationPolicy {
                v: 1,
                kind: "witness.invitation".into(),
                nonce: record::random_hex::<16>()?,
                space_id: authority.space(),
                stream_id: authority.stream(),
                authority_head: authority.head_id().ok_or("General unavailable.")?,
                issuer_credential_id: self.session.credential().id(),
                invitation_public_key: invitation_public_key.clone(),
                not_before_ms: current,
                expires_at_ms: current.checked_add(ttl).ok_or("Invalid expiry.")?,
                require_approval,
                max_uses: 128,
                witness_key_generation: pin.key_generation,
            };
            let signed =
                SignedRecord::sign(&serde_json::to_vec(&policy)?, self.session.signing_key())?;
            let descriptor = Descriptor {
                v: 1,
                kind: "witness.invitation.descriptor".into(),
                name: name.into(),
                hosting_profile: self.hosting_services.active.clone(),
                address: address.clone(),
                witness: pin.clone(),
                proof: authority.call_proof()?,
                policy: STANDARD.encode(signed.bytes()),
                invitation_public_key,
            };
            let encrypted = link::seal(
                &descriptor,
                self.session.signing_key(),
                seed,
                self.invitation_origin()?,
                &pin,
                current,
            )?;
            let invitation_link = match self.current_hosting_id() {
                Some(id) => encrypted
                    .link
                    .with_hosting_origin(&id, self.invitation_origin()?)?,
                None => encrypted.link,
            };
            offers.push(Offer {
                id: signed.id(),
                address: address.clone(),
                link: invitation_link.to_url().to_string(),
                policy: STANDARD.encode(signed.bytes()),
                ciphertext: STANDARD.encode(&encrypted.ciphertext),
                issued_at: current,
                expires_at: policy.expires_at_ms,
                require_approval,
                revoked: false,
                published: false,
                hosting_upgrade_pending: false,
            });
            self.save_witnessed_offers(&offers)?;
            offers.len() - 1
        };
        let offer = &offers[index];
        self.witness_register_invitation(&authority, &decode_record(&offer.policy)?)
            .await?;
        // A fresh proof is also imported into hosting before its upload gate.
        self.sync_witnessed_host(address, &authority).await?;
        self.publish_witnessed_offer(&authority, offer).await?;
        offers[index].published = true;
        offers[index].hosting_upgrade_pending = false;
        self.save_witnessed_offers(&offers)?;
        Ok(offers[index].link.clone())
    }

    /// Repackage a saved invitation without changing its admission policy, expiry
    /// or use budget. Previously distributed links remain valid until expiry.
    pub(super) async fn upgrade_witnessed_offers(
        &mut self,
        authority: &Authority,
        address: &SpaceAddress,
    ) -> Result<()> {
        let Some(profile) = self.hosting_services.active.clone() else {
            return Ok(());
        };
        let current = now()?.as_millis() as u64;
        let mut offers = self.witnessed_offers()?;
        for index in 0..offers.len() {
            let offer = &offers[index];
            if offer.revoked
                || offer.expires_at <= current
                || offer.address.scope.space != address.scope.space
                || (!offer.published && !offer.hosting_upgrade_pending)
            {
                continue;
            }
            let policy_record = decode_record(&offer.policy)?;
            let Ok(policy) = authority.verify_witness_invitation(&policy_record, current) else {
                continue;
            };
            if policy.issuer_credential_id != self.session.credential().id() {
                continue;
            }
            let link = InvitationLink::parse(&offer.link)?;
            if link.hosting_origin().is_none() {
                let upgraded = link.reseal_with_hosting(
                    &STANDARD.decode(&offer.ciphertext)?,
                    &profile,
                    self.session.signing_key(),
                    self.invitation_origin()?,
                    &profile.witness,
                    current,
                )?;
                offers[index].link = upgraded.link.to_url().to_string();
                offers[index].ciphertext = STANDARD.encode(&upgraded.ciphertext);
                offers[index].published = false;
                offers[index].hosting_upgrade_pending = true;
                // Persist before I/O so an uncertain upload retries the same
                // ciphertext rather than consuming another descriptor slot.
                self.save_witnessed_offers(&offers)?;
            }
            if !offers[index].published {
                self.publish_witnessed_offer(authority, &offers[index])
                    .await?;
                offers[index].published = true;
                offers[index].hosting_upgrade_pending = false;
                self.save_witnessed_offers(&offers)?;
            }
        }
        Ok(())
    }

    async fn publish_witnessed_offer(&self, authority: &Authority, offer: &Offer) -> Result<()> {
        let address = &offer.address;
        let invitation = InvitationLink::parse(&offer.link)?;
        let mut endpoint = reqwest::Url::parse(&address.url)?;
        let prefix = endpoint
            .path()
            .strip_suffix("/team/v1/spaces")
            .ok_or("Invalid Space address.")?;
        endpoint.set_path(&format!("{prefix}/invitations/v1"));
        let issued = now()?.as_millis() as u64;
        let ciphertext = STANDARD.decode(&offer.ciphertext)?;
        let command = json!({"v":1,"kind":"invitation.descriptor.put","nonce":record::random_hex::<32>()?,
            "audience":endpoint.as_str(),"space_id":authority.space(),"stream_id":authority.stream(),
            "authority_head":authority.head_id(),"credential_id":self.session.credential().id(),"policy_id":offer.id,
            "ciphertext_id":invitation.ciphertext_id(),"ciphertext_size":ciphertext.len(),
            "ciphertext_expires_at_ms":offer.expires_at,"issued_at_ms":issued,"expires_at_ms":issued+60_000});
        let command =
            SignedRecord::sign(&serde_json::to_vec(&command)?, self.session.signing_key())?;
        let mut response = self
            .invitation_http()?
            .post(endpoint)
            .json(&json!({"command":STANDARD.encode(command.bytes()),
            "policy":offer.policy,"ciphertext":offer.ciphertext}))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(super::space_service::space_status_error(response.status()).into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > 4096 {
                return Err("Invalid invitation response.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let ack: Value = serde_json::from_slice(&bytes)?;
        if ack["v"] != 1
            || ack["ciphertext_id"] != invitation.ciphertext_id()
            || ack["ciphertext_expires_at_ms"] != offer.expires_at
        {
            return Err("Invalid invitation response.".into());
        }
        Ok(())
    }

    pub(super) async fn revoke_witnessed_offer(
        &mut self,
        authority: &Authority,
        id: RecordId,
    ) -> Result<()> {
        let current = self.witness_read_authority(authority).await?;
        self.witness_revoke_invitation(&current, id).await?;
        let mut offers = self.witnessed_offers()?;
        if let Some(offer) = offers.iter_mut().find(|offer| offer.id == id) {
            offer.revoked = true;
        }
        self.save_witnessed_offers(&offers)
    }

    pub(super) fn verify_witnessed_relay_request(
        &self,
        authority: &Authority,
        address: &SpaceAddress,
        packet: &super::witness_durable_admission::DurableAdmissionRequest,
        selected: RecordId,
    ) -> Result<String> {
        let credential = decode_record(&packet.credential)?;
        let credential = VerifiedCredential::verify(
            credential.bytes(),
            &root_key(field(credential.body(), "root_public_key")?)?,
        )?;
        let request = authority.verify_witness_join_request(
            &packet.request,
            &credential,
            now()?.as_millis() as u64,
        )?;
        if packet.request_id != selected
            || decode_record(&packet.request.device_request)?.id() != selected
            || packet.expires_at_ms != request.expires_at_ms
            || serde_json::to_value(&packet.address)? != serde_json::to_value(address)?
        {
            return Err("Invalid admission request.".into());
        }
        let contact = decode_record(&packet.request.contact)?;
        Ok(field(contact.body(), "name")?.into())
    }

    pub(super) async fn sync_witnessed_host(
        &self,
        address: &SpaceAddress,
        authority: &Authority,
    ) -> Result<Value> {
        self.trusted_witness(authority)?;
        self.require_invitation_origin(&address.url)?;
        let enrollment = self.team_enrollment_request(&address.scope)?;
        let response = self
            .call_space(
                address,
                "witness_sync",
                json!({"proof":authority.call_proof()?,"enrollment":enrollment}),
            )
            .await?;
        if response["status"] != "approved"
            || response["general_head"] != json!(authority.head_id())
            || response["enrollment"]["v"] != 2
        {
            return Err("Invalid witnessed Space enrollment.".into());
        }
        let packet = STANDARD.decode(field(&response["enrollment"], "packet")?)?;
        let packet: Value = serde_json::from_slice(&packet)?;
        let proof = serde_json::from_value(packet["proof"].clone())?;
        let enrolled = self.verify_general_proof(&proof, authority.space(), authority.stream())?;
        if enrolled.head_id() != authority.head_id() || enrolled.is_forked() {
            return Err("Invalid witnessed Space enrollment.".into());
        }
        self.fetch_witness_freshness(&enrolled, std::time::Instant::now())
            .await?;
        Ok(response)
    }
}

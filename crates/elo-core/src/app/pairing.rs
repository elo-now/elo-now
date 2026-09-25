//! Explicit one-use, expiring companion-profile exchange over an untrusted Replica.
//! QR capabilities are scoped to one temporary mailbox; profile bytes are age encrypted.
use super::*;
use crate::{
    ids::ObjectId,
    replica::{ChildMailbox, MailboxDescriptor, TransferHint},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
pub const PREFIX: &str = "elo-pair:3:";
const LIFETIME: u64 = 10 * 60 * 1000;
const CHUNK: usize = 2 * 1024 * 1024;
const INTERRUPTED: &str = "Device linking was interrupted. Create a new code.";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    version: u8,
    nonce: String,
    expires: u64,
    identity: IdentityId,
    recipient: String,
    mailbox: PeerDescriptor,
    #[serde(default)]
    access: Option<String>,
    auth_key: String,
}
impl Drop for Offer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.auth_key.zeroize();
        self.access.zeroize();
        self.mailbox.read_token.zeroize();
        self.mailbox.write_token.zeroize();
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    kind: String,
    offer: String,
    nonce: String,
    name: String,
    recipient: String,
    authentication: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    kind: String,
    request: String,
    identity: IdentityId,
    secret: String,
    size: usize,
    digest: String,
    chunks: Vec<(ObjectId, u64)>,
    profile_password: Option<String>,
    authentication: String,
}
impl Drop for Response {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
        self.profile_password.zeroize();
    }
}

pub struct PairSource {
    offer: Offer,
    key: age::x25519::Identity,
    peer: Peer,
    cursor: u64,
    requests: BTreeMap<String, Request>,
    interrupted: bool,
    approved: Option<String>,
    response: Option<Vec<u8>>,
    upload: Vec<Vec<u8>>,
    device: Option<Session>,
}
pub struct PairTarget {
    offer: Offer,
    request: Request,
    key: age::x25519::Identity,
    peer: Peer,
    cursor: u64,
    response: Option<Response>,
    request_bytes: Vec<u8>,
    allow_loopback: bool,
    finished: bool,
}

fn time() -> Result<u64> {
    Ok(now()?.as_millis() as u64)
}
fn live(offer: &Offer) -> Result<()> {
    let now = time()?;
    if offer.version != 3 || offer.expires <= now || offer.expires > now + LIFETIME {
        return Err("This device code has expired. Create a new one".into());
    }
    Ok(())
}
fn authentication(offer: &Offer, payload: &impl Serialize) -> Result<String> {
    let key = Zeroizing::new(record::hex::<32>(&offer.auth_key)?);
    let mut mac = Hmac::<Sha256>::new_from_slice(&*key)?;
    mac.update(&Zeroizing::new(serde_json::to_vec(payload)?));
    Ok(record::encode_hex(&mac.finalize().into_bytes()))
}
fn authenticated(offer: &Offer, payload: &impl Serialize, proof: &str) -> bool {
    let Ok(bytes) = record::hex::<32>(proof) else {
        return false;
    };
    let Ok(key) = record::hex::<32>(&offer.auth_key) else {
        return false;
    };
    let key = Zeroizing::new(key);
    let Ok(payload) = serde_json::to_vec(payload) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(&*key).expect("fixed HMAC key");
    mac.update(&Zeroizing::new(payload));
    mac.verify_slice(&bytes).is_ok()
}
impl Request {
    fn payload(&self) -> impl Serialize + '_ {
        (
            "elo.now/pair-request/v3",
            &self.offer,
            &self.nonce,
            &self.name,
            &self.recipient,
        )
    }
}
impl Response {
    fn payload(&self) -> impl Serialize + '_ {
        (
            "elo.now/pair-response/v3",
            &self.request,
            self.identity,
            &self.secret,
            self.size,
            &self.digest,
            &self.chunks,
            &self.profile_password,
        )
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rejection {
    request: String,
    authentication: String,
}
fn code(offer: &Offer, request: &Request) -> Result<String> {
    let bytes = serde_json::to_vec(&("elo.now/pair-code/v2", offer, request))?;
    let hash = Sha256::digest(&bytes);
    // Full 128-bit comparison prevents an observer from grinding a matching
    // requester-controlled nonce as they could with a six-digit code.
    Ok(hash[..16]
        .chunks_exact(2)
        .map(record::encode_hex)
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase())
}
async fn post(peer: &Peer, bytes: Vec<u8>) -> Result<()> {
    peer.post(ObjectId::of_ciphertext(&bytes), bytes, TransferHint::Eager)
        .await?;
    Ok(())
}

impl PairSource {
    pub async fn new(app: &ClientApp) -> Result<Self> {
        if app.session.credential().authorizing_device().is_some() {
            return Err("Link another device from your original device.".into());
        }
        let transport = match &app.spaces {
            Some(spaces) => spaces.pairing_client(app),
            None => Some(app),
        }
        .ok_or("Connect to a Space before linking a device.")?;
        let parent = transport
            .session
            .peers()
            .iter()
            .find(|peer| peer.write_token.is_some())
            .ok_or("Connect to a Space before linking a device.")?
            .clone();
        let expires = time()? + LIFETIME;
        let child = ChildMailbox {
            descriptor: MailboxDescriptor::random()?,
            quota_bytes: 128 * 1024 * 1024,
            expires_at: expires,
        };
        Peer::new(parent.clone(), app.allow_loopback)?
            .with_identity(&transport.session)
            .create_child(&child)
            .await?;
        let mailbox = PeerDescriptor {
            mailbox_id: child.descriptor.mailbox_id,
            read_token: Some(child.descriptor.read_token),
            write_token: Some(child.descriptor.write_token),
            ..parent
        };
        let key = age::x25519::Identity::generate();
        let offer = Offer {
            version: 3,
            nonce: record::random_hex::<32>()?,
            expires,
            identity: app.identity_id(),
            recipient: key.to_public().to_string(),
            auth_key: record::random_hex::<32>()?,
            access: Peer::new(mailbox.clone(), app.allow_loopback)?
                .with_identity(&transport.session)
                .pairing_access()?
                .map(|encoded| -> Result<String> {
                    Ok(String::from_utf8(URL_SAFE_NO_PAD.decode(encoded)?)?)
                })
                .transpose()?,
            mailbox,
        };
        Ok(Self {
            peer: Peer::new(offer.mailbox.clone(), app.allow_loopback)?
                .with_identity(&transport.session),
            offer,
            key,
            cursor: 0,
            requests: BTreeMap::new(),
            interrupted: false,
            approved: None,
            response: None,
            upload: Vec::new(),
            device: None,
        })
    }
    pub fn link(&self) -> Result<String> {
        live(&self.offer)?;
        if self.interrupted {
            return Err(INTERRUPTED.into());
        }
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&Zeroizing::new(serde_json::to_vec(&self.offer)?))?;
        let packed = Zeroizing::new(encoder.finish()?);
        Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&*packed)))
    }
    pub fn expires_at(&self) -> u64 {
        self.offer.expires
    }
    pub async fn poll(&mut self) -> Result<Value> {
        live(&self.offer)?;
        if self.interrupted {
            return Err(INTERRUPTED.into());
        }
        if self.approved.is_none() {
            let page = self.peer.inventory(self.cursor).await?;
            // Never show an approvable first request while silently ignoring
            // contenders later in an oversized page.
            if page.entries.len() > 16 {
                self.interrupted = true;
                self.requests.clear();
                return Err(INTERRUPTED.into());
            }
            for entry in page.entries.into_iter().take(16) {
                if entry.size_bytes <= 8192 {
                    let bytes = self.peer.get(entry.object_id, entry.size_bytes).await?;
                    if let Ok(plain) = crypto::open_bytes(&bytes, &self.key, 4096) {
                        let plain = Zeroizing::new(plain);
                        if let Ok(request) = serde_json::from_slice::<Request>(&plain)
                            && request.kind == "elo.now/pair-request/v1"
                            && request.offer == self.offer.nonce
                            && record::hex::<32>(&request.nonce).is_ok()
                            && record::valid_display_name(&request.name)
                            && request.recipient.parse::<age::x25519::Recipient>().is_ok()
                            && authenticated(
                                &self.offer,
                                &request.payload(),
                                &request.authentication,
                            )
                        {
                            if self.requests.values().any(|existing| existing != &request) {
                                self.interrupted = true;
                                self.requests.clear();
                                return Err(INTERRUPTED.into());
                            }
                            self.requests
                                .entry(request.nonce.clone())
                                .or_insert(request);
                        }
                    }
                }
                self.cursor = entry.arrival_seq;
            }
        }
        let requests = self
            .requests
            .values()
            .map(|r| Ok(json!({"id":r.nonce,"name":r.name,"code":code(&self.offer,r)?})))
            .collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"requests":requests,"approved":self.approved,"expires":self.offer.expires,
            "credential":self.device.as_ref().map(|device| STANDARD.encode(device.credential().record().bytes())),
            "device_id":self.device.as_ref().map(|device| device.credential().id())}),
        )
    }
    pub async fn approve(
        &mut self,
        app: &ClientApp,
        id: &str,
        confirmed_code: &str,
        card: &RecoveryCard,
    ) -> Result<()> {
        self.approve_inner(app, id, confirmed_code, Some(card))
            .await
    }
    pub async fn accept(&mut self, app: &ClientApp, id: &str) -> Result<()> {
        let request = self.requests.get(id).ok_or("Device request not found")?;
        let confirmed_code = code(&self.offer, request)?;
        self.approve_inner(app, id, &confirmed_code, None).await
    }
    pub async fn reject(&mut self, id: &str) -> Result<()> {
        live(&self.offer)?;
        if self.approved.is_some() {
            return Err("This device code has already been used".into());
        }
        let request = self.requests.get(id).ok_or("Device request not found")?;
        let rejected = Rejection {
            request: id.into(),
            authentication: authentication(&self.offer, &("elo.now/pair-rejected/v3", id))?,
        };
        post(
            &self.peer,
            crypto::seal_bytes(
                &Zeroizing::new(serde_json::to_vec(&rejected)?),
                &[request.recipient.parse()?],
                4096,
            )?,
        )
        .await?;
        self.interrupted = true;
        self.requests.clear();
        Ok(())
    }
    async fn approve_inner(
        &mut self,
        app: &ClientApp,
        id: &str,
        confirmed_code: &str,
        card: Option<&RecoveryCard>,
    ) -> Result<()> {
        live(&self.offer)?;
        if self.interrupted {
            return Err(INTERRUPTED.into());
        }
        if self.approved.is_none() {
            // Recheck immediately before releasing any profile bytes, including
            // requests arriving after the user opened the confirmation form.
            self.poll().await?;
        }
        if self
            .approved
            .as_deref()
            .is_some_and(|previous| previous != id)
        {
            return Err("This code has already been used for another device".into());
        }
        let request = self.requests.get(id).ok_or("Device request not found")?;
        if code(&self.offer, request)? != confirmed_code {
            return Err("Compare and confirm the code on both devices".into());
        }
        if app.identity_id() != self.offer.identity {
            return Err("The open profile changed".into());
        }
        // Bind before the first upload. A retry can never release a second profile.
        self.approved = Some(id.into());
        if self.response.is_none() {
            let secret = record::random_hex::<32>()?;
            if self.device.is_none() {
                self.device = Some(match card {
                    Some(card) => app.session.companion(card)?,
                    None => app.session.linked_companion()?,
                });
            }
            let device = self.device.as_ref().ok_or("Missing pairing device")?;
            app.remember_device(device.credential(), &request.name)?;
            let backup = Zeroizing::new(
                app.export_device_copy(secret.clone().into(), device)
                    .await?,
            );
            let chunks = backup
                .chunks(CHUNK)
                .map(|bytes| (ObjectId::of_ciphertext(bytes), bytes.len() as u64))
                .collect();
            let mut response = Response {
                kind: "elo.now/pair-response/v1".into(),
                request: id.into(),
                identity: self.offer.identity,
                secret,
                size: backup.len(),
                digest: record::encode_hex(&Sha256::digest(&*backup)),
                chunks,
                profile_password: card
                    .is_none()
                    .then(|| app.password.expose_secret().to_owned()),
                authentication: String::new(),
            };
            let mac = authentication(&self.offer, &response.payload())?;
            response.authentication = mac;
            let plain = Zeroizing::new(serde_json::to_vec(&response)?);
            self.response = Some(crypto::seal_bytes(
                &plain,
                &[request.recipient.parse()?],
                32 * 1024,
            )?);
            // Freeze every ciphertext before uploading. Lost acknowledgements can
            // retry the exact object IDs without consuming the mailbox again.
            self.upload = backup.chunks(CHUNK).map(<[u8]>::to_vec).collect();
        }
        for bytes in &self.upload {
            post(&self.peer, bytes.clone()).await?;
        }
        post(
            &self.peer,
            self.response
                .as_ref()
                .ok_or("Missing pairing response")?
                .clone(),
        )
        .await
    }
}

impl PairTarget {
    pub fn new(link: &str, name: &str, allow_loopback: bool) -> Result<Self> {
        if link.len() > 16_384 || !record::valid_display_name(name.trim()) {
            return Err("Invalid device code or name".into());
        }
        let bytes = URL_SAFE_NO_PAD.decode(
            link.trim()
                .strip_prefix(PREFIX)
                .ok_or("Scan a device-linking code, not a public contact code")?,
        )?;
        let mut plain = Zeroizing::new(Vec::new());
        flate2::read::ZlibDecoder::new(bytes.as_slice())
            .take(12_289)
            .read_to_end(&mut plain)
            .map_err(|_| "Invalid device code")?;
        if plain.len() > 12_288 {
            return Err("Invalid device code".into());
        }
        let offer: Offer = serde_json::from_slice(&plain).map_err(|_| "Invalid device code")?;
        live(&offer)?;
        record::hex::<32>(&offer.nonce)?;
        record::hex::<32>(&offer.auth_key)?;
        let recipient = offer.recipient.parse::<age::x25519::Recipient>()?;
        let peer = Peer::new(offer.mailbox.clone(), allow_loopback)?.with_delegated_access(
            offer
                .access
                .as_ref()
                .map(|json| URL_SAFE_NO_PAD.encode(json.as_bytes())),
        );
        let key = age::x25519::Identity::generate();
        let mut request = Request {
            kind: "elo.now/pair-request/v1".into(),
            offer: offer.nonce.clone(),
            nonce: record::random_hex::<32>()?,
            name: name.trim().into(),
            recipient: key.to_public().to_string(),
            authentication: String::new(),
        };
        let mac = authentication(&offer, &request.payload())?;
        request.authentication = mac;
        let plain = Zeroizing::new(serde_json::to_vec(&request)?);
        let request_bytes = crypto::seal_bytes(&plain, &[recipient], 4096)?;
        Ok(Self {
            offer,
            request,
            key,
            peer,
            cursor: 0,
            response: None,
            request_bytes,
            allow_loopback,
            finished: false,
        })
    }
    pub fn summary(&self) -> Result<Value> {
        live(&self.offer)?;
        Ok(
            json!({"identity":self.offer.identity,"code":code(&self.offer,&self.request)?,"ready":self.response.is_some()}),
        )
    }
    pub async fn send(&self) -> Result<()> {
        live(&self.offer)?;
        post(&self.peer, self.request_bytes.clone()).await
    }
    pub async fn poll(&mut self) -> Result<Value> {
        live(&self.offer)?;
        if self.response.is_none() {
            let page = self.peer.inventory(self.cursor).await?;
            for entry in page.entries.into_iter().take(128) {
                if entry.size_bytes <= 48 * 1024 {
                    let bytes = self.peer.get(entry.object_id, entry.size_bytes).await?;
                    if let Ok(plain) = crypto::open_bytes(&bytes, &self.key, 32 * 1024) {
                        let plain = Zeroizing::new(plain);
                        if let Ok(rejected) = serde_json::from_slice::<Rejection>(&plain)
                            && rejected.request == self.request.nonce
                            && authenticated(
                                &self.offer,
                                &("elo.now/pair-rejected/v3", &rejected.request),
                                &rejected.authentication,
                            )
                        {
                            return Err("Device linking was declined.".into());
                        }
                        if let Ok(response) = serde_json::from_slice::<Response>(&plain)
                            && response.kind == "elo.now/pair-response/v1"
                            && response.request == self.request.nonce
                            && response.identity == self.offer.identity
                            && authenticated(
                                &self.offer,
                                &response.payload(),
                                &response.authentication,
                            )
                            && response
                                .profile_password
                                .as_ref()
                                .is_none_or(|password| (12..=1024).contains(&password.len()))
                            && record::hex::<32>(&response.secret).is_ok()
                            && record::hex::<32>(&response.digest).is_ok()
                            && (1..=48).contains(&response.chunks.len())
                            && response.size <= profile_backup::MAX_BACKUP
                            && response
                                .chunks
                                .iter()
                                .all(|(_, size)| *size > 0 && *size <= CHUNK as u64)
                            && response.chunks.iter().map(|(_, size)| *size).sum::<u64>()
                                == response.size as u64
                        {
                            self.response = Some(response);
                        }
                    }
                }
                self.cursor = entry.arrival_seq;
            }
        }
        self.summary()
    }
    pub async fn finish(
        &mut self,
        directory: PathBuf,
        password: SecretString,
        confirmed_code: &str,
    ) -> Result<ClientApp> {
        live(&self.offer)?;
        if self.finished {
            return Err("This device code has already been used".into());
        }
        if code(&self.offer, &self.request)? != confirmed_code {
            return Err("Compare and confirm the code on both devices".into());
        }
        let response = self
            .response
            .as_ref()
            .ok_or("Approve this device on your other device first")?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(response.size));
        for (object, size) in &response.chunks {
            bytes.extend(self.peer.get(*object, *size).await?);
        }
        if bytes.len() != response.size
            || record::encode_hex(&Sha256::digest(&*bytes)) != response.digest
        {
            return Err("The profile transfer is incomplete".into());
        }
        let app = ClientApp::restore_profile(
            directory,
            &bytes,
            response.secret.clone().into(),
            response.identity,
            password,
            self.allow_loopback,
        )
        .await?;
        self.finished = true;
        self.response = None;
        Ok(app)
    }
    pub async fn finish_linked(&mut self, directory: PathBuf) -> Result<ClientApp> {
        let password = self
            .response
            .as_ref()
            .and_then(|response| response.profile_password.as_ref())
            .ok_or("Approve this device on your other device first")?
            .clone()
            .into();
        let code = code(&self.offer, &self.request)?;
        self.finish(directory, password, &code).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qr_secret_authenticates_both_parties_and_every_transfer_field() {
        let mailbox = MailboxDescriptor::random().unwrap();
        let mut offer = Offer {
            version: 3,
            nonce: "11".repeat(32),
            expires: time().unwrap() + LIFETIME,
            identity: IdentityId::from_bytes([1; 32]),
            recipient: age::x25519::Identity::generate().to_public().to_string(),
            auth_key: "22".repeat(32),
            access: None,
            mailbox: PeerDescriptor {
                url: "https://replica.example.test".into(),
                signing_public_key: "33".repeat(32),
                mailbox_id: mailbox.mailbox_id,
                read_token: Some(mailbox.read_token),
                write_token: Some(mailbox.write_token),
            },
        };
        let mut request = Request {
            kind: "elo.now/pair-request/v1".into(),
            offer: offer.nonce.clone(),
            nonce: "44".repeat(32),
            name: "Test phone".into(),
            recipient: age::x25519::Identity::generate().to_public().to_string(),
            authentication: String::new(),
        };
        let proof = authentication(&offer, &request.payload()).unwrap();
        assert!(authenticated(&offer, &request.payload(), &proof));
        request.recipient = offer.recipient.clone();
        assert!(!authenticated(&offer, &request.payload(), &proof));
        let mut response = Response {
            kind: "elo.now/pair-response/v1".into(),
            request: request.nonce.clone(),
            identity: offer.identity,
            secret: "55".repeat(32),
            size: 3,
            digest: "66".repeat(32),
            chunks: vec![(ObjectId::of_ciphertext(b"abc"), 3)],
            profile_password: Some("fictional profile password".into()),
            authentication: String::new(),
        };
        let proof = authentication(&offer, &response.payload()).unwrap();
        assert!(authenticated(&offer, &response.payload(), &proof));
        response.profile_password = Some("substituted password".into());
        assert!(!authenticated(&offer, &response.payload(), &proof));
        response.profile_password = Some("fictional profile password".into());
        response.chunks[0].1 = 4;
        assert!(!authenticated(&offer, &response.payload(), &proof));
        response.chunks[0].1 = 3;
        offer.auth_key = "77".repeat(32);
        assert!(!authenticated(&offer, &response.payload(), &proof));
        assert!(!authenticated(
            &offer,
            &("elo.now/pair-rejected/v3", &request.nonce),
            &proof
        ));
    }
}

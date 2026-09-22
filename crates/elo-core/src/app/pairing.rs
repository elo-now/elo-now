//! Explicit one-use, expiring companion-profile exchange over an untrusted Replica.
//! QR capabilities are scoped to one temporary mailbox; profile bytes are age encrypted.
use super::*;
use crate::{
    ids::ObjectId,
    replica::{ChildMailbox, MailboxDescriptor, TransferHint},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
pub const PREFIX: &str = "elo-pair:1:";
const LIFETIME: u64 = 10 * 60 * 1000;
const CHUNK: usize = 2 * 1024 * 1024;

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
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    kind: String,
    offer: String,
    nonce: String,
    name: String,
    recipient: String,
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
}
impl Drop for Response {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

pub struct PairSource {
    offer: Offer,
    key: age::x25519::Identity,
    peer: Peer,
    cursor: u64,
    requests: BTreeMap<String, Request>,
    approved: Option<String>,
    response: Option<Vec<u8>>,
    upload: Vec<Vec<u8>>,
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
    if offer.version != 1 || offer.expires <= now || offer.expires > now + LIFETIME {
        return Err("This device code has expired. Create a new one".into());
    }
    Ok(())
}
fn code(offer: &Offer, request: &Request) -> Result<String> {
    let bytes = serde_json::to_vec(&("elo.now/pair-code/v1", offer, request))?;
    let hash = Sha256::digest(&bytes);
    let n = u32::from_be_bytes(hash[..4].try_into()?) % 1_000_000;
    Ok(format!("{:03} {:03}", n / 1000, n % 1000))
}
async fn post(peer: &Peer, bytes: Vec<u8>) -> Result<()> {
    peer.post(ObjectId::of_ciphertext(&bytes), bytes, TransferHint::Eager)
        .await?;
    Ok(())
}

impl PairSource {
    pub async fn new(app: &ClientApp) -> Result<Self> {
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
            version: 1,
            nonce: record::random_hex::<32>()?,
            expires,
            identity: app.identity_id(),
            recipient: key.to_public().to_string(),
            access: Peer::new(mailbox.clone(), app.allow_loopback)?
                .with_identity(&transport.session)
                .pairing_access()?,
            mailbox,
        };
        Ok(Self {
            peer: Peer::new(offer.mailbox.clone(), app.allow_loopback)?
                .with_identity(&transport.session),
            offer,
            key,
            cursor: 0,
            requests: BTreeMap::new(),
            approved: None,
            response: None,
            upload: Vec::new(),
        })
    }
    pub fn link(&self) -> Result<String> {
        live(&self.offer)?;
        Ok(format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.offer)?)
        ))
    }
    pub fn expires_at(&self) -> u64 {
        self.offer.expires
    }
    pub async fn poll(&mut self) -> Result<Value> {
        live(&self.offer)?;
        if self.approved.is_none() {
            let page = self.peer.inventory(self.cursor).await?;
            for entry in page.entries.into_iter().take(16) {
                if entry.size_bytes <= 8192 && self.requests.len() < 8 {
                    let bytes = self.peer.get(entry.object_id, entry.size_bytes).await?;
                    if let Ok(plain) = crypto::open_bytes(&bytes, &self.key, 4096) {
                        let plain = Zeroizing::new(plain);
                        if let Ok(request) = serde_json::from_slice::<Request>(&plain)
                            && request.kind == "elo.now/pair-request/v1"
                            && request.offer == self.offer.nonce
                            && record::hex::<32>(&request.nonce).is_ok()
                            && record::valid_display_name(&request.name)
                            && request.recipient.parse::<age::x25519::Recipient>().is_ok()
                        {
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
        Ok(json!({"requests":requests,"approved":self.approved,"expires":self.offer.expires}))
    }
    pub async fn approve(&mut self, app: &ClientApp, id: &str, confirmed_code: &str) -> Result<()> {
        live(&self.offer)?;
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
            let backup = Zeroizing::new(app.export_device_copy(secret.clone().into()).await?);
            let chunks = backup
                .chunks(CHUNK)
                .map(|bytes| (ObjectId::of_ciphertext(bytes), bytes.len() as u64))
                .collect();
            let response = Response {
                kind: "elo.now/pair-response/v1".into(),
                request: id.into(),
                identity: self.offer.identity,
                secret,
                size: backup.len(),
                digest: record::encode_hex(&Sha256::digest(&*backup)),
                chunks,
            };
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
        if link.len() > 4096 || !record::valid_display_name(name.trim()) {
            return Err("Invalid device code or name".into());
        }
        let bytes = URL_SAFE_NO_PAD.decode(
            link.trim()
                .strip_prefix(PREFIX)
                .ok_or("Scan a device-linking code, not a public contact code")?,
        )?;
        let offer: Offer = serde_json::from_slice(&bytes).map_err(|_| "Invalid device code")?;
        live(&offer)?;
        record::hex::<32>(&offer.nonce)?;
        let recipient = offer.recipient.parse::<age::x25519::Recipient>()?;
        let peer = Peer::new(offer.mailbox.clone(), allow_loopback)?
            .with_delegated_access(offer.access.clone());
        let key = age::x25519::Identity::generate();
        let request = Request {
            kind: "elo.now/pair-request/v1".into(),
            offer: offer.nonce.clone(),
            nonce: record::random_hex::<32>()?,
            name: name.trim().into(),
            recipient: key.to_public().to_string(),
        };
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
                        if let Ok(response) = serde_json::from_slice::<Response>(&plain)
                            && response.kind == "elo.now/pair-response/v1"
                            && response.request == self.request.nonce
                            && response.identity == self.offer.identity
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
}

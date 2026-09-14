//! Small CHANNEL files, independently encrypted, fetched only after explicit choice.
use crate::{
    authority::{Authority, Capability},
    crypto,
    ids::{IdentityId, ObjectId, RecordId, SpaceId, StreamId},
    record::{self, RecordError, Result, SignedRecord},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const MAX_FILE: usize = 10 * 1024 * 1024;
pub const MAX_FILE_RECORD: usize = 14 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileBody {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub resource_id: String,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub config_id: RecordId,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
    pub audience: Vec<IdentityId>,
    pub recipient_credentials: Vec<RecordId>,
    pub filename: String,
    pub mime: String,
    pub size_bytes: u64,
    pub content_sha256: String,
    pub content_base64: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileShared {
    pub v: u64,
    pub kind: String,
    pub nonce: String,
    pub resource_id: String,
    pub object_id: ObjectId,
    pub space_id: SpaceId,
    pub stream_id: StreamId,
    pub config_id: RecordId,
    pub issuer_identity: IdentityId,
    pub issuer_credential: RecordId,
    pub audience: Vec<IdentityId>,
    pub recipient_credentials: Vec<RecordId>,
    pub filename: String,
    pub mime: String,
    pub size_bytes: u64,
    pub content_sha256: String,
}
pub struct PreparedFile {
    pub body: SignedRecord,
    pub ciphertext: Vec<u8>,
    pub shared: SignedRecord,
    pub shared_ciphertext: Vec<u8>,
}
fn file_metadata(name: &str, mime: &str, size: u64, hash: &str, resource: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
        || mime.is_empty()
        || mime.len() > 127
        || !mime.contains('/')
        || !mime.bytes().all(|b| b.is_ascii_graphic())
        || size > MAX_FILE as u64
    {
        return Err(RecordError::Json);
    }
    record::hex::<32>(hash)?;
    record::hex::<16>(resource)?;
    Ok(())
}
fn scope(a: &Authority, r: &SignedRecord, v: &serde_json::Value) -> Result<()> {
    let space: SpaceId =
        serde_json::from_value(v["space_id"].clone()).map_err(|_| RecordError::Json)?;
    let stream: StreamId =
        serde_json::from_value(v["stream_id"].clone()).map_err(|_| RecordError::Json)?;
    let config: RecordId =
        serde_json::from_value(v["config_id"].clone()).map_err(|_| RecordError::Json)?;
    let issuer: RecordId =
        serde_json::from_value(v["issuer_credential"].clone()).map_err(|_| RecordError::Json)?;
    let c = a.credential(issuer)?;
    r.verify_signature(c.key())?;
    let (audience, recipients) = a.expected_recipients(config, issuer)?;
    if space != a.space()
        || stream != a.stream()
        || v["issuer_identity"]
            != serde_json::to_value(c.identity()).map_err(|_| RecordError::Json)?
        || v["audience"] != serde_json::to_value(audience).map_err(|_| RecordError::Json)?
        || v["recipient_credentials"]
            != serde_json::to_value(recipients).map_err(|_| RecordError::Json)?
        || !a.has(config, c.identity(), Capability::Post)
    {
        return Err(RecordError::Authority);
    }
    Ok(())
}
pub fn prepare(
    a: &Authority,
    issuer: RecordId,
    filename: &str,
    mime: &str,
    bytes: &[u8],
    key: &SigningKey,
) -> Result<PreparedFile> {
    if a.is_forked() || bytes.len() > MAX_FILE {
        return Err(RecordError::Authority);
    }
    let c = a.credential(issuer)?;
    if c.key() != &key.verifying_key() {
        return Err(RecordError::Authority);
    }
    let config = a.head_id().ok_or(RecordError::Authority)?;
    let (audience, recipient_credentials) = a.expected_recipients(config, issuer)?;
    let resource = record::random_hex::<16>()?;
    let hash = record::encode_hex(&Sha256::digest(bytes));
    file_metadata(filename, mime, bytes.len() as u64, &hash, &resource)?;
    let body = FileBody {
        v: 1,
        kind: "file.body".into(),
        nonce: record::random_hex::<16>()?,
        resource_id: resource.clone(),
        space_id: a.space(),
        stream_id: a.stream(),
        config_id: config,
        issuer_identity: c.identity(),
        issuer_credential: issuer,
        audience: audience.clone(),
        recipient_credentials: recipient_credentials.clone(),
        filename: filename.into(),
        mime: mime.into(),
        size_bytes: bytes.len() as u64,
        content_sha256: hash.clone(),
        content_base64: STANDARD.encode(bytes),
    };
    let body = SignedRecord::sign_bounded(
        &serde_json::to_vec(&body).map_err(|_| RecordError::Json)?,
        key,
        MAX_FILE_RECORD,
    )?;
    scope(a, &body, body.body())?;
    let keys = recipient_credentials
        .iter()
        .map(|id| a.credential(*id).map(|c| c.recipient()))
        .collect::<Result<Vec<_>>>()?;
    let ciphertext = crypto::seal_bytes(body.bytes(), &keys, MAX_FILE_RECORD)
        .map_err(|_| RecordError::Authority)?;
    let shared = FileShared {
        v: 1,
        kind: "file.shared".into(),
        nonce: record::random_hex::<16>()?,
        resource_id: resource,
        object_id: ObjectId::of_ciphertext(&ciphertext),
        space_id: a.space(),
        stream_id: a.stream(),
        config_id: config,
        issuer_identity: c.identity(),
        issuer_credential: issuer,
        audience,
        recipient_credentials,
        filename: filename.into(),
        mime: mime.into(),
        size_bytes: bytes.len() as u64,
        content_sha256: hash,
    };
    let shared = SignedRecord::sign(
        &serde_json::to_vec(&shared).map_err(|_| RecordError::Json)?,
        key,
    )?;
    let shared_ciphertext =
        crypto::seal_record(&shared, &keys).map_err(|_| RecordError::Authority)?;
    Ok(PreparedFile {
        body,
        ciphertext,
        shared,
        shared_ciphertext,
    })
}
#[derive(Clone)]
pub struct VerifiedFileShare {
    record: SignedRecord,
    body: FileShared,
}
impl VerifiedFileShare {
    pub fn verify(
        record: &SignedRecord,
        a: &Authority,
        recipient: RecordId,
        already_accepted: bool,
    ) -> Result<Self> {
        let body: FileShared = record.decode()?;
        if record.bytes().len() > record::MAX_RECORD || body.v != 1 || body.kind != "file.shared" {
            return Err(RecordError::Unsupported);
        }
        record::hex::<16>(&body.nonce)?;
        file_metadata(
            &body.filename,
            &body.mime,
            body.size_bytes,
            &body.content_sha256,
            &body.resource_id,
        )?;
        scope(a, record, record.body())?;
        if !body.recipient_credentials.contains(&recipient)
            || (!already_accepted && (a.is_forked() || Some(body.config_id) != a.head_id()))
        {
            return Err(RecordError::Authority);
        }
        Ok(Self {
            record: record.clone(),
            body,
        })
    }
    pub fn body(&self) -> &FileShared {
        &self.body
    }
    pub fn record(&self) -> &SignedRecord {
        &self.record
    }
}
pub struct VerifiedFile {
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}
pub fn open(
    ciphertext: &[u8],
    identity: &age::x25519::Identity,
    own: RecordId,
    share: &VerifiedFileShare,
    a: &Authority,
) -> Result<VerifiedFile> {
    if ObjectId::of_ciphertext(ciphertext) != share.body.object_id
        || a.credential(own)?.recipient() != identity.to_public()
        || !share.body.recipient_credentials.contains(&own)
    {
        return Err(RecordError::Authority);
    }
    let bytes = crypto::open_bytes(ciphertext, identity, MAX_FILE_RECORD)
        .map_err(|_| RecordError::Authority)?;
    let r = SignedRecord::parse_bounded(&bytes, MAX_FILE_RECORD)?;
    let body: FileBody = r.decode()?;
    if body.v != 1 || body.kind != "file.body" {
        return Err(RecordError::Unsupported);
    }
    record::hex::<16>(&body.nonce)?;
    file_metadata(
        &body.filename,
        &body.mime,
        body.size_bytes,
        &body.content_sha256,
        &body.resource_id,
    )?;
    scope(a, &r, r.body())?;
    let shared = &share.body;
    if body.resource_id != shared.resource_id
        || body.space_id != shared.space_id
        || body.stream_id != shared.stream_id
        || body.config_id != shared.config_id
        || body.issuer_identity != shared.issuer_identity
        || body.issuer_credential != shared.issuer_credential
        || body.audience != shared.audience
        || body.recipient_credentials != shared.recipient_credentials
        || body.filename != shared.filename
        || body.mime != shared.mime
        || body.size_bytes != shared.size_bytes
        || body.content_sha256 != shared.content_sha256
        || body.content_base64.len() > MAX_FILE.div_ceil(3) * 4
    {
        return Err(RecordError::Authority);
    }
    let content = STANDARD
        .decode(body.content_base64)
        .map_err(|_| RecordError::Json)?;
    if content.len() as u64 != body.size_bytes
        || record::encode_hex(&Sha256::digest(&content)) != body.content_sha256
    {
        return Err(RecordError::Authority);
    }
    Ok(VerifiedFile {
        filename: body.filename,
        mime: body.mime,
        bytes: content,
    })
}
pub(crate) fn verify_outgoing(a: &Authority, r: &SignedRecord, own: RecordId) -> Result<()> {
    if a.is_forked()
        || r.body()["config_id"]
            != serde_json::to_value(a.head_id().ok_or(RecordError::Authority)?)
                .map_err(|_| RecordError::Json)?
    {
        return Err(RecordError::Authority);
    }
    let recipients: Vec<RecordId> =
        serde_json::from_value(r.body()["recipient_credentials"].clone())
            .map_err(|_| RecordError::Json)?;
    if !recipients.contains(&own) {
        return Err(RecordError::Authority);
    }
    scope(a, r, r.body())?;
    match r.body()["kind"].as_str() {
        Some("file.shared") => {
            VerifiedFileShare::verify(r, a, own, false)?;
        }
        Some("file.body") => {
            let b: FileBody = r.decode()?;
            if b.v != 1 || b.content_base64.len() > MAX_FILE.div_ceil(3) * 4 {
                return Err(RecordError::Json);
            }
            record::hex::<16>(&b.nonce)?;
            file_metadata(
                &b.filename,
                &b.mime,
                b.size_bytes,
                &b.content_sha256,
                &b.resource_id,
            )?;
            let data = STANDARD
                .decode(b.content_base64)
                .map_err(|_| RecordError::Json)?;
            if data.len() as u64 != b.size_bytes
                || record::encode_hex(&Sha256::digest(&data)) != b.content_sha256
            {
                return Err(RecordError::Authority);
            }
        }
        _ => return Err(RecordError::Unsupported),
    }
    Ok(())
}

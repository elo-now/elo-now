//! Native age X25519 only. Decryption completes before any plaintext is returned.
use crate::{
    identity::VerifiedCredential,
    ids::RecordId,
    record::{ChatMessage, MAX_RECORD, SignedRecord},
};
use std::io::{Read, Write};
use thiserror::Error;
mod packing;
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid object size or recipient set")]
    InvalidInput,
    #[error("age encryption failed")]
    Encrypt,
    #[error("age decryption or final authentication failed")]
    Decrypt,
    #[error("recipient credentials do not match the signed record")]
    Recipients,
}
pub type Result<T> = std::result::Result<T, CryptoError>;
pub const MAX_CIPHERTEXT: usize = 16 * 1024 * 1024;
/// Every entry must already be approved by the authority layer, including self
/// and owner copies. This exact-set check does not itself establish membership.
pub fn seal_chat(record: &SignedRecord, credentials: &[VerifiedCredential]) -> Result<Vec<u8>> {
    let chat: ChatMessage = record.chat().map_err(|_| CryptoError::InvalidInput)?;
    let ids: Vec<RecordId> = credentials.iter().map(VerifiedCredential::id).collect();
    if ids != chat.recipient_credentials {
        return Err(CryptoError::Recipients);
    }
    let packed = packing::pack(record.bytes())?;
    seal_bytes(
        &packed,
        &credentials
            .iter()
            .map(VerifiedCredential::recipient)
            .collect::<Vec<_>>(),
        MAX_RECORD,
    )
}
pub fn seal_record(
    record: &SignedRecord,
    recipients: &[age::x25519::Recipient],
) -> Result<Vec<u8>> {
    seal_bytes(record.bytes(), recipients, MAX_RECORD)
}
pub(crate) fn seal_bytes(
    bytes: &[u8],
    recipients: &[age::x25519::Recipient],
    maximum: usize,
) -> Result<Vec<u8>> {
    if bytes.is_empty()
        || bytes.len() > maximum
        || !(1..=crate::record::MAX_CHAT_CREDENTIALS).contains(&recipients.len())
    {
        return Err(CryptoError::InvalidInput);
    }
    let mut keys: Vec<String> = recipients.iter().map(ToString::to_string).collect();
    keys.sort();
    keys.dedup();
    if keys.len() != recipients.len() {
        return Err(CryptoError::InvalidInput);
    }
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|_| CryptoError::Encrypt)?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|_| CryptoError::Encrypt)?;
    writer.write_all(bytes).map_err(|_| CryptoError::Encrypt)?;
    writer.finish().map_err(|_| CryptoError::Encrypt)?;
    if ciphertext.len() > MAX_CIPHERTEXT {
        return Err(CryptoError::InvalidInput);
    }
    Ok(ciphertext)
}
pub fn open_record(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<SignedRecord> {
    let bytes = packing::unpack(open_bytes(ciphertext, identity, MAX_RECORD)?, MAX_RECORD)?;
    let record = SignedRecord::parse(&bytes).map_err(|_| CryptoError::Decrypt)?;
    crate::erasure::verify_original(ciphertext, &record)?;
    Ok(record)
}
pub(crate) fn open_bytes(
    ciphertext: &[u8],
    identity: &age::x25519::Identity,
    maximum: usize,
) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT {
        return Err(CryptoError::InvalidInput);
    }
    let owned = crate::erasure::inspect(ciphertext)?;
    let payload = owned
        .as_ref()
        .map_or(ciphertext, |content| content.ciphertext);
    let decryptor = bounded_decryptor(payload).map_err(|_| CryptoError::Decrypt)?;
    if decryptor.is_scrypt() {
        return Err(CryptoError::Decrypt);
    }
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| CryptoError::Decrypt)?
        .take(maximum as u64 + 1);
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| CryptoError::Decrypt)?;
    if plaintext.len() > maximum {
        return Err(CryptoError::InvalidInput);
    }
    Ok(plaintext)
}

/// Bounded dispatch for implemented object kinds. Each schema enforces its own limit.
pub fn open_object(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<SignedRecord> {
    let bytes = packing::unpack(
        open_bytes(ciphertext, identity, crate::files::MAX_FILE_RECORD)?,
        MAX_RECORD,
    )?;
    let r = SignedRecord::parse_bounded(&bytes, crate::files::MAX_FILE_RECORD)
        .map_err(|_| CryptoError::Decrypt)?;
    crate::erasure::verify_original(ciphertext, &r)?;
    let maximum = match r.body()["kind"].as_str() {
        Some("file.body") => crate::files::MAX_FILE_RECORD,
        Some("history.access.granted") => crate::history::MAX_BUNDLE,
        _ => MAX_RECORD,
    };
    if bytes.len() > maximum {
        return Err(CryptoError::InvalidInput);
    }
    Ok(r)
}

const MAX_AGE_HEADER: usize = 512 * 1024;
// Limit the library parser's input while it reads the age header. The linear
// preflight below only enforces a resource budget; age validates all framing,
// stanzas, authentication and ciphertext.
pub(crate) struct HeaderReader<'a> {
    remaining: &'a [u8],
    budget: usize,
    limited: std::rc::Rc<std::cell::Cell<bool>>,
}
impl std::io::BufRead for HeaderReader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.limited.get() {
            if self.budget == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "age header limit",
                ));
            }
            Ok(&self.remaining[..self.remaining.len().min(self.budget)])
        } else {
            Ok(self.remaining)
        }
    }
    fn consume(&mut self, amount: usize) {
        self.remaining = &self.remaining[amount..];
        if self.limited.get() {
            self.budget = self.budget.saturating_sub(amount);
        }
    }
}
impl Read for HeaderReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        use std::io::BufRead;
        let data = self.fill_buf()?;
        let count = data.len().min(out.len());
        out[..count].copy_from_slice(&data[..count]);
        self.consume(count);
        Ok(count)
    }
}
pub(crate) fn bounded_decryptor(
    bytes: &[u8],
) -> std::result::Result<age::Decryptor<HeaderReader<'_>>, age::DecryptError> {
    let prefix = &bytes[..bytes.len().min(MAX_AGE_HEADER)];
    let mut end_seen = false;
    for (index, line) in prefix.split(|byte| *byte == b'\n').enumerate() {
        if index > crate::record::MAX_CHAT_CREDENTIALS * 4 + 128 {
            return Err(age::DecryptError::InvalidHeader);
        }
        if line.starts_with(b"--- ") {
            end_seen = true;
            break;
        }
    }
    if !end_seen {
        return Err(age::DecryptError::InvalidHeader);
    }
    let limited = std::rc::Rc::new(std::cell::Cell::new(true));
    let reader = HeaderReader {
        remaining: bytes,
        budget: MAX_AGE_HEADER,
        limited: limited.clone(),
    };
    let decryptor = age::Decryptor::new_buffered(reader)?;
    limited.set(false);
    Ok(decryptor)
}
#[cfg(test)]
mod header_tests {
    use super::*;
    #[test]
    fn library_header_parser_is_bounded_before_authentication() {
        let identity = age::x25519::Identity::generate();
        let r = SignedRecord::parse(include_bytes!(
            "../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap();
        let encrypted = seal_record(&r, &[identity.to_public()]).unwrap();
        let pos = encrypted.windows(5).position(|b| b == b"\n--- ").unwrap() + 1;
        let expanded = |count| {
            let mut b = encrypted[..pos].to_vec();
            for _ in 0..count {
                b.extend_from_slice(b"-> unknown\nAA\n");
            }
            b.extend_from_slice(&encrypted[pos..]);
            b
        };
        assert!(bounded_decryptor(&expanded(1)).is_ok());
        assert!(bounded_decryptor(&expanded(50_000)).is_err());
        assert_eq!(
            open_record(&encrypted, &identity).unwrap().bytes(),
            r.bytes()
        );
    }
}

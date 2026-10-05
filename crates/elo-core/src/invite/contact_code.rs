//! Self-contained My code transport. Compression is not encryption: recipients
//! can inspect the signed records. No upload or lookup is needed to decode them.
use crate::{
    identity::MAX_CREDENTIAL_BYTES,
    record::{MAX_RECORD, RecordError, Result, SignedRecord},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const PREFIX: &str = "elo://contact/v1#";
const MAX_PLAIN: usize = 4 + MAX_RECORD + MAX_CREDENTIAL_BYTES;
const MAX_ENCODED: usize = MAX_PLAIN * 2;

/// Preserve the exact signed bytes, including JSON field order and whitespace.
/// The envelope is u32be(card length) || card ELO1 || credential ELO1, compressed
/// with zlib and encoded as unpadded base64url. This does not change record IDs.
pub fn encode(card: &SignedRecord, credential: &SignedRecord) -> Result<String> {
    validate_records(card, credential)?;
    let mut zip = ZlibEncoder::new(Vec::new(), Compression::best());
    let length = u32::try_from(card.bytes().len()).map_err(|_| RecordError::Framing)?;
    zip.write_all(&length.to_be_bytes())
        .and_then(|_| zip.write_all(card.bytes()))
        .and_then(|_| zip.write_all(credential.bytes()))
        .map_err(|_| RecordError::Framing)?;
    let compressed = zip.finish().map_err(|_| RecordError::Framing)?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(compressed)))
}

/// Decode framing only. Callers must still verify the credential chain, card
/// signature, binding, expiry and the user's explicit identity confirmation.
pub fn decode(link: &str) -> Result<(SignedRecord, SignedRecord)> {
    let encoded = link
        .trim()
        .strip_prefix(PREFIX)
        .filter(|value| !value.is_empty() && value.len() <= MAX_ENCODED)
        .ok_or(RecordError::Framing)?;
    let compressed = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| RecordError::Framing)?,
    );
    let mut zip = ZlibDecoder::new(compressed.as_slice());
    let mut plain = Zeroizing::new(Vec::new());
    zip.by_ref()
        .take(MAX_PLAIN as u64 + 1)
        .read_to_end(&mut plain)
        .map_err(|_| RecordError::Framing)?;
    if !(148..=MAX_PLAIN).contains(&plain.len()) || zip.total_in() != compressed.len() as u64 {
        return Err(RecordError::Framing);
    }
    let length =
        u32::from_be_bytes(plain[..4].try_into().map_err(|_| RecordError::Framing)?) as usize;
    if !(72..=MAX_RECORD).contains(&length) || length > plain.len() - 76 {
        return Err(RecordError::Framing);
    }
    let (card, credential) = plain[4..].split_at(length);
    let card = SignedRecord::parse(card)?;
    let credential = SignedRecord::parse_bounded(credential, MAX_CREDENTIAL_BYTES)?;
    validate_records(&card, &credential)?;
    Ok((card, credential))
}

fn validate_records(card: &SignedRecord, credential: &SignedRecord) -> Result<()> {
    if card.bytes().len() > MAX_RECORD || credential.bytes().len() > MAX_CREDENTIAL_BYTES {
        return Err(RecordError::Framing);
    }
    if card.body()["kind"] != "identity.contact" || credential.body()["kind"] != "device.credential"
    {
        return Err(RecordError::Unsupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

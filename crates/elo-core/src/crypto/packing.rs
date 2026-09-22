//! Optional packing of signed chat records, inside authenticated age plaintext.
//! Raw ELO1 records remain readable; arbitrary seal_bytes payloads are unchanged.
use super::{CryptoError, Result};
use flate2::{Compression, Decompress, FlushDecompress, Status, write::DeflateEncoder};
use std::io::Write;

const MAGIC: &[u8] = b"elo-packed-record-v1\n";
const HEADER: usize = MAGIC.len() + 4;

pub(super) fn pack(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > crate::record::MAX_RECORD {
        return Err(CryptoError::InvalidInput);
    }
    // Each record has an independent stream, with no shared dictionary or state.
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).map_err(|_| CryptoError::Encrypt)?;
    let compressed = encoder.finish().map_err(|_| CryptoError::Encrypt)?;
    if HEADER + compressed.len() >= bytes.len() {
        return Ok(bytes.to_vec());
    }
    let mut packed = Vec::with_capacity(HEADER + compressed.len());
    packed.extend_from_slice(MAGIC);
    packed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    packed.extend_from_slice(&compressed);
    Ok(packed)
}

pub(super) fn unpack(bytes: Vec<u8>, maximum: usize) -> Result<Vec<u8>> {
    if !bytes.starts_with(MAGIC) {
        return Ok(bytes);
    }
    let size = bytes.get(MAGIC.len()..HEADER).ok_or(CryptoError::Decrypt)?;
    let size = u32::from_be_bytes(size.try_into().map_err(|_| CryptoError::Decrypt)?) as usize;
    if size == 0 || size > maximum {
        return Err(CryptoError::InvalidInput);
    }
    // One extra output byte detects false lengths and expansion beyond the bound.
    let mut plain = vec![0; size + 1];
    let mut decoder = Decompress::new(false);
    let status = decoder
        .decompress(&bytes[HEADER..], &mut plain, FlushDecompress::Finish)
        .map_err(|_| CryptoError::Decrypt)?;
    if status != Status::StreamEnd
        || decoder.total_out() != size as u64
        || decoder.total_in() != (bytes.len() - HEADER) as u64
    {
        return Err(CryptoError::Decrypt);
    }
    plain.truncate(size);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packing_is_lossless_and_never_expands_the_signed_record() {
        let bytes = include_bytes!("../../../../protocol/fixtures/chat-message-v1.record.bin");
        let packed = pack(bytes).unwrap();
        assert!(packed.len() < bytes.len());
        assert_eq!(unpack(packed, bytes.len()).unwrap(), bytes);
        assert_eq!(unpack(bytes.to_vec(), bytes.len()).unwrap(), bytes);
        assert_eq!(pack(b"short").unwrap(), b"short");
    }

    #[test]
    fn codec_initialization_and_maximum_record_fit_a_small_worker_stack() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let bytes = vec![b'x'; crate::record::MAX_RECORD];
                let packed = pack(&bytes).unwrap();
                assert_eq!(unpack(packed, crate::record::MAX_RECORD).unwrap(), bytes);
                // Invitations already use zlib framing on this same backend.
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&bytes).unwrap();
                assert!(!encoder.finish().unwrap().is_empty());
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn malformed_truncated_concatenated_and_expanding_streams_are_rejected() {
        let packed = pack(&vec![b'a'; 20_000]).unwrap();
        for length in MAGIC.len()..packed.len() {
            assert!(unpack(packed[..length].to_vec(), 20_000).is_err());
        }
        assert!(unpack(packed.clone(), 19_999).is_err());
        for claimed in [0u32, 1, 19_999, 20_001, u32::MAX] {
            let mut wrong = packed.clone();
            wrong[MAGIC.len()..HEADER].copy_from_slice(&claimed.to_be_bytes());
            assert!(unpack(wrong, 20_001).is_err());
        }
        for suffix in [&b"extra"[..], &packed[HEADER..]] {
            let mut trailing = packed.clone();
            trailing.extend_from_slice(suffix);
            assert!(unpack(trailing, 20_000).is_err());
        }
    }

    #[test]
    fn compressed_records_require_complete_age_authentication_before_opening() {
        use crate::{crypto, record::SignedRecord};
        let identity = age::x25519::Identity::generate();
        let fixture = include_bytes!("../../../../protocol/fixtures/chat-message-v1.record.bin");
        let packed = pack(fixture).unwrap();
        let cipher =
            crypto::seal_bytes(&packed, &[identity.to_public()], crate::record::MAX_RECORD)
                .unwrap();
        assert_eq!(
            crypto::open_record(&cipher, &identity).unwrap().bytes(),
            fixture
        );
        assert_eq!(
            crypto::open_object(&cipher, &identity).unwrap().id(),
            SignedRecord::parse(fixture).unwrap().id()
        );
        assert!(crypto::open_record(&cipher, &age::x25519::Identity::generate()).is_err());
        for end in [0, 20, cipher.len() - 17, cipher.len() - 1] {
            assert!(crypto::open_record(&cipher[..end], &identity).is_err());
        }
        let mut corrupted = cipher.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(crypto::open_record(&corrupted, &identity).is_err());
        let mut appended = cipher;
        appended.push(0);
        assert!(crypto::open_record(&appended, &identity).is_err());
        let mut bomb = pack(&vec![b'a'; 2 * crate::record::MAX_RECORD / 3]).unwrap();
        bomb[MAGIC.len()..HEADER].copy_from_slice(&u32::MAX.to_be_bytes());
        let bomb =
            crypto::seal_bytes(&bomb, &[identity.to_public()], crate::record::MAX_RECORD).unwrap();
        assert!(crypto::open_object(&bomb, &identity).is_err());
    }
}

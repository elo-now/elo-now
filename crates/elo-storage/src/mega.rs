//! Limited-folder MEGA access through a fixed, isolated helper.
//! Credentials travel over stdin, never argv, URLs, logs or a WebDAV listener.
use crate::storage::{AttachmentStorage, Result, StoredObject};
use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::Semaphore,
};
use zeroize::Zeroizing;

const MAX_BYTES: usize = 6 * 1024 * 1024;
const MAX_REPLY: u64 = 9 * 1024 * 1024;
static OPERATIONS: Semaphore = Semaphore::const_new(2);

struct MegaFolder {
    folder_link: Zeroizing<String>,
    write_auth: Zeroizing<String>,
}

#[derive(Serialize)]
struct Request<'a> {
    op: &'a str,
    folder_link: &'a str,
    write_auth: &'a str,
    space: &'a str,
    object: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    ok: bool,
    data: Option<String>,
    error: Option<String>,
}

fn folder_credentials_valid(link: &str, key: &str) -> bool {
    let Some((handle, folder_key)) = link
        .strip_prefix("https://mega.nz/folder/")
        .and_then(|tail| tail.split_once('#'))
    else {
        return false;
    };
    let alphabet = |value: &str| {
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    };
    handle.len() == 8
        && (22..=64).contains(&folder_key.len())
        && alphabet(handle)
        && alphabet(folder_key)
        && (16..=128).contains(&key.len())
        && alphabet(key)
}

fn segment_valid(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub async fn open(
    folder_link: &str,
    write_auth: &str,
    _work_root: &Path,
) -> Result<Arc<dyn AttachmentStorage>> {
    if !folder_credentials_valid(folder_link, write_auth) {
        return Err("Invalid MEGA folder credentials.".into());
    }
    Ok(Arc::new(MegaFolder {
        folder_link: Zeroizing::new(folder_link.to_owned()),
        write_auth: Zeroizing::new(write_auth.to_owned()),
    }))
}

pub async fn probe(folder_link: &str, write_auth: &str) -> Result<()> {
    if !folder_credentials_valid(folder_link, write_auth) {
        return Err("Invalid MEGA folder credentials.".into());
    }
    let store = MegaFolder {
        folder_link: Zeroizing::new(folder_link.to_owned()),
        write_auth: Zeroizing::new(write_auth.to_owned()),
    };
    let reply = store.run("probe", "", "", None).await?;
    if reply.data.is_some() {
        return Err("Invalid attachment storage response.".into());
    }
    Ok(())
}

impl MegaFolder {
    async fn run(
        &self,
        op: &str,
        space: &str,
        object: &str,
        data: Option<String>,
    ) -> Result<Reply> {
        if op != "probe" && (!segment_valid(space) || !segment_valid(object)) {
            return Err("Invalid attachment storage identifier.".into());
        }
        let payload = Zeroizing::new(
            serde_json::to_vec(&Request {
                op,
                folder_link: &self.folder_link,
                write_auth: &self.write_auth,
                space,
                object,
                data,
            })
            .map_err(|_| "Could not prepare storage request.")?,
        );
        // Avoid an unbounded queue of expensive provider sessions. Detached work
        // retains its permit and bounded deadline even if the HTTP caller leaves.
        let permit = OPERATIONS
            .try_acquire()
            .map_err(|_| "Attachment storage is busy.")?;
        tokio::spawn(async move {
            let _permit = permit;
            tokio::time::timeout(Duration::from_secs(80), helper(payload))
                .await
                .map_err(|_| std::io::Error::other("Attachment storage timed out."))?
        })
        .await
        .map_err(|_| "Attachment storage task failed.")?
    }
}

async fn helper(payload: Zeroizing<Vec<u8>>) -> Result<Reply> {
    let mut child = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg("/opt/elo/storage/mega_folder.py")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "Attachment storage is unavailable.")?;
    let mut input = child
        .stdin
        .take()
        .ok_or("Attachment storage is unavailable.")?;
    input
        .write_all(&payload)
        .await
        .map_err(|_| "Attachment storage request failed.")?;
    input
        .shutdown()
        .await
        .map_err(|_| "Attachment storage request failed.")?;
    drop(input);
    drop(payload);
    let output = child
        .stdout
        .take()
        .ok_or("Attachment storage is unavailable.")?;
    let mut limited = output.take(MAX_REPLY + 1);
    let mut reply = Vec::new();
    limited
        .read_to_end(&mut reply)
        .await
        .map_err(|_| "Attachment storage response failed.")?;
    if reply.len() as u64 > MAX_REPLY {
        return Err("Attachment storage response is too large.".into());
    }
    let status = child
        .wait()
        .await
        .map_err(|_| "Attachment storage failed.")?;
    if !status.success() {
        return Err("Attachment storage failed.".into());
    }
    decode_reply(&reply)
}

fn decode_reply(raw: &[u8]) -> Result<Reply> {
    let reply: Reply =
        serde_json::from_slice(raw).map_err(|_| "Invalid attachment storage response.")?;
    if !reply.ok {
        // Error strings from the provider/helper are deliberately not propagated.
        return match reply.error.as_deref() {
            Some("not_found") => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Attachment is unavailable.",
            )
            .into()),
            _ => Err("Attachment storage operation failed.".into()),
        };
    }
    if reply.error.is_some() {
        return Err("Invalid attachment storage response.".into());
    }
    Ok(reply)
}

#[async_trait]
impl AttachmentStorage for MegaFolder {
    async fn put(&self, space: &str, object: &str, body: Body, size: u64) -> Result<()> {
        if size > MAX_BYTES as u64 {
            return Err("Attachment is too large.".into());
        }
        let bytes = to_bytes(body, size as usize)
            .await
            .map_err(|_| "Attachment size mismatch.")?;
        if bytes.len() as u64 != size {
            return Err("Attachment size mismatch.".into());
        }
        let reply = self
            .run("put", space, object, Some(STANDARD.encode(bytes)))
            .await?;
        if reply.data.is_some() {
            return Err("Invalid attachment storage response.".into());
        }
        Ok(())
    }

    async fn get(&self, space: &str, object: &str) -> Result<StoredObject> {
        let reply = self.run("get", space, object, None).await?;
        let encoded = reply.data.ok_or("Invalid attachment storage response.")?;
        if encoded.len() > MAX_BYTES.div_ceil(3) * 4 {
            return Err("Attachment is too large.".into());
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| "Invalid attachment storage response.")?;
        if bytes.len() > MAX_BYTES {
            return Err("Attachment is too large.".into());
        }
        Ok(StoredObject {
            size: bytes.len() as u64,
            body: Box::pin(futures_util::stream::once(
                async move { Ok(Bytes::from(bytes)) },
            )),
        })
    }

    async fn delete(&self, space: &str, object: &str) -> Result<()> {
        let reply = self.run("delete", space, object, None).await?;
        if reply.data.is_some() {
            return Err("Invalid attachment storage response.".into());
        }
        Ok(())
    }

    async fn delete_space(&self, _space: &str) -> Result<()> {
        // The broker enumerates its own signed reservations. Never accept a
        // recursive provider delete which could reach unrelated owner files.
        Err("Bulk MEGA folder deletion is not supported.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_limited_mega_folder_credentials_are_accepted() {
        let link = "https://mega.nz/folder/abcdefgh#abcdefghijklmnopqrstuv";
        let key = "abcdefghijklmnop";
        assert!(folder_credentials_valid(link, key));
        for bad in [
            "https://evil.invalid/folder/abcdefgh#abcdefghijklmnopqrstuv",
            "https://mega.nz/file/abcdefgh#abcdefghijklmnopqrstuv",
            "https://mega.nz/folder/abcdefgh#abcdefghijklmnopqrstuv extra",
            "https://mega.nz/folder/abcdefgh#abcdefghijklmnopqrstuv\n",
        ] {
            assert!(!folder_credentials_valid(bad, key));
        }
        assert!(!folder_credentials_valid(link, "key --some-option"));
        assert!(!segment_valid("../abcdef0123456789"));
        assert!(!segment_valid("ABCDEF0123456789"));
        assert!(segment_valid("abcdef0123456789"));
    }

    #[test]
    fn provider_errors_cannot_echo_secrets() {
        let error = decode_reply(br#"{"ok":false,"error":"secret-folder-key"}"#)
            .err()
            .unwrap();
        assert!(!error.to_string().contains("secret-folder-key"));
        assert!(decode_reply(br#"{"ok":true,"error":"secret-folder-key"}"#).is_err());
        assert!(decode_reply(br#"{"ok":true,"extra":"unexpected"}"#).is_err());
    }
}

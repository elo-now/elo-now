use async_trait::async_trait;
use axum::body::Body;
use bytes::Bytes;
use chrono::Utc;
use futures_util::{Stream, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, pin::Pin};
use tokio::{fs::File, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type ObjectStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send>>;

pub struct StoredObject {
    pub size: u64,
    pub body: ObjectStream,
}

#[async_trait]
pub trait AttachmentStorage: Send + Sync {
    async fn put(&self, space: &str, object: &str, body: Body, size: u64) -> Result<()>;
    async fn get(&self, space: &str, object: &str) -> Result<StoredObject>;
    async fn delete(&self, space: &str, object: &str) -> Result<()>;
    async fn delete_space(&self, space: &str) -> Result<()>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttachmentStorageConfig {
    MegaWebDav {
        base_url: String,
    },
    S3Compatible {
        endpoint: String,
        region: String,
        bucket: String,
        access_key: String,
        secret_key: String,
    },
    Local {
        root: PathBuf,
    },
}

impl AttachmentStorageConfig {
    pub async fn open(&self) -> Result<std::sync::Arc<dyn AttachmentStorage>> {
        match self {
            Self::MegaWebDav { base_url } => {
                Ok(std::sync::Arc::new(MegaWebDavStorage::new(base_url)?))
            }
            Self::S3Compatible {
                endpoint,
                region,
                bucket,
                access_key,
                secret_key,
            } => Ok(std::sync::Arc::new(S3CompatibleStorage::new(
                endpoint, region, bucket, access_key, secret_key,
            )?)),
            Self::Local { root } => Ok(std::sync::Arc::new(LocalStorage::open(root).await?)),
        }
    }
}

fn validate_segment(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("Invalid attachment storage identifier.".into());
    }
    Ok(())
}

struct MegaWebDavStorage {
    client: reqwest::Client,
    base: String,
}

impl MegaWebDavStorage {
    fn new(base_url: &str) -> Result<Self> {
        let parsed = Url::parse(base_url)?;
        if parsed.scheme() != "http"
            || !parsed
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"))
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err("MEGA WebDAV must use a loopback-only HTTP endpoint.".into());
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(std::time::Duration::from_secs(4))
                .timeout(std::time::Duration::from_secs(90))
                .build()?,
            base: base_url.trim_end_matches('/').to_owned(),
        })
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/{}", self.base, suffix.trim_start_matches('/'))
    }

    async fn collection(&self, suffix: &str) -> Result<()> {
        let method = Method::from_bytes(b"MKCOL")?;
        for attempt in 0..3 {
            let response = self
                .client
                .request(method.clone(), self.url(suffix))
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await?;
            let status = response.status();
            if status.is_success() || status == StatusCode::METHOD_NOT_ALLOWED {
                return Ok(());
            }
            // A fresh WebDAV collection may not be visible immediately. A 409
            // means its parent is missing, never successful creation. MKCOL is
            // idempotent; the streaming PUT is deliberately not replayed here.
            if attempt < 2 && matches!(status.as_u16(), 409 | 423 | 429 | 502 | 503 | 504) {
                tokio::time::sleep(std::time::Duration::from_millis(150 * (attempt + 1))).await;
                continue;
            }
            return Err(
                format!("MEGA WebDAV could not create attachment storage ({status})").into(),
            );
        }
        unreachable!()
    }
}

#[async_trait]
impl AttachmentStorage for MegaWebDavStorage {
    async fn put(&self, space: &str, object: &str, body: Body, size: u64) -> Result<()> {
        validate_segment(space)?;
        validate_segment(object)?;
        self.collection("spaces").await?;
        self.collection(&format!("spaces/{space}")).await?;
        let response = self
            .client
            .put(self.url(&format!("spaces/{space}/{object}")))
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(format!("MEGA WebDAV upload failed ({})", response.status()).into());
        }
        Ok(())
    }

    async fn get(&self, space: &str, object: &str) -> Result<StoredObject> {
        validate_segment(space)?;
        validate_segment(object)?;
        let response = self
            .client
            .get(self.url(&format!("spaces/{space}/{object}")))
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err("Attachment object is missing.".into());
        }
        if !response.status().is_success() {
            return Err(format!("MEGA WebDAV download failed ({})", response.status()).into());
        }
        let size = response
            .content_length()
            .ok_or("Attachment storage did not return a content length.")?;
        Ok(StoredObject {
            size,
            body: Box::pin(
                response
                    .bytes_stream()
                    .map(|chunk| chunk.map_err(std::io::Error::other)),
            ),
        })
    }

    async fn delete(&self, space: &str, object: &str) -> Result<()> {
        validate_segment(space)?;
        validate_segment(object)?;
        let response = self
            .client
            .delete(self.url(&format!("spaces/{space}/{object}")))
            .send()
            .await?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(format!("MEGA WebDAV delete failed ({})", response.status()).into())
        }
    }

    async fn delete_space(&self, space: &str) -> Result<()> {
        validate_segment(space)?;
        let response = self
            .client
            .delete(self.url(&format!("spaces/{space}")))
            .send()
            .await?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(format!("MEGA WebDAV Space cleanup failed ({})", response.status()).into())
        }
    }
}

struct LocalStorage {
    root: PathBuf,
}

struct StagedUpload(PathBuf);
impl Drop for StagedUpload {
    fn drop(&mut self) {
        // Also runs when the HTTP body errors or the request future is dropped.
        let _ = std::fs::remove_file(&self.0);
    }
}

impl LocalStorage {
    async fn open(root: &PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(root).await?;
        Ok(Self { root: root.clone() })
    }

    fn path(&self, space: &str, object: Option<&str>) -> Result<PathBuf> {
        validate_segment(space)?;
        if let Some(object) = object {
            validate_segment(object)?;
        }
        let mut path = self.root.join(space);
        if let Some(object) = object {
            path.push(object);
        }
        Ok(path)
    }
}

#[async_trait]
impl AttachmentStorage for LocalStorage {
    async fn put(&self, space: &str, object: &str, body: Body, size: u64) -> Result<()> {
        let path = self.path(space, Some(object))?;
        tokio::fs::create_dir_all(path.parent().ok_or("Invalid attachment path.")?).await?;
        let stage = StagedUpload(path.with_extension("upload"));
        let mut file = File::create(&stage.0).await?;
        let mut seen = 0u64;
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            seen = seen
                .checked_add(chunk.len() as u64)
                .ok_or("Attachment is too large.")?;
            if seen > size {
                return Err("Attachment size mismatch.".into());
            }
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        drop(file);
        if seen != size {
            return Err("Attachment size mismatch.".into());
        }
        tokio::fs::rename(&stage.0, path).await?;
        Ok(())
    }

    async fn get(&self, space: &str, object: &str) -> Result<StoredObject> {
        let file = File::open(self.path(space, Some(object))?).await?;
        let size = file.metadata().await?.len();
        Ok(StoredObject {
            size,
            body: Box::pin(ReaderStream::new(file)),
        })
    }

    async fn delete(&self, space: &str, object: &str) -> Result<()> {
        match tokio::fs::remove_file(self.path(space, Some(object))?).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn delete_space(&self, space: &str) -> Result<()> {
        match tokio::fs::remove_dir_all(self.path(space, None)?).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

struct S3CompatibleStorage {
    client: reqwest::Client,
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: Zeroizing<String>,
}

impl S3CompatibleStorage {
    fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        let url = Url::parse(endpoint)?;
        if url.scheme() != "https"
            || url.query().is_some()
            || url.fragment().is_some()
            || region.is_empty()
            || bucket.is_empty()
            || access_key.is_empty()
            || secret_key.is_empty()
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
        {
            return Err("Invalid S3-compatible attachment storage configuration.".into());
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(std::time::Duration::from_secs(4))
                .timeout(std::time::Duration::from_secs(90))
                .build()?,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            access_key: access_key.to_owned(),
            secret_key: secret_key.to_owned().into(),
        })
    }

    fn object_url(&self, space: &str, object: Option<&str>) -> Result<Url> {
        validate_segment(space)?;
        if let Some(object) = object {
            validate_segment(object)?;
        }
        let suffix = object
            .map(|object| format!("{space}/{object}"))
            .unwrap_or_else(|| space.to_owned());
        Ok(Url::parse(&format!(
            "{}/{}/spaces/{}",
            self.endpoint, self.bucket, suffix
        ))?)
    }

    fn hmac(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
        mac.update(value);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn signed(&self, method: Method, url: Url) -> Result<reqwest::RequestBuilder> {
        let now = Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().ok_or("Invalid S3 endpoint.")?),
            None => url.host_str().ok_or("Invalid S3 endpoint.")?.to_owned(),
        };
        let payload = "UNSIGNED-PAYLOAD";
        let canonical_headers =
            format!("host:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{timestamp}\n");
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            method.as_str(),
            url.path(),
            canonical_headers,
            signed_headers,
            payload
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let mut start = b"AWS4".to_vec();
        start.extend_from_slice(self.secret_key.as_bytes());
        let date_key = Self::hmac(&start, date.as_bytes())?;
        start.zeroize();
        let region_key = Self::hmac(&date_key, self.region.as_bytes())?;
        let service_key = Self::hmac(&region_key, b"s3")?;
        let signing_key = Self::hmac(&service_key, b"aws4_request")?;
        let signature = hex(&Self::hmac(&signing_key, string_to_sign.as_bytes())?);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, scope, signed_headers, signature
        );
        Ok(self
            .client
            .request(method, url)
            .header(reqwest::header::HOST, host)
            .header("x-amz-content-sha256", payload)
            .header("x-amz-date", timestamp)
            .header(reqwest::header::AUTHORIZATION, authorization))
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[async_trait]
impl AttachmentStorage for S3CompatibleStorage {
    async fn put(&self, space: &str, object: &str, body: Body, size: u64) -> Result<()> {
        let url = self.object_url(space, Some(object))?;
        let response = self
            .signed(Method::PUT, url)?
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("S3-compatible upload failed ({})", response.status()).into())
        }
    }

    async fn get(&self, space: &str, object: &str) -> Result<StoredObject> {
        let response = self
            .signed(Method::GET, self.object_url(space, Some(object))?)?
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err("Attachment object is missing.".into());
        }
        if !response.status().is_success() {
            return Err(format!("S3-compatible download failed ({})", response.status()).into());
        }
        let size = response
            .content_length()
            .ok_or("Attachment storage did not return a content length.")?;
        Ok(StoredObject {
            size,
            body: Box::pin(
                response
                    .bytes_stream()
                    .map(|chunk| chunk.map_err(std::io::Error::other)),
            ),
        })
    }

    async fn delete(&self, space: &str, object: &str) -> Result<()> {
        let response = self
            .signed(Method::DELETE, self.object_url(space, Some(object))?)?
            .send()
            .await?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(format!("S3-compatible delete failed ({})", response.status()).into())
        }
    }

    async fn delete_space(&self, _space: &str) -> Result<()> {
        // S3 has no directory object. Every canonical object is deleted from
        // the signed Space index before this method is called.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn webdav_waits_for_new_collection_and_never_treats_conflict_as_success() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().fallback(move || {
                    let count = counter.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if count == 0 {
                            StatusCode::CONFLICT
                        } else {
                            StatusCode::CREATED
                        }
                    }
                }),
            )
            .await
            .unwrap();
        });
        let storage = MegaWebDavStorage::new(&address).unwrap();
        storage.collection("spaces").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.abort();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let storage =
            MegaWebDavStorage::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().fallback(|| async { StatusCode::CONFLICT }),
            )
            .await
            .unwrap();
        });
        assert!(
            storage
                .collection("spaces")
                .await
                .unwrap_err()
                .to_string()
                .contains("409")
        );
        server.abort();
    }

    #[tokio::test]
    async fn local_provider_streams_and_isolates_spaces() {
        let root = tempfile::tempdir().unwrap();
        let storage = LocalStorage::open(&root.path().to_path_buf())
            .await
            .unwrap();
        let a = "11".repeat(16);
        let b = "22".repeat(16);
        let object = "33".repeat(16);
        storage
            .put(&a, &object, Body::from("secret"), 6)
            .await
            .unwrap();
        assert!(storage.get(&b, &object).await.is_err());
        let stored = storage.get(&a, &object).await.unwrap();
        assert_eq!(stored.size, 6);
        let chunks = stored.body.collect::<Vec<_>>().await;
        assert_eq!(chunks[0].as_ref().unwrap().as_ref(), b"secret");
        storage.delete(&a, &object).await.unwrap();
        assert!(storage.get(&a, &object).await.is_err());
    }
}

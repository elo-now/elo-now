use async_trait::async_trait;
use axum::body::Body;
use bytes::Bytes;
use chrono::Utc;
use futures_util::{Stream, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{Method, StatusCode, Url};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, pin::Pin};
use tokio::{fs::File, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;
use zeroize::{Zeroize, Zeroizing};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
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

pub struct LocalStorage {
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
    pub async fn open(root: &PathBuf) -> Result<Self> {
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

pub struct S3CompatibleStorage {
    client: reqwest::Client,
    download_client: reqwest::Client,
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: Zeroizing<String>,
}

impl S3CompatibleStorage {
    /// Only compiled into the test binary. Production configuration continues
    /// to reject loopback endpoints and never accepts custom trust roots.
    #[cfg(test)]
    pub(crate) fn loopback_tls_fixture(
        endpoint: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
        root_pem: &[u8],
    ) -> Result<Self> {
        let url = Url::parse(endpoint)?;
        if url.scheme() != "https"
            || !url.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            })
            || url.path() != "/"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || bucket.is_empty()
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid isolated S3 test fixture.".into());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(root_pem)?)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(4))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            download_client: client.clone(),
            client,
            endpoint: endpoint.trim_end_matches('/').into(),
            region: "us-east-1".into(),
            bucket: bucket.into(),
            access_key: access_key.into(),
            secret_key: secret_key.to_owned().into(),
        })
    }

    #[cfg(test)]
    pub(crate) async fn fixture_bucket(&self, create: bool) -> Result<()> {
        let method = if create { Method::PUT } else { Method::DELETE };
        let response = self
            .signed(
                method,
                Url::parse(&format!("{}/{}", self.endpoint, self.bucket))?,
            )?
            .body(Vec::new())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(format!("S3 test bucket operation failed ({})", response.status()).into());
        }
        Ok(())
    }

    pub async fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        let url = Url::parse(endpoint)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.host_str().is_none()
            || url.path() != "/"
            || region.len() > 128
            || !region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
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
        let host = url.host_str().ok_or("Invalid S3 endpoint.")?;
        let addresses = tokio::time::timeout(
            std::time::Duration::from_secs(4),
            tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443))),
        )
        .await??
        .collect::<Vec<_>>();
        if addresses.is_empty()
            || addresses.len() > 32
            || addresses.iter().any(|address| !public_ip(address.ip()))
        {
            return Err("S3 endpoints must resolve only to public Internet addresses.".into());
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .resolve_to_addrs(host, &addresses)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(std::time::Duration::from_secs(4))
                .timeout(std::time::Duration::from_secs(90))
                .build()?,
            download_client: elo_core::attachments::download::client(
                reqwest::Client::builder()
                    .no_proxy()
                    .resolve_to_addrs(host, &addresses),
            )?,
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
        let date_key = Zeroizing::new(Self::hmac(&start, date.as_bytes())?);
        start.zeroize();
        let region_key = Zeroizing::new(Self::hmac(&date_key, self.region.as_bytes())?);
        let service_key = Zeroizing::new(Self::hmac(&region_key, b"s3")?);
        let signing_key = Zeroizing::new(Self::hmac(&service_key, b"aws4_request")?);
        let signature = hex(&Self::hmac(&signing_key, string_to_sign.as_bytes())?);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, scope, signed_headers, signature
        );
        let client = if method == Method::GET {
            &self.download_client
        } else {
            &self.client
        };
        Ok(client
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Attachment object is missing.",
            )
            .into());
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

fn public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
                && !(a == 192 && b == 0)
                && !(a == 192 && b == 88 && c == 99)
        }
        std::net::IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] <= 0x1ff || s[1] == 0xdb8))
                && s[0] != 0x3fff
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_private_and_special_endpoints() {
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "100.100.1.1",
            "192.0.2.1",
            "198.18.1.1",
            "::1",
            "::ffff:8.8.8.8",
            "2002:7f00:1::",
            "2001:db8::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()));
        }
    }
    #[tokio::test]
    async fn local_provider_checks_lengths_and_isolates_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::open(&dir.path().to_path_buf()).await.unwrap();
        storage
            .put("11", "22", Body::from("test"), 4)
            .await
            .unwrap();
        assert!(storage.get("33", "22").await.is_err());
        assert!(
            storage
                .put("11", "33", Body::from("too long"), 1)
                .await
                .is_err()
        );
        assert!(storage.get("11", "33").await.is_err());
        assert!(storage.get("..", "22").await.is_err());
        assert_eq!(storage.get("11", "22").await.unwrap().size, 4);
    }
}

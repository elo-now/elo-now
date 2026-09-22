use super::*;
use crate::attachments::{AttachmentDescriptor, AttachmentEncryption, MAX_ATTACHMENT_FILE_SIZE};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

struct TransferFile(PathBuf);

impl Drop for TransferFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn mime_for(name: &str) -> &'static str {
    match name
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "zip" => "application/zip",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}

impl ClientApp {
    fn attachment_transfer_file(&self) -> Result<TransferFile> {
        let directory = self.directory.join("attachment-transfers");
        if directory.exists() {
            let metadata = std::fs::symlink_metadata(&directory)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("Unsafe attachment transfer directory.".into());
            }
        } else {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&directory)?;
        }
        Ok(TransferFile(directory.join(format!(
            "{}.ciphertext",
            record::random_hex::<16>()?
        ))))
    }

    fn attachment_endpoint(
        &self,
        address: &space_service::SpaceAddress,
        operation: &str,
    ) -> Result<reqwest::Url> {
        address.validate(self.allow_loopback)?;
        let mut url = reqwest::Url::parse(&address.url)?;
        let path = url
            .path()
            .strip_suffix("/team/v1/spaces")
            .ok_or("Invalid attachment service address.")?;
        url.set_path(&format!("{path}/attachments/v1/{operation}"));
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    pub(super) async fn upload_attachment(
        &mut self,
        address: &space_service::SpaceAddress,
        request: &Value,
    ) -> Result<Value> {
        self.upload_attachment_observed(
            address,
            request,
            AttachmentCancellation::default(),
            |_, _| {},
        )
        .await
    }

    pub(super) async fn upload_attachment_observed<F>(
        &mut self,
        address: &space_service::SpaceAddress,
        request: &Value,
        cancellation: AttachmentCancellation,
        progress: F,
    ) -> Result<Value>
    where
        F: Fn(u64, u64) + Send + Sync + 'static,
    {
        if cancellation.is_cancelled() {
            return Err("Attachment transfer cancelled.".into());
        }
        let index = self.authority_index(request)?;
        let input = PathBuf::from(field(request, "path")?);
        let metadata = std::fs::symlink_metadata(&input)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("Could not safely open this attachment.".into());
        }
        if metadata.len() > MAX_ATTACHMENT_FILE_SIZE {
            return Err("Attachment files cannot exceed 5 MB.".into());
        }
        let name = request["name"]
            .as_str()
            .or_else(|| input.file_name().and_then(|name| name.to_str()))
            .ok_or("Attachment name is unavailable.")?;
        let plan = crate::attachments::crypto::plan(metadata.len())?;
        let temporary = self.attachment_transfer_file()?;
        let encrypted =
            crate::attachments::crypto::encrypt_file(&input, &temporary.0, &plan, |_| {})?;
        let attachment: AttachmentId = record::random_hex::<16>()?.parse()?;
        let object: AttachmentObjectId = record::random_hex::<16>()?.parse()?;
        let reservation = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err("Attachment transfer cancelled.".into()),
            result = self.call_space(
                address,
                "attachment_reserve",
                json!({
                    "attachment_id":attachment,
                    "object_id":object,
                    "plaintext_size":metadata.len(),
                    "encrypted_size":encrypted.encrypted_size,
                    "ciphertext_sha256":encrypted.ciphertext_sha256,
                }),
            ) => result?,
        };
        let result: Result<Value> = async {
        let token = field(&reservation, "upload_token")?;
        let file = tokio::fs::File::open(&temporary.0).await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(4))
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let total = encrypted.encrypted_size;
        progress(0, total);
        let sent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sent_for_stream = sent.clone();
        let progress = std::sync::Arc::new(progress);
        let progress_for_stream = progress.clone();
        let body = ReaderStream::new(file).map(move |result| {
            if let Ok(chunk) = &result {
                let value = sent_for_stream
                    .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed)
                    + chunk.len() as u64;
                progress_for_stream(value.min(total), total);
            }
            result
        });
        let upload = client
            .put(self.attachment_endpoint(address, "upload")?)
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_LENGTH, encrypted.encrypted_size)
            .body(reqwest::Body::wrap_stream(body))
            .send();
        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err("Attachment transfer cancelled.".into()),
            response = upload => response,
        }
        .map_err(|_| "Could not upload this attachment. Check your connection and try again.")?;
        if !response.status().is_success() {
            return Err("Could not upload this attachment. Try again.".into());
        }
        // The storage provider may finish the PUT while the following control
        // request crosses a short mobile-network transition. Retry only this
        // idempotent finalization step; never repeat the encrypted body upload.
        let mut committed = false;
        for attempt in 0..2 {
            let result = tokio::select! {
            biased;
                _ = cancellation.cancelled() => return Err("Attachment transfer cancelled.".into()),
                result = self.call_space(
                    address,
                    "attachment_commit",
                    json!({"attachment_id":attachment}),
                ) => result,
            };
            match result {
                Ok(_) => {
                    committed = true;
                    break;
                }
                Err(_) if attempt == 0 => {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                Err(_) => {}
            }
        }
        if !committed {
            return Err("Could not finish uploading this attachment. Try again.".into());
        }
        let descriptor = AttachmentDescriptor {
            id: attachment,
            name: name.to_owned(),
            mime: mime_for(name).into(),
            plaintext_size: metadata.len(),
            encrypted_size: encrypted.encrypted_size,
            created_at_ms: reservation["created_at_ms"]
                .as_u64()
                .ok_or("Invalid attachment reservation.")?,
            expires_at_ms: reservation["expires_at_ms"].as_u64(),
            object_id: object,
            encryption: AttachmentEncryption {
                algorithm: "xchacha20-poly1305-chunks-v1".into(),
                key: STANDARD.encode(&*plan.key),
                nonce_prefix: STANDARD.encode(plan.nonce_prefix),
                chunk_bytes: crate::attachments::ATTACHMENT_CHUNK_BYTES,
                ciphertext_sha256: encrypted.ciphertext_sha256,
            },
        };
        descriptor.validate()?;
        let prepared = crate::files::prepare_external(
            &self.authorities.0[index],
            self.session.credential().id(),
            descriptor,
            self.session.signing_key(),
        )?;
        let message = prepared.shared.id();
        // Link before committing the local message. Once the local commit
        // succeeds there is no later network step that can turn a successful
        // send into an ambiguous error in the UI.
        if cancellation.is_cancelled() {
            return Err("Attachment transfer cancelled.".into());
        }
        // Finalization is the send boundary. Once linking starts, finish the
        // local commit even if Cancel arrives, rather than claim an uncertain
        // cancellation of a request the server may already have accepted.
        let mut linked = false;
        for attempt in 0..2 {
            let result = self.call_space(address, "attachment_link",
                json!({"attachment_id":attachment,"message_id":message})).await;
            match result {
                Ok(_) => {
                    linked = true;
                    break;
                }
                Err(_) if attempt == 0 => {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                Err(_) => {}
            }
        }
        if !linked {
            return Err("Could not finish uploading this attachment. Try again.".into());
        }
        self.store
            .commit_attachment_share(prepared, self.targets(), now()?)
            .await?;
        Ok(json!({"record":message,"attachment_id":attachment}))
        }.await;
        if result.is_err() && cancellation.is_cancelled() {
            // The PUT may already have reached storage. Revoke its reservation
            // as well as dropping the socket; a bounded best-effort request lets
            // the server's normal cleanup reclaim any completed ciphertext.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                self.call_space(
                    address,
                    "attachment_cancel",
                    json!({"attachment_id":attachment}),
                ),
            )
            .await;
        }
        result
    }

    pub(super) async fn download_attachment(
        &mut self,
        address: &space_service::SpaceAddress,
        request: &Value,
    ) -> Result<Value> {
        self.download_attachment_observed(
            address,
            request,
            AttachmentCancellation::default(),
            |_, _| {},
        )
        .await
    }

    pub(super) async fn download_attachment_observed<F>(
        &mut self,
        address: &space_service::SpaceAddress,
        request: &Value,
        cancellation: AttachmentCancellation,
        progress: F,
    ) -> Result<Value>
    where
        F: Fn(u64, u64) + Send + Sync + 'static,
    {
        if cancellation.is_cancelled() {
            return Err("Attachment transfer cancelled.".into());
        }
        let index = self.authority_index(request)?;
        let authority = &self.authorities.0[index];
        let record_id: RecordId = field(request, "record")?.parse()?;
        let record = self.message_record(authority, record_id).await?;
        if message_actions::Projection::new(&self.originals(authority).await?).is_deleted(&record) {
            return Err("This message was deleted.".into());
        }
        let share = crate::files::VerifiedFileShare::verify(
            &record,
            authority,
            self.session.credential().id(),
            true,
        )?;
        let descriptor = share
            .attachment()
            .ok_or("This file uses the older attachment format.")?
            .clone();
        let authorization = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err("Attachment transfer cancelled.".into()),
            result = self.call_space(
                address,
                "attachment_download",
                json!({"attachment_id":descriptor.id}),
            ) => result?,
        };
        if authorization["status"] != "available" {
            return Err(match authorization["status"].as_str() {
                Some("expired") => "This attachment has expired on the server.",
                Some("deleted") => "This attachment was removed from the server.",
                _ => "This attachment is no longer available on the server.",
            }
            .into());
        }
        let token = field(&authorization, "download_token")?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(4))
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let endpoint = self.attachment_endpoint(address, "download")?;
        progress(0, descriptor.encrypted_size);
        let mut response = None;
        for attempt in 0..2 {
            let download = client.get(endpoint.clone()).bearer_auth(token).send();
            let result = tokio::select! {
            biased;
                _ = cancellation.cancelled() => return Err("Attachment transfer cancelled.".into()),
                result = download => result,
            };
            match result {
                Ok(candidate) if candidate.status().is_success() => {
                    response = Some(candidate);
                    break;
                }
                Ok(candidate) if attempt == 0 && candidate.status().is_server_error() => {}
                Ok(_) => return Err("Could not download this attachment. Try again later.".into()),
                Err(_) if attempt == 0 => {}
                Err(_) => {
                    return Err(
                        "Could not download this attachment. Check your connection and try again."
                            .into(),
                    );
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        let response = response
            .ok_or("Could not download this attachment. Check your connection and try again.")?;
        if !response.status().is_success()
            || response.content_length() != Some(descriptor.encrypted_size)
        {
            return Err("Could not download this attachment. Try again later.".into());
        }
        let temporary = self.attachment_transfer_file()?;
        let mut output = tokio::fs::File::create_new(&temporary.0).await?;
        let mut stream = response.bytes_stream();
        let mut hasher = Sha256::new();
        let mut received = 0u64;
        loop {
            let next = tokio::select! {
            biased;
                _ = cancellation.cancelled() => return Err("Attachment transfer cancelled.".into()),
                next = stream.next() => next,
            };
            let Some(chunk) = next else { break };
            let chunk = chunk.map_err(
                |_| "Could not download this attachment. Check your connection and try again.",
            )?;
            received = received
                .checked_add(chunk.len() as u64)
                .ok_or("Attachment is too large.")?;
            if received > descriptor.encrypted_size {
                return Err("Attachment size mismatch.".into());
            }
            hasher.update(&chunk);
            output.write_all(&chunk).await?;
            progress(received, descriptor.encrypted_size);
        }
        output.sync_all().await?;
        drop(output);
        if received != descriptor.encrypted_size
            || record::encode_hex(&hasher.finalize()) != descriptor.encryption.ciphertext_sha256
        {
            return Err("Attachment integrity check failed.".into());
        }
        if cancellation.is_cancelled() {
            return Err("Attachment transfer cancelled.".into());
        }
        let destination = PathBuf::from(field(request, "output")?);
        if destination.exists() {
            return Err("Choose a new output file.".into());
        }
        if let Err(error) = crate::attachments::crypto::decrypt_file(
            &temporary.0,
            &destination,
            &descriptor.encryption.key,
            &descriptor.encryption.nonce_prefix,
            descriptor.plaintext_size,
            &descriptor.encryption.ciphertext_sha256,
        ) {
            let _ = std::fs::remove_file(&destination);
            return Err(error);
        }
        Ok(json!({"filename":descriptor.name,"size_bytes":descriptor.plaintext_size}))
    }
}

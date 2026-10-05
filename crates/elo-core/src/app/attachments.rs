use super::*;
use crate::attachments::broker::{Operation as StorageOperation, Response as StorageResponse};
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
        self.upload_attachment_observed_with_activity(
            address,
            request,
            cancellation,
            progress,
            |_| {},
        )
        .await
    }

    pub(super) async fn upload_attachment_observed_with_activity<F, A>(
        &mut self,
        address: &space_service::SpaceAddress,
        request: &Value,
        cancellation: AttachmentCancellation,
        progress: F,
        activity: A,
    ) -> Result<Value>
    where
        F: Fn(u64, u64) + Send + Sync + 'static,
        A: Fn(AttachmentActivity) + Send + Sync + 'static,
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
        let mut descriptor = AttachmentDescriptor {
            id: attachment,
            name: name.to_owned(),
            mime: mime_for(name).into(),
            plaintext_size: metadata.len(),
            encrypted_size: encrypted.encrypted_size,
            // The reservation supplies these values before any activity is sent.
            created_at_ms: 0,
            expires_at_ms: None,
            object_id: object,
            external_storage: self.attachment_storage_endpoint.clone(),
            encryption: AttachmentEncryption {
                algorithm: "xchacha20-poly1305-chunks-v1".into(),
                key: STANDARD.encode(plan.key.as_slice()),
                nonce_prefix: STANDARD.encode(plan.nonce_prefix),
                chunk_bytes: crate::attachments::ATTACHMENT_CHUNK_BYTES,
                ciphertext_sha256: encrypted.ciphertext_sha256.clone(),
            },
        };
        // Validate display metadata before reserving storage or exposing it in
        // a remote placeholder. Activity has the same audience as a file share.
        descriptor.validate()?;
        let authority = &self.authorities.0[index];
        let head = authority
            .head_id()
            .ok_or("Chat permissions are unavailable.")?;
        if authority.is_forked()
            || !self.authorities.space_ready(authority)
            || !authority.has(head, self.identity_id(), Capability::Post)
        {
            return Err("You cannot send attachments in this chat.".into());
        }
        authority.expected_recipients(head, self.session.credential().id())?;
        if authority.head()?.chat_kind.or(self.pins[index].chat_kind) == Some(ChatKind::Direct)
            && authority
                .head()?
                .members
                .iter()
                .any(|member| self.blocked.contains(member.identity_id))
        {
            return Err("Unblock this user before contacting them.".into());
        }
        self.require_fresh_membership(authority).await?;
        let external = self.attachment_storage_endpoint.is_some();
        let (reservation, upload_endpoint) = if external {
            let created_at_ms = now()?.as_millis() as u64;
            let response = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err("Attachment transfer cancelled.".into()),
                response = self.external_storage_command(address, StorageOperation::Reserve {
                    object_id: object,
                    encrypted_size: encrypted.encrypted_size,
                    ciphertext_sha256: encrypted.ciphertext_sha256.clone(),
                }) => response?,
            };
            let (endpoint, token, expires_at_ms) =
                self.external_storage_transfer(response, object)?;
            (
                json!({"upload_token":token,"created_at_ms":created_at_ms,"expires_at_ms":expires_at_ms}),
                endpoint,
            )
        } else {
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
            (reservation, self.attachment_endpoint(address, "upload")?)
        };
        descriptor.created_at_ms = reservation["created_at_ms"]
            .as_u64()
            .ok_or("Invalid attachment reservation.")?;
        descriptor.expires_at_ms = reservation["expires_at_ms"].as_u64();
        activity(AttachmentActivity::Uploading {
            attachment_id: attachment,
            name: descriptor.name.clone(),
            size_bytes: descriptor.plaintext_size,
            created_at_ms: descriptor.created_at_ms,
        });
        let mut finalizing = false;
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
            .put(upload_endpoint)
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
        let mut committed = external;
        for attempt in 0..2 {
            if external { break; }
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
        self.require_fresh_membership(&self.authorities.0[index]).await?;
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
        finalizing = true;
        let mut linked = false;
        for attempt in 0..2 {
            let result = if external {
                self.external_storage_command(address, StorageOperation::Complete { object_id: object }).await
                    .and_then(|response| match response {
                        StorageResponse::Complete { object_id } if object_id == object => Ok(json!({})),
                        _ => Err("Invalid attachment storage response.".into()),
                    })
            } else {
                self.call_space(address, "attachment_link",
                    json!({"attachment_id":attachment,"message_id":message})).await
            };
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
        activity(AttachmentActivity::Ready {
            attachment_id: attachment,
            record: message,
        });
        // Cache failure must not turn an already committed send into a retry.
        let _ = crate::attachments::cache::store(&self.directory, &temporary.0, &encrypted.ciphertext_sha256);
        Ok(json!({"record":message,"attachment_id":attachment}))
        }.await;
        if result.is_err() {
            activity(if cancellation.is_cancelled() && !finalizing {
                AttachmentActivity::Cancelled {
                    attachment_id: attachment,
                }
            } else {
                AttachmentActivity::Interrupted {
                    attachment_id: attachment,
                }
            });
        }
        if result.is_err() && cancellation.is_cancelled() && !finalizing {
            // The PUT may already have reached storage. Revoke its reservation
            // as well as dropping the socket; a bounded best-effort request lets
            // the server's normal cleanup reclaim any completed ciphertext.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                if external {
                    self.external_storage_command(
                        address,
                        StorageOperation::Cancel { object_id: object },
                    )
                    .await
                    .map(|_| json!({}))
                } else {
                    self.call_space(
                        address,
                        "attachment_cancel",
                        json!({"attachment_id":attachment}),
                    )
                    .await
                }
            })
            .await;
        }
        result
    }

    async fn attachment_descriptor(&self, request: &Value) -> Result<AttachmentDescriptor> {
        let index = self.authority_index(request)?;
        let authority = &self.authorities.0[index];
        let record_id: RecordId = field(request, "record")?.parse()?;
        let record = self.message_record(authority, record_id).await?;
        if message_actions::Projection::new(&self.originals(authority).await?).is_deleted(&record) {
            return Err("This message was deleted.".into());
        }
        let recipient = crypto::history_recipient(
            &record,
            authority,
            self.identity_id(),
            self.session.age_identity(),
        )?;
        let share = crate::files::VerifiedFileShare::verify(&record, authority, recipient, true)?;
        let descriptor = share
            .attachment()
            .ok_or("This file uses the older attachment format.")?
            .clone();
        Ok(descriptor)
    }

    /// Read only an authenticated local attachment; never contact its server.
    pub async fn cached_attachment(
        &self,
        request: &Value,
        output: &std::path::Path,
    ) -> Result<Option<AttachmentDescriptor>> {
        if field(request, "expected_identity")? != self.identity_id().to_string()
            || Some(field(request, "expected_space")?) != self.active_space_id()
        {
            return Err("The selected Space has changed. Try again.".into());
        }
        let client = self.selected_space_client()?;
        let descriptor = client.attachment_descriptor(request).await?;
        Ok(
            crate::attachments::cache::restore(&client.directory, &descriptor, output)
                .then_some(descriptor),
        )
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
        let descriptor = self.attachment_descriptor(request).await?;
        let current = now()?.as_millis() as u64;
        if descriptor
            .expires_at_ms
            .is_some_and(|expiry| expiry <= current)
        {
            return Err("This attachment has expired on the server.".into());
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
        progress(0, descriptor.encrypted_size);
        let response = if let Some(service) = &descriptor.external_storage {
            if self.attachment_storage_endpoint.as_ref() != Some(service) {
                return Err("Attachment storage is unavailable in this build.".into());
            }
            self.external_storage_download(
                address,
                descriptor.object_id,
                descriptor
                    .expires_at_ms
                    .ok_or("Invalid attachment storage response.")?,
                &cancellation,
                deadline,
            )
            .await?
        } else {
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
            let endpoint = self.attachment_endpoint(address, "download")?;
            let token = field(&authorization, "download_token")?;
            let client =
                crate::attachments::download::client(reqwest::Client::builder().no_proxy())?;
            let mut response = None;
            for attempt in 0..2 {
                let download = client
                    .get(endpoint.clone())
                    .bearer_auth(token)
                    .timeout(deadline.saturating_duration_since(tokio::time::Instant::now()))
                    .send();
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
                    Ok(_) => {
                        return Err("Could not download this attachment. Try again later.".into());
                    }
                    Err(_) if attempt == 0 => {}
                    Err(_) => return Err(
                        "Could not download this attachment. Check your connection and try again."
                            .into(),
                    ),
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            response
                .ok_or("Could not download this attachment. Check your connection and try again.")?
        };
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
                next = tokio::time::timeout_at(deadline, stream.next()) => next.map_err(|_| "Could not download this attachment. Check your connection and try again.")?,
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
        let _ = crate::attachments::cache::store(
            &self.directory,
            &temporary.0,
            &descriptor.encryption.ciphertext_sha256,
        );
        Ok(json!({"filename":descriptor.name,"size_bytes":descriptor.plaintext_size}))
    }
}

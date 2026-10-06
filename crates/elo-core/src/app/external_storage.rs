//! Provider secrets travel directly to the configured broker in an ephemeral
//! signed command. Neither the Space API nor the local catalog receives them.
use super::*;
use crate::attachments::broker::{self, Operation, ProviderConfig, Response, StorageStatus};

fn endpoint(value: &str, allow_loopback: bool) -> Result<String> {
    let url = reqwest::Url::parse(value).map_err(|_| "Invalid attachment storage service.")?;
    let local = url.host_str().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if value.trim() != value
        || value.len() > 2048
        || value.chars().any(char::is_control)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/storage/v1"
        || !(url.scheme() == "https" || (allow_loopback && local && url.scheme() == "http"))
    {
        return Err("Invalid attachment storage service.".into());
    }
    Ok(url.to_string())
}

pub(super) fn provider(value: &Value) -> Result<ProviderConfig> {
    let mut fields = value
        .as_object()
        .cloned()
        .ok_or("Invalid attachment storage configuration.")?;
    fields.remove("enabled");
    fields.remove("expected_revision");
    fields.remove("retention_hours");
    let provider: ProviderConfig = serde_json::from_value(Value::Object(fields))
        .map_err(|_| "Invalid attachment storage configuration.")?;
    provider
        .validate()
        .map_err(|_| "Invalid attachment storage configuration.")?;
    Ok(provider)
}

fn retention_hours(value: &Value) -> Result<u32> {
    match value.as_u64() {
        Some(hours @ (1 | 12 | 24)) => Ok(hours as u32),
        _ => Err("attachment_retention_invalid".into()),
    }
}

fn transfer(
    audience: &str,
    response: Response,
    expected_object: AttachmentObjectId,
    time: u64,
) -> Result<(reqwest::Url, String, u64)> {
    let Response::Transfer {
        object_id,
        url,
        token,
        expires_at,
        object_expires_at_ms,
    } = response
    else {
        return Err("Invalid attachment storage response.".into());
    };
    if object_id != expected_object
        || url != format!("{audience}/objects/{object_id}")
        || token.is_empty()
        || token.len() > 1024
        || token.chars().any(char::is_control)
        || expires_at <= time
        || expires_at > time.saturating_add(broker::TRANSFER_TTL + 15)
        || object_expires_at_ms <= time.saturating_mul(1000)
        || object_expires_at_ms > time.saturating_add(24 * 3600 + 15).saturating_mul(1000)
        || expires_at.saturating_mul(1000) > object_expires_at_ms
    {
        return Err("Invalid attachment storage response.".into());
    }
    Ok((reqwest::Url::parse(&url)?, token, object_expires_at_ms))
}

async fn retry_download<T, F, Fut>(
    mut attempt: F,
    cancellation: &AttachmentCancellation,
    deadline: tokio::time::Instant,
) -> Result<T>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let operation = async {
        for index in 0..2 {
            if let Some(value) = attempt(index).await? {
                return Ok(value);
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        Err("Could not download this attachment. Try again later.".into())
    };
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err("Attachment transfer cancelled.".into()),
        response = tokio::time::timeout_at(deadline, operation) => response
            .map_err(|_| "Could not download this attachment. Check your connection and try again.")?,
    }
}

impl ClientApp {
    /// Native build configuration only; never populated from a renderer URL or
    /// a message descriptor. Missing configuration keeps the feature disabled.
    pub fn configure_attachment_storage_endpoint(&mut self, value: Option<&str>) -> Result<()> {
        self.attachment_storage_endpoint = value
            .filter(|value| !value.is_empty())
            .map(|value| endpoint(value, self.allow_loopback))
            .transpose()?;
        self.refresh_default_hosting_context();
        Ok(())
    }

    pub(super) async fn external_storage_command(
        &self,
        address: &space_service::SpaceAddress,
        operation: Operation,
    ) -> Result<Response> {
        let audience = self
            .attachment_storage_endpoint
            .as_deref()
            .ok_or("Attachment storage is unavailable in this build.")?;
        let authority = self
            .authorities
            .0
            .iter()
            .find(|authority| {
                authority.space() == address.scope.space
                    && authority.stream() == address.scope.stream
            })
            .ok_or("General unavailable.")?;
        if matches!(
            operation,
            Operation::Configure { .. }
                | Operation::ConfigureManaged { .. }
                | Operation::Disable { .. }
                | Operation::Policy { .. }
        ) && !authority.can_manage(self.session.credential().id())
        {
            return Err("Only a Space owner can configure attachment storage.".into());
        }
        let timeout = if matches!(
            operation,
            Operation::Configure { .. } | Operation::ConfigureManaged { .. }
        ) {
            broker::CONFIGURE_TTL
        } else {
            90
        };
        self.require_fresh_membership(authority).await?;
        let signed = broker::sign_command(
            authority,
            &self.session,
            audience,
            operation,
            now()?.as_millis() as u64 / 1000,
        )?;
        let request = broker::Request {
            command: STANDARD.encode(signed.bytes()),
            proof: authority.call_proof()?,
        };
        // Do not surface reqwest/serde errors: request bodies contain secrets.
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(4))
            .timeout(std::time::Duration::from_secs(timeout))
            .build()?;
        let response = client
            .post(format!("{audience}/command"))
            .json(&request)
            .send()
            .await
            .map_err(|_| "Could not contact attachment storage. Try again.")?;
        if !response.status().is_success() {
            return Err(match response.status() {
                reqwest::StatusCode::CONFLICT => {
                    "Attachment storage settings changed. Refresh and try again."
                }
                reqwest::StatusCode::PRECONDITION_FAILED => {
                    "Attachments are disabled for this Space."
                }
                reqwest::StatusCode::SERVICE_UNAVAILABLE => {
                    "Attachment storage is temporarily unavailable. Try again."
                }
                _ => "Could not configure attachment storage. Check the details and try again.",
            }
            .into());
        }
        if response.content_length().is_some_and(|size| size > 16_384) {
            return Err("Invalid attachment storage response.".into());
        }
        use futures_util::StreamExt;
        let mut stream = response.bytes_stream();
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "Could not contact attachment storage. Try again.")?;
            if bytes.len().saturating_add(chunk.len()) > 16_384 {
                return Err("Invalid attachment storage response.".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| "Invalid attachment storage response.".into())
    }

    pub(super) async fn external_storage_status(
        &self,
        address: &space_service::SpaceAddress,
    ) -> Result<StorageStatus> {
        match self
            .external_storage_command(address, Operation::Status)
            .await?
        {
            Response::Status { status } => Ok(status),
            _ => Err("Invalid attachment storage response.".into()),
        }
    }

    pub(super) async fn external_storage_settings(
        &self,
        address: &space_service::SpaceAddress,
        op: &str,
        body: &Value,
    ) -> Result<Value> {
        if self.attachment_storage_endpoint.is_none() {
            if op == "space_external_storage_status" {
                return Ok(
                    json!({"available":false,"configured":false,"enabled":false,"provider":null,"revision":0,"retention_hours":null}),
                );
            }
            return Err("Attachment storage is unavailable in this build.".into());
        }
        let operation = match op {
            "space_external_storage_status" => Operation::Status,
            "space_external_storage_configure" => Operation::Configure {
                expected_revision: body["expected_revision"]
                    .as_u64()
                    .ok_or("Refresh attachment storage settings first.")?,
                provider: provider(body)?,
                retention_hours: retention_hours(&body["retention_hours"])?,
            },
            "space_external_storage_disable" => Operation::Disable {
                expected_revision: body["expected_revision"]
                    .as_u64()
                    .ok_or("Refresh attachment storage settings first.")?,
            },
            "space_attachment_retention" => Operation::Policy {
                expected_revision: body["expected_revision"]
                    .as_u64()
                    .ok_or("Refresh attachment storage settings first.")?,
                retention_hours: retention_hours(&body["hours"])?,
            },
            _ => return Err("Invalid attachment storage operation.".into()),
        };
        match self.external_storage_command(address, operation).await? {
            Response::Status { status } => {
                let mut result = serde_json::to_value(status)?;
                result["available"] = json!(true);
                Ok(result)
            }
            _ => Err("Invalid attachment storage response.".into()),
        }
    }

    pub(super) fn external_storage_transfer(
        &self,
        response: Response,
        expected_object: AttachmentObjectId,
    ) -> Result<(reqwest::Url, String, u64)> {
        let audience = self
            .attachment_storage_endpoint
            .as_deref()
            .ok_or("Attachment storage is unavailable in this build.")?;
        transfer(
            audience,
            response,
            expected_object,
            now()?.as_millis() as u64 / 1000,
        )
    }

    pub(super) async fn external_storage_download(
        &self,
        address: &space_service::SpaceAddress,
        object_id: AttachmentObjectId,
        expected_expires_at_ms: u64,
        cancellation: &AttachmentCancellation,
        deadline: tokio::time::Instant,
    ) -> Result<reqwest::Response> {
        let client = crate::attachments::download::client(reqwest::Client::builder().no_proxy())?;
        let client = &client;
        retry_download(
            |attempt| async move {
                // Every GET consumes its capability, including when the
                // provider fails after authorization. Retry with a fresh signed
                // command, never by reusing the previous bearer token.
                let response = self
                    .external_storage_command(address, Operation::Download { object_id })
                    .await?;
                let (endpoint, token, expires_at_ms) =
                    self.external_storage_transfer(response, object_id)?;
                if expires_at_ms != expected_expires_at_ms {
                    return Err("Invalid attachment storage response.".into());
                }
                let response = client
                    .get(endpoint)
                    .bearer_auth(&token)
                    .timeout(deadline.saturating_duration_since(tokio::time::Instant::now()))
                    .send()
                    .await;
                match response {
                    Ok(response) if response.status().is_success() => Ok(Some(response)),
                    Ok(response) if attempt == 0 && response.status().is_server_error() => Ok(None),
                    Err(_) if attempt == 0 => Ok(None),
                    _ => Err("Could not download this attachment. Try again later.".into()),
                }
            },
            cancellation,
            deadline,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_configuration_is_independent_and_rejects_credential_urls() {
        assert_eq!(
            endpoint("https://storage.example.test/storage/v1", false).unwrap(),
            "https://storage.example.test/storage/v1"
        );
        for value in [
            "http://storage.example.test/storage/v1",
            "https://user:secret@storage.example.test/storage/v1",
            "https://storage.example.test/storage/v1?token=secret",
            "https://storage.example.test/storage/v1#secret",
            "https://storage.example.test/storage/v1/",
        ] {
            assert!(endpoint(value, false).is_err());
        }
        assert!(endpoint("http://127.0.0.1:9020/storage/v1", true).is_ok());
        assert!(endpoint("http://127.0.0.1:9020/storage/v1", false).is_err());
    }

    #[test]
    fn transfer_capability_cannot_redirect_a_token_or_choose_another_object() {
        let audience = "https://storage.example.test/storage/v1";
        let object = AttachmentObjectId::from_bytes([1; 16]);
        let url = format!("{audience}/objects/{object}");
        let response = |url: String, object_id, expires_at| Response::Transfer {
            object_id,
            url,
            token: "synthetic transfer capability".into(),
            expires_at,
            object_expires_at_ms: 3_700_000,
        };
        assert!(transfer(audience, response(url.clone(), object, 150), object, 100).is_ok());
        for foreign in [
            format!("https://other.example.test/storage/v1/objects/{object}"),
            format!("{audience}/objects/{object}?token=secret"),
            format!("{audience}/objects/{object}/next"),
        ] {
            assert!(transfer(audience, response(foreign, object, 150), object, 100).is_err());
        }
        assert!(
            transfer(
                audience,
                response(url.clone(), AttachmentObjectId::from_bytes([2; 16]), 150),
                object,
                100
            )
            .is_err()
        );
        assert!(transfer(audience, response(url.clone(), object, 100), object, 100).is_err());
        assert!(transfer(audience, response(url, object, 1000), object, 100).is_err());
    }

    async fn test_app() -> (tempfile::TempDir, ClientApp, space_service::SpaceAddress) {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ProfileDraft::new()
            .unwrap()
            .save(
                temp.path().join("profile"),
                "synthetic storage test password".into(),
                "General",
            )
            .await
            .unwrap();
        app.allow_loopback = true;
        let proof = app.owner_general_creation(&"12".repeat(16)).unwrap();
        let genesis = decode_record(&proof.genesis).unwrap();
        let body: SpaceGenesis = genesis.decode().unwrap();
        let scope = team::TeamScope {
            space: genesis.id().to_string().parse().unwrap(),
            stream: StreamId::from_bytes(record::hex(&body.nonce).unwrap()),
            root: body.owners[0].root_public_key.clone(),
            controller: body.controller_credential_id,
        };
        app.authorities =
            Authorities(vec![proof.verify(scope.space, scope.stream).unwrap()].into());
        // The API is intentionally unreachable: configuration never posts the
        // storage credential through that address.
        let address = space_service::SpaceAddress {
            url: "http://127.0.0.1:9/team/v1/spaces".into(),
            scope: scope.clone(),
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
            service_credential: None,
        };
        (temp, app, address)
    }

    #[tokio::test]
    async fn configure_sends_a_signed_command_only_to_the_broker_and_returns_no_credentials() {
        use axum::{Json, Router, routing::post};
        let (_temp, mut app, address) = test_app().await;
        let scope = address.scope.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let audience = format!("http://{}/storage/v1", listener.local_addr().unwrap());
        app.configure_attachment_storage_endpoint(Some(&audience))
            .unwrap();
        let checked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let checked_request = checked.clone();
        let service = Router::new().route(
            "/storage/v1/command",
            post(move |Json(request): Json<broker::Request>| {
                let audience = audience.clone();
                let checked = checked_request.clone();
                async move {
                    let authority = request.proof.verify(scope.space, scope.stream).unwrap();
                    let signed = decode_record(&request.command).unwrap();
                    let command = broker::verify_command(
                        &authority,
                        &signed,
                        &audience,
                        now().unwrap().as_millis() as u64 / 1000,
                    )
                    .unwrap();
                    let (revision, retention_hours) = match command.operation {
                        Operation::Configure {
                            expected_revision: 1,
                            retention_hours: 1,
                            provider:
                                ProviderConfig::S3Compatible {
                                    ref access_key,
                                    ref secret_key,
                                    ..
                                },
                        } if access_key == "synthetic-storage-access"
                            && secret_key == "synthetic-storage-secret" =>
                        {
                            (2, 1)
                        }
                        Operation::Policy {
                            expected_revision: 2,
                            retention_hours: 12,
                        } => (3, 12),
                        _ => panic!("unexpected synthetic configure command"),
                    };
                    checked.store(true, std::sync::atomic::Ordering::SeqCst);
                    Json(Response::Status {
                        status: StorageStatus {
                            configured: true,
                            enabled: true,
                            provider: Some("s3_compatible".into()),
                            revision,
                            retention_hours: Some(retention_hours),
                            used_bytes: 0,
                            max_space_bytes: crate::attachments::MAX_SPACE_ATTACHMENT_STORAGE,
                            max_file_bytes: crate::attachments::MAX_ATTACHMENT_FILE_SIZE,
                        },
                    })
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
        let response = app.external_storage_settings(&address, "space_external_storage_configure", &json!({
            "enabled":true,"expected_revision":1,"retention_hours":1,"provider":"s3_compatible",
            "endpoint":"https://objects.example.test","region":"test","bucket":"test-bucket",
            "access_key":"synthetic-storage-access","secret_key":"synthetic-storage-secret",
        })).await.unwrap();
        assert!(checked.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(response["enabled"], true);
        let policy = app
            .external_storage_settings(
                &address,
                "space_attachment_retention",
                &json!({"hours":12,"expected_revision":2}),
            )
            .await
            .unwrap();
        assert_eq!(policy["retention_hours"], 12);
        assert_eq!(policy["revision"], 3);
        let visible = serde_json::to_string(&response).unwrap();
        for secret in ["synthetic-storage-access", "synthetic-storage-secret"] {
            assert!(!visible.contains(secret));
            for entry in std::fs::read_dir(&app.directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_file() {
                    let bytes = std::fs::read(entry.path()).unwrap();
                    assert!(
                        !bytes
                            .windows(secret.len())
                            .any(|value| value == secret.as_bytes())
                    );
                }
            }
        }
        server.abort();
        app.close().await.unwrap();
    }

    #[tokio::test]
    async fn failed_get_uses_a_fresh_signed_grant_and_bounds_retries() {
        use axum::{
            Json, Router,
            http::{HeaderMap, StatusCode},
            routing::{get, post},
        };
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        use std::time::Duration;
        let (_temp, mut app, address) = test_app().await;
        let scope = address.scope.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let audience = format!("http://{}/storage/v1", listener.local_addr().unwrap());
        app.configure_attachment_storage_endpoint(Some(&audience))
            .unwrap();
        let object = AttachmentObjectId::from_bytes([6; 16]);
        let object_expiry = (now().unwrap().as_millis() as u64 / 1000 + 3600) * 1000;
        let issued = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(Mutex::new(BTreeSet::new()));
        let gets = Arc::new(AtomicUsize::new(0));
        let always_fail = Arc::new(AtomicBool::new(false));
        let grant_issued = issued.clone();
        let grant_active = active.clone();
        let get_active = active.clone();
        let get_count = gets.clone();
        let get_failure = always_fail.clone();
        let service = Router::new()
            .route("/storage/v1/command", post(move |Json(request): Json<broker::Request>| {
                let audience = audience.clone();
                let issued = grant_issued.clone();
                let active = grant_active.clone();
                async move {
                    let authority = request.proof.verify(scope.space, scope.stream).unwrap();
                    let signed = decode_record(&request.command).unwrap();
                    let time = now().unwrap().as_millis() as u64 / 1000;
                    let command = broker::verify_command(&authority, &signed, &audience, time).unwrap();
                    assert!(matches!(command.operation, Operation::Download { object_id } if object_id == object));
                    issued.lock().unwrap().push(signed.id());
                    let token = signed.id().to_string();
                    active.lock().unwrap().insert(token.clone());
                    Json(Response::Transfer { object_id: object, url: format!("{audience}/objects/{object}"), token, expires_at: time + 120, object_expires_at_ms: object_expiry })
                }
            }))
            .route("/storage/v1/objects/{object}", get(move |headers: HeaderMap| {
                let active = get_active.clone();
                let count = get_count.clone();
                let fail = get_failure.clone();
                async move {
                    let token = headers.get("authorization").unwrap().to_str().unwrap().strip_prefix("Bearer ").unwrap();
                    if !active.lock().unwrap().remove(token) {
                        return (StatusCode::FORBIDDEN, "single-use token already consumed");
                    }
                    let attempt = count.fetch_add(1, Ordering::SeqCst);
                    if fail.load(Ordering::SeqCst) || attempt == 0 {
                        (StatusCode::SERVICE_UNAVAILABLE, "synthetic provider outage")
                    } else {
                        (StatusCode::OK, "synthetic ciphertext")
                    }
                }
            }));
        let server = tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
        let response = app
            .external_storage_download(
                &address,
                object,
                object_expiry,
                &AttachmentCancellation::default(),
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            b"synthetic ciphertext"
        );
        assert_eq!(gets.load(Ordering::SeqCst), 2);
        let commands = issued.lock().unwrap().clone();
        assert_eq!(commands.len(), 2);
        assert_ne!(
            commands[0], commands[1],
            "a retry must be signed with a new nonce"
        );

        assert!(
            app.external_storage_download(
                &address,
                object,
                object_expiry + 1,
                &AttachmentCancellation::default(),
                tokio::time::Instant::now() + Duration::from_secs(2)
            )
            .await
            .is_err()
        );
        assert_eq!(
            gets.load(Ordering::SeqCst),
            2,
            "a grant cannot replace the signed message's expiry"
        );

        always_fail.store(true, Ordering::SeqCst);
        gets.store(0, Ordering::SeqCst);
        issued.lock().unwrap().clear();
        assert!(
            app.external_storage_download(
                &address,
                object,
                object_expiry,
                &AttachmentCancellation::default(),
                tokio::time::Instant::now() + Duration::from_secs(2)
            )
            .await
            .is_err()
        );
        assert_eq!(
            gets.load(Ordering::SeqCst),
            2,
            "an outage must not cause unbounded retries"
        );

        let cancellation = AttachmentCancellation::default();
        cancellation.cancel();
        assert!(
            app.external_storage_download(
                &address,
                object,
                object_expiry,
                &cancellation,
                tokio::time::Instant::now() + Duration::from_secs(2)
            )
            .await
            .is_err()
        );
        assert_eq!(
            issued.lock().unwrap().len(),
            2,
            "cancellation cannot issue another grant"
        );
        server.abort();
        app.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn retry_delay_and_initial_attempt_share_the_original_deadline() {
        use std::{cell::Cell, time::Duration};
        let attempts = Cell::new(0);
        let started = tokio::time::Instant::now();
        let budget = Duration::from_millis(300);
        let result: Result<()> = retry_download(
            |_| {
                attempts.set(attempts.get() + 1);
                async {
                    // The first request uses part of the total budget. Its
                    // retry delay must not receive a fresh 300 milliseconds.
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    Ok(None)
                }
            },
            &AttachmentCancellation::default(),
            started + budget,
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "Could not download this attachment. Check your connection and try again."
        );
        assert_eq!(started.elapsed(), budget);
        assert_eq!(attempts.get(), 1, "the deadline prevents a second attempt");
    }

    #[tokio::test(start_paused = true)]
    async fn retry_can_succeed_within_the_remaining_original_budget() {
        use std::{cell::Cell, time::Duration};
        let attempts = Cell::new(0);
        let started = tokio::time::Instant::now();
        let result = retry_download(
            |attempt| {
                attempts.set(attempts.get() + 1);
                async move {
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    Ok((attempt == 1).then_some("downloaded"))
                }
            },
            &AttachmentCancellation::default(),
            started + Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(result, "downloaded");
        assert_eq!(attempts.get(), 2);
        assert_eq!(started.elapsed(), Duration::from_millis(410));
    }
}

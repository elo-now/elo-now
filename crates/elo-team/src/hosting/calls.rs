//! Read-only membership admission on the private operator listener.
use super::*;
use elo_core::ids::SpaceId;
use subtle::ConstantTimeEq;

pub(super) fn load_key(path: Option<&FilePath>) -> Result<Option<Zeroizing<Vec<u8>>>> {
    path.map(|path| {
        let key = Zeroizing::new(vault::read_private(path)?);
        // A dedicated 256-bit hexadecimal bearer secret, without whitespace.
        if key.len() != 64
            || !key
                .iter()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Invalid call admission key.".into());
        }
        Ok(key)
    })
    .transpose()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    space_id: SpaceId,
    identity_id: IdentityId,
    #[serde(default)]
    device: Option<(
        elo_core::ids::RecordId,
        elo_core::calls::CallScope,
        elo_core::ids::RecordId,
    )>,
}

pub(super) async fn admit(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let key = host
        .call_admission_key
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let presented = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !bool::from(key.as_slice().ct_eq(presented.as_bytes())) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let entry = host
        .spaces
        .read()
        .await
        .iter()
        .find(|(_, space)| space.config.address.scope.space == request.space_id)
        .map(|(id, space)| (id.clone(), space.clone()));
    let Some((id, space)) = entry else {
        return Ok(Json(json!({"allowed":false})));
    };
    if host
        .account_scope_pending(&id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Ok(Json(json!({"allowed":false})));
    }
    let serving = space.serving.read().await;
    if !*serving {
        return Ok(Json(json!({"allowed":false})));
    }
    // Concurrent call signals and hosting maintenance share this client. A
    // momentary lock collision is not lost membership. Wait within the private
    // caller's three-second deadline, then check the current authorization.
    let client = tokio::time::timeout(Duration::from_secs(2), space.client.lock())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if host
        .account_scope_pending(&id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Ok(Json(json!({"allowed":false})));
    }
    let Some(client) = client.as_ref() else {
        return Ok(Json(json!({"allowed":false})));
    };
    let allowed = client
        .space_access_members()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .contains(&request.identity_id);
    let allowed = allowed
        && match request.device {
            Some((credential, scope, head)) => client
                .space_call_device_allowed(request.identity_id, credential, scope, head)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
            None => true,
        };
    Ok(Json(json!({"allowed":allowed})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admission_is_private_requires_its_own_key_and_denies_unknown_spaces() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("call.key");
        let secret = record::random_hex::<32>().unwrap();
        vault::write_private(&key_path, secret.as_bytes(), false).unwrap();
        let host = Host::open(
            HostConfig {
                root: directory.path().join("host"),
                public_url: "http://127.0.0.1:18000".into(),
                max_spaces_per_identity: 3,
                mailbox_quota_bytes: 32 * 1024 * 1024,
                operator_snapshot: None,
                call_admission_key: Some(key_path),
                attachment_storage: None,
            },
            true,
        )
        .await
        .unwrap();
        let request = || Request {
            space_id: SpaceId::from_bytes([1; 32]),
            identity_id: IdentityId::from_bytes([2; 32]),
            device: None,
        };
        assert_eq!(
            admit(State(host.clone()), HeaderMap::new(), Json(request()))
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {secret}").parse().unwrap());
        assert_eq!(
            admit(State(host.clone()), headers, Json(request()))
                .await
                .unwrap()
                .0["allowed"],
            false
        );
        let public = app(host)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/internal/calls/admission")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!public.status().is_success());
    }

    #[tokio::test]
    async fn live_membership_and_call_bridge_follow_hosted_space_admission_and_removal() {
        use super::super::tests::{close_host, profile};
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use elo_core::vault::Session;
        use elo_core::{authority::CallAuthorityProof, calls, record::SignedRecord};
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("call.key");
        let key = record::random_hex::<32>().unwrap();
        vault::write_private(&key_path, key.as_bytes(), false).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let host = Host::open(
            HostConfig {
                root: directory.path().join("host"),
                public_url: base.clone(),
                max_spaces_per_identity: 3,
                mailbox_quota_bytes: 32 * 1024 * 1024,
                operator_snapshot: None,
                call_admission_key: Some(key_path),
                attachment_storage: None,
            },
            true,
        )
        .await
        .unwrap();
        let task = tokio::spawn(axum::serve(listener, app(host.clone())).into_future());
        let mut owner = profile(&directory.path().join("owner")).await;
        let mut guest = profile(&directory.path().join("guest")).await;
        let created = owner.operate(json!({"op":"space_create","contact_email":"owner@example.test",
            "host":format!("{base}/spaces/v1/create"),"message_lifetime_seconds":86400,"name":"Call test"})).await.unwrap();
        let space: SpaceId = created["view"]["active_space"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        owner
            .operate(json!({"op":"space_setup_done"}))
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {key}").parse().unwrap());
        let request = |identity_id| {
            Json(Request {
                space_id: space,
                identity_id,
                device: None,
            })
        };
        assert_eq!(
            admit(
                State(host.clone()),
                headers.clone(),
                request(guest.identity_id())
            )
            .await
            .unwrap()
            .0["allowed"],
            false
        );
        let invite = owner
            .operate(json!({"op":"space_invite","id":space,
            "body":{"lifetime":86400,"require_approval":false}}))
            .await
            .unwrap()["result"]["link"]
            .clone();
        let joined = guest
            .operate(json!({"op":"space_join","link":invite}))
            .await
            .unwrap();
        assert_eq!(
            admit(
                State(host.clone()),
                headers.clone(),
                request(guest.identity_id())
            )
            .await
            .unwrap()
            .0["allowed"],
            true
        );
        let chat = joined["view"]["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["is_general"] == true)
            .unwrap();
        let mut operation = json!({"op":"call_authorization","target_space":space,"hosting_space_id":space,
            "space":chat["space"],"stream":chat["stream"],"audience":"https://calls.example.test/calls/v1",
            "include_proof":true,"operation":{"type":"subscribe"},"expected_identity":guest.identity_id()});
        let authorization = guest.operate(operation.clone()).await.unwrap();
        assert!(
            authorization.get("view").is_none(),
            "call signing must not rebuild the full chat view"
        );
        let proof: CallAuthorityProof =
            serde_json::from_value(authorization["proof"].clone()).unwrap();
        let authority = proof
            .verify(
                chat["space"].as_str().unwrap().parse().unwrap(),
                chat["stream"].as_str().unwrap().parse().unwrap(),
            )
            .unwrap();
        let signed = SignedRecord::parse(
            &STANDARD
                .decode(authorization["command"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let command = calls::verify_command(
            &authority,
            &signed,
            "https://calls.example.test/calls/v1",
            current().unwrap() / 1000,
        )
        .unwrap();
        assert_eq!(command.hosting_space_id, space);
        operation["hosting_space_id"] = json!(SpaceId::from_bytes([8; 32]));
        assert!(guest.operate(operation.clone()).await.is_err());
        operation["hosting_space_id"] = json!(space);
        operation["expected_identity"] = json!(Session::create().unwrap().0.identity_id());
        assert!(guest.operate(operation).await.is_err());
        // Private scope registration is independent of whether a call ever ran.
        let private_created = owner
            .operate(json!({"op":"create_chat","name":"Private call", "chat_kind":"chat"}))
            .await
            .unwrap();
        let private = private_created["view"]["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "Private call")
            .unwrap();
        let authorize_private = json!({"op":"call_authorization","target_space":space,"hosting_space_id":space,
            "space":private["space"],"stream":private["stream"],"audience":"https://calls.example.test/calls/v1",
            "include_proof":true,"operation":{"type":"subscribe"},"expected_identity":owner.identity_id()});
        let initial = owner.operate(authorize_private.clone()).await.unwrap();
        let initial: calls::Command = SignedRecord::parse(
            &STANDARD
                .decode(initial["command"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap()
        .decode()
        .unwrap();
        let device_request = |scope, head| {
            Json(Request {
                space_id: space,
                identity_id: owner.identity_id(),
                device: Some((initial.credential_id, scope, head)),
            })
        };
        assert_eq!(
            admit(
                State(host.clone()),
                headers.clone(),
                device_request(initial.scope, initial.config_id)
            )
            .await
            .unwrap()
            .0["allowed"],
            true
        );
        // A busy Space must defer admission, never allow it without validation
        // or immediately fail and evict a participant from an active call.
        let hosted = host
            .spaces
            .read()
            .await
            .values()
            .find(|entry| entry.config.address.scope.space == space)
            .unwrap()
            .clone();
        let held = hosted.client.lock().await;
        let pending = admit(
            State(host.clone()),
            headers.clone(),
            device_request(initial.scope, initial.config_id),
        );
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut pending)
                .await
                .is_err()
        );
        drop(held);
        assert_eq!(pending.await.unwrap().0["allowed"], true);
        // A stalled service still fails closed within the caller's deadline.
        let held = hosted.client.lock().await;
        assert_eq!(
            admit(
                State(host.clone()),
                headers.clone(),
                device_request(initial.scope, initial.config_id),
            )
            .await
            .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(held);
        drop(hosted);
        let unknown = calls::CallScope {
            stream_id: elo_core::ids::StreamId::from_bytes([91; 16]),
            ..initial.scope
        };
        assert_eq!(
            admit(
                State(host.clone()),
                headers.clone(),
                device_request(unknown, initial.config_id)
            )
            .await
            .unwrap()
            .0["allowed"],
            false
        );
        let card = guest
            .operate(json!({"op":"contact_create", "name":"Guest"}))
            .await
            .unwrap();
        let preview = owner
            .operate(json!({"op":"contact_preview", "link":card["link"]}))
            .await
            .unwrap();
        owner.operate(json!({"op":"contact_add", "link":card["link"], "trusted":true,"confirmed_contact":preview["id"]})).await.unwrap();
        owner.operate(json!({"op":"contact_add_members", "space":private["space"],"stream":private["stream"],
            "request_id":"41".repeat(16),"people":[guest.identity_id()]})).await.unwrap();
        let updated = owner.operate(authorize_private).await.unwrap();
        let updated: calls::Command = SignedRecord::parse(
            &STANDARD
                .decode(updated["command"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap()
        .decode()
        .unwrap();
        assert_ne!(updated.config_id, initial.config_id);
        assert_eq!(
            admit(
                State(host.clone()),
                headers.clone(),
                Json(Request {
                    space_id: space,
                    identity_id: owner.identity_id(),
                    device: Some((updated.credential_id, updated.scope, initial.config_id))
                })
            )
            .await
            .unwrap()
            .0["allowed"],
            false
        );
        assert_eq!(
            admit(
                State(host.clone()),
                headers.clone(),
                Json(Request {
                    space_id: space,
                    identity_id: owner.identity_id(),
                    device: Some((updated.credential_id, updated.scope, updated.config_id))
                })
            )
            .await
            .unwrap()
            .0["allowed"],
            true
        );
        owner
            .operate(json!({"op":"space_role_change","id":space,
            "body":{"revision":0,"kind":"remove_member","target":guest.identity_id()}}))
            .await
            .unwrap();
        assert_eq!(
            admit(State(host.clone()), headers, request(guest.identity_id()))
                .await
                .unwrap()
                .0["allowed"],
            false
        );
        owner.close().await.unwrap();
        guest.close().await.unwrap();
        task.abort();
        let _ = task.await;
        close_host(host).await;
    }
}

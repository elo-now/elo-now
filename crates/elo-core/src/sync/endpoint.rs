//! Stable logical Replica paths. Physical backend addresses never enter a peer.
use crate::record;

pub(crate) fn valid_base(path: &str) -> bool {
    path == "/" || reservation(path).is_some()
}

fn reservation(path: &str) -> Option<&str> {
    let id = path.strip_prefix("/spaces/")?.strip_suffix("/replica/")?;
    record::hex::<32>(id).ok()?;
    (id == id.to_ascii_lowercase()).then_some(id)
}

pub(crate) fn mailbox_prefix(path: &str) -> bool {
    let relative = if let Some(rest) = path.strip_prefix("/spaces/") {
        let (id, relative) = rest.split_once("/replica/").unwrap_or(("", ""));
        if reservation(&format!("/spaces/{id}/replica/")).is_none() {
            return false;
        }
        relative
    } else {
        path.strip_prefix('/').unwrap_or("")
    };
    relative
        .strip_prefix("v1/mailboxes/")
        .and_then(|rest| rest.strip_suffix('/'))
        .is_some_and(|mailbox| record::hex::<32>(mailbox).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_endpoints_have_one_canonical_namespace() {
        let id = "ab".repeat(32);
        assert!(valid_base("/"));
        assert!(valid_base(&format!("/spaces/{id}/replica/")));
        for path in [
            format!("/spaces/{id}/replica"),
            format!("/spaces/{id}/replica/../"),
            format!("/spaces/{}/replica/", id.to_uppercase()),
            "/arbitrary/".into(),
            "/spaces/invalid/replica/".into(),
        ] {
            assert!(!valid_base(&path));
        }
        assert!(mailbox_prefix(&format!("/v1/mailboxes/{id}/")));
        assert!(mailbox_prefix(&format!(
            "/spaces/{id}/replica/v1/mailboxes/{id}/"
        )));
        assert!(!mailbox_prefix("/v1/mailboxes/"));
        assert!(!mailbox_prefix(&format!("/v1/mailboxes/{id}/objects/")));
    }
    #[tokio::test]
    async fn scoped_transport_binds_identity_and_pairing_to_the_full_path() {
        use crate::{
            http,
            ids::ObjectId,
            replica::{ChildMailbox, MailboxDescriptor, ReplicaStore, TransferHint},
            sync::{Peer, PeerDescriptor, access::Signer},
            vault::Session,
        };
        let temp = tempfile::tempdir().unwrap();
        let store = ReplicaStore::open(temp.path().join("replica"))
            .await
            .unwrap();
        let mailbox = store.create_mailbox(1024 * 1024).await.unwrap();
        let (session, _) = Session::create().unwrap();
        store
            .set_space_members(mailbox.mailbox_id, vec![session.identity_id()])
            .await
            .unwrap();
        let listener = http::local_listener("127.0.0.1:0".parse().unwrap(), true)
            .await
            .unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let id = ObjectId::of_ciphertext(b"scoped test");
        let other = ObjectId::of_ciphertext(b"other scope");
        // Deliberately expose the same store at two paths: capabilities alone
        // cannot protect against a proxy replaying a proof under another path.
        let app = http::space_router(store.clone(), id, &origin).merge(http::space_router(
            store.clone(),
            other,
            &origin,
        ));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let descriptor = PeerDescriptor {
            url: format!("{origin}/spaces/{id}/replica/"),
            signing_public_key: crate::record::encode_hex(store.key().as_bytes()),
            mailbox_id: mailbox.mailbox_id,
            read_token: Some(mailbox.read_token.clone()),
            write_token: Some(mailbox.write_token.clone()),
        };
        let peer = Peer::new(descriptor.clone(), true)
            .unwrap()
            .with_identity(&session);
        let payload = b"synthetic scoped ciphertext".to_vec();
        let object = ObjectId::of_ciphertext(&payload);
        peer.post(object, payload.clone(), TransferHint::Eager)
            .await
            .unwrap();
        assert_eq!(
            peer.get(object, payload.len() as u64).await.unwrap(),
            payload
        );
        assert_eq!(peer.inventory(0).await.unwrap().entries.len(), 1);
        let path = format!(
            "/spaces/{id}/replica/v1/mailboxes/{}/inventory?after=0&limit=128",
            mailbox.mailbox_id
        );
        let proof = Signer::new(&session)
            .proof(&crate::sync::access::RequestContext {
                origin: &origin,
                replica: store.key(),
                method: "GET",
                path: &path,
                body: &[],
                transfer: "",
                retention: "",
            })
            .unwrap();
        let response = reqwest::Client::new()
            .get(format!(
                "{origin}{}",
                path.replace(&id.to_string(), &other.to_string())
            ))
            .bearer_auth(&mailbox.read_token)
            .header("x-elo-identity", proof.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        let http = reqwest::Client::new();
        for status in [reqwest::StatusCode::OK, reqwest::StatusCode::FORBIDDEN] {
            let response = http
                .get(format!("{origin}{path}"))
                .bearer_auth(&mailbox.read_token)
                .header("x-elo-identity", &proof)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), status, "a valid proof is single-use");
        }
        let wrong_origin = Signer::new(&session)
            .proof(&crate::sync::access::RequestContext {
                origin: "https://attacker.example",
                replica: store.key(),
                method: "GET",
                path: &path,
                body: &[],
                transfer: "",
                retention: "",
            })
            .unwrap();
        let response = http
            .get(format!("{origin}{path}"))
            .header("host", "attacker.example")
            .header("x-forwarded-host", "attacker.example")
            .bearer_auth(&mailbox.read_token)
            .header("x-elo-identity", wrong_origin)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "proxy headers cannot replace configured origin"
        );
        let child = ChildMailbox {
            descriptor: MailboxDescriptor::random().unwrap(),
            quota_bytes: 1024,
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 600_000,
        };
        peer.create_child(&child).await.unwrap();
        let child_peer = Peer::new(
            PeerDescriptor {
                mailbox_id: child.descriptor.mailbox_id,
                read_token: Some(child.descriptor.read_token),
                write_token: Some(child.descriptor.write_token),
                ..descriptor.clone()
            },
            true,
        )
        .unwrap()
        .with_identity(&session);
        let delegation = child_peer.pairing_access().unwrap();
        let linked = Peer::new(child_peer.descriptor.clone(), true)
            .unwrap()
            .with_delegated_access(delegation.clone());
        assert!(linked.inventory(0).await.is_ok());
        let wrong = Peer::new(
            PeerDescriptor {
                url: format!("{origin}/spaces/{other}/replica/"),
                ..linked.descriptor.clone()
            },
            true,
        )
        .unwrap()
        .with_delegated_access(delegation.clone());
        assert!(wrong.inventory(0).await.is_err());
        let parent = Peer::new(descriptor.clone(), true)
            .unwrap()
            .with_delegated_access(delegation);
        assert!(parent.inventory(0).await.is_err());
        let other_key = ReplicaStore::open(temp.path().join("wrong-key"))
            .await
            .unwrap();
        let wrong_pin = Peer::new(
            PeerDescriptor {
                signing_public_key: crate::record::encode_hex(other_key.key().as_bytes()),
                ..descriptor
            },
            true,
        )
        .unwrap()
        .with_identity(&session);
        assert!(
            wrong_pin
                .post(object, payload, TransferHint::Eager)
                .await
                .is_err()
        );
        store
            .set_space_members(mailbox.mailbox_id, vec![])
            .await
            .unwrap();
        assert!(linked.inventory(0).await.is_err());
        server.abort();
        let _ = server.await;
    }
}

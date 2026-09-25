use super::*;
use crate::ids::IdentityId;

impl ReplicaStore {
    /// Fresh managed hosts reject unattributed permanent uploads. Temporary
    /// pairing data is attributed to its authenticated uploader at admission.
    pub async fn require_content_ownership(&self) -> Result<()> {
        self.call(|db| {
            db.connection.execute(
                "INSERT OR REPLACE INTO node_meta(key,value) VALUES('require_content_owner','yes')",
                [],
            )?;
            Ok(())
        })
        .await
    }
    pub async fn has_account_content(&self, identity: IdentityId) -> Result<bool> {
        self.call(move |db| {
            Ok(db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM object_owners WHERE identity_id=?1)",
                [identity.to_string()],
                |r| r.get(0),
            )?)
        })
        .await
    }
    pub async fn supports_account_erasure(&self) -> Result<bool> {
        self.call(|db| {
            Ok(db.connection.query_row(
                "SELECT value='complete' FROM node_meta WHERE key='erasure_coverage'",
                [],
                |row| row.get(0),
            )?)
        })
        .await
    }
    /// A local host operation, never exposed through possession of mailbox tokens.
    /// The host must first verify self-deletion and check current primary ownership.
    pub async fn erase_account_content(
        &self,
        root: MailboxId,
        identity: IdentityId,
    ) -> Result<u64> {
        self.call(move |db| {
            let complete: bool = db.connection.query_row("SELECT value='complete' FROM node_meta WHERE key='erasure_coverage'", [], |row| row.get(0))?;
            if !complete { return Err(ReplicaError::Invalid); }
            let roots: Vec<String> = {
                let mut q = db.connection.prepare("SELECT mailbox_id FROM mailboxes m WHERE NOT EXISTS(SELECT 1 FROM mailbox_delegations d WHERE d.mailbox_id=m.mailbox_id)")?;
                q.query_map([], |row| row.get(0))?.collect::<std::result::Result<_,_>>()?
            };
            if roots != vec![root.to_string()] { return Err(ReplicaError::Invalid); }
            db.connection.pragma_update(None, "secure_delete", "ON")?;
            let time = now()?;
            let tx = db.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("INSERT OR IGNORE INTO erased_identities VALUES(?1,?2)", params![identity.to_string(),time as i64])?;
            tx.execute("INSERT OR IGNORE INTO pruned_objects SELECT ?1, object_id, ?3 FROM object_owners WHERE identity_id=?2", params![root.to_string(),identity.to_string(),time as i64])?;
            let removed = tx.execute("DELETE FROM deliveries WHERE object_id IN (SELECT object_id FROM object_owners WHERE identity_id=?1)", [identity.to_string()])?;
            tx.execute("DELETE FROM objects WHERE NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.object_id=objects.object_id)", [])?;
            tx.execute("DELETE FROM space_access_members WHERE identity_id=?1", [identity.to_string()])?;
            tx.execute("DELETE FROM message_requests WHERE requester_identity=?1", [identity.to_string()])?;
            tx.execute("DELETE FROM message_acceptances WHERE accepting_identity=?1", [identity.to_string()])?;
            tx.commit()?;
            maintenance::reclaim(&db.connection)?;
            Ok(removed as u64)
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, erasure, vault::Session};
    #[tokio::test]
    async fn temporary_pairing_bytes_require_and_retain_authenticated_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplicaStore::open(dir.path().join("replica"))
            .await
            .unwrap();
        store.require_content_ownership().await.unwrap();
        let root = store.create_mailbox(16 * 1024 * 1024).await.unwrap();
        let child = ChildMailbox {
            descriptor: MailboxDescriptor::random().unwrap(),
            quota_bytes: 1024,
            expires_at: now().unwrap() + 60_000,
        };
        store
            .create_child(root.mailbox_id, root.write_token, child.clone())
            .await
            .unwrap();
        let bytes = b"synthetic encrypted pairing chunk".to_vec();
        let object = ObjectId::of_ciphertext(&bytes);
        assert!(
            store
                .post(
                    child.descriptor.mailbox_id,
                    child.descriptor.write_token.clone(),
                    object,
                    bytes.clone(),
                    TransferHint::Eager
                )
                .await
                .is_err()
        );
        let session = Session::create().unwrap().0;
        let identity = session.identity_id();
        store
            .post_authenticated(
                child.descriptor.mailbox_id,
                child.descriptor.write_token,
                object,
                bytes,
                TransferHint::Eager,
                false,
                Some(session.credential().into()),
            )
            .await
            .unwrap();
        assert!(store.has_account_content(identity).await.unwrap());
        store
            .erase_account_content(root.mailbox_id, identity)
            .await
            .unwrap();
        assert!(
            store
                .get(
                    child.descriptor.mailbox_id,
                    child.descriptor.read_token,
                    object
                )
                .await
                .is_err()
        );
        drop(store);
    }
    #[tokio::test]
    async fn erasure_removes_only_account_content_and_rejects_reupload_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replica");
        let store = ReplicaStore::open(&path).await.unwrap();
        store.require_content_ownership().await.unwrap();
        let mailbox = store.create_mailbox(16 * 1024 * 1024).await.unwrap();
        let unowned = b"unattributed message".to_vec();
        assert!(
            store
                .post_classified(
                    mailbox.mailbox_id,
                    mailbox.write_token.clone(),
                    ObjectId::of_ciphertext(&unowned),
                    unowned,
                    TransferHint::Eager,
                    true
                )
                .await
                .is_err()
        );
        let unowned = b"unattributed retained control".to_vec();
        assert!(
            store
                .post_classified(
                    mailbox.mailbox_id,
                    mailbox.write_token.clone(),
                    ObjectId::of_ciphertext(&unowned),
                    unowned,
                    TransferHint::Eager,
                    false
                )
                .await
                .is_err()
        );
        assert!(store.supports_account_erasure().await.unwrap());
        let alice = Session::create().unwrap().0;
        let bob = Session::create().unwrap().0;
        let mut objects = Vec::new();
        for session in [&alice, &bob] {
            let plain = crypto::seal_bytes(
                b"synthetic personal content",
                &[session.age_identity().to_public()],
                1024,
            )
            .unwrap();
            let cipher = erasure::wrap(plain, session.credential(), session.signing_key()).unwrap();
            let id = crate::ids::ObjectId::of_ciphertext(&cipher);
            store
                .post(
                    mailbox.mailbox_id,
                    mailbox.write_token.clone(),
                    id,
                    cipher.clone(),
                    TransferHint::Eager,
                )
                .await
                .unwrap();
            objects.push((id, cipher));
        }
        store
            .set_space_members(
                mailbox.mailbox_id,
                vec![alice.identity_id(), bob.identity_id()],
            )
            .await
            .unwrap();
        assert!(
            store
                .has_account_content(alice.identity_id())
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .erase_account_content(mailbox.mailbox_id, alice.identity_id())
                .await
                .unwrap(),
            1
        );
        assert!(
            !store
                .has_account_content(alice.identity_id())
                .await
                .unwrap()
        );
        assert!(store.has_account_content(bob.identity_id()).await.unwrap());
        assert_eq!(
            store
                .erase_account_content(mailbox.mailbox_id, alice.identity_id())
                .await
                .unwrap(),
            0
        );
        drop(store);
        let store = ReplicaStore::open(path).await.unwrap();
        store
            .set_space_members(
                mailbox.mailbox_id,
                vec![alice.identity_id(), bob.identity_id()],
            )
            .await
            .unwrap();
        assert!(
            store
                .authorize_identity(mailbox.mailbox_id, Some(alice.identity_id()))
                .await
                .is_err()
        );
        assert!(
            store
                .authorize_identity(mailbox.mailbox_id, Some(bob.identity_id()))
                .await
                .is_ok()
        );
        assert!(
            store
                .post(
                    mailbox.mailbox_id,
                    mailbox.write_token.clone(),
                    objects[0].0,
                    objects[0].1.clone(),
                    TransferHint::Eager
                )
                .await
                .is_err()
        );
        store
            .post(
                mailbox.mailbox_id,
                mailbox.write_token,
                objects[1].0,
                objects[1].1.clone(),
                TransferHint::Eager,
            )
            .await
            .unwrap();
    }
}

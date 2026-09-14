use age::secrecy::SecretString;
use elo_core::{
    crypto,
    ids::IdentityId,
    record::SignedRecord,
    vault::{ControllerMode, RecoveryCard, Session, read_private, write_private},
};
fn password() -> SecretString {
    "Public test passphrase only 2026".into()
}
#[test]
fn root_phrase_is_entropy_round_trip_and_never_restores_device_or_membership() {
    let (session, card) = Session::create().unwrap();
    assert_eq!(card.phrase.split_whitespace().count(), 24);
    let restored = Session::recover(&card, session.identity_id()).unwrap();
    assert_eq!(restored.identity_id(), session.identity_id());
    assert_ne!(restored.credential().id(), session.credential().id());
    assert_ne!(
        restored.signing_key().verifying_key(),
        session.signing_key().verifying_key()
    );
    assert!(restored.peers().is_empty());
    assert!(restored.controller_mode() == ControllerMode::Follower);
    let r = SignedRecord::parse(include_bytes!(
        "../../../protocol/fixtures/chat-message-v1.record.bin"
    ))
    .unwrap();
    let c = crypto::seal_record(&r, &[session.age_identity().to_public()]).unwrap();
    assert!(crypto::open_record(&c, restored.age_identity()).is_err());
    assert!(Session::recover(&card, IdentityId::from_bytes([0; 32])).is_err());
    let wrong = RecoveryCard {
        format: card.format.clone(),
        identity_id: card.identity_id,
        phrase: "abandon ".repeat(24),
    };
    assert!(Session::recover(&wrong, card.identity_id).is_err());
    let wrong=RecoveryCard{format:card.format.clone(),identity_id:card.identity_id,phrase:"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into()};
    assert!(Session::recover(&wrong, card.identity_id).is_err());
}
#[test]
fn vault_authentication_private_atomic_files_and_backup_role() {
    let (mut session, card) = Session::create().unwrap();
    let original_space = elo_core::ids::SpaceId::from_bytes([1; 32]);
    session
        .activate_new_space_controller(original_space)
        .unwrap();
    let ciphertext = session.seal(password()).unwrap();
    let reopened = Session::open(&ciphertext, password(), session.identity_id()).unwrap();
    assert_eq!(reopened.credential().id(), session.credential().id());
    assert!(reopened.controller_mode() == ControllerMode::Active);
    let mut restored =
        Session::restore_backup(&ciphertext, password(), session.identity_id()).unwrap();
    assert!(restored.controller_mode() == ControllerMode::Follower);
    assert!(reopened.can_control(original_space));
    assert!(!restored.can_control(original_space));
    let independent_space = elo_core::ids::SpaceId::from_bytes([2; 32]);
    restored
        .activate_new_space_controller(independent_space)
        .unwrap();
    assert!(restored.can_control(independent_space));
    assert!(!restored.can_control(original_space));
    let scoped = Session::open(
        &restored.seal(password()).unwrap(),
        password(),
        restored.identity_id(),
    )
    .unwrap();
    assert!(scoped.can_control(independent_space));
    assert!(!scoped.can_control(original_space));
    assert!(
        Session::open(
            &ciphertext,
            "Incorrect public test password".into(),
            session.identity_id()
        )
        .is_err()
    );
    assert!(
        Session::open(
            &ciphertext[..ciphertext.len() - 1],
            password(),
            session.identity_id()
        )
        .is_err()
    );
    let mut bad = ciphertext.clone();
    let end = bad.len() - 1;
    bad[end] ^= 1;
    assert!(Session::open(&bad, password(), session.identity_id()).is_err());
    assert!(
        !ciphertext
            .windows(card.phrase.len())
            .any(|w| w == card.phrase.as_bytes())
    );
    assert!(
        !ciphertext
            .windows(32)
            .any(|w| w == session.signing_key().to_bytes())
    );
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("vault.age");
    write_private(&path, &ciphertext, false).unwrap();
    assert_eq!(read_private(&path).unwrap(), ciphertext);
    assert!(write_private(&path, b"do not replace", false).is_err());
    assert_eq!(read_private(&path).unwrap(), ciphertext);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.path().join("link.age");
        symlink(&path, &link).unwrap();
        assert!(read_private(&link).is_err());
        assert!(write_private(&link, b"x", true).is_err());
    }
    // Rewrite only the public KDF parameter; library rejects excessive work before
    // trying to authenticate/decrypt. No expensive test factor is ever evaluated.
    let line_end = ciphertext
        .iter()
        .enumerate()
        .find(|(i, b)| **b == b'\n' && *i > 22)
        .unwrap()
        .0;
    let header = std::str::from_utf8(&ciphertext[..line_end]).unwrap();
    let (prefix, _factor) = header.rsplit_once(' ').unwrap();
    let mut excessive = format!("{prefix} 63").into_bytes();
    excessive.extend_from_slice(&ciphertext[line_end..]);
    assert!(Session::open(&excessive, password(), session.identity_id()).is_err());
}

#[test]
fn planned_transfer_retires_source_and_old_backup_cannot_auto_activate() {
    let (mut source, _) = Session::create().unwrap();
    source
        .activate_new_space_controller(elo_core::ids::SpaceId::from_bytes([1; 32]))
        .unwrap();
    let backup = source.seal(password()).unwrap();
    let mut destination =
        Session::restore_backup(&backup, password(), source.identity_id()).unwrap();
    let mut older = Session::restore_backup(&backup, password(), source.identity_id()).unwrap();
    assert_ne!(destination.transfer_nonce(), older.transfer_nonce());
    let dir = tempfile::TempDir::new().unwrap();
    let source_path = dir.path().join("source.age");
    write_private(&source_path, &backup, false).unwrap();
    let space = elo_core::ids::SpaceId::from_bytes([1; 32]);
    let head = elo_core::ids::RecordId::from_bytes([2; 32]);
    let ticket = source
        .retire_for_transfer(
            &source_path,
            password(),
            destination.transfer_nonce(),
            space,
            head,
        )
        .unwrap();
    let reopened = Session::open(
        &read_private(&source_path).unwrap(),
        password(),
        source.identity_id(),
    )
    .unwrap();
    assert!(reopened.controller_mode() == ControllerMode::Retired);
    assert!(older.activate_transfer(&ticket, space, head).is_err());
    destination.activate_transfer(&ticket, space, head).unwrap();
    assert!(destination.controller_mode() == ControllerMode::Active);
    assert!(destination.can_control(space));
    assert!(!destination.can_control(elo_core::ids::SpaceId::from_bytes([9; 32])));
    assert!(destination.activate_transfer(&ticket, space, head).is_err());
}

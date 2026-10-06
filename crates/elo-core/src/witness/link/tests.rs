use super::*;
use crate::{
    app::team::TeamScope,
    authority::{Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig},
    identity::DeviceCredential,
    ids::{RecordId, SpaceId, StreamId},
};

const API: &str = "https://api.example.test";
const NOW: u64 = 2_000;

fn seed() -> InvitationSeed {
    InvitationSeed(Zeroizing::new([9; 32]))
}

fn signed<T: Serialize>(value: &T, key: &SigningKey) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(value).unwrap(), key).unwrap()
}

struct Fixture {
    owner: SigningKey,
    pin: WitnessPin,
    descriptor: Descriptor,
}

fn fixture() -> Fixture {
    let root = SigningKey::from_bytes(&[1; 32]);
    let owner = SigningKey::from_bytes(&[2; 32]);
    let age = age::x25519::Identity::generate();
    let credential =
        DeviceCredential::issue(&root, &owner.verifying_key(), &age.to_public()).unwrap();
    let witness = SigningKey::from_bytes(&[3; 32]);
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(witness.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let genesis = signed(
        &SpaceGenesis {
            v: 4,
            kind: "space.genesis".into(),
            nonce: record::random_hex::<16>().unwrap(),
            issuer_identity: credential.identity(),
            owners: vec![Owner {
                identity_id: credential.identity(),
                root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            }],
            controller_credential_id: credential.id(),
            witness: Some(pin.clone()),
        },
        &owner,
    );
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &root.verifying_key(),
        credential.clone(),
        StreamId::from_bytes([4; 16]),
    )
    .unwrap();
    let config = StreamConfig {
        v: 4,
        kind: "stream.config".into(),
        nonce: record::random_hex::<16>().unwrap(),
        space_id: authority.space(),
        stream_id: authority.stream(),
        sequence: 1,
        previous_config_id: None,
        controller_credential_id: credential.id(),
        members: vec![Member {
            identity_id: credential.identity(),
            identity_type: "HUMAN".into(),
            root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            capabilities: vec![
                Capability::Read,
                Capability::Post,
                Capability::ShareHistory,
                Capability::Manage,
            ],
            credential_ids: vec![credential.id()],
            external: false,
        }],
        owner_credential_ids: vec![credential.id()],
        action: ConfigAction {
            operation: "create".into(),
            actor_identity: credential.identity(),
            request_record_id: None,
        },
        chat_kind: Some(ChatKind::Chat),
        recovery: None,
        witness_evidence: None,
    };
    authority
        .apply_config(config.sign(&owner).unwrap())
        .unwrap();
    let invitation_public_key =
        record::encode_hex(seed().invitation_public_key().unwrap().as_bytes());
    let policy = signed(
        &WitnessInvitationPolicy {
            v: 1,
            kind: "witness.invitation".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            authority_head: authority.head_id().unwrap(),
            issuer_credential_id: credential.id(),
            invitation_public_key: invitation_public_key.clone(),
            not_before_ms: 1_000,
            expires_at_ms: 10_000,
            require_approval: true,
            max_uses: 3,
            witness_key_generation: 1,
        },
        &owner,
    );
    let descriptor = Descriptor {
        v: 1,
        kind: "witness.invitation.descriptor".into(),
        name: "Test Space".into(),
        address: SpaceAddress {
            url: format!("{API}/spaces/{}/team/v1/spaces", authority.space()),
            scope: TeamScope {
                space: authority.space(),
                stream: authority.stream(),
                root: record::encode_hex(root.verifying_key().as_bytes()),
                controller: credential.id(),
            },
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours6,
            service_credential: Some(STANDARD.encode(credential.record().bytes())),
        },
        witness: pin.clone(),
        proof: authority.call_proof().unwrap(),
        policy: STANDARD.encode(policy.bytes()),
        invitation_public_key,
        hosting_profile: None,
    };
    Fixture {
        owner,
        pin,
        descriptor,
    }
}

fn encrypted(f: &Fixture) -> EncryptedInvitation {
    seal(&f.descriptor, &f.owner, seed(), API, &f.pin, NOW).unwrap()
}

fn unchecked(f: &Fixture, descriptor: &Descriptor) -> EncryptedInvitation {
    encrypt_signed(&signed(descriptor, &f.owner), seed()).unwrap()
}

fn hosting(f: &Fixture) -> HostingProfile {
    HostingProfile {
        v: 1,
        kind: "hosting.configuration".into(),
        revision: 1,
        name: "Private test hosting".into(),
        signing_public_key: record::encode_hex(
            SigningKey::from_bytes(&[11; 32]).verifying_key().as_bytes(),
        ),
        create_url: format!("{API}/spaces/v1/create"),
        witness: f.pin.clone(),
        storage: None,
        push_url: Some(format!("{API}/")),
        call_url: Some(format!("{API}/calls/v1")),
        message_lifetimes: vec![crate::message_retention::MessageRetention::Hours6],
        default_message_lifetime: crate::message_retention::MessageRetention::Hours6,
    }
}

fn self_contained(f: &Fixture) -> EncryptedInvitation {
    let mut descriptor = f.descriptor.clone();
    let profile = hosting(f);
    descriptor.hosting_profile = Some(profile.clone());
    let mut invitation = seal(&descriptor, &f.owner, seed(), API, &f.pin, NOW).unwrap();
    invitation.link = invitation
        .link
        .with_hosting_origin(&profile.id(), &format!("{API}/"))
        .unwrap();
    invitation
}

#[test]
fn v3_roundtrip_verifies_owner_bound_hosting_without_local_configuration() {
    let f = fixture();
    let invitation = self_contained(&f);
    let url = invitation.link.to_url();
    let bytes = URL_SAFE_NO_PAD.decode(&url[PREFIX.len()..]).unwrap();
    assert_eq!(bytes[0], 3);
    assert_eq!(bytes.len(), 97 + format!("{API}/").len());
    let parsed = InvitationLink::parse(&url).unwrap();
    assert_eq!(parsed.hosting_origin(), Some(format!("{API}/").as_str()));
    let (verified, profile) = parsed
        .open_with_embedded_hosting(&invitation.ciphertext, NOW)
        .unwrap();
    assert_eq!(profile, hosting(&f));
    assert_eq!(parsed.hosting_id(), Some(profile.id().as_str()));
    assert_eq!(
        verified.descriptor().hosting_profile.as_ref(),
        Some(&profile)
    );
    assert!(
        parsed
            .open(&invitation.ciphertext, API, &f.pin, NOW)
            .is_ok()
    );
    assert!(
        parsed
            .open(
                &invitation.ciphertext,
                "https://other.example/",
                &f.pin,
                NOW
            )
            .is_err()
    );
    assert!(
        parsed
            .open_with_embedded_hosting(&invitation.ciphertext, 10_000)
            .is_err()
    );
}

#[test]
fn v3_routing_selectors_and_embedded_profile_cannot_be_substituted() {
    let f = fixture();
    let invitation = self_contained(&f);
    for (id, origin) in [
        (record::encode_hex(&[17; 32]), format!("{API}/")),
        (hosting(&f).id(), "https://other.example/".into()),
    ] {
        let parsed = InvitationLink::parse(&invitation.link.to_url())
            .unwrap()
            .with_hosting_origin(&id, &origin)
            .unwrap();
        assert!(
            parsed
                .open_with_embedded_hosting(&invitation.ciphertext, NOW)
                .is_err()
        );
        assert!(
            parsed
                .open(&invitation.ciphertext, API, &f.pin, NOW)
                .is_err()
        );
    }
    for case in 0..5 {
        let mut descriptor = f.descriptor.clone();
        let mut profile = hosting(&f);
        match case {
            0 => profile.create_url = "https://other.example/spaces/v1/create".into(),
            1 => {
                profile.witness.public_key =
                    record::encode_hex(SigningKey::from_bytes(&[12; 32]).verifying_key().as_bytes())
            }
            2 => {
                profile.signing_public_key =
                    record::encode_hex(SigningKey::from_bytes(&[12; 32]).verifying_key().as_bytes())
            }
            3 => profile.revision = 0,
            _ => (),
        }
        descriptor.hosting_profile = (case != 4).then_some(profile);
        let mut forged = unchecked(&f, &descriptor);
        forged.link = forged
            .link
            .with_hosting_origin(&hosting(&f).id(), &format!("{API}/"))
            .unwrap();
        assert!(
            forged
                .link
                .open_with_embedded_hosting(&forged.ciphertext, NOW)
                .is_err()
        );
        assert!(
            forged
                .link
                .open(&forged.ciphertext, API, &f.pin, NOW)
                .is_err()
        );
    }

    // Knowing the seed permits encryption but never an owner-authorized change
    // to the deployment (including services outside the API origin).
    let mut descriptor = f.descriptor.clone();
    let mut profile = hosting(&f);
    profile.call_url = Some("https://attacker.example/calls/v1".into());
    descriptor.hosting_profile = Some(profile);
    let mut forged =
        encrypt_signed(&signed(&descriptor, &seed().signing_key().unwrap()), seed()).unwrap();
    forged.link = forged
        .link
        .with_hosting_origin(&hosting(&f).id(), &format!("{API}/"))
        .unwrap();
    assert!(
        forged
            .link
            .open_with_embedded_hosting(&forged.ciphertext, NOW)
            .is_err()
    );
}

#[test]
fn v3_origin_encoding_is_bounded_canonical_and_not_an_arbitrary_url() {
    let f = fixture();
    for origin in [
        "https://api.example.test",
        "https://API.example.test/",
        "https://api.example.test:443/",
        "http://api.example.test/",
        "https://user@api.example.test/",
        "https://api.example.test/path",
        "https://api.example.test/?query=x",
        "https://api.example.test/#fragment",
        "https://api.example.test/\n",
    ] {
        assert!(
            encrypted(&f)
                .link
                .with_hosting_origin(&hosting(&f).id(), origin)
                .is_err()
        );
        let mut bytes = URL_SAFE_NO_PAD
            .decode(&self_contained(&f).link.to_url()[PREFIX.len()..])
            .unwrap();
        bytes.truncate(97);
        bytes.extend_from_slice(origin.as_bytes());
        assert!(
            InvitationLink::parse(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))).is_err()
        );
    }
    for suffix in [vec![], vec![0xff], vec![b'a'; MAX_HOSTING_ORIGIN_BYTES + 1]] {
        let mut bytes = URL_SAFE_NO_PAD
            .decode(&self_contained(&f).link.to_url()[PREFIX.len()..])
            .unwrap();
        bytes.truncate(97);
        bytes.extend(suffix);
        assert!(
            InvitationLink::parse(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))).is_err()
        );
    }
    let mut invitation = self_contained(&f);
    invitation.ciphertext[30] ^= 1;
    assert!(
        invitation
            .link
            .open_with_embedded_hosting(&invitation.ciphertext, NOW)
            .is_err()
    );
    invitation.link.ciphertext_id = Sha256::digest(&invitation.ciphertext).into();
    assert!(
        invitation
            .link
            .open_with_embedded_hosting(&invitation.ciphertext, NOW)
            .is_err()
    );
    assert!(matches!(
        invitation
            .link
            .open_with_embedded_hosting(&vec![0; MAX_CIPHERTEXT_BYTES + 1], NOW),
        Err(LinkError::DescriptorTooLarge)
    ));
}

#[test]
fn resealing_legacy_offers_preserves_policy_seed_and_the_old_usable_link() {
    let f = fixture();
    let profile = hosting(&f);
    for version in [1, 2] {
        let mut old = encrypted(&f);
        if version == 2 {
            old.link = old.link.with_hosting(&profile.id()).unwrap();
        }
        let old_url = old.link.to_url();
        assert!(old.link.hosting_origin().is_none());
        assert!(
            old.link
                .open_with_embedded_hosting(&old.ciphertext, NOW)
                .is_err()
        );
        let upgraded = old
            .link
            .reseal_with_hosting(&old.ciphertext, &profile, &f.owner, API, &f.pin, NOW)
            .unwrap();
        let (verified, attached) = upgraded
            .link
            .open_with_embedded_hosting(&upgraded.ciphertext, NOW)
            .unwrap();
        assert_eq!(attached, profile);
        assert_eq!(verified.descriptor().policy, f.descriptor.policy);
        assert_eq!(verified.policy().expires_at_ms, 10_000);
        assert_eq!(verified.policy().max_uses, 3);
        assert_eq!(
            verified.invitation_signing_key().verifying_key(),
            seed().invitation_public_key().unwrap()
        );
        assert_ne!(upgraded.link.ciphertext_id(), old.link.ciphertext_id());
        assert_eq!(old.link.to_url().as_str(), old_url.as_str());
        assert!(old.link.open(&old.ciphertext, API, &f.pin, NOW).is_ok());
        assert!(
            old.link
                .reseal_with_hosting(
                    &old.ciphertext,
                    &profile,
                    &SigningKey::from_bytes(&[25; 32]),
                    API,
                    &f.pin,
                    NOW
                )
                .is_err()
        );
        assert!(
            old.link
                .reseal_with_hosting(&old.ciphertext, &profile, &f.owner, API, &f.pin, 10_000)
                .is_err()
        );
    }
}

#[test]
fn routed_link_selects_a_host_without_changing_crypto_or_trusting_new_keys() {
    let f = fixture();
    let invitation = encrypted(&f);
    let id = record::encode_hex(&[4; 32]);
    let link = invitation.link.with_hosting(&id).unwrap();
    let encoded = link.to_url();
    assert_eq!(encoded.len(), PREFIX.len() + 130);
    let parsed = InvitationLink::parse(&encoded).unwrap();
    assert_eq!(parsed.hosting_id(), Some(id.as_str()));
    assert!(
        parsed
            .open(&invitation.ciphertext, API, &f.pin, NOW)
            .is_ok()
    );
    assert!(
        parsed
            .open(
                &invitation.ciphertext,
                "https://other.example/",
                &f.pin,
                NOW
            )
            .is_err()
    );
}

#[test]
fn short_link_roundtrip_exposes_only_verified_pinned_descriptor() {
    let f = fixture();
    let invitation = encrypted(&f);
    let url = invitation.link.to_url();
    assert_eq!(url.len(), PREFIX.len() + FRAGMENT_LENGTH);
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&url[PREFIX.len()..]).unwrap().len(),
        65
    );
    let link = InvitationLink::parse(&url).unwrap();
    assert_eq!(
        link.ciphertext_id(),
        record::encode_hex(&Sha256::digest(&invitation.ciphertext))
    );
    let verified = link.open(&invitation.ciphertext, API, &f.pin, NOW).unwrap();
    assert_eq!(verified.descriptor().address.url, f.descriptor.address.url);
    assert_eq!(
        verified.authority().space(),
        f.descriptor.address.scope.space
    );
    assert!(verified.policy().require_approval);
    assert_eq!(verified.policy().max_uses, 3);
    assert_eq!(
        verified.invitation_signing_key().verifying_key(),
        seed().invitation_public_key().unwrap()
    );
    let public_ciphertext = &invitation.ciphertext;
    for secret_or_plaintext in [
        seed().0.as_slice().to_vec(),
        f.descriptor.policy.as_bytes().to_vec(),
        b"folder_link".to_vec(),
        b"write_auth".to_vec(),
        b"invitation_public_key".to_vec(),
    ] {
        assert!(
            !public_ciphertext
                .windows(secret_or_plaintext.len())
                .any(|x| x == secret_or_plaintext)
        );
    }
    let descriptor_json = serde_json::to_value(&f.descriptor).unwrap();
    assert!(descriptor_json.get("seed").is_none());
    assert!(descriptor_json.get("token").is_none());
}

#[test]
fn hkdf_separates_admission_key_from_encryption_and_seed_and_nonces_are_fresh() {
    let raw = seed();
    assert_ne!(
        raw.derive(ENCRYPTION_INFO).unwrap().as_slice(),
        raw.derive(SIGNING_INFO).unwrap().as_slice()
    );
    assert_ne!(
        raw.derive(ENCRYPTION_INFO).unwrap().as_slice(),
        raw.0.as_slice()
    );
    assert_ne!(
        raw.invitation_public_key().unwrap(),
        SigningKey::from_bytes(&raw.0).verifying_key()
    );
    let f = fixture();
    let first = encrypted(&f);
    let second = encrypted(&f);
    assert_ne!(&first.ciphertext[1..25], &second.ciphertext[1..25]);
    assert_ne!(first.link.ciphertext_id(), second.link.ciphertext_id());
}

#[test]
fn ciphertext_hash_authentication_seed_and_size_fail_closed() {
    let f = fixture();
    let mut invitation = encrypted(&f);
    for length in [0, 25, 112, invitation.ciphertext.len() - 1] {
        assert!(
            invitation
                .link
                .open(&invitation.ciphertext[..length], API, &f.pin, NOW)
                .is_err()
        );
    }
    let oversized = vec![0; MAX_CIPHERTEXT_BYTES + 1];
    assert!(invitation.link.open(&oversized, API, &f.pin, NOW).is_err());
    invitation.ciphertext[30] ^= 1;
    assert!(
        invitation
            .link
            .open(&invitation.ciphertext, API, &f.pin, NOW)
            .is_err()
    );
    // Even a replacement storage ID cannot bypass the AEAD tag.
    invitation.link.ciphertext_id = Sha256::digest(&invitation.ciphertext).into();
    assert!(
        invitation
            .link
            .open(&invitation.ciphertext, API, &f.pin, NOW)
            .is_err()
    );
    let mut invitation = encrypted(&f);
    invitation.link.seed.0[0] ^= 1;
    assert!(
        invitation
            .link
            .open(&invitation.ciphertext, API, &f.pin, NOW)
            .is_err()
    );
}

#[test]
fn oversized_descriptor_and_download_report_a_typed_limit() {
    let f = fixture();
    let invitation = encrypted(&f);
    assert!(matches!(
        invitation
            .link
            .open(&vec![0; MAX_CIPHERTEXT_BYTES + 1], API, &f.pin, NOW),
        Err(LinkError::DescriptorTooLarge)
    ));
    let mut descriptor = f.descriptor.clone();
    descriptor.proof.genesis = "A".repeat(record::MAX_RECORD);
    assert!(matches!(
        seal(&descriptor, &f.owner, seed(), API, &f.pin, NOW),
        Err(LinkError::DescriptorTooLarge)
    ));
}

#[test]
fn supplied_deployment_pins_are_required_even_for_valid_owner_records() {
    let f = fixture();
    let invitation = encrypted(&f);
    for api in [
        "https://other.example.test",
        "http://api.example.test",
        "https://api.example.test/path",
        "https://api.example.test/?query=x",
        " https://api.example.test",
    ] {
        assert!(
            invitation
                .link
                .open(&invitation.ciphertext, api, &f.pin, NOW)
                .is_err()
        );
    }
    let mut wrong = f.pin.clone();
    wrong.public_key =
        record::encode_hex(SigningKey::from_bytes(&[8; 32]).verifying_key().as_bytes());
    assert!(
        invitation
            .link
            .open(&invitation.ciphertext, API, &wrong, NOW)
            .is_err()
    );
    wrong = f.pin.clone();
    wrong.url = "https://other.example.test/witness/v1".into();
    assert!(
        invitation
            .link
            .open(&invitation.ciphertext, API, &wrong, NOW)
            .is_err()
    );
    wrong = f.pin.clone();
    wrong.key_generation += 1;
    assert!(
        invitation
            .link
            .open(&invitation.ciphertext, API, &wrong, NOW)
            .is_err()
    );
}

#[test]
fn possessing_the_invitation_seed_cannot_resign_the_owner_address_or_policy() {
    let f = fixture();
    let mut altered = f.descriptor.clone();
    altered.address.url = altered
        .address
        .url
        .replace(API, "https://attacker.example.test");
    let attacker_signed = signed(&altered, &seed().signing_key().unwrap());
    let invitation = encrypt_signed(&attacker_signed, seed()).unwrap();
    assert!(
        invitation
            .link
            .open(
                &invitation.ciphertext,
                "https://attacker.example.test",
                &f.pin,
                NOW
            )
            .is_err()
    );
    assert!(
        seal(
            &f.descriptor,
            &seed().signing_key().unwrap(),
            seed(),
            API,
            &f.pin,
            NOW
        )
        .is_err()
    );
    let mut altered = f.descriptor.clone();
    let policy_record = SignedRecord::parse(&STANDARD.decode(&altered.policy).unwrap()).unwrap();
    let policy: WitnessInvitationPolicy = policy_record.decode().unwrap();
    altered.policy = STANDARD.encode(signed(&policy, &seed().signing_key().unwrap()).bytes());
    let invitation = unchecked(&f, &altered);
    assert!(
        invitation
            .link
            .open(&invitation.ciphertext, API, &f.pin, NOW)
            .is_err()
    );
}

#[test]
fn identity_scope_and_derived_public_key_must_match_every_binding() {
    let f = fixture();
    let mut cases = Vec::new();
    let mut bad = f.descriptor.clone();
    bad.address.scope.space = SpaceId::from_bytes([8; 32]);
    cases.push(bad);
    let mut bad = f.descriptor.clone();
    bad.address.scope.stream = StreamId::from_bytes([8; 16]);
    cases.push(bad);
    let mut bad = f.descriptor.clone();
    bad.address.scope.controller = RecordId::from_bytes([8; 32]);
    cases.push(bad);
    let mut bad = f.descriptor.clone();
    bad.address.scope.root = f.pin.public_key.clone();
    cases.push(bad);
    let mut bad = f.descriptor.clone();
    bad.address.url = format!("{API}/spaces/not-a-canonical-hosting-id/team/v1/spaces");
    cases.push(bad);
    let mut bad = f.descriptor.clone();
    bad.invitation_public_key = f.pin.public_key.clone();
    cases.push(bad);
    let mut bad = f.descriptor.clone();
    bad.proof.genesis = f.descriptor.policy.clone();
    cases.push(bad);
    let mut bad = f.descriptor.clone();
    bad.policy = "malformed".into();
    cases.push(bad);
    for bad in cases {
        let invitation = unchecked(&f, &bad);
        assert!(
            invitation
                .link
                .open(&invitation.ciphertext, API, &f.pin, NOW)
                .is_err()
        );
    }
}

#[test]
fn owner_policy_time_use_count_and_invitation_key_are_enforced() {
    let f = fixture();
    let invitation = encrypted(&f);
    for now in [999, 10_000] {
        assert!(
            invitation
                .link
                .open(&invitation.ciphertext, API, &f.pin, now)
                .is_err()
        );
    }
    let original: WitnessInvitationPolicy =
        SignedRecord::parse(&STANDARD.decode(&f.descriptor.policy).unwrap())
            .unwrap()
            .decode()
            .unwrap();
    for case in 0..6 {
        let mut policy = original.clone();
        match case {
            0 => policy.max_uses = 0,
            1 => policy.expires_at_ms = policy.not_before_ms,
            2 => policy.invitation_public_key = f.pin.public_key.clone(),
            3 => policy.witness_key_generation += 1,
            4 => policy.space_id = SpaceId::from_bytes([8; 32]),
            _ => policy.authority_head = RecordId::from_bytes([8; 32]),
        }
        let mut descriptor = f.descriptor.clone();
        descriptor.policy = STANDARD.encode(signed(&policy, &f.owner).bytes());
        let invitation = unchecked(&f, &descriptor);
        assert!(
            invitation
                .link
                .open(&invitation.ciphertext, API, &f.pin, NOW)
                .is_err()
        );
    }
}

#[test]
fn malformed_link_encodings_and_descriptor_schema_are_rejected() {
    let f = fixture();
    let invitation = encrypted(&f);
    let url = invitation.link.to_url();
    let url = url.as_str();
    for invalid in [
        format!(" {url}"),
        format!("{url}\n"),
        format!("{url}="),
        format!("{url}#x"),
        url.replace("elo.now", "other.example.test"),
        url.replace("https://", "http://"),
        url.replace("/join#", "/join?x#"),
        format!("{PREFIX}{}", "A".repeat(88)),
        String::from("elo://space/v1#old"),
    ] {
        assert!(InvitationLink::parse(&invalid).is_err());
    }
    let mut bytes = URL_SAFE_NO_PAD.decode(&url[PREFIX.len()..]).unwrap();
    bytes[0] = 2;
    assert!(InvitationLink::parse(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))).is_err());
    let mut value = serde_json::to_value(&f.descriptor).unwrap();
    value["unexpected_field"] = serde_json::json!(true);
    let invitation = encrypt_signed(&signed(&value, &f.owner), seed()).unwrap();
    assert!(
        invitation
            .link
            .open(&invitation.ciphertext, API, &f.pin, NOW)
            .is_err()
    );
}

#[test]
fn owner_signed_hosting_allocation_id_can_differ_from_cryptographic_space() {
    let f = fixture();
    let mut descriptor = f.descriptor.clone();
    descriptor.address.url = format!("{API}/spaces/{}/team/v1/spaces", "ab".repeat(32));
    let invitation = seal(&descriptor, &f.owner, seed(), API, &f.pin, NOW).unwrap();
    let verified = invitation
        .link
        .open(&invitation.ciphertext, API, &f.pin, NOW)
        .unwrap();
    assert_eq!(verified.descriptor().address.url, descriptor.address.url);
    assert_eq!(
        verified.authority().space(),
        f.descriptor.address.scope.space
    );
}

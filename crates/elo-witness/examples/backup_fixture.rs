//! Synthetic backup acceptance only. No production keys, network or activation files.
//! `create ROOT` keeps its SQLite connection open until one input line is read.
//! `verify DATA KEY ANCHOR` tests sealed reopening and an independently retained anchor.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{
        Authority, Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig,
        WitnessInvitationPolicy, WitnessPin,
    },
    identity::DeviceCredential,
    ids::StreamId,
    record::{self, SignedRecord},
    vault,
    witness::{Command, Operation, Position, Receipt, Request},
};
use elo_witness::{
    engine::Engine,
    journal::{Activation, Journal},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    path::Path,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const URL: &str = "https://backup-fixture.invalid/witness/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    pin: WitnessPin,
    position: Position,
    receipt: String,
}

fn signed(body: &impl Serialize, key: &SigningKey) -> Result<SignedRecord> {
    Ok(SignedRecord::sign(&serde_json::to_vec(body)?, key)?)
}

fn private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    Ok(vault::write_private(
        path,
        &serde_json::to_vec(value)?,
        false,
    )?)
}

fn create(root: &Path) -> Result<()> {
    // All keys are deliberately public test seeds; never use this example to
    // provision a real witness. Refuse existing destinations.
    std::fs::create_dir(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let owner_root = SigningKey::from_bytes(&[1; 32]);
    let owner = SigningKey::from_bytes(&[2; 32]);
    let witness = SigningKey::from_bytes(&[5; 32]);
    let invitation = SigningKey::from_bytes(&[6; 32]);
    let age = age::x25519::Identity::generate();
    let credential =
        DeviceCredential::issue(&owner_root, &owner.verifying_key(), &age.to_public())?;
    let pin = WitnessPin {
        url: URL.into(),
        public_key: record::encode_hex(witness.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let stream = StreamId::from_bytes([7; 16]);
    let genesis = signed(
        &SpaceGenesis {
            v: 4,
            kind: "space.genesis".into(),
            nonce: stream.to_string(),
            issuer_identity: credential.identity(),
            owners: vec![Owner {
                identity_id: credential.identity(),
                root_public_key: record::encode_hex(owner_root.verifying_key().as_bytes()),
            }],
            controller_credential_id: credential.id(),
            witness: Some(pin.clone()),
        },
        &owner,
    )?;
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse()?,
        &owner_root.verifying_key(),
        credential.clone(),
        stream,
    )?;
    authority.apply_config(
        StreamConfig {
            v: 4,
            kind: "stream.config".into(),
            nonce: record::random_hex::<16>()?,
            space_id: authority.space(),
            stream_id: stream,
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: credential.id(),
            members: vec![Member {
                identity_id: credential.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: record::encode_hex(owner_root.verifying_key().as_bytes()),
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
        }
        .sign(&owner)?,
    )?;
    let request = |operation: Operation| -> Result<Request> {
        let now = elo_witness::now_ms()?;
        let command = Command {
            v: 1,
            kind: "witness.command".into(),
            nonce: record::random_hex::<32>()?,
            audience: URL.into(),
            space_id: authority.space(),
            stream_id: stream,
            credential_id: credential.id(),
            authority_head: authority.head_id().ok_or("Missing head")?,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            operation,
        };
        Ok(Request {
            command: STANDARD.encode(signed(&command, &owner)?.bytes()),
            invitation_signature: None,
            proof: None,
            registration_work: None,
        })
    };
    let key = root.join("synthetic-key.bin");
    vault::write_private(&key, &witness.to_bytes(), false)?;
    private_json(&root.join("pin.json"), &pin)?;
    let now = elo_witness::now_ms()?;
    let mut journal = Journal::open(&root.join("data"), &key, pin.clone(), now)?;
    if journal.ready(now) {
        return Err("A new journal was unexpectedly active".into());
    }
    journal.activate(
        Activation {
            startup_nonce: journal.startup()?.startup_nonce,
            // This fixture creates a new, empty journal. No observed position is
            // used as an authority for restoring an existing journal.
            expected_position: Position {
                sequence: 0,
                record_id: None,
            },
            public_key: pin.public_key.clone(),
            key_generation: 1,
            expires_at_ms: now + 60_000,
        },
        now,
    )?;
    let mut engine = Engine { journal };
    let mut registration = request(Operation::Register)?;
    registration.proof = Some(authority.call_proof()?);
    registration.solve_registration_work()?;
    engine.apply(registration, "127.0.0.1".parse()?, elo_witness::now_ms()?)?;
    // Keep a correctly signed older snapshot for the independent-anchor test.
    std::fs::create_dir(root.join("old-data"))?;
    let source = rusqlite::Connection::open_with_flags(
        root.join("data/witness.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    source.execute(
        "VACUUM main INTO ?1",
        [root
            .join("old-data/witness.sqlite")
            .to_str()
            .ok_or("Invalid fixture path")?],
    )?;
    drop(source);
    let now = elo_witness::now_ms()?;
    let policy = signed(
        &WitnessInvitationPolicy {
            v: 1,
            kind: "witness.invitation".into(),
            nonce: record::random_hex::<16>()?,
            space_id: authority.space(),
            stream_id: stream,
            authority_head: authority.head_id().ok_or("Missing head")?,
            issuer_credential_id: credential.id(),
            invitation_public_key: record::encode_hex(invitation.verifying_key().as_bytes()),
            not_before_ms: now.saturating_sub(1000),
            expires_at_ms: now + 3_600_000,
            require_approval: true,
            max_uses: 1,
            witness_key_generation: 1,
        },
        &owner,
    )?;
    engine.apply(
        request(Operation::RegisterInvitation {
            policy: STANDARD.encode(policy.bytes()),
        })?,
        "127.0.0.1".parse()?,
        elo_witness::now_ms()?,
    )?;
    let response = engine.apply(
        request(Operation::RevokeInvitation {
            policy_id: policy.id(),
        })?,
        "127.0.0.1".parse()?,
        elo_witness::now_ms()?,
    )?;
    let receipt = response.receipt.ok_or("Missing receipt")?;
    let record = SignedRecord::parse(&STANDARD.decode(&receipt)?)?;
    record.verify_signature(&pin.key()?)?;
    let body: Receipt = record.decode()?;
    let anchor = Anchor {
        pin,
        position: Position {
            sequence: body.sequence,
            record_id: Some(record.id()),
        },
        receipt,
    };
    private_json(&root.join("anchor.json"), &anchor)?;
    println!(
        "{}",
        serde_json::json!({"fixture_ready":true,"position":anchor.position,"sqlite_connection_open":true})
    );
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    drop(engine);
    Ok(())
}

fn verify(data: &Path, key: &Path, anchor_path: &Path) -> Result<()> {
    let anchor: Anchor = serde_json::from_slice(&std::fs::read(anchor_path)?)?;
    anchor.pin.validate()?;
    let signed = SignedRecord::parse(&STANDARD.decode(&anchor.receipt)?)?;
    signed.verify_signature(&anchor.pin.key()?)?;
    let receipt: Receipt = signed.decode()?;
    if receipt.v != 1
        || receipt.kind != "witness.receipt"
        || receipt.audience != anchor.pin.url
        || receipt.witness_key_generation != anchor.pin.key_generation
        || receipt.sequence != anchor.position.sequence
        || Some(signed.id()) != anchor.position.record_id
    {
        return Err("Independent anchor does not match its signed receipt".into());
    }
    let now = elo_witness::now_ms()?;
    let mut journal = Journal::open(data, key, anchor.pin.clone(), now)?;
    if journal.ready(now) {
        return Err("Restored journal did not start sealed".into());
    }
    journal.activate(
        Activation {
            startup_nonce: journal.startup()?.startup_nonce,
            expected_position: anchor.position,
            public_key: anchor.pin.public_key,
            key_generation: anchor.pin.key_generation,
            expires_at_ms: now + 60_000,
        },
        now,
    )?;
    if !journal.ready(now) {
        return Err("Verified restore did not activate".into());
    }
    println!(
        "{}",
        serde_json::json!({"journal_verified":true,"sealed_on_open":true,"independent_anchor_matched":true})
    );
    Ok(())
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    match arguments
        .iter()
        .skip(1)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["create", root] => create(Path::new(root)),
        ["verify", data, key, anchor] => verify(Path::new(data), Path::new(key), Path::new(anchor)),
        _ => Err("Usage: backup_fixture create ROOT | verify DATA KEY ANCHOR".into()),
    }
}

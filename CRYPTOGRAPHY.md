# Cryptography — object profile, not a custom ratchet

This is the implemented cryptographic composition; **the elo.now implementation has not undergone an independent security audit**. Primitive selection is not certification of the whole protocol. Dependency versions are pinned by the repository lockfiles.

## 1. What we use

Signatures: Ed25519 under RFC 8032 through `ed25519-dalek`, with strict verification and no fallback to legacy modes. Store and sign the exact bytes defined in [PROTOCOL](PROTOCOL.md).

Object encryption: **age v1**, native X25519 recipients, and the Rust `age` library. The format provides its own fresh file key and wrapping for multiple recipients. The library owns those age cryptographic operations and header construction. Other application formats are separate: attachments use a chunked XChaCha20-Poly1305 container, and short invitations use domain-separated HKDF-derived keys and XChaCha20-Poly1305 through existing primitive libraries. Their composition is application code and needs its own review; see [attachments](docs/ATTACHMENTS.md) and [the invitation codec](crates/elo-core/src/witness/link.rs).

Identifiers: SHA-256 with separate domains for identities, records, and encrypted objects. TLS protects transport and connection tokens; age protects content from an intermediary without keys. These roles are not interchangeable.

This implementation has no shared Stream secrets, MLS, Double Ratchet, cryptocurrency, or blockchain. `config_id` is not a group-key epoch number.

## 2. Keys and responsibilities

| Key / secret | Role | What it does not do |
|---|---|---|
| HUMAN root Ed25519 | Signs device credentials; the original controller owner's root also authorizes explicit version-1 Space recovery | Does not decrypt history by definition |
| Device Ed25519 | Signs events and requests | Does not replace a credential or membership |
| Device age X25519 | Decrypts objects addressed to the device | Is not a shared Stream secret |
| Replica Ed25519 | Signs storage receipts | Does not grant READ |
| Witness Ed25519 | Signs General ordering, receipts and freshness with independently verified transition evidence | Does not decrypt content or replace required owner/invitation evidence |
| Invitation seed | Derives descriptor-decryption and admission-signing keys for a short invitation | Does not authorize changes outside its owner-signed policy |
| Opaque mailbox tokens | Restrict HTTP reads/writes of ciphertext | Do not decrypt objects |
| Local vault secret/passphrase | Protects the secrets file on disk | Does not protect a compromised, unlocked process |

Generate signing and encryption keys independently. Do not silently convert one private key into another. The root is not a day-to-day messaging key and should remain in active-client memory only as long as enrollment/recovery requires.

`identity_id = SHA256("elo.now/identity/v1" || 0x00 || root_public_key_raw32)`.
A root-signed `DeviceCredential` binds identity_id, the root public key, the device's public Ed25519 key, a native age recipient, and a random credential nonce. Its record_id is `credential_id`. A device name is descriptive, not a security identifier.

A credential alone does not grant Space access. Its exact ID must be admitted by the applicable authority: a single controller, an admitted General owner device, or version-4 witness evidence under an owner proposal or invitation policy. Open witnessed invitations can admit an ordinary participant while the owner is offline; device management remains a separate operation. Live pairing can issue a delegated credential through an admitted device of the same identity; verification binds the complete chain to the root and bounds its depth and size. New delegation requires an active authorizing device. Revoking that parent does not revoke a child already admitted independently. Live pairing separately transfers an encrypted profile copy, including historical decryption keys. See [authority versions](PROTOCOL.md#authority-versions-and-hosted-general).

## 3. One API for all small objects

Domain API:

```text
seal_record(signed_bytes, approved_device_recipients) -> ciphertext
open_record(ciphertext, own_age_identity) -> exact_signed_bytes
verify_record(exact_signed_bytes, credential, authority_context) -> VerifiedRecord
```

The authorization layer supplies recipients; cryptography does not infer permissions from a channel name. A normal message targets current READ recipients, required owners, and the author's local self-copy. A post-only author knows their own content but receives no keys to other messages.

A new history bundle is a new record with new encryption. **Never add a recipient to an old age header as an implementation of a history grant.** File keys are not reused between objects. The library handles them; application code does not extract those keys from age.

Retry sends the stored ciphertext. After a crash, do not reconstruct encryptor state from a nonce counter. Encryption succeeds only after `finish`; decryption must successfully finish the entire stream before the document is accepted. A verified prefix is insufficient for a truncated bundle.

## 4. age does not authenticate the author

Anyone knowing a recipient's public key can encrypt an object for that recipient. Ed25519 signature, credential, and configuration verification are therefore mandatory after decryption. Successful decryption alone does not prove that Alice sent the object.

The signature protects content and the declared audience. It does not prove that the author made no additional private copy for someone else. Audit shows protocol permissions and explicit sharing, not proof that no out-of-protocol disclosure occurred.

## 5. Secrets on disk

SQLite stores ciphertext, local identifiers, statuses and the outbox. Records are decrypted for rendering and search in the unlocked process. The bounded attachment cache stores ciphertext, not preview plaintext or file keys; native previews and sharing temporarily materialize plaintext under app-controlled paths. Explicitly saved files are outside the encrypted vault. Operational database metadata is not completely hidden by this approach.

Device signing secrets and current/historical age identities are stored in the encrypted vault. The portable vault uses an age file in **passphrase/scrypt mode**, through the library API rather than a custom KDF. The strong password is independent of identity recovery; writes are atomic and file access is restricted. Scrypt cost limits defend against malicious files. Do not silently reduce the KDF cost to make tests pass faster.

This mode is not allowed for network content bundles: the client must not launch password prompts for unknown senders. age plugins/SSH recipients are disabled. Native biometric unlock protects a separate wrapping key with the platform credential store and uses a profile-bound local password envelope; it does not change the message format or add forward secrecy.

The root seed is not copied into the everyday device vault by default. Recovery export is explicit. After unlock, process memory remains a trust boundary; zeroization reduces risk but cannot guarantee erasure from the entire system, swap, or debugger copies.

## 6. Recovery — purpose and stages

Root recovery uses a recovery phrase; social recovery is not implemented. **No owner, SSO, or provider gains the right to recover a HUMAN root merely by its role**. An encrypted device backup and root identity recovery are different operations.

`elo.now identity-recovery-v1` encodes exactly 32 random root-seed bytes as 24 **BIP39 English** words using `Mnemonic::from_entropy(root_seed)`. Recovery validates the checksum and uses `to_entropy()`, requires exactly 32 bytes, reconstructs the Ed25519 root, and checks the expected identity_id. It does not use wallet `to_seed()`, derivation paths, or an extra “25th word”. The export card includes a version and public identity_id; its checksum detects some mistakes but does not authenticate the card.

The implementation uses the BIP39 library; words are not derived from a human password and wallet phrases are not reused. [Vault code and tests](crates/elo-core/src/vault.rs) verify the format and identity binding. This is a random-secret backup format; it does not add blockchain to the system.

The phrase restores only that root seed. A new device generates new keys, obtains a root-signed credential, and must be admitted under the applicable current configuration and policy. It does not restore revoked membership or silently reconstruct all old content keys.

Version-1 controller loss has a separate, explicit authorization path: the original controlling owner's root can sign a Space-generation change to a fresh credential of the same identity. The new key signs a configuration based on an approved checkpoint, replacing that owner's old devices. This does not change the owner set or genesis and does not cover other Spaces or ordinary membership of a recovered identity. The [recovery validator](crates/elo-core/src/authority/recovery.rs) defines the signed bindings and the cost of trusting the root and checkpoint. A compromised root can authorize this administrative recovery; the mechanism is not protection against root compromise.

Owner-managed General versions 2 and 4 admit several independent owner devices. A surviving approved device can continue management, revoke a lost device and authorize a replacement. It does not use the version-1 recovery certificate or compact checkpoint. Version 4 additionally requires the witness to serialize the owner proposal. Recovery after losing every owner device is not implemented for these versions; importing a backup alone does not activate administrative control.

Data from a lost device requires a separate backup of its secrets/ciphertexts or a new bundle from an authorized holder. A Replica storing only ciphertext is not a recovery authority. Missing copies or keys can mean irreversible data loss.

Social recovery, composition of both methods, guardian rotation, and root-key rotation are not implemented. Revoking one device does not repair root-seed compromise; this profile may require a new identity. This limitation must be visible to users rather than hidden by an owner-operated reset.

## 7. No archive forward-secrecy promise

The age X25519 profile uses the recipient's long-term private key to open retained envelopes. **Inference from this construction:** later compromise of that key permits decryption of retained ciphertext addressed to it. A new file key per bundle, TLS, or removing a recipient from the current StreamConfig does not repair this property.

We do not claim post-compromise security, deniability, post-quantum resistance, or Signal-level protection. Author signatures deliberately support audit rather than deniable authorship. Sensitive uses need a separate assessment; adopting a later group standard/ratchet is not a simple feature flag within this profile.

## 8. Verification

The SignedRecord fixture checks local framing/signatures; it does not certify the entire system. [Core tests](crates/elo-core/tests), [cryptographic tests](crates/elo-core/src/crypto.rs), [authority validation](crates/elo-core/src/authority.rs) and [witness validation](crates/elo-core/src/authority/witness.rs) exercise the implemented boundaries. Run the applicable checks for matching client/server builds. Source tests do not replace independent assessment, deployment validation or physical-device acceptance.

# SignedRecord/chat.message v1 — initial fixture

The `.body.json` file contains the exact bytes B **without a trailing LF**; `.record.bin` is the complete R, and `.expected.json` provides domain-separated IDs, the public key, signature, and public test seed. Different JSON representations are not equivalent signed bytes. Preserve the original Polish message text: translating it would change the cryptographic fixture.

Seed `00 01 ... 1f` is public and intended only for repeatable tests. Never initialize a CLI identity with it. Space/config/credential/audience identifiers are synthetic values of the correct shape. This fixture **does not establish authorization or a valid identity chain**. It is not age ciphertext either. The [record tests](../../crates/elo-core/tests/record.rs) and [encryption tests](../../crates/elo-core/tests/crypto.rs) exercise the Rust implementations separately.

The signature was generated and verified with `cryptography`/Ed25519. Tests also check changes to content, signatures, whitespace, framing, versions, duplicate fields, and size boundaries. The reference verifier does not replace Rust `verify_strict` or pathological cross-implementation vectors.

Run `cargo test --locked -p elo-core --test record --test crypto` from the repository root. The fixture is a deterministic framing and cryptography check, not a complete authorization or security audit.

//! A hosting registry selects one private conversation; only signed chat
//! authority grants a device access. No message keys enter this protocol.
use crate::{
    app::Result,
    authority::{Authority, CallAuthorityProof, ChatKind, SpaceGenesis},
    ids::{IdentityId, SpaceId, StreamId},
    record::SignedRecord,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

pub(crate) const MAX_PROOF: usize = 512 * 1024;

pub(crate) fn stream(hosting: SpaceId, general: StreamId, identity: IdentityId) -> StreamId {
    let hash = Sha256::digest(
        [
            b"elo.now/notes/v1\0".as_slice(),
            hosting.as_bytes(),
            general.as_bytes(),
            identity.as_bytes(),
        ]
        .concat(),
    );
    StreamId::from_bytes(hash[..16].try_into().expect("SHA-256 prefix"))
}

pub(crate) fn verify(
    proof: &CallAuthorityProof,
    general: &Authority,
    identity: IdentityId,
) -> Result<Authority> {
    let authority = verify_scope(proof, general, identity)?;
    let member = general
        .head()?
        .members
        .iter()
        .find(|member| member.identity_id == identity)
        .ok_or("This profile is no longer in the Space.")?;
    if authority.head()?.members[0]
        .credential_ids
        .iter()
        .any(|id| !member.credential_ids.contains(id))
    {
        return Err(
            "Notes devices have changed. Open Notes on its original device to update access."
                .into(),
        );
    }
    Ok(authority)
}

pub(crate) fn verify_scope(
    proof: &CallAuthorityProof,
    general: &Authority,
    identity: IdentityId,
) -> Result<Authority> {
    if proof.v != 1
        || proof.checkpoint.is_some()
        || proof.configs.len() > 256
        || serde_json::to_vec(proof)?.len() > MAX_PROOF
    {
        return Err("Invalid Notes authority.".into());
    }
    let genesis = SignedRecord::parse(&STANDARD.decode(&proof.genesis)?)?;
    let body: SpaceGenesis = genesis.decode()?;
    if body.v != 3 || body.owners.len() != 1 || body.owners[0].identity_id != identity {
        return Err("Notes must belong only to this profile.".into());
    }
    let authority = proof.verify(
        SpaceId::from_bytes(*genesis.id().as_bytes()),
        stream(general.space(), general.stream(), identity),
    )?;
    for encoded in &proof.configs {
        let record = SignedRecord::parse(&STANDARD.decode(encoded)?)?;
        let config = authority.config(record.id())?;
        if config.chat_kind != Some(ChatKind::Direct)
            || config.members.len() != 1
            || config.members[0].identity_id != identity
            || config.members[0].identity_type != "HUMAN"
        {
            return Err("Notes cannot contain other people.".into());
        }
    }
    Ok(authority)
}

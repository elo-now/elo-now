use crate::{
    Error, Result,
    journal::{self, Event, Journal, decode},
    wire::*,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use elo_core::{
    authority::{
        Authority, Capability, ChatKind, WitnessAdmissionIntent, WitnessAdmissionIntentV2,
        WitnessApproval, WitnessApprovalV2, WitnessChallenge, WitnessChallengeV2,
    },
    identity::{DeviceCredential, VerifiedCredential},
    ids::{RecordId, SpaceId, StreamId},
    record::{self, SignedRecord},
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, net::IpAddr};

pub struct Engine {
    pub journal: Journal,
}

fn registration_network(ip: IpAddr, day: i64) -> String {
    let prefix = match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.octets()[..8].to_vec(), |ip| ip.octets().to_vec()),
    };
    let mut hash = Sha256::new();
    hash.update(b"elo.witness.registration-network.v1\0");
    hash.update(day.to_be_bytes());
    hash.update(prefix);
    record::encode_hex(&hash.finalize())
}

impl Engine {
    pub fn head(&mut self, request: HeadRequest, now: u64) -> Result<String> {
        self.journal.guard(now)?;
        hex32(&request.nonce)?;
        let authority = load(
            &self.journal.db,
            request.space_id,
            request.stream_id,
            &self.journal.pin,
        )?;
        let body = Freshness {
            v: 1,
            kind: "witness.freshness".into(),
            audience: self.journal.pin.url.clone(),
            nonce: request.nonce,
            space_id: request.space_id,
            stream_id: request.stream_id,
            authority_head: authority.head_id().ok_or(Error::Missing)?,
            position: journal::position(&self.journal.db)?,
            issued_at_ms: now,
            expires_at_ms: now.checked_add(30_000).ok_or(Error::Invalid)?,
            witness_key_generation: self.journal.pin.key_generation,
        };
        Ok(STANDARD.encode(
            SignedRecord::sign(
                &serde_json::to_vec(&body).map_err(|_| Error::Invalid)?,
                &self.journal.key,
            )?
            .bytes(),
        ))
    }

    pub fn apply(&mut self, request: Request, ip: IpAddr, now: u64) -> Result<Response> {
        self.journal.guard(now)?;
        let signed = decode(&request.command)?;
        let command: Command = signed.decode()?;
        hex32(&command.nonce)?;
        if command.v != 1
            || command.kind != "witness.command"
            || command.audience != self.journal.pin.url
            || command.expires_at_ms <= now
            || command.issued_at_ms > now.saturating_add(5_000)
            || command.expires_at_ms <= command.issued_at_ms
            || command.expires_at_ms - command.issued_at_ms > 60_000
        {
            return Err(Error::Invalid);
        }
        let registering = matches!(command.operation, Operation::Register);
        if registering {
            request.verify_registration_work()?;
        } else if request.registration_work.is_some() {
            return Err(Error::Invalid);
        }
        let registered = self
            .journal
            .db
            .query_row(
                "SELECT 1 FROM spaces WHERE space=?1 UNION SELECT 1 FROM events WHERE space=?1 UNION SELECT 1 FROM policies WHERE space=?1 UNION SELECT 1 FROM challenges WHERE space=?1 UNION SELECT 1 FROM tombstones WHERE space=?1 LIMIT 1",
                [command.space_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let mut authority = if registering {
            let proof = request.proof.as_ref().ok_or(Error::Invalid)?;
            let authority =
                proof.verify_witnessed(command.space_id, command.stream_id, &self.journal.pin)?;
            if authority.head()?.sequence != 1
                || authority.head()?.chat_kind != Some(ChatKind::Chat)
                || authority.genesis().body()["nonce"].as_str()
                    != Some(command.stream_id.to_string().as_str())
            {
                return Err(Error::Invalid);
            }
            if registered {
                // A registration retry must use current permissions, even if
                // its originally supplied genesis proof was valid.
                load(
                    &self.journal.db,
                    command.space_id,
                    command.stream_id,
                    &self.journal.pin,
                )?
            } else {
                authority
            }
        } else {
            if request.proof.is_some() {
                return Err(Error::Invalid);
            }
            load(
                &self.journal.db,
                command.space_id,
                command.stream_id,
                &self.journal.pin,
            )?
        };
        let candidate = match &command.operation {
            Operation::Challenge { credential, .. }
            | Operation::Admit { credential, .. }
            | Operation::ChallengeV2 { credential, .. }
            | Operation::AdmitV2 { credential, .. } => Some(verify_credential(credential)?),
            _ => None,
        };
        let signer = if let Some(candidate) = &candidate {
            candidate
        } else {
            authority.credential(command.credential_id)?
        };
        if signer.id() != command.credential_id {
            return Err(Error::Unauthorized);
        }
        signed.verify_signature(signer.key())?;
        if !matches!(
            command.operation,
            Operation::Challenge { .. }
                | Operation::Admit { .. }
                | Operation::ChallengeV2 { .. }
                | Operation::AdmitV2 { .. }
        ) {
            require_read(&authority, command.credential_id)?;
        }
        if matches!(
            command.operation,
            Operation::Register
                | Operation::RegisterInvitation { .. }
                | Operation::RevokeInvitation { .. }
                | Operation::OwnerUpdate { .. }
        ) && !authority.can_manage(command.credential_id)
        {
            return Err(Error::Unauthorized);
        }
        if matches!(command.operation, Operation::Read) {
            return Ok(Response {
                receipt: None,
                proof: Some(authority.call_proof()?),
                challenge: None,
            });
        }
        // No receipt is returned before checking the current signer permissions.
        if let Some(response) = journal::replay(&self.journal.db, signed.id())? {
            if matches!(
                command.operation,
                Operation::Admit { .. } | Operation::AdmitV2 { .. }
            ) {
                require_read(&authority, command.credential_id)?;
            }
            return Ok(response);
        }
        if matches!(
            command.operation,
            Operation::Register
                | Operation::RegisterInvitation { .. }
                | Operation::RevokeInvitation { .. }
                | Operation::OwnerUpdate { .. }
        ) && authority.head_id() != Some(command.authority_head)
        {
            return Err(Error::Conflict);
        }
        let tx = self.journal.db.transaction()?;
        tx.execute(
            "DELETE FROM command_nonces WHERE expires < ?1",
            [now.saturating_sub(600_000) as i64],
        )?;
        tx.execute(
            "DELETE FROM challenges WHERE space=?1 AND expires < ?2 AND intent IS NULL",
            params![
                command.space_id.to_string(),
                now.saturating_sub(600_000) as i64
            ],
        )?;
        if tx
            .query_row(
                "SELECT request FROM command_nonces WHERE credential=?1 AND nonce=?2",
                params![command.credential_id.to_string(), command.nonce],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .is_some()
        {
            return Err(Error::Conflict);
        }
        let mut response = Response {
            receipt: None,
            proof: None,
            challenge: None,
        };
        let event = match &command.operation {
            Operation::Register => {
                if tx.query_row(
                    "SELECT count(*) FROM spaces WHERE space=?1",
                    [command.space_id.to_string()],
                    |r| r.get::<_, i64>(0),
                )? != 0
                {
                    return Err(Error::Conflict);
                }
                if tx.query_row("SELECT count(*) FROM spaces", [], |r| r.get::<_, i64>(0))? >= 128 {
                    return Err(Error::Limit);
                }
                let day = (now / 86_400_000) as i64;
                let network = registration_network(ip, day);
                let count = tx
                    .query_row(
                        "SELECT count FROM registration_limits WHERE ip=?1 AND day=?2",
                        params![network, day],
                        |r| r.get::<_, i64>(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                let global = tx.query_row(
                    "SELECT COALESCE(sum(count),0) FROM registration_limits WHERE day=?1",
                    [day],
                    |r| r.get::<_, i64>(0),
                )?;
                if count >= 4 || global >= 32 {
                    return Err(Error::Limit);
                }
                tx.execute("INSERT INTO registration_limits(ip,day,count) VALUES(?1,?2,1) ON CONFLICT(ip,day) DO UPDATE SET count=count+1", params![network,day])?;
                tx.execute("DELETE FROM registration_limits WHERE day < ?1", [day])?;
                save(&tx, &authority)?;
                "space.registered"
            }
            Operation::RegisterInvitation { policy } => {
                let record = decode(policy)?;
                let body = authority.verify_witness_invitation(&record, now)?;
                if body.issuer_credential_id != command.credential_id {
                    return Err(Error::Unauthorized);
                }
                if tx.query_row(
                    "SELECT count(*) FROM policies WHERE space=?1",
                    [command.space_id.to_string()],
                    |r| r.get::<_, i64>(0),
                )? >= 4096
                {
                    return Err(Error::Limit);
                }
                // Never reset the counters or revocation state of a known policy.
                tx.execute(
                    "INSERT OR IGNORE INTO policies(space,id,record) VALUES(?1,?2,?3)",
                    params![
                        command.space_id.to_string(),
                        record.id().to_string(),
                        policy
                    ],
                )?;
                "invitation.registered"
            }
            Operation::RevokeInvitation { policy_id } => {
                if tx.execute(
                    "UPDATE policies SET revoked=1 WHERE space=?1 AND id=?2",
                    params![command.space_id.to_string(), policy_id.to_string()],
                )? == 0
                {
                    return Err(Error::Missing);
                }
                "invitation.revoked"
            }
            Operation::Challenge {
                policy_id,
                client_nonce,
                ..
            } => {
                hex32(client_nonce)?;
                let (_, policy) = policy(&tx, &authority, *policy_id, now)?;
                // Prove invitation possession before allocating any challenge.
                let possession = decode(
                    request
                        .invitation_signature
                        .as_ref()
                        .ok_or(Error::Unauthorized)?,
                )?;
                if possession.body_bytes() != signed.body_bytes() {
                    return Err(Error::Unauthorized);
                }
                let key = VerifyingKey::from_bytes(&hex32(&policy.invitation_public_key)?)
                    .map_err(|_| Error::Invalid)?;
                possession.verify_signature(&key)?;
                if tx.query_row("SELECT count(*) FROM challenges WHERE space=?1 AND expires>=?2 AND intent IS NULL", params![command.space_id.to_string(),now as i64], |r|r.get::<_,i64>(0))? >= 256 { return Err(Error::Limit); }
                let body = WitnessChallenge {
                    v: 1,
                    kind: "witness.challenge".into(),
                    nonce: record::random_hex::<32>()?,
                    client_nonce: client_nonce.clone(),
                    space_id: command.space_id,
                    stream_id: command.stream_id,
                    policy_id: *policy_id,
                    credential_id: command.credential_id,
                    issued_at_ms: now,
                    expires_at_ms: now.saturating_add(120_000),
                    witness_key_generation: self.journal.pin.key_generation,
                };
                let record = SignedRecord::sign(
                    &serde_json::to_vec(&body).map_err(|_| Error::Invalid)?,
                    &self.journal.key,
                )?;
                let encoded = STANDARD.encode(record.bytes());
                tx.execute("INSERT INTO challenges(id,space,policy,credential,record,expires) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![record.id().to_string(), command.space_id.to_string(), policy_id.to_string(), command.credential_id.to_string(), encoded, body.expires_at_ms as i64])?;
                response.challenge = Some(encoded);
                "invitation.challenged"
            }
            Operation::ChallengeV2 {
                request: join,
                client_nonce,
                ..
            } => {
                hex32(client_nonce)?;
                let candidate = candidate.as_ref().ok_or(Error::Invalid)?;
                let body = authority.verify_witness_join_request(join, candidate, now)?;
                let (stored_policy, policy_body) = policy(&tx, &authority, body.policy_id, now)?;
                if stored_policy != join.policy {
                    return Err(Error::Unauthorized);
                }
                // A previously published request is not fresh possession. Sign
                // this exact nonce-bound command again with the invitation key.
                let possession = decode(
                    request
                        .invitation_signature
                        .as_ref()
                        .ok_or(Error::Unauthorized)?,
                )?;
                if possession.body_bytes() != signed.body_bytes() {
                    return Err(Error::Unauthorized);
                }
                let key = VerifyingKey::from_bytes(&hex32(&policy_body.invitation_public_key)?)
                    .map_err(|_| Error::Invalid)?;
                possession.verify_signature(&key)?;
                let request_id = decode(&join.device_request)?.id();
                let consumption = format!("v2:{request_id}");
                if tx.query_row(
                    "SELECT count(*) FROM challenges WHERE space=?1 AND intent=?2",
                    params![command.space_id.to_string(), consumption],
                    |r| r.get::<_, i64>(0),
                )? != 0
                {
                    return Err(Error::Conflict);
                }
                if tx.query_row("SELECT count(*) FROM challenges WHERE space=?1 AND expires>=?2 AND intent IS NULL", params![command.space_id.to_string(),now as i64], |r|r.get::<_,i64>(0))? >= 256 {
                    return Err(Error::Limit);
                }
                let challenge = WitnessChallengeV2 {
                    v: 2,
                    kind: "witness.challenge".into(),
                    nonce: record::random_hex::<32>()?,
                    client_nonce: client_nonce.clone(),
                    space_id: command.space_id,
                    stream_id: command.stream_id,
                    policy_id: body.policy_id,
                    credential_id: command.credential_id,
                    request_id,
                    authority_head: authority.head_id().ok_or(Error::Missing)?,
                    issued_at_ms: now,
                    expires_at_ms: now.saturating_add(120_000).min(body.expires_at_ms),
                    witness_key_generation: self.journal.pin.key_generation,
                };
                let record = SignedRecord::sign(
                    &serde_json::to_vec(&challenge).map_err(|_| Error::Invalid)?,
                    &self.journal.key,
                )?;
                let encoded = STANDARD.encode(record.bytes());
                tx.execute("INSERT INTO challenges(id,space,policy,credential,record,expires) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![record.id().to_string(), command.space_id.to_string(), body.policy_id.to_string(), command.credential_id.to_string(), encoded, challenge.expires_at_ms as i64])?;
                response.challenge = Some(encoded);
                "invitation.challenged_v2"
            }
            Operation::AdmitV2 { evidence, .. } => {
                let candidate = candidate.ok_or(Error::Invalid)?;
                let intent_record = decode(&evidence.device_intent)?;
                let intent: WitnessAdmissionIntentV2 = intent_record.decode()?;
                let (stored_policy, _) = policy(&tx, &authority, intent.policy_id, now)?;
                if stored_policy != evidence.request.policy
                    || intent.credential_id != command.credential_id
                {
                    return Err(Error::Unauthorized);
                }
                let request_id = decode(&evidence.request.device_request)?.id();
                let consumption = format!("v2:{request_id}");
                if tx.query_row(
                    "SELECT count(*) FROM challenges WHERE space=?1 AND intent=?2",
                    params![command.space_id.to_string(), consumption],
                    |r| r.get::<_, i64>(0),
                )? != 0
                {
                    return Err(Error::Conflict);
                }
                let (challenge, consumed): (String, Option<String>) = tx.query_row("SELECT record,intent FROM challenges WHERE id=?1 AND space=?2 AND credential=?3 AND expires>=?4",
                    params![intent.challenge_id.to_string(),command.space_id.to_string(),command.credential_id.to_string(),now as i64], |r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(Error::Unauthorized)?;
                if challenge != evidence.challenge || consumed.is_some() {
                    return Err(Error::Conflict);
                }
                let body: WitnessChallengeV2 = decode(&challenge)?.decode()?;
                if body.authority_head != command.authority_head || body.request_id != request_id {
                    return Err(Error::Unauthorized);
                }
                let removed = tx.query_row("SELECT count(*) FROM tombstones WHERE space=?1 AND (credential=?2 OR identity=?3)",
                    params![command.space_id.to_string(),candidate.id().to_string(),candidate.identity().to_string()], |r|r.get::<_,i64>(0))? > 0;
                if removed {
                    let approval: WitnessApprovalV2 =
                        decode(evidence.approval.as_ref().ok_or(Error::Unauthorized)?)?.decode()?;
                    if !approval.readmission {
                        return Err(Error::Unauthorized);
                    }
                }
                authority.add_credential(candidate);
                let mut evidence = evidence.clone();
                evidence.admitted_at_ms = now;
                let config = authority.prepare_witness_admission_v2(evidence, &self.journal.key)?;
                authority.apply_config(config)?;
                save(&tx, &authority)?;
                // The versioned stable request marker remains in the existing
                // signed state digest. It also prevents a second fresh challenge
                // from consuming the same durable request after a restart.
                if tx.execute(
                    "UPDATE challenges SET intent=?1 WHERE id=?2 AND intent IS NULL",
                    params![consumption, intent.challenge_id.to_string()],
                )? != 1
                {
                    return Err(Error::Conflict);
                }
                if tx.execute(
                    "UPDATE policies SET uses=uses+1 WHERE id=?1 AND space=?2 AND revoked=0",
                    params![intent.policy_id.to_string(), command.space_id.to_string()],
                )? != 1
                {
                    return Err(Error::Conflict);
                }
                "device.admitted_v2"
            }
            Operation::Admit { evidence, .. } => {
                let candidate = candidate.ok_or(Error::Invalid)?;
                let intent_record = decode(&evidence.device_intent)?;
                let intent: WitnessAdmissionIntent = intent_record.decode()?;
                let (stored_policy, _) = policy(&tx, &authority, intent.policy_id, now)?;
                if stored_policy != evidence.policy || intent.credential_id != command.credential_id
                {
                    return Err(Error::Unauthorized);
                }
                let (challenge, consumed): (String, Option<String>) = tx.query_row("SELECT record,intent FROM challenges WHERE id=?1 AND space=?2 AND credential=?3 AND expires>=?4",
                    params![intent.challenge_id.to_string(),command.space_id.to_string(),command.credential_id.to_string(),now as i64], |r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(Error::Unauthorized)?;
                if challenge != evidence.challenge || consumed.is_some() {
                    return Err(Error::Conflict);
                }
                let removed = tx.query_row("SELECT count(*) FROM tombstones WHERE space=?1 AND (credential=?2 OR identity=?3)",
                    params![command.space_id.to_string(),candidate.id().to_string(),candidate.identity().to_string()], |r|r.get::<_,i64>(0))? > 0;
                if removed {
                    let approval: WitnessApproval =
                        decode(evidence.approval.as_ref().ok_or(Error::Unauthorized)?)?.decode()?;
                    if !approval.readmission {
                        return Err(Error::Unauthorized);
                    }
                }
                authority.add_credential(candidate);
                let mut evidence = evidence.clone();
                evidence.admitted_at_ms = now;
                let config = authority.prepare_witness_admission(evidence, &self.journal.key)?;
                authority.apply_config(config)?;
                save(&tx, &authority)?;
                tx.execute(
                    "UPDATE challenges SET intent=?1 WHERE id=?2 AND intent IS NULL",
                    params![
                        intent_record.id().to_string(),
                        intent.challenge_id.to_string()
                    ],
                )?;
                tx.execute(
                    "UPDATE policies SET uses=uses+1 WHERE id=?1",
                    [intent.policy_id.to_string()],
                )?;
                "device.admitted"
            }
            Operation::OwnerUpdate {
                proposal,
                credentials,
            } => {
                if credentials.len() > 64 {
                    return Err(Error::Limit);
                }
                let before = members(&authority)?;
                for credential in credentials {
                    authority.add_credential(verify_credential(credential)?);
                }
                let proposal = decode(proposal)?;
                let config =
                    authority.prepare_witness_owner_config(&proposal, &self.journal.key)?;
                authority.apply_config(config)?;
                let after = members(&authority)?;
                for (credential, identity) in before.difference(&after) {
                    tx.execute("INSERT OR IGNORE INTO tombstones(space,credential,identity) VALUES(?1,?2,?3)",
                        params![command.space_id.to_string(),credential,identity])?;
                }
                save(&tx, &authority)?;
                "authority.updated"
            }
            Operation::Read => unreachable!(),
        };
        tx.execute(
            "INSERT INTO command_nonces(credential,nonce,request,expires) VALUES(?1,?2,?3,?4)",
            params![
                command.credential_id.to_string(),
                command.nonce,
                signed.id().to_string(),
                command.expires_at_ms as i64
            ],
        )?;
        let response = journal::append(
            &tx,
            &self.journal.key,
            &self.journal.pin,
            Event {
                request: signed.id(),
                space: command.space_id,
                head: authority.head_id().ok_or(Error::Missing)?,
                name: event,
                now,
            },
            response,
        )?;
        tx.commit()?;
        Ok(response)
    }
}

fn load(
    db: &Connection,
    space: SpaceId,
    stream: StreamId,
    pin: &elo_core::authority::WitnessPin,
) -> Result<Authority> {
    let proof = db
        .query_row(
            "SELECT proof FROM spaces WHERE space=?1 AND stream=?2",
            params![space.to_string(), stream.to_string()],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .ok_or(Error::Missing)?;
    if proof.len() > 9 * 1024 * 1024 {
        return Err(Error::Unavailable);
    }
    let proof: elo_core::authority::CallAuthorityProof =
        serde_json::from_str(&proof).map_err(|_| Error::Unavailable)?;
    let receipt = journal::verify_materialized_space(db, space, pin)?;
    let authority = proof.verify_witnessed(space, stream, pin)?;
    if authority.head_id() != Some(receipt.authority_head) {
        return Err(Error::RecoveryRequired);
    }
    Ok(authority)
}
fn save(db: &Connection, authority: &Authority) -> Result<()> {
    let proof = serde_json::to_string(&authority.call_proof()?).map_err(|_| Error::Invalid)?;
    db.execute("INSERT INTO spaces(space,stream,proof) VALUES(?1,?2,?3) ON CONFLICT(space) DO UPDATE SET proof=excluded.proof", params![authority.space().to_string(),authority.stream().to_string(),proof])?;
    Ok(())
}
fn require_read(authority: &Authority, credential: RecordId) -> Result<()> {
    if !authority.head()?.members.iter().any(|member| {
        member.credential_ids.contains(&credential)
            && member.capabilities.contains(&Capability::Read)
    }) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
fn members(authority: &Authority) -> Result<BTreeSet<(String, String)>> {
    Ok(authority
        .head()?
        .members
        .iter()
        .flat_map(|m| {
            m.credential_ids
                .iter()
                .map(|id| (id.to_string(), m.identity_id.to_string()))
        })
        .collect())
}
fn policy(
    db: &Connection,
    authority: &Authority,
    id: RecordId,
    now: u64,
) -> Result<(String, elo_core::authority::WitnessInvitationPolicy)> {
    let (encoded, revoked, uses): (String, bool, i64) = db
        .query_row(
            "SELECT record,revoked,uses FROM policies WHERE id=?1 AND space=?2",
            params![id.to_string(), authority.space().to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .ok_or(Error::Missing)?;
    let body = authority.verify_witness_invitation(&decode(&encoded)?, now)?;
    if revoked || uses < 0 || uses as u64 >= body.max_uses {
        return Err(Error::Unauthorized);
    }
    Ok((encoded, body))
}
fn verify_credential(encoded: &str) -> Result<VerifiedCredential> {
    let signed = decode(encoded)?;
    let body: DeviceCredential = signed.decode()?;
    let root =
        VerifyingKey::from_bytes(&hex32(&body.root_public_key)?).map_err(|_| Error::Invalid)?;
    // This establishes only credential authorship. Admission is separately
    // authorized by a registered owner policy and proof of invitation possession.
    Ok(VerifiedCredential::verify(signed.bytes(), &root)?)
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    Ok(*value
        .parse::<RecordId>()
        .map_err(|_| Error::Invalid)?
        .as_bytes())
}

#[cfg(test)]
mod tests;

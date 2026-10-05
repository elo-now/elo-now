//! Signed witness commands. A mutation receipt acknowledges a request; it does
//! not authorize importing a new membership head without its complete proof.
use super::*;
use crate::{
    authority::{CallAuthorityProof, WitnessPin},
    identity::VerifiedCredential,
    witness::{Command, Operation, Position, Receipt, Request, Response},
};
use std::time::{Duration, Instant};

const ERROR: &str = "Chat permissions need to be refreshed.";
const RESPONSE_BYTES: usize = 9 * 1024 * 1024;

struct VerifiedResponse {
    receipt: Option<Receipt>,
    authority: Option<Authority>,
}

fn verify_receipt(
    pin: &WitnessPin,
    request: &SignedRecord,
    command: &Command,
    encoded: &str,
    now_ms: u64,
    floor: Option<&Position>,
) -> Result<(Receipt, Position)> {
    if encoded.len() > 16_384 {
        return Err(ERROR.into());
    }
    let signed = decode_record(encoded)?;
    signed.verify_signature(&pin.key()?)?;
    let receipt: Receipt = signed.decode()?;
    let event = match command.operation {
        Operation::Register => "space.registered",
        Operation::RegisterInvitation { .. } => "invitation.registered",
        Operation::RevokeInvitation { .. } => "invitation.revoked",
        Operation::OwnerUpdate { .. } => "authority.updated",
        _ => return Err(ERROR.into()),
    };
    record::hex::<32>(&receipt.state_digest)?;
    let position = Position {
        sequence: receipt.sequence,
        record_id: Some(signed.id()),
    };
    if receipt.v != 1
        || receipt.kind != "witness.receipt"
        || receipt.audience != pin.url
        || receipt.witness_key_generation != pin.key_generation
        || receipt.space_id != command.space_id
        || receipt.request_id != request.id()
        || receipt.event != event
        || receipt.sequence == 0
        || (receipt.sequence == 1) != receipt.previous.is_none()
        || receipt.accepted_at_ms < command.issued_at_ms.saturating_sub(5_000)
        || receipt.accepted_at_ms >= command.expires_at_ms
        || receipt.accepted_at_ms > now_ms.saturating_add(5_000)
        || now_ms >= command.expires_at_ms
        || (!matches!(command.operation, Operation::OwnerUpdate { .. })
            && receipt.authority_head != command.authority_head)
        || (matches!(command.operation, Operation::OwnerUpdate { .. })
            && receipt.authority_head == command.authority_head)
        || floor.is_some_and(|floor| {
            position.sequence < floor.sequence
                || (position.sequence == floor.sequence && position.record_id != floor.record_id)
                || (position.sequence == floor.sequence.saturating_add(1)
                    && receipt.previous != floor.record_id)
        })
    {
        return Err(ERROR.into());
    }
    Ok((receipt, position))
}

fn verify_returned_proof(
    pin: &WitnessPin,
    current: &Authority,
    proof: &CallAuthorityProof,
) -> Result<Authority> {
    let authority = proof.verify_witnessed(current.space(), current.stream(), pin)?;
    if !authority.proves_config_at(current.head_id().ok_or(ERROR)?, current.head()?.sequence) {
        return Err(ERROR.into());
    }
    Ok(authority)
}

impl ClientApp {
    pub async fn witness_register_authority(&self, authority: &Authority) -> Result<Receipt> {
        if authority.head()?.sequence != 1
            || authority.genesis().body()["nonce"] != authority.stream().to_string()
        {
            return Err(ERROR.into());
        }
        self.send_witness_command(
            authority,
            Operation::Register,
            Some(authority.call_proof()?),
        )
        .await?
        .receipt
        .ok_or_else(|| ERROR.into())
    }

    pub async fn witness_register_invitation(
        &self,
        authority: &Authority,
        policy: &SignedRecord,
    ) -> Result<Receipt> {
        let body = authority.verify_witness_invitation(policy, now()?.as_millis() as u64)?;
        if body.issuer_credential_id != self.session.credential().id() {
            return Err(ERROR.into());
        }
        self.send_witness_command(
            authority,
            Operation::RegisterInvitation {
                policy: STANDARD.encode(policy.bytes()),
            },
            None,
        )
        .await?
        .receipt
        .ok_or_else(|| ERROR.into())
    }

    pub async fn witness_revoke_invitation(
        &self,
        authority: &Authority,
        policy_id: RecordId,
    ) -> Result<Receipt> {
        self.send_witness_command(authority, Operation::RevokeInvitation { policy_id }, None)
            .await?
            .receipt
            .ok_or_else(|| ERROR.into())
    }

    /// Read and import the witnessed configuration separately after this ack.
    pub async fn witness_owner_update(
        &self,
        authority: &Authority,
        proposal: &SignedRecord,
        credentials: &[VerifiedCredential],
    ) -> Result<Receipt> {
        let proposed: StreamConfig = proposal.decode()?;
        if credentials.len() > 64
            || proposed.v != 4
            || proposed.witness_evidence.is_some()
            || proposed.space_id != authority.space()
            || proposed.stream_id != authority.stream()
            || proposed.previous_config_id != authority.head_id()
            || proposed.sequence != authority.head()?.sequence + 1
            || !authority.can_manage(proposed.controller_credential_id)
        {
            return Err(ERROR.into());
        }
        proposal.verify_signature(
            authority
                .credential(proposed.controller_credential_id)?
                .key(),
        )?;
        self.send_witness_command(
            authority,
            Operation::OwnerUpdate {
                proposal: STANDARD.encode(proposal.bytes()),
                credentials: credentials
                    .iter()
                    .map(|credential| STANDARD.encode(credential.record().bytes()))
                    .collect(),
            },
            None,
        )
        .await?
        .receipt
        .ok_or_else(|| ERROR.into())
    }

    /// A Read proof is not nonce-bound. Confirm its head with a separate fresh
    /// witness answer before exposing it for import, preserving the local chain.
    pub async fn witness_read_authority(&self, authority: &Authority) -> Result<Authority> {
        self.send_witness_command(authority, Operation::Read, None)
            .await?
            .authority
            .ok_or_else(|| ERROR.into())
    }

    async fn send_witness_command(
        &self,
        authority: &Authority,
        operation: Operation,
        proof: Option<CallAuthorityProof>,
    ) -> Result<VerifiedResponse> {
        let pin = self.trusted_witness(authority)?;
        let read = matches!(operation, Operation::Read);
        let register = matches!(operation, Operation::Register);
        if !matches!(
            operation,
            Operation::Register
                | Operation::RegisterInvitation { .. }
                | Operation::RevokeInvitation { .. }
                | Operation::OwnerUpdate { .. }
                | Operation::Read
        ) || (!read && !authority.can_manage(self.session.credential().id()))
            || !authority.head()?.members.iter().any(|member| {
                member
                    .credential_ids
                    .contains(&self.session.credential().id())
                    && member.capabilities.contains(&Capability::Read)
            })
            || register != proof.is_some()
        {
            return Err(ERROR.into());
        }
        let issued_at_ms = now()?.as_millis() as u64;
        let command = Command {
            v: 1,
            kind: "witness.command".into(),
            nonce: record::random_hex::<32>()?,
            audience: pin.url.clone(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            credential_id: self.session.credential().id(),
            authority_head: authority.head_id().ok_or(ERROR)?,
            issued_at_ms,
            expires_at_ms: issued_at_ms.checked_add(60_000).ok_or(ERROR)?,
            operation,
        };
        let signed =
            SignedRecord::sign(&serde_json::to_vec(&command)?, self.session.signing_key())?;
        let mut request = Request {
            command: STANDARD.encode(signed.bytes()),
            invitation_signature: None,
            proof,
            registration_work: None,
        };
        if register {
            request = tokio::task::spawn_blocking(move || {
                request.solve_registration_work()?;
                Ok::<_, record::RecordError>(request)
            })
            .await??;
        }
        if now()?.as_millis() as u64 >= command.expires_at_ms {
            return Err(ERROR.into());
        }
        let floor = self.witness_position(pin)?;
        let endpoint = self.witness_endpoint(pin, "command")?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()?;
        if !read {
            self.invalidate_permission_leases();
        }
        // There is no automatic mutation retry. A caller must reconcile an
        // uncertain outcome before preparing any new request nonce.
        let response = client
            .post(endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|_| ERROR)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|size| size > RESPONSE_BYTES as u64)
        {
            return Err(ERROR.into());
        }
        use futures_util::StreamExt;
        let mut chunks = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|_| ERROR)?;
            if bytes.len().saturating_add(chunk.len()) > RESPONSE_BYTES {
                return Err(ERROR.into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let response: Response = serde_json::from_slice(&bytes).map_err(|_| ERROR)?;
        if response.challenge.is_some() {
            return Err(ERROR.into());
        }
        let returned = response
            .proof
            .as_ref()
            .map(|proof| verify_returned_proof(pin, authority, proof))
            .transpose()?;
        if read {
            if response.receipt.is_some() {
                return Err(ERROR.into());
            }
            let returned = returned.ok_or(ERROR)?;
            self.fetch_witness_freshness(&returned, Instant::now())
                .await?;
            return Ok(VerifiedResponse {
                receipt: None,
                authority: Some(returned),
            });
        }
        let (receipt, position) = verify_receipt(
            pin,
            &signed,
            &command,
            response.receipt.as_deref().ok_or(ERROR)?,
            now()?.as_millis() as u64,
            floor.as_ref(),
        )?;
        if returned
            .as_ref()
            .is_some_and(|authority| authority.head_id() != Some(receipt.authority_head))
        {
            return Err(ERROR.into());
        }
        self.record_witness_receipt_position(pin, position, receipt.previous)?;
        Ok(VerifiedResponse {
            receipt: Some(receipt),
            authority: returned,
        })
    }
}

#[cfg(test)]
mod tests;

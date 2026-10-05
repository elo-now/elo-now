//! Durable public approval evidence. Admission remains exclusively at the witness.
use super::*;
use crate::app::witness_durable_admission::DurableAdmissionRequest;
use crate::authority::WitnessApprovalV2;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    packet: DurableAdmissionRequest,
    approval: Option<String>,
    declined: bool,
}

impl PublicSpaceService {
    fn relay_packet(
        &self,
        packet: &DurableAdmissionRequest,
        config: Option<&ServiceConfig>,
        now: u64,
    ) -> Result<VerifiedCredential> {
        if serde_json::to_vec(packet)?.len() > 32 * 1024 {
            return Err("Admission request is too large.".into());
        }
        let candidate = verify_credential(&packet.credential)?;
        let authority = &self.authorities.0[0];
        let body = authority.verify_witness_join_request(&packet.request, &candidate, now)?;
        let scope = self.team_scope()?;
        if packet.request_id != decode_record(&packet.request.device_request)?.id()
            || packet.expires_at_ms != body.expires_at_ms
            || !record::valid_display_name(&packet.name)
            || serde_json::to_value(&packet.address.scope)? != serde_json::to_value(scope)?
        {
            return Err("Invalid admission request.".into());
        }
        packet.address.validate(self.allow_loopback)?;
        if let Some(config) = config
            && (serde_json::to_value(&packet.address)? != serde_json::to_value(&config.address)?
                || packet.name != config.name)
        {
            return Err("Admission request belongs to another Space.".into());
        }
        Ok(candidate)
    }
    pub(super) fn relay_candidate(
        &self,
        command: &Command,
        credential: &VerifiedCredential,
    ) -> Result<bool> {
        let packet = match command.action.as_str() {
            "witness_request" => serde_json::from_value(command.body["request"].clone())?,
            "witness_pending" => {
                let id: RecordId = field(&command.body, "request_id")?.parse()?;
                self.service_state()?
                    .witness_requests
                    .get(&id)
                    .ok_or("Admission request is unavailable.")?
                    .packet
                    .clone()
            }
            _ => return Ok(false),
        };
        let candidate = self.relay_packet(&packet, None, time()?)?;
        if candidate.record().bytes() != credential.record().bytes() {
            if command.action == "witness_pending"
                && self.authorities.0[0].can_manage(credential.id())
            {
                return Ok(false);
            }
            return Err("Admission request belongs to another device.".into());
        }
        Ok(true)
    }
    pub(super) fn witnessed_relay_command(
        &self,
        config: &ServiceConfig,
        credential: &VerifiedCredential,
        command: &Command,
    ) -> Result<Option<Value>> {
        if !matches!(
            command.action.as_str(),
            "witness_request"
                | "witness_pending"
                | "witness_approve"
                | "witness_decline"
                | "manage"
        ) {
            return Ok(None);
        }
        let now = time()?;
        let authority = &self.authorities.0[0];
        let mut state = self.service_state()?;
        state
            .witness_requests
            .retain(|_, pending| pending.packet.expires_at_ms > now);
        let value = match command.action.as_str() {
            "witness_request" => {
                let packet: DurableAdmissionRequest =
                    serde_json::from_value(command.body["request"].clone())?;
                let candidate = self.relay_packet(&packet, Some(config), now)?;
                if candidate.record().bytes() != credential.record().bytes() {
                    return Err("Admission request belongs to another device.".into());
                }
                if let Some(previous) = state.witness_requests.get(&packet.request_id) {
                    if serde_json::to_value(&previous.packet)? != serde_json::to_value(&packet)? {
                        return Err("Admission request conflicts with stored evidence.".into());
                    }
                } else {
                    if state.witness_requests.len() >= 128
                        || state
                            .witness_requests
                            .values()
                            .filter(|p| p.packet.credential == packet.credential)
                            .count()
                            >= 4
                        || state
                            .witness_requests
                            .values()
                            .filter(|p| p.packet.request.policy == packet.request.policy)
                            .count()
                            >= 32
                    {
                        return Err("Space request limit reached.".into());
                    }
                    state.witness_requests.insert(
                        packet.request_id,
                        Pending {
                            packet: packet.clone(),
                            approval: None,
                            declined: false,
                        },
                    );
                }
                let pending = &state.witness_requests[&packet.request_id];
                json!({"request_id":packet.request_id,"status":if pending.declined {"declined"} else {"pending"}})
            }
            "witness_pending" => {
                let id: RecordId = field(&command.body, "request_id")?.parse()?;
                let pending = state
                    .witness_requests
                    .get(&id)
                    .ok_or("Admission request is unavailable.")?;
                let candidate = self.relay_packet(&pending.packet, Some(config), now)?;
                if candidate.record().bytes() != credential.record().bytes()
                    && !authority.can_manage(credential.id())
                {
                    return Err("Admission request belongs to another device.".into());
                }
                json!({"request":pending.packet,"approval":pending.approval,"status":if pending.declined {"declined"} else {"pending"}})
            }
            "witness_approve" | "witness_decline" => {
                if !authority.can_manage(credential.id()) {
                    return Err("Owner permission is required.".into());
                }
                let id: RecordId = field(&command.body, "request_id")?.parse()?;
                let pending = state
                    .witness_requests
                    .get_mut(&id)
                    .ok_or("Admission request is unavailable.")?;
                self.relay_packet(&pending.packet, Some(config), now)?;
                if command.action == "witness_decline" {
                    if pending.approval.is_some() {
                        return Err("An issued approval cannot be withdrawn by the relay.".into());
                    }
                    pending.declined = true;
                } else {
                    if pending.declined {
                        return Err("This request was declined.".into());
                    }
                    let encoded = field(&command.body, "approval")?;
                    if encoded.len() > 16 * 1024 {
                        return Err("Invalid approval.".into());
                    }
                    let signed = decode_record(encoded)?;
                    let body: WitnessApprovalV2 = signed.decode()?;
                    record::hex::<16>(&body.nonce)?;
                    if body.v != 2
                        || body.kind != "witness.approval"
                        || body.space_id != authority.space()
                        || body.stream_id != authority.stream()
                        || body.request_id != id
                        || body.issuer_credential_id != credential.id()
                        || body.expires_at_ms > pending.packet.expires_at_ms
                        || body.expires_at_ms <= now
                    {
                        return Err("Invalid approval.".into());
                    }
                    signed.verify_signature(credential.key())?;
                    if let Some(previous) = &pending.approval {
                        if decode_record(previous)?.bytes() != signed.bytes() {
                            return Err("An approval already exists.".into());
                        }
                    } else {
                        if Some(body.authority_head) != authority.head_id() {
                            return Err(
                                "General permissions have changed. Refresh and try again.".into()
                            );
                        }
                        pending.approval = Some(encoded.into());
                    }
                }
                json!({"request_id":id,"status":if pending.declined {"declined"} else {"approved"}})
            }
            "manage" => {
                if !authority.can_manage(credential.id()) {
                    return Err("Owner permission is required.".into());
                }
                let requests = state
                    .witness_requests
                    .iter()
                    .filter(|(_, pending)| !pending.declined && pending.approval.is_none())
                    .map(|(id, p)| {
                        let contact = decode_record(&p.packet.request.contact)?;
                        Ok(json!({"id":id,"name":contact.body()["name"],"request":p.packet}))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let roles = state.roles.as_ref().ok_or("Space roles unavailable.")?;
                json!({"offers":[],"requests":requests,"members":self.space_role_members(&state)?,"roles_revision":roles.revision,"primary_owner":roles.primary,"contact_email":roles.contact_email})
            }
            _ => unreachable!(),
        };
        self.save_service_state(&state)?;
        Ok(Some(value))
    }
}

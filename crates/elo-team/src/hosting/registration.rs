//! Reserve hosting capacity before authorizing independent witness registration.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use elo_core::{
    app::space_host::PrepareResponse,
    witness::registration::{MAX_TICKET_LIFETIME_MS, RegistrationTicket},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationBudget {
    // Monotonic and identity-free: local deletion cannot erase a possible
    // registration from the independent, append-only witness.
    issued: usize,
}

fn registration_budget(host: &Host) -> Result<RegistrationBudget> {
    let path = host.config.root.join("registration-budget.json");
    if path.exists() {
        return Ok(serde_json::from_slice(&vault::read_private(&path)?)?);
    }
    // Existing allocations/tombstones count conservatively at the first upgrade.
    let active = host
        .allocations
        .lock()
        .map_err(|_| "Hosting allocation index unavailable.")?
        .len();
    let deleted = std::fs::read_dir(host.config.root.join("deleted"))?.count();
    Ok(RegistrationBudget {
        issued: active.saturating_add(deleted),
    })
}

impl Host {
    /// The caller holds the account write gate. Keep only the identity-free
    /// registration counter when account deletion removes an unfinished setup.
    pub(super) async fn erase_unprovisioned_account_reservations(
        &self,
        identity: IdentityId,
    ) -> Result<()> {
        let _creation = self
            .creation
            .try_lock()
            .map_err(|_| "Hosting creation is busy.")?;
        let active = self.spaces.read().await;
        for entry in std::fs::read_dir(self.config.root.join("spaces"))? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().to_string();
            if id.parse::<ObjectId>().is_err() || active.contains_key(&id) {
                continue;
            }
            let path = entry.path();
            // A quarantined configured Space must follow normal account erasure.
            if path.join("config.json").exists() {
                continue;
            }
            private_directory(&path)?;
            let reservation: Reservation = serde_json::from_slice(&Zeroizing::new(
                vault::read_private(&path.join("reservation.json"))?,
            ))?;
            if reservation.creator != Some(identity) {
                continue;
            }
            if reservation.registration_ticket_issued
                && !self.config.root.join("registration-budget.json").exists()
            {
                return Err("Hosting registration accounting is unavailable.".into());
            }
            std::fs::remove_dir_all(&path)?;
            self.allocations
                .lock()
                .map_err(|_| "Hosting allocation index unavailable.")?
                .remove(&id);
        }
        std::fs::File::open(self.config.root.join("spaces"))?.sync_all()?;
        Ok(())
    }
}

pub(super) fn load_key(path: Option<&FilePath>) -> Result<Option<Zeroizing<[u8; 32]>>> {
    path.map(|path| {
        let bytes = Zeroizing::new(vault::read_private(path)?);
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid hosting registration signing key.")?;
        Ok(Zeroizing::new(key))
    })
    .transpose()
}

pub(super) async fn prepare(
    State(host): State<Arc<Host>>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: HeaderMap,
    Json(request): Json<CreateRequest>,
) -> std::result::Result<Json<PrepareResponse>, StatusCode> {
    let _accounts = host
        .accounts
        .try_read()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    // No queue and no network await: serialize bounded signature verification
    // and durable allocation against creation/deletion before issuing a ticket.
    let _permit = host
        .creation
        .try_lock()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let key = host
        .registration_signing_key
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let pin = host.config.witness.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let now = current().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let expected = format!("{}/spaces/v1/create", host.config.public_url);
    let (command, credential) =
        space_host::verify_create_with_witness(&request, &expected, now, Some(pin))
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    require_owner_managed_creation(&command).map_err(|_| StatusCode::UPGRADE_REQUIRED)?;
    require_creation_device(&host, &credential)?;
    if host.account_requested(credential.identity()) {
        return Err(StatusCode::GONE);
    }
    let authority =
        space_host::verify_creation_authority_with_witness(&command, &credential, Some(pin))
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .ok_or(StatusCode::BAD_REQUEST)?;
    let mut budget = registration_budget(&host).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let existing = host
        .config
        .root
        .join("spaces")
        .join(reservation_id(credential.identity(), &command.request_id))
        .join("reservation.json");
    let ticket_already_issued = if existing.exists() {
        let saved: Reservation = serde_json::from_slice(
            &vault::read_private(&existing).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        saved.registration_ticket_issued
    } else {
        false
    };
    if !ticket_already_issued && budget.issued >= host.config.max_spaces.min(128) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let (reservation_id, mut reservation) = host
        .reserve_creation(
            &command,
            credential.identity(),
            Some(creation_network(peer.map(|peer| peer.0.0.ip()), &headers)),
            Some(elo_core::public_space::AdminEvidence {
                record: request.record,
                credential: request.credential,
            }),
        )
        .map_err(|error| match error.to_string().as_str() {
            "Hosting capacity reached." => StatusCode::TOO_MANY_REQUESTS,
            "Creation request cannot be changed."
            | "This hosting service does not allow the selected message retention policy." => {
                StatusCode::BAD_REQUEST
            }
            "This Space was deleted." => StatusCode::GONE,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        })?;
    // The client may register at the witness and never finish API creation.
    // Retain this allocation durably before releasing any valid ticket, so GC
    // cannot reset API quotas while the witness still retains that genesis.
    if !reservation.registration_ticket_issued {
        budget.issued = budget.issued.saturating_add(1);
        // Count before marking/issuing. Interrupted writes may consume capacity,
        // but can never produce an uncounted valid registration ticket.
        save(&host.config.root.join("registration-budget.json"), &budget)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        reservation.registration_ticket_issued = true;
        save(
            &host
                .config
                .root
                .join("spaces")
                .join(&reservation_id)
                .join("reservation.json"),
            &reservation,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    let expires_at_ms = now.saturating_add(MAX_TICKET_LIFETIME_MS);
    let ticket = RegistrationTicket {
        v: 1,
        kind: "witness.registration_ticket".into(),
        audience: pin.url.clone(),
        witness_public_key: pin.public_key.clone(),
        witness_key_generation: pin.key_generation,
        host: expected,
        space_id: authority.space(),
        stream_id: authority.stream(),
        authority_head: authority.head_id().ok_or(StatusCode::BAD_REQUEST)?,
        creator_identity: credential.identity(),
        credential_id: credential.id(),
        issued_at_ms: now,
        expires_at_ms,
        reservation_id,
    };
    let signed = ticket
        .sign(key)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(PrepareResponse {
        registration_ticket: STANDARD.encode(signed.bytes()),
    }))
}

#[cfg(test)]
mod tests;

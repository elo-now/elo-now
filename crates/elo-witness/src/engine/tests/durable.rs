use super::*;
use elo_core::authority::{
    WitnessAdmissionEvidenceV2, WitnessJoinRequest, WitnessJoinRequestEvidence,
};

fn at(authority: &Authority, actor: &Device, operation: Operation, now: u64) -> Request {
    let mut request = command(authority, actor, operation);
    let mut body: Command = decode(&request.command).unwrap().decode().unwrap();
    body.issued_at_ms = now;
    body.expires_at_ms = now + 60_000;
    request.command = encoded(&signed(&body, &actor.key));
    request
}

impl Fixture {
    fn durable_policy(&mut self, approval: bool, uses: u64) -> SignedRecord {
        let old = self.policy(approval, uses);
        let mut body: WitnessInvitationPolicy = old.decode().unwrap();
        body.nonce = record::random_hex::<16>().unwrap();
        body.expires_at_ms = NOW + 86_400_000;
        let policy = signed(&body, &self.owner.key);
        self.apply(command(
            &self.authority,
            &self.owner,
            Operation::RegisterInvitation {
                policy: encoded(&policy),
            },
        ))
        .unwrap();
        policy
    }

    fn durable_request(&self, policy: &SignedRecord) -> WitnessJoinRequestEvidence {
        let contact = shared::contact(
            &self.guest.credential,
            &self.guest.key,
            "Guest",
            (NOW + 86_400_000) / 1_000,
        )
        .unwrap();
        let body = WitnessJoinRequest {
            v: 1,
            kind: "witness.join_request".into(),
            nonce: record::random_hex::<32>().unwrap(),
            space_id: self.authority.space(),
            stream_id: self.authority.stream(),
            policy_id: policy.id(),
            credential_id: self.guest.credential.id(),
            contact_id: contact.id(),
            issued_at_ms: NOW,
            expires_at_ms: NOW + 86_400_000,
            witness_key_generation: 1,
        };
        WitnessJoinRequestEvidence {
            policy: encoded(policy),
            device_request: encoded(&signed(&body, &self.guest.key)),
            invitation_request: encoded(&signed(&body, &self.invitation)),
            contact: encoded(&contact),
        }
    }

    fn durable_approval(&self, request: &WitnessJoinRequestEvidence) -> String {
        encoded(&signed(
            &WitnessApprovalV2 {
                v: 2,
                kind: "witness.approval".into(),
                nonce: record::random_hex::<16>().unwrap(),
                space_id: self.authority.space(),
                stream_id: self.authority.stream(),
                authority_head: self.authority.head_id().unwrap(),
                issuer_credential_id: self.owner.credential.id(),
                request_id: decode(&request.device_request).unwrap().id(),
                readmission: false,
                expires_at_ms: NOW + 86_400_000,
            },
            &self.owner.key,
        ))
    }

    fn challenge_request(&self, request: WitnessJoinRequestEvidence, now: u64) -> Request {
        let mut command = at(
            &self.authority,
            &self.guest,
            Operation::ChallengeV2 {
                credential: encoded(self.guest.credential.record()),
                request,
                client_nonce: record::random_hex::<32>().unwrap(),
            },
            now,
        );
        command.invitation_signature = Some(encoded(
            &SignedRecord::sign(
                decode(&command.command).unwrap().body_bytes(),
                &self.invitation,
            )
            .unwrap(),
        ));
        command
    }

    fn durable_evidence(
        &mut self,
        request: WitnessJoinRequestEvidence,
        approval: Option<String>,
        now: u64,
    ) -> WitnessAdmissionEvidenceV2 {
        let command = self.challenge_request(request.clone(), now);
        let response = self
            .engine
            .apply(command, "127.0.0.1".parse().unwrap(), now)
            .unwrap();
        let challenge = response.challenge.unwrap();
        let body: WitnessJoinRequest = decode(&request.device_request).unwrap().decode().unwrap();
        let intent = WitnessAdmissionIntentV2 {
            v: 2,
            kind: "witness.admission".into(),
            nonce: record::random_hex::<32>().unwrap(),
            space_id: body.space_id,
            stream_id: body.stream_id,
            policy_id: body.policy_id,
            request_id: decode(&request.device_request).unwrap().id(),
            challenge_id: decode(&challenge).unwrap().id(),
            credential_id: body.credential_id,
            contact_id: body.contact_id,
        };
        WitnessAdmissionEvidenceV2 {
            request,
            challenge,
            device_intent: encoded(&signed(&intent, &self.guest.key)),
            invitation_intent: encoded(&signed(&intent, &self.invitation)),
            approval,
            admitted_at_ms: 0,
        }
    }

    fn durable_admit(&self, evidence: WitnessAdmissionEvidenceV2, now: u64) -> Request {
        let challenge: WitnessChallengeV2 = decode(&evidence.challenge).unwrap().decode().unwrap();
        let mut request = at(
            &self.authority,
            &self.guest,
            Operation::AdmitV2 {
                credential: encoded(self.guest.credential.record()),
                evidence,
            },
            now,
        );
        let mut body: Command = decode(&request.command).unwrap().decode().unwrap();
        body.authority_head = challenge.authority_head;
        request.command = encoded(&signed(&body, &self.guest.key));
        request
    }

    fn restart(mut self, now: u64) -> Self {
        // Retain the anchor before shutting down; never derive approval to
        // activate from the replacement process's own observed position.
        let anchor = self.engine.journal.startup().unwrap().observed_position;
        drop(self.engine);
        let path = self.directory.path();
        let mut journal =
            Journal::open(&path.join("data"), &path.join("key"), self.pin.clone(), now).unwrap();
        let startup = journal.startup().unwrap();
        journal
            .activate(
                Activation {
                    startup_nonce: startup.startup_nonce,
                    expected_position: anchor,
                    public_key: self.pin.public_key.clone(),
                    key_generation: 1,
                    expires_at_ms: now + 60_000,
                },
                now,
            )
            .unwrap();
        self.engine = Engine { journal };
        self
    }
}

#[test]
fn durable_owner_approval_survives_one_hour_and_witness_restart() {
    let mut f = Fixture::new();
    let policy = f.durable_policy(true, 3);
    let request = f.durable_request(&policy);
    let approval = f.durable_approval(&request);
    let old = f.durable_evidence(request.clone(), Some(approval.clone()), NOW);
    let persisted = serde_json::to_vec(&(request, approval)).unwrap();
    let later = NOW + 3_600_000;
    let mut f = f.restart(later);
    let expired = f.durable_admit(old, later);
    assert!(
        f.engine
            .apply(expired, "127.0.0.1".parse().unwrap(), later)
            .is_err()
    );
    let (request, approval) = serde_json::from_slice(&persisted).unwrap();
    let fresh = f.durable_evidence(request, Some(approval), later);
    let admit = f.durable_admit(fresh, later);
    f.engine
        .apply(admit, "127.0.0.1".parse().unwrap(), later)
        .unwrap();
    f.refresh();
    assert!(require_read(&f.authority, f.guest.credential.id()).is_ok());
    assert!(!f.authority.can_manage(f.guest.credential.id()));
    let mut f = f.restart(later);
    f.refresh();
    assert!(require_read(&f.authority, f.guest.credential.id()).is_ok());
}

#[test]
fn durable_two_challenges_consume_one_request_once_across_restart() {
    let mut f = Fixture::new();
    let policy = f.durable_policy(false, 3);
    let request = f.durable_request(&policy);
    let first = f.durable_evidence(request.clone(), None, NOW);
    let competing = f.durable_evidence(request.clone(), None, NOW);
    let first = f.durable_admit(first, NOW);
    let replay = serde_json::to_vec(&first).unwrap();
    let receipt = f.apply(first).unwrap().receipt;
    assert_eq!(
        f.apply(serde_json::from_slice(&replay).unwrap())
            .unwrap()
            .receipt,
        receipt
    );
    let competing = f.durable_admit(competing, NOW);
    assert!(matches!(f.apply(competing), Err(Error::Conflict)));
    let uses: i64 = f
        .engine
        .journal
        .db
        .query_row(
            "SELECT uses FROM policies WHERE id=?1",
            [policy.id().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(uses, 1);
    let mut f = f.restart(NOW);
    let retry = f.challenge_request(request, NOW);
    assert!(matches!(f.apply(retry), Err(Error::Conflict)));
}

#[test]
fn durable_failed_approval_leaves_challenge_and_use_budget_untouched() {
    let mut f = Fixture::new();
    let policy = f.durable_policy(true, 1);
    let request = f.durable_request(&policy);
    let mut evidence = f.durable_evidence(request.clone(), None, NOW);
    let valid = f.durable_approval(&request);
    let legacy = WitnessApproval {
        v: 1,
        kind: "witness.approval".into(),
        nonce: record::random_hex::<16>().unwrap(),
        space_id: f.authority.space(),
        stream_id: f.authority.stream(),
        authority_head: f.authority.head_id().unwrap(),
        issuer_credential_id: f.owner.credential.id(),
        intent_id: decode(&evidence.device_intent).unwrap().id(),
        readmission: false,
    };
    evidence.approval = Some(encoded(&signed(&legacy, &f.owner.key)));
    let before = journal::position(&f.engine.journal.db).unwrap();
    let bad = f.durable_admit(evidence.clone(), NOW);
    assert!(f.apply(bad).is_err());
    assert_eq!(journal::position(&f.engine.journal.db).unwrap(), before);
    assert_eq!(
        f.engine
            .journal
            .db
            .query_row(
                "SELECT uses FROM policies WHERE id=?1",
                [policy.id().to_string()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    evidence.approval = Some(valid);
    let good = f.durable_admit(evidence, NOW);
    f.apply(good).unwrap();
}

#[test]
fn durable_pending_request_does_not_bypass_policy_revocation_or_fresh_possession() {
    let mut f = Fixture::new();
    let policy = f.durable_policy(true, 3);
    let request = f.durable_request(&policy);
    let mut stale_possession = f.challenge_request(request.clone(), NOW);
    stale_possession.invitation_signature = Some(request.invitation_request.clone());
    assert!(f.apply(stale_possession).is_err());
    let approval = f.durable_approval(&request);
    let evidence = f.durable_evidence(request.clone(), Some(approval), NOW);
    f.apply(command(
        &f.authority,
        &f.owner,
        Operation::RevokeInvitation {
            policy_id: policy.id(),
        },
    ))
    .unwrap();
    // Re-registering identical bytes must not reset the durable revoke flag.
    f.apply(command(
        &f.authority,
        &f.owner,
        Operation::RegisterInvitation {
            policy: encoded(&policy),
        },
    ))
    .unwrap();
    let admit = f.durable_admit(evidence, NOW);
    assert!(f.apply(admit).is_err());
    let challenge = f.challenge_request(request, NOW);
    assert!(f.apply(challenge).is_err());
}

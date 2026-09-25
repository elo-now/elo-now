#![allow(dead_code)]
use base64::{Engine, engine::general_purpose::STANDARD};
use elo_call_service::engine::Request;
use elo_core::{
    authority::{
        Authority, Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig,
    },
    calls::{self, Command, Operation},
    ids::StreamId,
    record::{SignedRecord, encode_hex, random_hex},
    vault::Session,
};
pub const AUDIENCE: &str = "https://calls.example.test/calls/v1";
pub const NOW: u64 = 1_800_000_000;

pub struct Fixture {
    pub owner: Session,
    pub owner_recovery: elo_core::vault::RecoveryCard,
    pub peer: Session,
    pub peer_device: Session,
    pub third: Session,
    pub authority: Authority,
}
impl Fixture {
    pub fn new(direct: bool) -> Self {
        let (owner, card) = Session::create().unwrap();
        let (peer, recovery) = Session::create().unwrap();
        let peer_device = Session::recover(&recovery, peer.identity_id()).unwrap();
        let third = Session::create().unwrap().0;
        let root = card.recover_root(owner.identity_id()).unwrap();
        let genesis = SpaceGenesis {
            v: 1,
            kind: "space.genesis".into(),
            nonce: random_hex::<16>().unwrap(),
            issuer_identity: owner.identity_id(),
            owners: vec![Owner {
                identity_id: owner.identity_id(),
                root_public_key: encode_hex(root.verifying_key().as_bytes()),
            }],
            controller_credential_id: owner.credential().id(),
        };
        let record = SignedRecord::sign(&serde_json::to_vec(&genesis).unwrap(), &root).unwrap();
        let mut authority = Authority::new(
            record.bytes(),
            record.id().to_string().parse().unwrap(),
            &root.verifying_key(),
            owner.credential().clone(),
            StreamId::from_bytes([7; 16]),
        )
        .unwrap();
        let mut people = vec![&owner, &peer];
        if !direct {
            people.push(&third);
        }
        let mut members = people
            .into_iter()
            .map(|person| {
                authority.add_credential(person.credential().clone());
                Member {
                    identity_id: person.identity_id(),
                    identity_type: "HUMAN".into(),
                    root_public_key: person.credential().record().body()["root_public_key"]
                        .as_str()
                        .unwrap()
                        .into(),
                    capabilities: if person.identity_id() == owner.identity_id() {
                        vec![
                            Capability::Read,
                            Capability::Post,
                            Capability::ShareHistory,
                            Capability::Manage,
                        ]
                    } else {
                        vec![Capability::Read, Capability::Post]
                    },
                    credential_ids: vec![person.credential().id()],
                    external: false,
                }
            })
            .collect::<Vec<_>>();
        let peer_member = members
            .iter_mut()
            .find(|m| m.identity_id == peer.identity_id())
            .unwrap();
        peer_member
            .credential_ids
            .push(peer_device.credential().id());
        peer_member.credential_ids.sort();
        authority.add_credential(peer_device.credential().clone());
        members.sort_by_key(|person| person.identity_id);
        let config = StreamConfig {
            v: 1,
            kind: "stream.config".into(),
            nonce: random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            sequence: 1,
            previous_config_id: None,
            controller_credential_id: owner.credential().id(),
            members,
            owner_credential_ids: vec![owner.credential().id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: owner.identity_id(),
                request_record_id: None,
            },
            chat_kind: Some(if direct {
                ChatKind::Direct
            } else {
                ChatKind::Chat
            }),
            recovery: None,
        };
        authority
            .apply_config(config.sign(owner.signing_key()).unwrap())
            .unwrap();
        Self {
            owner,
            owner_recovery: card,
            peer,
            peer_device,
            third,
            authority,
        }
    }
    pub fn command(&self, person: &Session, operation: Operation, time: u64) -> Command {
        calls::sign_command(
            &self.authority,
            person,
            self.authority.space(),
            AUDIENCE,
            operation,
            time,
        )
        .unwrap()
        .decode()
        .unwrap()
    }
    pub fn request(
        &self,
        person: &Session,
        operation: Operation,
        time: u64,
        proof: bool,
    ) -> Request {
        Request {
            command: STANDARD.encode(
                calls::sign_command(
                    &self.authority,
                    person,
                    self.authority.space(),
                    AUDIENCE,
                    operation,
                    time,
                )
                .unwrap()
                .bytes(),
            ),
            proof: proof.then(|| self.authority.call_proof().unwrap()),
        }
    }
    pub fn remove_peer(&mut self) {
        let mut config = self.authority.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = self.authority.head_id();
        config.nonce = random_hex::<16>().unwrap();
        config
            .members
            .retain(|member| member.identity_id != self.peer.identity_id());
        config.action.operation = "replace".into();
        self.authority
            .apply_config(config.sign(self.owner.signing_key()).unwrap())
            .unwrap();
    }
}

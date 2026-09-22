//! Explicitly reviewed public contact cards. No chat membership is granted here.
use super::*;

impl ClientApp {
    pub(in crate::app) fn saved_contacts(
        &self,
    ) -> Result<Vec<(SignedRecord, VerifiedCredential, String)>> {
        self.invitation_state()?
            .contacts
            .iter()
            .map(|(id, packet)| {
                if !matches!(packet, Packet::Contact { .. }) {
                    return Err("Invalid saved contact.".into());
                }
                // Expiry bounds the initial exchange, not the lifetime of an explicitly
                // saved contact. Revalidate its signed binding on every use.
                let contact = candidate(packet, 0)?;
                if contact.1.id().to_string() != *id
                    || contact.1.identity() == self.session.identity_id()
                {
                    return Err("Invalid saved contact.".into());
                }
                Ok(contact)
            })
            .collect()
    }

    pub(in crate::app) fn contact_summary(&self) -> Result<Vec<Value>> {
        let mut people = BTreeMap::new();
        for (card, credential, name) in self.saved_contacts()? {
            let body: shared::Contact = card.decode()?;
            let version = (body.expires_at, card.id());
            let entry = people
                .entry(credential.identity())
                .or_insert((version, name.clone()));
            if version > entry.0 {
                *entry = (version, name);
            }
        }
        Ok(people
            .into_iter()
            .map(|(identity, (_, name))| json!({"id":identity,"name":name,"blocked":self.blocked.contains(identity)}))
            .collect())
    }

    pub(super) async fn contact_operation(
        &mut self,
        v: Value,
        mut state: Invitations,
    ) -> Result<Value> {
        let packet = decode(field(&v, "link")?)?;
        if !matches!(packet, Packet::Contact { .. }) {
            return Err("Scan a person's contact code.".into());
        }
        let (card, credential, name) = candidate(&packet, u64::try_from(now()?.as_millis())?)?;
        if credential.identity() == self.session.identity_id() {
            return Err("This is your own contact code.".into());
        }
        if field(&v, "op")? == "contact_preview" {
            return Ok(
                json!({"kind":"contact","id":card.id(),"identity":credential.identity(),"name":name}),
            );
        }
        if self.blocked.contains(credential.identity()) {
            return Err("Unblock this user before contacting them.".into());
        }
        if v["trusted"] != true || v["confirmed_contact"] != json!(card.id()) {
            return Err("Review and confirm this person's identity first.".into());
        }
        state.contacts.insert(credential.id().to_string(), packet);
        self.save_invitations(&state)?;
        Ok(json!({"view":self.view().await?}))
    }
}

//! Local verified unread state. Partial snapshots never erase other chats.
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct Counts {
    pub(crate) identity: String,
    streams: BTreeMap<(String, String, String), u64>,
    invitations: u64,
}

impl Counts {
    pub(crate) const fn new() -> Self {
        Self {
            identity: String::new(),
            streams: BTreeMap::new(),
            invitations: 0,
        }
    }
    pub(crate) fn update(&mut self, view: &Value) -> Option<u64> {
        let identity = view["identity"].as_str()?;
        if identity != self.identity || view["partial"] != true {
            self.streams.clear();
            self.invitations = 0;
            self.identity = identity.into();
        }
        // Use native unread summaries instead of only the loaded history page.
        // Their projection already excludes blocked authors and expired locators.
        let streams = view.get("all_streams").unwrap_or(&view["streams"]);
        for stream in streams.as_array().into_iter().flatten() {
            let key = (
                stream["space_context"].as_str().unwrap_or("").into(),
                stream["space"].as_str()?.into(),
                stream["stream"].as_str()?.into(),
            );
            let count = if stream["muted"] == true {
                0
            } else {
                stream["unread_count"].as_u64().unwrap_or(0)
            };
            self.streams.insert(key, count);
        }
        // A partial chat view carries only its own Space's invitation summary.
        // It must not overwrite the aggregate for other connected Spaces.
        let invitations = view.get("all_invitations").or_else(|| {
            (view["partial"] != true)
                .then(|| view.get("invitations"))
                .flatten()
        });
        if let Some(invitations) = invitations {
            self.invitations = invitations["unseen"]
                .as_u64()
                .unwrap_or(0)
                .saturating_add(invitations["notifications"].as_u64().unwrap_or(0));
        } else if view["partial"] != true {
            self.invitations = 0;
        }
        Some(
            self.streams
                .values()
                .fold(self.invitations, |sum, n| sum.saturating_add(*n)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn unread_activity_survives_partial_reads_but_never_crosses_profiles() {
        let mut counts = Counts::new();
        assert_eq!(
            counts.update(&json!({"identity":"alice","streams":[
            {"space":"a","stream":"chat","unread_count":3},
            {"space":"b","stream":"chat","unread_count":10,"muted":true}],
            "all_invitations":{"unseen":2,"notifications":1,"actionable":7}})),
            Some(6)
        );
        assert_eq!(
            counts.update(&json!({"identity":"alice","partial":true,"streams":[
            {"space":"a","stream":"chat","unread_count":0}],"invitations":{"unseen":0,"notifications":0}})),
            Some(3)
        );
        assert_eq!(
            counts.update(&json!({"identity":"alice","partial":true,"streams":[],
            "all_invitations":{"unseen":0,"notifications":0,"actionable":7}})),
            Some(0)
        );
        assert_eq!(
            counts.update(&json!({"identity":"bob","partial":true,"streams":[]})),
            Some(0)
        );
    }
}

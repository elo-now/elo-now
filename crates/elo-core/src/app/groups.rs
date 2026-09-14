//! Private chat organization, persisted only inside the encrypted workspace.
use super::*;
use std::collections::BTreeSet;

const MAX_GROUPS: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ChatGroup {
    pub id: String,
    pub name: String,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name == name.trim()
        && !name.chars().any(char::is_control)
}

impl Workspace {
    pub(super) fn validate(&self) -> Result<()> {
        if ![1, 2, 3].contains(&self.v) || self.groups.len() > MAX_GROUPS {
            return Err("invalid workspace".into());
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for group in &self.groups {
            if record::hex::<16>(&group.id).is_err()
                || !valid_name(&group.name)
                || !ids.insert(group.id.as_str())
                || !names.insert(group.name.to_lowercase())
            {
                return Err("invalid workspace".into());
            }
        }
        if self.pins.iter().any(|pin| {
            pin.created_at < 0
                || (self.v == 3 && pin.chat_kind.is_none())
                || pin
                    .group
                    .as_ref()
                    .is_some_and(|group| !ids.contains(group.as_str()))
        }) {
            return Err("invalid workspace".into());
        }
        Ok(())
    }
}

impl ClientApp {
    pub(super) fn validate_group(&self, group: Option<&str>) -> Result<()> {
        if group.is_some_and(|id| !self.groups.iter().any(|g| g.id == id)) {
            return Err("unknown chat group".into());
        }
        Ok(())
    }

    pub(super) fn parse_group(&self, request: &Value) -> Result<Option<String>> {
        let group = match request.get("group") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if value.is_empty() => None,
            Some(Value::String(value)) => Some(value.clone()),
            _ => return Err("unknown chat group".into()),
        };
        self.validate_group(group.as_deref())?;
        Ok(group)
    }

    pub(super) fn create_group(&mut self, name: &str) -> Result<()> {
        let name = name.trim();
        if name.eq_ignore_ascii_case("dms") {
            return Err("reserved chat group name".into());
        }
        if !valid_name(name) {
            return Err("invalid chat group name".into());
        }
        if self.groups.len() >= MAX_GROUPS {
            return Err("chat group limit".into());
        }
        if self
            .groups
            .iter()
            .any(|g| g.name.to_lowercase() == name.to_lowercase())
        {
            return Err("chat group name already exists".into());
        }
        let mut groups = self.groups.clone();
        groups.push(ChatGroup {
            id: record::random_hex::<16>()?,
            name: name.into(),
        });
        self.write_workspace(&Workspace {
            v: 3,
            pins: self.pins.clone(),
            groups: groups.clone(),
        })?;
        self.groups = groups;
        Ok(())
    }

    pub(super) fn set_chat_group(&mut self, request: &Value) -> Result<()> {
        let index = self.authority_index(request)?;
        let group = self.parse_group(request)?;
        let mut pins = self.pins.clone();
        pins[index].group = group;
        self.write_workspace(&Workspace {
            v: 3,
            pins: pins.clone(),
            groups: self.groups.clone(),
        })?;
        self.pins = pins;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

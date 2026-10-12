//! Bound proof collection overhead while parsing, before signature verification.
use elo_core::authority::CallAuthorityProof;
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::fmt;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundedProof {
    v: u8,
    genesis: String,
    #[serde(deserialize_with = "credentials")]
    credentials: Vec<String>,
    #[serde(deserialize_with = "configs")]
    configs: Vec<String>,
    #[serde(default)]
    checkpoint: Option<String>,
}

fn strings<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<Vec<String>, D::Error> {
    struct Strings<const N: usize>;
    impl<'de, const N: usize> Visitor<'de> for Strings<N> {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "at most {N} public proof records")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while let Some(value) = input.next_element::<String>()? {
                if values.len() == N {
                    return Err(de::Error::custom("Too many public proof records"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Strings::<N>)
}
fn credentials<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    strings::<D, 8192>(d)
}
fn configs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    strings::<D, 4096>(d)
}
pub(super) fn proof<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<CallAuthorityProof>, D::Error> {
    Ok(
        Option::<BoundedProof>::deserialize(d)?.map(|p| CallAuthorityProof {
            v: p.v,
            genesis: p.genesis,
            credentials: p.credentials,
            configs: p.configs,
            checkpoint: p.checkpoint,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::super::Request;
    use serde_json::json;

    #[test]
    fn oversized_record_collections_fail_during_deserialization() {
        for (field, limit) in [("credentials", 8192), ("configs", 4096)] {
            let mut input = json!({"command":"", "proof":{
                "v":1,"genesis":"", "credentials":[], "configs":[]
            }});
            input["proof"][field] = json!(vec![""; limit]);
            assert!(serde_json::from_value::<Request>(input.clone()).is_ok());
            input["proof"][field]
                .as_array_mut()
                .unwrap()
                .push("".into());
            let bytes = serde_json::to_vec(&input).unwrap();
            assert!(serde_json::from_slice::<Request>(&bytes).is_err());
        }
    }

    #[test]
    fn public_proof_shape_and_optional_fields_are_preserved() {
        for input in [
            json!({"command":"signed"}),
            json!({"command":"signed","proof":null}),
            json!({"command":"signed","proof":{"v":2,"genesis":"g", "credentials":["c"], "configs":["h"], "checkpoint":"p"}}),
        ] {
            let parsed: Request = serde_json::from_value(input.clone()).unwrap();
            assert_eq!(parsed.command, "signed");
            assert_eq!(
                serde_json::to_value(parsed).unwrap()["proof"],
                input["proof"]
            );
        }
    }

    #[test]
    fn unknown_fields_are_rejected_before_their_values_are_traversed() {
        // Deliberately incomplete values demonstrate that no generic Value tree
        // is built for fields outside the signed request/proof format.
        for input in [
            r#"{"command":"signed","unknown":[[["#,
            r#"{"command":"signed","proof":{"unknown":[[["#,
        ] {
            let error = serde_json::from_str::<Request>(input).err().unwrap();
            assert!(error.to_string().contains("unknown field"));
        }
    }

    #[test]
    fn nested_or_duplicate_proof_collections_are_rejected() {
        let nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
        for field in ["credentials", "configs"] {
            let input = format!(
                r#"{{"command":"signed","proof":{{"v":1,"genesis":"g","{field}":[{nested}]}}}}"#
            );
            assert!(serde_json::from_str::<Request>(&input).is_err());
            let duplicate = format!(
                r#"{{"command":"signed","proof":{{"v":1,"genesis":"g","{field}":[],"{field}":[[["#
            );
            let error = serde_json::from_str::<Request>(&duplicate).err().unwrap();
            assert!(error.to_string().contains("duplicate field"));
        }
    }
}

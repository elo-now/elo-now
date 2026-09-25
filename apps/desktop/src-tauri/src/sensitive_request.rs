//! Erase the native JSON copy of profile passwords and recovery material on
//! success, failure, and cancelled futures. This cannot erase WebView/OS copies.
use serde_json::Value;
use zeroize::Zeroize;

pub struct SensitiveRequest(pub Value);
impl std::ops::Deref for SensitiveRequest {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(values) => values.values_mut().for_each(wipe),
        _ => {}
    }
}
impl Drop for SensitiveRequest {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nested_profile_material_is_erased_without_serializing_another_copy() {
        let mut value = serde_json::json!({"password":"test secret", "nested":[{"words":"test recovery words"}], "confirmed":true});
        super::wipe(&mut value);
        assert_eq!(value["password"], "");
        assert_eq!(value["nested"][0]["words"], "");
        assert_eq!(value["confirmed"], true);
    }
}

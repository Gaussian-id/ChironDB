//! Shared CLI parsing helpers reused by gaussctl, gaussgrpcctl, and gausswirectl.

use std::collections::HashMap;

use anyhow::Context as _;

use crate::model::PayloadType;

/// Parse repeated `--payload-field field:type` arguments into a typed schema map.
pub fn parse_payload_schema(raw: &[String]) -> anyhow::Result<HashMap<String, PayloadType>> {
    let mut schema = HashMap::new();
    for item in raw {
        let (field, value_type) = item.split_once(':').with_context(|| {
            format!("invalid payload schema field, expected field:type: {item}")
        })?;
        if field.is_empty() {
            anyhow::bail!("payload schema field must not be empty");
        }
        schema.insert(field.to_string(), parse_payload_type(value_type)?);
    }
    Ok(schema)
}

/// Parse a payload type name string into the typed enum variant.
pub fn parse_payload_type(raw: &str) -> anyhow::Result<PayloadType> {
    match raw {
        "string" => Ok(PayloadType::String),
        "number" => Ok(PayloadType::Number),
        "bool" => Ok(PayloadType::Bool),
        "object" => Ok(PayloadType::Object),
        "array" => Ok(PayloadType::Array),
        "optional_string" | "string?" => Ok(PayloadType::OptionalString),
        "optional_number" | "number?" => Ok(PayloadType::OptionalNumber),
        "optional_bool" | "bool?" => Ok(PayloadType::OptionalBool),
        "optional_object" | "object?" => Ok(PayloadType::OptionalObject),
        "optional_array" | "array?" => Ok(PayloadType::OptionalArray),
        "nullable_string" => Ok(PayloadType::NullableString),
        "nullable_number" => Ok(PayloadType::NullableNumber),
        "nullable_bool" => Ok(PayloadType::NullableBool),
        "nullable_object" => Ok(PayloadType::NullableObject),
        "nullable_array" => Ok(PayloadType::NullableArray),
        v => anyhow::bail!(
            "unknown payload type {v}; expected string, number, bool, object, array, \
             optional_<type>, <type>?, or nullable_<type>"
        ),
    }
}

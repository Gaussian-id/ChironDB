//! Borrowed, versioned audit semantics; timestamps and chain coordinates are
//! projection metadata, while principal, outcome and sanitized details bind
//! the projection to its canonical COMMIT.
use super::*;
use crate::relational::wal_decode::MetadataCharge;
use serde::ser::{SerializeMap, SerializeSeq};

#[derive(Debug)]
pub(crate) struct Sanitized<'a>(pub(crate) &'a Value);
impl Serialize for Sanitized<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(object) => {
                let mut map = serializer.serialize_map(None)?;
                for (key, value) in object {
                    if ![
                        "api_key", "vector", "vectors", "payload", "sql", "query", "point_id",
                    ]
                    .iter()
                    .any(|excluded| key.eq_ignore_ascii_case(excluded))
                    {
                        map.serialize_entry(key, &Sanitized(value))?;
                    }
                }
                map.end()
            }
            Value::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&Sanitized(value))?;
                }
                seq.end()
            }
            value => value.serialize(serializer),
        }
    }
}

#[derive(Serialize)]
struct Semantics<'a, T: Serialize> {
    category: &'a str,
    operation: &'a str,
    collection: Option<&'a str>,
    principal_id: &'a str,
    tenant_id: Option<&'a str>,
    transport: &'a str,
    request_id: Option<&'a str>,
    outcome: &'a str,
    error_code: Option<&'a str>,
    details: T,
}

pub(super) fn digest(value: &impl Serialize) -> Result<[u8; 32]> {
    struct Output(Sha256);
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            crate::relational::check_sql_cancelled().map_err(std::io::Error::other)?;
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut memory = MetadataCharge::default();
    memory.prepare(512)?;
    let mut output = Output(Sha256::new());
    serde_json::to_writer(&mut output, value)?;
    Ok(output.0.finalize().into())
}

pub(crate) fn expected(audit: &crate::transaction_journal::TransactionAudit) -> Result<[u8; 32]> {
    digest(&Semantics {
        category: &audit.category,
        operation: &audit.operation,
        collection: audit.collection.as_deref(),
        principal_id: &audit.principal_id,
        tenant_id: audit.tenant_id.as_deref(),
        transport: &audit.transport,
        request_id: audit.request_id.as_deref(),
        outcome: "success",
        error_code: None,
        details: Sanitized(&audit.details),
    })
}

pub(super) fn record_expected(record: &AuditRecord<'_>) -> Result<[u8; 32]> {
    digest(&Semantics {
        category: record.category,
        operation: record.operation,
        collection: record.collection,
        principal_id: record.principal_id,
        tenant_id: record.tenant_id,
        transport: record.transport,
        request_id: record.request_id,
        outcome: record.outcome,
        error_code: record.error_code,
        details: &record.details,
    })
}

pub(super) fn actual(value: &Value) -> Result<[u8; 32]> {
    let required = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("audit semantics missing {key}")))
    };
    let optional = |key: &str| match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(invalid(format!("invalid audit semantics {key}"))),
    };
    digest(&Semantics {
        category: required("category")?,
        operation: required("operation")?,
        collection: optional("collection")?,
        principal_id: required("principal_id")?,
        tenant_id: optional("tenant_id")?,
        transport: required("transport")?,
        request_id: optional("request_id")?,
        outcome: required("outcome")?,
        error_code: optional("error_code")?,
        details: value.get("details").unwrap_or(&Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantics_bind_every_field_and_use_recursive_redaction_only_for_expected_details() {
        let audit = crate::transaction_journal::TransactionAudit::mutation(
            "insert",
            Some("docs"),
            &AuditContext {
                principal_id: "writer".into(),
                tenant_id: Some("tenant".into()),
                transport: "http".into(),
                request_id: Some("retry".into()),
            },
            serde_json::json!({"rows": 1, "SQL": "secret", "nested": [{"Payload": {"private": true}, "keep": 2}]}),
        );
        let value = serde_json::json!({"category": "mutation", "operation": "insert", "collection": "docs",
            "principal_id": "writer", "tenant_id": "tenant", "transport": "http", "request_id": "retry",
            "outcome": "success", "details": {"rows": 1, "nested": [{"keep": 2}]}});
        let expected = expected(&audit).unwrap();
        assert_eq!(
            super::super::hex_digest(&expected),
            "0ee24d6e0d6681cb9adffc8edd8be2820bd08ac818349efca9eb9ca5ed42a91a"
        );
        assert_eq!(actual(&value).unwrap(), expected);
        for key in [
            "category",
            "operation",
            "collection",
            "principal_id",
            "tenant_id",
            "transport",
            "request_id",
            "outcome",
            "error_code",
            "details",
        ] {
            let mut changed = value.clone();
            changed[key] = Value::String("changed".into());
            assert_ne!(actual(&changed).unwrap(), expected, "{key}");
        }
        let mut injected = value;
        injected["details"]["sql"] = Value::String("unexpected persisted secret".into());
        assert_ne!(actual(&injected).unwrap(), expected);
    }

    #[test]
    fn fingerprint_admission_and_cancellation_release_ownership() {
        crate::relational::wal_decode::with_test_storage_pool(511, |used| {
            assert!(matches!(
                digest(&Value::Null),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        crate::relational::wal_decode::with_test_storage_pool(4096, |used| {
            let flag = Arc::new(AtomicBool::new(true));
            assert!(
                crate::relational::with_sql_cancellation(flag, || digest(&Value::Null)).is_err()
            );
            assert_eq!(used(), 0);
            digest(&Value::Null).unwrap();
            assert_eq!(used(), 0);
        });
    }
}

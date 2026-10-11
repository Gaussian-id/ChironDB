//! Compile the existing filter grammar before policy evaluation. Ambiguous
//! literal/dotted aliases are checked against schema, never against secret data.
use super::{policy, *};
use crate::Filter;
use serde_json::Value;
use std::collections::BTreeSet;

type Result<T> = std::result::Result<T, SecurityError>;

#[derive(Clone, Debug)]
pub struct SecurityFilter {
    filter: Filter,
    references: Vec<BTreeSet<String>>,
}
impl SecurityFilter {
    pub fn compile(filter: Filter) -> Result<Self> {
        filter
            .validate_complexity()
            .map_err(SecurityError::Invalid)?;
        super::storage::serialized_len(&filter, 64 * 1024)
            .map_err(|_| SecurityError::BudgetExceeded)?;
        let mut references = Vec::new();
        collect(
            &filter.0,
            &BTreeSet::from([String::new()]),
            &mut references,
            &mut 0,
        )?;
        Ok(Self { filter, references })
    }
    pub(crate) fn matches(
        &self,
        record: &ResourceRecord,
        attributes: &SubjectAttributes,
        payload: &Value,
    ) -> Result<bool> {
        for aliases in &self.references {
            let mut known = false;
            for alias in aliases {
                if let Some(rule) = rule_for_path(record, alias) {
                    known = true;
                    if attributes.clearance < rule.classification
                        || !rule.actions.contains(&PropertyAction::Query)
                    {
                        return Err(SecurityError::Forbidden);
                    }
                }
            }
            if !known {
                return Err(SecurityError::Forbidden);
            }
        }
        // Unlabelled/hidden literal keys must not shadow an authorized dotted
        // path in Filter's legacy literal-first lookup.
        let query_payload =
            policy::project_payload(record, attributes, payload, PropertyAction::Query);
        Ok(self.filter.matches(&query_payload))
    }
}

fn rule_for_path<'a>(record: &'a ResourceRecord, path: &str) -> Option<&'a PropertyRule> {
    record.properties.get(path).or_else(|| {
        path.rmatch_indices('/')
            .filter(|(index, _)| *index > 0)
            .find_map(|(index, _)| record.properties.get(&path[..index]))
    })
}
fn pointer_component(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
fn collect(
    value: &Value,
    prefixes: &BTreeSet<String>,
    references: &mut Vec<BTreeSet<String>>,
    work: &mut usize,
) -> Result<()> {
    let conditions = value
        .as_object()
        .ok_or_else(|| SecurityError::Invalid("filter must be an object".into()))?;
    for (field, expected) in conditions {
        let mut aliases = BTreeSet::new();
        for prefix in prefixes {
            aliases.insert(format!("{prefix}/{}", pointer_component(field)));
            let path = field
                .split('.')
                .map(|part| pointer_component(part.strip_suffix("[]").unwrap_or(part)))
                .collect::<Vec<_>>()
                .join("/");
            aliases.insert(format!("{prefix}/{path}"));
        }
        *work = work
            .checked_add(aliases.len())
            .ok_or(SecurityError::BudgetExceeded)?;
        if *work > MAX_POLICY_GRANTS {
            return Err(SecurityError::BudgetExceeded);
        }
        // A nested-only condition inspects its children, not the full container.
        // Empty nested conditions still query container existence.
        let nested_only = expected
            .as_object()
            .is_some_and(|ops| ops.len() == 1 && ops.contains_key("nested"));
        if !nested_only {
            references.push(aliases.clone());
        }
        if let Some(operators) = expected.as_object() {
            for (operator, bound) in operators {
                match operator.as_str() {
                    "eq" | "ne" => {}
                    "gt" | "gte" | "lt" | "lte" if bound.is_number() => {}
                    "in" if bound.is_array() => {}
                    "text" if bound.is_string() => {}
                    "nested" => {
                        let nested = if let Some(wrapper) =
                            bound.as_object().filter(|map| map.contains_key("filter"))
                        {
                            if wrapper.len() != 1 {
                                return Err(SecurityError::Invalid(
                                    "ambiguous nested filter wrapper".into(),
                                ));
                            }
                            &wrapper["filter"]
                        } else {
                            bound
                        };
                        if nested.as_object().is_some_and(|map| map.is_empty()) {
                            references.push(aliases.clone());
                        }
                        collect(nested, &aliases, references, work)?;
                    }
                    _ => {
                        return Err(SecurityError::Invalid(
                            "unsupported filter operator or value type".into(),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn literal_shadowing_and_nested_filters_cannot_query_hidden_properties() {
        let attributes = SubjectAttributes {
            department: "Finance".into(),
            clearance: Classification::Internal,
        };
        let mut record = ResourceRecord {
            key: PointKey {
                collection: uuid::Uuid::new_v4(),
                tenant: "acme".into(),
                id: "doc".into(),
            },
            storage_id: uuid::Uuid::new_v4(),
            labels: ResourceLabels {
                owner: "writer".into(),
                department: "Finance".into(),
                classification: Classification::Internal,
                quarantined: false,
            },
            properties: BTreeMap::from([(
                "/profile/name".into(),
                PropertyRule {
                    classification: Classification::Internal,
                    actions: BTreeSet::from([PropertyAction::Query]),
                },
            )]),
            representations: BTreeMap::new(),
            grants: Vec::new(),
            parent: None,
            revision: 1,
            retired: false,
            create_receipt: None,
        };
        let filter =
            SecurityFilter::compile(Filter(serde_json::json!({"profile.name":"visible"}))).unwrap();
        for secret in ["visible", "private", "different"] {
            let payload = serde_json::json!({"profile":{"name":"visible"},"profile.name":secret});
            assert!(
                filter.matches(&record, &attributes, &payload).unwrap(),
                "unlabelled literal must not shadow the authorized nested path"
            );
        }
        record.properties.insert(
            "/profile.name".into(),
            PropertyRule {
                classification: Classification::Restricted,
                actions: BTreeSet::from([PropertyAction::Query]),
            },
        );
        for payload in [
            serde_json::json!({"profile":{"name":"visible"}}),
            serde_json::json!({"profile":{"name":"visible"},"profile.name":"private"}),
        ] {
            assert_eq!(
                filter.matches(&record, &attributes, &payload).unwrap_err(),
                SecurityError::Forbidden,
                "ambiguous reference must be rejected independently of hidden key presence"
            );
        }
        let nested = SecurityFilter::compile(Filter(
            serde_json::json!({"profile":{"nested":{"name":"visible"}}}),
        ))
        .unwrap();
        assert!(
            nested
                .matches(
                    &record,
                    &attributes,
                    &serde_json::json!({"profile":{"name":"visible"}})
                )
                .unwrap(),
            "nested traversal to a queryable child does not read the entire container"
        );
        let existence =
            SecurityFilter::compile(Filter(serde_json::json!({"profile":{"nested":{}}}))).unwrap();
        assert_eq!(
            existence
                .matches(
                    &record,
                    &attributes,
                    &serde_json::json!({"profile":{"name":"visible"}})
                )
                .unwrap_err(),
            SecurityError::Forbidden
        );
        let large = Filter(serde_json::json!({"profile.name":"x".repeat(65536)}));
        assert_eq!(
            SecurityFilter::compile(large).unwrap_err(),
            SecurityError::BudgetExceeded
        );
        assert!(SecurityFilter::compile(Filter(serde_json::json!([]))).is_err());
        assert!(
            SecurityFilter::compile(Filter(
                serde_json::json!({"profile.name":{"gte":"bad-type"}})
            ))
            .is_err()
        );
    }
}

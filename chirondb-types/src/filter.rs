use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Filter(pub Value);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedFilterTerm {
    pub field: String,
    pub values: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum IndexedFilterPredicate {
    Equality(IndexedFilterTerm),
    NumericRange(IndexedNumericRangeTerm),
    Text(IndexedTextTerm),
}

#[derive(Clone, Debug, PartialEq)]
pub struct IndexedTextTerm {
    pub field: String,
    pub required_terms: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IndexedNumericRangeTerm {
    pub field: String,
    pub gt: Option<f64>,
    pub gte: Option<f64>,
    pub lt: Option<f64>,
    pub lte: Option<f64>,
}

impl IndexedNumericRangeTerm {
    pub fn matches(&self, value: f64) -> bool {
        self.gt.is_none_or(|bound| value > bound)
            && self.gte.is_none_or(|bound| value >= bound)
            && self.lt.is_none_or(|bound| value < bound)
            && self.lte.is_none_or(|bound| value <= bound)
    }
}

impl Filter {
    pub fn validate_complexity(&self) -> Result<(), String> {
        const MAX_DEPTH: usize = 16;
        const MAX_NODES: usize = 1024;
        const MAX_CONTAINER_ITEMS: usize = 256;
        const MAX_FIELD_BYTES: usize = 256;

        let mut stack = vec![(&self.0, 0_usize)];
        let mut nodes = 0_usize;
        while let Some((value, depth)) = stack.pop() {
            nodes = nodes
                .checked_add(1)
                .ok_or_else(|| "filter node count overflow".to_string())?;
            if nodes > MAX_NODES {
                return Err(format!("filter exceeds {MAX_NODES} value nodes"));
            }
            if depth > MAX_DEPTH {
                return Err(format!("filter nesting exceeds depth {MAX_DEPTH}"));
            }
            match value {
                Value::Object(object) => {
                    if object.len() > MAX_CONTAINER_ITEMS {
                        return Err(format!(
                            "filter object exceeds {MAX_CONTAINER_ITEMS} entries"
                        ));
                    }
                    for (field, child) in object {
                        if field.len() > MAX_FIELD_BYTES {
                            return Err(format!("filter field exceeds {MAX_FIELD_BYTES} bytes"));
                        }
                        stack.push((child, depth + 1));
                    }
                }
                Value::Array(array) => {
                    if array.len() > MAX_CONTAINER_ITEMS {
                        return Err(format!(
                            "filter array exceeds {MAX_CONTAINER_ITEMS} entries"
                        ));
                    }
                    stack.extend(array.iter().map(|child| (child, depth + 1)));
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }
        Ok(())
    }

    pub fn matches(&self, payload: &Value) -> bool {
        let Some(conditions) = self.0.as_object() else {
            return true;
        };

        conditions.iter().all(|(field, expected)| {
            let actual_values = payload_field_values(payload, field);
            !actual_values.is_empty()
                && actual_values
                    .iter()
                    .any(|actual| matches_condition(actual, expected))
        })
    }

    pub fn indexed_terms(&self) -> Option<Vec<IndexedFilterTerm>> {
        let terms: Vec<IndexedFilterTerm> = self
            .indexed_predicates()?
            .into_iter()
            .filter_map(|predicate| match predicate {
                IndexedFilterPredicate::Equality(term) => Some(term),
                IndexedFilterPredicate::NumericRange(_) | IndexedFilterPredicate::Text(_) => None,
            })
            .collect();
        if terms.is_empty() { None } else { Some(terms) }
    }

    pub fn indexed_predicates(&self) -> Option<Vec<IndexedFilterPredicate>> {
        let conditions = self.0.as_object()?;
        let mut predicates = Vec::with_capacity(conditions.len());
        for (field, expected) in conditions {
            predicates.extend(indexed_condition(field, expected)?);
        }
        Some(predicates)
    }
}

fn matches_condition(actual: &Value, expected: &Value) -> bool {
    let Some(condition) = expected.as_object() else {
        return actual == expected;
    };

    condition.iter().all(|(op, bound)| match op.as_str() {
        "eq" => actual == bound,
        "ne" => actual != bound,
        "gt" => compare_numbers(actual, bound, |left, right| left > right),
        "gte" => compare_numbers(actual, bound, |left, right| left >= right),
        "lt" => compare_numbers(actual, bound, |left, right| left < right),
        "lte" => compare_numbers(actual, bound, |left, right| left <= right),
        "nested" => matches_nested_filter(actual, bound),
        "text" => matches_text(actual, bound),
        "in" => bound
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value == actual)),
        _ => false,
    })
}

fn matches_text(actual: &Value, expected: &Value) -> bool {
    let Some(actual) = actual.as_str() else {
        return false;
    };
    let Some(query) = expected.as_str() else {
        return false;
    };
    contains_all_terms(actual, query)
}

fn contains_all_terms(actual: &str, query: &str) -> bool {
    let terms = tokenize(query);
    if terms.is_empty() {
        return false;
    }
    let haystack = tokenize(actual);
    terms
        .iter()
        .all(|term| haystack.iter().any(|candidate| candidate == term))
}

pub fn tokenize(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn matches_nested_filter(actual: &Value, expected: &Value) -> bool {
    let filter = expected
        .as_object()
        .and_then(|condition| condition.get("filter"))
        .unwrap_or(expected);
    if !filter.is_object() {
        return false;
    }
    Filter(filter.clone()).matches(actual)
}

fn payload_field_values<'a>(payload: &'a Value, field: &str) -> Vec<&'a Value> {
    if let Some(value) = payload.get(field) {
        let mut values = Vec::new();
        collect_terminal_values(value, &mut values);
        return values;
    }
    let components = field.split('.').collect::<Vec<_>>();
    let mut values = Vec::new();
    collect_path_values(payload, &components, &mut values);
    values
}

fn collect_path_values<'a>(value: &'a Value, components: &[&str], values: &mut Vec<&'a Value>) {
    if components.is_empty() {
        collect_terminal_values(value, values);
        return;
    }

    match value {
        Value::Object(object) => {
            let component = normalize_path_component(components[0]);
            if let Some(child) = object.get(component) {
                collect_path_values(child, &components[1..], values);
            }
        }
        Value::Array(array) => {
            for item in array {
                collect_path_values(item, components, values);
            }
        }
        _ => {}
    }
}

fn collect_terminal_values<'a>(value: &'a Value, values: &mut Vec<&'a Value>) {
    match value {
        Value::Array(array) => {
            for item in array {
                collect_terminal_values(item, values);
            }
        }
        _ => values.push(value),
    }
}

fn normalize_path_component(component: &str) -> &str {
    component.strip_suffix("[]").unwrap_or(component)
}

fn compare_numbers<F>(actual: &Value, bound: &Value, predicate: F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    match (actual.as_f64(), bound.as_f64()) {
        (Some(left), Some(right)) => predicate(left, right),
        _ => false,
    }
}

fn indexed_condition(field: &str, expected: &Value) -> Option<Vec<IndexedFilterPredicate>> {
    let field = normalize_index_field(field);
    let Some(condition) = expected.as_object() else {
        if !is_indexable_value(expected) {
            return None;
        }
        return Some(vec![IndexedFilterPredicate::Equality(IndexedFilterTerm {
            field,
            values: vec![expected.clone()],
        })]);
    };

    if condition.len() == 1 {
        let (op, bound) = condition.iter().next()?;
        match op.as_str() {
            "eq" if is_indexable_value(bound) => {
                return Some(vec![IndexedFilterPredicate::Equality(IndexedFilterTerm {
                    field,
                    values: vec![bound.clone()],
                })]);
            }
            "in" => {
                return bound
                    .as_array()
                    .filter(|values| values.iter().all(is_indexable_value))
                    .cloned()
                    .map(|values| {
                        vec![IndexedFilterPredicate::Equality(IndexedFilterTerm {
                            field,
                            values,
                        })]
                    });
            }
            "nested" => return indexed_nested_conditions(&field, bound),
            "text" => {
                let terms = bound.as_str().map(tokenize).unwrap_or_default();
                if terms.is_empty() {
                    return None;
                }
                return Some(vec![IndexedFilterPredicate::Text(IndexedTextTerm {
                    field,
                    required_terms: terms,
                })]);
            }
            _ => {}
        }
    }

    let mut range = IndexedNumericRangeTerm {
        field,
        gt: None,
        gte: None,
        lt: None,
        lte: None,
    };
    for (op, bound) in condition {
        let bound = bound.as_f64()?;
        match op.as_str() {
            "gt" => range.gt = Some(bound),
            "gte" => range.gte = Some(bound),
            "lt" => range.lt = Some(bound),
            "lte" => range.lte = Some(bound),
            _ => return None,
        }
    }
    Some(vec![IndexedFilterPredicate::NumericRange(range)])
}

fn indexed_nested_conditions(field: &str, expected: &Value) -> Option<Vec<IndexedFilterPredicate>> {
    let nested_filter = expected
        .as_object()
        .and_then(|condition| condition.get("filter"))
        .unwrap_or(expected);
    let conditions = nested_filter.as_object()?;
    let mut predicates = Vec::new();
    for (nested_field, nested_expected) in conditions {
        let nested_predicates = match indexed_condition(nested_field, nested_expected) {
            Some(predicates) => predicates,
            None => continue,
        };
        predicates.extend(
            nested_predicates
                .into_iter()
                .map(|predicate| prefix_indexed_predicate_field(field, predicate)),
        );
    }
    Some(predicates)
}

fn prefix_indexed_predicate_field(
    prefix: &str,
    predicate: IndexedFilterPredicate,
) -> IndexedFilterPredicate {
    match predicate {
        IndexedFilterPredicate::Equality(mut term) => {
            term.field = join_index_fields(prefix, &term.field);
            IndexedFilterPredicate::Equality(term)
        }
        IndexedFilterPredicate::NumericRange(mut term) => {
            term.field = join_index_fields(prefix, &term.field);
            IndexedFilterPredicate::NumericRange(term)
        }
        IndexedFilterPredicate::Text(mut term) => {
            term.field = join_index_fields(prefix, &term.field);
            IndexedFilterPredicate::Text(term)
        }
    }
}

fn join_index_fields(prefix: &str, field: &str) -> String {
    if prefix.is_empty() {
        field.to_string()
    } else if field.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}.{field}")
    }
}

fn normalize_index_field(field: &str) -> String {
    field
        .split('.')
        .map(normalize_path_component)
        .collect::<Vec<_>>()
        .join(".")
}

fn is_indexable_value(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{Filter, IndexedFilterPredicate};

    #[test]
    fn supports_equality_and_range_filters() {
        let payload = json!({"tenant": "acme", "price": 125});
        let filter = Filter(json!({"tenant": "acme", "price": {"gte": 100, "lt": 200}}));
        assert!(filter.matches(&payload));
    }

    #[test]
    fn supports_nested_payload_field_paths() {
        let payload = json!({
            "profile": {"region": "us", "score": 42},
            "profile.region": "direct"
        });
        assert!(Filter(json!({"profile.region": "direct"})).matches(&payload));
        assert!(Filter(json!({"profile.score": {"gte": 40}})).matches(&payload));
        assert!(!Filter(json!({"profile.missing": "us"})).matches(&payload));
    }

    #[test]
    fn supports_array_payload_field_paths() {
        let payload = json!({
            "tags": ["black", "green"],
            "diet": [
                {"food": "leaves", "likes": false},
                {"food": "meat", "likes": true}
            ]
        });
        assert!(Filter(json!({"tags": "black"})).matches(&payload));
        assert!(Filter(json!({"diet[].food": "meat"})).matches(&payload));
        assert!(Filter(json!({"diet.likes": true})).matches(&payload));
        assert!(!Filter(json!({"diet[].food": "fish"})).matches(&payload));
    }

    #[test]
    fn supports_correlated_nested_array_filters() {
        let target = json!({
            "dinosaur": "t-rex",
            "diet": [
                {"food": "leaves", "likes": false},
                {"food": "meat", "likes": true}
            ]
        });
        let false_positive_without_nested = json!({
            "dinosaur": "diplodocus",
            "diet": [
                {"food": "leaves", "likes": true},
                {"food": "meat", "likes": false}
            ]
        });

        let flattened = Filter(json!({"diet[].food": "meat", "diet[].likes": true}));
        assert!(flattened.matches(&target));
        assert!(flattened.matches(&false_positive_without_nested));

        let nested = Filter(json!({"diet": {"nested": {"food": "meat", "likes": true}}}));
        assert!(nested.matches(&target));
        assert!(!nested.matches(&false_positive_without_nested));

        let nested_with_filter_key =
            Filter(json!({"diet[]": {"nested": {"filter": {"food": "meat", "likes": true}}}}));
        assert!(nested_with_filter_key.matches(&target));
        assert!(!nested_with_filter_key.matches(&false_positive_without_nested));
    }

    #[test]
    fn extracts_indexable_equality_terms() {
        let filter = Filter(json!({"tenant": "acme", "tier": {"in": ["gold", "silver"]}}));
        let terms = filter.indexed_terms().unwrap();
        assert_eq!(terms.len(), 2);
        assert_eq!(terms[0].field, "tenant");
        assert_eq!(terms[0].values, vec![json!("acme")]);
        assert_eq!(terms[1].field, "tier");
        assert_eq!(terms[1].values, vec![json!("gold"), json!("silver")]);

        let nested_array = Filter(json!({"diet[].food": "meat"}));
        assert_eq!(nested_array.indexed_terms().unwrap()[0].field, "diet.food");

        let range_filter = Filter(json!({"price": {"gte": 100}}));
        assert!(range_filter.indexed_terms().is_none());

        let nested_filter = Filter(json!({"metadata": {"eq": {"region": "us"}}}));
        assert!(nested_filter.indexed_terms().is_none());

        let correlated_nested = Filter(json!({"diet": {"nested": {"food": "meat"}}}));
        let nested_terms = correlated_nested.indexed_terms().unwrap();
        assert_eq!(nested_terms.len(), 1);
        assert_eq!(nested_terms[0].field, "diet.food");
        assert_eq!(nested_terms[0].values, vec![json!("meat")]);
    }

    #[test]
    fn extracts_indexable_numeric_range_terms() {
        let filter = Filter(json!({"tenant": "acme", "price": {"gte": 100, "lt": 200}}));
        let predicates = filter.indexed_predicates().unwrap();
        assert_eq!(predicates.len(), 2);
        assert!(
            predicates
                .iter()
                .any(|predicate| matches!(predicate, IndexedFilterPredicate::Equality(_)))
        );
        let range = predicates
            .iter()
            .find_map(|predicate| match predicate {
                IndexedFilterPredicate::NumericRange(range) => Some(range),
                IndexedFilterPredicate::Equality(_) | IndexedFilterPredicate::Text(_) => None,
            })
            .expect("expected numeric range predicate");
        assert_eq!(range.field, "price");
        assert!(range.matches(100.0));
        assert!(range.matches(199.0));
        assert!(!range.matches(200.0));

        let nested =
            Filter(json!({"diet": {"nested": {"food": "meat", "calories": {"lte": 500}}}}));
        let predicates = nested.indexed_predicates().unwrap();
        assert_eq!(predicates.len(), 2);
        assert!(predicates.iter().any(|predicate| {
            matches!(
                predicate,
                IndexedFilterPredicate::Equality(term)
                    if term.field == "diet.food" && term.values == vec![json!("meat")]
            )
        }));
        assert!(predicates.iter().any(|predicate| {
            matches!(
                predicate,
                IndexedFilterPredicate::NumericRange(range)
                    if range.field == "diet.calories" && range.lte == Some(500.0)
            )
        }));
    }

    #[test]
    fn supports_full_text_payload_filter_operator() {
        let payload = json!({
            "title": "Rust-native vector search",
            "body": "Hybrid dense sparse retrieval with payload filters"
        });
        assert!(Filter(json!({"title": {"text": "vector rust"}})).matches(&payload));
        assert!(Filter(json!({"body": {"text": "Dense retrieval"}})).matches(&payload));
        assert!(!Filter(json!({"title": {"text": "python"}})).matches(&payload));
        assert!(!Filter(json!({"title": {"text": ""}})).matches(&payload));
    }

    #[test]
    fn rejects_excessive_filter_depth_and_width() {
        let mut nested = json!(true);
        for _ in 0..18 {
            nested = json!({"nested": nested});
        }
        assert!(Filter(nested).validate_complexity().is_err());
        assert!(
            Filter(Value::Array((0..257).map(Value::from).collect()))
                .validate_complexity()
                .is_err()
        );
    }
}

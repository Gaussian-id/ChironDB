use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap, HashSet},
    ops::Bound,
};

use roaring::RoaringBitmap;
use serde_json::Value;

use crate::{
    Filter,
    error::{GaussError, Result},
    filter::{
        IndexedFilterPredicate, IndexedFilterTerm, IndexedNumericRangeTerm, IndexedTextTerm,
        tokenize,
    },
    model::{CollectionConfig, PayloadType, Point},
    ordinal::SegmentOrdinalSet,
};

pub(crate) type PayloadEqualityIndex = HashMap<String, HashMap<String, HashSet<String>>>;
pub(crate) type PayloadNumericIndex = HashMap<String, BTreeMap<u64, HashSet<String>>>;
/// field → term → set of point IDs that contain the term in that field.
pub(crate) type PayloadTextIndex = HashMap<String, HashMap<String, HashSet<String>>>;

#[derive(Clone, Debug, Default)]
pub(crate) struct PayloadIndex {
    pub(crate) equality: PayloadEqualityIndex,
    pub(crate) numeric: PayloadNumericIndex,
    pub(crate) text: PayloadTextIndex,
}

pub(crate) type OrdinalPayloadEqualityIndex = HashMap<String, HashMap<String, RoaringBitmap>>;
pub(crate) type OrdinalPayloadNumericIndex = HashMap<String, BTreeMap<u64, RoaringBitmap>>;
pub(crate) type OrdinalPayloadTextIndex = HashMap<String, HashMap<String, RoaringBitmap>>;

/// Payload postings for one immutable sealed segment.
///
/// Unlike [`PayloadIndex`], postings contain stable segment ordinals. The
/// string index remains the permanent mutable/legacy fallback.
#[derive(Clone, Debug, Default)]
pub(crate) struct OrdinalPayloadIndex {
    equality: OrdinalPayloadEqualityIndex,
    numeric: OrdinalPayloadNumericIndex,
    text: OrdinalPayloadTextIndex,
}

/// Internal prefilter result: ordinal-native sealed candidates plus the
/// string-keyed mutable/legacy compatibility leg.
#[derive(Clone, Debug, Default)]
pub(crate) struct PayloadCandidateSet {
    pub(crate) sealed: SegmentOrdinalSet,
    pub(crate) fallback: HashSet<String>,
}

impl PayloadCandidateSet {
    pub(crate) fn len(&self) -> usize {
        usize::try_from(self.sealed.len())
            .unwrap_or(usize::MAX)
            .saturating_add(self.fallback.len())
    }
}

// ── Schema validation ────────────────────────────────────────────────────────

pub(crate) fn validate_payload_schema(config: &CollectionConfig, point: &Point) -> Result<()> {
    for (field, expected) in &config.payload_schema {
        let values = payload_schema_values(&point.payload, field);
        if values.is_empty() {
            if expected.is_optional() {
                continue;
            }
            return Err(GaussError::InvalidRequest(format!(
                "payload field '{field}' is required by schema"
            )));
        }
        if values
            .iter()
            .all(|value| payload_type_matches(value, *expected))
        {
            continue;
        }
        return Err(GaussError::InvalidRequest(format!(
            "payload field '{field}' must be {expected}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_payload_field(field: &str) -> Result<()> {
    if field.is_empty() || !field.split('.').all(is_valid_payload_field_component) {
        return Err(GaussError::InvalidRequest(
            "payload schema fields must be dot-separated non-empty ASCII alphanumeric, '_' or '-' components".to_string(),
        ));
    }
    Ok(())
}

fn payload_type_matches(value: &Value, expected: PayloadType) -> bool {
    if value.is_null() {
        return expected.is_nullable();
    }
    match expected.base_type() {
        PayloadType::String => value.is_string(),
        PayloadType::Number => value.is_number(),
        PayloadType::Bool => value.is_boolean(),
        PayloadType::Object => value.is_object(),
        PayloadType::Array => value.is_array(),
        PayloadType::OptionalString
        | PayloadType::OptionalNumber
        | PayloadType::OptionalBool
        | PayloadType::OptionalObject
        | PayloadType::OptionalArray
        | PayloadType::NullableString
        | PayloadType::NullableNumber
        | PayloadType::NullableBool
        | PayloadType::NullableObject
        | PayloadType::NullableArray => unreachable!("base_type returns a primitive payload type"),
    }
}

pub(crate) fn payload_schema_values<'a>(payload: &'a Value, field: &str) -> Vec<&'a Value> {
    if let Some(value) = payload.get(field) {
        return vec![value];
    }
    let components = field.split('.').collect::<Vec<_>>();
    let mut values = Vec::new();
    collect_payload_path_values(payload, &components, &mut values);
    values
}

fn collect_payload_path_values<'a>(
    value: &'a Value,
    components: &[&str],
    values: &mut Vec<&'a Value>,
) {
    if components.is_empty() {
        values.push(value);
        return;
    }

    match value {
        Value::Object(object) => {
            let component = normalize_payload_path_component(components[0]);
            if let Some(child) = object.get(component) {
                collect_payload_path_values(child, &components[1..], values);
            }
        }
        Value::Array(array) => {
            for item in array {
                collect_payload_path_values(item, components, values);
            }
        }
        _ => {}
    }
}

fn normalize_payload_path_component(component: &str) -> &str {
    component.strip_suffix("[]").unwrap_or(component)
}

fn is_valid_payload_field_component(component: &str) -> bool {
    let component = normalize_payload_path_component(component);
    !component.is_empty()
        && component
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

// ── Index construction ───────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) fn build_payload_index(points: &HashMap<String, Point>) -> PayloadIndex {
    build_payload_index_iter(points.values())
}

/// Iterator variant: builds from any live-point stream (multi-segment
/// collections chain the streamer and every searcher store).
pub(crate) fn build_payload_index_iter<P: Borrow<Point>>(
    points: impl Iterator<Item = P>,
) -> PayloadIndex {
    let mut index = PayloadIndex::default();
    for point in points {
        insert_payload_point(&mut index, point.borrow());
    }
    index
}

pub(crate) fn build_ordinal_payload_index<P: Borrow<Point>>(
    points: impl Iterator<Item = (u32, P)>,
) -> OrdinalPayloadIndex {
    let mut index = OrdinalPayloadIndex::default();
    for (ordinal, point) in points {
        insert_ordinal_payload_point(&mut index, point.borrow(), ordinal);
    }
    index
}

fn insert_ordinal_payload_point(index: &mut OrdinalPayloadIndex, point: &Point, ordinal: u32) {
    let Some(payload) = point.payload.as_object() else {
        return;
    };
    for (field, value) in payload {
        insert_ordinal_payload_value(index, field, value, ordinal);
    }
}

fn insert_ordinal_payload_value(
    index: &mut OrdinalPayloadIndex,
    field: &str,
    value: &Value,
    ordinal: u32,
) {
    if let Some(key) = payload_index_key(value) {
        index
            .equality
            .entry(field.to_string())
            .or_default()
            .entry(key)
            .or_default()
            .insert(ordinal);
        if let Some(sort_key) = numeric_payload_sort_key_from_value(value) {
            index
                .numeric
                .entry(field.to_string())
                .or_default()
                .entry(sort_key)
                .or_default()
                .insert(ordinal);
        }
        if let Some(text) = value.as_str() {
            for term in tokenize(text) {
                index
                    .text
                    .entry(field.to_string())
                    .or_default()
                    .entry(term)
                    .or_default()
                    .insert(ordinal);
            }
        }
        return;
    }

    let Some(object) = value.as_object() else {
        if let Some(array) = value.as_array() {
            for item in array {
                insert_ordinal_payload_value(index, field, item, ordinal);
            }
        }
        return;
    };
    for (child, child_value) in object {
        insert_ordinal_payload_value(index, &format!("{field}.{child}"), child_value, ordinal);
    }
}

// ── Index mutation ───────────────────────────────────────────────────────────

pub(crate) fn insert_payload_point(index: &mut PayloadIndex, point: &Point) {
    let Some(payload) = point.payload.as_object() else {
        return;
    };
    for (field, value) in payload {
        insert_payload_value(index, field, value, &point.id);
    }
}

fn insert_payload_value(index: &mut PayloadIndex, field: &str, value: &Value, point_id: &str) {
    if let Some(key) = payload_index_key(value) {
        index
            .equality
            .entry(field.to_string())
            .or_default()
            .entry(key)
            .or_default()
            .insert(point_id.to_string());
        if let Some(sort_key) = numeric_payload_sort_key_from_value(value) {
            index
                .numeric
                .entry(field.to_string())
                .or_default()
                .entry(sort_key)
                .or_default()
                .insert(point_id.to_string());
        }
        // Index text terms for string values.
        if let Some(text) = value.as_str() {
            for term in tokenize(text) {
                index
                    .text
                    .entry(field.to_string())
                    .or_default()
                    .entry(term)
                    .or_default()
                    .insert(point_id.to_string());
            }
        }
        return;
    }

    let Some(object) = value.as_object() else {
        if let Some(array) = value.as_array() {
            for item in array {
                insert_payload_value(index, field, item, point_id);
            }
        }
        return;
    };
    for (child, child_value) in object {
        insert_payload_value(index, &format!("{field}.{child}"), child_value, point_id);
    }
}

pub(crate) fn remove_payload_point(index: &mut PayloadIndex, point: &Point) {
    let Some(payload) = point.payload.as_object() else {
        return;
    };
    for (field, value) in payload {
        remove_payload_value(index, field, value, &point.id);
    }
}

fn remove_payload_value(index: &mut PayloadIndex, field: &str, value: &Value, point_id: &str) {
    if let Some(key) = payload_index_key(value) {
        if let Some(values) = index.equality.get_mut(field) {
            remove_equality_payload_id(values, &key, point_id);
        }
        if let Some(sort_key) = numeric_payload_sort_key_from_value(value)
            && let Some(values) = index.numeric.get_mut(field)
        {
            remove_numeric_payload_id(values, sort_key, point_id);
        }
        if let Some(text) = value.as_str()
            && let Some(field_terms) = index.text.get_mut(field)
        {
            for term in tokenize(text) {
                if let Some(ids) = field_terms.get_mut(&term) {
                    ids.remove(point_id);
                    if ids.is_empty() {
                        field_terms.remove(&term);
                    }
                }
            }
            if field_terms.is_empty() {
                index.text.remove(field);
            }
        }
        if index.equality.get(field).is_some_and(HashMap::is_empty) {
            index.equality.remove(field);
        }
        if index.numeric.get(field).is_some_and(BTreeMap::is_empty) {
            index.numeric.remove(field);
        }
        return;
    }

    let Some(object) = value.as_object() else {
        if let Some(array) = value.as_array() {
            for item in array {
                remove_payload_value(index, field, item, point_id);
            }
        }
        return;
    };
    for (child, child_value) in object {
        remove_payload_value(index, &format!("{field}.{child}"), child_value, point_id);
    }
}

fn remove_equality_payload_id(
    values: &mut HashMap<String, HashSet<String>>,
    key: &str,
    point_id: &str,
) {
    if let Some(ids) = values.get_mut(key) {
        ids.remove(point_id);
        if ids.is_empty() {
            values.remove(key);
        }
    }
}

fn remove_numeric_payload_id(
    values: &mut BTreeMap<u64, HashSet<String>>,
    key: u64,
    point_id: &str,
) {
    if let Some(ids) = values.get_mut(&key) {
        ids.remove(point_id);
        if ids.is_empty() {
            values.remove(&key);
        }
    }
}

// ── Candidate pre-filtering ──────────────────────────────────────────────────

pub(crate) fn payload_filter_candidates(
    index: &PayloadIndex,
    filter: Option<&Filter>,
) -> Option<HashSet<String>> {
    let predicates = filter?.indexed_predicates()?;
    if predicates.is_empty() {
        return None;
    }

    let mut candidates: Option<HashSet<String>> = None;
    for predicate in predicates {
        let term_ids = match predicate {
            IndexedFilterPredicate::Equality(term) => equality_payload_candidates(index, term),
            IndexedFilterPredicate::NumericRange(term) => {
                numeric_range_payload_candidates(index, term)
            }
            IndexedFilterPredicate::Text(term) => text_payload_candidates(index, term),
        };
        candidates = Some(match candidates {
            Some(existing) => existing.intersection(&term_ids).cloned().collect(),
            None => term_ids,
        });
    }
    candidates
}

pub(crate) fn payload_filter_ordinal_candidates(
    index: &OrdinalPayloadIndex,
    filter: Option<&Filter>,
) -> Option<RoaringBitmap> {
    let predicates = filter?.indexed_predicates()?;
    if predicates.is_empty() {
        return None;
    }

    let mut candidates: Option<RoaringBitmap> = None;
    for predicate in predicates {
        let term_ordinals = match predicate {
            IndexedFilterPredicate::Equality(term) => {
                equality_ordinal_payload_candidates(index, term)
            }
            IndexedFilterPredicate::NumericRange(term) => {
                numeric_range_ordinal_payload_candidates(index, term)
            }
            IndexedFilterPredicate::Text(term) => text_ordinal_payload_candidates(index, term),
        };
        candidates = Some(match candidates {
            Some(mut existing) => {
                existing &= &term_ordinals;
                existing
            }
            None => term_ordinals,
        });
    }
    candidates
}

fn equality_ordinal_payload_candidates(
    index: &OrdinalPayloadIndex,
    term: IndexedFilterTerm,
) -> RoaringBitmap {
    let mut term_ordinals = RoaringBitmap::new();
    if let Some(values) = index.equality.get(&term.field) {
        for value in term.values {
            let Some(key) = payload_index_key(&value) else {
                continue;
            };
            if let Some(ordinals) = values.get(&key) {
                term_ordinals |= ordinals;
            }
        }
    }
    term_ordinals
}

fn numeric_range_ordinal_payload_candidates(
    index: &OrdinalPayloadIndex,
    term: IndexedNumericRangeTerm,
) -> RoaringBitmap {
    let mut term_ordinals = RoaringBitmap::new();
    if let Some(values) = index.numeric.get(&term.field) {
        for (_, ordinals) in values.range(numeric_payload_range_bounds(&term)) {
            term_ordinals |= ordinals;
        }
    }
    term_ordinals
}

fn text_ordinal_payload_candidates(
    index: &OrdinalPayloadIndex,
    term: IndexedTextTerm,
) -> RoaringBitmap {
    let Some(field_terms) = index.text.get(&term.field) else {
        return RoaringBitmap::new();
    };
    let mut candidates: Option<RoaringBitmap> = None;
    for required in &term.required_terms {
        let posting = field_terms.get(required).cloned().unwrap_or_default();
        candidates = Some(match candidates {
            Some(mut existing) => {
                existing &= &posting;
                existing
            }
            None => posting,
        });
    }
    candidates.unwrap_or_default()
}

fn equality_payload_candidates(index: &PayloadIndex, term: IndexedFilterTerm) -> HashSet<String> {
    let mut term_ids = HashSet::new();
    if let Some(values) = index.equality.get(&term.field) {
        for value in term.values {
            let Some(key) = payload_index_key(&value) else {
                continue;
            };
            if let Some(ids) = values.get(&key) {
                term_ids.extend(ids.iter().cloned());
            }
        }
    }
    term_ids
}

fn numeric_range_payload_candidates(
    index: &PayloadIndex,
    term: IndexedNumericRangeTerm,
) -> HashSet<String> {
    let mut term_ids = HashSet::new();
    if let Some(values) = index.numeric.get(&term.field) {
        let range = numeric_payload_range_bounds(&term);
        for (_, ids) in values.range(range) {
            term_ids.extend(ids.iter().cloned());
        }
    }
    term_ids
}

/// Returns the intersection of per-term candidate sets: only point IDs that
/// contain ALL required terms in the given field.
fn text_payload_candidates(index: &PayloadIndex, term: IndexedTextTerm) -> HashSet<String> {
    let Some(field_terms) = index.text.get(&term.field) else {
        return HashSet::new();
    };
    let mut candidates: Option<HashSet<String>> = None;
    for required in &term.required_terms {
        let posting = field_terms.get(required).cloned().unwrap_or_default();
        candidates = Some(match candidates {
            Some(existing) => existing.intersection(&posting).cloned().collect(),
            None => posting,
        });
    }
    candidates.unwrap_or_default()
}

fn numeric_payload_range_bounds(term: &IndexedNumericRangeTerm) -> (Bound<u64>, Bound<u64>) {
    let lower = match (term.gt, term.gte) {
        (Some(gt), Some(gte)) if gt >= gte => numeric_payload_sort_key(gt).map(Bound::Excluded),
        (Some(_), Some(gte)) => numeric_payload_sort_key(gte).map(Bound::Included),
        (Some(gt), None) => numeric_payload_sort_key(gt).map(Bound::Excluded),
        (None, Some(gte)) => numeric_payload_sort_key(gte).map(Bound::Included),
        (None, None) => None,
    }
    .unwrap_or(Bound::Unbounded);

    let upper = match (term.lt, term.lte) {
        (Some(lt), Some(lte)) if lt <= lte => numeric_payload_sort_key(lt).map(Bound::Excluded),
        (Some(_), Some(lte)) => numeric_payload_sort_key(lte).map(Bound::Included),
        (Some(lt), None) => numeric_payload_sort_key(lt).map(Bound::Excluded),
        (None, Some(lte)) => numeric_payload_sort_key(lte).map(Bound::Included),
        (None, None) => None,
    }
    .unwrap_or(Bound::Unbounded);

    (lower, upper)
}

// ── Key encoding helpers ─────────────────────────────────────────────────────

fn numeric_payload_sort_key_from_value(value: &Value) -> Option<u64> {
    let Value::Number(number) = value else {
        return None;
    };
    numeric_payload_sort_key(number.as_f64()?)
}

fn numeric_payload_sort_key(value: f64) -> Option<u64> {
    if !value.is_finite() {
        return None;
    }
    let bits = value.to_bits();
    Some(if bits & (1 << 63) == 0 {
        bits | (1 << 63)
    } else {
        !bits
    })
}

fn payload_index_key(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_string()),
        Value::Bool(value) => Some(format!("bool:{value}")),
        Value::Number(value) => Some(format!("number:{value}")),
        Value::String(value) => Some(format!("string:{value}")),
        Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_ordinal_payload_index, build_payload_index, payload_filter_candidates,
        payload_filter_ordinal_candidates,
    };
    use crate::{Filter, model::Point};
    use serde_json::json;
    use std::collections::{HashMap, HashSet};

    fn make_point(id: &str, payload: serde_json::Value) -> Point {
        Point {
            id: id.to_string(),
            vector: vec![0.0],
            vectors: HashMap::new(),
            sparse_vector: None,
            payload,
        }
    }

    #[test]
    fn text_index_pre_filters_candidates() {
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            make_point("a", json!({"title": "vector database rust"})),
        );
        points.insert(
            "b".to_string(),
            make_point("b", json!({"title": "machine learning python"})),
        );
        points.insert(
            "c".to_string(),
            make_point("c", json!({"title": "vector search engine"})),
        );

        let index = build_payload_index(&points);

        // Single term
        let filter = Filter(json!({"title": {"text": "vector"}}));
        let candidates = payload_filter_candidates(&index, Some(&filter)).unwrap();
        assert!(candidates.contains("a"), "a should match 'vector'");
        assert!(!candidates.contains("b"), "b should not match 'vector'");
        assert!(candidates.contains("c"), "c should match 'vector'");

        // Multiple terms — requires ALL terms present
        let filter = Filter(json!({"title": {"text": "vector rust"}}));
        let candidates = payload_filter_candidates(&index, Some(&filter)).unwrap();
        assert!(candidates.contains("a"), "a has both 'vector' and 'rust'");
        assert!(!candidates.contains("c"), "c has 'vector' but not 'rust'");
    }

    #[test]
    fn text_index_removes_on_delete() {
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            make_point("a", json!({"body": "hello world"})),
        );
        let mut index = build_payload_index(&points);

        // Remove point a
        super::remove_payload_point(&mut index, points.get("a").unwrap());

        let filter = Filter(json!({"body": {"text": "hello"}}));
        let candidates = payload_filter_candidates(&index, Some(&filter));
        // Should return None (no candidates) or empty set
        assert!(candidates.is_none_or(|c| c.is_empty()));
    }

    #[test]
    fn text_index_case_insensitive() {
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            make_point("a", json!({"note": "GaussDB Vector Search"})),
        );
        let index = build_payload_index(&points);

        let filter = Filter(json!({"note": {"text": "gaussdb vector"}}));
        let candidates = payload_filter_candidates(&index, Some(&filter)).unwrap();
        assert!(candidates.contains("a"));
    }

    #[test]
    fn ordinal_postings_match_string_postings_for_indexed_predicates() {
        let points = [
            make_point(
                "a",
                json!({"tenant": "acme", "price": 8, "body": "vector graph"}),
            ),
            make_point(
                "b",
                json!({"tenant": "other", "price": 12, "body": "vector only"}),
            ),
            make_point(
                "c",
                json!({"tenant": "acme", "price": 20, "body": "graph only"}),
            ),
        ];
        let string_points = points
            .iter()
            .cloned()
            .map(|point| (point.id.clone(), point))
            .collect::<HashMap<_, _>>();
        let string_index = build_payload_index(&string_points);
        let ordinal_index = build_ordinal_payload_index(
            points
                .iter()
                .cloned()
                .enumerate()
                .map(|(ordinal, point)| (ordinal as u32, point)),
        );

        for filter in [
            Filter(json!({"tenant": "acme"})),
            Filter(json!({"price": {"gte": 10, "lt": 20}})),
            Filter(json!({"body": {"text": "vector graph"}})),
        ] {
            let string_candidates =
                payload_filter_candidates(&string_index, Some(&filter)).unwrap();
            let ordinal_candidates =
                payload_filter_ordinal_candidates(&ordinal_index, Some(&filter)).unwrap();
            let ordinal_ids = ordinal_candidates
                .iter()
                .map(|ordinal| points[ordinal as usize].id.clone())
                .collect::<HashSet<_>>();
            assert_eq!(ordinal_ids, string_candidates);
        }
    }
}

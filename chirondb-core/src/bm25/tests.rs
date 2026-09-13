use super::*;
use serde_json::json;

fn point(id: &str, text: &str, tenant: &str) -> Point {
    Point {
        id: id.into(),
        vector: vec![1.0, 0.0],
        vectors: HashMap::new(),
        sparse_vector: None,
        payload: json!({"text":text,"tenant_id":tenant}),
    }
}

// Deliberately scans raw text, independent of the production postings/statistics.
fn oracle(
    points: &[Point],
    query: &str,
    tenant: Option<&str>,
    keep: &dyn Fn(&str) -> bool,
    k: usize,
) -> Vec<(String, f32)> {
    let split = |text: &str| {
        text.split(|ch: char| !ch.is_alphanumeric())
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
    };
    let corpus: Vec<_> = points
        .iter()
        .filter(|point| tenant.is_none_or(|tenant| point.payload["tenant_id"] == tenant))
        .filter_map(|point| {
            point.payload["text"]
                .as_str()
                .map(|text| (point, split(text)))
        })
        .collect();
    let terms: BTreeSet<_> = split(query).into_iter().collect();
    let n = corpus.len() as f64;
    let avg = corpus.iter().map(|(_, words)| words.len()).sum::<usize>() as f64 / n;
    let mut scored: Vec<_> = corpus
        .iter()
        .filter(|(point, _)| keep(&point.id))
        .filter_map(|(point, words)| {
            let mut score = 0.0;
            for term in &terms {
                let count = words.iter().filter(|word| *word == term).count() as f64;
                if count == 0.0 {
                    continue;
                }
                let df = corpus
                    .iter()
                    .filter(|(_, words)| words.contains(term))
                    .count() as f64;
                score += (1.0 + (n - df + 0.5) / (df + 0.5)).ln() * (count * 2.5)
                    / (count + 1.5 * (0.25 + 0.75 * words.len() as f64 / avg));
            }
            (score > 0.0).then(|| (point.id.clone(), score as f32))
        })
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    scored.truncate(k);
    scored
}

#[test]
fn exhaustive_oracle_terms_lengths_new_words_ties_and_filters() {
    let mut points = Vec::new();
    for i in 0..240 {
        let text = (0..i % 23)
            .map(|j| format!("t{}", (i * 7 + j * 3) % 17))
            .collect::<Vec<_>>()
            .join(" ");
        points.push(point(
            &format!("doc-{i:03}"),
            &text,
            if i % 2 == 0 { "a" } else { "b" },
        ));
    }
    let mut index = TextIndex::default();
    for point in &points {
        index.insert(point);
    }
    for tenant in [None, Some("a"), Some("b")] {
        for k in [1, 7, 300] {
            for query in ["t1 t4", "t1 t1 T1 t4", "unknown", "t2 t8 t13"] {
                let keep = |id: &str| !id.ends_with('4');
                let actual = index
                    .search("text", query, tenant, k, &keep, &|| false)
                    .ranked
                    .into_iter()
                    .map(|hit| (hit.id, hit.score))
                    .collect::<Vec<_>>();
                assert_eq!(actual, oracle(&points, query, tenant, &keep, k));
            }
        }
    }
    let before = index
        .search("text", "t1 t4", Some("a"), 300, &|_| true, &|| false)
        .ranked;
    for i in 0..100 {
        index.insert(&point(&format!("new-{i}"), "aaa-new-word t1 t1 t1", "b"));
    }
    let after = index
        .search("text", "t1 t4", Some("a"), 300, &|_| true, &|| false)
        .ranked;
    assert_eq!(
        before
            .iter()
            .map(|hit| (&hit.id, hit.score))
            .collect::<Vec<_>>(),
        after
            .iter()
            .map(|hit| (&hit.id, hit.score))
            .collect::<Vec<_>>()
    );
    for point in &points {
        index.remove(point);
    }
    assert!(
        index
            .search("text", "t1", Some("a"), 10, &|_| true, &|| false)
            .ranked
            .is_empty()
    );
}

#[test]
fn replacement_field_removal_and_cancellation() {
    let mut index = TextIndex::default();
    let old = point("one", "retur retur item", "a");
    index.insert(&old);
    index.remove(&old);
    let mut new = point("one", "refund", "b");
    index.insert(&new);
    assert!(
        index
            .search("text", "retur", None, 5, &|_| true, &|| false)
            .ranked
            .is_empty()
    );
    assert!(
        index
            .search("text", "refund", None, 5, &|_| true, &|| true)
            .degraded
    );
    index.remove(&new);
    new.payload["text"] = json!(17);
    index.insert(&new);
    assert!(!index.contains("text", "one"));
    assert!(!index.fields.contains_key("text"));
    for i in 0..100 {
        index.insert(&point(&format!("doc-{i:03}"), "refund policy", "a"));
    }
    let checked = std::cell::Cell::new(0);
    let partial = index.search("text", "refund", Some("a"), 100, &|_| true, &|| {
        checked.set(checked.get() + 1);
        checked.get() > 12
    });
    assert!(partial.degraded);
    assert_eq!(partial.searched, 12);
    assert_eq!(partial.ranked.len(), 12);
}

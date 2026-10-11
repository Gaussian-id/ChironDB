use super::*;
use serde_json::json;
use std::collections::BTreeSet;

#[test]
fn posting_workspace_refuses_before_candidate_and_large_limit_is_lazy() {
    use crate::relational::wal_decode::with_test_storage_pool;
    let mut index = TextIndex::default();
    index.insert(&point("one", "alpha beta", "a"));
    for budget in [1, 200] {
        with_test_storage_pool(budget, |used| {
            let called = std::cell::Cell::new(0);
            let result = index.try_search(
                "text",
                "alpha",
                None,
                1,
                &|_| {
                    called.set(called.get() + 1);
                    Ok(true)
                },
                &|| false,
            );
            assert!(matches!(
                result,
                Err(crate::GaussError::ResourceExhausted(_))
            ));
            assert_eq!(
                called.get(),
                0,
                "posting workspace must admit before scoring"
            );
            assert_eq!(used(), 0);
        });
    }
    with_test_storage_pool(64 * 1024, |used| {
        let result = index
            .try_search("text", "alpha", None, usize::MAX, &|_| Ok(true), &|| false)
            .unwrap();
        assert_eq!(result.ranked.len(), 1);
        assert_eq!(result.ranked[0].id, "one");
        assert!(used() > 0);
        drop(result);
        assert_eq!(used(), 0);
    });
}

#[test]
fn terms_match_legacy_unicode_tokenization_and_release_on_refusal() {
    use crate::relational::wal_decode::with_test_storage_pool;
    for text in [
        "",
        "!?",
        "T2 t2 t2",
        "İßCAFÉ-日本語 café_ABC",
        "αβ γδ CDB9",
        "\0alpha\nALPHA",
    ] {
        let expected: BTreeSet<_> = tokenize(text).into_iter().collect();
        with_test_storage_pool(64 * 1024, |used| {
            let terms = query::Terms::new(text).unwrap();
            assert_eq!(&*terms, &expected.into_iter().collect::<Vec<_>>());
            if !terms.is_empty() {
                assert!(used() > 0);
            }
            drop(terms);
            assert_eq!(used(), 0);
        });
    }
    with_test_storage_pool(1, |used| {
        assert!(query::Terms::new("!").unwrap().is_empty());
        assert!(matches!(
            query::Terms::new("日本語"),
            Err(crate::GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
}

#[test]
fn protected_statistics_and_partial_posting_cancel_drop_all_query_leases() {
    use crate::relational::wal_decode::with_test_storage_pool;
    let mut index = TextIndex::default();
    for id in ["a", "b", "c"] {
        index.insert(&point(id, "alpha beta", "tenant"));
    }
    let public_ids: HashMap<_, _> = ["a", "b", "c"].into_iter().map(|id| (id, id)).collect();
    with_test_storage_pool(200, |used| {
        assert!(matches!(
            index.search_authorized(
                "text",
                "alpha",
                2,
                &|id| Ok(public_ids.get(id).copied()),
                &|_| Ok(true),
                &|| Ok(())
            ),
            Err(crate::GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    with_test_storage_pool(64 * 1024, |used| {
        let checks = std::cell::Cell::new(0);
        let result = index.search_authorized(
            "text",
            "alpha",
            2,
            &|id| Ok(public_ids.get(id).copied()),
            &|_| Ok(true),
            &|| {
                checks.set(checks.get() + 1);
                if checks.get() == 7 {
                    assert!(used() > 0);
                    Err(crate::security::SecurityError::BudgetExceeded.into())
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(
            result,
            Err(crate::GaussError::Security(
                crate::security::SecurityError::BudgetExceeded
            ))
        ));
        assert_eq!(used(), 0);
        let retry = index
            .search_authorized(
                "text",
                "alpha",
                2,
                &|id| Ok(public_ids.get(id).copied()),
                &|_| Ok(true),
                &|| Ok(()),
            )
            .unwrap();
        assert_eq!(
            retry
                .ranked
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(used() > 0);
        drop(retry);
        assert_eq!(used(), 0);
    });
}

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

#[test]
fn protected_statistics_and_ties_depend_only_on_authorized_field_corpus() {
    let mut index = TextIndex::default();
    let mut corpus = Vec::new();
    let mut public_ids = HashMap::new();
    for i in 0..120 {
        let id = format!("physical-{i:03}");
        let public_id = format!("public-{:03}", 120 - i);
        let text = (0..i % 13 + 1)
            .map(|j| format!("t{}", (i + j) % 7))
            .collect::<Vec<_>>()
            .join(" ");
        let physical = point(&id, &text, "same-tenant");
        index.insert(&physical);
        if i % 3 != 0 {
            public_ids.insert(id, public_id.clone());
            corpus.push(point(&public_id, &text, "same-tenant"));
        }
    }
    for query in ["t1 t2", "T2 t2 t2", "unknown", "t1 t4 t6"] {
        for k in [1, 7, 100] {
            let actual = index
                .search_authorized(
                    "text",
                    query,
                    k,
                    &|id| Ok(public_ids.get(id).map(String::as_str)),
                    &|id| Ok(!public_ids[id].ends_with('4')),
                    &|| Ok(()),
                )
                .unwrap()
                .ranked;
            let expected = oracle(&corpus, query, None, &|id| !id.ends_with('4'), k);
            assert_eq!(
                actual
                    .iter()
                    .map(|hit| (hit.id.clone(), hit.score))
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
    let run = |index: &TextIndex| {
        index
            .search_authorized(
                "text",
                "t1 t4",
                100,
                &|id| Ok(public_ids.get(id).map(String::as_str)),
                &|_| Ok(true),
                &|| Ok(()),
            )
            .unwrap()
            .ranked
    };
    let before = run(&index);
    for i in 0..300 {
        index.insert(&point(
            &format!("hidden-{i}"),
            &"t1 t4 t4 t4 ".repeat(i + 1),
            "same-tenant",
        ));
    }
    let after = run(&index);
    assert_eq!(
        before
            .iter()
            .map(|hit| (&hit.id, hit.score.to_bits()))
            .collect::<Vec<_>>(),
        after
            .iter()
            .map(|hit| (&hit.id, hit.score.to_bits()))
            .collect::<Vec<_>>()
    );
    let checked = std::cell::Cell::new(0);
    assert!(
        index
            .search_authorized(
                "text",
                "t1",
                5,
                &|id| Ok(public_ids.get(id).map(String::as_str)),
                &|_| Ok(true),
                &|| {
                    checked.set(checked.get() + 1);
                    if checked.get() > 10 {
                        Err(crate::security::SecurityError::BudgetExceeded.into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
    );
}

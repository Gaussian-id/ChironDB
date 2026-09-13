use std::{borrow::Borrow, collections::HashMap};

use serde_json::Value;

use crate::{
    filter::tokenize,
    model::{Point, SparseVector},
};

// ── BM25 parameters ──────────────────────────────────────────────────────────

const BM25_K1: f32 = 1.5;
const BM25_B: f32 = 0.75;

/// Compute BM25-weighted sparse vectors from text fields in a collection.
///
/// `text_fields` lists which payload fields to treat as text.  Empty means
/// every top-level string value is included.  The term vocabulary is built from
/// `corpus` on each call; call once per batch for efficiency.
pub fn bm25_encode_text(
    text: &str,
    corpus: &HashMap<String, Point>,
    text_fields: &[String],
) -> SparseVector {
    let corpus_stats = build_bm25_corpus(corpus, text_fields);
    encode_bm25(&corpus_stats, text)
}

/// Corpus statistics required to compute BM25 weights.
pub struct Bm25Corpus {
    /// Stable term → dimension-index mapping (sorted term order → stable dim).
    term_to_dim: HashMap<String, u32>,
    /// Per-dimension document frequency (how many docs contain the term).
    dim_df: HashMap<u32, usize>,
    /// Total number of documents in the corpus.
    doc_count: usize,
    /// Sum of all document lengths (token counts) for avgdl.
    total_tokens: usize,
}

/// Build BM25 corpus statistics from a collection's current points.
pub fn build_bm25_corpus(points: &HashMap<String, Point>, text_fields: &[String]) -> Bm25Corpus {
    build_bm25_corpus_from_points(&points.values().collect::<Vec<_>>(), text_fields)
}

/// Slice-of-refs variant: multi-segment collections pass the chained live
/// view (streamer + searchers) without materializing a merged map.
pub fn build_bm25_corpus_from_points(points: &[&Point], text_fields: &[String]) -> Bm25Corpus {
    // Collect all unique terms and assign stable dimension indices.
    let mut all_terms: Vec<String> = Vec::new();
    for point in points.iter() {
        for term in extract_text_terms(point, text_fields) {
            if !all_terms.contains(&term) {
                all_terms.push(term);
            }
        }
    }
    all_terms.sort();
    let term_to_dim: HashMap<String, u32> = all_terms
        .into_iter()
        .enumerate()
        .map(|(i, t)| (t, i as u32))
        .collect();

    let mut dim_df: HashMap<u32, usize> = HashMap::new();
    let mut total_tokens = 0_usize;

    for point in points.iter() {
        let terms = extract_text_terms(point, text_fields);
        total_tokens += terms.len();
        let doc_terms: std::collections::HashSet<String> = terms.into_iter().collect();
        for term in &doc_terms {
            if let Some(&dim) = term_to_dim.get(term) {
                *dim_df.entry(dim).or_default() += 1;
            }
        }
    }

    Bm25Corpus {
        term_to_dim,
        dim_df,
        doc_count: points.len(),
        total_tokens,
    }
}

/// Encode a text string as a BM25-weighted sparse vector using the given corpus.
pub fn encode_bm25(corpus: &Bm25Corpus, text: &str) -> SparseVector {
    if corpus.doc_count == 0 {
        return SparseVector {
            indices: Vec::new(),
            values: Vec::new(),
        };
    }

    let n = corpus.doc_count as f32;
    let avgdl = if corpus.doc_count == 0 {
        1.0
    } else {
        corpus.total_tokens as f32 / corpus.doc_count as f32
    };

    let terms = tokenize(text);
    let doc_len = terms.len() as f32;
    if terms.is_empty() {
        return SparseVector {
            indices: Vec::new(),
            values: Vec::new(),
        };
    }

    // Count term frequencies in the query document.
    let mut tf: HashMap<String, f32> = HashMap::new();
    for term in &terms {
        *tf.entry(term.clone()).or_default() += 1.0;
    }

    let mut indices: Vec<u32> = Vec::new();
    let mut values: Vec<f32> = Vec::new();

    for (term, &raw_tf) in &tf {
        let Some(&dim) = corpus.term_to_dim.get(term) else {
            continue;
        };
        let df = corpus.dim_df.get(&dim).copied().unwrap_or(0) as f32;
        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
        let tf_norm = raw_tf * (BM25_K1 + 1.0)
            / (raw_tf + BM25_K1 * (1.0 - BM25_B + BM25_B * doc_len / avgdl));
        let weight = idf * tf_norm;
        if weight > 0.0 {
            indices.push(dim);
            values.push(weight);
        }
    }

    // Sort by dimension index for canonical ordering.
    let mut pairs: Vec<(u32, f32)> = indices.into_iter().zip(values).collect();
    pairs.sort_by_key(|&(dim, _)| dim);
    let (indices, values) = pairs.into_iter().unzip();
    SparseVector { indices, values }
}

fn extract_text_terms(point: &Point, text_fields: &[String]) -> Vec<String> {
    let Some(payload) = point.payload.as_object() else {
        return Vec::new();
    };
    let mut terms = Vec::new();
    for (field, value) in payload {
        let include = text_fields.is_empty() || text_fields.iter().any(|f| f == field);
        if include {
            collect_string_terms(value, &mut terms);
        }
    }
    terms
}

fn collect_string_terms(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.extend(tokenize(s)),
        Value::Array(arr) => {
            for item in arr {
                collect_string_terms(item, out);
            }
        }
        _ => {}
    }
}

pub(crate) const SPARSE_BLOCK_SIZE: usize = 16;

#[derive(Debug, Default)]
pub(crate) struct SparseIndex {
    pub(crate) dimensions: HashMap<u32, SparsePostingList>,
    pub(crate) text: crate::bm25::TextIndex,
}

#[derive(Clone, Debug)]
pub(crate) struct SparsePosting {
    pub(crate) id: String,
    pub(crate) value: f32,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SparsePostingList {
    pub(crate) postings: Vec<SparsePosting>,
    pub(crate) blocks: Vec<SparsePostingBlock>,
    pub(crate) max_value: f32,
    pub(crate) min_value: f32,
}

#[derive(Clone, Debug)]
pub(crate) struct SparsePostingBlock {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) max_value: f32,
}

#[cfg(test)]
pub(crate) fn build_sparse_index(points: &HashMap<String, Point>) -> SparseIndex {
    build_sparse_index_iter(points.values())
}

/// Iterator variant: builds from any live-point stream (multi-segment
/// collections chain the streamer and every searcher store).
pub(crate) fn build_sparse_index_iter<P: Borrow<Point>>(
    points: impl Iterator<Item = P>,
) -> SparseIndex {
    let mut index = SparseIndex::default();
    for point in points {
        let point = point.borrow();
        index.text.insert(point);
        let Some(sparse_vector) = &point.sparse_vector else {
            continue;
        };
        for (&dimension, &value) in sparse_vector.indices.iter().zip(&sparse_vector.values) {
            index
                .dimensions
                .entry(dimension)
                .or_default()
                .postings
                .push(SparsePosting {
                    id: point.id.clone(),
                    value,
                });
        }
    }
    for list in index.dimensions.values_mut() {
        rebuild_sparse_posting_blocks(list);
    }
    index
}

pub(crate) fn insert_sparse_point(index: &mut SparseIndex, point: &Point) {
    index.text.insert(point);
    let Some(sparse_vector) = &point.sparse_vector else {
        return;
    };
    for (&dimension, &value) in sparse_vector.indices.iter().zip(&sparse_vector.values) {
        let list = index.dimensions.entry(dimension).or_default();
        list.postings.push(SparsePosting {
            id: point.id.clone(),
            value,
        });
        rebuild_sparse_posting_blocks(list);
    }
}

pub(crate) fn remove_sparse_point(index: &mut SparseIndex, point: &Point) {
    index.text.remove(point);
    let Some(sparse_vector) = &point.sparse_vector else {
        return;
    };
    for dimension in &sparse_vector.indices {
        if let Some(postings) = index.dimensions.get_mut(dimension) {
            postings.postings.retain(|posting| posting.id != point.id);
            rebuild_sparse_posting_blocks(postings);
            if postings.postings.is_empty() {
                index.dimensions.remove(dimension);
            }
        }
    }
}

pub(crate) fn rebuild_sparse_posting_blocks(list: &mut SparsePostingList) {
    list.postings.sort_by(|left, right| {
        right
            .value
            .total_cmp(&left.value)
            .then_with(|| left.id.cmp(&right.id))
    });
    list.blocks.clear();
    list.max_value = f32::NEG_INFINITY;
    list.min_value = f32::INFINITY;
    for posting in &list.postings {
        list.max_value = list.max_value.max(posting.value);
        list.min_value = list.min_value.min(posting.value);
    }
    if list.postings.is_empty() {
        list.max_value = 0.0;
        list.min_value = 0.0;
        return;
    }
    for start in (0..list.postings.len()).step_by(SPARSE_BLOCK_SIZE) {
        let end = (start + SPARSE_BLOCK_SIZE).min(list.postings.len());
        let max_value = list.postings[start..end]
            .iter()
            .map(|posting| posting.value)
            .fold(f32::NEG_INFINITY, f32::max);
        list.blocks.push(SparsePostingBlock {
            start,
            end,
            max_value,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{bm25_encode_text, build_bm25_corpus, encode_bm25};
    use crate::model::Point;
    use serde_json::json;
    use std::collections::HashMap;

    fn make_text_point(id: &str, title: &str) -> Point {
        Point {
            id: id.to_string(),
            vector: vec![0.0],
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"title": title}),
        }
    }

    #[test]
    fn bm25_encodes_nonempty_text_to_sparse_vector() {
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            make_text_point("a", "vector database search"),
        );
        points.insert(
            "b".to_string(),
            make_text_point("b", "machine learning models"),
        );
        points.insert(
            "c".to_string(),
            make_text_point("c", "vector similarity search"),
        );

        let sv = bm25_encode_text("vector search", &points, &[]);
        assert!(
            !sv.indices.is_empty(),
            "should produce non-empty sparse vector"
        );
        assert_eq!(sv.indices.len(), sv.values.len());
        assert!(
            sv.values.iter().all(|&v| v > 0.0),
            "all BM25 weights should be positive"
        );
    }

    #[test]
    fn bm25_indices_are_sorted() {
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            make_text_point("a", "rust database engine fast"),
        );
        points.insert(
            "b".to_string(),
            make_text_point("b", "database systems rust"),
        );

        let sv = bm25_encode_text("rust database", &points, &[]);
        for window in sv.indices.windows(2) {
            assert!(window[0] < window[1], "indices must be sorted ascending");
        }
    }

    #[test]
    fn bm25_rare_term_gets_higher_weight() {
        let mut points = HashMap::new();
        // "common" appears in all 4 docs; "rare" appears in only 1
        for i in 0..4 {
            let text = if i == 0 {
                "common rare term"
            } else {
                "common term"
            };
            points.insert(i.to_string(), make_text_point(&i.to_string(), text));
        }
        let corpus = build_bm25_corpus(&points, &[]);
        let sv = encode_bm25(&corpus, "common rare");

        let common_dim = corpus.term_to_dim.get("common").copied().unwrap();
        let rare_dim = corpus.term_to_dim.get("rare").copied().unwrap();

        let common_w = sv
            .indices
            .iter()
            .zip(&sv.values)
            .find_map(|(&i, &v)| if i == common_dim { Some(v) } else { None })
            .unwrap_or(0.0);
        let rare_w = sv
            .indices
            .iter()
            .zip(&sv.values)
            .find_map(|(&i, &v)| if i == rare_dim { Some(v) } else { None })
            .unwrap_or(0.0);

        assert!(
            rare_w > common_w,
            "rare term should have higher IDF weight: rare={rare_w} common={common_w}"
        );
    }

    #[test]
    fn bm25_empty_corpus_returns_empty_vector() {
        let points: HashMap<String, Point> = HashMap::new();
        let sv = bm25_encode_text("anything", &points, &[]);
        assert!(sv.indices.is_empty());
    }

    #[test]
    fn bm25_field_filter_restricts_vocabulary() {
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            Point {
                id: "a".to_string(),
                vector: vec![0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"title": "vector search", "body": "other content here"}),
            },
        );
        let title_sv = bm25_encode_text("vector search", &points, &["title".to_string()]);
        let all_sv = bm25_encode_text("vector search", &points, &[]);
        // title-only should produce fewer or equal dimensions
        assert!(title_sv.indices.len() <= all_sv.indices.len());
    }
}

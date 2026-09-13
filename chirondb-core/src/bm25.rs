//! Derived, mutable text postings. Payload/WAL remain the persistence authority.
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap},
};

use crate::{
    filter::tokenize,
    model::Point,
    search::{RankedPoint, SparseSearchOutcome},
};

const K1: f64 = 1.5;
const B: f64 = 0.75;

#[derive(Debug, Default)]
pub(crate) struct TextIndex {
    fields: HashMap<String, Field>,
}

#[derive(Debug, Default)]
struct Field {
    documents: HashMap<String, Document>,
    postings: HashMap<String, BTreeMap<String, u32>>,
    all: Statistics,
    tenants: HashMap<Option<String>, Statistics>,
}

#[derive(Debug)]
struct Document {
    tenant: Option<String>,
    length: usize,
}

#[derive(Debug, Default)]
struct Statistics {
    documents: usize,
    length: usize,
    df: HashMap<String, usize>,
}

impl Statistics {
    fn insert(&mut self, length: usize, terms: &BTreeMap<String, u32>) {
        self.documents += 1;
        self.length += length;
        for term in terms.keys() {
            *self.df.entry(term.clone()).or_default() += 1;
        }
    }

    fn remove(&mut self, length: usize, terms: &BTreeMap<String, u32>) {
        self.documents -= 1;
        self.length -= length;
        for term in terms.keys() {
            if let Some(df) = self.df.get_mut(term) {
                *df -= 1;
                if *df == 0 {
                    self.df.remove(term);
                }
            }
        }
    }
}

fn frequencies(text: &str) -> BTreeMap<String, u32> {
    let mut terms = BTreeMap::new();
    for term in tokenize(text) {
        *terms.entry(term).or_default() += 1;
    }
    terms
}

impl TextIndex {
    pub(crate) fn insert(&mut self, point: &Point) {
        let Some(payload) = point.payload.as_object() else {
            return;
        };
        let tenant = point
            .payload
            .get(crate::tenant::TENANT_FIELD)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        for (name, value) in payload {
            let Some(text) = value.as_str() else { continue };
            let field = self.fields.entry(name.clone()).or_default();
            let terms = frequencies(text);
            let length = terms.values().map(|tf| *tf as usize).sum();
            field.all.insert(length, &terms);
            field
                .tenants
                .entry(tenant.clone())
                .or_default()
                .insert(length, &terms);
            field.documents.insert(
                point.id.clone(),
                Document {
                    tenant: tenant.clone(),
                    length,
                },
            );
            for (term, tf) in terms {
                field
                    .postings
                    .entry(term)
                    .or_default()
                    .insert(point.id.clone(), tf);
            }
        }
    }

    pub(crate) fn remove(&mut self, point: &Point) {
        let Some(payload) = point.payload.as_object() else {
            return;
        };
        for (name, value) in payload {
            let Some(text) = value.as_str() else { continue };
            let Some(field) = self.fields.get_mut(name) else {
                continue;
            };
            let Some(document) = field.documents.remove(&point.id) else {
                continue;
            };
            let terms = frequencies(text);
            field.all.remove(document.length, &terms);
            if let Some(stats) = field.tenants.get_mut(&document.tenant) {
                stats.remove(document.length, &terms);
                if stats.documents == 0 {
                    field.tenants.remove(&document.tenant);
                }
            }
            for term in terms.keys() {
                if let Some(postings) = field.postings.get_mut(term) {
                    postings.remove(&point.id);
                    if postings.is_empty() {
                        field.postings.remove(term);
                    }
                }
            }
            if field.documents.is_empty() {
                self.fields.remove(name);
            }
        }
    }

    /// Membership lookup avoids reading payloads to qualify dense candidates.
    pub(crate) fn contains(&self, field: &str, id: &str) -> bool {
        self.fields
            .get(field)
            .is_some_and(|field| field.documents.contains_key(id))
    }

    /// Merge ID-sorted postings, retaining only a bounded top-k heap. Statistics
    /// belong to the authorized corpus; the ordinary filter only admits candidates.
    pub(crate) fn search(
        &self,
        field: &str,
        query: &str,
        tenant: Option<&str>,
        limit: usize,
        eligible: &dyn Fn(&str) -> bool,
        stopped: &dyn Fn() -> bool,
    ) -> SparseSearchOutcome {
        let mut outcome = SparseSearchOutcome {
            ranked: Vec::new(),
            searched: 0,
            degraded: false,
        };
        let Some(field) = self.fields.get(field) else {
            return outcome;
        };
        let stats = match tenant {
            Some(tenant) => field.tenants.get(&Some(tenant.to_owned())),
            None => Some(&field.all),
        };
        let Some(stats) = stats.filter(|stats| stats.length > 0) else {
            return outcome;
        };
        if limit == 0 {
            return outcome;
        }
        let avg = stats.length as f64 / stats.documents as f64;
        let terms: BTreeSet<_> = tokenize(query).into_iter().collect();
        let mut lists: Vec<_> = terms
            .iter()
            .filter_map(|term| {
                let df = *stats.df.get(term)? as f64;
                let idf = (1.0 + (stats.documents as f64 - df + 0.5) / (df + 0.5)).ln();
                Some((idf, field.postings.get(term)?.iter().peekable()))
            })
            .collect();
        let mut heap = BinaryHeap::with_capacity(limit);
        loop {
            if stopped() {
                outcome.degraded = true;
                break;
            }
            let Some(id) = lists
                .iter_mut()
                .filter_map(|(_, list)| list.peek().map(|(id, _)| *id))
                .min()
                .cloned()
            else {
                break;
            };
            let document = &field.documents[&id];
            let admitted = tenant.is_none_or(|tenant| document.tenant.as_deref() == Some(tenant))
                && eligible(&id);
            let mut score = 0.0;
            for (idf, list) in &mut lists {
                if list.peek().is_some_and(|(next, _)| **next == id) {
                    let (_, tf) = list.next().expect("peeked posting");
                    if admitted {
                        let tf = *tf as f64;
                        score += *idf * tf * (K1 + 1.0)
                            / (tf + K1 * (1.0 - B + B * document.length as f64 / avg));
                    }
                }
            }
            if admitted {
                outcome.searched += 1;
                heap.push(WorstFirst(RankedPoint {
                    id,
                    score: score as f32,
                }));
                if heap.len() > limit {
                    heap.pop();
                }
            }
        }
        outcome.ranked = heap.into_iter().map(|entry| entry.0).collect();
        outcome.ranked.sort_by(crate::search::rank_order);
        outcome
    }
}

struct WorstFirst(RankedPoint);
impl PartialEq for WorstFirst {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for WorstFirst {}
impl PartialOrd for WorstFirst {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for WorstFirst {
    fn cmp(&self, other: &Self) -> Ordering {
        crate::search::rank_order(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests;

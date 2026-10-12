//! Derived, mutable text postings. Payload/WAL remain the persistence authority.
use std::collections::{BTreeMap, HashMap};

use crate::{
    filter::tokenize,
    model::Point,
    search::{AdmittedVec, BorrowedMap, RankedHeap, SparseSearchOutcome},
};

mod query;

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

    pub(crate) fn document_ids<'a>(&'a self, field: &str) -> impl Iterator<Item = &'a str> {
        self.fields
            .get(field)
            .into_iter()
            .flat_map(|field| field.documents.keys().map(String::as_str))
    }

    /// Merge ID-sorted postings, retaining only a bounded top-k heap. Statistics
    /// belong to the authorized corpus; the ordinary filter only admits candidates.
    #[cfg(test)]
    pub(crate) fn search(
        &self,
        field: &str,
        query: &str,
        tenant: Option<&str>,
        limit: usize,
        eligible: &dyn Fn(&str) -> bool,
        stopped: &dyn Fn() -> bool,
    ) -> SparseSearchOutcome {
        self.try_search(field, query, tenant, limit, &|id| Ok(eligible(id)), stopped)
            .expect("infallible test posting callbacks")
    }

    pub(crate) fn try_search(
        &self,
        field: &str,
        query: &str,
        tenant: Option<&str>,
        limit: usize,
        eligible: &dyn Fn(&str) -> crate::Result<bool>,
        stopped: &dyn Fn() -> bool,
    ) -> crate::Result<SparseSearchOutcome> {
        let Some(field) = self.fields.get(field) else {
            return Ok(empty_outcome());
        };
        let stats = match tenant {
            Some(tenant) => field.tenants.get(&Some(tenant.to_owned())),
            None => Some(&field.all),
        };
        let Some(stats) = stats else {
            return Ok(empty_outcome());
        };
        let terms = query::Terms::new(query)?;
        rank_postings(
            field,
            &terms,
            &Corpus {
                documents: stats.documents,
                length: stats.length,
                df: &|term| stats.df.get(term).copied(),
            },
            limit,
            &|id| {
                let document = &field.documents[id];
                Ok(
                    (tenant.is_none_or(|tenant| document.tenant.as_deref() == Some(tenant))
                        && eligible(id)?)
                    .then(|| {
                        field
                            .documents
                            .get_key_value(id)
                            .expect("indexed document")
                            .0
                            .as_str()
                    }),
                )
            },
            &|| Ok(!stopped()),
        )
    }

    /// Use only the caller's searchable field domain for N, avgdl and query-term
    /// document frequency. Ordinary predicates affect candidates, never corpus
    /// statistics. The returned ID is supplied by authority before top-k ties.
    pub(crate) fn search_authorized<'a>(
        &self,
        field: &str,
        query: &str,
        limit: usize,
        authorize: &dyn Fn(&str) -> crate::Result<Option<&'a str>>,
        eligible: &dyn Fn(&str) -> crate::Result<bool>,
        check: &dyn Fn() -> crate::Result<()>,
    ) -> crate::Result<SparseSearchOutcome> {
        check()?;
        let Some(field) = self.fields.get(field) else {
            return Ok(empty_outcome());
        };
        let terms = query::Terms::new(query)?;
        if limit == 0 || terms.is_empty() {
            return Ok(empty_outcome());
        }
        let mut documents = 0;
        let mut length = 0;
        let mut df = BorrowedMap::<usize>::default();
        for (id, document) in &field.documents {
            check()?;
            if authorize(id)?.is_none() {
                continue;
            }
            documents += 1;
            length += document.length;
            for term in terms.iter() {
                if field
                    .postings
                    .get(term)
                    .is_some_and(|postings| postings.contains_key(id))
                {
                    if let Some(count) = df.get_mut(term) {
                        *count += 1;
                    } else {
                        df.insert(term, 1)?;
                    }
                }
            }
        }
        rank_postings(
            field,
            &terms,
            &Corpus {
                documents,
                length,
                df: &|term| df.get(term).copied(),
            },
            limit,
            &|id| {
                let Some(public_id) = authorize(id)? else {
                    return Ok(None);
                };
                Ok(eligible(id)?.then_some(public_id))
            },
            &|| {
                check()?;
                Ok(true)
            },
        )
    }
}

fn empty_outcome() -> SparseSearchOutcome {
    SparseSearchOutcome {
        ranked: Default::default(),
        searched: 0,
        degraded: false,
    }
}

struct Corpus<'a> {
    documents: usize,
    length: usize,
    df: &'a dyn Fn(&str) -> Option<usize>,
}

fn rank_postings<'a>(
    field: &Field,
    terms: &[String],
    stats: &Corpus<'_>,
    limit: usize,
    candidate: &dyn Fn(&str) -> crate::Result<Option<&'a str>>,
    proceed: &dyn Fn() -> crate::Result<bool>,
) -> crate::Result<SparseSearchOutcome> {
    let mut outcome = empty_outcome();
    if stats.length == 0 || limit == 0 {
        return Ok(outcome);
    }
    let avg = stats.length as f64 / stats.documents as f64;
    let mut lists = AdmittedVec::default();
    for term in terms {
        if let (Some(df), Some(postings)) = ((stats.df)(term), field.postings.get(term)) {
            let df = df as f64;
            let idf = (1.0 + (stats.documents as f64 - df + 0.5) / (df + 0.5)).ln();
            lists.push((idf, postings.iter().peekable()))?;
        }
    }
    let mut heap = RankedHeap::new(limit);
    loop {
        if !proceed()? {
            outcome.degraded = true;
            break;
        }
        let Some(id) = lists
            .iter_mut()
            .filter_map(|(_, list)| list.peek().map(|(id, _)| *id))
            .min()
        else {
            break;
        };
        let public_id = candidate(id)?;
        let mut score = 0.0;
        for (idf, list) in lists.iter_mut() {
            if list.peek().is_some_and(|(next, _)| *next == id) {
                let (_, tf) = list.next().expect("peeked posting");
                if public_id.is_some() {
                    let tf = *tf as f64;
                    score += *idf * tf * (K1 + 1.0)
                        / (tf + K1 * (1.0 - B + B * field.documents[id].length as f64 / avg));
                }
            }
        }
        if let Some(id) = public_id {
            outcome.searched += 1;
            heap.copy_push(id, score as f32)?;
        }
    }
    outcome.ranked = heap.finish();
    Ok(outcome)
}

#[cfg(test)]
mod tests;

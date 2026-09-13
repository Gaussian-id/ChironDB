use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use chirondb_types::Filter;
pub use chirondb_types::graph::{
    ColdTraversalBudget, ConfigureEdgeTypeResult, EdgeToken, GraphConstraint,
    GraphDeferredSessionId, GraphDeferredSessionResult, GraphDeferredSessionState,
    GraphDeferredUpsertResult, GraphDirection, GraphDispatchTrace, GraphEdgeType, GraphEpoch,
    GraphLifecycleResult, GraphMutationReceipt, GraphRelationScope, GraphTraversalQueryRequest,
    GraphTraversalQueryResult, GraphTraversalReturn, GraphTraversalRows, GraphTraverseRequest,
    RelateRequest, RelateResult, TraversalBudget,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("API error {status}: {message}")]
    Api { status: u16, message: String },
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("invalid structural point '{id}': {message}")]
    InvalidStructuralPoint { id: String, message: String },
    #[error("invalid unsafe structural embedding override: {0}")]
    InvalidUnsafeStructuralOverride(String),
}

/// Primary public error name. `Error` remains available for source compatibility.
pub type ChironDbError = Error;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CollectionConfig {
    pub name: String,
    pub vector_dim: u64,
    #[serde(default)]
    pub metric: String,
    #[serde(default = "default_shards")]
    pub shards: u32,
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantization: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub payload_schema: HashMap<String, String>,
}

fn default_shards() -> u32 {
    1
}
fn default_replicas() -> u32 {
    1
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SparseVector {
    pub indices: Vec<u32>,
    pub values: Vec<f32>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Point {
    pub id: String,
    #[serde(default)]
    pub vector: Vec<f32>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub vectors: HashMap<String, Vec<f32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse_vector: Option<SparseVector>,
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Explicit exception to D18's identity-derived, non-zero structural-vector
/// convention. The reason is carried to the server and stored in its durable
/// audit record; constructing this value does not itself disable validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsafeStructuralEmbeddingOverride {
    reason: String,
}

impl UnsafeStructuralEmbeddingOverride {
    pub fn new(reason: impl Into<String>) -> Result<Self> {
        let reason = reason.into();
        let trimmed = reason.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidUnsafeStructuralOverride(
                "reason must not be empty".to_string(),
            ));
        }
        if trimmed.len() > 1024 {
            return Err(Error::InvalidUnsafeStructuralOverride(format!(
                "reason is {} bytes; maximum is 1024",
                trimmed.len()
            )));
        }
        Ok(Self {
            reason: trimmed.to_string(),
        })
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// A point admitted through the graph-aware structural-node path.
///
/// Use [`StructuralPoint::new`] for normal identity-derived embeddings. The
/// unsafe constructor is intentionally verbose and requires a reasoned token.
#[derive(Clone, Debug)]
pub struct StructuralPoint {
    point: Point,
    unsafe_reason: Option<String>,
}

impl StructuralPoint {
    pub fn new(point: Point) -> Result<Self> {
        validate_finite_structural_vector(&point)?;
        if point.vector.iter().all(|value| *value == 0.0) {
            return Err(Error::InvalidStructuralPoint {
                id: point.id.clone(),
                message: "all-zero vectors are rejected; embed the point identity or use the explicit audited unsafe override"
                    .to_string(),
            });
        }
        Ok(Self {
            point,
            unsafe_reason: None,
        })
    }

    pub fn with_unsafe_zero_vector_override(
        point: Point,
        override_token: UnsafeStructuralEmbeddingOverride,
    ) -> Result<Self> {
        validate_finite_structural_vector(&point)?;
        if !point.vector.iter().all(|value| *value == 0.0) {
            return Err(Error::InvalidStructuralPoint {
                id: point.id.clone(),
                message: "unsafe zero-vector override was supplied for a non-zero vector"
                    .to_string(),
            });
        }
        Ok(Self {
            point,
            unsafe_reason: Some(override_token.reason),
        })
    }

    pub fn point(&self) -> &Point {
        &self.point
    }

    pub fn into_point(self) -> Point {
        self.point
    }
}

fn validate_finite_structural_vector(point: &Point) -> Result<()> {
    if point.vector.iter().any(|value| !value.is_finite()) {
        return Err(Error::InvalidStructuralPoint {
            id: point.id.clone(),
            message: "vector values must be finite".to_string(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
pub struct StructuralUpsertResponse {
    pub total: usize,
    pub operation_lsn: u64,
    pub unsafe_override_audited: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SearchHit {
    pub id: String,
    pub score: f32,
    #[serde(default)]
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SearchResponse {
    pub hits: Vec<SearchHit>,
    #[serde(default)]
    pub degraded: bool,
    #[serde(default)]
    pub searched: u64,
    #[serde(default)]
    pub elapsed_ms: u64,
    /// Planner and bounded-expansion evidence for graph-constrained search.
    #[serde(default)]
    pub graph: Option<GraphDispatchTrace>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SearchQuery {
    pub vector: Vec<f32>,
    #[serde(default = "default_k")]
    pub k: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
    /// Restrict ranking to the live points reachable through this graph clause.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph: Option<GraphConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_ms: Option<u64>,
    /// Per-query `ef_search` override. Higher is more accurate and slower.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ef_search: Option<u32>,
    /// Target recall in `0.0..=1.0`. The engine picks `ef_search` from its
    /// calibration curve. This states a target, never an achieved figure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recall_target: Option<f32>,
    /// Set `false` to omit payloads from the hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub with_payload: Option<bool>,
}

/// How a hybrid or multi-vector search combines its result sets.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fusion {
    /// Reciprocal rank fusion. Rank-based, so the two score scales never have
    /// to be made comparable.
    #[default]
    Rrf,
    /// Weighted score fusion, using the per-leg weights.
    Weighted,
}

/// Dense and lexical retrieval in one request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct HybridQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse_vector: Option<SparseVector>,
    pub k: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
    /// One membership constraint shared by both dense and sparse branches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph: Option<GraphConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_ms: Option<u64>,
    pub fusion: Fusion,
    /// Only used when `fusion` is `Weighted`.
    pub dense_weight: f32,
    /// Only used when `fusion` is `Weighted`.
    pub sparse_weight: f32,
}

/// Several query vectors against one collection, optionally fused.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MultiSearchQuery {
    pub searches: Vec<SearchQuery>,
    /// With no fusion the response carries one result set per search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fusion: Option<Fusion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fused_k: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub weights: Vec<f32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MultiSearchResponse {
    pub results: Vec<SearchResponse>,
}

/// "More like these, less like those", by stored point id.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RecommendQuery {
    pub positive: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub negative: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_name: Option<String>,
    pub k: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_ms: Option<u64>,
}

/// One payload-based score adjustment applied during a rerank.
#[derive(Clone, Debug, Serialize)]
pub struct ScoreBoost {
    pub field: String,
    pub value: serde_json::Value,
    /// Multiplied into the hit's score when the field matches.
    ///
    /// **The sign of the score matters.** Results are sorted descending, so a
    /// factor above 1.0 lifts a match only when scores are positive — cosine
    /// and inner product. Under L2 the score is a negated distance, so the
    /// same factor makes it more negative and pushes the match *down*. On an
    /// L2 collection, use a factor between 0 and 1 to promote.
    pub boost: f32,
}

/// ANN prefetch followed by payload-aware rescoring.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RerankQuery {
    pub vector: Vec<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_name: Option<String>,
    pub k: u64,
    /// Candidates to retrieve before reranking. Defaults to `3 * k`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefetch_k: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub score_boosts: Vec<ScoreBoost>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_ms: Option<u64>,
}

#[allow(dead_code)]
fn default_k() -> u64 {
    10
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScrollRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    pub limit: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScrollResponse {
    pub points: Vec<Point>,
    pub next_offset: Option<String>,
}

/// Result of deleting one opaque edge token.
#[derive(Clone, Debug, Deserialize)]
pub struct UnrelateResult {
    pub deleted: usize,
    pub receipt: GraphMutationReceipt,
}

// ── Client ───────────────────────────────────────────────────────────────────

pub struct ChironDbClient {
    base_url: String,
    api_key: Option<String>,
    client: Client,
}

/// Deprecated compatibility name retained throughout the beta.
pub type GaussDbClient = ChironDbClient;

impl ChironDbClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: None,
            client: Client::new(),
        }
    }

    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    fn req(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut b = self.client.request(method, url);
        if let Some(k) = &self.api_key {
            b = b.header("Authorization", format!("Bearer {k}"));
        }
        b
    }

    async fn ok<T: for<'de> Deserialize<'de>>(&self, r: reqwest::Response) -> Result<T> {
        let status = r.status();
        if status.is_success() {
            Ok(r.json().await?)
        } else {
            let msg = r.text().await.unwrap_or_default();
            Err(Error::Api {
                status: status.as_u16(),
                message: msg,
            })
        }
    }

    pub async fn health(&self) -> Result<serde_json::Value> {
        let r = self.req(Method::GET, "/health").send().await?;
        self.ok(r).await
    }

    pub async fn create_collection(&self, config: CollectionConfig) -> Result<CollectionConfig> {
        let r = self
            .req(Method::POST, "/collections")
            .json(&config)
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn list_collections(&self) -> Result<Vec<CollectionConfig>> {
        let r = self.req(Method::GET, "/collections").send().await?;
        self.ok(r).await
    }

    pub async fn delete_collection(&self, name: &str) -> Result<serde_json::Value> {
        let r = self
            .req(Method::DELETE, &format!("/collections/{name}"))
            .send()
            .await?;
        self.ok(r).await
    }

    /// Enable a collection's graph overlay.
    pub async fn enable_graph(&self, collection: &str, wait: bool) -> Result<GraphLifecycleResult> {
        let r = self
            .req(
                Method::PUT,
                &format!("/collections/{collection}/graph?wait={wait}"),
            )
            .send()
            .await?;
        self.ok(r).await
    }

    /// Drop a collection's complete graph overlay while retaining its points.
    pub async fn drop_graph(&self, collection: &str, wait: bool) -> Result<GraphLifecycleResult> {
        let r = self
            .req(
                Method::DELETE,
                &format!("/collections/{collection}/graph?wait={wait}"),
            )
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn list_edge_types(&self, collection: &str) -> Result<Vec<GraphEdgeType>> {
        #[derive(Deserialize)]
        struct Resp {
            edge_types: Vec<GraphEdgeType>,
        }

        let r = self
            .req(
                Method::GET,
                &format!("/collections/{collection}/graph/types"),
            )
            .send()
            .await?;
        Ok(self.ok::<Resp>(r).await?.edge_types)
    }

    pub async fn configure_edge_type(
        &self,
        collection: &str,
        edge_type: &str,
        weight_property: Option<String>,
        wait: bool,
    ) -> Result<ConfigureEdgeTypeResult> {
        #[derive(Serialize)]
        struct Req {
            weight_property: Option<String>,
            wait: bool,
        }

        let r = self
            .req(
                Method::PUT,
                &format!("/collections/{collection}/graph/types/{edge_type}"),
            )
            .json(&Req {
                weight_property,
                wait,
            })
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn relate(
        &self,
        collection: &str,
        request: RelateRequest,
        wait: bool,
    ) -> Result<RelateResult> {
        #[derive(Serialize)]
        struct Req<'a> {
            #[serde(flatten)]
            request: &'a RelateRequest,
            wait: bool,
        }

        let r = self
            .req(Method::POST, &format!("/collections/{collection}/edges"))
            .json(&Req {
                request: &request,
                wait,
            })
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn unrelate(
        &self,
        collection: &str,
        edge_id: &EdgeToken,
        wait: bool,
    ) -> Result<UnrelateResult> {
        let r = self
            .req(
                Method::DELETE,
                &format!(
                    "/collections/{collection}/edges/{}?wait={wait}",
                    edge_id.as_str()
                ),
            )
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn merge_edge_properties(
        &self,
        collection: &str,
        edge_id: &EdgeToken,
        properties: serde_json::Value,
        wait: bool,
    ) -> Result<GraphMutationReceipt> {
        self.update_edge_properties(collection, edge_id, properties, wait, Method::PATCH)
            .await
    }

    pub async fn replace_edge_properties(
        &self,
        collection: &str,
        edge_id: &EdgeToken,
        properties: serde_json::Value,
        wait: bool,
    ) -> Result<GraphMutationReceipt> {
        self.update_edge_properties(collection, edge_id, properties, wait, Method::PUT)
            .await
    }

    async fn update_edge_properties(
        &self,
        collection: &str,
        edge_id: &EdgeToken,
        properties: serde_json::Value,
        wait: bool,
        method: Method,
    ) -> Result<GraphMutationReceipt> {
        #[derive(Serialize)]
        struct Req {
            properties: serde_json::Value,
            wait: bool,
        }

        let r = self
            .req(
                method,
                &format!("/collections/{collection}/edges/{}", edge_id.as_str()),
            )
            .json(&Req { properties, wait })
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn traverse(
        &self,
        collection: &str,
        request: GraphTraversalQueryRequest,
    ) -> Result<GraphTraversalQueryResult> {
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/graph/traverse"),
            )
            .json(&request)
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn open_deferred_graph_session(
        &self,
        collection: &str,
        wait: bool,
    ) -> Result<GraphDeferredSessionResult> {
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/graph/deferred-sessions?wait={wait}"),
            )
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn deferred_upsert(
        &self,
        collection: &str,
        session_id: &GraphDeferredSessionId,
        points: Vec<Point>,
        wait: bool,
    ) -> Result<GraphDeferredUpsertResult> {
        #[derive(Serialize)]
        struct Req<'a> {
            points: &'a [Point],
            wait: bool,
        }

        let r = self
            .req(
                Method::POST,
                &format!(
                    "/collections/{collection}/graph/deferred-sessions/{}/points",
                    session_id.as_str()
                ),
            )
            .json(&Req {
                points: &points,
                wait,
            })
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn deferred_relate(
        &self,
        collection: &str,
        session_id: &GraphDeferredSessionId,
        request: RelateRequest,
        wait: bool,
    ) -> Result<RelateResult> {
        #[derive(Serialize)]
        struct Req<'a> {
            #[serde(flatten)]
            request: &'a RelateRequest,
            wait: bool,
        }

        let r = self
            .req(
                Method::POST,
                &format!(
                    "/collections/{collection}/graph/deferred-sessions/{}/edges",
                    session_id.as_str()
                ),
            )
            .json(&Req {
                request: &request,
                wait,
            })
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn commit_deferred_graph_session(
        &self,
        collection: &str,
        session_id: &GraphDeferredSessionId,
        wait: bool,
    ) -> Result<GraphDeferredSessionResult> {
        self.finish_deferred_graph_session(collection, session_id, wait, "commit")
            .await
    }

    pub async fn abort_deferred_graph_session(
        &self,
        collection: &str,
        session_id: &GraphDeferredSessionId,
        wait: bool,
    ) -> Result<GraphDeferredSessionResult> {
        self.finish_deferred_graph_session(collection, session_id, wait, "abort")
            .await
    }

    async fn finish_deferred_graph_session(
        &self,
        collection: &str,
        session_id: &GraphDeferredSessionId,
        wait: bool,
        action: &str,
    ) -> Result<GraphDeferredSessionResult> {
        let r = self
            .req(
                Method::POST,
                &format!(
                    "/collections/{collection}/graph/deferred-sessions/{}/{action}?wait={wait}",
                    session_id.as_str()
                ),
            )
            .send()
            .await?;
        self.ok(r).await
    }

    /// Upsert points. `wait = true` (default) blocks until WAL fsync.
    pub async fn upsert(
        &self,
        collection: &str,
        points: Vec<Point>,
        wait: bool,
    ) -> Result<serde_json::Value> {
        #[derive(Serialize)]
        struct Req<'a> {
            points: &'a [Point],
            wait: bool,
        }
        let r = self
            .req(Method::PUT, &format!("/collections/{collection}/points"))
            .json(&Req {
                points: &points,
                wait,
            })
            .send()
            .await?;
        self.ok(r).await
    }

    /// Upsert graph structural nodes with D18 embedding validation.
    ///
    /// Generic [`Self::upsert`] remains compatibility-preserving. This typed
    /// path rejects a shared all-zero sentinel locally and the server repeats
    /// the check before its WAL append.
    pub async fn upsert_structural(
        &self,
        collection: &str,
        points: Vec<StructuralPoint>,
        wait: bool,
    ) -> Result<StructuralUpsertResponse> {
        #[derive(Serialize)]
        struct Req<'a> {
            points: &'a [Point],
            wait: bool,
        }

        let mut unsafe_reason: Option<String> = None;
        for point in &points {
            if let Some(reason) = point.unsafe_reason.as_deref() {
                match unsafe_reason.as_deref() {
                    None => unsafe_reason = Some(reason.to_string()),
                    Some(existing) if existing == reason => {}
                    Some(_) => {
                        return Err(Error::InvalidUnsafeStructuralOverride(
                            "one batch cannot contain multiple override reasons".to_string(),
                        ));
                    }
                }
            }
        }
        let raw_points = points
            .into_iter()
            .map(StructuralPoint::into_point)
            .collect::<Vec<_>>();
        let mut request = self
            .req(Method::PUT, &format!("/collections/{collection}/points"))
            .header("x-chiron-structural-points", "1")
            .json(&Req {
                points: &raw_points,
                wait,
            });
        if let Some(reason) = unsafe_reason {
            request = request.header(
                "x-chiron-unsafe-structural-embedding-reason",
                URL_SAFE_NO_PAD.encode(reason.as_bytes()),
            );
        }
        self.ok(request.send().await?).await
    }

    pub async fn get_points(&self, collection: &str, ids: Vec<String>) -> Result<Vec<Point>> {
        #[derive(Serialize)]
        struct Req {
            ids: Vec<String>,
        }
        #[derive(Deserialize)]
        struct Resp {
            points: Vec<Point>,
        }
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/points/get"),
            )
            .json(&Req { ids })
            .send()
            .await?;
        Ok(self.ok::<Resp>(r).await?.points)
    }

    pub async fn delete(&self, collection: &str, ids: Vec<String>) -> Result<serde_json::Value> {
        #[derive(Serialize)]
        struct Req {
            ids: Vec<String>,
        }
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/points/delete"),
            )
            .json(&Req { ids })
            .send()
            .await?;
        self.ok(r).await
    }

    /// Set or merge payload on a single point.
    /// `merge = true` (default) merges fields; `false` replaces entirely.
    pub async fn set_payload(
        &self,
        collection: &str,
        id: &str,
        payload: serde_json::Value,
        merge: bool,
    ) -> Result<Point> {
        #[derive(Serialize)]
        struct Req<'a> {
            id: &'a str,
            payload: serde_json::Value,
            merge: bool,
        }
        #[derive(Deserialize)]
        struct Resp {
            point: Point,
        }
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/points/payload"),
            )
            .json(&Req { id, payload, merge })
            .send()
            .await?;
        Ok(self.ok::<Resp>(r).await?.point)
    }

    /// Delete all points matching `filter` (key-value map, e.g. `{"status": "deleted"}`).
    pub async fn delete_by_filter(
        &self,
        collection: &str,
        filter: serde_json::Value,
    ) -> Result<serde_json::Value> {
        #[derive(Serialize)]
        struct Req {
            filter: serde_json::Value,
        }
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/points/delete/filter"),
            )
            .json(&Req { filter })
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn search(&self, collection: &str, query: SearchQuery) -> Result<SearchResponse> {
        let r = self
            .req(Method::POST, &format!("/collections/{collection}/search"))
            .json(&query)
            .send()
            .await?;
        self.ok(r).await
    }

    /// Native BM25 over payload text fused with the supplied dense query vector.
    pub async fn text_hybrid_search(
        &self,
        collection: &str,
        query: TextHybridQuery,
    ) -> Result<SearchResponse> {
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/text_hybrid_search"),
            )
            .json(&query)
            .send()
            .await?;
        self.ok(r).await
    }

    /// Dense and lexical retrieval fused into one ranked list.
    pub async fn hybrid_search(
        &self,
        collection: &str,
        query: HybridQuery,
    ) -> Result<SearchResponse> {
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/hybrid_search"),
            )
            .json(&query)
            .send()
            .await?;
        self.ok(r).await
    }

    /// Several query vectors in one round trip. With a fusion set the engine
    /// returns one fused list; without one, a result set per search.
    pub async fn multi_search(
        &self,
        collection: &str,
        query: MultiSearchQuery,
    ) -> Result<MultiSearchResponse> {
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/multi_search"),
            )
            .json(&query)
            .send()
            .await?;
        self.ok(r).await
    }

    /// Recommend from stored points rather than a query vector.
    pub async fn recommend(
        &self,
        collection: &str,
        query: RecommendQuery,
    ) -> Result<SearchResponse> {
        let r = self
            .req(
                Method::POST,
                &format!("/collections/{collection}/recommend"),
            )
            .json(&query)
            .send()
            .await?;
        self.ok(r).await
    }

    /// Prefetch by vector similarity, then rescore with payload rules.
    pub async fn rerank(&self, collection: &str, query: RerankQuery) -> Result<SearchResponse> {
        let r = self
            .req(Method::POST, &format!("/collections/{collection}/rerank"))
            .json(&query)
            .send()
            .await?;
        self.ok(r).await
    }

    pub async fn count(&self, collection: &str, filter: Option<serde_json::Value>) -> Result<u64> {
        #[derive(Serialize)]
        struct Req {
            #[serde(skip_serializing_if = "Option::is_none")]
            filter: Option<serde_json::Value>,
        }
        #[derive(Deserialize)]
        struct Resp {
            count: u64,
        }
        let r = self
            .req(Method::POST, &format!("/collections/{collection}/count"))
            .json(&Req { filter })
            .send()
            .await?;
        Ok(self.ok::<Resp>(r).await?.count)
    }

    pub async fn scroll(&self, collection: &str, req: ScrollRequest) -> Result<ScrollResponse> {
        let r = self
            .req(Method::POST, &format!("/collections/{collection}/scroll"))
            .json(&req)
            .send()
            .await?;
        self.ok(r).await
    }
}

/// Additive native text retrieval contract; legacy sparse dimensions are unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TextHybridQuery {
    pub vector: Vec<f32>,
    pub query: String,
    pub text_field: String,
    pub k: usize,
    pub filter: Option<serde_json::Value>,
    pub budget_ms: Option<u64>,
}

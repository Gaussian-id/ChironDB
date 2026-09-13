"""Primary synchronous HTTP client for ChironDB."""
from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass
from typing import Any, Iterator, Optional

import requests


class ChironDbError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message


@dataclass(frozen=True)
class EdgeToken:
    """Opaque edge identity returned by ChironDB.

    Store and return this token unchanged. Its contents are deliberately not
    exposed as graph topology or a sortable identifier.
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("edge token must be a non-empty string")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class GraphDeferredSessionId:
    """Opaque identity for one durable deferred graph-load window."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("graph deferred session id must be a non-empty string")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class GraphConstraint:
    """Reachability membership applied before dense or hybrid ranking."""

    anchors: tuple[str, ...]
    edge_types: tuple[str, ...] = ()
    direction: str = "outgoing"
    node_filter: Optional[dict[str, Any]] = None
    edge_filter: Optional[dict[str, Any]] = None
    budget: Optional[dict[str, Any]] = None
    allow_degraded: bool = False

    def __post_init__(self) -> None:
        if not self.anchors:
            raise ValueError("graph constraint needs at least one anchor")
        if self.direction not in {"outgoing", "incoming", "both"}:
            raise ValueError("graph direction must be outgoing, incoming, or both")

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "anchors": list(self.anchors),
            "direction": self.direction,
        }
        if self.edge_types:
            body["edge_types"] = list(self.edge_types)
        if self.node_filter is not None:
            body["node_filter"] = self.node_filter
        if self.edge_filter is not None:
            body["edge_filter"] = self.edge_filter
        if self.budget is not None:
            body["budget"] = self.budget
        if self.allow_degraded:
            body["allow_degraded"] = True
        return body


@dataclass(frozen=True)
class RelateResult:
    edge_id: EdgeToken
    receipt: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RelateResult":
        return cls(EdgeToken(value["edge_id"]), value["receipt"])


@dataclass(frozen=True)
class UnrelateResult:
    deleted: int
    receipt: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "UnrelateResult":
        return cls(value["deleted"], value["receipt"])


@dataclass(frozen=True)
class GraphDeferredSessionResult:
    session_id: GraphDeferredSessionId
    state: str
    receipt: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "GraphDeferredSessionResult":
        return cls(
            GraphDeferredSessionId(value["session_id"]),
            value["state"],
            value["receipt"],
        )


def _graph_constraint_body(graph: GraphConstraint | dict[str, Any]) -> dict[str, Any]:
    if isinstance(graph, GraphConstraint):
        return graph.to_dict()
    return dict(graph)


@dataclass(frozen=True)
class UnsafeStructuralEmbeddingOverride:
    """Explicit, server-audited exception for a zero structural vector."""

    reason: str

    def __post_init__(self) -> None:
        reason = self.reason.strip()
        if not reason:
            raise ValueError("unsafe structural embedding override reason must not be empty")
        if len(reason.encode("utf-8")) > 1024:
            raise ValueError("unsafe structural embedding override reason exceeds 1024 bytes")
        object.__setattr__(self, "reason", reason)


@dataclass(frozen=True)
class StructuralPoint:
    """A graph structural node with an identity-derived dense vector."""

    point: dict
    _unsafe_reason: Optional[str] = None

    @classmethod
    def create(cls, point: dict) -> "StructuralPoint":
        vector = _finite_structural_vector(point)
        if all(value == 0.0 for value in vector):
            raise ValueError(
                f"structural point {point.get('id')!r} has an all-zero vector; "
                "embed its identity or use the explicit audited unsafe override"
            )
        return cls(point=dict(point))

    @classmethod
    def with_unsafe_zero_vector_override(
        cls,
        point: dict,
        override: UnsafeStructuralEmbeddingOverride,
    ) -> "StructuralPoint":
        vector = _finite_structural_vector(point)
        if not all(value == 0.0 for value in vector):
            raise ValueError("unsafe zero-vector override was supplied for a non-zero vector")
        return cls(point=dict(point), _unsafe_reason=override.reason)


def _finite_structural_vector(point: dict) -> list[float]:
    point_id = point.get("id")
    vector = point.get("vector")
    if not isinstance(vector, list) or not vector:
        raise ValueError(f"structural point {point_id!r} must have a non-empty vector list")
    if any(not isinstance(value, (int, float)) or not math.isfinite(value) for value in vector):
        raise ValueError(f"structural point {point_id!r} vector values must be finite numbers")
    return vector


class ChironDbClient:
    """Synchronous HTTP client for ChironDB.

    Args:
        base_url: Server URL, e.g. ``"http://localhost:7401"``.
        api_key: Optional API key sent as ``Authorization: Bearer <key>``.
        timeout: Request timeout in seconds (default 30).
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = 30,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"
        self._session.headers["Content-Type"] = "application/json"

    # ── Internal ─────────────────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    def _check(self, resp: requests.Response) -> Any:
        if resp.ok:
            return resp.json()
        raise ChironDbError(resp.status_code, resp.text)

    def _get(self, path: str) -> Any:
        return self._check(self._session.get(self._url(path), timeout=self._timeout))

    def _post(self, path: str, body: Any) -> Any:
        return self._check(
            self._session.post(
                self._url(path),
                data=json.dumps(body),
                timeout=self._timeout,
            )
        )

    def _post_without_body(self, path: str) -> Any:
        return self._check(self._session.post(self._url(path), timeout=self._timeout))

    def _put(
        self,
        path: str,
        body: Any,
        headers: Optional[dict[str, str]] = None,
    ) -> Any:
        return self._check(
            self._session.put(
                self._url(path),
                data=json.dumps(body),
                headers=headers,
                timeout=self._timeout,
            )
        )

    def _patch(self, path: str, body: Any) -> Any:
        return self._check(
            self._session.patch(
                self._url(path),
                data=json.dumps(body),
                timeout=self._timeout,
            )
        )

    def _delete(self, path: str) -> Any:
        return self._check(self._session.delete(self._url(path), timeout=self._timeout))

    # ── Collections ───────────────────────────────────────────────────────────

    def health(self) -> dict:
        """Return server health info."""
        return self._get("/health")

    def create_collection(
        self,
        name: str,
        vector_dim: int,
        metric: str = "cosine",
        shards: int = 1,
        replicas: int = 1,
        quantization: Optional[str] = None,
        payload_schema: Optional[dict[str, str]] = None,
        index_kind: Optional[str] = None,
        hnsw_m: Optional[int] = None,
        hnsw_ef_construction: Optional[int] = None,
        hnsw_ef_search: Optional[int] = None,
    ) -> dict:
        """Create a new collection.

        Args:
            index_kind: ``"lsvec"`` is the sole accepted index. ``None`` uses
                that default. Other values are rejected by the server.
            hnsw_m: Legacy field retained for protocol compatibility; HNSW is
                not a selectable sealed index.
            hnsw_ef_construction: Legacy field retained for compatibility.
            hnsw_ef_search: Mutable-tier search budget; a per-query
                ``ef_search`` passed to :meth:`search` overrides it.
        """
        body: dict = {
            "name": name,
            "vector_dim": vector_dim,
            "metric": metric,
            "shards": shards,
            "replicas": replicas,
        }
        if quantization is not None:
            body["quantization"] = quantization
        if payload_schema:
            body["payload_schema"] = payload_schema
        if index_kind is not None:
            body["index_kind"] = index_kind
        if hnsw_m is not None:
            body["hnsw_m"] = hnsw_m
        if hnsw_ef_construction is not None:
            body["hnsw_ef_construction"] = hnsw_ef_construction
        if hnsw_ef_search is not None:
            body["hnsw_ef_search"] = hnsw_ef_search
        return self._post("/collections", body)

    def list_collections(self) -> list[dict]:
        """Return all collections."""
        return self._get("/collections")

    def delete_collection(self, name: str) -> dict:
        """Delete a collection by name."""
        return self._delete(f"/collections/{name}")

    # ── Property graph ───────────────────────────────────────────────────────

    def enable_graph(self, collection: str, wait: bool = True) -> dict[str, Any]:
        """Enable the graph overlay and return its epoch/durability receipt."""
        return self._put(f"/collections/{collection}/graph?wait={str(wait).lower()}", {})

    def drop_graph(self, collection: str, wait: bool = True) -> dict[str, Any]:
        """Drop graph topology while retaining the collection's points."""
        return self._delete(f"/collections/{collection}/graph?wait={str(wait).lower()}")

    def list_edge_types(self, collection: str) -> list[dict[str, Any]]:
        return self._get(f"/collections/{collection}/graph/types")["edge_types"]

    def configure_edge_type(
        self,
        collection: str,
        edge_type: str,
        weight_property: Optional[str] = None,
        wait: bool = True,
    ) -> dict[str, Any]:
        return self._put(
            f"/collections/{collection}/graph/types/{edge_type}",
            {"weight_property": weight_property, "wait": wait},
        )

    def relate(
        self,
        collection: str,
        source_point_id: str,
        target_point_id: str,
        edge_type: str,
        properties: Optional[dict[str, Any]] = None,
        scope: str = "local",
        idempotency_key: Optional[str] = None,
        wait: bool = True,
    ) -> RelateResult:
        body: dict[str, Any] = {
            "source_point_id": source_point_id,
            "target_point_id": target_point_id,
            "edge_type": edge_type,
            "properties": properties or {},
            "scope": scope,
            "wait": wait,
        }
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        return RelateResult.from_dict(self._post(f"/collections/{collection}/edges", body))

    def unrelate(
        self,
        collection: str,
        edge_id: EdgeToken,
        wait: bool = True,
    ) -> UnrelateResult:
        response = self._delete(
            f"/collections/{collection}/edges/{edge_id.value}?wait={str(wait).lower()}"
        )
        return UnrelateResult.from_dict(response)

    def merge_edge_properties(
        self,
        collection: str,
        edge_id: EdgeToken,
        properties: dict[str, Any],
        wait: bool = True,
    ) -> dict[str, Any]:
        return self._patch(
            f"/collections/{collection}/edges/{edge_id.value}",
            {"properties": properties, "wait": wait},
        )

    def replace_edge_properties(
        self,
        collection: str,
        edge_id: EdgeToken,
        properties: dict[str, Any],
        wait: bool = True,
    ) -> dict[str, Any]:
        return self._put(
            f"/collections/{collection}/edges/{edge_id.value}",
            {"properties": properties, "wait": wait},
        )

    def traverse(
        self,
        collection: str,
        anchors: list[str],
        edge_types: Optional[list[str]] = None,
        direction: str = "outgoing",
        node_filter: Optional[dict[str, Any]] = None,
        edge_filter: Optional[dict[str, Any]] = None,
        budget: Optional[dict[str, Any]] = None,
        returns: str = "nodes",
        limit: Optional[int] = None,
        with_payload: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "anchors": anchors,
            "edge_types": edge_types or [],
            "direction": direction,
            "returns": returns,
            "with_payload": with_payload,
        }
        if node_filter is not None:
            body["node_filter"] = node_filter
        if edge_filter is not None:
            body["edge_filter"] = edge_filter
        if budget is not None:
            body["budget"] = budget
        if limit is not None:
            body["limit"] = limit
        return self._post(f"/collections/{collection}/graph/traverse", body)

    def open_deferred_graph_session(
        self,
        collection: str,
        wait: bool = True,
    ) -> GraphDeferredSessionResult:
        response = self._post_without_body(
            f"/collections/{collection}/graph/deferred-sessions?wait={str(wait).lower()}"
        )
        return GraphDeferredSessionResult.from_dict(response)

    def deferred_upsert(
        self,
        collection: str,
        session_id: GraphDeferredSessionId,
        points: list[dict[str, Any]],
        wait: bool = True,
    ) -> dict[str, Any]:
        return self._post(
            f"/collections/{collection}/graph/deferred-sessions/{session_id.value}/points",
            {"points": points, "wait": wait},
        )

    def deferred_relate(
        self,
        collection: str,
        session_id: GraphDeferredSessionId,
        source_point_id: str,
        target_point_id: str,
        edge_type: str,
        properties: Optional[dict[str, Any]] = None,
        scope: str = "local",
        idempotency_key: Optional[str] = None,
        wait: bool = True,
    ) -> RelateResult:
        body: dict[str, Any] = {
            "source_point_id": source_point_id,
            "target_point_id": target_point_id,
            "edge_type": edge_type,
            "properties": properties or {},
            "scope": scope,
            "wait": wait,
        }
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        response = self._post(
            f"/collections/{collection}/graph/deferred-sessions/{session_id.value}/edges",
            body,
        )
        return RelateResult.from_dict(response)

    def commit_deferred_graph_session(
        self,
        collection: str,
        session_id: GraphDeferredSessionId,
        wait: bool = True,
    ) -> GraphDeferredSessionResult:
        return self._finish_deferred_graph_session(collection, session_id, "commit", wait)

    def abort_deferred_graph_session(
        self,
        collection: str,
        session_id: GraphDeferredSessionId,
        wait: bool = True,
    ) -> GraphDeferredSessionResult:
        return self._finish_deferred_graph_session(collection, session_id, "abort", wait)

    def _finish_deferred_graph_session(
        self,
        collection: str,
        session_id: GraphDeferredSessionId,
        action: str,
        wait: bool,
    ) -> GraphDeferredSessionResult:
        response = self._post_without_body(
            f"/collections/{collection}/graph/deferred-sessions/{session_id.value}/{action}"
            f"?wait={str(wait).lower()}"
        )
        return GraphDeferredSessionResult.from_dict(response)

    # ── Points ────────────────────────────────────────────────────────────────

    def upsert(
        self,
        collection: str,
        points: list[dict],
        wait: bool = True,
    ) -> dict:
        """Insert or update points.

        Each point dict must have ``"id"`` and ``"vector"``, and optionally
        ``"payload"``, ``"sparse_vector"``, and ``"vectors"``.

        Args:
            wait: When ``True`` (default), block until WAL fsync confirms the
                write. When ``False``, return immediately (lower latency,
                slightly less durable on crash).
        """
        return self._put(
            f"/collections/{collection}/points",
            {"points": points, "wait": wait},
        )

    def upsert_structural(
        self,
        collection: str,
        points: list[StructuralPoint],
        wait: bool = True,
    ) -> dict:
        """Upsert typed structural nodes with zero-vector rejection.

        The server repeats validation before WAL append. Unsafe points require
        one shared, non-empty reason for the batch; that reason is written to
        the durable server audit record with the operation LSN.
        """
        reasons = {point._unsafe_reason for point in points if point._unsafe_reason is not None}
        if len(reasons) > 1:
            raise ValueError("one structural batch cannot contain multiple override reasons")
        headers = {"x-chiron-structural-points": "1"}
        if reasons:
            reason = next(iter(reasons))
            headers["x-chiron-unsafe-structural-embedding-reason"] = (
                base64.urlsafe_b64encode(reason.encode("utf-8")).decode("ascii").rstrip("=")
            )
        return self._put(
            f"/collections/{collection}/points",
            {"points": [point.point for point in points], "wait": wait},
            headers=headers,
        )

    def get_points(self, collection: str, ids: list[str]) -> list[dict]:
        """Fetch points by ID. Missing IDs are silently skipped."""
        resp = self._post(
            f"/collections/{collection}/points/get",
            {"ids": ids},
        )
        return resp["points"]

    def delete(self, collection: str, ids: list[str]) -> dict:
        """Delete points by ID."""
        return self._post(
            f"/collections/{collection}/points/delete",
            {"ids": ids},
        )

    def set_payload(
        self,
        collection: str,
        id: str,
        payload: dict,
        merge: bool = True,
    ) -> dict:
        """Set or merge payload fields on a single point.

        Args:
            merge: When ``True`` (default), merge new fields into existing
                payload. When ``False``, replace the entire payload.
        """
        resp = self._post(
            f"/collections/{collection}/points/payload",
            {"id": id, "payload": payload, "merge": merge},
        )
        return resp["point"]

    def delete_by_filter(self, collection: str, filter: dict) -> dict:
        """Delete all points matching the filter.

        ``filter`` is a key-value map, e.g. ``{"status": "archived"}``.
        """
        return self._post(
            f"/collections/{collection}/points/delete/filter",
            {"filter": filter},
        )

    # ── Search ────────────────────────────────────────────────────────────────

    def search(
        self,
        collection: str,
        vector: list[float],
        k: int = 10,
        filter: Optional[dict] = None,
        vector_name: Optional[str] = None,
        budget_ms: Optional[int] = None,
        ef_search: Optional[int] = None,
        recall_target: Optional[float] = None,
        with_payload: Optional[bool] = None,
        graph: Optional[GraphConstraint | dict[str, Any]] = None,
    ) -> dict:
        """ANN search. Returns ``{"hits": [...], "elapsed_ms": ..., ...}``.

        Args:
            ef_search: Per-query HNSW ``ef`` override (clamped to at least
                ``k`` server-side). Wins over the collection default and
                ``recall_target``.
            recall_target: Target recall in ``0.0..=1.0``; the engine picks
                ``ef_search`` from its calibration curve when ``ef_search``
                is not set.
        """
        body: dict = {"vector": vector, "k": k}
        if filter is not None:
            body["filter"] = filter
        if vector_name is not None:
            body["vector_name"] = vector_name
        if budget_ms is not None:
            body["budget_ms"] = budget_ms
        if ef_search is not None:
            body["ef_search"] = ef_search
        if recall_target is not None:
            body["recall_target"] = recall_target
        if with_payload is not None:
            body["with_payload"] = with_payload
        if graph is not None:
            body["graph"] = _graph_constraint_body(graph)
        return self._post(f"/collections/{collection}/search", body)

    def text_hybrid_search(
        self, collection: str, vector: list[float], query: str,
        text_field: str, k: int = 10, filter: Optional[dict] = None,
        budget_ms: Optional[int] = None,
    ) -> dict:
        """Fuse dense retrieval with native BM25 over a top-level text field."""
        body = {"vector": vector, "query": query, "text_field": text_field, "k": k}
        if filter is not None:
            body["filter"] = filter
        if budget_ms is not None:
            body["budget_ms"] = budget_ms
        return self._post(f"/collections/{collection}/text_hybrid_search", body)

    def hybrid_search(
        self,
        collection: str,
        vector: Optional[list[float]] = None,
        sparse_vector: Optional[dict] = None,
        k: int = 10,
        filter: Optional[dict] = None,
        vector_name: Optional[str] = None,
        fusion: str = "rrf",
        dense_weight: Optional[float] = None,
        sparse_weight: Optional[float] = None,
        budget_ms: Optional[int] = None,
        graph: Optional[GraphConstraint | dict[str, Any]] = None,
    ) -> dict:
        """Dense and lexical retrieval fused into one ranked list.

        Args:
            sparse_vector: ``{"indices": [...], "values": [...]}``.
            fusion: ``"rrf"`` (rank-based, the default) or ``"weighted"``.
            dense_weight, sparse_weight: only used when ``fusion`` is
                ``"weighted"``.

        At least one of ``vector`` or ``sparse_vector`` is required.
        """
        if vector is None and sparse_vector is None:
            raise ValueError("hybrid_search needs a vector, a sparse_vector, or both")
        body: dict = {"k": k, "fusion": fusion}
        if vector is not None:
            body["vector"] = vector
        if sparse_vector is not None:
            body["sparse_vector"] = sparse_vector
        if vector_name is not None:
            body["vector_name"] = vector_name
        if filter is not None:
            body["filter"] = filter
        if dense_weight is not None:
            body["dense_weight"] = dense_weight
        if sparse_weight is not None:
            body["sparse_weight"] = sparse_weight
        if budget_ms is not None:
            body["budget_ms"] = budget_ms
        if graph is not None:
            body["graph"] = _graph_constraint_body(graph)
        return self._post(f"/collections/{collection}/hybrid_search", body)

    def multi_search(
        self,
        collection: str,
        searches: list[dict],
        fusion: Optional[str] = None,
        fused_k: Optional[int] = None,
        weights: Optional[list[float]] = None,
    ) -> dict:
        """Several query vectors in one round trip.

        Args:
            searches: search bodies, each shaped like the ``search`` payload -
                ``{"vector": [...], "k": 10, ...}``.
            fusion: with a fusion set the engine returns one fused list;
                without one, the response carries a result set per search.

        Returns ``{"results": [{"hits": [...]}, ...]}``.
        """
        body: dict = {"searches": searches}
        if fusion is not None:
            body["fusion"] = fusion
        if fused_k is not None:
            body["fused_k"] = fused_k
        if weights is not None:
            body["weights"] = weights
        return self._post(f"/collections/{collection}/multi_search", body)

    def recommend(
        self,
        collection: str,
        positive: list[str],
        negative: Optional[list[str]] = None,
        k: int = 10,
        filter: Optional[dict] = None,
        vector_name: Optional[str] = None,
        budget_ms: Optional[int] = None,
    ) -> dict:
        """Recommend from stored point ids rather than a query vector.

        Args:
            positive: ids to move towards. At least one is required.
            negative: ids to move away from.
        """
        if not positive:
            raise ValueError("recommend needs at least one positive id")
        body: dict = {"positive": positive, "k": k}
        if negative:
            body["negative"] = negative
        if filter is not None:
            body["filter"] = filter
        if vector_name is not None:
            body["vector_name"] = vector_name
        if budget_ms is not None:
            body["budget_ms"] = budget_ms
        return self._post(f"/collections/{collection}/recommend", body)

    def rerank(
        self,
        collection: str,
        vector: list[float],
        k: int = 10,
        prefetch_k: Optional[int] = None,
        score_boosts: Optional[list[dict]] = None,
        filter: Optional[dict] = None,
        vector_name: Optional[str] = None,
        budget_ms: Optional[int] = None,
    ) -> dict:
        """ANN prefetch, then rescoring with payload rules.

        Args:
            prefetch_k: candidates to retrieve before reranking. Defaults to
                ``3 * k`` server-side.
            score_boosts: ``[{"field": ..., "value": ..., "boost": 1.5}]``.
                The factor is multiplied into the score and results are sorted
                descending, so the sign of the score matters: above 1.0 lifts a
                match on cosine or inner-product collections, where scores are
                positive. On an L2 collection the score is a negated distance,
                so a factor above 1.0 pushes the match *down* — use a factor
                between 0 and 1 to promote there.
        """
        body: dict = {"vector": vector, "k": k}
        if prefetch_k is not None:
            body["prefetch_k"] = prefetch_k
        if score_boosts:
            body["score_boosts"] = score_boosts
        if filter is not None:
            body["filter"] = filter
        if vector_name is not None:
            body["vector_name"] = vector_name
        if budget_ms is not None:
            body["budget_ms"] = budget_ms
        return self._post(f"/collections/{collection}/rerank", body)

    def compact(self, collection: str) -> dict:
        """Force segment compaction + a full index rebuild to steady state."""
        return self._post(f"/collections/{collection}/compact", {})

    def count(self, collection: str, filter: Optional[dict] = None) -> int:
        """Count points, optionally filtered."""
        body: dict = {}
        if filter is not None:
            body["filter"] = filter
        return self._post(f"/collections/{collection}/count", body)["count"]

    def scroll(
        self,
        collection: str,
        limit: int = 100,
        offset: Optional[str] = None,
        filter: Optional[dict] = None,
    ) -> dict:
        """Paginate points. Returns ``{"points": [...], "next_offset": ...}``.

        Pass ``next_offset`` from the previous response as ``offset`` to get
        the next page. ``next_offset`` is ``None`` on the last page.
        """
        body: dict = {"limit": limit}
        if offset is not None:
            body["offset"] = offset
        if filter is not None:
            body["filter"] = filter
        return self._post(f"/collections/{collection}/scroll", body)

    def scroll_all(
        self,
        collection: str,
        filter: Optional[dict] = None,
        page_size: int = 100,
    ) -> Iterator[dict]:
        """Yield every matching point using automatic pagination."""
        offset: Optional[str] = None
        while True:
            resp = self.scroll(collection, limit=page_size, offset=offset, filter=filter)
            yield from resp["points"]
            offset = resp.get("next_offset")
            if not offset:
                break

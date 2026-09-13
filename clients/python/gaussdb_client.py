"""Deprecated GaussDB import retained for ChironDB beta compatibility."""

from chirondb_client import (
    ChironDbClient,
    ChironDbError,
    EdgeToken,
    GraphConstraint,
    GraphDeferredSessionId,
    GraphDeferredSessionResult,
    RelateResult,
    StructuralPoint,
    UnrelateResult,
    UnsafeStructuralEmbeddingOverride,
)

GaussDbClient = ChironDbClient
GaussDbError = ChironDbError

__all__ = [
    "GaussDbClient",
    "GaussDbError",
    "EdgeToken",
    "GraphConstraint",
    "GraphDeferredSessionId",
    "GraphDeferredSessionResult",
    "RelateResult",
    "StructuralPoint",
    "UnrelateResult",
    "UnsafeStructuralEmbeddingOverride",
]

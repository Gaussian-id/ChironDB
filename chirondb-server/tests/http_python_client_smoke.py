"""Smoke test for the GaussDB Python HTTP client.

Invoked by the Rust scenario test with the server URL as argv[1].
Prints JSON result to stdout so the Rust test can assert on it.
"""
import json
import sys
import os

# Allow running against a bundled copy of the client module.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clients", "python"))
from gaussdb_client import GaussDbClient, GraphConstraint

url = sys.argv[1]
db = GaussDbClient(url)

# Health
h = db.health()
assert h["status"] == "ok", f"unexpected health: {h}"

# Create collection
db.create_collection("pysmoke", vector_dim=3, metric="cosine")
collections = db.list_collections()
assert [collection["name"] for collection in collections] == ["pysmoke"]

# Upsert
db.upsert("pysmoke", [
    {"id": "a", "vector": [1.0, 0.0, 0.0], "payload": {"color": "red", "active": True}},
    {"id": "b", "vector": [0.0, 1.0, 0.0], "payload": {"color": "blue", "active": False}},
    {"id": "c", "vector": [0.0, 0.0, 1.0], "payload": {"color": "green", "active": True}},
])

# Get points by ID
pts = db.get_points("pysmoke", ["a", "c"])
assert len(pts) == 2, f"expected 2 points, got {len(pts)}"
assert {p["id"] for p in pts} == {"a", "c"}

# Set payload (merge)
db.set_payload("pysmoke", "a", {"rank": 1}, merge=True)
pts2 = db.get_points("pysmoke", ["a"])
assert pts2[0]["payload"]["rank"] == 1
assert pts2[0]["payload"]["color"] == "red"  # original field preserved

# Search
resp = db.search("pysmoke", [1.0, 0.0, 0.0], k=2)
assert len(resp["hits"]) >= 1
assert resp["hits"][0]["id"] == "a"

# Search with per-query ef_search override (clamped to k server-side)
resp_ef = db.search("pysmoke", [1.0, 0.0, 0.0], k=2, ef_search=1)
assert resp_ef["hits"][0]["id"] == "a"

# Typed graph lifecycle, opaque EdgeId and graph-constrained retrieval.
enabled = db.enable_graph("pysmoke")
assert enabled["enabled"] is True
db.configure_edge_type("pysmoke", "related_to", weight_property="weight")
edge = db.relate(
    "pysmoke",
    "a",
    "b",
    "related_to",
    properties={"weight": 0.8},
)
assert str(edge.edge_id)
db.merge_edge_properties("pysmoke", edge.edge_id, {"source": "python-sdk"})
traversed = db.traverse(
    "pysmoke",
    ["a"],
    edge_types=["related_to"],
    returns="edges",
    limit=10,
    with_payload=True,
)
assert traversed["result"]["rows"][0]["id"] == str(edge.edge_id)
graph_search = db.search(
    "pysmoke",
    [0.0, 1.0, 0.0],
    k=2,
    graph=GraphConstraint(anchors=("a",), edge_types=("related_to",)),
)
assert graph_search["hits"][0]["id"] == "b"
assert graph_search["graph"]["graph_epoch"] is not None
deleted_edge = db.unrelate("pysmoke", edge.edge_id, wait=False)
assert deleted_edge.deleted == 1

# Compact
db.compact("pysmoke")

# Explicit LS-VEC is accepted; omitted index_kind above uses the same family.
db.create_collection(
    "pysmoke_lsvec",
    vector_dim=3,
    metric="l2",
    index_kind="lsvec",
)
db.upsert("pysmoke_lsvec", [
    {"id": "x", "vector": [1.0, 0.0, 0.0]},
    {"id": "y", "vector": [0.0, 1.0, 0.0]},
])
hits = db.search("pysmoke_lsvec", [1.0, 0.0, 0.0], k=1)["hits"]
assert hits[0]["id"] == "x", f"lsvec: expected x, got {hits}"
db.delete_collection("pysmoke_lsvec")

# Count
total = db.count("pysmoke")
assert total == 3, f"expected 3, got {total}"

filtered = db.count("pysmoke", filter={"active": True})
assert filtered == 2, f"expected 2 active, got {filtered}"

# Scroll
page = db.scroll("pysmoke", limit=2)
assert len(page["points"]) == 2
assert page["next_offset"] is not None

page2 = db.scroll("pysmoke", limit=2, offset=page["next_offset"])
assert len(page2["points"]) == 1
assert page2["next_offset"] is None

# scroll_all
all_pts = list(db.scroll_all("pysmoke", page_size=2))
assert len(all_pts) == 3

# Delete by filter
db.delete_by_filter("pysmoke", {"active": False})
assert db.count("pysmoke") == 2

# Delete by ID
db.delete("pysmoke", ["c"])
assert db.count("pysmoke") == 1

# Deferred loading admits edges before their point endpoints, then binds both
# identities at commit without exposing internal graph IDs.
session = db.open_deferred_graph_session("pysmoke")
deferred_edge = db.deferred_relate(
    "pysmoke",
    session.session_id,
    "late-a",
    "late-b",
    "related_to",
)
bound = db.deferred_upsert(
    "pysmoke",
    session.session_id,
    [
        {"id": "late-a", "vector": [0.2, 0.8, 0.0]},
        {"id": "late-b", "vector": [0.1, 0.9, 0.0]},
    ],
    wait=False,
)
assert bound["bound_endpoints"] == 2
committed = db.commit_deferred_graph_session("pysmoke", session.session_id)
assert committed.state == "committed"
deferred_traversal = db.traverse(
    "pysmoke",
    ["late-a"],
    edge_types=["related_to"],
    returns="edges",
    limit=10,
)
assert deferred_traversal["result"]["rows"][0]["id"] == str(deferred_edge.edge_id)
assert db.drop_graph("pysmoke")["enabled"] is False

print(json.dumps({"python_http_client": "ok"}))

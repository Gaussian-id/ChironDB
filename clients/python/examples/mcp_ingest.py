"""Ingest one example chunk with the operator's embedding model, then search it.

Requires a fresh `sop` collection and the matching MCP binding documented in
docs/SDKS.md. No sparse vectors or inference runtime are installed by ChironDB.
"""
import json
import math
import os
from ipaddress import ip_address
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener

from chirondb_client import ChironDbClient


def main():
    model = os.environ.get("CHIRONDB_MCP_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    endpoint = os.environ["CHIRONDB_EMBEDDING_ENDPOINT"]
    parsed = urlsplit(endpoint)
    try:
        loopback = ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    assert parsed.scheme == "https" or (parsed.scheme == "http" and loopback)
    assert not parsed.username and not parsed.password and not parsed.fragment

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *_):
            return None

    opener = build_opener(NoRedirect())
    headers = {"Content-Type": "application/json"}
    if key := os.environ.get("CHIRONDB_EMBEDDING_API_KEY"):
        headers["Authorization"] = f"Bearer {key}"

    def embed(text):
        request = Request(endpoint, data=json.dumps({"model": model, "input": text}).encode(), headers=headers)
        with opener.open(request, timeout=30) as response:
            result = json.load(response)
        assert len(result["data"]) == 1
        vector = result["data"][0]["embedding"]
        assert len(vector) == 384 and all(math.isfinite(value) for value in vector)
        return vector

    db = ChironDbClient(os.environ.get("CHIRONDB_URL", "http://127.0.0.1:7401"), api_key=os.environ["CHIRONDB_API_KEY"])
    text = "Pengembalian barang diajukan melalui layanan pelanggan."
    vector = embed(text)
    db.create_collection(name="sop", vector_dim=384, metric="cosine")
    db.upsert("sop", [{"id": "retur-001-chunk-01", "vector": vector, "payload": {
        "text": text, "department": "customer_service", "title": "SOP Pengembalian Barang", "source": "https://docs.example.com/sop/retur",
    }}], wait=True)
    question = "Bagaimana prosedur pengembalian barang?"
    result = db.text_hybrid_search("sop", vector=embed(question), query=question, text_field="text", k=5)
    assert result["hits"][0]["id"] == "retur-001-chunk-01"
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()

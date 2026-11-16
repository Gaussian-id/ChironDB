#!/usr/bin/env python3
"""Frozen reconstructed read guard: all 300 SciFact queries and mixed p99.

10,000 reads at 50 scheduled requests/s, concurrency8, max16pending. Latencies
include scheduler/queue delay (no coordinated omission). This does not recreate
the unavailable historical P4 script. Quality must match the baseline rankings
and nDCG; mixed p99 must be <=1.05x baseline. No retry is accepted as success.
"""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import json
import math
from pathlib import Path
import random
import time


def quality(http, corpus):
    scores, ranking = {}, hashlib.sha256()
    for mode in ("dense", "lexical", "hybrid"):
        total = 0.0
        for query in corpus["queries"]:
            if mode == "dense":
                result = http.request("POST", "/v1/collections/chunks/search", {"vector": query["vector"], "k": 10}, "quality-dense")
            else:
                result = http.request("POST", "/v1/collections/chunks/text_hybrid_search", {
                    "query": query["text"], "text_field": "text", "k": 10,
                    "vector": query["vector"] if mode == "hybrid" else []}, "quality-" + mode)
            assert not result.get("degraded")
            ids = [hit["id"] for hit in result["hits"]]
            assert len(ids) == len(set(ids))
            ranking.update(json.dumps([mode, query["id"], ids], separators=(",", ":")).encode())
            relevance = corpus["qrels"][query["id"]]
            dcg = sum(relevance.get(identity, 0) / math.log2(index + 2) for index, identity in enumerate(ids[:10]))
            ideal = sum(value / math.log2(index + 2) for index, value in enumerate(sorted(relevance.values(), reverse=True)[:10]))
            total += dcg / ideal if ideal else 0.0
        scores[mode] = total / len(corpus["queries"])
    return {"queries": len(corpus["queries"]), "ndcg_at_10": scores, "ranking_sha256": ranking.hexdigest()}


def reads(http, corpus, output):
    identities = sorted(row["id"] for row in corpus["corpus"])
    rng = random.Random(20261103)
    plan = []
    for number in range(10000):
        query = corpus["queries"][rng.randrange(len(corpus["queries"]))]
        identity = identities[rng.randrange(len(identities))]
        kind = number % 20
        if kind < 10:
            path, body, phase = "/v1/collections/chunks/search", {"vector": query["vector"], "k": 10}, "read-dense"
        elif kind < 15:
            hybrid = kind >= 12
            path, body, phase = "/v1/collections/chunks/text_hybrid_search", {
                "query": query["text"], "text_field": "text", "k": 10, "vector": query["vector"] if hybrid else []}, "read-hybrid" if hybrid else "read-lexical"
        elif kind < 18:
            path, body, phase = "/v1/collections/chunks/graph/traverse", {
                "anchors": [identity], "edge_types": ["cites"], "direction": "outgoing", "returns": "edges", "with_payload": True,
                "budget": {"max_depth": 1, "max_frontier": 10000, "max_visited": 10000, "max_edges": 10000,
                           "max_time_ms": 5000, "max_memory_bytes": 16 * 1024 * 1024, "cold": None}}, "read-graph"
        else:
            path, body, phase = "/v1/sql", {"statements": [{"sql": "SELECT id, ordinal FROM documents WHERE id=$1",
                "parameters": [{"type": "text", "value": identity}]}]}, "read-sql"
        plan.append((path, json.dumps(body, separators=(",", ":")), phase))
    digest = hashlib.sha256(json.dumps(plan, separators=(",", ":")).encode()).hexdigest()
    # Warm every planned operation shape without consuming measured samples.
    for path, body, phase in plan[:200]:
        http.request("POST", path, body, "warmup-" + phase)
    started, samples = time.monotonic() + 0.1, []

    def send(number, due):
        path, body, phase = plan[number]
        service_started = time.monotonic()
        result = http.request("POST", path, body, phase)
        assert not result.get("degraded") and not result.get("truncation")
        return {"number": number, "phase": phase, "seconds": time.monotonic() - due,
                "scheduling_delay_seconds": service_started - due}

    with ThreadPoolExecutor(max_workers=8) as pool:
        pending = set()
        for number in range(len(plan)):
            due = started + number / 50
            while len(pending) >= 16:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                samples.extend(future.result() for future in done)
            delay = due - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            pending.add(pool.submit(send, number, due))
            completed = {future for future in pending if future.done()}
            samples.extend(future.result() for future in completed)
            pending -= completed
        samples.extend(future.result() for future in pending)
    with output.open("w") as stream:
        for sample in sorted(samples, key=lambda row: row["number"]):
            stream.write(json.dumps(sample) + "\n")
    def percentiles(rows):
        values = sorted(row["seconds"] for row in rows)
        return {"samples": len(values), **{f"p{p}_seconds": values[math.ceil(len(values) * p / 100) - 1] for p in (50, 95, 99)}}
    return {"plan_sha256": digest, "seed": 20261103, "scheduled_qps": 50, "concurrency": 8, "max_pending": 16,
            "total": percentiles(samples), "phases": {phase: percentiles([row for row in samples if row["phase"] == phase])
                for phase in sorted({row["phase"] for row in samples})}}

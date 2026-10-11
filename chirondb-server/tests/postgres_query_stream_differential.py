#!/usr/bin/env python3
"""Compare bounded single-table SELECT, COUNT and ORDER BY with PostgreSQL.

Requires CHIRONDB_DSN and POSTGRES_DSN. Both databases are disposable test
installations: this probe drops and recreates its own stream_diff_ranking table.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from typing import Any

import psycopg


TABLE = "stream_diff_ranking"


def read(connection: psycopg.Connection[Any], sql: str) -> list[list[int | str | None]]:
    return [list(row) for row in connection.execute(sql).fetchall()]


def query_for(randomizer: random.Random) -> str:
    limit = randomizer.randrange(0, 32)
    offset = randomizer.randrange(0, 40)
    threshold = randomizer.randrange(-6, 7)
    minimum_id = randomizer.randrange(0, 128)
    shape = randomizer.randrange(10)
    if shape == 0:
        return f"SELECT id, score FROM {TABLE} LIMIT {limit} OFFSET {offset}"
    if shape == 1:
        return (
            f"SELECT id, score FROM {TABLE} WHERE id >= {minimum_id} "
            f"ORDER BY score ASC NULLS FIRST, id DESC LIMIT {limit} OFFSET {offset}"
        )
    if shape == 2:
        return (
            f"SELECT id, score FROM {TABLE} WHERE score >= {threshold} "
            f"ORDER BY score DESC NULLS LAST, id ASC LIMIT {limit} OFFSET {offset}"
        )
    if shape == 3:
        return (
            f"SELECT id, score AS score_alias FROM {TABLE} "
            f"ORDER BY score_alias DESC NULLS FIRST, id ASC LIMIT {limit} OFFSET {offset}"
        )
    if shape == 4:
        return (
            f"SELECT id, score FROM {TABLE} "
            f"ORDER BY 2 ASC NULLS LAST, 1 DESC LIMIT {limit} OFFSET {offset}"
        )
    if shape == 5:
        return f"SELECT COUNT(*) AS total FROM {TABLE} WHERE id >= {minimum_id}"
    if shape == 6:
        return f"SELECT COUNT(score) FROM {TABLE} WHERE id >= {minimum_id}"
    if shape == 7:
        return (
            f"SELECT id, note FROM {TABLE} WHERE score IS NULL "
            f"ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
        )
    if shape == 8:
        return (
            f"SELECT id, score FROM {TABLE} WHERE score = {threshold} "
            f"ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
        )
    return f"SELECT COUNT(*) FROM {TABLE} WHERE score = {threshold}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20260926)
    parser.add_argument("--queries", type=int, default=1000)
    args = parser.parse_args()
    if args.queries <= 0:
        parser.error("--queries must be positive")
    chiron_dsn = os.environ["CHIRONDB_DSN"]
    postgres_dsn = os.environ["POSTGRES_DSN"]
    randomizer = random.Random(args.seed)
    digest = hashlib.sha256()
    with (
        psycopg.connect(chiron_dsn, autocommit=True) as chiron,
        psycopg.connect(postgres_dsn, autocommit=True) as postgres,
    ):
        for connection in (chiron, postgres):
            connection.execute(f"DROP TABLE IF EXISTS {TABLE}")
            connection.execute(
                f"CREATE TABLE {TABLE} (id INTEGER PRIMARY KEY, score INTEGER, note TEXT)"
            )
            values = ", ".join(
                f"({index}, {('NULL' if index % 11 == 0 else str((index * 17) % 13 - 6))}, "
                f"'item-{index:03d}')"
                for index in range(128)
            )
            connection.execute(f"INSERT INTO {TABLE} VALUES {values}")
            connection.execute(f"CREATE INDEX stream_diff_score_idx ON {TABLE} (score)")
        for index in range(args.queries):
            sql = query_for(randomizer)
            chiron_rows = read(chiron, sql)
            postgres_rows = read(postgres, sql)
            if chiron_rows != postgres_rows:
                raise AssertionError(
                    f"query {index} mismatch: {sql}\n"
                    f"ChironDB={chiron_rows!r}\nPostgreSQL={postgres_rows!r}"
                )
            encoded = json.dumps([sql, chiron_rows], separators=(",", ":")).encode()
            digest.update(len(encoded).to_bytes(8, "little"))
            digest.update(encoded)
        print(
            json.dumps(
                {
                    "status": "pass",
                    "seed": args.seed,
                    "queries": args.queries,
                    "result_digest_sha256": digest.hexdigest(),
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()

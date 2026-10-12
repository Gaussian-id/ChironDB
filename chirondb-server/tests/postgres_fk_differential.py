#!/usr/bin/env python3
"""Differential foreign-key history against ChironDB and PostgreSQL.

Both databases receive the same deterministic autocommit statements.  The
harness compares success/error SQLSTATE and the complete ordered contents of
the parent plus five child tables after every statement.  It deliberately uses
only the SQL profile shared by the two engines.

Required environment variables:

    CHIRONDB_DSN="host=127.0.0.1 port=17603 user=chiron dbname=gaussdb sslmode=disable"
    POSTGRES_DSN="host=127.0.0.1 port=17643 user=postgres password=... dbname=postgres sslmode=disable"

The psycopg version is pinned by requirements-postgres-orm.txt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass
from typing import Any

import psycopg


DEFAULT_SEED = 0x4348_4952_4F4E_4442
MASK64 = (1 << 64) - 1
PREFIX = "fk_diff_"
PARENT = f"{PREFIX}parent"
CHILDREN = (
    f"{PREFIX}restrict_children",
    f"{PREFIX}no_action_children",
    f"{PREFIX}cascade_children",
    f"{PREFIX}nullable_children",
    f"{PREFIX}default_children",
)


@dataclass
class SplitMix64:
    state: int

    def next(self) -> int:
        self.state = (self.state + 0x9E37_79B9_7F4A_7C15) & MASK64
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58_476D_1CE4_E5B9) & MASK64
        value = ((value ^ (value >> 27)) * 0x94D0_49BB_1331_11EB) & MASK64
        return (value ^ (value >> 31)) & MASK64


def execute(connection: psycopg.Connection[Any], sql: str) -> tuple[bool, str | None]:
    try:
        connection.execute(sql)
        return True, None
    except psycopg.Error as error:
        return False, error.sqlstate


def fetch_state(connection: psycopg.Connection[Any]) -> dict[str, list[list[int | None]]]:
    state: dict[str, list[list[int | None]]] = {}
    state[PARENT] = [list(row) for row in connection.execute(
        f"SELECT id FROM {PARENT} ORDER BY id"
    ).fetchall()]
    for table in CHILDREN:
        state[table] = [list(row) for row in connection.execute(
            f"SELECT id, parent_id FROM {table} ORDER BY id"
        ).fetchall()]
    return state


def state_digest(state: dict[str, list[list[int | None]]]) -> str:
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def cleanup(connection: psycopg.Connection[Any]) -> None:
    for table in reversed(CHILDREN):
        connection.execute(f"DROP TABLE IF EXISTS {table}")
    connection.execute(f"DROP TABLE IF EXISTS {PARENT}")


def setup(connection: psycopg.Connection[Any]) -> None:
    cleanup(connection)
    statements = (
        f"CREATE TABLE {PARENT} (id INTEGER PRIMARY KEY)",
        f"CREATE TABLE {CHILDREN[0]} (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES {PARENT}(id) ON UPDATE RESTRICT ON DELETE RESTRICT)",
        f"CREATE TABLE {CHILDREN[1]} (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES {PARENT}(id) ON UPDATE NO ACTION ON DELETE NO ACTION)",
        f"CREATE TABLE {CHILDREN[2]} (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES {PARENT}(id) ON UPDATE CASCADE ON DELETE CASCADE)",
        f"CREATE TABLE {CHILDREN[3]} (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES {PARENT}(id) ON UPDATE SET NULL ON DELETE SET NULL)",
        f"CREATE TABLE {CHILDREN[4]} (id INTEGER PRIMARY KEY, parent_id INTEGER DEFAULT 0 NOT NULL REFERENCES {PARENT}(id) ON UPDATE SET DEFAULT ON DELETE SET DEFAULT)",
        f"INSERT INTO {PARENT} VALUES (0)",
    )
    for statement in statements:
        connection.execute(statement)


def generate_statement(random: SplitMix64) -> tuple[str, str, str | None]:
    operation = random.next() % 6
    if operation == 0:
        parent = 1 + random.next() % 9
        return "parent_insert", f"INSERT INTO {PARENT} VALUES ({parent})", None
    if operation == 1:
        parent = 1 + random.next() % 9
        return "parent_delete", f"DELETE FROM {PARENT} WHERE id = {parent}", None
    if operation == 2:
        old = 1 + random.next() % 9
        new = 1 + random.next() % 9
        return (
            "parent_key_update",
            f"UPDATE {PARENT} SET id = {new} WHERE id = {old}",
            None,
        )

    table_index = random.next() % len(CHILDREN)
    child = 1 + random.next() % 18
    if operation in (3, 4):
        nullable = table_index != 4 and random.next() % 5 == 0
        parent = None if nullable else random.next() % 10
        encoded_parent = "NULL" if parent is None else str(parent)
        if operation == 3:
            return (
                "child_insert",
                f"INSERT INTO {CHILDREN[table_index]} VALUES ({child}, {encoded_parent})",
                CHILDREN[table_index],
            )
        return (
            "child_update",
            f"UPDATE {CHILDREN[table_index]} SET parent_id = {encoded_parent} WHERE id = {child}",
            CHILDREN[table_index],
        )
    return (
        "child_delete",
        f"DELETE FROM {CHILDREN[table_index]} WHERE id = {child}",
        CHILDREN[table_index],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--steps", type=int, default=160)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=DEFAULT_SEED)
    parser.add_argument("--keep-tables", action="store_true")
    args = parser.parse_args()
    if args.steps <= 0:
        parser.error("--steps must be positive")

    chirondb_dsn = os.environ["CHIRONDB_DSN"]
    postgres_dsn = os.environ["POSTGRES_DSN"]
    operations: Counter[str] = Counter()
    child_tables: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    random = SplitMix64(args.seed)

    with (
        psycopg.connect(chirondb_dsn, autocommit=True, prepare_threshold=5) as chirondb,
        psycopg.connect(postgres_dsn, autocommit=True, prepare_threshold=5) as postgres,
    ):
        setup(chirondb)
        setup(postgres)
        try:
            for step in range(args.steps):
                operation, sql, child_table = generate_statement(random)
                operations[operation] += 1
                if child_table is not None:
                    child_tables[child_table] += 1

                chirondb_outcome = execute(chirondb, sql)
                postgres_outcome = execute(postgres, sql)
                if chirondb_outcome != postgres_outcome:
                    raise AssertionError(
                        f"outcome mismatch at step {step}: {sql}; "
                        f"ChironDB={chirondb_outcome}, PostgreSQL={postgres_outcome}"
                    )
                if not chirondb_outcome[0]:
                    errors[chirondb_outcome[1] or "missing"] += 1

                chirondb_state = fetch_state(chirondb)
                postgres_state = fetch_state(postgres)
                if chirondb_state != postgres_state:
                    raise AssertionError(
                        f"state mismatch at step {step}: {sql}\n"
                        f"ChironDB={json.dumps(chirondb_state, sort_keys=True)}\n"
                        f"PostgreSQL={json.dumps(postgres_state, sort_keys=True)}"
                    )

            final_state = fetch_state(chirondb)
            print(json.dumps({
                "status": "pass",
                "steps": args.steps,
                "seed_hex": f"0x{args.seed:016x}",
                "operations": dict(sorted(operations.items())),
                "child_table_selections": {
                    name.removeprefix(PREFIX).removesuffix("_children"): count
                    for name, count in sorted(child_tables.items())
                },
                "error_sqlstates": dict(sorted(errors.items())),
                "final_state_sha256": state_digest(final_state),
                "final_state": final_state,
            }, indent=2, sort_keys=True))
        finally:
            if not args.keep_tables:
                cleanup(chirondb)
                cleanup(postgres)


if __name__ == "__main__":
    main()

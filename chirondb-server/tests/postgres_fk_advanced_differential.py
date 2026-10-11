#!/usr/bin/env python3
"""Compare advanced foreign-key semantics with PostgreSQL.

This deterministic probe covers composite keys, MATCH SIMPLE/FULL, deferred
validation, SET CONSTRAINTS, self references, and a deferred self-cycle.  It
uses only SQL supported by both engines and compares SQLSTATE plus complete
visible table state after each statement for which the transaction is usable.

Required environment variables:

    CHIRONDB_DSN="host=127.0.0.1 port=17603 user=chiron dbname=gaussdb sslmode=disable"
    POSTGRES_DSN="host=127.0.0.1 port=17643 user=postgres password=... dbname=postgres sslmode=disable"
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable

import psycopg


Connection = psycopg.Connection[Any]
StateReader = Callable[[Connection], dict[str, list[list[int | None]]]]


@dataclass(frozen=True)
class Step:
    sql: str
    expected_sqlstate: str | None = None
    compare_state: bool = True


def execute(connection: Connection, sql: str) -> tuple[bool, str | None]:
    try:
        connection.execute(sql)
        return True, None
    except psycopg.Error as error:
        return False, error.sqlstate


def ordered_rows(connection: Connection, table: str, columns: str) -> list[list[int | None]]:
    return [
        list(row)
        for row in connection.execute(
            f"SELECT {columns} FROM {table} ORDER BY 1"
        ).fetchall()
    ]


def run_scenario(
    name: str,
    chirondb: Connection,
    postgres: Connection,
    setup: tuple[str, ...],
    steps: tuple[Step, ...],
    read_state: StateReader,
    cleanup: tuple[str, ...],
) -> dict[str, Any]:
    for connection in (chirondb, postgres):
        for statement in cleanup:
            connection.execute(statement)
        for statement in setup:
            connection.execute(statement)

    errors: dict[str, int] = {}
    compared_states = 0
    try:
        for index, step in enumerate(steps):
            chirondb_outcome = execute(chirondb, step.sql)
            postgres_outcome = execute(postgres, step.sql)
            if chirondb_outcome != postgres_outcome:
                raise AssertionError(
                    f"{name} outcome mismatch at step {index}: {step.sql}; "
                    f"ChironDB={chirondb_outcome}, PostgreSQL={postgres_outcome}"
                )
            expected = (step.expected_sqlstate is None, step.expected_sqlstate)
            if chirondb_outcome != expected:
                raise AssertionError(
                    f"{name} unexpected outcome at step {index}: {step.sql}; "
                    f"expected={expected}, actual={chirondb_outcome}"
                )
            if step.expected_sqlstate is not None:
                errors[step.expected_sqlstate] = errors.get(step.expected_sqlstate, 0) + 1
            if step.compare_state:
                chirondb_state = read_state(chirondb)
                postgres_state = read_state(postgres)
                if chirondb_state != postgres_state:
                    raise AssertionError(
                        f"{name} state mismatch at step {index}: {step.sql}\n"
                        f"ChironDB={json.dumps(chirondb_state, sort_keys=True)}\n"
                        f"PostgreSQL={json.dumps(postgres_state, sort_keys=True)}"
                    )
                compared_states += 1
        final_state = read_state(chirondb)
        if final_state != read_state(postgres):
            raise AssertionError(f"{name} final state mismatch")
        return {
            "steps": len(steps),
            "state_comparisons": compared_states + 1,
            "error_sqlstates": errors,
            "final_state": final_state,
        }
    finally:
        for connection in (chirondb, postgres):
            execute(connection, "ROLLBACK")
            for statement in cleanup:
                connection.execute(statement)


def composite_state(connection: Connection) -> dict[str, list[list[int | None]]]:
    return {
        "fk_adv_parent": ordered_rows(connection, "fk_adv_parent", "tenant_id, id"),
        "fk_adv_full": ordered_rows(connection, "fk_adv_full", "id, tenant_id, parent_id"),
        "fk_adv_simple": ordered_rows(connection, "fk_adv_simple", "id, tenant_id, parent_id"),
    }


def self_state(connection: Connection) -> dict[str, list[list[int | None]]]:
    return {"fk_adv_node": ordered_rows(connection, "fk_adv_node", "id, parent_id")}


def restrict_state(connection: Connection) -> dict[str, list[list[int | None]]]:
    return {
        "fk_adv_restrict_parent": ordered_rows(connection, "fk_adv_restrict_parent", "id"),
        "fk_adv_restrict_child": ordered_rows(connection, "fk_adv_restrict_child", "id, parent_id"),
        "fk_adv_no_action_child": ordered_rows(connection, "fk_adv_no_action_child", "id, parent_id"),
    }


def main() -> None:
    chirondb_dsn = os.environ["CHIRONDB_DSN"]
    postgres_dsn = os.environ["POSTGRES_DSN"]
    results: dict[str, Any] = {}
    with (
        psycopg.connect(chirondb_dsn, autocommit=True, prepare_threshold=5) as chirondb,
        psycopg.connect(postgres_dsn, autocommit=True, prepare_threshold=5) as postgres,
    ):
        composite_cleanup = (
            "DROP TABLE IF EXISTS fk_adv_full",
            "DROP TABLE IF EXISTS fk_adv_simple",
            "DROP TABLE IF EXISTS fk_adv_parent",
        )
        results["composite_match_and_deferred"] = run_scenario(
            "composite_match_and_deferred",
            chirondb,
            postgres,
            (
                "CREATE TABLE fk_adv_parent (tenant_id INTEGER, id INTEGER, PRIMARY KEY (tenant_id, id))",
                "CREATE TABLE fk_adv_full (id INTEGER PRIMARY KEY, tenant_id INTEGER, parent_id INTEGER, CONSTRAINT fk_adv_full_parent FOREIGN KEY (tenant_id, parent_id) REFERENCES fk_adv_parent (tenant_id, id) MATCH FULL DEFERRABLE INITIALLY DEFERRED)",
                "CREATE TABLE fk_adv_simple (id INTEGER PRIMARY KEY, tenant_id INTEGER, parent_id INTEGER, CONSTRAINT fk_adv_simple_parent FOREIGN KEY (tenant_id, parent_id) REFERENCES fk_adv_parent (tenant_id, id) MATCH SIMPLE)",
            ),
            (
                Step("INSERT INTO fk_adv_parent VALUES (1, 10)"),
                Step("INSERT INTO fk_adv_full VALUES (1, NULL, NULL)"),
                Step("INSERT INTO fk_adv_simple VALUES (1, 1, NULL)"),
                Step("INSERT INTO fk_adv_full VALUES (2, 1, NULL)", "23503"),
                Step("INSERT INTO fk_adv_full VALUES (2, 1, 10)"),
                Step("BEGIN"),
                Step("INSERT INTO fk_adv_full VALUES (3, 2, 20)"),
                Step("INSERT INTO fk_adv_parent VALUES (2, 20)"),
                Step("COMMIT"),
                Step("BEGIN"),
                Step("INSERT INTO fk_adv_full VALUES (4, 3, 30)"),
                Step("SET CONSTRAINTS ALL IMMEDIATE", "23503", compare_state=False),
                Step("ROLLBACK"),
                Step("BEGIN"),
                Step("SET CONSTRAINTS fk_adv_full_parent IMMEDIATE"),
                Step("INSERT INTO fk_adv_full VALUES (5, 4, 40)", "23503", compare_state=False),
                Step("ROLLBACK"),
            ),
            composite_state,
            composite_cleanup,
        )

        self_cleanup = ("DROP TABLE IF EXISTS fk_adv_node",)
        results["self_reference_and_cycle"] = run_scenario(
            "self_reference_and_cycle",
            chirondb,
            postgres,
            (
                "CREATE TABLE fk_adv_node (id INTEGER PRIMARY KEY, parent_id INTEGER, CONSTRAINT fk_adv_node_parent FOREIGN KEY (parent_id) REFERENCES fk_adv_node (id) ON UPDATE CASCADE ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED)",
            ),
            (
                Step("INSERT INTO fk_adv_node VALUES (1, NULL)"),
                Step("INSERT INTO fk_adv_node VALUES (2, 1)"),
                Step("INSERT INTO fk_adv_node VALUES (3, 2)"),
                Step("UPDATE fk_adv_node SET id = 10 WHERE id = 1"),
                Step("DELETE FROM fk_adv_node WHERE id = 2"),
                Step("BEGIN"),
                Step("INSERT INTO fk_adv_node VALUES (20, 21)"),
                Step("INSERT INTO fk_adv_node VALUES (21, 20)"),
                Step("COMMIT"),
                Step("DELETE FROM fk_adv_node WHERE id = 20"),
            ),
            self_state,
            self_cleanup,
        )

        restrict_cleanup = (
            "DROP TABLE IF EXISTS fk_adv_restrict_child",
            "DROP TABLE IF EXISTS fk_adv_no_action_child",
            "DROP TABLE IF EXISTS fk_adv_restrict_parent",
        )
        results["restrict_and_unique_precedence"] = run_scenario(
            "restrict_and_unique_precedence",
            chirondb,
            postgres,
            (
                "CREATE TABLE fk_adv_restrict_parent (id INTEGER PRIMARY KEY)",
                "CREATE TABLE fk_adv_restrict_child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES fk_adv_restrict_parent(id) ON UPDATE RESTRICT ON DELETE RESTRICT)",
                "CREATE TABLE fk_adv_no_action_child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES fk_adv_restrict_parent(id) ON UPDATE NO ACTION ON DELETE NO ACTION)",
            ),
            (
                Step("INSERT INTO fk_adv_restrict_parent VALUES (1), (2)"),
                Step("INSERT INTO fk_adv_restrict_child VALUES (10, 1)"),
                Step("INSERT INTO fk_adv_no_action_child VALUES (20, 2)"),
                Step("DELETE FROM fk_adv_restrict_parent WHERE id = 1", "23001"),
                Step("UPDATE fk_adv_restrict_parent SET id = 3 WHERE id = 1", "23001"),
                Step("UPDATE fk_adv_restrict_parent SET id = 2 WHERE id = 1", "23505"),
                Step("DELETE FROM fk_adv_restrict_parent WHERE id = 2", "23503"),
                Step("UPDATE fk_adv_restrict_parent SET id = 3 WHERE id = 2", "23503"),
            ),
            restrict_state,
            restrict_cleanup,
        )

    print(json.dumps({"status": "pass", "scenarios": results}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

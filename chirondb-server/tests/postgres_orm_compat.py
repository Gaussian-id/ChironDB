#!/usr/bin/env python3
"""Live PostgreSQL-wire smoke for psycopg 3 and SQLAlchemy 2.

This intentionally uses the unmodified PostgreSQL drivers. Start ChironDB,
install the optional test dependencies in an isolated environment, then run:

    python postgres_orm_compat.py

Environment variables: CHIRONDB_PG_HOST, CHIRONDB_PG_PORT, CHIRONDB_PG_USER,
and CHIRONDB_PG_DATABASE. Protected runs additionally set CHIRONDB_PG_SSLMODE
(verify-full), CHIRONDB_PG_SSLROOTCERT, and CHIRONDB_PG_PASSWORD_FILE. The password
is read from a private file and is never printed in the result.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import psycopg
import sqlalchemy
import alembic
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    BigInteger,
    Column,
    ForeignKeyConstraint,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    inspect,
    text,
)


host = os.getenv("CHIRONDB_PG_HOST", "127.0.0.1")
port = int(os.getenv("CHIRONDB_PG_PORT", "7403"))
user = os.getenv("CHIRONDB_PG_USER", "chiron")
database = os.getenv("CHIRONDB_PG_DATABASE", "gaussdb")
sslmode = os.getenv("CHIRONDB_PG_SSLMODE", "disable")
sslrootcert = os.getenv("CHIRONDB_PG_SSLROOTCERT")
password_file = os.getenv("CHIRONDB_PG_PASSWORD_FILE")
password = Path(password_file).read_text().strip() if password_file else None
connection_options = {
    "host": host, "port": port, "user": user, "dbname": database,
    "sslmode": sslmode, "connect_timeout": 3,
}
url_options = {"sslmode": sslmode, "connect_timeout": "3"}
if sslrootcert:
    connection_options["sslrootcert"] = sslrootcert
    url_options["sslrootcert"] = sslrootcert
if password is not None:
    connection_options["password"] = password
dsn = psycopg.conninfo.make_conninfo(**connection_options)
url = sqlalchemy.URL.create(
    "postgresql+psycopg", username=user, password=password,
    host=host, port=port, database=database, query=url_options,
)

with psycopg.connect(dsn) as connection:
    with connection.cursor() as cursor:
        cursor.execute(
            "CREATE TABLE orm_accounts ("
            "id BIGINT PRIMARY KEY, "
            "email VARCHAR(128) NOT NULL UNIQUE, "
            "note TEXT)"
        )
        cursor.execute(
            "CREATE TABLE orm_parents ("
            "tenant_id BIGINT, id BIGINT, "
            "PRIMARY KEY (tenant_id, id))"
        )
        cursor.execute(
            "CREATE TABLE orm_children ("
            "id BIGINT PRIMARY KEY, tenant_id BIGINT, parent_id BIGINT, "
            "CONSTRAINT orm_children_parent_fkey "
            "FOREIGN KEY (tenant_id, parent_id) "
            "REFERENCES orm_parents (tenant_id, id) MATCH FULL "
            "ON UPDATE CASCADE ON DELETE RESTRICT "
            "DEFERRABLE INITIALLY DEFERRED)"
        )
        cursor.execute(
            "INSERT INTO orm_accounts (id,email,note) "
            "VALUES (%s,%s,%s) RETURNING id",
            (1, "a@example.test", None),
        )
        inserted = cursor.fetchone()
        cursor.execute(
            "SELECT id,email,note FROM orm_accounts WHERE id=%s",
            (1,),
        )
        selected = cursor.fetchone()
    connection.commit()

assert inserted == (1,)
assert selected == (1, "a@example.test", None)

engine = create_engine(url)
with engine.connect() as connection:
    rows = [dict(row) for row in connection.execute(
        text("SELECT id,email FROM orm_accounts ORDER BY id")
    ).mappings()]
    inspector = inspect(connection)
    tables = inspector.get_table_names(schema="public")
    columns = inspector.get_columns("orm_accounts", schema="public")
    primary_key = inspector.get_pk_constraint("orm_accounts", schema="public")
    unique = inspector.get_unique_constraints("orm_accounts", schema="public")
    foreign_keys = inspector.get_foreign_keys("orm_children", schema="public")
    information_tables = [
        dict(row)
        for row in connection.execute(
            text(
                "SELECT table_schema,table_name,table_type "
                "FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name='orm_accounts'"
            )
        ).mappings()
    ]
    information_columns = [
        dict(row)
        for row in connection.execute(
            text(
                "SELECT column_name,data_type,is_nullable,column_default,"
                "ordinal_position,character_maximum_length "
                "FROM information_schema.columns "
                "WHERE table_schema='public' AND table_name='orm_accounts' "
                "ORDER BY ordinal_position"
            )
        ).mappings()
    ]

    metadata = MetaData()
    Table(
        "orm_accounts",
        metadata,
        Column("id", BigInteger, primary_key=True),
        Column("email", String(128), nullable=False),
        Column("note", Text, nullable=True),
        UniqueConstraint("email", name="orm_accounts_email_key"),
    )
    Table(
        "orm_parents",
        metadata,
        Column("tenant_id", BigInteger, primary_key=True),
        Column("id", BigInteger, primary_key=True),
    )
    Table(
        "orm_children",
        metadata,
        Column("id", BigInteger, primary_key=True),
        Column("tenant_id", BigInteger),
        Column("parent_id", BigInteger),
        ForeignKeyConstraint(
            ["tenant_id", "parent_id"],
            ["orm_parents.tenant_id", "orm_parents.id"],
            name="orm_children_parent_fkey",
            match="FULL",
            onupdate="CASCADE",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
    )
    alembic_diffs = compare_metadata(MigrationContext.configure(connection), metadata)

assert rows == [{"id": 1, "email": "a@example.test"}]
assert "orm_accounts" in tables
assert [(column["name"], str(column["type"]), column["nullable"]) for column in columns] == [
    ("id", "BIGINT", False),
    ("email", "VARCHAR(128)", False),
    ("note", "TEXT", True),
]
assert primary_key["constrained_columns"] == ["id"]
assert any(item["column_names"] == ["email"] for item in unique)
assert foreign_keys == [
    {
        "name": "orm_children_parent_fkey",
        "constrained_columns": ["tenant_id", "parent_id"],
        "referred_schema": "public",
        "referred_table": "orm_parents",
        "referred_columns": ["tenant_id", "id"],
        "options": {
            "onupdate": "CASCADE",
            "ondelete": "RESTRICT",
            "initially": "DEFERRED",
            "deferrable": True,
            "match": "FULL",
        },
        "comment": None,
    }
]
assert information_tables == [
    {
        "table_schema": "public",
        "table_name": "orm_accounts",
        "table_type": "BASE TABLE",
    }
]
assert information_columns == [
    {
        "column_name": "id",
        "data_type": "bigint",
        "is_nullable": "NO",
        "column_default": None,
        "ordinal_position": 1,
        "character_maximum_length": None,
    },
    {
        "column_name": "email",
        "data_type": "character varying",
        "is_nullable": "NO",
        "column_default": None,
        "ordinal_position": 2,
        "character_maximum_length": 128,
    },
    {
        "column_name": "note",
        "data_type": "text",
        "is_nullable": "YES",
        "column_default": None,
        "ordinal_position": 3,
        "character_maximum_length": None,
    },
]
assert alembic_diffs == []

# Exercise executable Alembic operations through the real PostgreSQL dialect,
# rather than treating an empty autogenerate diff as migration acceptance.
with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.create_table(
        "alembic_items",
        Column("id", BigInteger, primary_key=True, autoincrement=False),
        Column("name", String(64), nullable=False),
    )
    operations.add_column("alembic_items", Column("note", Text, nullable=True))
    operations.create_index(
        "ix_alembic_items_name",
        "alembic_items",
        ["name"],
        unique=True,
    )

with engine.begin() as connection:
    connection.execute(
        text(
            "INSERT INTO alembic_items (id,name,note) "
            "VALUES (1,'migration','applied')"
        )
    )
    migrated = dict(
        connection.execute(
            text("SELECT id,name,note FROM alembic_items WHERE id=1")
        ).mappings().one()
    )
    migration_columns = [
        column["name"]
        for column in inspect(connection).get_columns(
            "alembic_items", schema="public"
        )
    ]

assert migrated == {"id": 1, "name": "migration", "note": "applied"}
assert migration_columns == ["id", "name", "note"]

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.drop_index("ix_alembic_items_name", table_name="alembic_items")
    operations.drop_column("alembic_items", "note")

with engine.connect() as connection:
    post_drop_columns = [
        column["name"]
        for column in inspect(connection).get_columns(
            "alembic_items", schema="public"
        )
    ]
    post_drop_row = dict(
        connection.execute(
            text("SELECT id,name FROM alembic_items WHERE id=1")
        ).mappings().one()
    )

assert post_drop_columns == ["id", "name"]
assert post_drop_row == {"id": 1, "name": "migration"}

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.alter_column(
        "alembic_items", "name", new_column_name="title"
    )

with engine.connect() as connection:
    renamed_columns = [
        column["name"]
        for column in inspect(connection).get_columns(
            "alembic_items", schema="public"
        )
    ]
    renamed_row = dict(
        connection.execute(
            text("SELECT id,title FROM alembic_items WHERE id=1")
        ).mappings().one()
    )

assert renamed_columns == ["id", "title"]
assert renamed_row == {"id": 1, "title": "migration"}

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.alter_column(
        "alembic_items",
        "title",
        existing_type=Text(),
        nullable=False,
    )
    operations.alter_column(
        "alembic_items",
        "title",
        existing_type=Text(),
        server_default=sqlalchemy.text("'fallback'"),
    )
    connection.execute(text("INSERT INTO alembic_items (id) VALUES (2)"))

with engine.connect() as connection:
    altered_title = next(
        column
        for column in inspect(connection).get_columns(
            "alembic_items", schema="public"
        )
        if column["name"] == "title"
    )
    defaulted_title = connection.execute(
        text("SELECT title FROM alembic_items WHERE id=2")
    ).scalar_one()

assert altered_title["nullable"] is False
assert defaulted_title == "fallback"

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.create_unique_constraint(
        "uq_alembic_items_title", "alembic_items", ["title"]
    )

with engine.connect() as connection:
    altered_unique = inspect(connection).get_unique_constraints(
        "alembic_items", schema="public"
    )

assert any(
    constraint["name"] == "uq_alembic_items_title"
    and constraint["column_names"] == ["title"]
    for constraint in altered_unique
)

with engine.begin() as connection:
    connection.execute(
        text(
            "ALTER TABLE alembic_items RENAME CONSTRAINT "
            "uq_alembic_items_title TO uq_alembic_items_title_renamed"
        )
    )

with engine.connect() as connection:
    renamed_unique = inspect(connection).get_unique_constraints(
        "alembic_items", schema="public"
    )

assert any(
    constraint["name"] == "uq_alembic_items_title_renamed"
    and constraint["column_names"] == ["title"]
    for constraint in renamed_unique
)

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.create_table(
        "alembic_item_refs",
        Column("id", BigInteger, primary_key=True, autoincrement=False),
        Column("title", String(64), nullable=False),
        ForeignKeyConstraint(
            ["title"],
            ["alembic_items.title"],
            name="fk_alembic_item_refs_title",
        ),
    )
    connection.execute(
        text(
            "ALTER TABLE alembic_items DROP CONSTRAINT "
            "uq_alembic_items_title_renamed CASCADE"
        )
    )
    connection.execute(
        text("INSERT INTO alembic_item_refs VALUES (1, 'orphan-after-cascade')")
    )

with engine.connect() as connection:
    cascaded_unique = inspect(connection).get_unique_constraints(
        "alembic_items", schema="public"
    )
    cascaded_foreign_keys = inspect(connection).get_foreign_keys(
        "alembic_item_refs", schema="public"
    )

assert not any(
    constraint["name"] == "uq_alembic_items_title_renamed"
    for constraint in cascaded_unique
)
assert cascaded_foreign_keys == []

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.drop_table("alembic_item_refs")
    operations.alter_column(
        "alembic_items",
        "title",
        existing_type=Text(),
        server_default=None,
    )
    operations.alter_column(
        "alembic_items",
        "title",
        existing_type=Text(),
        nullable=True,
    )
    connection.execute(text("DELETE FROM alembic_items WHERE id=2"))

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.create_table(
        "alembic_drop_parent",
        Column("id", BigInteger, primary_key=True, autoincrement=False),
    )
    operations.create_table(
        "alembic_drop_child",
        Column("id", BigInteger, primary_key=True, autoincrement=False),
        Column("parent_id", BigInteger, nullable=False),
        ForeignKeyConstraint(
            ["parent_id"],
            ["alembic_drop_parent.id"],
            name="fk_alembic_drop_child_parent",
        ),
    )

try:
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_drop_parent"))
except sqlalchemy.exc.DBAPIError as error:
    assert error.orig.sqlstate == "2BP01"
else:
    raise AssertionError("DROP TABLE RESTRICT must reject a dependent FK")

with engine.begin() as connection:
    connection.execute(text("DROP TABLE alembic_drop_parent CASCADE"))
    connection.execute(text("INSERT INTO alembic_drop_child VALUES (1, 999)"))

with engine.connect() as connection:
    dropped_table_foreign_keys = inspect(connection).get_foreign_keys(
        "alembic_drop_child", schema="public"
    )

assert dropped_table_foreign_keys == []

with engine.begin() as connection:
    Operations(MigrationContext.configure(connection)).drop_table(
        "alembic_drop_child"
    )

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.create_table(
        "alembic_column_parent",
        Column("id", BigInteger, primary_key=True, autoincrement=False),
        Column("code", String(64), nullable=False),
        Column("obsolete", Text, nullable=True),
        Column("keep", Text, nullable=True),
        UniqueConstraint("code", name="uq_alembic_column_parent_code"),
    )
    operations.create_table(
        "alembic_column_child",
        Column("id", BigInteger, primary_key=True, autoincrement=False),
        Column("parent_code", String(64), nullable=False),
        ForeignKeyConstraint(
            ["parent_code"],
            ["alembic_column_parent.code"],
            name="fk_alembic_column_child_parent",
        ),
    )

try:
    with engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE alembic_column_parent DROP COLUMN code")
        )
except sqlalchemy.exc.DBAPIError as error:
    assert error.orig.sqlstate == "2BP01"
else:
    raise AssertionError("DROP COLUMN RESTRICT must reject dependent objects")

with engine.begin() as connection:
    connection.execute(
        text(
            "ALTER TABLE alembic_column_parent "
            "DROP COLUMN code CASCADE, DROP COLUMN obsolete"
        )
    )
    connection.execute(
        text("INSERT INTO alembic_column_child VALUES (1, 'orphan')")
    )

with engine.connect() as connection:
    dropped_column_parent_columns = [
        column["name"]
        for column in inspect(connection).get_columns(
            "alembic_column_parent", schema="public"
        )
    ]
    dropped_column_foreign_keys = inspect(connection).get_foreign_keys(
        "alembic_column_child", schema="public"
    )

assert dropped_column_parent_columns == ["id", "keep"]
assert dropped_column_foreign_keys == []

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.drop_table("alembic_column_child")
    operations.drop_table("alembic_column_parent")

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.create_table(
        "alembic_keys",
        Column("id", BigInteger, nullable=True),
        Column("label", Text, nullable=True),
    )
    connection.execute(text("INSERT INTO alembic_keys VALUES (1, 'key')"))
    operations.create_primary_key("pk_alembic_keys", "alembic_keys", ["id"])

with engine.connect() as connection:
    altered_primary_key = inspect(connection).get_pk_constraint(
        "alembic_keys", schema="public"
    )

assert altered_primary_key["name"] == "pk_alembic_keys"
assert altered_primary_key["constrained_columns"] == ["id"]

with engine.begin() as connection:
    connection.execute(
        text(
            "ALTER TABLE alembic_keys RENAME CONSTRAINT "
            "pk_alembic_keys TO pk_alembic_keys_renamed"
        )
    )

with engine.connect() as connection:
    renamed_primary_key = inspect(connection).get_pk_constraint(
        "alembic_keys", schema="public"
    )

assert renamed_primary_key["name"] == "pk_alembic_keys_renamed"
assert renamed_primary_key["constrained_columns"] == ["id"]

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.drop_constraint(
        "pk_alembic_keys_renamed", "alembic_keys", type_="primary"
    )
    operations.drop_table("alembic_keys")

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.alter_column(
        "alembic_items", "title", new_column_name="name"
    )
    operations.alter_column(
        "alembic_items",
        "id",
        existing_type=sqlalchemy.Integer(),
        type_=BigInteger(),
    )
    operations.rename_table("alembic_items", "archived_items")

with engine.connect() as connection:
    renamed_table_names = inspect(connection).get_table_names(schema="public")
    renamed_table_types = {
        column["name"]: str(column["type"])
        for column in inspect(connection).get_columns(
            "archived_items", schema="public"
        )
    }
    renamed_table_row = dict(
        connection.execute(
            text("SELECT id,name FROM archived_items WHERE id=1")
        ).mappings().one()
    )

assert "alembic_items" not in renamed_table_names
assert "archived_items" in renamed_table_names
assert renamed_table_types["id"] == "BIGINT"
assert renamed_table_row == {"id": 1, "name": "migration"}

with engine.begin() as connection:
    operations = Operations(MigrationContext.configure(connection))
    operations.rename_table("archived_items", "alembic_items")
    operations.drop_table("alembic_items")

with engine.connect() as connection:
    assert "alembic_items" not in inspect(connection).get_table_names(schema="public")

print(
    "RESULT_JSON="
    + json.dumps(
        {
            "psycopg": "pass",
            "sqlalchemy": "pass",
            "versions": {
                "psycopg": psycopg.__version__,
                "sqlalchemy": sqlalchemy.__version__,
                "alembic": alembic.__version__,
            },
            "rows": rows,
            "tables": tables,
            "columns": [
                {
                    "name": column["name"],
                    "type": str(column["type"]),
                    "nullable": column["nullable"],
                }
                for column in columns
            ],
            "primary_key": primary_key,
            "unique": unique,
            "foreign_keys": foreign_keys,
            "information_schema": {
                "tables": information_tables,
                "columns": information_columns,
            },
            "alembic_diffs": alembic_diffs,
            "alembic_migration": {
                "upgrade": "pass",
                "downgrade": "pass",
                "columns": migration_columns,
                "post_drop_columns": post_drop_columns,
                "renamed_columns": renamed_columns,
                "renamed_table": "pass",
                "altered_type": renamed_table_types["id"],
                "altered_nullability": "pass",
                "altered_default": "pass",
                "altered_unique": "pass",
                "altered_primary_key": "pass",
                "renamed_unique_constraint": "pass",
                "renamed_primary_key_constraint": "pass",
                "drop_constraint_cascade": "pass",
                "drop_table_cascade": "pass",
                "drop_column_cascade": "pass",
            },
        },
        sort_keys=True,
    )
)

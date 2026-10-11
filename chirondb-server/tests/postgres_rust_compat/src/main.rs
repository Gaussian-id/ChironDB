use anyhow::{Context, Result};
use diesel::{Connection, PgConnection, QueryDsl, RunQueryDsl, SelectableHelper};
use sqlx::{Acquire, Row, postgres::PgPoolOptions};

diesel::table! {
    diesel_accounts (id) {
        id -> BigInt,
        email -> Text,
        note -> Nullable<Text>,
    }
}

#[derive(diesel::Insertable)]
#[diesel(table_name = diesel_accounts)]
struct NewDieselAccount<'a> {
    id: i64,
    email: &'a str,
    note: Option<&'a str>,
}

#[derive(diesel::Queryable, diesel::Selectable, Debug, PartialEq)]
#[diesel(table_name = diesel_accounts)]
struct DieselAccount {
    id: i64,
    email: String,
    note: Option<String>,
}
#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::var("CHIRONDB_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chiron@127.0.0.1:7403/gaussdb?sslmode=disable".into());
    // Older protected fixtures supply tables and explicit data grants. Strict
    // SQL scopes also support driver-created tables through creator authority.
    let preprovisioned = std::env::var_os("CHIRONDB_PROTECTED_PREPROVISIONED").is_some();

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .context("SQLx connect")?;
    if !preprovisioned {
        sqlx::query(
            "CREATE TABLE sqlx_accounts (id BIGINT PRIMARY KEY, email TEXT NOT NULL UNIQUE, note TEXT)",
        )
        .execute(&pool)
        .await
        .context("SQLx create")?;
    }
    let mut tx = pool.begin().await.context("SQLx begin")?;
    let inserted =
        sqlx::query("INSERT INTO sqlx_accounts (id,email,note) VALUES ($1,$2,$3) RETURNING id")
            .bind(1_i64)
            .bind("sqlx@example.test")
            .bind(Option::<String>::None)
            .fetch_one(&mut *tx)
            .await
            .context("SQLx prepared insert")?;
    let inserted_id: i64 = inserted.try_get("id")?;
    tx.commit().await.context("SQLx commit")?;
    let selected = sqlx::query("SELECT id,email,note FROM sqlx_accounts WHERE id=$1")
        .bind(1_i64)
        .fetch_one(&pool)
        .await
        .context("SQLx prepared select")?;
    let selected_id: i64 = selected.try_get("id")?;
    let email: String = selected.try_get("email")?;
    let note: Option<String> = selected.try_get("note")?;
    let mut rollback_tx = pool.begin().await?;
    sqlx::query("INSERT INTO sqlx_accounts VALUES ($1,$2,$3)")
        .bind(2_i64)
        .bind("rollback@example.test")
        .bind(Option::<String>::None)
        .execute(&mut *rollback_tx)
        .await?;
    rollback_tx.rollback().await?;
    let mut outer = pool
        .begin()
        .await
        .context("SQLx outer savepoint transaction")?;
    sqlx::query("INSERT INTO sqlx_accounts VALUES ($1,$2,$3)")
        .bind(3_i64)
        .bind("outer@example.test")
        .bind(Option::<String>::None)
        .execute(&mut *outer)
        .await?;
    let mut nested = outer.begin().await.context("SQLx savepoint")?;
    sqlx::query("INSERT INTO sqlx_accounts VALUES ($1,$2,$3)")
        .bind(4_i64)
        .bind("savepoint@example.test")
        .bind(Option::<String>::None)
        .execute(&mut *nested)
        .await?;
    nested.rollback().await.context("SQLx rollback savepoint")?;
    outer
        .commit()
        .await
        .context("SQLx commit after savepoint")?;
    let duplicate = sqlx::query("INSERT INTO sqlx_accounts VALUES ($1,$2,$3)")
        .bind(1_i64)
        .bind("duplicate@example.test")
        .bind(Option::<String>::None)
        .execute(&pool)
        .await
        .expect_err("SQLx duplicate must fail");
    assert_eq!(
        duplicate
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23505")
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlx_accounts")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        (inserted_id, selected_id, email.as_str(), note, count),
        (1, 1, "sqlx@example.test", None, 2)
    );
    pool.close().await;
    let reconnect_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .context("SQLx reconnect")?;
    let reconnect_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlx_accounts")
        .fetch_one(&reconnect_pool)
        .await?;
    assert_eq!(reconnect_count, 2);
    reconnect_pool.close().await;

    let mut connection = PgConnection::establish(&url).context("Diesel connect")?;
    if !preprovisioned {
        diesel::sql_query("CREATE TABLE diesel_accounts (id BIGINT PRIMARY KEY, email TEXT NOT NULL UNIQUE, note TEXT)")
            .execute(&mut connection).context("Diesel create")?;
    }
    connection
        .transaction::<_, diesel::result::Error, _>(|conn| {
            diesel::insert_into(diesel_accounts::table)
                .values(NewDieselAccount {
                    id: 1,
                    email: "diesel@example.test",
                    note: None,
                })
                .execute(conn)?;
            Ok(())
        })
        .context("Diesel transaction insert")?;
    connection
        .transaction::<_, diesel::result::Error, _>(|conn| {
            diesel::insert_into(diesel_accounts::table)
                .values(NewDieselAccount {
                    id: 2,
                    email: "diesel-outer@example.test",
                    note: Some("kept"),
                })
                .execute(conn)?;
            let nested = conn.transaction::<(), diesel::result::Error, _>(|conn| {
                diesel::insert_into(diesel_accounts::table)
                    .values(NewDieselAccount {
                        id: 3,
                        email: "diesel-savepoint@example.test",
                        note: None,
                    })
                    .execute(conn)?;
                Err(diesel::result::Error::RollbackTransaction)
            });
            assert!(matches!(
                nested,
                Err(diesel::result::Error::RollbackTransaction)
            ));
            Ok(())
        })
        .context("Diesel nested savepoint transaction")?;
    let diesel_rows = diesel_accounts::table
        .select(DieselAccount::as_select())
        .load::<DieselAccount>(&mut connection)
        .context("Diesel select rows")?;
    assert_eq!(
        diesel_rows,
        [
            DieselAccount {
                id: 1,
                email: "diesel@example.test".into(),
                note: None,
            },
            DieselAccount {
                id: 2,
                email: "diesel-outer@example.test".into(),
                note: Some("kept".into()),
            },
        ]
    );
    let duplicate = diesel::insert_into(diesel_accounts::table)
        .values(NewDieselAccount {
            id: 1,
            email: "diesel-duplicate@example.test",
            note: None,
        })
        .execute(&mut connection)
        .expect_err("Diesel duplicate must fail");
    assert!(matches!(
        duplicate,
        diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)
    ));
    let diesel_count = diesel_rows.len();
    println!(
        "RESULT_JSON={{\"sqlx\":\"pass\",\"sqlx_version\":\"0.8.6\",\"sqlx_count\":{count},\"diesel\":\"pass\",\"diesel_version\":\"2.3.13\",\"diesel_count\":{diesel_count},\"savepoint\":\"pass\",\"pool_reconnect\":\"pass\",\"unique_sqlstate\":\"23505\"}}"
    );
    Ok(())
}

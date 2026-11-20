//! Offline historical-format fixtures. Never run beside an open Db handle.
use chirondb_core::{
    Db, RelationalValue, SqlExecutionRequest, SqlResult,
    audit::AuditContext,
    relational::{RelationalBatch, RelationalMutation, StoredRow},
    security::{AuthenticatedIdentity, Classification},
    transaction_journal::{
        IdempotencyAdmission, TransactionAudit, TransactionJournal, TransactionTarget,
    },
    wal::WalEntry,
};
use serde_json::json;
use std::path::Path;

pub fn seed_tables(root: &Path, names: &[&str], title: bool, retained_row: bool) {
    let journal = TransactionJournal::open(root).unwrap();
    let mut mutations = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let mut columns = vec![json!({"name":"id", "data_type":{"kind":"big_int"}})];
        if title {
            columns.push(json!({"name":"title", "data_type":{"kind":"text"}, "nullable":true}));
        }
        // Deliberately omit incarnation, creator, row policy and row authority:
        // these fields did not exist in this persisted format.
        let definition = serde_json::from_value(json!({
            "table_id": index as u64 * 2 + 1, "tenant_id":"acme", "managed_by_ml":false,
            "name":name, "columns":columns, "primary_key":["id"],
            "primary_key_index_id": index as u64 * 2 + 2
        }))
        .unwrap();
        mutations.push(RelationalMutation::CreateTable { definition });
        if retained_row {
            assert!(title);
            mutations.push(RelationalMutation::Insert {
                table: (*name).into(),
                rows: vec![StoredRow {
                    row_id: 1,
                    security: None,
                    values: vec![
                        RelationalValue::Integer(1),
                        RelationalValue::Text("retained".into()),
                    ],
                }],
            });
        }
    }
    journal
        .commit(
            TransactionTarget::Relational,
            WalEntry::RelationalBatch {
                batch: RelationalBatch {
                    sequence: 1,
                    mutations,
                },
            },
            TransactionAudit::mutation("sql_batch", None, &AuditContext::embedded(), json!({})),
        )
        .unwrap();
}

#[allow(dead_code)] // Only the SQL-scope fixture needs a pre-authority receipt.
pub fn seed_insert_receipt(
    root: &Path,
    actor: &AuthenticatedIdentity,
    request: &SqlExecutionRequest,
) {
    let journal = TransactionJournal::open(root).unwrap();
    let context = AuditContext {
        principal_id: actor.principal().id.clone(),
        tenant_id: Some("acme".into()),
        transport: "historical-fixture".into(),
        request_id: None,
    };
    let IdempotencyAdmission::Execute(claim) = journal
        .begin_idempotent(
            request.idempotency_key.as_deref().unwrap(),
            &context,
            "sql_batch",
            &request.statements,
            || Ok(()),
        )
        .unwrap()
    else {
        panic!("fresh historical receipt")
    };
    claim
        .commit(
            TransactionTarget::Relational,
            WalEntry::RelationalBatch {
                batch: RelationalBatch {
                    sequence: 2,
                    mutations: vec![RelationalMutation::Insert {
                        table: "docs".into(),
                        rows: vec![StoredRow {
                            row_id: 1,
                            security: None,
                            values: vec![RelationalValue::Integer(1)],
                        }],
                    }],
                },
            },
            TransactionAudit::mutation("sql_batch", None, &context, json!({})),
            json!({"snapshot":2,"committed":true,"outcome":"committed","commit_sequence":2,
            "retryable":false,"results":[]}),
        )
        .unwrap();
}

pub fn register_rows(
    db: &Db,
    admin: &AuthenticatedIdentity,
    name: &str,
    owner: &AuthenticatedIdentity,
) {
    let table = db
        .relational_tables()
        .into_iter()
        .find(|table| table.name == name)
        .unwrap();
    let view = db
        .relational_security_authorized(admin, name, 0, 128)
        .unwrap();
    let SqlResult::Rows { rows, .. } = &view.results[0] else {
        panic!()
    };
    let RelationalValue::Json(metadata) = &rows[0][0] else {
        panic!()
    };
    let incarnation = table.security_incarnation.unwrap();
    // Explicit Search lets the schema administrator validate keys during DDL;
    // it does not grant row Read. Ownership still belongs to the data user.
    let classification = Classification::Internal;
    let properties = table
        .columns
        .iter()
        .map(|column| {
            (
                format!("/{}", column.name),
                json!({"classification":classification,"actions":["read","query","write"]}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let records = metadata["rows"].as_array().unwrap().iter().map(|row| json!({
        "key":{"tenant":"acme","collection":incarnation,"id":row["row_id"].to_string()},
        "storage_id":uuid::Uuid::new_v4(), "revision":1,
        "labels":{"owner":owner.principal().id,"department":admin.principal().attributes.department,
            "classification":classification, "quarantined":false}, "properties":properties,
        "representations":{}, "grants":[], "parent":null, "retired":false
    })).collect::<Vec<_>>();
    let delta = serde_json::from_value(json!({
        "table":name,"incarnation":incarnation,"expected_revision":0,
        "policy":{"revision":1,"default_template":"owner","policy":{
            "owner_actions":["read","create","update","delete","labels_manage","grants_manage"],
            "department_actions":["search"],"templates":{"owner":{
                "department":admin.principal().attributes.department,"classification":classification,
                "properties":properties,"representations":{}
            }}
        }},"records":records
    })).unwrap();
    db.change_relational_security_authorized(admin, delta)
        .unwrap()
        .consume(|_| Ok(()))
        .unwrap();
}

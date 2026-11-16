use chirondb::chironql_exec::{ExecContext, Session, execute};
use chirondb::rbac::Role;
use chirondb::{
    CollectionConfig, Db, Point,
    db::temporal::{SensorValue, TemporalAccess, TemporalSample},
    tenant::TenantScope,
};
use chirondb_types::chironql::{ChironQlError, ChironQlResponse};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn query(db: &Db, tenant: &TenantScope, s: &str) -> Result<ChironQlResponse, ChironQlError> {
    execute(
        &mut ExecContext {
            db,
            session: &mut Session::default(),
            role: Role::Admin,
            allowed_collections: None,
            want_trace: false,
            confirm: true,
            parameters: vec![],
            idempotency_key: None,
            retry_id: None,
            tenant: tenant.clone(),
        },
        s,
    )
}
fn config() -> CollectionConfig {
    serde_json::from_value(
        json!({"name":"armada","vector_dim":2,"metric":"l2","shards":1,"replicas":1}),
    )
    .unwrap()
}
const APPEND: &str = "APPEND INTO armada [{asset:'truk-7', property:'suhu', time_ns:'1700000000000000000', value:24.5},{asset:'truk-7', property:'suhu',time_ns:'1700000000000000001',value:25.0}];";
const HISTORY: &str = "HISTORY armada ASSET 'truk-7' PROPERTY 'suhu' FROM '1700000000000000000' TO '1700000000000000002' LIMIT 100;";
const LATEST: &str = "LATEST armada ASSET 'truk-7' PROPERTY 'suhu';";
fn expect_history(db: &Db, t: &TenantScope) {
    let rows = query(db, t, HISTORY).unwrap().rows;
    assert_eq!(
        rows.iter()
            .map(|p| (&p["time_ns"], &p["value"]))
            .collect::<Vec<_>>(),
        vec![
            (&json!("1700000000000000000"), &json!(24.5)),
            (&json!("1700000000000000001"), &json!(25.0))
        ]
    );
    assert_eq!(query(db, t, LATEST).unwrap().rows, [rows[1].clone()]);
}
#[test]
fn temporal_in_multimodel_transaction_rejects_before_any_write() {
    let dir = tempfile::tempdir().unwrap();
    let tenant = TenantScope::tenant("writer", "fleet");
    let db = Db::open(dir.path()).unwrap();
    db.create_collection(config()).unwrap();
    query(
        &db,
        &tenant,
        "SQL CREATE TABLE temporal_receipts (id BIGINT PRIMARY KEY);",
    )
    .unwrap();
    let block =
        format!("TRANSACTION {{ SQL INSERT INTO temporal_receipts VALUES (1); {APPEND} }};");
    assert!(query(&db, &tenant, &block).is_err());
    assert!(
        query(&db, &tenant, "SQL SELECT id FROM temporal_receipts;")
            .unwrap()
            .rows
            .is_empty()
    );
    assert!(query(&db, &tenant, HISTORY).unwrap().rows.is_empty());
    drop(db);
    let db = Db::open(dir.path()).unwrap();
    assert!(
        query(&db, &tenant, "SQL SELECT id FROM temporal_receipts;")
            .unwrap()
            .rows
            .is_empty()
    );
    assert!(query(&db, &tenant, HISTORY).unwrap().rows.is_empty());
}
#[test]
fn journal_tail_seal_late_conflict_and_collection_incarnation() {
    let dir = tempfile::tempdir().unwrap();
    let t = TenantScope::tenant("caller", "A");
    {
        let db = Db::open(dir.path()).unwrap();
        db.create_collection(config()).unwrap();
        assert_eq!(query(&db, &t, APPEND).unwrap().stats.affected, Some(2));
        expect_history(&db, &t);
    }
    for i in 0..2 {
        let db = Db::open(dir.path()).unwrap();
        expect_history(&db, &t);
        if i == 0 {
            db.compact_collection("armada").unwrap();
            assert_eq!(query(&db, &t, APPEND).unwrap().stats.affected, Some(0));
            query(
                &db,
                &t,
                "APPEND INTO armada [{asset:'truk-7',property:'suhu',time_ns:'-1',value:1}];",
            )
            .unwrap();
            assert!(query(&db,&t,"APPEND INTO armada [{asset:'truk-7',property:'suhu',time_ns:'9',value:3},{asset:'truk-7',property:'suhu',time_ns:'-1',value:2}];").is_err());
            assert!(
                query(
                    &db,
                    &t,
                    "HISTORY armada ASSET 'truk-7' PROPERTY 'suhu' FROM '0' TO '10' LIMIT 1;"
                )
                .unwrap()
                .rows
                .is_empty()
            );
            let b = TenantScope::tenant("someone", "B");
            assert!(query(&db, &b, LATEST).unwrap().rows.is_empty());
            query(
                &db,
                &b,
                "APPEND INTO armada [{asset:'truk-7',property:'suhu',time_ns:'0',value:false}];",
            )
            .unwrap();
            assert_eq!(query(&db, &b, LATEST).unwrap().rows[0]["value"], false);
            db.compact_collection("armada").unwrap();
        }
    }
    let db = Db::open(dir.path()).unwrap();
    expect_history(&db, &t);
    db.delete_collection("armada").unwrap();
    db.create_collection(config()).unwrap();
    assert!(query(&db, &t, LATEST).unwrap().rows.is_empty());
}

#[test]
fn full_tsbs_census_through_db_and_language_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let t = TenantScope::tenant("fixture", "tsbs");
    let mut samples = Vec::new();
    let mut expected = BTreeMap::<(&str, &str), Vec<(i64, u64)>>::new();
    for row in include_str!("../../chirondb-temporal/verification/fixtures/tsbs-iot.tsv").lines() {
        let c: Vec<_> = row.split('\t').collect();
        let time = c[3].parse().unwrap();
        let bits = u64::from_str_radix(c[5], 16).unwrap();
        samples.push(TemporalSample::new(
            c[1],
            c[2],
            time,
            SensorValue::Float(f64::from_bits(bits)),
        ));
        expected.entry((c[1], c[2])).or_default().push((time, bits));
    }
    assert_eq!(samples.len(), 427);
    assert_eq!(expected.len(), 8);
    for ps in expected.values_mut() {
        ps.sort_unstable();
    }
    for round in 0..3 {
        let db = Db::open(dir.path()).unwrap();
        if round == 0 {
            db.create_collection(config()).unwrap();
            samples.reverse();
            assert_eq!(
                db.append_temporal_batch("armada", TemporalAccess::Scoped(&t), samples.clone())
                    .unwrap(),
                427
            );
        }
        for (&(asset, property), ps) in &expected {
            let sql = format!(
                "HISTORY armada ASSET '{asset}' PROPERTY '{property}' FROM '0' TO '9223372036854775807' LIMIT 1000;"
            );
            let rows = query(&db, &t, &sql).unwrap().rows;
            assert_eq!(
                rows.iter()
                    .map(|v| (
                        v["time_ns"].as_str().unwrap().parse::<i64>().unwrap(),
                        v["value"].as_f64().unwrap().to_bits()
                    ))
                    .collect::<Vec<_>>(),
                *ps
            );
            let latest_sql = format!("LATEST armada ASSET '{asset}' PROPERTY '{property}';");
            assert_eq!(
                query(&db, &t, &latest_sql).unwrap().rows,
                std::slice::from_ref(rows.last().unwrap())
            );
            let latest = db
                .latest_temporal("armada", TemporalAccess::Scoped(&t), asset, property)
                .unwrap()
                .unwrap();
            assert_eq!(
                (latest.time, latest.value),
                (
                    ps.last().unwrap().0,
                    SensorValue::Float(f64::from_bits(ps.last().unwrap().1))
                )
            );
            let points = db
                .scan_temporal(
                    "armada",
                    TemporalAccess::Scoped(&t),
                    asset,
                    property,
                    0..i64::MAX,
                    1000,
                )
                .unwrap();
            assert_eq!(
                points
                    .iter()
                    .map(|p| match p.value {
                        SensorValue::Float(f) => (p.time, f.to_bits()),
                        _ => panic!(),
                    })
                    .collect::<Vec<_>>(),
                *ps
            );
        }
        if round == 1 {
            db.compact_collection("armada").unwrap();
        }
    }
}

#[test]
fn temporal_pipeline_sql_only_and_vector_selected_assets() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    db.create_collection(config()).unwrap();
    let t = TenantScope::tenant("operator", "fleet");
    for s in [
        APPEND,
        "SQL CREATE TABLE trucks (id TEXT PRIMARY KEY, ref RECORD_REF('armada') NOT NULL);",
        "SQL INSERT INTO trucks VALUES ('a',RECORD_REF('armada','truk-7')),('b',RECORD_REF('armada','missing'));",
    ] {
        query(&db, &t, s).unwrap();
    }
    let rel = "RELATIONAL r { SQL SELECT id,ref FROM trucks LIMIT 2 }";
    for (body, count) in [
        ("LATEST armada ASSET r.ref PROPERTY 'suhu'", 1),
        (
            "HISTORY armada ASSET r.ref PROPERTY 'suhu' FROM '0' TO '1700000000000000002' LIMIT 2",
            2,
        ),
    ] {
        for (kind, extra) in [("INNER", 0), ("LEFT", 1)] {
            let sql = format!(
                "PIPELINE\n{rel}\nTEMPORAL t {{ {body} }}\n{kind} JOIN t ON t.asset_ref = r.ref\nRETURN r.id,t.time_ns,t.value\nORDER BY r.id ASC\nLIMIT 8;"
            );
            let rows = query(&db, &t, &sql).unwrap().rows;
            assert_eq!(rows.len(), count + extra);
            assert_eq!(rows[0]["id"], "a");
            assert_eq!(rows[count - 1]["value"], 25.0);
            if extra > 0 {
                assert_eq!(rows[count]["value"], Value::Null);
            }
            assert!(
                !query(&db, &t, &format!("EXPLAIN {sql}"))
                    .unwrap()
                    .rows
                    .is_empty()
            );
        }
    }
    db.upsert(
        "armada",
        vec![Point {
            id: "truk-7".into(),
            vector: vec![1., 0.],
            payload: json!({}),
            vectors: Default::default(),
            sparse_vector: None,
        }],
    )
    .unwrap();
    let sql = format!(
        "PIPELINE\nVECTOR v {{ SEARCH armada NEAR [1,0] LIMIT 1 }}\n{rel}\nTEMPORAL t {{ LATEST armada ASSET v.record_ref PROPERTY 'suhu' }}\nINNER JOIN r ON r.ref = v.record_ref\nINNER JOIN t ON t.asset_ref = v.record_ref\nRETURN r.id,t.value\nLIMIT 1;"
    );
    assert_eq!(
        query(&db, &t, &sql).unwrap().rows,
        [json!({"id":"a","value":25.0})]
    );
    let history=sql.replace("LATEST armada ASSET v.record_ref PROPERTY 'suhu'", "HISTORY armada ASSET v.record_ref PROPERTY 'suhu' FROM '0' TO '1700000000000000002' LIMIT 2").replace("RETURN r.id,t.value","RETURN r.id,t.time_ns,t.value").replace("LIMIT 1;","LIMIT 2;");
    assert_eq!(
        query(&db, &t, &history).unwrap().rows,
        [
            json!({"id":"a","time_ns":"1700000000000000000","value":24.5}),
            json!({"id":"a","time_ns":"1700000000000000001","value":25.0})
        ]
    );
    assert!(
        query(
            &db,
            &t,
            &sql.replace("v.record_ref PROPERTY", "r.id PROPERTY")
        )
        .is_err()
    );
}

fn documented_query(name: &str) -> &'static str {
    let docs = include_str!("../../docs/CHIRONQL.md");
    docs.split_once(&format!("<!-- {name} -->\n```sql\n"))
        .unwrap()
        .1
        .split_once("\n```")
        .unwrap()
        .0
}
#[test]
fn documented_time_series_statements_and_pipeline_limits() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(tmp.path()).unwrap();
    db.create_collection(config()).unwrap();
    let tenant = TenantScope::tenant("driver", "fleet");
    let run = |s: &str| query(&db, &tenant, s);
    let stmt = |s| documented_query(&format!("chironql-example: temporal-{s}"));
    run(stmt("Append")).unwrap();
    assert_eq!(run(stmt("History")).unwrap().rows.len(), 2);
    assert_eq!(run(stmt("Latest")).unwrap().rows[0]["value"], 25.);
    assert!(run(stmt("RejectNumericTime")).is_err());
    for sql in documented_query("temporal-pipeline").split_inclusive(';') {
        run(sql.trim()).unwrap();
    }
    let pipe = stmt("Pipeline");
    let mut session = Session::default();
    let mut restricted = ExecContext {
        db: &db,
        session: &mut session,
        role: Role::ReadWrite,
        allowed_collections: Some(std::collections::HashSet::from(["armada".into()])),
        want_trace: false,
        confirm: true,
        parameters: vec![],
        idempotency_key: None,
        retry_id: None,
        tenant: tenant.clone(),
    };
    assert_eq!(
        execute(&mut restricted, pipe).unwrap_err().code,
        "chironql.collection_forbidden"
    );
    restricted.allowed_collections = Some(std::collections::HashSet::from(["trucks".into()]));
    assert_eq!(
        execute(&mut restricted, pipe).unwrap_err().code,
        "chironql.collection_forbidden"
    );
    let rows = run(pipe).unwrap().rows;
    assert_eq!(
        rows,
        [
            json!({"id":"truk-7","time_ns":"1700000000000000000","value":24.5}),
            json!({"id":"truk-7","time_ns":"1700000000000000001","value":25.0}),
            json!({"id":"truk-8","time_ns":null,"value":null})
        ]
    );
    assert_eq!(
        run(&pipe.replace("LIMIT 2 }\nLEFT", "LIMIT 4096 }\nLEFT"))
            .unwrap_err()
            .code,
        "chironql.resource_exhausted"
    );
    assert!(run(&pipe.replace("LIMIT 2 }\nLEFT", "LIMIT 4097 }\nLEFT")).is_err());
    let boundary=run("HISTORY armada ASSET 'truk-7' PROPERTY 'suhu' FROM '1700000000000000000' TO '1700000000000000001' LIMIT 1;").unwrap();
    assert_eq!(boundary.rows.len(), 1);
    assert_eq!(boundary.rows[0]["value"], 24.5);
    assert!(
        run("HISTORY armada ASSET 'truk-7' PROPERTY 'suhu' FROM '5' TO '5' LIMIT 1;")
            .unwrap()
            .rows
            .is_empty()
    );
    let bad = vec![TemporalSample::new(
        "truk-7",
        "suhu",
        3,
        SensorValue::Float(f64::NAN),
    )];
    assert!(
        db.append_temporal_batch("armada", TemporalAccess::Scoped(&tenant), bad)
            .is_err()
    );
}

#[test]
fn full_snapshot_preserves_runs_and_tail_and_pre_activation_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let live = tmp.path().join("live");
    let legacy = tmp.path().join("legacy");
    let snapshot = tmp.path().join("snapshot");
    let t = TenantScope::tenant("driver", "fleet");
    let db = Db::open(&live).unwrap();
    db.create_collection(config()).unwrap();
    db.snapshot(&legacy).unwrap();
    query(&db, &t, APPEND).unwrap();
    db.compact_collection("armada").unwrap();
    let append = |v| {
        format!("APPEND INTO armada [{{asset:'truk-7',property:'rpm',time_ns:'{v}',value:{v}}}];")
    };
    let latest = "LATEST armada ASSET 'truk-7' PROPERTY 'rpm';";
    query(&db, &t, &append(1)).unwrap();
    db.snapshot(&snapshot).unwrap();
    query(&db, &t, &append(2)).unwrap();
    assert!(
        db.restore_to_wal_lsns(
            &snapshot,
            &std::collections::HashMap::from([("armada".into(), 0)])
        )
        .is_err()
    );
    assert_eq!(query(&db, &t, latest).unwrap().rows[0]["value"], 2.);
    db.restore(&snapshot).unwrap();
    expect_history(&db, &t);
    assert_eq!(query(&db, &t, latest).unwrap().rows[0]["value"], 1.);
    query(&db, &t, &append(3)).unwrap();
    db.compact_collection("armada").unwrap();
    drop(db);
    let db = Db::open(&live).unwrap();
    expect_history(&db, &t);
    assert_eq!(query(&db, &t, latest).unwrap().rows[0]["value"], 3.);
    db.restore(&legacy).unwrap();
    assert!(query(&db, &t, LATEST).unwrap().rows.is_empty());
    query(&db, &t, APPEND).unwrap();
    expect_history(&db, &t);
}

#[test]
fn damaged_temporal_run_or_missing_checkpoint_refuses_open() {
    for damage in ["run", "checkpoint", "missing_run"] {
        let temp = tempfile::tempdir().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(config()).unwrap();
        query(&db, &TenantScope::tenant("driver", "fleet"), APPEND).unwrap();
        db.compact_collection("armada").unwrap();
        drop(db);
        let coll = chirondb::storage_layout::resolve(temp.path())
            .unwrap()
            .active_root
            .join("collections/armada");
        let run = std::fs::read_dir(coll.join("temporal"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        match damage {
            "run" => {
                let mut bytes = std::fs::read(&run).unwrap();
                bytes[0] ^= 16;
                std::fs::write(run, bytes).unwrap();
            }
            "checkpoint" => std::fs::remove_file(coll.join("checkpoint.gdx")).unwrap(),
            _ => std::fs::remove_file(run).unwrap(),
        }
        assert!(Db::open(temp.path()).is_err(), "{damage}");
    }
}

#[test]
fn concurrent_conflicting_batches_have_one_winner_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    db.create_collection(config()).unwrap();
    let barrier = std::sync::Barrier::new(3);
    let tenant = TenantScope::tenant("driver", "fleet");
    let samples = |start: i64| {
        (0..32)
            .map(|i| {
                TemporalSample::new("truck", "temp", i, SensorValue::Float((i + start) as f64))
            })
            .collect()
    };
    std::thread::scope(|scope| {
        let send = |start| {
            barrier.wait();
            db.append_temporal_batch("armada", TemporalAccess::Scoped(&tenant), samples(start))
        };
        let a = scope.spawn(move || send(10));
        let b = scope.spawn(move || send(20));
        barrier.wait();
        let rows = db
            .scan_temporal(
                "armada",
                TemporalAccess::Scoped(&tenant),
                "truck",
                "temp",
                0..32,
                32,
            )
            .unwrap();
        assert!(rows.is_empty() || rows.len() == 32);
        let outcomes = [a.join().unwrap(), b.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|r| matches!(r, Ok(32))).count(), 1);
        assert_eq!(outcomes.iter().filter(|r| r.is_err()).count(), 1);
    });
    drop(db);
    let db = Db::open(dir.path()).unwrap();
    let rows = db
        .scan_temporal(
            "armada",
            TemporalAccess::Scoped(&tenant),
            "truck",
            "temp",
            0..32,
            32,
        )
        .unwrap();
    assert_eq!(rows.len(), 32);
    let SensorValue::Float(start) = rows[0].value else {
        panic!()
    };
    assert!(start == 10. || start == 20.);
    assert!(
        rows.iter()
            .all(|p| p.value == SensorValue::Float(p.time as f64 + start))
    );
}

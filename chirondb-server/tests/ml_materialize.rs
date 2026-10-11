//! Optional real-worker end-to-end checks. Run with both ML worker paths set.

use std::{process::Command, time::Duration};

use chirondb::grpc::chiron_pb::{self, chiron_db_client::ChironDbClient as GrpcClient};
use chirondb::grpc::pb::{WireChironQlRequest, WireRequest, wire_request, wire_response};
use chirondb::tenant::TenantEnforcement;
use chirondb::{Db, api, grpc, wire};
use chirondb_client::{ChironDbClient, MlModel, MlTask};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

async fn query(client: &reqwest::Client, base: &str, sql: &str) -> Value {
    let response = client
        .post(format!("{base}/v1/chironql"))
        .json(&json!({"query": sql}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{sql}: {status} {body}");
    body
}

async fn wait_job(client: &reqwest::Client, base: &str, job_id: &str) -> Value {
    for _ in 0..3100 {
        let response = client
            .get(format!("{base}/v1/ml/jobs/{job_id}"))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        let response: Value = serde_json::from_str(&body)
            .unwrap_or_else(|_| panic!("job endpoint returned {status}: {body}"));
        if response["status"] == "succeeded" {
            return response;
        }
        assert_ne!(response["status"], "failed", "{response}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("ML job {job_id} did not complete");
}

async fn wait_failed_job(client: &reqwest::Client, base: &str, job_id: &str) -> Value {
    for _ in 0..300 {
        let response: Value = client
            .get(format!("{base}/v1/ml/jobs/{job_id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if response["status"] == "failed" {
            return response;
        }
        assert_ne!(response["status"], "succeeded", "{response}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("ML job {job_id} did not fail");
}

async fn python_sdk_read(base: &str, view: &str, job_id: &str) -> Value {
    let executable = std::env::var("CHIRONDB_ML_SDK_PYTHON").unwrap_or_else(|_| "python3".into());
    let path = format!("{}/../clients/python", env!("CARGO_MANIFEST_DIR"));
    let args = [base.to_string(), view.to_string(), job_id.to_string()];
    let output = tokio::task::spawn_blocking(move || {
        Command::new(executable)
            .env("PYTHONPATH", path)
            .arg("-c")
            .arg("import json,sys; from chirondb_client import ChironDbClient; c=ChironDbClient(sys.argv[1]); print(json.dumps({'job':c.get_ml_job(sys.argv[3]),'view':c.get_ml_view(sys.argv[2])}))")
            .args(args)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "Python SDK: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

async fn python_sdk_materialize(base: &str) -> Value {
    let executable = std::env::var("CHIRONDB_ML_SDK_PYTHON").unwrap_or_else(|_| "python3".into());
    let path = format!("{}/../clients/python", env!("CARGO_MANIFEST_DIR"));
    let base = base.to_string();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(executable)
            .env("PYTHONPATH", path)
            .arg("-c")
            .arg("import json,sys; from chirondb_client import ChironDbClient; c=ChironDbClient(sys.argv[1]); print(json.dumps(c.materialize_ml('view_tree_reg','source_tree_reg','target',['region','price'],'regression','decision_tree')))")
            .arg(base)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "Python materialize_ml: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test]
async fn removed_foundation_models_are_rejected_before_scheduling() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });
    let http = reqwest::Client::new();
    for model in ["TABFM", "CAUSILO"] {
        let response = http
            .post(format!("{base}/v1/chironql"))
            .json(&json!({"query": format!("ML MATERIALIZE gated_view FROM source TARGET label FEATURES (feature) TASK CLASSIFICATION USING {model};")}))
            .send()
            .await
            .unwrap();
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "chironql.ml_model");
        assert!(body["error"].as_str().unwrap().contains("DECISION_TREE"));
    }
    server.abort();
}

#[tokio::test]
async fn tenant_enforcement_denies_unscoped_ml_routes() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });
    let http = reqwest::Client::new();
    for path in ["/v1/ml/jobs/00000000", "/ml/views/secret_view"] {
        let response = http.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    }
    let response = http
        .post(format!("{base}/v1/chironql"))
        .json(&json!({"query":"ML MATERIALIZE secret_view FROM source TARGET label FEATURES (feature) TASK REGRESSION USING DECISION_TREE;"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "chironql.ml_tenant_unsupported");
    server.abort();
}

#[tokio::test]
#[ignore = "requires optional Python ML worker with scikit-learn"]
async fn traditional_models_materialize_and_refresh_through_http_and_sdks() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });
    let http = reqwest::Client::new();
    let rust_sdk = ChironDbClient::new(&base);
    let mut published = Vec::new();

    for (suffix, task, model) in [
        ("tree_class", MlTask::Classification, MlModel::DecisionTree),
        ("tree_reg", MlTask::Regression, MlModel::DecisionTree),
        (
            "forest_class",
            MlTask::Classification,
            MlModel::RandomForest,
        ),
        ("forest_reg", MlTask::Regression, MlModel::RandomForest),
    ] {
        let table = format!("source_{suffix}");
        let view = format!("view_{suffix}");
        let classification = task == MlTask::Classification;
        let target_type = if classification {
            "TEXT"
        } else {
            "DOUBLE PRECISION"
        };
        query(
            &http,
            &base,
            &format!(
                "SQL CREATE TABLE {table} (id INTEGER PRIMARY KEY, region TEXT, price DOUBLE PRECISION, target {target_type})"
            ),
        )
        .await;
        let target_values = if classification {
            "'low', 'high', 'low', 'high', 'low', 'high'"
        } else {
            "2.0, 4.0, 6.0, 8.0, 10.0, 12.0"
        };
        let values = target_values.split(", ").collect::<Vec<_>>();
        let mut tuples = (0..6)
            .map(|index| {
                format!(
                    "({}, '{}', {}, {})",
                    index + 1,
                    if index % 2 == 0 { "north" } else { "south" },
                    index + 1,
                    values[index]
                )
            })
            .collect::<Vec<_>>();
        tuples.extend([
            "(7, 'north', 7.0, NULL)".into(),
            "(8, 'south', 8.0, NULL)".into(),
        ]);
        query(
            &http,
            &base,
            &format!("SQL INSERT INTO {table} VALUES {}", tuples.join(", ")),
        )
        .await;

        let response = rust_sdk
            .materialize_ml(&view, &table, "target", &["region", "price"], task, model)
            .await
            .unwrap();
        let job_id = response.rows[0]["job_id"].as_str().unwrap();
        let job = wait_job(&http, &base, job_id).await;
        assert_eq!(job["row_count"], 8);
        let first_source_version = job["source_version"].as_i64().unwrap();
        let from_sdk = rust_sdk.get_ml_job(job_id).await.unwrap();
        assert_eq!(from_sdk["status"], "succeeded");
        let page = rust_sdk.get_ml_view(&view, 100, None).await.unwrap();
        assert_eq!(page["version"], 1);
        assert_eq!(page["rows"].as_array().unwrap().len(), 8);
        assert!(!page["rows"][6]["prediction"].is_null());
        let first_prediction = page["rows"][6]["prediction"].clone();
        if suffix == "tree_class" {
            for sql in [
                "UPDATE view_tree_class SET prediction = 'corrupt' WHERE id = 1",
                "DROP TABLE view_tree_class",
                "DELETE FROM __chiron_ml_jobs",
            ] {
                let denied = http
                    .post(format!("{base}/v1/sql"))
                    .json(&json!({"statements":[{"sql":sql,"parameters":[]}]}))
                    .send()
                    .await
                    .unwrap();
                assert!(!denied.status().is_success(), "{sql} must be read-only");
            }
        }
        let sql_rows = query(
            &http,
            &base,
            &format!("SQL SELECT * FROM {view} ORDER BY id"),
        )
        .await;
        assert_eq!(sql_rows["rows"].as_array().unwrap().len(), 8);

        query(
            &http,
            &base,
            &format!("SQL INSERT INTO {table} VALUES (9, 'north', 9.0, NULL)"),
        )
        .await;
        query(
            &http,
            &base,
            &format!("SQL UPDATE {table} SET price = 20.0 WHERE id = 7"),
        )
        .await;
        query(
            &http,
            &base,
            &format!(
                "SQL UPDATE {table} SET target = {} WHERE id <= 6",
                if classification {
                    "'refreshed'"
                } else {
                    "100.0"
                }
            ),
        )
        .await;
        let same_query = rust_sdk
            .materialize_ml(&view, &table, "target", &["region", "price"], task, model)
            .await
            .unwrap();
        let refresh_id = same_query.rows[0]["job_id"].as_str().unwrap();
        let refreshed_job = wait_job(&http, &base, refresh_id).await;
        assert!(
            refreshed_job["source_version"].as_i64().unwrap() > first_source_version,
            "refresh must use a newer source snapshot"
        );
        let refreshed = rust_sdk.get_ml_view(&view, 100, None).await.unwrap();
        assert_eq!(refreshed["version"], 2);
        assert_eq!(refreshed["rows"].as_array().unwrap().len(), 9);
        assert_eq!(refreshed["source_version"], refreshed_job["source_version"]);
        assert_ne!(refreshed["rows"][6]["prediction"], first_prediction);
        let python = python_sdk_read(&base, &view, refresh_id).await;
        assert_eq!(python["job"]["status"], "succeeded");
        assert_eq!(python["view"]["version"], 2);
        assert_eq!(python["view"]["rows"].as_array().unwrap().len(), 9);
        let unversioned: Value = http
            .get(format!("{base}/ml/views/{view}?limit=2"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(unversioned["rows"].as_array().unwrap().len(), 2);
        assert!(unversioned["next"].as_str().is_some());
        published.push((view, refresh_id.to_string(), 2));
        println!(
            "{suffix}: job={job_id} refresh={refresh_id} version=2 rows=9 source_version={}→{} prediction={}→{}",
            first_source_version,
            refreshed_job["source_version"],
            first_prediction,
            refreshed["rows"][6]["prediction"]
        );
    }

    query(
        &http,
        &base,
        "SQL UPDATE source_tree_class SET region = NULL",
    )
    .await;
    let failed_refresh = rust_sdk
        .materialize_ml(
            "view_tree_class",
            "source_tree_class",
            "target",
            &["region", "price"],
            MlTask::Classification,
            MlModel::DecisionTree,
        )
        .await
        .unwrap();
    let failed_id = failed_refresh.rows[0]["job_id"].as_str().unwrap();
    let failure = wait_failed_job(&http, &base, failed_id).await;
    assert!(
        failure["error"]
            .as_str()
            .unwrap()
            .contains("no observed labeled values")
    );
    let intact = rust_sdk
        .get_ml_view("view_tree_class", 100, None)
        .await
        .unwrap();
    assert_eq!(intact["version"], 2);
    assert_eq!(intact["rows"].as_array().unwrap().len(), 9);
    query(
        &http,
        &base,
        "SQL UPDATE source_tree_class SET region = 'north'",
    )
    .await;
    let retried = rust_sdk
        .materialize_ml(
            "view_tree_class",
            "source_tree_class",
            "target",
            &["region", "price"],
            MlTask::Classification,
            MlModel::DecisionTree,
        )
        .await
        .unwrap();
    let retry_id = retried.rows[0]["job_id"].as_str().unwrap();
    wait_job(&http, &base, retry_id).await;
    let after_retry = rust_sdk
        .get_ml_view("view_tree_class", 100, None)
        .await
        .unwrap();
    assert_eq!(after_retry["version"], 3);
    published[0].1 = retry_id.to_string();
    published[0].2 = 3;
    println!("failure/retry view_tree_class: failed={failed_id} version=3");
    let python_submit = python_sdk_materialize(&base).await;
    let python_job_id = python_submit["rows"][0]["job_id"].as_str().unwrap();
    wait_job(&http, &base, python_job_id).await;
    let python_refreshed = rust_sdk
        .get_ml_view("view_tree_reg", 100, None)
        .await
        .unwrap();
    assert_eq!(python_refreshed["version"], 3);
    published[1].1 = python_job_id.to_string();
    published[1].2 = 3;
    println!("Python SDK materialize_ml view_tree_reg: version=3");
    server.abort();
    let _ = server.await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let reopened = Db::open(data.path()).expect("reopen ML data directory");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reopened_base = format!("http://{}", listener.local_addr().unwrap());
    let reopened_server = tokio::spawn(async move {
        api::serve_listener(reopened, listener).await.unwrap();
    });
    let reopened_sdk = ChironDbClient::new(&reopened_base);
    for (view, job_id, expected_version) in published {
        let job = reopened_sdk.get_ml_job(&job_id).await.unwrap();
        assert_eq!(job["status"], "succeeded");
        let persisted: Value = http
            .get(format!("{reopened_base}/v1/ml/views/{view}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(persisted["version"], expected_version);
        assert_eq!(persisted["rows"].as_array().unwrap().len(), 9);
        let denied = http
            .post(format!("{reopened_base}/v1/sql"))
            .json(&json!({"statements":[{"sql":format!("DELETE FROM {view}"),"parameters":[]}]}))
            .send()
            .await
            .unwrap();
        assert!(
            !denied.status().is_success(),
            "view protection must survive restart"
        );
        println!("reopen {view}: version={expected_version} rows=9");
    }
    let conflict = reopened_sdk
        .materialize_ml(
            "view_forest_reg",
            "source_forest_reg",
            "target",
            &["region", "price"],
            MlTask::Regression,
            MlModel::DecisionTree,
        )
        .await;
    assert!(
        conflict.is_err(),
        "definition changes need an explicit drop"
    );
    let dropped = reopened_sdk.drop_ml_view("view_forest_reg").await.unwrap();
    assert_eq!(dropped["dropped"], true);
    let redefined = reopened_sdk
        .materialize_ml(
            "view_forest_reg",
            "source_forest_reg",
            "target",
            &["region", "price"],
            MlTask::Regression,
            MlModel::DecisionTree,
        )
        .await
        .unwrap();
    let redefined_id = redefined.rows[0]["job_id"].as_str().unwrap();
    wait_job(&http, &reopened_base, redefined_id).await;
    let new_generation = reopened_sdk
        .get_ml_view("view_forest_reg", 100, None)
        .await
        .unwrap();
    assert_eq!(new_generation["version"], 1);
    println!("drop/redefine view_forest_reg: new version=1");
    reopened_server.abort();
}

#[tokio::test]
#[ignore = "requires delayed_worker.py as the optional ML worker script"]
async fn job_uses_submission_snapshot_and_serializes_refreshes() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });
    let http = reqwest::Client::new();
    let sdk = ChironDbClient::new(&base);
    query(
        &http,
        &base,
        "SQL CREATE TABLE snapshot_source (id INTEGER PRIMARY KEY, price DOUBLE PRECISION, target DOUBLE PRECISION)",
    )
    .await;
    query(
        &http,
        &base,
        "SQL INSERT INTO snapshot_source VALUES (1, 1.0, 2.0), (2, 2.0, 4.0), (3, 3.0, NULL)",
    )
    .await;
    let submitted = sdk
        .materialize_ml(
            "snapshot_view",
            "snapshot_source",
            "target",
            &["price"],
            MlTask::Regression,
            MlModel::DecisionTree,
        )
        .await
        .unwrap();
    let job_id = submitted.rows[0]["job_id"].as_str().unwrap();
    query(
        &http,
        &base,
        "SQL UPDATE snapshot_source SET price = 30.0 WHERE id = 3",
    )
    .await;
    let conflicting = http
        .post(format!("{base}/v1/chironql"))
        .json(&json!({"query":"ML MATERIALIZE snapshot_view FROM snapshot_source TARGET target FEATURES (price) TASK REGRESSION USING DECISION_TREE;"}))
        .send()
        .await
        .unwrap();
    assert!(!conflicting.status().is_success());
    let body: Value = conflicting.json().await.unwrap();
    assert_eq!(body["code"], "chironql.ml_refresh_running");
    wait_job(&http, &base, job_id).await;
    let first = sdk.get_ml_view("snapshot_view", 100, None).await.unwrap();
    assert_eq!(first["version"], 1);
    assert_eq!(first["rows"][2]["price"], 3.0);
    let refresh = sdk
        .materialize_ml(
            "snapshot_view",
            "snapshot_source",
            "target",
            &["price"],
            MlTask::Regression,
            MlModel::DecisionTree,
        )
        .await
        .unwrap();
    wait_job(&http, &base, refresh.rows[0]["job_id"].as_str().unwrap()).await;
    let second = sdk.get_ml_view("snapshot_view", 100, None).await.unwrap();
    assert_eq!(second["version"], 2);
    assert_eq!(second["rows"][2]["price"], 30.0);
    println!("snapshot: version 1 price=3, version 2 price=30; concurrent refresh rejected");
    server.abort();
}

#[tokio::test]
#[ignore = "requires optional Python ML worker with scikit-learn"]
async fn grpc_and_chironwire_share_ml_materialization() {
    run_transport_materialization(MlTask::Regression, MlModel::DecisionTree).await;
}

async fn run_transport_materialization(task: MlTask, model: MlModel) {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", http_listener.local_addr().unwrap());
    let http_db = db.clone();
    let http_server = tokio::spawn(async move {
        api::serve_listener(http_db, http_listener).await.unwrap();
    });
    let grpc_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_address = grpc_probe.local_addr().unwrap();
    drop(grpc_probe);
    let grpc_db = db.clone();
    let grpc_server = tokio::spawn(async move {
        grpc::serve(grpc_db, grpc_address).await.unwrap();
    });
    let wire_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wire_address = wire_listener.local_addr().unwrap();
    let wire_server = tokio::spawn(async move {
        wire::serve_listener(db, wire_listener).await.unwrap();
    });
    let http = reqwest::Client::new();
    let target_type = if task == MlTask::Classification {
        "TEXT"
    } else {
        "DOUBLE PRECISION"
    };
    query(&http, &base, &format!("SQL CREATE TABLE transport_source (id INTEGER PRIMARY KEY, price DOUBLE PRECISION, target {target_type})")).await;
    query(
        &http,
        &base,
        if task == MlTask::Classification {
            "SQL INSERT INTO transport_source VALUES (1, 1.0, 'low'), (2, 2.0, 'high'), (3, 3.0, NULL)"
        } else {
            "SQL INSERT INTO transport_source VALUES (1, 1.0, 2.0), (2, 2.0, 4.0), (3, 3.0, NULL)"
        },
    )
    .await;
    let task_keyword = if task == MlTask::Classification {
        "CLASSIFICATION"
    } else {
        "REGRESSION"
    };
    let model_keyword = match model {
        MlModel::DecisionTree => "DECISION_TREE",
        MlModel::RandomForest => "RANDOM_FOREST",
    };
    let statement = format!(
        "ML MATERIALIZE transport_view FROM transport_source TARGET target FEATURES (price) TASK {task_keyword} USING {model_keyword};"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut grpc_client = GrpcClient::connect(format!("http://{grpc_address}"))
        .await
        .unwrap();
    let grpc_result = grpc_client
        .execute_query(chiron_pb::ChironQlRequest {
            query: statement.clone(),
            collection: None,
            trace: false,
            confirm: false,
            parameters: Vec::new(),
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .unwrap()
        .into_inner();
    let grpc_row: Value = serde_json::from_str(&grpc_result.rows_json[0]).unwrap();
    let first_job = grpc_row["job_id"].as_str().unwrap();
    wait_job(&http, &base, first_job).await;
    let first: Value = http
        .get(format!("{base}/v1/ml/views/transport_view"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["version"], 1);

    query(
        &http,
        &base,
        "SQL UPDATE transport_source SET price = 30.0 WHERE id = 3",
    )
    .await;
    let wire_response = wire::send_request(
        &wire_address.to_string(),
        WireRequest {
            request_id: 1,
            api_key: String::new(),
            operation: Some(wire_request::Operation::Chironql(WireChironQlRequest {
                query: statement.clone(),
                collection: None,
                trace: false,
                confirm: false,
                deferred_session_id: None,
                parameters_json: None,
                idempotency_key: None,
                retry_id: None,
            })),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        wire_response.error_code, "",
        "{}",
        wire_response.error_message
    );
    let wire_response::Payload::Chironql(wire_result) = wire_response.payload.unwrap() else {
        panic!("expected ChironQL response");
    };
    let wire_row: Value = serde_json::from_str(&wire_result.rows_json[0]).unwrap();
    let refresh_job = wire_row["job_id"].as_str().unwrap();
    wait_job(&http, &base, refresh_job).await;
    let refreshed: Value = http
        .get(format!("{base}/v1/ml/views/transport_view"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(refreshed["version"], 2);
    assert_eq!(refreshed["rows"][2]["price"], 30.0);
    println!(
        "gRPC submit job={first_job}; ChironWire refresh job={refresh_job}; HTTP view version=2"
    );
    assert_eq!(refreshed["rows"].as_array().unwrap().len(), 3);
    if task == MlTask::Classification {
        assert!(
            refreshed["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| { ["low", "high"].contains(&row["prediction"].as_str().unwrap()) })
        );
    } else {
        assert!(
            refreshed["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| { row["prediction"].as_f64().unwrap().is_finite() })
        );
    }
    let sql_result = query(&http, &base, "SQL SELECT * FROM transport_view ORDER BY id").await;
    assert_eq!(sql_result["rows"].as_array().unwrap().len(), 3);
    let rust_sdk = ChironDbClient::new(&base);
    let third = rust_sdk
        .materialize_ml(
            "transport_view",
            "transport_source",
            "target",
            &["price"],
            task,
            model,
        )
        .await
        .unwrap();
    let third_id = third.rows[0]["job_id"].as_str().unwrap();
    let third_job = wait_job(&http, &base, third_id).await;
    assert_eq!(third_job["context_rows"], 2);
    assert_eq!(
        rust_sdk
            .get_ml_view("transport_view", 100, None)
            .await
            .unwrap()["version"],
        3
    );
    let python_result = python_sdk_read(&base, "transport_view", third_id).await;
    assert_eq!(python_result["view"]["version"], 3);
    println!(
        "{model_keyword} {task_keyword}: gRPC/ChironWire/HTTP/SQL/both SDKs; version=3; context_rows=2"
    );
    http_server.abort();
    grpc_server.abort();
    wire_server.abort();
}

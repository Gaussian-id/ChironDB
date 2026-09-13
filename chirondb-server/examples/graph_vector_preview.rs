//! Disposable local graph+vector preview.
//!
//! Run with:
//! `cargo run --locked -p chirondb --example graph_vector_preview`

use std::error::Error;
use std::io;

use chirondb::{Db, api};
use chirondb_client::{
    ChironDbClient, CollectionConfig, Fusion, GraphConstraint, GraphDirection, GraphRelationScope,
    GraphTraversalQueryRequest, GraphTraversalReturn, GraphTraversalRows, GraphTraverseRequest,
    HybridQuery, Point, RelateRequest, SearchQuery, SparseVector, TraversalBudget,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const COLLECTION: &str = "preview_products";
const EDGE_TYPE: &str = "related_to";

struct PreviewServer {
    base_url: String,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl PreviewServer {
    async fn start(db: Db) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (shutdown, wait_for_shutdown) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, api::router(db))
                .with_graceful_shutdown(async {
                    let _ = wait_for_shutdown.await;
                })
                .await
        });
        Ok(Self {
            base_url: format!("http://{address}"),
            shutdown,
            task,
        })
    }

    async fn stop(self) -> Result<(), Box<dyn Error>> {
        let _ = self.shutdown.send(());
        match self.task.await {
            Err(error) => Err(error.into()),
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
        }
    }
}

fn graph_constraint(anchor: &str) -> GraphConstraint {
    GraphConstraint {
        anchors: vec![anchor.to_string()],
        edge_types: vec![EDGE_TYPE.to_string()],
        direction: GraphDirection::Outgoing,
        node_filter: None,
        edge_filter: None,
        budget: TraversalBudget {
            max_depth: 1,
            ..TraversalBudget::default()
        },
        allow_degraded: false,
    }
}

fn traversal(anchor: &str) -> GraphTraversalQueryRequest {
    GraphTraversalQueryRequest {
        traversal: GraphTraverseRequest {
            anchors: vec![anchor.to_string()],
            edge_types: vec![EDGE_TYPE.to_string()],
            direction: GraphDirection::Outgoing,
            node_filter: None,
            edge_filter: None,
            budget: TraversalBudget {
                max_depth: 1,
                ..TraversalBudget::default()
            },
        },
        returns: GraphTraversalReturn::Edges,
        limit: Some(100),
        with_payload: true,
    }
}

fn relation(source: &str, target: &str, purpose: &str) -> RelateRequest {
    RelateRequest {
        source_point_id: source.to_string(),
        target_point_id: target.to_string(),
        edge_type: EDGE_TYPE.to_string(),
        properties: json!({"purpose": purpose, "weight": 0.8}),
        scope: GraphRelationScope::Local,
        idempotency_key: Some(format!("preview-{source}-{target}")),
    }
}

fn require(condition: bool, message: &str) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let data = TempDir::new()?;
    let server = PreviewServer::start(Db::open(data.path())?).await?;
    let client = ChironDbClient::new(&server.base_url);

    client
        .create_collection(CollectionConfig {
            name: COLLECTION.to_string(),
            vector_dim: 3,
            metric: "cosine".to_string(),
            ..Default::default()
        })
        .await?;
    let enabled = client.enable_graph(COLLECTION, true).await?;
    client
        .configure_edge_type(COLLECTION, EDGE_TYPE, Some("weight".to_string()), true)
        .await?;
    client
        .upsert(
            COLLECTION,
            vec![
                Point {
                    id: "phone".to_string(),
                    vector: vec![1.0, 0.0, 0.0],
                    sparse_vector: Some(SparseVector {
                        indices: vec![1],
                        values: vec![1.0],
                    }),
                    payload: json!({"kind": "product"}),
                    ..Default::default()
                },
                Point {
                    id: "case".to_string(),
                    vector: vec![0.9, 0.1, 0.0],
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    payload: json!({"kind": "accessory"}),
                    ..Default::default()
                },
                Point {
                    id: "book".to_string(),
                    vector: vec![0.0, 1.0, 0.0],
                    sparse_vector: Some(SparseVector {
                        indices: vec![9],
                        values: vec![1.0],
                    }),
                    payload: json!({"kind": "media"}),
                    ..Default::default()
                },
            ],
            true,
        )
        .await?;

    let first_edge = client
        .relate(
            COLLECTION,
            relation("phone", "case", "initial relation"),
            true,
        )
        .await?;
    let traversed = client.traverse(COLLECTION, traversal("phone")).await?;
    let GraphTraversalRows::Edges(edges) = traversed.result else {
        return Err(io::Error::other("preview traversal did not return edge rows").into());
    };
    require(
        edges.len() == 1 && edges[0].id == first_edge.edge_id,
        "initial edge did not round-trip through traversal",
    )?;

    let dense = client
        .search(
            COLLECTION,
            SearchQuery {
                vector: vec![0.9, 0.1, 0.0],
                k: 3,
                graph: Some(graph_constraint("phone")),
                ..Default::default()
            },
        )
        .await?;
    require(
        dense.hits.first().is_some_and(|hit| hit.id == "case") && dense.graph.is_some(),
        "dense constrained search lost its reachable point or graph trace",
    )?;

    let hybrid = client
        .hybrid_search(
            COLLECTION,
            HybridQuery {
                vector: Some(vec![0.9, 0.1, 0.0]),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                k: 3,
                graph: Some(graph_constraint("phone")),
                fusion: Fusion::Rrf,
                ..Default::default()
            },
        )
        .await?;
    require(
        hybrid.hits.first().is_some_and(|hit| hit.id == "case") && hybrid.graph.is_some(),
        "hybrid constrained search lost its reachable point or graph trace",
    )?;

    client
        .merge_edge_properties(
            COLLECTION,
            &first_edge.edge_id,
            json!({"verified_by": "d10-preview"}),
            true,
        )
        .await?;
    let updated = client.traverse(COLLECTION, traversal("phone")).await?;
    let GraphTraversalRows::Edges(updated_edges) = updated.result else {
        return Err(io::Error::other("updated traversal did not return edge rows").into());
    };
    require(
        updated_edges[0]
            .properties
            .as_ref()
            .is_some_and(|properties| properties["verified_by"] == "d10-preview"),
        "edge property merge was not visible",
    )?;

    let deleted = client
        .unrelate(COLLECTION, &first_edge.edge_id, true)
        .await?;
    require(deleted.deleted == 1, "UNRELATE did not delete one edge")?;
    let after_delete = client.traverse(COLLECTION, traversal("phone")).await?;
    let GraphTraversalRows::Edges(after_delete_edges) = after_delete.result else {
        return Err(io::Error::other("post-delete traversal did not return edge rows").into());
    };
    require(
        after_delete_edges.is_empty(),
        "deleted edge remained visible",
    )?;

    let durable_edge = client
        .relate(COLLECTION, relation("phone", "book", "reopen proof"), true)
        .await?;
    let durable_token = durable_edge.edge_id.clone();
    drop(client);
    server.stop().await?;

    let reopened_server = PreviewServer::start(Db::open(data.path())?).await?;
    let reopened = ChironDbClient::new(&reopened_server.base_url);
    let collections = reopened.list_collections().await?;
    require(
        collections.iter().any(|config| config.name == COLLECTION),
        "collection did not survive reopen",
    )?;
    let edge_types = reopened.list_edge_types(COLLECTION).await?;
    require(
        edge_types
            .iter()
            .any(|edge_type| edge_type.name == EDGE_TYPE),
        "edge type did not survive reopen",
    )?;
    let reopened_traversal = reopened.traverse(COLLECTION, traversal("phone")).await?;
    let GraphTraversalRows::Edges(reopened_edges) = reopened_traversal.result else {
        return Err(io::Error::other("reopened traversal did not return edge rows").into());
    };
    require(
        reopened_edges.len() == 1 && reopened_edges[0].id == durable_token,
        "opaque edge token/topology did not survive reopen",
    )?;
    let reopened_search = reopened
        .search(
            COLLECTION,
            SearchQuery {
                vector: vec![0.0, 1.0, 0.0],
                k: 3,
                graph: Some(graph_constraint("phone")),
                ..Default::default()
            },
        )
        .await?;
    require(
        reopened_search
            .hits
            .first()
            .is_some_and(|hit| hit.id == "book"),
        "reopened constrained search did not return the durable target",
    )?;
    let trace = reopened_search
        .graph
        .as_ref()
        .ok_or_else(|| io::Error::other("reopened search omitted graph trace"))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "preview": "ok",
            "data": "disposable_tempdir",
            "network": "loopback_ephemeral_port",
            "surface_exercised": "typed_rust_sdk_over_http",
            "operations": [
                "create_collection",
                "enable_graph",
                "configure_edge_type",
                "upsert_points",
                "relate",
                "traverse_edges",
                "dense_graph_constraint",
                "hybrid_graph_constraint",
                "merge_edge_properties",
                "unrelate",
                "reopen",
            ],
            "graph_epoch": enabled.graph_epoch.map(|epoch| epoch.raw()),
            "reopen_edge_token_equal": reopened_edges[0].id == durable_token,
            "reopen_search_target": reopened_search.hits[0].id,
            "reopen_plan": trace.graph_plan.chosen,
            "acceptance_claimed": false,
            "c10_started": false,
        }))?
    );

    drop(reopened);
    reopened_server.stop().await?;
    Ok(())
}

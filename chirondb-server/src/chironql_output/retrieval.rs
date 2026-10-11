//! Admit retrieval JSON before growth, moving projected payloads and identifiers.
//! Protected callers convert inside AuthorizedOutput::publish to retain sources.
use super::query::{QueryMemory, add, full};
use crate::{Point, Result, SearchHit};
use chirondb_types::{chironql::*, graph::*};
use serde_json::Value;
use std::mem::size_of;

fn slots(count: usize) -> Result<u64> {
    (count as u64)
        .checked_mul(size_of::<Value>() as u64)
        .ok_or_else(full)
}
fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
fn array<T>(
    values: Vec<T>,
    memory: &QueryMemory,
    mut render: impl FnMut(T) -> Result<Value>,
) -> Result<Value> {
    let mut out = Vec::new();
    out.try_reserve_exact(values.len()).map_err(|_| full())?;
    for (i, value) in values.into_iter().enumerate() {
        if i % 1024 == 0 {
            memory.check()?;
        }
        out.push(render(value)?);
    }
    Ok(Value::Array(out))
}
fn start(
    memory: &mut QueryMemory,
    query_id: &str,
    columns: &[&str],
    count: usize,
    extra: u64,
) -> Result<()> {
    let mut bytes = add(add(4096, query_id.len() as u64)?, slots(count)?)?;
    for column in columns {
        bytes = add(bytes, add(1024, column.len() as u64)?)?;
    }
    memory.admit(add(bytes, extra)?)
}
fn response(query_id: &str, columns: &[&str], rows: Vec<Value>) -> ChironQlResponse {
    ChironQlResponse {
        kind: ChironQlKind::Rows,
        columns: columns.iter().map(|s| (*s).into()).collect(),
        column_types: Vec::new(),
        rows,
        stats: ChironQlStats::default(),
        next: None,
        query_id: query_id.into(),
        domains: Vec::new(),
        snapshot_id: None,
        transaction_id: None,
        committed: None,
        trace: None,
        credential: None,
    }
}
fn row_vec(count: usize) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(count).map_err(|_| full())?;
    Ok(rows)
}
pub(crate) fn hits(
    hits: Vec<SearchHit>,
    query_id: &str,
    memory: &mut QueryMemory,
) -> Result<ChironQlResponse> {
    let mut bytes = 0;
    for hit in &hits {
        memory.check()?;
        bytes = add(
            bytes,
            add(
                4096 + hit.id.capacity() as u64,
                memory.json_heap(&hit.payload)?,
            )?,
        )?;
    }
    start(
        memory,
        query_id,
        &["id", "score", "payload"],
        hits.len(),
        bytes,
    )?;
    let mut rows = row_vec(hits.len())?;
    for hit in hits {
        memory.check()?;
        rows.push(object([
            ("id", Value::String(hit.id)),
            ("score", Value::from(hit.score)),
            ("payload", hit.payload),
        ]));
    }
    Ok(response(query_id, &["id", "score", "payload"], rows))
}
pub(crate) fn points(
    points: Vec<Point>,
    next: Option<String>,
    full_point: bool,
    query_id: &str,
    memory: &mut QueryMemory,
) -> Result<ChironQlResponse> {
    let columns: &[&str] = if full_point {
        &["id", "vector", "vectors", "payload"]
    } else {
        &["id", "payload"]
    };
    let mut bytes = next.as_ref().map_or(0, |s| s.capacity()) as u64;
    for point in &points {
        memory.check()?;
        bytes = add(
            bytes,
            add(
                8192 + point.id.capacity() as u64,
                memory.json_heap(&point.payload)?,
            )?,
        )?;
        if full_point {
            bytes = add(bytes, slots(point.vector.len())?)?;
            for (name, vector) in &point.vectors {
                bytes = add(
                    bytes,
                    add(1024 + name.capacity() as u64, slots(vector.len())?)?,
                )?;
            }
            if let Some(sparse) = &point.sparse_vector {
                bytes = add(
                    bytes,
                    add(slots(sparse.indices.len())?, slots(sparse.values.len())?)?,
                )?;
            }
        }
    }
    start(memory, query_id, columns, points.len(), bytes)?;
    let mut rows = row_vec(points.len())?;
    for point in points {
        memory.check()?;
        if full_point {
            let mut vectors = serde_json::Map::new();
            for (name, vector) in point.vectors {
                vectors.insert(name, array(vector, memory, |v| Ok(Value::from(v)))?);
            }
            let sparse = match point.sparse_vector {
                Some(s) => object([
                    ("indices", array(s.indices, memory, |v| Ok(Value::from(v)))?),
                    ("values", array(s.values, memory, |v| Ok(Value::from(v)))?),
                ]),
                None => Value::Null,
            };
            rows.push(object([
                ("id", Value::String(point.id)),
                (
                    "vector",
                    array(point.vector, memory, |v| Ok(Value::from(v)))?,
                ),
                ("vectors", Value::Object(vectors)),
                ("sparse_vector", sparse),
                ("payload", point.payload),
            ]));
        } else {
            rows.push(object([
                ("id", Value::String(point.id)),
                ("payload", point.payload),
            ]));
        }
    }
    let mut result = response(query_id, columns, rows);
    result.next = next;
    Ok(result)
}
fn node_bytes(node: &GraphTraversalNodeRow, memory: &QueryMemory) -> Result<u64> {
    add(
        4096 + node.id.capacity() as u64,
        node.payload
            .as_ref()
            .map_or(Ok(0), |v| memory.json_heap(v))?,
    )
}
fn edge_bytes(edge: &GraphTraversalEdgeRow, memory: &QueryMemory) -> Result<u64> {
    add(
        8192 + edge.id.capacity() as u64
            + edge.source.capacity() as u64
            + edge.target.capacity() as u64
            + edge.edge_type.capacity() as u64,
        edge.properties
            .as_ref()
            .map_or(Ok(0), |v| memory.json_heap(v))?,
    )
}
fn node(node: GraphTraversalNodeRow) -> Value {
    let mut fields = match object([
        ("id", Value::String(node.id)),
        ("depth", Value::from(node.depth)),
    ]) {
        Value::Object(fields) => fields,
        _ => unreachable!(),
    };
    if let Some(payload) = node.payload {
        fields.insert("payload".into(), payload);
    }
    Value::Object(fields)
}
fn edge(edge: GraphTraversalEdgeRow) -> Value {
    let mut fields = match object([
        ("id", Value::String(edge.id.into_encoded())),
        ("source", Value::String(edge.source)),
        ("target", Value::String(edge.target)),
        ("type", Value::String(edge.edge_type)),
    ]) {
        Value::Object(fields) => fields,
        _ => unreachable!(),
    };
    if let Some(properties) = edge.properties {
        fields.insert("properties".into(), properties);
    }
    Value::Object(fields)
}
pub(crate) fn graph(
    graph: GraphTraversalQueryResult,
    with_payload: bool,
    query_id: &str,
    memory: &mut QueryMemory,
) -> Result<ChironQlResponse> {
    let (columns, count): (&[&str], usize) = match &graph.result {
        GraphTraversalRows::Nodes(rows) => (
            if with_payload {
                &["id", "depth", "payload"]
            } else {
                &["id", "depth"]
            },
            rows.len(),
        ),
        GraphTraversalRows::Edges(rows) => (
            if with_payload {
                &["id", "source", "target", "type", "properties"]
            } else {
                &["id", "source", "target", "type"]
            },
            rows.len(),
        ),
        GraphTraversalRows::Paths(rows) => (&["nodes", "edges"], rows.len()),
    };
    let mut bytes = (graph.warnings.len() as u64)
        .checked_mul(256)
        .ok_or_else(full)?;
    match &graph.result {
        GraphTraversalRows::Nodes(rows) => {
            for row in rows {
                memory.check()?;
                bytes = add(bytes, node_bytes(row, memory)?)?;
            }
        }
        GraphTraversalRows::Edges(rows) => {
            for row in rows {
                memory.check()?;
                bytes = add(bytes, edge_bytes(row, memory)?)?;
            }
        }
        GraphTraversalRows::Paths(rows) => {
            for row in rows {
                memory.check()?;
                bytes = add(
                    bytes,
                    add(4096, add(slots(row.nodes.len())?, slots(row.edges.len())?)?)?,
                )?;
                for n in &row.nodes {
                    memory.check()?;
                    bytes = add(bytes, node_bytes(n, memory)?)?;
                }
                for e in &row.edges {
                    memory.check()?;
                    bytes = add(bytes, edge_bytes(e, memory)?)?;
                }
            }
        }
    }
    start(memory, query_id, columns, count, bytes)?;
    let rows = match graph.result {
        GraphTraversalRows::Nodes(rows) => array(rows, memory, |v| Ok(node(v)))?,
        GraphTraversalRows::Edges(rows) => array(rows, memory, |v| Ok(edge(v)))?,
        GraphTraversalRows::Paths(rows) => array(rows, memory, |v| {
            Ok(object([
                ("nodes", array(v.nodes, memory, |v| Ok(node(v)))?),
                ("edges", array(v.edges, memory, |v| Ok(edge(v)))?),
            ]))
        })?,
    };
    let Value::Array(rows) = rows else {
        unreachable!()
    };
    let mut result = response(query_id, columns, rows);
    result.domains = vec![ExecutionDomain::Graph];
    result.stats.graph_epoch = Some(graph.graph_epoch.raw());
    result.stats.truncation = graph.truncation;
    result
        .stats
        .warnings
        .try_reserve_exact(graph.warnings.len())
        .map_err(|_| full())?;
    for warning in graph.warnings {
        result
            .stats
            .warnings
            .push(crate::chironql_exec::graph_warning_code(warning).into());
    }
    Ok(result)
}
pub(crate) fn pipeline_nodes(
    graph: GraphTraversalResult,
    limit: usize,
    query_id: &str,
    memory: &mut QueryMemory,
) -> Result<ChironQlResponse> {
    let count = graph.nodes.len().min(limit);
    let mut bytes = 0;
    for row in graph.nodes.iter().take(count) {
        memory.check()?;
        bytes = add(bytes, 4096 + row.point_id.capacity() as u64)?;
    }
    start(memory, query_id, &["id", "depth"], count, bytes)?;
    let mut rows = row_vec(count)?;
    for row in graph.nodes.into_iter().take(count) {
        memory.check()?;
        rows.push(object([
            ("id", Value::String(row.point_id)),
            ("depth", Value::from(row.depth)),
        ]));
    }
    Ok(response(query_id, &["id", "depth"], rows))
}
pub(crate) fn count(
    count: usize,
    query_id: &str,
    memory: &mut QueryMemory,
) -> Result<ChironQlResponse> {
    start(memory, query_id, &["count"], 1, 4096)?;
    Ok(response(
        query_id,
        &["count"],
        vec![object([("count", Value::from(count))])],
    ))
}
pub(crate) fn affected(
    count: usize,
    query_id: &str,
    memory: &mut QueryMemory,
) -> Result<ChironQlResponse> {
    start(memory, query_id, &[], 0, 0)?;
    let mut result = response(query_id, &[], vec![]);
    result.kind = ChironQlKind::Affected;
    result.stats.affected = Some(count as u64);
    Ok(result)
}

#[cfg(test)]
mod tests;

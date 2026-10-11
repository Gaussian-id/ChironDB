//! Receiving protobuf/string and codec reservations follow outgoing byte owners.
use crate::{
    grpc::pb,
    response_buffer::{ResponseBuffer, ResponseReservation},
};
use axum::body::Bytes;
use prost::Message;
use std::{mem::size_of, sync::Arc};
use tonic::Status;

const LIMIT: usize = 8 * 1024 * 1024;

pub(crate) struct MessageAdmission {
    _payloads: Vec<ResponseReservation>,
    _containers_and_codec: ResponseReservation,
}
pub(crate) type SharedAdmission = Arc<MessageAdmission>;

fn full() -> Status {
    Status::resource_exhausted("response memory limit exceeded")
}

fn admit_codec(
    length: usize,
    containers: u64,
    memory: &mut ResponseReservation,
) -> Result<(), Status> {
    if length > LIMIT {
        return Err(full());
    }
    // Pinned, uncompressed tonic/prost unary encoding uses one BytesMut with
    // an 8 KiB initial block and geometric growth. Capacity < 2*max(initial,
    // final length); old/new overlap < 3*capacity. Include the gRPC header,
    // initial empty scratch and outgoing Bytes owner/controller overhead.
    // Review this bound if the codec/dependency or compression changes.
    let codec = length
        .checked_add(5)
        .map(|n| n.max(8 * 1024))
        .and_then(|n| n.checked_mul(6))
        .and_then(|n| n.checked_add(8 * 1024 + 512))
        .ok_or_else(full)?;
    memory
        .prepare(containers.checked_add(codec as u64).ok_or_else(full)?)
        .map_err(crate::grpc_protected::engine_error)
}

fn point_rows(
    points: Vec<crate::Point>,
    extra: u64,
) -> Result<(Vec<pb::Point>, MessageAdmission, u64), Status> {
    let mut containers = (points.len() as u64)
        .checked_mul((size_of::<pb::Point>() + size_of::<ResponseReservation>()) as u64)
        .and_then(|n| n.checked_add(extra))
        .and_then(|n| n.checked_add(512))
        .ok_or_else(full)?;
    for point in &points {
        let mut bytes = point.id.capacity() as u64;
        bytes = bytes
            .checked_add(
                (point.vector.capacity() as u64)
                    .checked_mul(4)
                    .ok_or_else(full)?,
            )
            .ok_or_else(full)?;
        if let Some(sparse) = &point.sparse_vector {
            bytes = bytes
                .checked_add(
                    (sparse.indices.capacity() as u64)
                        .checked_mul(4)
                        .ok_or_else(full)?,
                )
                .and_then(|n| n.checked_add((sparse.values.capacity() as u64).checked_mul(4)?))
                .ok_or_else(full)?;
        }
        if !point.vectors.is_empty() {
            let buckets = point
                .vectors
                .len()
                .checked_next_power_of_two()
                .and_then(|n| n.checked_mul(2))
                .ok_or_else(full)?;
            // Conservative std HashMap bucket/control bound, including its
            // smallest nonempty allocation (capacity three for one entry).
            bytes = bytes
                .checked_add(
                    (buckets as u64)
                        .checked_mul((size_of::<(String, pb::DenseVector)>() + 64) as u64)
                        .and_then(|n| n.checked_add(128))
                        .ok_or_else(full)?,
                )
                .ok_or_else(full)?;
        }
        for (name, values) in &point.vectors {
            bytes = bytes
                .checked_add(name.capacity() as u64)
                .and_then(|n| n.checked_add((values.capacity() as u64).checked_mul(4)?))
                .ok_or_else(full)?;
        }
        containers = containers.checked_add(bytes).ok_or_else(full)?;
    }
    let memory =
        ResponseReservation::new(containers).map_err(crate::grpc_protected::engine_error)?;
    let mut payloads = Vec::new();
    let mut rows = Vec::new();
    payloads
        .try_reserve_exact(points.len())
        .map_err(|_| full())?;
    rows.try_reserve_exact(points.len()).map_err(|_| full())?;
    for point in points {
        let owner = ResponseBuffer::json(&point.payload, LIMIT)
            .map_err(crate::grpc_protected::engine_error)?;
        let mut vectors = std::collections::HashMap::new();
        vectors
            .try_reserve(point.vectors.len())
            .map_err(|_| full())?;
        for (name, values) in point.vectors {
            vectors.insert(name, pb::DenseVector { values });
        }
        let (bytes, reservation) = owner.into_parts();
        let payload_json =
            String::from_utf8(bytes).map_err(|_| Status::internal("response encoding failed"))?;
        rows.push(pb::Point {
            id: point.id,
            vector: point.vector,
            payload_json,
            sparse_vector: point.sparse_vector.map(crate::grpc::sparse_vector_to_proto),
            vectors,
        });
        payloads.push(reservation);
    }
    Ok((
        rows,
        MessageAdmission {
            _payloads: payloads,
            _containers_and_codec: memory,
        },
        containers,
    ))
}

pub(crate) fn points(
    points: Vec<crate::Point>,
) -> Result<(pb::GetPointsResponse, SharedAdmission), Status> {
    let (points, mut admission, containers) = point_rows(points, 0)?;
    let message = pb::GetPointsResponse { points };
    admit_codec(
        message.encoded_len(),
        containers,
        &mut admission._containers_and_codec,
    )?;
    Ok((message, Arc::new(admission)))
}

pub(crate) fn scroll(
    page: crate::ScrollResponse,
) -> Result<(pb::ScrollResponse, SharedAdmission), Status> {
    let next_offset = page.next_offset.unwrap_or_default();
    let (points, mut admission, containers) =
        point_rows(page.points, next_offset.capacity() as u64)?;
    let message = pb::ScrollResponse {
        points,
        next_offset,
    };
    admit_codec(
        message.encoded_len(),
        containers,
        &mut admission._containers_and_codec,
    )?;
    Ok((message, Arc::new(admission)))
}

pub(crate) fn hits(
    hits: Vec<crate::SearchHit>,
) -> Result<(pb::SearchResponse, SharedAdmission), Status> {
    let full = || Status::resource_exhausted("response memory limit exceeded");
    let containers = hits
        .len()
        .checked_mul(size_of::<pb::SearchHit>() + size_of::<ResponseReservation>())
        .and_then(|n| n.checked_add(512))
        .ok_or_else(full)?;
    let containers = hits
        .iter()
        .try_fold(containers as u64, |n, hit| {
            n.checked_add(hit.id.capacity() as u64)
        })
        .ok_or_else(full)?;
    let mut memory =
        ResponseReservation::new(containers).map_err(crate::grpc_protected::engine_error)?;
    let mut payloads = Vec::new();
    let mut rows = Vec::new();
    payloads.try_reserve_exact(hits.len()).map_err(|_| full())?;
    rows.try_reserve_exact(hits.len()).map_err(|_| full())?;
    for hit in hits {
        let owner = ResponseBuffer::json(&hit.payload, LIMIT)
            .map_err(crate::grpc_protected::engine_error)?;
        let (bytes, reservation) = owner.into_parts();
        let payload_json =
            String::from_utf8(bytes).map_err(|_| Status::internal("response encoding failed"))?;
        rows.push(pb::SearchHit {
            id: hit.id,
            score: hit.score,
            payload_json,
        });
        payloads.push(reservation);
    }
    let message = pb::SearchResponse {
        hits: rows,
        degraded: false,
        searched: 0,
        elapsed_ms: 0,
        graph_json: None,
    };
    admit_codec(message.encoded_len(), containers, &mut memory)?;
    Ok((
        message,
        Arc::new(MessageAdmission {
            _payloads: payloads,
            _containers_and_codec: memory,
        }),
    ))
}

/// Transfer SQL allocations into an admitted protobuf DTO. Source admission is
/// retained through the callback; the receiving lease then follows the frame.
pub(crate) fn sql(
    output: crate::SqlResponse,
) -> Result<
    (
        crate::grpc::chiron_pb::SqlExecutionResponse,
        SharedAdmission,
    ),
    Status,
> {
    use crate::grpc::chiron_pb as sql_pb;
    use crate::{RelationalValue as V, SqlResult as R};
    let mut containers = 1024_u64;
    let mut strings = 0_usize;
    let mut add = |bytes: u64| -> Result<(), Status> {
        containers = containers.checked_add(bytes).ok_or_else(full)?;
        Ok(())
    };
    add((output.results.len() as u64)
        .checked_mul(size_of::<sql_pb::SqlResult>() as u64)
        .ok_or_else(full)?)?;
    if let Some(id) = &output.transaction_id {
        add(id.capacity() as u64)?;
    }
    for result in &output.results {
        match result {
            R::Definition { .. } | R::Mutation { .. } => {}
            R::Explain { plan } => {
                add((plan.capacity() as u64)
                    .checked_mul(size_of::<String>() as u64)
                    .ok_or_else(full)?)?;
                for line in plan {
                    add(line.capacity() as u64)?;
                }
            }
            R::Rows {
                columns,
                column_types,
                rows,
            } => {
                add((columns.capacity() as u64)
                    .checked_mul(size_of::<String>() as u64)
                    .ok_or_else(full)?)?;
                for name in columns {
                    add(name.capacity() as u64)?;
                }
                add((column_types.len() as u64)
                    .checked_mul(size_of::<String>() as u64)
                    .ok_or_else(full)?)?;
                strings = strings.checked_add(column_types.len()).ok_or_else(full)?;
                add((rows.len() as u64)
                    .checked_mul(size_of::<sql_pb::SqlRow>() as u64)
                    .ok_or_else(full)?)?;
                for row in rows {
                    add((row.len() as u64)
                        .checked_mul(size_of::<sql_pb::SqlValue>() as u64)
                        .ok_or_else(full)?)?;
                    for value in row {
                        add(match value {
                            V::Text(s) | V::Decimal(s) | V::Date(s) | V::TimestampUtc(s) => {
                                s.capacity() as u64
                            }
                            V::Bytes(b) => b.capacity() as u64,
                            V::Vector(v) => {
                                (v.capacity() as u64).checked_mul(4).ok_or_else(full)?
                            }
                            V::RecordRef(r) => (r.namespace.capacity() as u64)
                                .checked_add(r.id.capacity() as u64)
                                .ok_or_else(full)?,
                            V::Uuid(_) => 128,
                            V::Json(_) => {
                                strings = strings.checked_add(1).ok_or_else(full)?;
                                0
                            }
                            _ => 0,
                        })?;
                    }
                }
            }
        }
    }
    add((strings as u64)
        .checked_mul(size_of::<ResponseReservation>() as u64)
        .ok_or_else(full)?)?;
    let mut memory =
        ResponseReservation::new(containers).map_err(crate::grpc_protected::engine_error)?;
    let (message, payloads) = output
        .consume(|response| {
            let exhausted = || {
                crate::GaussError::ResourceExhausted("SQL response memory limit exceeded".into())
            };
            let mut payloads = Vec::new();
            payloads
                .try_reserve_exact(strings)
                .map_err(|_| exhausted())?;
            let mut results = Vec::new();
            results
                .try_reserve_exact(response.results.len())
                .map_err(|_| exhausted())?;
            for result in response.results {
                use sql_pb::sql_result::Result as PR;
                let result = match result {
                    R::Definition { affected_objects } => {
                        PR::Definition(sql_pb::SqlDefinitionResult { affected_objects })
                    }
                    R::Mutation { affected_rows } => {
                        PR::Mutation(sql_pb::SqlMutationResult { affected_rows })
                    }
                    R::Explain { plan } => PR::Explain(sql_pb::SqlExplainResult { plan }),
                    R::Rows {
                        columns,
                        column_types,
                        rows,
                    } => {
                        let mut types = Vec::new();
                        types
                            .try_reserve_exact(column_types.len())
                            .map_err(|_| exhausted())?;
                        for ty in &column_types {
                            types.push(sql_json(ty, &mut payloads)?);
                        }
                        let mut converted_rows = Vec::new();
                        converted_rows
                            .try_reserve_exact(rows.len())
                            .map_err(|_| exhausted())?;
                        for row in rows {
                            let mut values = Vec::new();
                            values
                                .try_reserve_exact(row.len())
                                .map_err(|_| exhausted())?;
                            for value in row {
                                use sql_pb::sql_value::Value as PV;
                                let value = match value {
                                    V::Null => PV::Null(sql_pb::SqlNull {}),
                                    V::Boolean(v) => PV::Boolean(v),
                                    V::Integer(v) => PV::Integer(v),
                                    V::Float(v) => PV::Floating(v),
                                    V::Decimal(v) => PV::Decimal(v),
                                    V::Text(v) => PV::Text(v),
                                    V::TimestampUtc(v) => PV::TimestampUtc(v),
                                    V::Uuid(v) => PV::Uuid(v.to_string()),
                                    V::Vector(values) => PV::Vector(sql_pb::SqlVector { values }),
                                    V::RecordRef(v) => PV::RecordRef(sql_pb::SqlRecordRef {
                                        namespace: v.namespace,
                                        id: v.id,
                                    }),
                                    V::Bytes(v) => PV::BytesValue(v),
                                    V::Date(v) => PV::Date(v),
                                    V::Json(v) => PV::Jsonb(sql_json(&v, &mut payloads)?),
                                };
                                values.push(sql_pb::SqlValue { value: Some(value) });
                            }
                            converted_rows.push(sql_pb::SqlRow { values });
                        }
                        PR::Rows(sql_pb::SqlRowsResult {
                            columns,
                            column_types_json: types,
                            rows: converted_rows,
                        })
                    }
                };
                results.push(sql_pb::SqlResult {
                    result: Some(result),
                });
            }
            Ok((
                sql_pb::SqlExecutionResponse {
                    transaction_id: response.transaction_id,
                    snapshot: response.snapshot,
                    committed: response.committed,
                    outcome: match response.outcome {
                        crate::SqlOutcome::Rejected => "rejected",
                        crate::SqlOutcome::Committed => "committed",
                        crate::SqlOutcome::Unknown => "unknown",
                    }
                    .into(),
                    commit_sequence: response.commit_sequence,
                    retryable: response.retryable,
                    results,
                },
                payloads,
            ))
        })
        .map_err(crate::grpc_protected::engine_error)?;
    admit_codec(message.encoded_len(), containers, &mut memory)?;
    Ok((
        message,
        Arc::new(MessageAdmission {
            _payloads: payloads,
            _containers_and_codec: memory,
        }),
    ))
}

/// Receiving ChironQL strings and protobuf containers are admitted before
/// allocation. The shared lease remains on gRPC/ChironWire outgoing frames.
pub(crate) fn chironql(
    value: chirondb_types::chironql::ChironQlResponse,
) -> Result<(crate::grpc::chiron_pb::ChironQlResponse, SharedAdmission), Status> {
    use chirondb_types::chironql::{ChironQlKind, ExecutionDomain};
    let count = value
        .column_types
        .len()
        .checked_add(value.rows.len())
        .and_then(|n| n.checked_add(3))
        .ok_or_else(full)?;
    let mut containers = 1024_u64
        .checked_add(
            (count as u64)
                .checked_mul((size_of::<String>() + size_of::<ResponseReservation>()) as u64)
                .ok_or_else(full)?,
        )
        .ok_or_else(full)?;
    containers = containers
        .checked_add(
            (value.columns.capacity() as u64)
                .checked_mul(size_of::<String>() as u64)
                .ok_or_else(full)?,
        )
        .and_then(|n| {
            n.checked_add(
                (value.domains.len() as u64).checked_mul((size_of::<String>() + 16) as u64)?,
            )
        })
        .ok_or_else(full)?;
    for string in value
        .columns
        .iter()
        .chain(std::iter::once(&value.query_id))
        .chain(value.next.iter())
        .chain(value.snapshot_id.iter())
        .chain(value.transaction_id.iter())
    {
        containers = containers
            .checked_add(string.capacity() as u64)
            .ok_or_else(full)?;
    }
    let mut memory =
        ResponseReservation::new(containers).map_err(crate::grpc_protected::engine_error)?;
    let mut payloads = Vec::new();
    payloads.try_reserve_exact(count).map_err(|_| full())?;
    let mut column_types_json = Vec::new();
    column_types_json
        .try_reserve_exact(value.column_types.len())
        .map_err(|_| full())?;
    for data_type in &value.column_types {
        column_types_json
            .push(sql_json(data_type, &mut payloads).map_err(crate::grpc_protected::engine_error)?);
    }
    let mut rows_json = Vec::new();
    rows_json
        .try_reserve_exact(value.rows.len())
        .map_err(|_| full())?;
    for row in &value.rows {
        rows_json.push(sql_json(row, &mut payloads).map_err(crate::grpc_protected::engine_error)?);
    }
    let stats_json =
        sql_json(&value.stats, &mut payloads).map_err(crate::grpc_protected::engine_error)?;
    let trace_json = value
        .trace
        .as_ref()
        .map(|trace| sql_json(trace, &mut payloads))
        .transpose()
        .map_err(crate::grpc_protected::engine_error)?;
    let credential_json = value
        .credential
        .as_ref()
        .map(|credential| sql_json(credential, &mut payloads))
        .transpose()
        .map_err(crate::grpc_protected::engine_error)?;
    let mut domains = Vec::new();
    domains
        .try_reserve_exact(value.domains.len())
        .map_err(|_| full())?;
    for domain in value.domains {
        domains.push(
            match domain {
                ExecutionDomain::Relational => "relational",
                ExecutionDomain::Vector => "vector",
                ExecutionDomain::Graph => "graph",
                ExecutionDomain::Catalog => "catalog",
                ExecutionDomain::Security => "security",
            }
            .into(),
        );
    }
    let message = crate::grpc::chiron_pb::ChironQlResponse {
        kind: match value.kind {
            ChironQlKind::Rows => "rows",
            ChironQlKind::Affected => "affected",
            ChironQlKind::Empty => "empty",
        }
        .into(),
        columns: value.columns,
        column_types_json,
        rows_json,
        stats_json,
        next: value.next,
        query_id: value.query_id,
        domains,
        snapshot_id: value.snapshot_id,
        transaction_id: value.transaction_id,
        committed: value.committed,
        trace_json,
        credential_json,
    };
    admit_codec(message.encoded_len(), containers, &mut memory)?;
    Ok((
        message,
        Arc::new(MessageAdmission {
            _payloads: payloads,
            _containers_and_codec: memory,
        }),
    ))
}

fn sql_json(
    value: &impl serde::Serialize,
    payloads: &mut Vec<ResponseReservation>,
) -> crate::Result<String> {
    let owner = ResponseBuffer::json_native(value, LIMIT)?;
    let (bytes, reservation) = owner.into_parts();
    let string = String::from_utf8(bytes)
        .map_err(|_| crate::GaussError::InvalidRequest("SQL response encoding failed".into()))?;
    payloads.push(reservation);
    Ok(string)
}

/// Compact JSON DTO ownership for ChironWire, held through its outgoing frame.
pub(crate) fn wire_json(
    value: &impl serde::Serialize,
) -> Result<(String, SharedAdmission), Status> {
    let owner =
        ResponseBuffer::json_native(value, LIMIT).map_err(crate::grpc_protected::engine_error)?;
    let (bytes, reservation) = owner.into_parts();
    let mut memory = ResponseReservation::new(512 + size_of::<ResponseReservation>() as u64)
        .map_err(crate::grpc_protected::engine_error)?;
    admit_codec(bytes.len(), 512, &mut memory)?;
    let string =
        String::from_utf8(bytes).map_err(|_| Status::internal("SQL response encoding failed"))?;
    Ok((
        string,
        Arc::new(MessageAdmission {
            _payloads: vec![reservation],
            _containers_and_codec: memory,
        }),
    ))
}

struct FrameOwner {
    bytes: Bytes,
    _admission: SharedAdmission,
}
impl AsRef<[u8]> for FrameOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
pub(crate) fn retain_frame(bytes: Bytes, admission: SharedAdmission) -> Bytes {
    Bytes::from_owner(FrameOwner {
        bytes,
        _admission: admission,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chironql_fixture() -> chirondb_types::chironql::ChironQlResponse {
        use chirondb_types::chironql::*;
        let mut trace = QueryTrace::new("query-id");
        trace.push_ok("render", 1, Some(serde_json::json!({"zero":-0.0_f64})));
        ChironQlResponse {
            kind: ChironQlKind::Rows,
            columns: vec!["row".into()],
            column_types: vec![crate::RelationalType::RecordRef {
                namespace: "docs".into(),
            }],
            rows: vec![
                serde_json::json!({"min":i64::MIN,"max":u64::MAX,"float":1.2345678901234567e300_f64,"zero":-0.0_f64,"vector":[0.7181532_f32,-0.0_f32],"text":"\n日本語"}),
            ],
            stats: ChironQlStats::default(),
            next: Some("cursor".into()),
            query_id: "query-id".into(),
            domains: vec![
                ExecutionDomain::Relational,
                ExecutionDomain::Vector,
                ExecutionDomain::Graph,
                ExecutionDomain::Catalog,
                ExecutionDomain::Security,
            ],
            snapshot_id: Some("frontier:17".into()),
            transaction_id: Some("txn-id".into()),
            committed: Some(true),
            trace: Some(trace),
            credential: Some(ChironQlCredential {
                id: "fixture-credential".into(),
                secret: "fixture-only".into(),
            }),
        }
    }
    #[test]
    fn chironql_receiving_json_preserves_fields_numbers_and_last_frame_admission() {
        let source = chironql_fixture();
        let rows = source
            .rows
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>();
        let types = source
            .column_types
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>();
        let trace = serde_json::to_string(source.trace.as_ref().unwrap()).unwrap();
        let stats = serde_json::to_string(&source.stats).unwrap();
        let credential = serde_json::to_string(source.credential.as_ref().unwrap()).unwrap();
        let column_ptr = source.columns.as_ptr();
        let (message, admission) = chironql(source).unwrap();
        assert_eq!(message.columns.as_ptr(), column_ptr);
        assert_eq!(message.kind, "rows");
        assert_eq!(message.rows_json, rows);
        assert_eq!(message.column_types_json, types);
        assert_eq!(message.trace_json, Some(trace));
        assert_eq!(message.stats_json, stats);
        assert_eq!(message.credential_json, Some(credential));
        assert_eq!(message.next, Some("cursor".into()));
        assert_eq!(message.snapshot_id, Some("frontier:17".into()));
        assert_eq!(message.transaction_id, Some("txn-id".into()));
        assert_eq!(message.committed, Some(true));
        assert_eq!(
            message.domains,
            ["relational", "vector", "graph", "catalog", "security"]
        );
        let weak = Arc::downgrade(&admission);
        let bytes = retain_frame(Bytes::from(message.encode_to_vec()), admission);
        let last = bytes.slice(bytes.len() - 1..);
        drop(message);
        drop(bytes);
        assert!(weak.upgrade().is_some());
        drop(last);
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn chironql_receiving_tiny_pool_and_total_encoded_limit_refuse_output() {
        const CHILD: &str = "CHIRON_TEST_CHIRONQL_RESPONSE_TINY_POOL";
        if std::env::var_os(CHILD).is_some() {
            crate::resource_profile::install(
                crate::resource_profile::ResourceProfile::from_limits(1, 1),
            );
            assert_eq!(
                chironql(chironql_fixture()).err().unwrap().code(),
                tonic::Code::ResourceExhausted
            );
            return;
        }
        assert!(std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","response_output::tests::chironql_receiving_tiny_pool_and_total_encoded_limit_refuse_output","--nocapture"]).env(CHILD,"1").status().unwrap().success());
        let mut single = chironql_fixture();
        single.rows = vec![serde_json::Value::String("x".repeat(LIMIT))];
        assert_eq!(
            chironql(single).err().unwrap().code(),
            tonic::Code::ResourceExhausted
        );
        let mut total = chironql_fixture();
        total.rows = vec![
            serde_json::Value::String("x".repeat(LIMIT / 2)),
            serde_json::Value::String("x".repeat(LIMIT / 2)),
        ];
        assert_eq!(
            chironql(total).err().unwrap().code(),
            tonic::Code::ResourceExhausted
        );
        drop(chironql(chironql_fixture()).unwrap());
    }
    fn point() -> crate::Point {
        crate::Point {
            id: "public-日本語".into(),
            vector: vec![f32::MAX, -0.0, f32::MIN_POSITIVE],
            vectors: std::collections::HashMap::from([("named".into(), vec![-0.0, 0.1])]),
            sparse_vector: Some(crate::SparseVector {
                indices: vec![0, u32::MAX],
                values: vec![-0.0, 1.0],
            }),
            payload: serde_json::json!({"text":"\n日本語".repeat(4096), "integer":u64::MAX, "float":1.2345678901234567e300_f64}),
        }
    }

    fn sql_fixture(text_length: usize) -> (tempfile::TempDir, crate::Db, crate::SqlResponse) {
        use crate::RelationalValue as V;
        let dir = tempfile::tempdir().unwrap();
        let db = crate::Db::open(dir.path()).unwrap();
        db.execute_sql(crate::SqlExecutionRequest {statements:vec![crate::SqlStatementRequest {
            sql:"CREATE TABLE seed (c1 TEXT, c2 BOOLEAN, c3 BIGINT, c4 FLOAT, c5 DECIMAL(10,2), c6 TEXT, c7 TIMESTAMPTZ, c8 UUID, c9 VECTOR(2), c10 BYTEA, c11 DATE, c12 JSONB, c13 RECORD_REF('documents'))".into(),parameters:Vec::new()}],idempotency_key:None,retry_id:None}).unwrap();
        let values = vec![
            V::Null,
            V::Boolean(true),
            V::Integer(i64::MIN),
            V::Float(1.2345678901234567e300),
            V::Decimal("123.45".into()),
            V::Text("日本語".repeat(text_length)),
            V::TimestampUtc("2026-10-05T00:00:00Z".into()),
            V::Uuid(uuid::Uuid::nil()),
            V::Vector(vec![0.7181532, -0.0]),
            V::Bytes(vec![0, 255]),
            V::Date("2026-10-05".into()),
            V::Json(
                serde_json::json!({"max":u64::MAX,"zero":-0.0,"float":1.2345678901234567e300_f64}),
            ),
            V::RecordRef(crate::RecordRef {
                namespace: "documents".into(),
                id: "opaque".into(),
            }),
        ];
        let sql = format!(
            "INSERT INTO seed VALUES ({})",
            (1..=values.len())
                .map(|n| format!("${n}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        db.execute_sql(crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql,
                parameters: values,
            }],
            idempotency_key: None,
            retry_id: None,
        })
        .unwrap();
        let result = db
            .execute_sql_owned(crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "SELECT * FROM seed".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        (dir, db, result)
    }

    #[test]
    fn sql_protobuf_moves_payloads_preserves_every_value_and_keeps_last_frame_owner() {
        use crate::grpc::chiron_pb as sql_pb;
        use sql_pb::sql_value::Value as V;
        let (_dir, _db, output) = sql_fixture(4096);
        let crate::SqlResult::Rows {
            rows, column_types, ..
        } = &output.results[0]
        else {
            panic!()
        };
        let crate::RelationalValue::Vector(vector) = &rows[0][8] else {
            panic!()
        };
        let vector_ptr = vector.as_ptr();
        let crate::RelationalValue::Bytes(bytes) = &rows[0][9] else {
            panic!()
        };
        let bytes_ptr = bytes.as_ptr();
        let types: Vec<_> = column_types
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        let (message, admission) = sql(output).unwrap();
        assert_eq!(message.outcome, "committed");
        assert!(message.committed);
        let sql_pb::sql_result::Result::Rows(rows) = message.results[0].result.as_ref().unwrap()
        else {
            panic!()
        };
        assert_eq!(rows.column_types_json, types);
        let values = &rows.rows[0].values;
        assert!(matches!(values[0].value, Some(V::Null(_))));
        assert_eq!(values[1].value, Some(V::Boolean(true)));
        assert_eq!(values[2].value, Some(V::Integer(i64::MIN)));
        let Some(V::Floating(f)) = values[3].value else {
            panic!()
        };
        assert_eq!(f.to_bits(), 1.2345678901234567e300_f64.to_bits());
        assert_eq!(values[4].value, Some(V::Decimal("123.45".into())));
        assert_eq!(values[5].value, Some(V::Text("日本語".repeat(4096))));
        assert_eq!(
            values[6].value,
            Some(V::TimestampUtc("2026-10-05T00:00:00Z".into()))
        );
        assert_eq!(
            values[7].value,
            Some(V::Uuid(uuid::Uuid::nil().to_string()))
        );
        let Some(V::Vector(v)) = &values[8].value else {
            panic!()
        };
        assert_eq!(v.values.as_ptr(), vector_ptr);
        assert_eq!(v.values[1].to_bits(), (-0.0_f32).to_bits());
        let Some(V::BytesValue(v)) = &values[9].value else {
            panic!()
        };
        assert_eq!(v.as_ptr(), bytes_ptr);
        assert_eq!(v, &[0, 255]);
        assert_eq!(values[10].value, Some(V::Date("2026-10-05".into())));
        let Some(V::Jsonb(json)) = &values[11].value else {
            panic!()
        };
        let j: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(j["max"].as_u64(), Some(u64::MAX));
        assert_eq!(j["zero"].as_f64().unwrap().to_bits(), (-0.0_f64).to_bits());
        assert_eq!(j["float"].as_f64().unwrap().to_bits(), f.to_bits());
        assert_eq!(
            values[12].value,
            Some(V::RecordRef(sql_pb::SqlRecordRef {
                namespace: "documents".into(),
                id: "opaque".into()
            }))
        );
        let expected = message.clone();
        let weak = Arc::downgrade(&admission);
        let frame = retain_frame(Bytes::from(message.encode_to_vec()), admission);
        drop(message);
        let decoded = sql_pb::SqlExecutionResponse::decode(frame.clone()).unwrap();
        assert_eq!(decoded, expected);
        drop(decoded);
        let slice = frame.slice(1..);
        drop(frame);
        assert!(weak.upgrade().is_some());
        drop(slice);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn wire_sql_json_preserves_compact_vectors_and_refuses_oversized_output() {
        let (_dir, _db, output) = sql_fixture(4096);
        let expected = serde_json::to_string(&output).unwrap();
        let (json, admission) = wire_json(&output).unwrap();
        assert_eq!(json, expected);
        let weak = Arc::downgrade(&admission);
        let bytes = retain_frame(Bytes::from(json.into_bytes()), admission);
        drop(output);
        let clone = bytes.clone();
        drop(bytes);
        assert!(weak.upgrade().is_some());
        drop(clone);
        assert!(weak.upgrade().is_none());
        assert_eq!(
            wire_json(&"x".repeat(LIMIT + 1)).err().unwrap().code(),
            tonic::Code::ResourceExhausted
        );
        let mut reservation = ResponseReservation::new(512).unwrap();
        assert_eq!(
            admit_codec(LIMIT + 1, 512, &mut reservation)
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[test]
    fn point_protobuf_handoff_preserves_vectors_payload_cursor_and_last_frame_pin() {
        let input = point();
        let expected = crate::grpc::point_to_proto(input.clone()).unwrap();
        let vector = input.vector.as_ptr();
        let named = input.vectors["named"].as_ptr();
        let sparse = input.sparse_vector.as_ref().unwrap().indices.as_ptr();
        let cursor = input.id.clone();
        let (message, admission) = scroll(crate::ScrollResponse {
            points: vec![input],
            next_offset: Some(cursor.clone()),
        })
        .unwrap();
        assert_eq!(message.points.as_slice(), std::slice::from_ref(&expected));
        assert_eq!(
            message.points[0].vector.as_ptr(),
            vector,
            "dense ownership transfers without copy"
        );
        assert_eq!(message.points[0].vectors["named"].values.as_ptr(), named);
        assert_eq!(
            message.points[0]
                .sparse_vector
                .as_ref()
                .unwrap()
                .indices
                .as_ptr(),
            sparse
        );
        assert_eq!(message.points[0].vector[1].to_bits(), (-0.0_f32).to_bits());
        assert_eq!(
            message.points[0].vectors["named"].values[0].to_bits(),
            (-0.0_f32).to_bits()
        );
        assert_eq!(message.next_offset, cursor);
        let weak = Arc::downgrade(&admission);
        let bytes = retain_frame(Bytes::from(message.encode_to_vec()), admission);
        drop(message);
        let slice = bytes.slice(1..);
        drop(bytes);
        assert!(weak.upgrade().is_some());
        drop(slice);
        assert!(weak.upgrade().is_none());
        let (message, admission) = points(vec![point()]).unwrap();
        assert_eq!(message.points, [expected]);
        let weak = Arc::downgrade(&admission);
        drop(message);
        drop(admission);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn point_response_overload_and_envelope_limit_reject_without_publication() {
        const CHILD: &str = "CHIRON_TEST_POINT_RESPONSE_TINY_POOL";
        if std::env::var_os(CHILD).is_some() {
            crate::resource_profile::install(
                crate::resource_profile::ResourceProfile::from_limits(1, 1),
            );
            assert_eq!(
                points(vec![point()]).err().unwrap().code(),
                tonic::Code::ResourceExhausted
            );
            assert_eq!(
                scroll(crate::ScrollResponse {
                    points: vec![point()],
                    next_offset: Some("cursor".into())
                })
                .err()
                .unwrap()
                .code(),
                tonic::Code::ResourceExhausted
            );
            assert_eq!(
                points(Vec::new()).err().unwrap().code(),
                tonic::Code::ResourceExhausted
            );
            return;
        }
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "response_output::tests::point_response_overload_and_envelope_limit_reject_without_publication", "--nocapture"])
            .env(CHILD, "1").status().unwrap().success());
        let mut oversized = point();
        oversized.payload = serde_json::Value::String("x".repeat(LIMIT - 200));
        oversized.vector = vec![1.0; 1024];
        assert_eq!(
            points(vec![oversized]).err().unwrap().code(),
            tonic::Code::ResourceExhausted
        );
        let (empty, admission) = points(Vec::new()).unwrap();
        assert!(empty.points.is_empty());
        drop(empty);
        drop(admission);
    }

    #[test]
    fn protobuf_payload_and_last_frame_clone_keep_receiving_lease() {
        let input = vec![crate::SearchHit {
            id: "日本語".into(),
            score: -0.0,
            payload: serde_json::json!({"text":"\n".repeat(4096)}),
        }];
        let expected = serde_json::to_string(&input[0].payload).unwrap();
        let (message, admission) = hits(input).unwrap();
        assert_eq!(message.hits[0].payload_json, expected);
        assert_eq!(message.hits[0].score.to_bits(), (-0.0f32).to_bits());
        let weak = Arc::downgrade(&admission);
        let encoded = Bytes::from(message.encode_to_vec());
        drop(message);
        let bytes = retain_frame(encoded, admission);
        let clone = bytes.clone();
        let slice = clone.slice(1..);
        drop(bytes);
        drop(clone);
        assert!(weak.upgrade().is_some());
        drop(slice);
        assert!(weak.upgrade().is_none());
    }
}

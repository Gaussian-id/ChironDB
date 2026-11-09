use super::*;
use crate::chironql_parser::{AssetSelector, TemporalRead};
use chirondb_core::db::temporal::{MAX_HISTORY, SensorValue, TemporalAccess};
use chirondb_types::chironql::ExecutionDomain;

fn problem(query_id: &str, code: &str, message: &str) -> ChironQlError {
    ChironQlError {
        error: message.into(),
        code: code.into(),
        hint: None,
        position: None,
        affected_estimate: None,
        query_id: query_id.into(),
        trace: None,
    }
}
fn empty(query_id: &str, collection: &str) -> ChironQlResponse {
    let mut r = rows_response(
        query_id,
        ["asset_ref", "property", "time_ns", "value"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        vec![],
    );
    r.column_types = vec![
        RelationalType::RecordRef {
            namespace: collection.into(),
        },
        RelationalType::Text,
        RelationalType::Text,
        RelationalType::Jsonb,
    ];
    r.domains = vec![ExecutionDomain::Temporal];
    r
}
fn read_budget(query: &TemporalRead, asset: &str) -> u64 {
    let n = query.range.map_or(1, |(_, _, n)| n);
    n as u64 * (2048 + 2 * (asset.len() + query.collection.len() + query.property.len()) as u64)
}
fn read(
    db: &Db,
    access: TemporalAccess<'_>,
    query: &TemporalRead,
    asset: &str,
    query_id: &str,
    map: &mut impl FnMut(GaussError) -> ChironQlError,
) -> ExecResult {
    let points = if let Some((lo, hi, n)) = query.range {
        db.scan_temporal(&query.collection, access, asset, &query.property, lo..hi, n)
            .map_err(map)?
    } else {
        db.latest_temporal(&query.collection, access, asset, &query.property)
            .map_err(map)?
            .into_iter()
            .collect()
    };
    let mut r = empty(query_id, &query.collection);
    for point in points {
        let value = match point.value {
            SensorValue::Boolean(b) => json!(b),
            SensorValue::Float(v) if v.is_finite() => json!(v),
            SensorValue::Float(v) => json!(if v.is_sign_positive() {
                "+Infinity"
            } else {
                "-Infinity"
            }),
        };
        r.rows.push(json!({"asset_ref":{"namespace":query.collection,"id":asset},"property":query.property,"time_ns":point.time.to_string(),"value":value}));
    }
    Ok(r)
}
pub(crate) fn execute(
    db: &Db,
    access: TemporalAccess<'_>,
    statement: &Statement,
    query_id: &str,
    memory: &mut QueryMemory,
    mut map: impl FnMut(GaussError) -> ChironQlError,
) -> ExecResult {
    match statement {
        Statement::TemporalAppend {
            collection,
            samples,
        } => {
            let bytes = samples
                .iter()
                .map(|p| p.asset.len() + p.property.len() + 256)
                .sum::<usize>();
            memory.ql(bytes as u64, query_id)?;
            let mut response = affected_response(
                query_id,
                db.append_temporal_batch(collection, access, samples.clone())
                    .map_err(map)? as u64,
            );
            response.stats.durable = Some(true);
            response.domains = vec![ExecutionDomain::Temporal];
            Ok(response)
        }
        Statement::TemporalRead(query) => {
            let AssetSelector::Id(asset) = &query.asset else {
                return Err(problem(
                    query_id,
                    "chironql.invalid_pipeline_anchor",
                    "standalone read needs an asset ID",
                ));
            };
            memory.ql(read_budget(query, asset), query_id)?;
            read(db, access, query, asset, query_id, &mut map)
        }
        _ => unreachable!("temporal statement"),
    }
}
/// A relational seed may synthesize the same typed record_ref as VECTOR
/// from a visible TEXT id. Stored SQL references still undergo SQL authorization.
pub(crate) fn relational_seed(
    pipeline: &Pipeline,
    response: ChironQlResponse,
    memory: &mut QueryMemory,
) -> Result<PipelineRows, ChironQlError> {
    let ns = pipeline
        .temporal
        .as_ref()
        .filter(|stage| {
            matches!(&stage.query.asset,AssetSelector::Field(field)
        if field.alias==pipeline.relational_alias && field.field=="record_ref")
        })
        .filter(|_| !response.columns.iter().any(|c| c == "record_ref"));
    if ns.is_some()
        && !response
            .columns
            .iter()
            .zip(&response.column_types)
            .any(|(c, t)| {
                c == "id" && matches!(t, RelationalType::Text | RelationalType::Varchar { .. })
            })
    {
        return Err(problem(
            &response.query_id,
            "chironql.pipeline_type_mismatch",
            "relational temporal seed needs a TEXT id or typed RECORD_REF",
        ));
    }
    qualify_pipeline_rows(
        &pipeline.relational_alias,
        response,
        ns.map(|stage| stage.query.collection.as_str()),
        memory,
    )
}
pub(crate) fn stage_rows(
    db: &Db,
    access: TemporalAccess<'_>,
    pipeline: &Pipeline,
    sources: [Option<(&str, &PipelineRows)>; 3],
    query_id: &str,
    memory: &mut QueryMemory,
    mut map: impl FnMut(GaussError) -> ChironQlError,
) -> Result<Option<PipelineRows>, ChironQlError> {
    let Some(stage) = &pipeline.temporal else {
        return Ok(None);
    };
    let AssetSelector::Field(field) = &stage.query.asset else {
        return Err(problem(
            query_id,
            "chironql.invalid_pipeline_anchor",
            "temporal source must be a RECORD_REF",
        ));
    };
    let key = pipeline_field_key(field);
    let (_, source) = sources
        .into_iter()
        .flatten()
        .find(|(alias, _)| *alias == field.alias)
        .ok_or_else(|| {
            problem(
                query_id,
                "chironql.invalid_pipeline_anchor",
                "missing source",
            )
        })?;
    if source.types.get(&key)
        != Some(&RelationalType::RecordRef {
            namespace: stage.query.collection.clone(),
        })
    {
        return Err(problem(
            query_id,
            "chironql.pipeline_type_mismatch",
            "temporal source must be a RECORD_REF in the selected collection",
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    let per_asset = stage.query.range.map_or(1, |(_, _, n)| n);
    for row in &source.rows {
        memory.check().map_err(|e| receiving::error(query_id, e))?;
        let Some(reference) = row.get(&key).filter(|v| !v.is_null()) else {
            continue;
        };
        let id = reference
            .get("id")
            .and_then(Value::as_str)
            .filter(|_| {
                reference.get("namespace").and_then(Value::as_str) == Some(&stage.query.collection)
            })
            .ok_or_else(|| {
                problem(
                    query_id,
                    "chironql.pipeline_type_mismatch",
                    "invalid temporal asset reference",
                )
            })?;
        if ids.insert(id) && ids.len() > MAX_HISTORY / per_asset {
            return Err(problem(
                query_id,
                "chironql.resource_exhausted",
                "temporal stage exceeds total row budget",
            ));
        }
    }
    memory.ql(
        ids.iter().map(|id| read_budget(&stage.query, id)).sum(),
        query_id,
    )?;
    let mut response = empty(query_id, &stage.query.collection);
    for id in ids {
        memory.check().map_err(|e| receiving::error(query_id, e))?;
        response
            .rows
            .extend(read(db, access, &stage.query, id, query_id, &mut map)?.rows);
    }
    qualify_pipeline_rows(&stage.alias, response, None, memory).map(Some)
}

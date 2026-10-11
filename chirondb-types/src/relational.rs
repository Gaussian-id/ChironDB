use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationalType {
    Boolean,
    SmallInt,
    Integer,
    BigInt,
    Real,
    Float,
    Decimal {
        precision: u8,
        scale: u8,
    },
    Text,
    Varchar {
        length: usize,
    },
    Bytea,
    Date,
    TimestampUtc,
    Uuid,
    Jsonb,
    Vector {
        dimension: usize,
    },
    /// A stable reference to a vector/graph record namespace.
    RecordRef {
        namespace: String,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RelationalValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    Decimal(String),
    Text(String),
    Bytes(Vec<u8>),
    Date(String),
    TimestampUtc(String),
    Uuid(uuid::Uuid),
    Json(serde_json::Value),
    Vector(Vec<f32>),
    RecordRef(RecordRef),
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRef {
    pub namespace: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationalColumn {
    pub name: String,
    pub data_type: RelationalType,
    #[serde(default)]
    pub nullable: bool,
    /// Static SQL default used by INSERT and referential `SET DEFAULT` actions.
    ///
    /// The first production relational format deliberately persists the typed
    /// value rather than parser-specific SQL text. Volatile/default functions
    /// are rejected by the binder until expression defaults have a versioned
    /// representation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<RelationalValue>,
    /// SQL identity generation. The engine derives generated values from the
    /// table's durable row-identity frontier, so recovery cannot reuse one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityGeneration>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityGeneration {
    Always,
    ByDefault,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UniqueConstraint {
    /// Stable physical index identity. Zero is accepted only while decoding a
    /// legacy preview definition and is assigned before catalog publication.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub index_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub columns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarIndexDefinition {
    /// Stable physical index identity shared with compatible constraints.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub index_id: u64,
    pub name: String,
    pub columns: Vec<String>,
    #[serde(default)]
    pub unique: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckConstraintDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Canonical SQL expression text. The engine reparses this with the
    /// versioned SQL grammar before validation instead of persisting a parser
    /// crate's internal AST representation.
    pub expression: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferencedKeyKind {
    PrimaryKey,
    UniqueConstraint,
    UniqueIndex,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignKeyDefinition {
    /// Stable identity of the child-side supporting index.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub index_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub columns: Vec<String>,
    pub referenced_table: String,
    pub referenced_columns: Vec<String>,
    /// Stable catalog owner selected for the referenced key. The kind keeps
    /// constraint and relation namespaces distinct when names happen to match.
    /// Legacy preview definitions may omit either field and use conservative
    /// dependency checks until they are rewritten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referenced_key_kind: Option<ReferencedKeyKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referenced_key_name: Option<String>,
    #[serde(default)]
    pub match_kind: ForeignKeyMatch,
    #[serde(default)]
    pub on_delete: ForeignKeyAction,
    #[serde(default)]
    pub on_update: ForeignKeyAction,
    #[serde(default)]
    pub deferrable: bool,
    #[serde(default)]
    pub initially_deferred: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignKeyMatch {
    #[default]
    Simple,
    Full,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignKeyAction {
    #[default]
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TableDefinition {
    /// Stable catalog identity used by persisted row keys.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub table_id: u64,
    /// Protected SQL grant identity. Legacy tables acquire it through the
    /// offline table-authority migration; row/index IDs remain unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_incarnation: Option<uuid::Uuid>,
    /// Immutable principal that created a table under strict SQL authority.
    /// Confers SQL data rights only; legacy tables have no inferred creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_principal_id: Option<String>,
    /// Tenant that owns this table in the protected profile. Legacy and
    /// unprotected tables deliberately remain installation-local (`None`).
    /// A protected request may only resolve tables owned by its catalog
    /// tenant; this is persisted so restart/recovery cannot weaken isolation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Materialized ML results and runtime metadata reject external SQL writes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub managed_by_ml: bool,
    pub name: String,
    pub columns: Vec<RelationalColumn>,
    #[serde(default)]
    pub primary_key: Vec<String>,
    /// Stable SQL constraint name. Legacy preview definitions may omit it and
    /// are exposed through the conventional `<table>_pkey` fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_key_name: Option<String>,
    /// Stable identity of the primary-key physical index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_key_index_id: Option<u64>,
    #[serde(default)]
    pub unique_constraints: Vec<UniqueConstraint>,
    #[serde(default)]
    pub check_constraints: Vec<CheckConstraintDefinition>,
    #[serde(default)]
    pub foreign_keys: Vec<ForeignKeyDefinition>,
    #[serde(default)]
    pub indexes: Vec<ScalarIndexDefinition>,
    /// Engine-owned point-reference indexes. IDs are stable physical catalog
    /// identities; clients do not create or drop these indexes directly.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reference_index_ids: BTreeMap<String, u64>,
}

const fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlStatementRequest {
    pub sql: String,
    #[serde(default)]
    pub parameters: Vec<RelationalValue>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlExecutionRequest {
    pub statements: Vec<SqlStatementRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SqlResult {
    Definition {
        affected_objects: u64,
    },
    Mutation {
        affected_rows: u64,
    },
    Rows {
        columns: Vec<String>,
        column_types: Vec<RelationalType>,
        rows: Vec<Vec<RelationalValue>>,
    },
    Explain {
        plan: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlOutcome {
    Rejected,
    Committed,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlExecutionResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    pub snapshot: u64,
    pub committed: bool,
    #[serde(default)]
    pub outcome: SqlOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sequence: Option<u64>,
    #[serde(default)]
    pub retryable: bool,
    pub results: Vec<SqlResult>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlTransactionState {
    Active,
    Aborted,
    Committed,
    RolledBack,
    Expired,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlTransactionHandleResponse {
    pub handle: String,
    pub snapshot: u64,
    pub state: SqlTransactionState,
    /// Reserved at BEGIN; COMMIT uses this same durable reconciliation identity.
    /// Private progress/rollback alone does not create a durable journal decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

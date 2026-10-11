//! Native relational rows and SQL execution.
//!
//! The module deliberately owns parsing, constraints, MVCC visibility and its
//! storage projection. `Db` remains the orchestrator that supplies the common
//! transaction journal and audit projection.

mod catalog;
mod catalog_view;
pub use catalog_view::RelationalCatalogSnapshot;
mod checkpoint;
pub(crate) mod disk_map;
mod history;
mod indexes;
mod intents;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "v1 physical row/index keys are frozen before immutable segment publication"
    )
)]
mod key_encoding;
mod maintenance;
mod memory;
mod output;
mod parsing;
mod query_spill;
mod receipt;
mod record_bindings;
mod record_references;
mod replay;
mod row_chain;
mod rows;
mod runs;
mod schema;
mod segment;
mod sessions;
mod table_authority;
mod value_decode;
mod values;
pub(crate) mod wal_decode;

use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sqlparser::{
    ast::{
        AlterColumnOperation, AlterTableOperation, AssignmentTarget, BinaryOperator, CastKind,
        ColumnOption, ConflictTarget, ConstraintCharacteristics, ConstraintReferenceMatchKind,
        DataType, DeferrableInitial, Distinct, DropBehavior, DuplicateTreatment, Expr,
        ForeignKeyConstraint, FromTable, FunctionArg, FunctionArgExpr, FunctionArguments,
        GeneratedAs, GroupByExpr, JoinConstraint, JoinOperator, LimitClause, ObjectName,
        ObjectType, OnConflictAction, OnInsert, OrderByKind, Query, ReferentialAction,
        RenameTableNameKind, SelectItem, SelectItemQualifiedWildcardKind, SetExpr, Statement,
        TableConstraint, TableFactor, TableObject, Value,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

use crate::{
    CheckConstraintDefinition, ForeignKeyAction, ForeignKeyDefinition, ForeignKeyMatch, GaussError,
    IdentityGeneration, ReferencedKeyKind, RelationalColumn, RelationalType, RelationalValue,
    Result, ScalarIndexDefinition, SqlExecutionRequest, SqlExecutionResponse, SqlOutcome,
    SqlResult, SqlTransactionHandleResponse, SqlTransactionState, TableDefinition,
    UniqueConstraint,
    audit::AuditContext,
    encryption::{FileType, PersistentFile},
    security::{Action as SecurityAction, AuthenticatedIdentity, PublicationPermit, SecurityError},
    transaction_journal::{
        CommittedTransaction, ProjectionKind, TransactionAudit, TransactionId, TransactionJournal,
        TransactionTarget,
    },
    wal::{MULTI_MODEL_BATCH_VERSION, MultiModelBatch, MultiModelCollectionBatch, Wal, WalEntry},
};
use checkpoint::materialize as materialize_checkpoint_segments;
use indexes::Catalog as IndexCatalog;
use intents::{IntentKey, IntentManager, IntentMode, IntentRequest};
use key_encoding::encode_equality_value;
use key_encoding::{
    RowIdentityKey, encode_index_key_v1, encode_index_prefix_v1, encode_row_key_v1,
};
pub use output::SqlResponse;
use parsing::{parse_interactive_control, parse_relational_statement};
use row_chain::{ChainRead, VersionChain};
use rows::RowStore;
use schema::Schema;
use segment::{
    SegmentKind, SegmentMetadata, SegmentRecord, remove_segment_if_exists, write_segment,
};
use sessions::InteractiveSessions;
use values::RowValues;

const RELATIONAL_WAL_DIR: &str = "relational/wal";
const RELATIONAL_CHECKPOINT_FILE: &str = "relational/checkpoint.gdx";
const RELATIONAL_SEGMENT_DIR: &str = "relational/segments";
const RELATIONAL_QUERY_SPILL_DIR: &str = "relational/query-spill";
const RELATIONAL_CHECKPOINT_MAGIC: &[u8; 8] = b"CHRNREL1";
const RELATIONAL_CHECKPOINT_HEADER_LEN: usize = 20;
const RELATIONAL_CHECKPOINT_VERSION: u32 = 4;
const RELATIONAL_CHECKPOINT_RUNS_VERSION: u32 = 3;
const RELATIONAL_CHECKPOINT_LEGACY_VERSION: u32 = 2;
const RELATIONAL_CHECKPOINT_INTERVAL: u64 = 1_024;
const RELATIONAL_MAX_RUNS_PER_TABLE: usize = 4;
const MAX_STATEMENTS_PER_REQUEST: usize = 32;
const MAX_DECODED_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_WRITE_SET_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROWS_PER_RESULT: usize = 100_000;
const MAX_REFERENTIAL_ACTION_ROWS: usize = 100_000;
const MAX_INTERACTIVE_TRANSACTIONS: usize = 128;
const INTERACTIVE_TRANSACTION_TTL: Duration = Duration::from_secs(300);
const INTENT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const SQL_WAIT_CHECK_INTERVAL: Duration = Duration::from_millis(10);

static SQL_ADMISSION: LazyLock<SqlAdmission> = LazyLock::new(|| {
    let profile = crate::resource_profile::current();
    SqlAdmission {
        capacity: profile.sql_pool_bytes,
        reservation: profile.sql_request_working_set_bytes,
        used: Mutex::new(0),
        changed: Condvar::new(),
    }
});

struct SqlAdmission {
    capacity: u64,
    reservation: u64,
    used: Mutex<u64>,
    changed: Condvar,
}

impl SqlAdmission {
    fn acquire(&self) -> Result<SqlAdmissionPermit<'_>> {
        let deadline = Instant::now() + INTENT_WAIT_TIMEOUT;
        let mut used = self
            .used
            .lock()
            .map_err(|_| invalid("SQL admission lock poisoned"))?;
        loop {
            check_sql_cancelled()?;
            let next = used
                .checked_add(self.reservation)
                .ok_or_else(sql_overloaded)?;
            if next <= self.capacity {
                *used = next;
                metrics::gauge!("chirondb_sql_pool_used_bytes").set(next as f64);
                return Ok(SqlAdmissionPermit { admission: self });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                metrics::counter!("chirondb_sql_admission_rejections_total").increment(1);
                return Err(sql_overloaded());
            }
            #[cfg(test)]
            sessions::observe_wait();
            let (next_used, _) = self
                .changed
                .wait_timeout(used, remaining.min(SQL_WAIT_CHECK_INTERVAL))
                .map_err(|_| invalid("SQL admission lock poisoned"))?;
            used = next_used;
        }
    }
}

struct SqlAdmissionPermit<'a> {
    admission: &'a SqlAdmission,
}

impl Drop for SqlAdmissionPermit<'_> {
    fn drop(&mut self) {
        let Ok(mut used) = self.admission.used.lock() else {
            return;
        };
        *used = used.saturating_sub(self.admission.reservation);
        metrics::gauge!("chirondb_sql_pool_used_bytes").set(*used as f64);
        self.admission.changed.notify_one();
    }
}

fn sql_overloaded() -> GaussError {
    GaussError::ResourceExhausted("SQL memory budget is exhausted; retry later".into())
}

struct BoundedCounter {
    written: usize,
    limit: usize,
}

impl Write for BoundedCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(buffer.len())
            .filter(|next| *next <= self.limit)
            .ok_or_else(|| io::Error::other("serialized value exceeds limit"))?;
        self.written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn enforce_serialized_limit<T: Serialize>(value: &T, limit: usize, label: &str) -> Result<()> {
    let mut counter = BoundedCounter { written: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|error| {
        GaussError::ResourceExhausted(format!("{label} exceeds {limit} bytes: {error}"))
    })
}

thread_local! {
    static SQL_CANCELLATION_STACK: RefCell<Vec<Arc<AtomicBool>>> = const { RefCell::new(Vec::new()) };
    static SQL_DEADLINE_STACK: RefCell<Vec<Instant>> = const { RefCell::new(Vec::new()) };
}

struct SqlCancellationScope;

impl Drop for SqlCancellationScope {
    fn drop(&mut self) {
        SQL_CANCELLATION_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

pub(crate) fn with_sql_cancellation<T>(
    cancellation: Arc<AtomicBool>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    SQL_CANCELLATION_STACK.with(|stack| stack.borrow_mut().push(cancellation));
    let _scope = SqlCancellationScope;
    check_sql_cancelled()?;
    operation()
}

pub(crate) fn with_sql_deadline<T>(
    deadline: Instant,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    struct DeadlineScope;
    impl Drop for DeadlineScope {
        fn drop(&mut self) {
            SQL_DEADLINE_STACK.with(|stack| {
                stack.borrow_mut().pop();
            });
        }
    }
    SQL_DEADLINE_STACK.with(|stack| stack.borrow_mut().push(deadline));
    let _scope = DeadlineScope;
    check_sql_cancelled()?;
    operation()
}

pub(crate) fn check_sql_cancelled() -> Result<()> {
    let cancelled = SQL_CANCELLATION_STACK.with(|stack| {
        stack
            .borrow()
            .iter()
            .any(|flag| flag.load(AtomicOrdering::Acquire))
    });
    if SQL_DEADLINE_STACK.with(|stack| {
        stack
            .borrow()
            .iter()
            .any(|deadline| Instant::now() >= *deadline)
    }) {
        return Err(GaussError::ResourceExhausted(
            "maintenance deadline exceeded".into(),
        ));
    }
    if cancelled {
        Err(invalid("query canceled"))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RelationalMutation {
    CreateTable {
        definition: TableDefinition,
    },
    DropTable {
        name: String,
    },
    AlterTable {
        definition: TableDefinition,
    },
    RenameTable {
        old_name: String,
        definition: TableDefinition,
    },
    RewriteTable {
        definition: TableDefinition,
        rows: Vec<StoredRow>,
    },
    Insert {
        table: String,
        rows: Vec<StoredRow>,
    },
    Update {
        table: String,
        rows: Vec<StoredRow>,
    },
    Delete {
        table: String,
        row_ids: Vec<u64>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationalBatch {
    pub sequence: u64,
    pub mutations: Vec<RelationalMutation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRow {
    pub row_id: u64,
    pub values: Vec<RelationalValue>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RowVersion {
    begin: u64,
    end: Option<u64>,
    values: RowValues,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelationalCheckpointTable {
    definition: TableDefinition,
    #[serde(default)]
    rows: BTreeMap<u64, Vec<RowVersion>>,
    next_row_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    row_segment: Option<RelationalSegmentReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    index_segment: Option<RelationalSegmentReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    row_segments: Vec<RelationalSegmentReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    index_segments: Vec<RelationalSegmentReference>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelationalCheckpoint {
    version: u32,
    sequence: u64,
    next_catalog_id: u64,
    wal_watermark: u64,
    tables: Vec<RelationalCheckpointTable>,
    #[serde(deserialize_with = "replay::discard_legacy_ids")]
    applied_transactions: Vec<TransactionId>,
    // Admission follows decoded or copied metadata through consumption.
    // Runtime catalog ownership has a separate lifetime.
    #[serde(skip)]
    owned_memory: memory::Charge,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RelationalSegmentReference {
    file_name: String,
    kind: SegmentKind,
    sequence: u64,
    record_count: u64,
    min_key: Option<Vec<u8>>,
    max_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRowVersion {
    row_id: u64,
    version: RowVersion,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedIndexVersion {
    row_id: u64,
    begin: u64,
    end: Option<u64>,
}

struct CapturedRelationalCheckpoint {
    manifest: RelationalCheckpoint,
    tables: Vec<Arc<TableState>>,
    _owned_memory: memory::Charge,
}

#[derive(Clone, Debug)]
struct TableSegmentBacking {
    sequence: u64,
    file_name: String,
    #[cfg(test)]
    path: PathBuf,
    reader: Arc<segment::SegmentReader>,
}

impl TableSegmentBacking {
    fn open(directory: &Path, reference: &RelationalSegmentReference) -> Result<Self> {
        let path = checkpoint_segment_path(directory, reference)?;
        let reader = Arc::new(segment::SegmentReader::open(&path)?);
        validate_segment_reference(reference, reader.metadata())?;
        Ok(Self {
            sequence: reference.sequence,
            file_name: reference.file_name.clone(),
            #[cfg(test)]
            path,
            reader,
        })
    }
}

struct CheckpointTableBackings {
    rows: RowStore,
    indexes: Vec<TableSegmentBacking>,
    scalar_indexes: IndexCatalog,
}

#[derive(Clone, Debug)]
struct TableState {
    directory: Arc<PathBuf>,
    definition: Schema,
    rows: RowStore,
    next_row_id: u64,
    /// Disk index runs are the current immutable base. Only changed memberships
    /// occupy RAM; a table snapshot shares the pinned mappings and delta values.
    indexes: IndexCatalog,
    index_segments: Vec<TableSegmentBacking>,
    index_snapshot: u64,
}

impl TableState {
    fn empty(definition: TableDefinition, directory: Arc<PathBuf>) -> Result<Self> {
        Self::with_schema(Schema::adopt(definition)?, directory)
    }

    fn with_schema(definition: Schema, directory: Arc<PathBuf>) -> Result<Self> {
        let indexes = IndexCatalog::new(&definition)?;
        Ok(Self {
            directory,
            definition,
            rows: RowStore::default(),
            next_row_id: 1,
            indexes,
            index_segments: Vec::new(),
            index_snapshot: 0,
        })
    }

    fn index_row(&mut self, row_id: u64, values: &[RelationalValue]) -> Result<()> {
        self.set_index_row(row_id, values, true)
    }

    fn unindex_row(&mut self, row_id: u64, values: &[RelationalValue]) -> Result<()> {
        self.set_index_row(row_id, values, false)
    }

    fn set_index_row(
        &mut self,
        row_id: u64,
        values: &[RelationalValue],
        present: bool,
    ) -> Result<()> {
        if self.indexes.is_empty() {
            return Ok(());
        }
        for (columns, entries) in self.indexes.iter_mut()? {
            let values = columns
                .iter()
                .map(|column| Ok(&values[column_index(&self.definition, column)?]))
                .collect::<Result<Vec<_>>>()?;
            entries.set(row_id, &values, present)?;
        }
        Ok(())
    }

    fn indexed_entries<'a>(
        &'a self,
        columns: &[String],
        values: &[&RelationalValue],
    ) -> Result<Option<indexes::IndexEntries<'a>>> {
        let index = self
            .indexes
            .get(columns)
            .ok_or_else(|| invalid("missing scalar index"))?;
        index
            .key(values)?
            .map(|key| index.entries(&self.index_segments, self.index_snapshot, Some(&key)))
            .transpose()
    }

    fn replace_definition(&mut self, definition: TableDefinition, snapshot: u64) -> Result<()> {
        let mut replacement = Self::empty(definition, Arc::clone(&self.directory))?;
        replacement.rows = self.rows.clone();
        replacement.next_row_id = self.next_row_id;
        replacement.rebuild_indexes(snapshot)?;
        *self = replacement;
        Ok(())
    }

    fn rebuild_indexes(&mut self, snapshot: u64) -> Result<()> {
        let indexes = IndexCatalog::new(&self.definition)?;
        let backings = if indexes.is_empty() {
            Vec::new()
        } else {
            vec![checkpoint::rebuild_indexes(self, snapshot)?]
        };
        self.indexes = indexes;
        self.index_segments = backings;
        self.index_snapshot = snapshot;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct RelationalState {
    directory: Arc<PathBuf>,
    sequence: u64,
    /// Installation-local monotonic allocator. Table and physical index IDs
    /// share one namespace so no persisted key identity can be reused.
    next_catalog_id: u64,
    /// Snapshots share table roots, immutable row locators and persistent
    /// row/index overlay branches. Writes replace only affected paths/chains.
    tables: catalog::Catalog,
}

impl RelationalState {
    fn empty(directory: PathBuf) -> Result<Self> {
        Ok(Self {
            directory: Arc::new(directory),
            sequence: 0,
            next_catalog_id: 1,
            tables: catalog::Catalog::empty()?,
        })
    }
}

impl RelationalState {
    fn retained_bytes(&self) -> u64 {
        self.tables.values().fold(0_u64, |total, table| {
            table.indexes.values().fold(
                total.saturating_add(table.rows.retained_bytes()),
                |total, index| total.saturating_add(index.retained_bytes()),
            )
        })
    }

    fn checkpoint_required(&self) -> bool {
        self.retained_bytes() >= memory::flush_threshold()
            || self.sequence.is_multiple_of(RELATIONAL_CHECKPOINT_INTERVAL)
    }
}

#[derive(Clone, Debug)]
struct QueryColumn {
    qualifier: String,
    name: String,
    data_type: RelationalType,
}

#[derive(Clone, Debug)]
struct QueryRelation {
    columns: Vec<QueryColumn>,
    rows: Vec<RowValues>,
}

#[derive(Clone, Debug)]
enum QueryProjectionSource {
    Column(usize),
    RecordRef { namespace: String, id_column: usize },
    Scalar(RelationalValue),
}

#[derive(Clone, Debug)]
struct QueryProjection {
    source: QueryProjectionSource,
    name: String,
    data_type: RelationalType,
}

#[derive(Clone, Copy, Debug)]
struct QueryOrderKey {
    source_index: Option<usize>,
    projected: bool,
}

#[derive(Clone, Copy)]
struct QueryOrderSpec {
    index: Option<usize>,
    ascending: bool,
    nulls_first: Option<bool>,
}

struct IndexedSelectionProbe {
    columns: Vec<String>,
    key: Option<Vec<u8>>,
}

struct RankedQueryRow<'a> {
    source_position: usize,
    values: RowValues,
    charge: usize,
    ordering: &'a [QueryOrderSpec],
}

impl PartialEq for RankedQueryRow<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RankedQueryRow<'_> {}

impl PartialOrd for RankedQueryRow<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedQueryRow<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_query_order(
            &self.values,
            self.source_position,
            &other.values,
            other.source_position,
            self.ordering,
        )
    }
}

#[derive(Clone, Debug)]
enum AggregateSource {
    GroupColumn(usize),
    CountStar,
    Count(usize),
    Sum(usize),
    Avg(usize),
    Min(usize),
    Max(usize),
}

#[derive(Clone, Debug)]
struct AggregateProjection {
    source: AggregateSource,
    distinct: bool,
    name: String,
    expression_key: String,
    data_type: RelationalType,
}

#[derive(Clone, Debug)]
struct ParentChange {
    table: String,
    old_values: Vec<RelationalValue>,
    new_values: Option<Vec<RelationalValue>>,
}

#[derive(Clone, Debug, Default)]
struct SnapshotRegistry {
    active: Arc<std::sync::Mutex<BTreeMap<u64, usize>>>,
}

impl SnapshotRegistry {
    fn pin(&self, snapshot: u64) -> Result<SnapshotPin> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| invalid("relational snapshot registry lock poisoned"))?;
        *active.entry(snapshot).or_default() += 1;
        Ok(SnapshotPin {
            registry: self.clone(),
            snapshot,
        })
    }

    fn oldest(&self) -> Result<Option<u64>> {
        Ok(self
            .active
            .lock()
            .map_err(|_| invalid("relational snapshot registry lock poisoned"))?
            .first_key_value()
            .map(|(snapshot, _)| *snapshot))
    }

    #[cfg(test)]
    fn active_count(&self) -> usize {
        self.active
            .lock()
            .expect("snapshot registry")
            .values()
            .sum()
    }
}

#[derive(Debug)]
struct SnapshotPin {
    registry: SnapshotRegistry,
    snapshot: u64,
}

impl Drop for SnapshotPin {
    fn drop(&mut self) {
        let Ok(mut active) = self.registry.active.lock() else {
            return;
        };
        let Some(count) = active.get_mut(&self.snapshot) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            active.remove(&self.snapshot);
        }
    }
}

#[derive(Debug)]
pub struct RelationalEngine {
    state: RwLock<RelationalState>,
    wal: std::sync::Mutex<Wal>,
    journal: Arc<TransactionJournal>,
    wal_dir: PathBuf,
    checkpoint_path: PathBuf,
    checkpoint: std::sync::Mutex<()>,
    self_weak: Weak<Self>,
    checkpoint_worker: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    checkpoint_cancel: Arc<AtomicBool>,
    checkpoint_lease: std::sync::Mutex<Option<Arc<dyn Send + Sync + std::fmt::Debug>>>,
    interactive: InteractiveSessions,
    snapshots: SnapshotRegistry,
    intents: IntentManager,
}

pub struct RelationalExecution {
    pub response: SqlExecutionResponse,
    pub committed: Option<CommittedTransaction>,
    pub projection_error: Option<GaussError>,
    // Last: response allocations die before their unique receiving reservation.
    response_memory: wal_decode::Reservation,
}

struct PreparedRelationalExecution {
    snapshot: u64,
    results: Vec<SqlResult>,
    mutations: Vec<RelationalMutation>,
    reference_writes: BTreeSet<crate::RecordRef>,
    catalog: catalog::Catalog,
    write_dependencies: Vec<RowWriteDependency>,
    rebasable: bool,
    intents: Vec<IntentRequest>,
    authorization: Option<SqlAuthorization>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RowWriteDependency {
    table: String,
    row_id: u64,
    version_begin: u64,
}

#[derive(Debug)]
struct InteractiveTransaction {
    base: RelationalState,
    history: history::History,
    protected_tenant: bool,
    last_activity: Instant,
    aborted: bool,
    _snapshot_pin: SnapshotPin,
}

/// Persist only permission dependencies for commit acknowledgement replay,
/// never SQL parameter values. Interactive COMMIT responses contain no row results.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SqlAuthorization {
    tenant: String,
    schema: bool,
    grants: BTreeSet<(String, SecurityAction)>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    table_grants: BTreeSet<SqlTableRequirement>,
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
struct SqlTableRequirement {
    table: String,
    table_id: u64,
    incarnation: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    creator_principal_id: Option<String>,
    action: SecurityAction,
}

impl SqlAuthorization {
    fn empty(tenant: &str) -> Self {
        Self {
            tenant: tenant.into(),
            schema: false,
            grants: BTreeSet::new(),
            table_grants: BTreeSet::new(),
        }
    }

    pub(crate) fn authorize(&self, identity: &AuthenticatedIdentity) -> Result<PublicationPermit> {
        if identity.principal().tenant != self.tenant
            || (self.schema && !identity.allows_installation(SecurityAction::Schema))
            || (identity.has_strict_sql_scopes() && !self.grants.is_empty())
            || self
                .grants
                .iter()
                .any(|(table, action)| !identity.allows(&self.tenant, table, *action))
            || self.table_grants.iter().any(|grant| {
                !identity.owns_table(&self.tenant, grant.creator_principal_id.as_deref())
                    && !identity.allows_table(
                        &self.tenant,
                        &grant.table,
                        grant.table_id,
                        grant.incarnation,
                        grant.action,
                    )
            })
        {
            return Err(SecurityError::Forbidden.into());
        }
        identity.publication_permit().map_err(Into::into)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InteractiveCommitReceipt {
    version: u16,
    authorization: Option<SqlAuthorization>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    references: BTreeSet<crate::RecordRef>,
    response: SqlExecutionResponse,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StandaloneCommitReceipt {
    version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization: Option<SqlAuthorization>,
    references: BTreeSet<crate::RecordRef>,
    response: SqlExecutionResponse,
}

enum SqlCommitReceipt<'a> {
    Standalone {
        claim: &'a crate::transaction_journal::IdempotencyGuard,
        table_authority: bool,
    },
    Interactive {
        claim: &'a crate::transaction_journal::IdempotencyGuard,
        transaction_id: TransactionId,
        authorization: Option<&'a SqlAuthorization>,
        decision_started: &'a AtomicBool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlStatementClass {
    Read,
    Write,
    Admin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlStatementKind {
    Select,
    Explain,
    Insert,
    Update,
    Delete,
    CreateTable,
    DropTable,
    AlterTable,
    CreateIndex,
    DropIndex,
    SetConstraints,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlStatementAnalysis {
    pub class: SqlStatementClass,
    pub kind: SqlStatementKind,
    pub tables: Vec<String>,
    pub indexes: Vec<String>,
    /// CREATE TABLE declares a VECTOR column and therefore belongs to the
    /// historical pgvector compatibility profile when received on pgwire.
    pub declares_vector: bool,
}

#[derive(Clone, Debug)]
enum ParsedRelationalStatement {
    Sql(Box<Statement>),
    SetConstraints(SetConstraintsStatement),
}

#[derive(Clone, Debug)]
struct SetConstraintsStatement {
    target: SetConstraintsTarget,
    deferred: bool,
}

#[derive(Clone, Debug)]
enum InteractiveControl {
    Savepoint(String),
    RollbackTo(String),
    Release(String),
}

#[derive(Clone, Debug)]
enum SetConstraintsTarget {
    All,
    Names(Vec<String>),
}

#[derive(Clone, Debug, Default)]
struct ConstraintModes {
    all: Option<bool>,
    named: HashMap<String, bool>,
}

impl ConstraintModes {
    fn is_deferred(&self, foreign_key: &ForeignKeyDefinition) -> bool {
        if !foreign_key.deferrable {
            return false;
        }
        foreign_key
            .name
            .as_ref()
            .and_then(|name| self.named.get(name))
            .copied()
            .or(self.all)
            .unwrap_or(foreign_key.initially_deferred)
    }
}

fn apply_constraint_mode(
    state: &RelationalState,
    modes: &mut ConstraintModes,
    statement: &SetConstraintsStatement,
) -> Result<()> {
    match &statement.target {
        SetConstraintsTarget::All => {
            modes.all = Some(statement.deferred);
            modes.named.clear();
        }
        SetConstraintsTarget::Names(names) => {
            for name in names {
                let matches = state
                    .tables
                    .values()
                    .flat_map(|table| &table.definition.foreign_keys)
                    .filter(|foreign_key| foreign_key.name.as_deref() == Some(name.as_str()))
                    .collect::<Vec<_>>();
                if matches.is_empty() {
                    return Err(invalid(format!("constraint {name} does not exist")));
                }
                if statement.deferred && matches.iter().any(|foreign_key| !foreign_key.deferrable) {
                    return Err(invalid(format!("constraint {name} is not deferrable")));
                }
                modes.named.insert(name.clone(), statement.deferred);
            }
        }
    }
    Ok(())
}

impl RelationalEngine {
    pub fn analyze_statement(sql: &str) -> Result<SqlStatementAnalysis> {
        match parse_relational_statement(sql)? {
            ParsedRelationalStatement::Sql(statement) => analyze_parsed_statement(&statement),
            ParsedRelationalStatement::SetConstraints(_) => Ok(SqlStatementAnalysis {
                class: SqlStatementClass::Write,
                kind: SqlStatementKind::SetConstraints,
                tables: Vec::new(),
                indexes: Vec::new(),
                declares_vector: false,
            }),
        }
    }

    /// Authorize a complete SQL request against the current protected catalog.
    ///
    /// Table names reuse the protected authority's exact collection-scope
    /// grants. This keeps the durable identity format additive while still
    /// giving relational tables independent Read/Create/Update/Delete grants.
    /// DDL requires the installation-scoped `Schema` action. The returned
    /// permit must be held through execution; transports acquire a fresh
    /// permit again when publishing a result.
    pub(crate) fn authorize_request(
        &self,
        identity: &AuthenticatedIdentity,
        request: &SqlExecutionRequest,
    ) -> Result<PublicationPermit> {
        self.authorization_requirements(request, &identity.principal().tenant)?
            .authorize(identity)
    }

    pub(crate) fn authorization_requirements(
        &self,
        request: &SqlExecutionRequest,
        tenant: &str,
    ) -> Result<SqlAuthorization> {
        let state = self.state.read();
        let mut authorization = SqlAuthorization::empty(tenant);
        for item in &request.statements {
            // Savepoints operate only on the caller-owned private transaction
            // state; table authorization applies to the statements they retain.
            if parse_interactive_control(&item.sql)?.is_some() {
                continue;
            }
            let parsed = parse_relational_statement(&item.sql)?;
            let ParsedRelationalStatement::Sql(statement) = parsed else {
                continue;
            };
            extend_statement_authorization(&state, &statement, &mut authorization)?;
        }
        Ok(authorization)
    }

    pub fn ensure_storage(root: &Path) -> Result<()> {
        fs::create_dir_all(root.join(RELATIONAL_WAL_DIR))?;
        fs::create_dir_all(root.join(RELATIONAL_SEGMENT_DIR))?;
        Ok(())
    }

    pub fn open(root: &Path, journal: Arc<TransactionJournal>) -> Result<Arc<Self>> {
        memory::initialize_history_metrics();
        let wal_dir = root.join(RELATIONAL_WAL_DIR);
        let checkpoint_path = root.join(RELATIONAL_CHECKPOINT_FILE);
        let segment_dir = root.join(RELATIONAL_SEGMENT_DIR);
        fs::create_dir_all(&wal_dir)?;
        fs::create_dir_all(&segment_dir)?;
        query_spill::cleanup_interrupted(&root.join(RELATIONAL_QUERY_SPILL_DIR))?;
        checkpoint::cleanup_interrupted(&segment_dir, &checkpoint_path)?;
        let checkpoint = read_relational_checkpoint(&checkpoint_path)?;
        let mut recovery_generation = checkpoint
            .as_ref()
            .map(checkpoint::projection_manifest)
            .transpose()?;
        let mut staged_batch = false;
        let (mut state, wal_watermark) = match checkpoint {
            Some(checkpoint) => restore_relational_checkpoint(checkpoint, &segment_dir)?,
            None => (RelationalState::empty(segment_dir.clone())?, 0),
        };
        let recovery = Wal::recover_from(&wal_dir, wal_watermark, |record| {
            if staged_batch || state.retained_bytes() >= memory::flush_threshold() {
                checkpoint::flush_recovery_prefix(
                    &mut state,
                    record.lsn,
                    &checkpoint_path,
                    &segment_dir,
                    &mut recovery_generation,
                )?;
                staged_batch = false;
            }
            match record.entry {
                WalEntry::TransactionApply {
                    transaction_id,
                    entry,
                } => match *entry {
                    WalEntry::RelationalBatch { batch } => {
                        journal.validate_relational_projection(transaction_id, &batch)?;
                        if !replay::check_frontier(&state, &batch)? {
                            return Ok(());
                        }
                        let mut candidate = state.clone();
                        let mut candidate_generation = recovery_generation
                            .as_ref()
                            .map(RelationalCheckpoint::try_clone)
                            .transpose()?;
                        apply_batch_with_flush(&mut candidate, &batch, &mut |state| {
                            if state.retained_bytes() >= memory::flush_threshold() {
                                checkpoint::stage_recovery_rows(
                                    state,
                                    batch.sequence,
                                    &mut candidate_generation,
                                    &segment_dir,
                                    &checkpoint_path,
                                )?;
                                staged_batch = true;
                            }
                            Ok(())
                        })?;
                        state = candidate;
                        recovery_generation = candidate_generation;
                    }
                    other => {
                        return Err(GaussError::WalCorruption {
                            path: wal_dir.display().to_string(),
                            message: format!(
                                "non-relational transaction in relational WAL: {other:?}"
                            ),
                        });
                    }
                },
                other => {
                    return Err(GaussError::WalCorruption {
                        path: wal_dir.display().to_string(),
                        message: format!("invalid relational WAL entry: {other:?}"),
                    });
                }
            }
            Ok(())
        })?;
        if staged_batch || state.retained_bytes() >= memory::flush_threshold() {
            checkpoint::flush_recovery_prefix(
                &mut state,
                recovery.end_lsn,
                &checkpoint_path,
                &segment_dir,
                &mut recovery_generation,
            )?;
        }
        let mut wal = Wal::open(&wal_dir)?;
        if let Some(checkpoint) = read_relational_checkpoint(&checkpoint_path)? {
            wal.drop_prefix(checkpoint.wal_watermark)?;
        }
        Ok(Arc::new_cyclic(|weak| Self {
            state: RwLock::new(state),
            wal: std::sync::Mutex::new(wal),
            journal,
            wal_dir,
            checkpoint_path,
            checkpoint: std::sync::Mutex::new(()),
            self_weak: weak.clone(),
            checkpoint_worker: std::sync::Mutex::new(None),
            checkpoint_cancel: Arc::new(AtomicBool::new(false)),
            checkpoint_lease: std::sync::Mutex::new(None),
            interactive: InteractiveSessions::default(),
            snapshots: SnapshotRegistry::default(),
            intents: IntentManager::default(),
        }))
    }

    pub fn table_definitions(&self) -> Vec<TableDefinition> {
        self.state
            .read()
            .tables
            .values()
            .map(|table| table.definition.as_ref().clone())
            .collect()
    }

    /// Low-level storage execution. The caller must durably project the audit
    /// from `execution.committed`, then mark `ProjectionKind::Audit` in the
    /// journal. Pending audit work retains its PREPARE for recovery. Prefer
    /// `Db::execute_sql_owned`, which completes this lifecycle and owns output.
    pub fn execute(&self, request: SqlExecutionRequest) -> Result<RelationalExecution> {
        self.execute_with_audit(request, &AuditContext::embedded())
    }

    pub fn execute_with_audit(
        &self,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
    ) -> Result<RelationalExecution> {
        self.execute_scoped_with_audit(request, audit_context, None, None)
    }

    pub fn execute_with_audit_cancellable(
        &self,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
        cancellation: Arc<AtomicBool>,
    ) -> Result<RelationalExecution> {
        with_sql_cancellation(cancellation, || {
            self.execute_scoped_with_audit(request, audit_context, None, None)
        })
    }

    #[cfg(test)]
    pub(crate) fn execute_authorized_with_audit(
        &self,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
    ) -> Result<RelationalExecution> {
        let tenant = audit_context
            .tenant_id
            .as_deref()
            .ok_or(SecurityError::Forbidden)?;
        self.execute_scoped_with_audit(request, audit_context, Some(tenant), None)
    }

    pub(crate) fn execute_authorized_with_audit_cancellable(
        &self,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
        cancellation: Arc<AtomicBool>,
        db: &crate::Db,
        identity: &AuthenticatedIdentity,
    ) -> Result<RelationalExecution> {
        with_sql_cancellation(cancellation, || {
            let tenant = audit_context
                .tenant_id
                .as_deref()
                .ok_or(SecurityError::Forbidden)?;
            self.execute_scoped_with_audit(
                request,
                audit_context,
                Some(tenant),
                Some((db, identity)),
            )
        })
    }

    fn execute_scoped_with_audit(
        &self,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
        protected_tenant: Option<&str>,
        reference_scope: Option<(&crate::Db, &AuthenticatedIdentity)>,
    ) -> Result<RelationalExecution> {
        let _admission = SQL_ADMISSION.acquire()?;
        check_sql_cancelled()?;
        let idempotency = if let Some(key) = request.idempotency_key.as_deref() {
            if Self::request_is_read_only(&request)? {
                return Err(invalid("idempotency_key requires a mutating SQL request"));
            }
            match self.journal.begin_idempotent(
                key,
                audit_context,
                "sql_batch",
                &request.statements,
                check_sql_cancelled,
            )? {
                crate::transaction_journal::IdempotencyAdmission::Execute(guard) => Some(guard),
                crate::transaction_journal::IdempotencyAdmission::Replay(receipt) => {
                    return replay_standalone_sql_receipt(self, receipt, reference_scope, &request);
                }
            }
        } else {
            None
        };
        self.collect_mvcc_garbage()?;
        let statement_count = request.statements.len();
        let retry_id = request.retry_id.clone();
        let base = self.state.read().clone();
        let snapshot_pin = self.snapshots.pin(base.sequence)?;
        let mut prepared = prepare_execution(
            base,
            request,
            true,
            true,
            protected_tenant,
            reference_scope.map(|(_, identity)| identity),
            audit_context.transport == "chironql-ml",
        )?;
        prepared
            .reference_writes
            .extend(record_references::result_references(&prepared.results));
        check_sql_cancelled()?;
        let result = if prepared.mutations.is_empty() && idempotency.is_none() {
            let response_memory = output::reserve_results(&prepared.results)?;
            let response = RelationalExecution {
                response: SqlExecutionResponse {
                    transaction_id: None,
                    snapshot: prepared.snapshot,
                    committed: true,
                    outcome: SqlOutcome::Committed,
                    commit_sequence: None,
                    retryable: false,
                    results: prepared.results,
                },
                committed: None,
                projection_error: None,
                response_memory,
            };
            if let Some((db, identity)) = reference_scope {
                db.with_standalone_reference_commit(identity, &prepared.reference_writes, || {
                    Ok(response)
                })
            } else {
                Ok(response)
            }
        } else {
            self.commit_prepared(
                prepared,
                audit_context,
                statement_count,
                retry_id.as_deref(),
                idempotency
                    .as_ref()
                    .map(|claim| SqlCommitReceipt::Standalone {
                        claim,
                        table_authority: reference_scope
                            .is_some_and(|(_, identity)| identity.supports_table_grants()),
                    }),
                reference_scope,
            )
        };
        drop(snapshot_pin);
        if result
            .as_ref()
            .is_ok_and(|execution| execution.committed.is_some())
        {
            self.collect_after_decision();
        }
        result
    }

    /// Commit relational mutations together with prevalidated vector/graph
    /// collection batches under one installation-journal decision.
    ///
    /// The caller holds every affected collection write guard while this
    /// method holds the relational publication guard. The callback appends
    /// and applies each collection projection. The relational state is made
    /// visible only after all collection projections succeed, and the shared
    /// storage marker is written only after both sides are visible.
    pub(crate) fn execute_multimodel_with_projection<F>(
        &self,
        request: SqlExecutionRequest,
        collections: Vec<MultiModelCollectionBatch>,
        audit_context: &AuditContext,
        protected_tenant: Option<&str>,
        receipt: Option<crate::db::multimodel::CommitReceipt<'_>>,
        project_collections: F,
    ) -> Result<RelationalExecution>
    where
        F: FnOnce(TransactionId, &[MultiModelCollectionBatch]) -> Result<()>,
    {
        if request.idempotency_key.is_some()
            != receipt
                .as_ref()
                .is_some_and(|receipt| receipt.claim.is_some())
        {
            return Err(invalid(
                "multi-model idempotency claim is missing or unexpected",
            ));
        }
        let _admission = SQL_ADMISSION.acquire()?;
        if request.statements.is_empty() {
            return Err(invalid(
                "multi-model transaction requires at least one SQL mutation",
            ));
        }
        for statement in &request.statements {
            let analysis = Self::analyze_statement(&statement.sql)?;
            if !matches!(
                analysis.kind,
                SqlStatementKind::Insert | SqlStatementKind::Update | SqlStatementKind::Delete
            ) {
                return Err(invalid(
                    "multi-model transaction SQL supports INSERT, UPDATE, and DELETE only",
                ));
            }
        }
        self.collect_mvcc_garbage()?;
        let statement_count = request.statements.len();
        let retry_id = request.retry_id.clone();
        let base = self.state.read().clone();
        let snapshot_pin = self.snapshots.pin(base.sequence)?;
        let prepared = prepare_execution(base, request, true, true, protected_tenant, None, false)?;
        if prepared.mutations.is_empty() {
            return Err(invalid(
                "multi-model transaction SQL produced no relational mutation",
            ));
        }
        let _intent_guard = self
            .intents
            .acquire(prepared.intents.clone(), INTENT_WAIT_TIMEOUT)?;
        let mut guard = self.state.write();
        let commit_sequence = guard
            .sequence
            .checked_add(1)
            .ok_or_else(|| GaussError::ResourceExhausted("relational sequence overflow".into()))?;
        let mutations = if guard.sequence != prepared.snapshot {
            validate_rebase(&prepared, &guard)?;
            rebase_mutations(&prepared, &guard)?
        } else {
            prepared.mutations.clone()
        };
        let relational = RelationalBatch {
            sequence: commit_sequence,
            mutations,
        };
        let mut candidate = guard.clone();
        apply_batch(&mut candidate, &relational)?;
        let collection_names = collections
            .iter()
            .map(|projection| projection.collection.clone())
            .collect::<Vec<_>>();
        let write_set = MultiModelBatch {
            version: MULTI_MODEL_BATCH_VERSION,
            relational: relational.clone(),
            collections,
        };
        write_set.validate()?;
        let response_memory = output::reserve_results(&prepared.results)?;
        let response = SqlExecutionResponse {
            transaction_id: None,
            snapshot: commit_sequence,
            committed: true,
            outcome: SqlOutcome::Committed,
            commit_sequence: Some(commit_sequence),
            retryable: false,
            results: prepared.results,
        };
        let target = TransactionTarget::MultiModel {
            collections: collection_names,
        };
        let mutation = WalEntry::MultiModelBatch {
            batch: write_set.clone(),
        };
        let audit = TransactionAudit::mutation(
            "multi_model_transaction",
            None,
            audit_context,
            serde_json::json!({
                "statement_count": statement_count,
                "collection_count": write_set.collections.len(),
                "retry_id": retry_id,
                "relational_sequence": commit_sequence,
                "domains": ["relational", "vector", "graph"],
            }),
        );
        let transaction = match receipt {
            Some(receipt) => receipt.commit(
                &self.journal,
                target,
                mutation,
                audit,
                &response,
                |access, reads, retired| {
                    record_references::validate(
                        &guard,
                        &candidate,
                        &relational,
                        access,
                        reads,
                        retired,
                    )
                },
            )?,
            None => self.journal.commit(target, mutation, audit)?,
        };
        let transaction_id = transaction.prepare.transaction_id;
        let mut relational_watermark = None;
        let mut projection = crate::failpoint::check("multi_model.before_relational_projection")
            .and_then(|()| {
                self.wal
                    .lock()
                    .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))
            })
            .and_then(|mut wal| {
                let watermark = wal.append(&WalEntry::TransactionApply {
                    transaction_id,
                    entry: Box::new(WalEntry::RelationalBatch {
                        batch: relational.clone(),
                    }),
                })?;
                relational_watermark = Some(watermark);
                crate::failpoint::check("multi_model.after_relational_wal")?;
                project_collections(transaction_id, &write_set.collections)
            });
        if projection.is_ok() {
            *guard = candidate;
            projection =
                crate::failpoint::check("multi_model.before_storage_marker").and_then(|()| {
                    self.journal
                        .mark_projected(transaction_id, ProjectionKind::Storage)
                });
            if projection.is_ok()
                && let Err(error) = crate::failpoint::check("multi_model.after_storage_marker")
            {
                projection = Err(error);
            }
        }
        let checkpoint = relational_watermark.and_then(|watermark| {
            (projection.is_ok() && guard.checkpoint_required())
                .then(|| capture_relational_checkpoint(&guard, watermark))
        });
        drop(guard);
        drop(snapshot_pin);
        if let Some(checkpoint) = checkpoint {
            self.checkpoint_after_commit(checkpoint, "multi-model");
        }
        let execution = RelationalExecution {
            response: SqlExecutionResponse {
                transaction_id: Some(transaction_id.to_string()),
                ..response
            },
            committed: Some(transaction),
            projection_error: projection.err(),
            response_memory,
        };
        self.collect_after_decision();
        Ok(execution)
    }

    fn commit_prepared(
        &self,
        mut prepared: PreparedRelationalExecution,
        audit_context: &AuditContext,
        statement_count: usize,
        retry_id: Option<&str>,
        idempotency: Option<SqlCommitReceipt<'_>>,
        reference_scope: Option<(&crate::Db, &AuthenticatedIdentity)>,
    ) -> Result<RelationalExecution> {
        let references = std::mem::take(&mut prepared.reference_writes);
        if let Some((db, identity)) = reference_scope
            && !references.is_empty()
        {
            return db.with_standalone_reference_commit(identity, &references, || {
                self.commit_prepared_under_reference_gate(
                    prepared,
                    audit_context,
                    statement_count,
                    retry_id,
                    idempotency,
                )
            });
        }
        self.commit_prepared_under_reference_gate(
            prepared,
            audit_context,
            statement_count,
            retry_id,
            idempotency,
        )
    }

    fn commit_prepared_under_reference_gate(
        &self,
        prepared: PreparedRelationalExecution,
        audit_context: &AuditContext,
        statement_count: usize,
        retry_id: Option<&str>,
        idempotency: Option<SqlCommitReceipt<'_>>,
    ) -> Result<RelationalExecution> {
        check_sql_cancelled()?;
        let _intent_guard = self
            .intents
            .acquire(prepared.intents.clone(), INTENT_WAIT_TIMEOUT)?;
        check_sql_cancelled()?;
        let mut guard = self.state.write();
        let commit_sequence = guard
            .sequence
            .checked_add(1)
            .ok_or_else(|| GaussError::ResourceExhausted("relational sequence overflow".into()))?;
        let mutations = if !prepared.mutations.is_empty() && guard.sequence != prepared.snapshot {
            validate_rebase(&prepared, &guard)?;
            rebase_mutations(&prepared, &guard)?
        } else {
            prepared.mutations.clone()
        };
        let batch = RelationalBatch {
            sequence: commit_sequence,
            mutations,
        };
        // Validate the exact candidate state before recording the durable
        // decision. The state write guard prevents another commit from
        // invalidating UNIQUE/FK checks between validation and publication.
        let mut candidate = guard.clone();
        apply_batch(&mut candidate, &batch)?;
        // Cancellation is accepted only before the durable journal decision.
        // Once journal.commit returns, the transaction must be reported using
        // its durable outcome rather than changed into a cancellation error.
        check_sql_cancelled()?;
        let response_memory = output::reserve_results(&prepared.results)?;
        let target = TransactionTarget::Relational;
        let mutation = WalEntry::RelationalBatch {
            batch: batch.clone(),
        };
        let audit = TransactionAudit::mutation(
            "sql_transaction",
            None,
            audit_context,
            serde_json::json!({"statement_count": statement_count, "retry_id": retry_id, "relational_sequence": commit_sequence}),
        );
        let transaction = if let Some(claim) = idempotency {
            claim.commit(commit_sequence, &prepared, target, mutation, audit)?
        } else {
            self.journal.commit(target, mutation, audit)?
        };
        let transaction_id = transaction.prepare.transaction_id;
        let projection = self
            .wal
            .lock()
            .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))
            .and_then(|mut wal| {
                let watermark = wal.append(&WalEntry::TransactionApply {
                    transaction_id,
                    entry: Box::new(WalEntry::RelationalBatch {
                        batch: batch.clone(),
                    }),
                })?;
                self.journal
                    .mark_projected(transaction_id, ProjectionKind::Storage)?;
                Ok(watermark)
            });
        *guard = candidate;
        let checkpoint = projection.as_ref().ok().and_then(|wal_watermark| {
            guard
                .checkpoint_required()
                .then(|| capture_relational_checkpoint(&guard, *wal_watermark))
        });
        drop(guard);
        if let Some(checkpoint) = checkpoint {
            self.checkpoint_after_commit(checkpoint, "relational");
        }
        Ok(RelationalExecution {
            response: SqlExecutionResponse {
                transaction_id: Some(transaction_id.to_string()),
                snapshot: commit_sequence,
                committed: true,
                outcome: SqlOutcome::Committed,
                commit_sequence: Some(commit_sequence),
                retryable: false,
                results: prepared.results,
            },
            committed: Some(transaction),
            projection_error: projection.err(),
            response_memory,
        })
    }

    /// Persist an immutable relational state image and reclaim only the WAL
    /// prefix covered by that image. The transaction journal remains the
    /// commit authority; this checkpoint only bounds restart work.
    pub fn checkpoint(&self) -> Result<u64> {
        self.collect_mvcc_garbage()?;
        let guard = self.state.read();
        let wal_watermark = self
            .wal
            .lock()
            .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))?
            .len()?;
        let checkpoint = capture_relational_checkpoint(&guard, wal_watermark)?;
        drop(guard);
        self.publish_checkpoint(&checkpoint)?;
        Ok(checkpoint.manifest.sequence)
    }

    /// Backfill private RECORD_REF indexes while the installation is offline.
    /// The catalog and its row/index runs become authoritative at one manifest
    /// replacement; no transaction sequence or user-visible schema changes.
    pub(crate) fn migrate_reference_indexes_offline(&self) -> Result<usize> {
        let _checkpoint = self.checkpoint.lock().map_err(|_| {
            GaussError::WalUnavailable("relational checkpoint lock poisoned".into())
        })?;
        let mut state = self.state.write();
        let mut candidate = state.clone();
        let mut migrated = 0;
        let names = candidate.tables.keys().cloned().collect::<Vec<_>>();
        for name in names {
            let previous = Arc::clone(&candidate.tables[&name]);
            if previous.definition.tenant_id.is_none()
                || !previous.definition.columns.iter().any(|column| {
                    matches!(column.data_type, RelationalType::RecordRef { .. })
                        && !previous
                            .definition
                            .reference_index_ids
                            .contains_key(&column.name)
                })
            {
                continue;
            }
            let mut definition = previous.definition.as_ref().clone();
            assign_missing_catalog_ids(&mut candidate, &mut definition)?;
            validate_definition(&definition)?;
            let mut replacement = TableState::empty(definition, Arc::clone(&previous.directory))?;
            replacement.rows = previous.rows.clone();
            replacement.next_row_id = previous.next_row_id;
            candidate.tables.insert(&name, Arc::new(replacement))?;
            migrated += 1;
        }
        if migrated == 0 {
            return Ok(0);
        }
        let wal_watermark = self
            .wal
            .lock()
            .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))?
            .len()?;
        let captured = capture_relational_checkpoint(&candidate, wal_watermark)?;
        let segment_dir = self
            .checkpoint_path
            .parent()
            .expect("relational checkpoint has a parent")
            .join("segments");
        let existing = read_relational_checkpoint(&self.checkpoint_path)?;
        let persisted =
            checkpoint::materialize_migration(&captured, existing.as_ref(), &segment_dir)?;
        crate::failpoint::check("relational_migration.after_segments")?;
        let backings = prepare_checkpoint_backings(&persisted, &segment_dir)?;
        let permit = candidate.tables.prepare_install()?;
        write_relational_checkpoint(&self.checkpoint_path, &persisted)?;
        assert!(install_checkpoint_backings(
            &mut candidate,
            &persisted,
            backings,
            permit
        ));
        *state = candidate;
        crate::failpoint::check("relational_migration.after_manifest")?;
        self.wal
            .lock()
            .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))?
            .drop_prefix(wal_watermark)?;
        let retained = recovered_index_segment_names(&state);
        cleanup_unreferenced_checkpoint_segments(&segment_dir, &persisted, &retained);
        Ok(migrated)
    }

    pub(crate) fn ensure_no_live_references(
        &self,
        tenant: &str,
        collection: &str,
        ids: &BTreeSet<String>,
    ) -> Result<()> {
        let state = self.state.read();
        record_references::ensure_unreferenced(&state, tenant, collection, ids)
    }

    pub(crate) fn authorize_reference_results(
        &self,
        db: &crate::Db,
        identity: &AuthenticatedIdentity,
        results: &[SqlResult],
    ) -> Result<()> {
        let references = record_references::result_references(results);
        db.with_standalone_reference_commit(identity, &references, || Ok(()))
    }

    pub(crate) fn result_references(results: &[SqlResult]) -> BTreeSet<crate::RecordRef> {
        record_references::result_references(results)
    }

    /// The Db installation lease stays owned by the worker until its private
    /// checkpoint output is either published or discarded. Direct embedded
    /// engines keep synchronous checkpoints and their existing drop semantics.
    pub(crate) fn enable_background_checkpoints(
        &self,
        lease: Arc<dyn Send + Sync + std::fmt::Debug>,
    ) {
        *self.checkpoint_lease.lock().unwrap() = Some(lease);
    }

    pub(crate) fn cancel_and_drain_checkpoint(&self, deadline: Instant) -> bool {
        self.checkpoint_cancel.store(true, AtomicOrdering::Release);
        loop {
            let mut slot = self.checkpoint_worker.lock().unwrap();
            if slot
                .as_ref()
                .is_none_or(std::thread::JoinHandle::is_finished)
            {
                if let Some(worker) = slot.take() {
                    let _ = worker.join();
                }
                return true;
            }
            drop(slot);
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn checkpoint_after_commit(
        &self,
        checkpoint: Result<CapturedRelationalCheckpoint>,
        operation: &'static str,
    ) {
        let checkpoint = match checkpoint {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                metrics::counter!("chirondb_relational_checkpoint_failures_total").increment(1);
                tracing::warn!(%operation, %error,
                    "could not capture relational checkpoint; committed WAL remains authoritative");
                return;
            }
        };
        let lease = self.checkpoint_lease.lock().unwrap().clone();
        if let Some(lease) = lease {
            if self.checkpoint_cancel.load(AtomicOrdering::Acquire) {
                return;
            }
            let mut slot = self.checkpoint_worker.lock().unwrap();
            if slot.as_ref().is_some_and(|worker| !worker.is_finished()) {
                return;
            }
            if let Some(worker) = slot.take() {
                let _ = worker.join();
            }
            let Some(engine) = self.self_weak.upgrade() else {
                return;
            };
            let cancel = Arc::clone(&self.checkpoint_cancel);
            let flush_threshold = memory::flush_threshold();
            let initial_sequence = checkpoint.manifest.sequence;
            match std::thread::Builder::new()
                .name("chirondb-relational-checkpoint".into())
                .spawn(move || {
                    let _lease = lease;
                    metrics::gauge!("chirondb_relational_checkpoint_in_flight").set(1.0);
                    let result = with_sql_cancellation(cancel.clone(), || {
                        engine.drain_background_checkpoint(checkpoint, flush_threshold)
                    });
                    metrics::gauge!("chirondb_relational_checkpoint_in_flight").set(0.0);
                    if let Err(error) = result
                        && !cancel.load(AtomicOrdering::Acquire)
                    {
                        metrics::counter!("chirondb_relational_checkpoint_failures_total")
                            .increment(1);
                        tracing::warn!(initial_sequence, %operation, %error,
                            "background relational checkpoint failed; WAL remains authoritative");
                    }
                }) {
                Ok(worker) => *slot = Some(worker),
                Err(error) => {
                    metrics::counter!("chirondb_relational_checkpoint_failures_total").increment(1);
                    tracing::warn!(%operation, %error,
                        "could not start relational checkpoint; WAL remains authoritative");
                }
            }
        } else if let Err(error) = self.publish_checkpoint(&checkpoint) {
            metrics::counter!("chirondb_relational_checkpoint_failures_total").increment(1);
            tracing::warn!(sequence = checkpoint.manifest.sequence, %operation, %error,
                "relational checkpoint failed; WAL remains authoritative");
        }
    }

    fn publish_checkpoint(&self, checkpoint: &CapturedRelationalCheckpoint) -> Result<()> {
        let _checkpoint = self.checkpoint.lock().map_err(|_| {
            GaussError::WalUnavailable("relational checkpoint lock poisoned".into())
        })?;
        let segment_dir = self
            .checkpoint_path
            .parent()
            .expect("relational checkpoint has a parent")
            .join("segments");
        let existing = read_relational_checkpoint(&self.checkpoint_path)?;
        if let Some(current) = existing
            .as_ref()
            .filter(|current| current.sequence >= checkpoint.manifest.sequence)
        {
            let backings = prepare_checkpoint_backings(current, &segment_dir)?;
            let permit = self.state.read().tables.prepare_install()?;
            if !install_checkpoint_backings(&mut self.state.write(), current, backings, permit) {
                return Ok(());
            }
            self.wal
                .lock()
                .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))?
                .drop_prefix(current.wal_watermark)?;
            let retained_backings = recovered_index_segment_names(&self.state.read());
            cleanup_unreferenced_checkpoint_segments(&segment_dir, current, &retained_backings);
            return Ok(());
        }
        let persisted =
            materialize_checkpoint_segments(checkpoint, existing.as_ref(), &segment_dir)?;
        crate::failpoint::check("relational_checkpoint.after_segments")?;
        let backings = prepare_live_checkpoint_backings(
            &persisted,
            checkpoint,
            existing.as_ref(),
            &segment_dir,
        )?;
        let permit = self.state.read().tables.prepare_install()?;
        write_relational_checkpoint(&self.checkpoint_path, &persisted)?;
        crate::failpoint::check("relational_checkpoint.after_manifest")?;
        if !install_checkpoint_backings(&mut self.state.write(), &persisted, backings, permit) {
            return Ok(());
        }
        self.wal
            .lock()
            .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))?
            .drop_prefix(checkpoint.manifest.wal_watermark)?;
        crate::failpoint::check("relational_checkpoint.after_wal_reclaim")?;
        let retained_backings = recovered_index_segment_names(&self.state.read());
        cleanup_unreferenced_checkpoint_segments(&segment_dir, &persisted, &retained_backings);
        metrics::counter!("chirondb_relational_checkpoints_total").increment(1);
        Ok(())
    }

    pub fn begin_interactive(
        &self,
        audit_context: &AuditContext,
    ) -> Result<SqlTransactionHandleResponse> {
        self.begin_interactive_scoped(audit_context, false)
    }

    pub(crate) fn begin_interactive_authorized(
        &self,
        audit_context: &AuditContext,
    ) -> Result<SqlTransactionHandleResponse> {
        if audit_context.tenant_id.is_none() {
            return Err(SecurityError::Forbidden.into());
        }
        self.begin_interactive_scoped(audit_context, true)
    }

    fn begin_interactive_scoped(
        &self,
        audit_context: &AuditContext,
        protected_tenant: bool,
    ) -> Result<SqlTransactionHandleResponse> {
        self.collect_mvcc_garbage()?;
        let base = self.state.read().clone();
        let snapshot = base.sequence;
        let snapshot_pin = self.snapshots.pin(snapshot)?;
        let handle = TransactionId::new().to_string();
        self.interactive.insert(
            handle.clone(),
            InteractiveTransaction {
                base,
                history: history::History::new()?,
                protected_tenant,
                last_activity: Instant::now(),
                aborted: false,
                _snapshot_pin: snapshot_pin,
            },
            audit_context,
        )?;
        Ok(SqlTransactionHandleResponse {
            transaction_id: Some(handle.clone()),
            handle,
            snapshot,
            state: SqlTransactionState::Active,
        })
    }

    pub fn execute_interactive(
        &self,
        handle: &str,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
    ) -> Result<SqlExecutionResponse> {
        self.execute_interactive_inner(handle, request, audit_context, None)
            .map(SqlResponse::into_dto)
    }

    /// Resolve PgWire routing against this session's private catalog. Savepoint
    /// rollback truncates `statements`, so replaying only DDL names cannot
    /// resurrect a table that the session has rolled back.
    pub(crate) fn interactive_has_table(
        &self,
        handle: &str,
        audit_context: &AuditContext,
        table: &str,
    ) -> Result<bool> {
        let entry = self.interactive.get(handle, audit_context)?;
        let state = entry.lock(handle)?;
        let session = state.as_ref().expect("active session checked under lock");
        let mut tables = session
            .base
            .tables
            .iter()
            .filter(|(_, table)| {
                table.definition.tenant_id.as_deref() == entry.tenant_id.as_deref()
            })
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        for item in session.history.statements() {
            let ParsedRelationalStatement::Sql(statement) = parse_relational_statement(&item.sql)?
            else {
                continue;
            };
            match statement.as_ref() {
                Statement::CreateTable(create) => {
                    tables.insert(normalize_name(&create.name));
                }
                Statement::Drop {
                    object_type: ObjectType::Table,
                    names,
                    ..
                } => {
                    for name in names {
                        tables.remove(&normalize_name(name));
                    }
                }
                Statement::AlterTable(alter) => {
                    let mut old = normalize_name(&alter.name);
                    for operation in &alter.operations {
                        if let AlterTableOperation::RenameTable { table_name } = operation {
                            let name = match table_name {
                                RenameTableNameKind::As(name) | RenameTableNameKind::To(name) => {
                                    name
                                }
                            };
                            let renamed = normalize_name(name);
                            if tables.remove(&old) {
                                tables.insert(renamed.clone());
                            }
                            old = renamed;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(tables.contains(table))
    }

    pub fn execute_interactive_cancellable(
        &self,
        handle: &str,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
        cancellation: Arc<AtomicBool>,
    ) -> Result<SqlExecutionResponse> {
        self.execute_interactive_cancellable_owned(handle, request, audit_context, cancellation)
            .map(SqlResponse::into_dto)
    }

    pub(crate) fn execute_interactive_cancellable_owned(
        &self,
        handle: &str,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
        cancellation: Arc<AtomicBool>,
    ) -> Result<SqlResponse> {
        with_sql_cancellation(cancellation, || {
            self.execute_interactive_inner(handle, request, audit_context, None)
        })
    }

    pub(crate) fn execute_interactive_authorized_cancellable(
        &self,
        handle: &str,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
        cancellation: Arc<AtomicBool>,
        identity: &AuthenticatedIdentity,
    ) -> Result<SqlResponse> {
        with_sql_cancellation(cancellation, || {
            self.execute_interactive_inner(handle, request, audit_context, Some(identity))
        })
    }

    fn execute_interactive_inner(
        &self,
        handle: &str,
        request: SqlExecutionRequest,
        audit_context: &AuditContext,
        identity: Option<&AuthenticatedIdentity>,
    ) -> Result<SqlResponse> {
        if request.idempotency_key.is_some() {
            return Err(invalid(
                "interactive statements do not accept idempotency_key; reconcile their commit instead",
            ));
        }
        check_sql_cancelled()?;
        enforce_serialized_limit(&request, MAX_DECODED_REQUEST_BYTES, "decoded SQL request")?;
        if request.statements.is_empty() {
            return Err(invalid("SQL request must contain at least one statement"));
        }
        if request.statements.len() > MAX_STATEMENTS_PER_REQUEST {
            return Err(GaussError::ResourceExhausted(format!(
                "SQL request has {} statements; maximum is {MAX_STATEMENTS_PER_REQUEST}",
                request.statements.len()
            )));
        }
        let entry = self.interactive.get(handle, audit_context)?;
        let mut state = entry.lock(handle)?;
        // Same-session waiters consume no global execution reservation.
        let _admission = SQL_ADMISSION.acquire()?;
        let session = state.as_mut().expect("active session checked under lock");
        if session.protected_tenant != identity.is_some()
            || identity.is_some_and(|identity| {
                identity.principal().id != audit_context.principal_id
                    || Some(identity.principal().tenant.as_str())
                        != audit_context.tenant_id.as_deref()
            })
        {
            return Err(SecurityError::Forbidden.into());
        }
        let mut results = Vec::with_capacity(request.statements.len());
        for statement in request.statements {
            check_sql_cancelled()?;
            let control = parse_interactive_control(&statement.sql)?;
            if session.aborted && !matches!(control, Some(InteractiveControl::RollbackTo(_))) {
                return Err(invalid(format!(
                    "interactive transaction {handle} is aborted; use ROLLBACK TO SAVEPOINT or roll it back"
                )));
            }
            match control {
                Some(InteractiveControl::Savepoint(name)) => {
                    if !statement.parameters.is_empty() {
                        return Err(invalid("SAVEPOINT does not accept parameters"));
                    }
                    if let Err(error) = session.history.push_savepoint(name) {
                        session.aborted = true;
                        return Err(error);
                    }
                    results.push(SqlResult::Definition {
                        affected_objects: 0,
                    });
                }
                Some(InteractiveControl::RollbackTo(name)) => {
                    if !statement.parameters.is_empty() {
                        return Err(invalid("ROLLBACK TO SAVEPOINT does not accept parameters"));
                    }
                    let index = session
                        .history
                        .savepoints()
                        .iter()
                        .rposition(|(saved, _)| saved == &name)
                        .ok_or_else(|| invalid(format!("savepoint {name} does not exist")))?;
                    let statement_count = session.history.savepoints()[index].1;
                    session.history.truncate_statements(statement_count);
                    session.history.truncate_savepoints(index + 1);
                    session.aborted = false;
                    results.push(SqlResult::Definition {
                        affected_objects: 0,
                    });
                }
                Some(InteractiveControl::Release(name)) => {
                    if !statement.parameters.is_empty() {
                        return Err(invalid("RELEASE SAVEPOINT does not accept parameters"));
                    }
                    let index = session
                        .history
                        .savepoints()
                        .iter()
                        .rposition(|(saved, _)| saved == &name)
                        .ok_or_else(|| invalid(format!("savepoint {name} does not exist")))?;
                    session.history.truncate_savepoints(index);
                    results.push(SqlResult::Definition {
                        affected_objects: 0,
                    });
                }
                None => {
                    if session.history.statements().len() >= MAX_STATEMENTS_PER_REQUEST {
                        session.aborted = true;
                        return Err(GaussError::ResourceExhausted(format!(
                            "interactive transaction exceeds {MAX_STATEMENTS_PER_REQUEST} statements"
                        )));
                    }
                    let previous_count = session.history.statements().len();
                    let execution = (|| {
                        session.history.push_statement(statement)?;
                        let (replay, _history_memory) =
                            session.history.copy_request(request.retry_id.as_deref())?;
                        prepare_execution(
                            session.base.clone(),
                            replay,
                            true,
                            false,
                            session
                                .protected_tenant
                                .then_some(entry.tenant_id.as_deref())
                                .flatten(),
                            identity,
                            false,
                        )
                    })();
                    let mut prepared = match execution {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            session.history.truncate_statements(previous_count);
                            session.aborted = true;
                            return Err(error);
                        }
                    };
                    results.push(
                        prepared
                            .results
                            .pop()
                            .expect("one result per SQL statement"),
                    );
                }
            }
        }
        session.last_activity = Instant::now();
        let response_memory = match output::reserve_results(&results) {
            Ok(memory) => memory,
            Err(error) => {
                session.aborted = true;
                return Err(error);
            }
        };
        Ok(SqlResponse::new(
            SqlExecutionResponse {
                transaction_id: Some(handle.to_string()),
                snapshot: session.base.sequence,
                committed: false,
                outcome: SqlOutcome::Unknown,
                commit_sequence: None,
                retryable: false,
                results,
            },
            response_memory,
        ))
    }

    pub fn commit_interactive(
        &self,
        handle: &str,
        audit_context: &AuditContext,
    ) -> Result<RelationalExecution> {
        self.commit_interactive_inner(handle, audit_context, None, None)
    }

    pub fn commit_interactive_cancellable(
        &self,
        handle: &str,
        audit_context: &AuditContext,
        cancellation: Arc<AtomicBool>,
    ) -> Result<RelationalExecution> {
        with_sql_cancellation(cancellation, || {
            self.commit_interactive_inner(handle, audit_context, None, None)
        })
    }

    pub(crate) fn commit_interactive_authorized(
        &self,
        db: &crate::Db,
        identity: &AuthenticatedIdentity,
        handle: &str,
        audit_context: &AuditContext,
        cancellation: Arc<AtomicBool>,
    ) -> Result<RelationalExecution> {
        with_sql_cancellation(cancellation, || {
            self.commit_interactive_inner(handle, audit_context, Some(identity), Some(db))
        })
    }

    fn commit_interactive_inner(
        &self,
        handle: &str,
        audit_context: &AuditContext,
        identity: Option<&AuthenticatedIdentity>,
        db: Option<&crate::Db>,
    ) -> Result<RelationalExecution> {
        check_sql_cancelled()?;
        let transaction_id = handle.parse::<TransactionId>()?;
        if identity.is_some_and(|identity| {
            identity.principal().id != audit_context.principal_id
                || Some(identity.principal().tenant.as_str()) != audit_context.tenant_id.as_deref()
        }) {
            return Err(SecurityError::Forbidden.into());
        }
        // The server-issued handle names a frozen private transaction. Its
        // COMMIT request is immutable, so reconnecting clients need only that
        // handle, not a replay of every statement executed in the session.
        let claim = match self.journal.begin_idempotent(
            &format!("interactive:{transaction_id}"),
            audit_context,
            "interactive_sql_commit",
            &transaction_id,
            || {
                check_sql_cancelled()?;
                if let Some(identity) = identity {
                    drop(identity.publication_permit()?);
                }
                Ok(())
            },
        )? {
            crate::transaction_journal::IdempotencyAdmission::Execute(claim) => claim,
            crate::transaction_journal::IdempotencyAdmission::Replay(receipt) => {
                let _admission = SQL_ADMISSION.acquire()?;
                return replay_interactive_sql_receipt(receipt, identity, db);
            }
        };
        let entry = self.interactive.get(handle, audit_context)?;
        // Keep this session's lock/history/pin until the durable outcome is
        // known. Proven pre-PREPARE refusal leaves it available for retry.
        let mut state = entry.lock(handle)?;
        let (mut prepared, statement_count, authorization, _permit, _admission) = {
            let admission = SQL_ADMISSION.acquire()?;
            let session = state.as_ref().expect("active session checked under lock");
            if session.protected_tenant != identity.is_some() {
                return Err(SecurityError::Forbidden.into());
            }
            if session.aborted {
                return Err(invalid(format!(
                    "interactive transaction {handle} is aborted and cannot commit"
                )));
            }
            // Rebuild the frozen private snapshot once under the session lock.
            // Every statement is authorized against the catalog produced by
            // its predecessors before its data stage reads or writes.
            let statement_count = session.history.statements().len();
            let mut prepared = if statement_count == 0 {
                PreparedRelationalExecution {
                    snapshot: session.base.sequence,
                    results: Vec::new(),
                    mutations: Vec::new(),
                    reference_writes: BTreeSet::new(),
                    catalog: session.base.tables.clone(),
                    write_dependencies: Vec::new(),
                    rebasable: true,
                    intents: Vec::new(),
                    authorization: identity
                        .map(|identity| SqlAuthorization::empty(&identity.principal().tenant)),
                }
            } else {
                let (replay, _history_memory) = session.history.copy_request(Some(handle))?;
                prepare_execution(
                    session.base.clone(),
                    replay,
                    true,
                    true,
                    session
                        .protected_tenant
                        .then_some(entry.tenant_id.as_deref())
                        .flatten(),
                    identity,
                    false,
                )?
            };
            // Move the proof out of the frozen preparation; it is held through
            // authorization and borrowed by the interactive durable receipt.
            let authorization = prepared.authorization.take();
            let permit = authorization
                .as_ref()
                .zip(identity)
                .map(|(authorization, identity)| authorization.authorize(identity))
                .transpose()?;
            check_sql_cancelled()?;
            (prepared, statement_count, authorization, permit, admission)
        };
        let decision_started = AtomicBool::new(false);
        let result = (|| {
            check_sql_cancelled()?;
            prepared.results.clear();
            // Even an empty/no-op COMMIT has one durable decision. The caller
            // can reconcile it after the private session disappears on restart.
            self.commit_prepared(
                prepared,
                audit_context,
                statement_count,
                Some(handle),
                Some(SqlCommitReceipt::Interactive {
                    claim: &claim,
                    transaction_id,
                    authorization: authorization.as_ref(),
                    decision_started: &decision_started,
                }),
                db.zip(identity),
            )
        })();
        // Once PREPARE starts, only the journal may reconcile the consumed
        // identity. Retire the private session even for an ambiguous outcome.
        let retired = if result.is_ok() || decision_started.load(AtomicOrdering::Acquire) {
            let retired = state.take();
            if let Err(error) = self.interactive.remove(handle, &entry) {
                tracing::warn!(%error, "could not remove retired SQL session from registry");
            }
            retired
        } else {
            None
        };
        drop(state);
        drop(retired);
        self.collect_after_decision();
        result
    }

    pub fn rollback_interactive(
        &self,
        handle: &str,
        audit_context: &AuditContext,
    ) -> Result<SqlTransactionHandleResponse> {
        let entry = self.interactive.get(handle, audit_context)?;
        let session = {
            let mut state = entry.lock(handle)?;
            let session = state.take().expect("active session checked under lock");
            self.interactive.remove(handle, &entry)?;
            session
        };
        let response = SqlTransactionHandleResponse {
            handle: handle.to_string(),
            snapshot: session.base.sequence,
            state: SqlTransactionState::RolledBack,
            transaction_id: Some(handle.to_string()),
        };
        drop(session);
        self.collect_after_decision();
        Ok(response)
    }

    pub fn request_is_read_only(request: &SqlExecutionRequest) -> Result<bool> {
        for item in &request.statements {
            if parse_interactive_control(&item.sql)?.is_some() {
                continue;
            }
            if Self::analyze_statement(&item.sql)?.class != SqlStatementClass::Read {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn wal_dir(&self) -> &Path {
        &self.wal_dir
    }

    fn collect_after_decision(&self) {
        if let Err(error) = crate::failpoint::check("relational_gc.after_decision")
            .and_then(|()| self.collect_mvcc_garbage())
        {
            metrics::counter!("chirondb_relational_gc_deferred_total").increment(1);
            tracing::warn!(error = %error, "deferred relational GC after completed decision");
        }
    }

    fn collect_mvcc_garbage(&self) -> Result<usize> {
        // Ordinary SQL also retires idle handles, so their snapshot pins cannot
        // retain obsolete row versions until another interactive request arrives.
        self.interactive.expire()?;
        let oldest_snapshot = self.snapshots.oldest()?;
        let mut state = self.state.write();
        let frontier = oldest_snapshot.unwrap_or_else(|| state.sequence.saturating_add(1));
        let mut reclaimed = 0_usize;
        state.tables.try_update_all(|table| {
            let count = table.rows.reclaimable(frontier)?;
            if count == 0 {
                return Ok(None);
            }
            let mut replacement = table.clone();
            match Arc::make_mut(&mut replacement).rows.reclaim(frontier) {
                Ok(()) => {}
                Err(GaussError::ResourceExhausted(_)) => {
                    metrics::counter!("chirondb_relational_gc_deferred_total").increment(1);
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
            reclaimed += count;
            Ok(Some(replacement))
        })?;
        if reclaimed > 0 {
            metrics::counter!("chirondb_relational_mvcc_versions_reclaimed_total")
                .increment(reclaimed as u64);
        }
        Ok(reclaimed)
    }
}

fn extend_statement_authorization(
    state: &RelationalState,
    statement: &Statement,
    authorization: &mut SqlAuthorization,
) -> Result<()> {
    ensure_statement_tenant(state, statement, Some(&authorization.tenant))?;
    let analysis = analyze_parsed_statement(statement)?;
    let mut requirements = BTreeSet::new();
    match analysis.kind {
        SqlStatementKind::Select | SqlStatementKind::Explain => {
            requirements.extend(
                analysis
                    .tables
                    .into_iter()
                    .map(|table| (table, SecurityAction::Read)),
            );
        }
        SqlStatementKind::Insert => {
            let may_update = matches!(statement, Statement::Insert(insert)
                if matches!(&insert.on, Some(OnInsert::OnConflict(conflict))
                    if matches!(conflict.action, OnConflictAction::DoUpdate(_))));
            for table in analysis.tables {
                add_relational_requirement(
                    state,
                    &mut requirements,
                    table.clone(),
                    SecurityAction::Create,
                )?;
                if may_update {
                    add_relational_requirement(
                        state,
                        &mut requirements,
                        table,
                        SecurityAction::Update,
                    )?;
                }
            }
        }
        SqlStatementKind::Update => {
            for table in analysis.tables {
                add_relational_requirement(
                    state,
                    &mut requirements,
                    table,
                    SecurityAction::Update,
                )?;
            }
        }
        SqlStatementKind::Delete => {
            for table in analysis.tables {
                add_relational_requirement(
                    state,
                    &mut requirements,
                    table,
                    SecurityAction::Delete,
                )?;
            }
        }
        SqlStatementKind::CreateTable
        | SqlStatementKind::DropTable
        | SqlStatementKind::AlterTable
        | SqlStatementKind::CreateIndex
        | SqlStatementKind::DropIndex => {
            authorization.schema = true;
        }
        SqlStatementKind::SetConstraints => {}
    }
    for (table, action) in requirements {
        if let Some(definition) = state.tables.get(&table).map(|state| &state.definition)
            && let Some(incarnation) = definition.security_incarnation
        {
            authorization.table_grants.insert(SqlTableRequirement {
                table,
                table_id: definition.table_id,
                incarnation,
                creator_principal_id: definition.creator_principal_id.clone(),
                action,
            });
        } else {
            authorization.grants.insert((table, action));
        }
    }
    Ok(())
}

fn ensure_statement_tenant(
    state: &RelationalState,
    statement: &Statement,
    tenant_id: Option<&str>,
) -> Result<()> {
    let analysis = analyze_parsed_statement(statement)?;
    let mut tables = analysis.tables.into_iter().collect::<BTreeSet<_>>();
    if analysis.kind == SqlStatementKind::DropIndex {
        for index in analysis.indexes {
            for (table_name, table) in state.tables.iter() {
                if table
                    .definition
                    .indexes
                    .iter()
                    .any(|candidate| candidate.name == index)
                {
                    tables.insert(table_name.clone());
                }
            }
        }
    }
    for table_name in tables {
        if let Some(table) = state.tables.get(&table_name)
            && table.definition.tenant_id.as_deref() != tenant_id
        {
            // A tenant boundary is intentionally indistinguishable from a
            // missing object. SQL errors must not reveal another tenant's
            // catalog names.
            return Err(SecurityError::NotFound.into());
        }
    }
    Ok(())
}

fn add_relational_requirement(
    state: &RelationalState,
    requirements: &mut BTreeSet<(String, SecurityAction)>,
    table: String,
    action: SecurityAction,
) -> Result<()> {
    let mut pending = VecDeque::from([(table, action)]);
    while let Some((table_name, action)) = pending.pop_front() {
        if !requirements.insert((table_name.clone(), action)) {
            continue;
        }
        let table = state
            .tables
            .get(&table_name)
            .ok_or(SecurityError::NotFound)?;
        if matches!(action, SecurityAction::Create | SecurityAction::Update) {
            for foreign_key in &table.definition.foreign_keys {
                pending.push_back((foreign_key.referenced_table.clone(), SecurityAction::Read));
            }
        }
        if !matches!(action, SecurityAction::Update | SecurityAction::Delete) {
            continue;
        }
        for (child_name, child) in state.tables.iter() {
            for foreign_key in child
                .definition
                .foreign_keys
                .iter()
                .filter(|foreign_key| foreign_key.referenced_table == table_name)
            {
                let referential_action = if action == SecurityAction::Update {
                    foreign_key.on_update
                } else {
                    foreign_key.on_delete
                };
                let required = match referential_action {
                    ForeignKeyAction::Cascade if action == SecurityAction::Delete => {
                        SecurityAction::Delete
                    }
                    ForeignKeyAction::Cascade
                    | ForeignKeyAction::SetNull
                    | ForeignKeyAction::SetDefault => SecurityAction::Update,
                    ForeignKeyAction::NoAction | ForeignKeyAction::Restrict => SecurityAction::Read,
                };
                pending.push_back((child_name.clone(), required));
            }
        }
    }
    Ok(())
}

struct DecodedSqlReceipt {
    response: SqlExecutionResponse,
    authorization: Option<SqlAuthorization>,
    references: BTreeSet<crate::RecordRef>,
}

fn replay_standalone_sql_receipt(
    engine: &RelationalEngine,
    receipt: crate::transaction_journal::IdempotencyReceipt,
    reference_scope: Option<(&crate::Db, &AuthenticatedIdentity)>,
    request: &SqlExecutionRequest,
) -> Result<RelationalExecution> {
    if receipt.expired
        || !matches!(
            receipt.status.state,
            crate::transaction_journal::TransactionState::Committed
        )
    {
        let _permit = reference_scope
            .map(|(_, identity)| engine.authorize_request(identity, request))
            .transpose()?;
        return replay_sql_receipt(receipt);
    }
    let encoded = receipt
        .response
        .as_ref()
        .ok_or_else(|| invalid("committed idempotency decision has no response"))?;
    // Wrapped receipts always carry version. A decode/admission error must not
    // fall through into a second legacy interpretation or hide overload.
    let saved = if encoded.get("version").is_some() {
        wal_decode::borrowed::<StandaloneCommitReceipt>(encoded)?.try_map(|saved| {
            if !matches!(saved.version, 1 | 2)
                || (saved.version == 2 && saved.authorization.is_none())
            {
                return Err(invalid("unsupported standalone SQL receipt version"));
            }
            Ok(DecodedSqlReceipt {
                response: saved.response,
                authorization: saved.authorization,
                references: saved.references,
            })
        })?
    } else {
        wal_decode::borrowed::<SqlExecutionResponse>(encoded)?.try_map(|response| {
            Ok(DecodedSqlReceipt {
                response,
                authorization: None,
                references: BTreeSet::new(),
            })
        })?
    };
    let _permit = match (saved.authorization.as_ref(), reference_scope) {
        (Some(authorization), Some((_, identity))) => Some(authorization.authorize(identity)?),
        (None, Some((_, identity))) if !identity.has_strict_sql_scopes() => {
            Some(engine.authorize_request(identity, request)?)
        }
        (None, None) => None,
        _ => return Err(SecurityError::Forbidden.into()),
    };
    if let Some((db, identity)) = reference_scope {
        let references = record_references::replay_references(
            receipt.mutation.as_deref(),
            &saved.response,
            saved.references.iter(),
        )?;
        return db.with_standalone_reference_commit(identity, &references, || {
            replay_sql_value(receipt, saved.try_map(|saved| Ok(saved.response))?)
        });
    }
    replay_sql_value(receipt, saved.try_map(|saved| Ok(saved.response))?)
}

fn replay_interactive_sql_receipt(
    receipt: crate::transaction_journal::IdempotencyReceipt,
    identity: Option<&AuthenticatedIdentity>,
    db: Option<&crate::Db>,
) -> Result<RelationalExecution> {
    if receipt.expired
        || !matches!(
            receipt.status.state,
            crate::transaction_journal::TransactionState::Committed
        )
    {
        let _permit = identity
            .map(AuthenticatedIdentity::publication_permit)
            .transpose()?;
        return replay_sql_receipt(receipt);
    }
    let Some(encoded) = receipt.response.as_ref() else {
        let _permit = identity
            .map(AuthenticatedIdentity::publication_permit)
            .transpose()?;
        return replay_sql_receipt(receipt);
    };
    let saved = wal_decode::borrowed::<InteractiveCommitReceipt>(encoded)?;
    if !matches!(saved.version, 1 | 2) {
        return Err(invalid("unsupported interactive commit receipt version"));
    }
    let _permit = match (&saved.authorization, identity) {
        (Some(authorization), Some(identity)) => Some(authorization.authorize(identity)?),
        (None, None) => None,
        _ => return Err(SecurityError::Forbidden.into()),
    };
    if let Some((db, identity)) = db.zip(identity) {
        let references = record_references::replay_references(
            receipt.mutation.as_deref(),
            &saved.response,
            saved.references.iter(),
        )?;
        return db.with_standalone_reference_commit(identity, &references, || {
            replay_sql_value(receipt, saved.try_map(|saved| Ok(saved.response))?)
        });
    }
    replay_sql_value(receipt, saved.try_map(|saved| Ok(saved.response))?)
}

fn replay_sql_receipt(
    receipt: crate::transaction_journal::IdempotencyReceipt,
) -> Result<RelationalExecution> {
    use crate::transaction_journal::TransactionState;
    if receipt.expired {
        return Err(invalid(format!(
            "idempotency receipt expired; key remains consumed; transaction_id={}",
            receipt.status.transaction_id
        )));
    }
    match receipt.status.state {
        TransactionState::Committed => {
            let response = wal_decode::borrowed::<SqlExecutionResponse>(
                receipt
                    .response
                    .as_ref()
                    .ok_or_else(|| invalid("committed idempotency decision has no response"))?,
            )?;
            replay_sql_value(receipt, response)
        }
        TransactionState::Rejected => {
            let results = Vec::new();
            let response_memory = output::reserve_results(&results)?;
            Ok(RelationalExecution {
                response: SqlExecutionResponse {
                    transaction_id: Some(receipt.status.transaction_id.to_string()),
                    snapshot: 0,
                    committed: false,
                    outcome: SqlOutcome::Rejected,
                    commit_sequence: None,
                    retryable: false,
                    results,
                },
                committed: None,
                projection_error: None,
                response_memory,
            })
        }
        TransactionState::OutcomeUnknown => Err(GaussError::CommitOutcomeUnknown {
            transaction_id: receipt.status.transaction_id.to_string(),
        }),
        TransactionState::Expired => Err(invalid(
            "consumed idempotency key has no transaction decision",
        )),
    }
}

fn replay_sql_value(
    receipt: crate::transaction_journal::IdempotencyReceipt,
    mut response: wal_decode::Owned<SqlExecutionResponse>,
) -> Result<RelationalExecution> {
    response.reserve_extra(128)?; // Stable UUID string, admitted before allocation.
    let response = response.try_map(|mut response| {
        response.transaction_id = Some(receipt.status.transaction_id.to_string());
        Ok(response)
    })?;
    let (response, response_memory) = response.into_parts();
    Ok(RelationalExecution {
        response,
        committed: None,
        projection_error: None,
        response_memory,
    })
}

fn prepare_execution(
    mut working: RelationalState,
    request: SqlExecutionRequest,
    allow_transactional_ddl: bool,
    validate_deferred_at_end: bool,
    tenant_id: Option<&str>,
    authorized_identity: Option<&AuthenticatedIdentity>,
    ml_internal: bool,
) -> Result<PreparedRelationalExecution> {
    check_sql_cancelled()?;
    if authorized_identity
        .is_some_and(|identity| Some(identity.principal().tenant.as_str()) != tenant_id)
    {
        return Err(SecurityError::Forbidden.into());
    }
    enforce_serialized_limit(&request, MAX_DECODED_REQUEST_BYTES, "decoded SQL request")?;
    if request.statements.is_empty() {
        return Err(invalid("SQL request must contain at least one statement"));
    }
    if request.statements.len() > MAX_STATEMENTS_PER_REQUEST {
        return Err(GaussError::ResourceExhausted(format!(
            "SQL request has {} statements; maximum is {MAX_STATEMENTS_PER_REQUEST}",
            request.statements.len()
        )));
    }
    let mut parsed = Vec::with_capacity(request.statements.len());
    for item in request.statements {
        parsed.push((parse_relational_statement(&item.sql)?, item.parameters));
    }
    if !allow_transactional_ddl {
        let ddl_count = parsed
            .iter()
            .filter(|(statement, _)| {
                matches!(statement, ParsedRelationalStatement::Sql(statement) if is_ddl(statement))
            })
            .count();
        if ddl_count > 0 && parsed.len() != 1 {
            return Err(invalid(
                "DDL must be executed as one atomic statement and cannot be mixed with DML",
            ));
        }
    }

    let snapshot = working.sequence;
    let snapshot_state = working.clone();
    let catalog = working.tables.clone();
    let next_sequence = snapshot
        .checked_add(1)
        .ok_or_else(|| GaussError::ResourceExhausted("relational sequence overflow".into()))?;
    let mut mutations = Vec::new();
    let mut results = Vec::with_capacity(parsed.len());
    let mut constraint_modes = ConstraintModes::default();
    let mut authorization = authorized_identity
        .map(|_| SqlAuthorization::empty(tenant_id.expect("authorized tenant checked above")));
    for (statement, parameters) in parsed {
        check_sql_cancelled()?;
        match statement {
            ParsedRelationalStatement::Sql(statement) => {
                let _permit = if let (Some(identity), Some(combined)) =
                    (authorized_identity, authorization.as_mut())
                {
                    let mut required = SqlAuthorization::empty(&combined.tenant);
                    extend_statement_authorization(&working, &statement, &mut required)?;
                    let permit = required.authorize(identity)?;
                    combined.schema |= required.schema;
                    combined.grants.extend(required.grants);
                    combined.table_grants.extend(required.table_grants);
                    Some(permit)
                } else {
                    None
                };
                let mutation_count = mutations.len();
                let before_statement = working.clone();
                results.push(execute_statement(
                    &mut working,
                    snapshot,
                    next_sequence,
                    *statement,
                    &parameters,
                    &mut mutations,
                    (
                        tenant_id,
                        authorized_identity
                            .is_some_and(AuthenticatedIdentity::supports_table_grants),
                        authorized_identity
                            .filter(|identity| identity.has_strict_sql_scopes())
                            .map(|identity| identity.principal().id.as_str()),
                    ),
                )?);
                check_sql_cancelled()?;
                // A read observes the already-validated snapshot. Rechecking
                // every table after SELECT/EXPLAIN would turn indexed reads
                // into a full database scan as the installation grows.
                if mutations.len() != mutation_count {
                    validate_mutations(
                        &working,
                        &before_statement,
                        next_sequence,
                        &mutations[mutation_count..],
                        false,
                        &constraint_modes,
                    )?;
                }
            }
            ParsedRelationalStatement::SetConstraints(statement) => {
                if !parameters.is_empty() {
                    return Err(invalid("SET CONSTRAINTS does not accept parameters"));
                }
                apply_constraint_mode(&working, &mut constraint_modes, &statement)?;
                if !statement.deferred {
                    validate_database(&working, next_sequence, false, &constraint_modes)?;
                }
                results.push(SqlResult::Definition {
                    affected_objects: 0,
                });
            }
        }
        // Stop a multi-statement request before earlier result sets can pile
        // up beyond the same limit that applies to the final response.
        enforce_serialized_limit(&results, MAX_RESULT_BYTES, "SQL result")?;
    }
    if validate_deferred_at_end && !mutations.is_empty() {
        check_sql_cancelled()?;
        validate_mutations(
            &working,
            &snapshot_state,
            next_sequence,
            &mutations,
            true,
            &constraint_modes,
        )?;
    }
    guard_ml_managed_tables(&snapshot_state, &mut mutations, ml_internal)?;
    let rebasable = mutations.iter().all(|mutation| match mutation {
        RelationalMutation::Insert { table, .. } => {
            snapshot_state.tables.get(table).is_some_and(|table| {
                table
                    .definition
                    .columns
                    .iter()
                    .all(|column| column.identity.is_none())
            })
        }
        RelationalMutation::Update { .. } | RelationalMutation::Delete { .. } => true,
        RelationalMutation::CreateTable { .. }
        | RelationalMutation::DropTable { .. }
        | RelationalMutation::AlterTable { .. }
        | RelationalMutation::RenameTable { .. }
        | RelationalMutation::RewriteTable { .. } => false,
    });
    let mut write_dependencies = BTreeSet::new();
    if rebasable {
        let inserted_rows = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                RelationalMutation::Insert { table, rows } => Some(
                    rows.iter()
                        .map(|row| (table.clone(), row.row_id))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        for mutation in &mutations {
            let (table_name, row_ids) = match mutation {
                RelationalMutation::Update { table, rows } => {
                    (table, rows.iter().map(|row| row.row_id).collect::<Vec<_>>())
                }
                RelationalMutation::Delete { table, row_ids } => (table, row_ids.clone()),
                RelationalMutation::Insert { .. } => continue,
                _ => unreachable!("rebasable mutations contain only row changes"),
            };
            let table = snapshot_state
                .tables
                .get(table_name)
                .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
            for row_id in row_ids {
                if inserted_rows.contains(&(table_name.clone(), row_id)) {
                    continue;
                }
                let version = table.rows.visible(row_id, snapshot)?.ok_or_else(|| {
                    invalid(format!(
                        "row {row_id} in table {table_name} is not visible at snapshot {snapshot}"
                    ))
                })?;
                write_dependencies.insert(RowWriteDependency {
                    table: table_name.to_string(),
                    row_id,
                    version_begin: version.begin,
                });
            }
        }
    }
    let reference_writes =
        record_references::changed(&snapshot_state, &working, &mutations, next_sequence)?;
    let intents = collect_transaction_intents(&snapshot_state, &working, snapshot, &mutations)?;
    enforce_serialized_limit(&mutations, MAX_WRITE_SET_BYTES, "SQL write set")?;
    enforce_serialized_limit(&results, MAX_RESULT_BYTES, "SQL result")?;
    Ok(PreparedRelationalExecution {
        snapshot,
        results,
        mutations,
        reference_writes,
        catalog,
        write_dependencies: write_dependencies.into_iter().collect(),
        rebasable,
        intents,
        authorization,
    })
}

fn guard_ml_managed_tables(
    snapshot: &RelationalState,
    mutations: &mut [RelationalMutation],
    ml_internal: bool,
) -> Result<()> {
    for mutation in mutations {
        let name = match mutation {
            RelationalMutation::CreateTable { definition }
            | RelationalMutation::AlterTable { definition }
            | RelationalMutation::RewriteTable { definition, .. } => definition.name.clone(),
            RelationalMutation::RenameTable {
                old_name,
                definition,
            } => {
                if !ml_internal
                    && snapshot
                        .tables
                        .get(old_name)
                        .is_some_and(|table| table.definition.managed_by_ml)
                {
                    return Err(invalid("ML materialized tables are read-only through SQL"));
                }
                definition.name.clone()
            }
            RelationalMutation::DropTable { name }
            | RelationalMutation::Insert { table: name, .. }
            | RelationalMutation::Update { table: name, .. }
            | RelationalMutation::Delete { table: name, .. } => name.clone(),
        };
        if ml_internal {
            if let RelationalMutation::CreateTable { definition }
            | RelationalMutation::AlterTable { definition }
            | RelationalMutation::RewriteTable { definition, .. }
            | RelationalMutation::RenameTable { definition, .. } = mutation
            {
                definition.managed_by_ml = true;
            }
        } else if name.to_ascii_lowercase().starts_with("__chiron_ml_")
            || snapshot
                .tables
                .get(&name)
                .is_some_and(|table| table.definition.managed_by_ml)
        {
            return Err(invalid("ML materialized tables are read-only through SQL"));
        }
    }
    Ok(())
}

fn collect_transaction_intents(
    snapshot_state: &RelationalState,
    catalog_state: &RelationalState,
    snapshot: u64,
    mutations: &[RelationalMutation],
) -> Result<Vec<IntentRequest>> {
    let inserted_rows = mutations
        .iter()
        .filter_map(|mutation| match mutation {
            RelationalMutation::Insert { table, rows } => Some(
                rows.iter()
                    .map(|row| (table.clone(), row.row_id))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect::<BTreeSet<_>>();
    let mut requests = Vec::new();
    for mutation in mutations {
        match mutation {
            RelationalMutation::CreateTable { .. }
            | RelationalMutation::DropTable { .. }
            | RelationalMutation::AlterTable { .. }
            | RelationalMutation::RenameTable { .. }
            | RelationalMutation::RewriteTable { .. } => requests.push(IntentRequest {
                key: IntentKey::catalog(),
                mode: IntentMode::Exclusive,
            }),
            RelationalMutation::Insert { table, rows } => {
                let table_state = catalog_state
                    .tables
                    .get(table)
                    .ok_or_else(|| invalid(format!("table {table} does not exist")))?;
                for row in rows {
                    collect_new_row_intents(
                        catalog_state,
                        table_state,
                        &row.values,
                        &mut requests,
                    )?;
                }
            }
            RelationalMutation::Update { table, rows } => {
                let table_state = catalog_state
                    .tables
                    .get(table)
                    .or_else(|| snapshot_state.tables.get(table))
                    .ok_or_else(|| invalid(format!("table {table} does not exist")))?;
                for row in rows {
                    if !inserted_rows.contains(&(table.clone(), row.row_id)) {
                        requests.push(IntentRequest {
                            key: IntentKey::row(table_state.definition.table_id, row.row_id),
                            mode: IntentMode::Exclusive,
                        });
                        if let Some(old) = table_state.rows.visible(row.row_id, snapshot)? {
                            collect_unique_intents(
                                &table_state.definition,
                                &old.values,
                                &mut requests,
                            )?;
                        }
                    }
                    collect_new_row_intents(
                        catalog_state,
                        table_state,
                        &row.values,
                        &mut requests,
                    )?;
                }
            }
            RelationalMutation::Delete { table, row_ids } => {
                let table_state = catalog_state
                    .tables
                    .get(table)
                    .or_else(|| snapshot_state.tables.get(table))
                    .ok_or_else(|| invalid(format!("table {table} does not exist")))?;
                for row_id in row_ids {
                    if inserted_rows.contains(&(table.clone(), *row_id)) {
                        continue;
                    }
                    requests.push(IntentRequest {
                        key: IntentKey::row(table_state.definition.table_id, *row_id),
                        mode: IntentMode::Exclusive,
                    });
                    if let Some(old) = table_state.rows.visible(*row_id, snapshot)? {
                        collect_unique_intents(
                            &table_state.definition,
                            &old.values,
                            &mut requests,
                        )?;
                    }
                }
            }
        }
    }
    Ok(requests)
}

fn collect_new_row_intents(
    state: &RelationalState,
    table: &TableState,
    values: &[RelationalValue],
    requests: &mut Vec<IntentRequest>,
) -> Result<()> {
    collect_unique_intents(&table.definition, values, requests)?;
    for foreign_key in &table.definition.foreign_keys {
        let local_indexes = foreign_key
            .columns
            .iter()
            .map(|name| column_index(&table.definition, name))
            .collect::<Result<Vec<_>>>()?;
        let Some(encoded_key) = composite_key(values, &local_indexes) else {
            continue;
        };
        let parent = state
            .tables
            .get(&foreign_key.referenced_table)
            .ok_or_else(|| {
                invalid(format!(
                    "foreign key references missing table {}",
                    foreign_key.referenced_table
                ))
            })?;
        let parent_columns = resolved_referenced_columns(foreign_key, &parent.definition)?;
        let index_id = existing_index_id(&parent.definition, &parent_columns).ok_or_else(|| {
            invalid(format!(
                "catalog is missing referenced index for {}",
                parent_columns.join(", ")
            ))
        })?;
        requests.push(IntentRequest {
            key: IntentKey::index(index_id, &encoded_key),
            mode: IntentMode::Shared,
        });
    }
    Ok(())
}

fn collect_unique_intents(
    definition: &TableDefinition,
    values: &[RelationalValue],
    requests: &mut Vec<IntentRequest>,
) -> Result<()> {
    let mut unique_indexes = BTreeMap::new();
    if let Some(index_id) = definition.primary_key_index_id {
        unique_indexes.insert(index_id, definition.primary_key.as_slice());
    }
    for constraint in &definition.unique_constraints {
        unique_indexes.insert(constraint.index_id, constraint.columns.as_slice());
    }
    for index in &definition.indexes {
        if index.unique {
            unique_indexes.insert(index.index_id, index.columns.as_slice());
        }
    }
    for (index_id, columns) in unique_indexes {
        let indexes = columns
            .iter()
            .map(|name| column_index(definition, name))
            .collect::<Result<Vec<_>>>()?;
        let Some(encoded_key) = composite_key(values, &indexes) else {
            continue;
        };
        requests.push(IntentRequest {
            key: IntentKey::index(index_id, &encoded_key),
            mode: IntentMode::Exclusive,
        });
    }
    Ok(())
}

fn validate_rebase(
    prepared: &PreparedRelationalExecution,
    current: &RelationalState,
) -> Result<()> {
    let conflict = || {
        invalid(format!(
            "serialization conflict: relational snapshot {} is stale at {}; retry the transaction",
            prepared.snapshot, current.sequence
        ))
    };
    if !prepared.rebasable || prepared.catalog.len() != current.tables.len() {
        return Err(conflict());
    }
    for (name, original) in prepared.catalog.iter() {
        if current
            .tables
            .get(name)
            .is_none_or(|table| table.definition != original.definition)
        {
            return Err(conflict());
        }
    }
    for dependency in &prepared.write_dependencies {
        let table = current.tables.get(&dependency.table).ok_or_else(conflict)?;
        let Some(version) = table.rows.visible(dependency.row_id, current.sequence)? else {
            return Err(conflict());
        };
        if version.begin != dependency.version_begin {
            return Err(conflict());
        }
    }
    Ok(())
}

fn rebase_mutations(
    prepared: &PreparedRelationalExecution,
    current: &RelationalState,
) -> Result<Vec<RelationalMutation>> {
    let mut mutations = prepared.mutations.clone();
    let mut next_row_ids = BTreeMap::new();
    let mut remapped = BTreeMap::new();
    for mutation in &mutations {
        let RelationalMutation::Insert { table, rows } = mutation else {
            continue;
        };
        let next_row_id = next_row_ids.entry(table.clone()).or_insert_with(|| {
            current
                .tables
                .get(table)
                .map_or(1, |table| table.next_row_id)
        });
        for row in rows {
            let assigned = *next_row_id;
            *next_row_id = next_row_id.checked_add(1).ok_or_else(|| {
                GaussError::ResourceExhausted("relational row ID overflow".into())
            })?;
            remapped.insert((table.clone(), row.row_id), assigned);
        }
    }
    for mutation in &mutations {
        if let RelationalMutation::Insert { table, rows } = mutation {
            let expected = rows.iter().map(|row| row.row_id).collect::<BTreeSet<_>>();
            if expected.len() != rows.len()
                || expected
                    .iter()
                    .any(|row_id| !remapped.contains_key(&(table.clone(), *row_id)))
            {
                return Err(invalid("insert write set contains duplicate row identity"));
            }
        }
    }
    for mutation in &mut mutations {
        match mutation {
            RelationalMutation::Insert { table, rows }
            | RelationalMutation::Update { table, rows } => {
                for row in rows {
                    if let Some(row_id) = remapped.get(&(table.clone(), row.row_id)) {
                        row.row_id = *row_id;
                    }
                }
            }
            RelationalMutation::Delete { table, row_ids } => {
                for row_id in row_ids {
                    if let Some(remapped) = remapped.get(&(table.clone(), *row_id)) {
                        *row_id = *remapped;
                    }
                }
            }
            RelationalMutation::CreateTable { .. }
            | RelationalMutation::DropTable { .. }
            | RelationalMutation::AlterTable { .. }
            | RelationalMutation::RenameTable { .. }
            | RelationalMutation::RewriteTable { .. } => {
                return Err(invalid(
                    "catalog mutation cannot rebase on a stale snapshot",
                ));
            }
        }
    }
    Ok(mutations)
}

fn execute_statement(
    state: &mut RelationalState,
    snapshot: u64,
    sequence: u64,
    statement: Statement,
    parameters: &[RelationalValue],
    mutations: &mut Vec<RelationalMutation>,
    security_scope: (Option<&str>, bool, Option<&str>),
) -> Result<SqlResult> {
    let (tenant_id, table_authority, creator) = security_scope;
    ensure_statement_tenant(state, &statement, tenant_id)?;
    match statement {
        Statement::CreateTable(create) => {
            let if_not_exists = create.if_not_exists;
            let mut definition = table_definition(create)?;
            definition.tenant_id = tenant_id.map(str::to_owned);
            definition.security_incarnation = table_authority.then(uuid::Uuid::new_v4);
            definition.creator_principal_id = creator.map(str::to_owned);
            let name = definition.name.clone();
            if state.tables.contains_key(&name) {
                if if_not_exists {
                    return Ok(SqlResult::Definition {
                        affected_objects: 0,
                    });
                }
                return Err(invalid(format!("table {name} already exists")));
            }
            assign_missing_catalog_ids(state, &mut definition)?;
            bind_foreign_key_targets(state, &mut definition)?;
            state.tables.insert(
                &name,
                Arc::new(TableState::empty(
                    definition.clone(),
                    Arc::clone(&state.directory),
                )?),
            )?;
            mutations.push(RelationalMutation::CreateTable { definition });
            Ok(SqlResult::Definition {
                affected_objects: 1,
            })
        }
        Statement::AlterTable(alter) => execute_alter_table(state, sequence, alter, mutations),
        Statement::CreateIndex(create) => execute_create_index(state, sequence, create, mutations),
        Statement::Drop {
            object_type: ObjectType::Index,
            if_exists,
            names,
            cascade,
            ..
        } => execute_drop_index(state, sequence, if_exists, names, cascade, mutations),
        Statement::Drop {
            object_type,
            if_exists,
            names,
            cascade,
            ..
        } => execute_drop_table(
            state,
            sequence,
            object_type,
            if_exists,
            names,
            cascade,
            mutations,
        ),
        Statement::Insert(insert) => execute_insert(state, sequence, insert, parameters, mutations),
        Statement::Update(update) => execute_update(state, sequence, update, parameters, mutations),
        Statement::Delete(delete) => execute_delete(state, sequence, delete, parameters, mutations),
        Statement::Query(query) => execute_query(state, snapshot.max(sequence), &query, parameters),
        Statement::Explain {
            statement, analyze, ..
        } => {
            if analyze {
                return Err(unsupported("EXPLAIN ANALYZE is outside relational v1"));
            }
            Ok(SqlResult::Explain {
                plan: explain_statement(state, &statement)?,
            })
        }
        _ => Err(unsupported(
            "SQL statement is outside the native relational v1 subset",
        )),
    }
}

fn execute_drop_table(
    state: &mut RelationalState,
    sequence: u64,
    object_type: ObjectType,
    if_exists: bool,
    names: Vec<ObjectName>,
    cascade: bool,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<SqlResult> {
    if object_type != ObjectType::Table || names.len() != 1 {
        return Err(unsupported(
            "DROP TABLE supports exactly one table with RESTRICT or CASCADE",
        ));
    }
    let name = normalize_name(&names[0]);
    if !state.tables.contains_key(&name) {
        if if_exists {
            return Ok(SqlResult::Definition {
                affected_objects: 0,
            });
        }
        return Err(invalid(format!("table {name} does not exist")));
    }

    let mut dependent_tables = state
        .tables
        .iter()
        .filter(|(child_table, _)| child_table.as_str() != name)
        .filter_map(|(child_table, table)| {
            table
                .definition
                .foreign_keys
                .iter()
                .find(|foreign_key| foreign_key.referenced_table == name)
                .map(|foreign_key| {
                    (
                        child_table.clone(),
                        foreign_key
                            .name
                            .clone()
                            .unwrap_or_else(|| "<unnamed>".into()),
                    )
                })
        })
        .collect::<Vec<_>>();
    dependent_tables.sort();
    if !cascade && let Some((child_table, foreign_key)) = dependent_tables.first() {
        return Err(invalid(format!(
            "cannot drop table {name} because foreign key {foreign_key} on table {child_table} depends on it"
        )));
    }

    if cascade {
        for (child_table, _) in dependent_tables {
            let mut definition = state
                .tables
                .get(&child_table)
                .expect("dependent table exists during DROP TABLE")
                .definition
                .as_ref()
                .clone();
            definition
                .foreign_keys
                .retain(|foreign_key| foreign_key.referenced_table != name);
            validate_definition(&definition)?;
            Arc::make_mut(
                state
                    .tables
                    .get_mut(&child_table)?
                    .expect("dependent table exists during DROP TABLE"),
            )
            .replace_definition(definition.clone(), sequence)?;
            mutations.push(RelationalMutation::AlterTable { definition });
        }
    }
    state.tables.remove(&name)?;
    mutations.push(RelationalMutation::DropTable { name });
    Ok(SqlResult::Definition {
        affected_objects: 1,
    })
}

fn execute_alter_table(
    state: &mut RelationalState,
    sequence: u64,
    alter: sqlparser::ast::AlterTable,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<SqlResult> {
    if alter.only
        || alter.location.is_some()
        || alter.on_cluster.is_some()
        || alter.table_type.is_some()
        || alter.operations.is_empty()
    {
        return Err(unsupported(
            "ALTER TABLE requires one supported column or constraint operation",
        ));
    }
    let table_name = normalize_name(&alter.name);
    let Some(current) = state.tables.get(&table_name) else {
        if alter.if_exists {
            return Ok(SqlResult::Definition {
                affected_objects: 0,
            });
        }
        return Err(invalid(format!("table {table_name} does not exist")));
    };
    if alter.operations.len() > 1 {
        let mut drops = Vec::with_capacity(alter.operations.len());
        for operation in alter.operations {
            let AlterTableOperation::DropColumn {
                column_names,
                if_exists,
                drop_behavior,
                ..
            } = operation
            else {
                return Err(unsupported(
                    "multi-operation ALTER TABLE currently supports only DROP COLUMN",
                ));
            };
            if column_names.len() != 1 {
                return Err(unsupported(
                    "each ALTER TABLE DROP COLUMN operation requires exactly one column",
                ));
            }
            drops.push(DropColumnSpec {
                name: normalize_ident(&column_names[0].value),
                if_exists,
                cascade: matches!(drop_behavior, Some(DropBehavior::Cascade)),
            });
        }
        return execute_drop_columns(state, sequence, &table_name, drops, mutations);
    }
    let mut definition = current.definition.as_ref().clone();
    let mut rewritten_rows = Vec::new();
    let mut cascaded_definitions = Vec::new();
    match alter.operations.into_iter().next().expect("length checked") {
        AlterTableOperation::AddColumn {
            if_not_exists,
            column_def,
            column_position,
            ..
        } => {
            if column_position.is_some() {
                return Err(unsupported(
                    "ALTER TABLE ADD COLUMN FIRST/AFTER is outside the current profile",
                ));
            }
            let column_name = normalize_ident(&column_def.name.value);
            if definition
                .columns
                .iter()
                .any(|column| column.name == column_name)
            {
                if if_not_exists {
                    return Ok(SqlResult::Definition {
                        affected_objects: 0,
                    });
                }
                return Err(invalid(format!("column {column_name} already exists")));
            }
            let (column, checks) = added_column_definition(
                &table_name,
                definition.check_constraints.len(),
                column_def,
            )?;
            let fill_value = column.default.clone().unwrap_or(RelationalValue::Null);
            let existing_rows = visible_rows(current, sequence)?;
            if !column.nullable
                && matches!(fill_value, RelationalValue::Null)
                && !existing_rows.is_empty()
            {
                return Err(invalid(format!(
                    "column {column_name} contains NULL for existing rows"
                )));
            }
            definition.columns.push(column);
            definition.check_constraints.extend(checks);
            for (row_id, source) in existing_rows {
                let mut values = source.to_vec();
                values.push(fill_value.clone());
                validate_row(&definition, &values)?;
                rewritten_rows.push(StoredRow { row_id, values });
            }
        }
        AlterTableOperation::AddConstraint {
            constraint: TableConstraint::PrimaryKey(key),
            not_valid,
        } => {
            if not_valid
                || key.index_name.is_some()
                || key.index_type.is_some()
                || !key.index_options.is_empty()
                || key.characteristics.is_some()
            {
                return Err(unsupported(
                    "ALTER TABLE ADD PRIMARY KEY supports immediate constraints without index options",
                ));
            }
            if !definition.primary_key.is_empty() {
                return Err(invalid("table already has a primary key"));
            }
            let columns = key
                .columns
                .iter()
                .map(index_column_name)
                .collect::<Result<Vec<_>>>()?;
            if columns.is_empty() {
                return Err(invalid("primary key requires at least one column"));
            }
            let name = key
                .name
                .map(|value| normalize_ident(&value.value))
                .unwrap_or_else(|| format!("{table_name}_pkey"));
            definition.primary_key = columns;
            definition.primary_key_name = Some(name);
            definition.primary_key_index_id = None;
            for column in &definition.primary_key {
                let position = column_index(&definition, column)?;
                definition.columns[position].nullable = false;
            }
        }
        AlterTableOperation::AddConstraint {
            constraint: TableConstraint::Unique(unique),
            not_valid,
        } => {
            if not_valid
                || unique.index_name.is_some()
                || unique.index_type.is_some()
                || !unique.index_options.is_empty()
                || unique.characteristics.is_some()
                || unique.nulls_distinct != sqlparser::ast::NullsDistinctOption::None
            {
                return Err(unsupported(
                    "ALTER TABLE ADD UNIQUE supports immediate NULLS DISTINCT constraints without index options",
                ));
            }
            let columns = unique
                .columns
                .iter()
                .map(index_column_name)
                .collect::<Result<Vec<_>>>()?;
            if columns.is_empty() {
                return Err(invalid("unique constraint requires at least one column"));
            }
            let name = unique
                .name
                .map(|value| normalize_ident(&value.value))
                .unwrap_or_else(|| format!("{}_{}_key", table_name, columns.join("_")));
            definition.unique_constraints.push(UniqueConstraint {
                index_id: 0,
                name: Some(name),
                columns,
            });
        }
        AlterTableOperation::AddConstraint {
            constraint: TableConstraint::ForeignKey(foreign_key),
            not_valid,
        } => {
            if not_valid {
                return Err(unsupported(
                    "ALTER TABLE ADD FOREIGN KEY NOT VALID is outside the current profile",
                ));
            }
            let local_columns = foreign_key
                .columns
                .iter()
                .map(|value| normalize_ident(&value.value))
                .collect::<Vec<_>>();
            let generated_name = format!("{}_{}_fkey", table_name, local_columns.join("_"));
            let name = foreign_key
                .name
                .as_ref()
                .map(|value| normalize_ident(&value.value))
                .unwrap_or(generated_name);
            if definition
                .foreign_keys
                .iter()
                .any(|constraint| constraint.name.as_deref() == Some(name.as_str()))
            {
                return Err(invalid(format!("constraint {name} already exists")));
            }
            definition.foreign_keys.push(foreign_key_definition(
                Some(name),
                local_columns,
                foreign_key,
            )?);
        }
        AlterTableOperation::AddConstraint {
            constraint: TableConstraint::Check(check),
            not_valid,
        } => {
            if not_valid || check.enforced == Some(false) {
                return Err(unsupported(
                    "ALTER TABLE ADD CHECK NOT VALID/NOT ENFORCED is outside the current profile",
                ));
            }
            let name = check
                .name
                .map(|value| normalize_ident(&value.value))
                .unwrap_or_else(|| {
                    format!(
                        "{}_check_{}",
                        table_name,
                        definition.check_constraints.len() + 1
                    )
                });
            if definition
                .check_constraints
                .iter()
                .any(|constraint| constraint.name.as_deref() == Some(name.as_str()))
            {
                return Err(invalid(format!("constraint {name} already exists")));
            }
            definition
                .check_constraints
                .push(CheckConstraintDefinition {
                    name: Some(name),
                    expression: check.expr.to_string(),
                });
        }
        AlterTableOperation::DropConstraint {
            if_exists,
            name,
            drop_behavior,
        } => {
            let cascade = matches!(drop_behavior, Some(DropBehavior::Cascade));
            let name = normalize_ident(&name.value);
            let old_fk_len = definition.foreign_keys.len();
            let old_check_len = definition.check_constraints.len();
            let old_unique_len = definition.unique_constraints.len();
            let primary_key_matches = !definition.primary_key.is_empty()
                && primary_key_constraint_name(&definition) == name;
            let dropped_key_columns = if primary_key_matches {
                Some(definition.primary_key.clone())
            } else {
                definition
                    .unique_constraints
                    .iter()
                    .find(|constraint| {
                        constraint.name.as_deref() == Some(name.as_str())
                            || unique_constraint_name(&table_name, constraint) == name
                    })
                    .map(|constraint| constraint.columns.clone())
            };
            definition
                .foreign_keys
                .retain(|constraint| constraint.name.as_deref() != Some(name.as_str()));
            definition
                .check_constraints
                .retain(|constraint| constraint.name.as_deref() != Some(name.as_str()));
            definition.unique_constraints.retain(|constraint| {
                constraint.name.as_deref() != Some(name.as_str())
                    && unique_constraint_name(&table_name, constraint) != name
            });
            if primary_key_matches {
                definition.primary_key.clear();
                definition.primary_key_name = None;
                definition.primary_key_index_id = None;
            }
            if definition.foreign_keys.len() == old_fk_len
                && definition.check_constraints.len() == old_check_len
                && definition.unique_constraints.len() == old_unique_len
                && !primary_key_matches
            {
                if if_exists {
                    return Ok(SqlResult::Definition {
                        affected_objects: 0,
                    });
                }
                return Err(invalid(format!("constraint {name} does not exist")));
            }
            if let Some(columns) = dropped_key_columns {
                let kind = if primary_key_matches {
                    ReferencedKeyKind::PrimaryKey
                } else {
                    ReferencedKeyKind::UniqueConstraint
                };
                if cascade {
                    cascaded_definitions = cascade_referenced_key_drop(
                        state,
                        &table_name,
                        &mut definition,
                        &columns,
                        kind,
                        &name,
                    )?;
                } else {
                    reject_referenced_key_drop(state, &table_name, &columns, kind, &name)?;
                }
            }
        }
        AlterTableOperation::AlterColumn {
            column_name,
            op:
                AlterColumnOperation::SetDataType {
                    data_type, using, ..
                },
        } => {
            let column_name = normalize_ident(&column_name.value);
            let Some(column_position) = definition
                .columns
                .iter()
                .position(|column| column.name == column_name)
            else {
                return Err(invalid(format!("column {column_name} does not exist")));
            };
            if using.is_some() {
                return Err(unsupported(
                    "ALTER COLUMN TYPE USING expressions are outside the current profile",
                ));
            }
            let target_type = relational_type(&data_type)?;
            let source_type = definition.columns[column_position].data_type.clone();
            if source_type == target_type {
                return Ok(SqlResult::Definition {
                    affected_objects: 0,
                });
            }
            if !cast_storage_compatible(&source_type, &target_type) {
                return Err(unsupported(format!(
                    "ALTER COLUMN TYPE from {source_type:?} to {target_type:?} requires an explicit conversion that is outside the current profile"
                )));
            }
            if definition.columns[column_position].identity.is_some()
                && !matches!(
                    target_type,
                    RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt
                )
            {
                return Err(invalid(
                    "identity columns must use SMALLINT, INTEGER, or BIGINT",
                ));
            }
            if let Some(default) = &definition.columns[column_position].default {
                validate_value(&target_type, default)?;
            }
            definition.columns[column_position].data_type = target_type;
            validate_definition(&definition)?;
            let rewritten = visible_rows(current, sequence)?
                .into_iter()
                .map(|(row_id, values)| {
                    validate_row(&definition, &values)?;
                    Ok(StoredRow {
                        row_id,
                        values: values.to_vec(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            rewrite_table_state(state, definition.clone(), sequence, &rewritten)?;
            mutations.push(RelationalMutation::RewriteTable {
                definition,
                rows: rewritten,
            });
            return Ok(SqlResult::Definition {
                affected_objects: 1,
            });
        }
        AlterTableOperation::AlterColumn {
            column_name,
            op: AlterColumnOperation::SetNotNull,
        } => {
            let column_name = normalize_ident(&column_name.value);
            let column_position = column_index(&definition, &column_name)?;
            if !definition.columns[column_position].nullable {
                return Ok(SqlResult::Definition {
                    affected_objects: 0,
                });
            }
            definition.columns[column_position].nullable = false;
            for (_, values) in visible_rows(current, sequence)? {
                validate_row(&definition, &values)?;
            }
        }
        AlterTableOperation::AlterColumn {
            column_name,
            op: AlterColumnOperation::DropNotNull,
        } => {
            let column_name = normalize_ident(&column_name.value);
            let column_position = column_index(&definition, &column_name)?;
            if definition.columns[column_position].nullable {
                return Ok(SqlResult::Definition {
                    affected_objects: 0,
                });
            }
            if definition.primary_key.contains(&column_name) {
                return Err(invalid(format!(
                    "column {column_name} is used by a primary key and cannot drop NOT NULL"
                )));
            }
            if definition.columns[column_position].identity.is_some() {
                return Err(invalid(format!(
                    "identity column {column_name} cannot drop NOT NULL"
                )));
            }
            definition.columns[column_position].nullable = true;
        }
        AlterTableOperation::AlterColumn {
            column_name,
            op: AlterColumnOperation::SetDefault { value },
        } => {
            let column_name = normalize_ident(&column_name.value);
            let column_position = column_index(&definition, &column_name)?;
            if definition.columns[column_position].identity.is_some() {
                return Err(invalid(format!(
                    "identity column {column_name} cannot have a static default"
                )));
            }
            let default =
                static_default_value(&value, &definition.columns[column_position].data_type)?;
            if definition.columns[column_position].default.as_ref() == Some(&default) {
                return Ok(SqlResult::Definition {
                    affected_objects: 0,
                });
            }
            definition.columns[column_position].default = Some(default);
        }
        AlterTableOperation::AlterColumn {
            column_name,
            op: AlterColumnOperation::DropDefault,
        } => {
            let column_name = normalize_ident(&column_name.value);
            let column_position = column_index(&definition, &column_name)?;
            if definition.columns[column_position].default.is_none() {
                return Ok(SqlResult::Definition {
                    affected_objects: 0,
                });
            }
            definition.columns[column_position].default = None;
        }
        AlterTableOperation::RenameConstraint { old_name, new_name } => {
            let old_name = normalize_ident(&old_name.value);
            let new_name = normalize_ident(&new_name.value);
            let renamed_kind =
                rename_constraint_definition(&table_name, &mut definition, &old_name, &new_name)?;
            if old_name == new_name {
                return Ok(SqlResult::Definition {
                    affected_objects: 0,
                });
            }

            let mut affected = vec![definition];
            if let Some(referenced_kind) = renamed_kind.referenced_key_kind() {
                for candidate in state.tables.values() {
                    let mut other = if candidate.definition.name == table_name {
                        affected[0].clone()
                    } else {
                        candidate.definition.as_ref().clone()
                    };
                    let mut changed = false;
                    for foreign_key in &mut other.foreign_keys {
                        if foreign_key.referenced_table == table_name
                            && (foreign_key.referenced_key_kind == Some(referenced_kind)
                                || foreign_key.referenced_key_kind.is_none())
                            && foreign_key.referenced_key_name.as_deref() == Some(old_name.as_str())
                        {
                            foreign_key.referenced_key_name = Some(new_name.clone());
                            changed = true;
                        }
                    }
                    if changed {
                        validate_definition(&other)?;
                        if candidate.definition.name == table_name {
                            affected[0] = other;
                        } else {
                            affected.push(other);
                        }
                    }
                }
            }

            for definition in affected {
                let table = Arc::make_mut(
                    state
                        .tables
                        .get_mut(&definition.name)?
                        .expect("renamed constraint table exists"),
                );
                table.replace_definition(definition.clone(), sequence)?;
                mutations.push(RelationalMutation::AlterTable { definition });
            }
            return Ok(SqlResult::Definition {
                affected_objects: 1,
            });
        }
        AlterTableOperation::RenameTable {
            table_name: renamed,
        } => {
            let renamed = match renamed {
                RenameTableNameKind::To(name) => normalize_name(&name),
                RenameTableNameKind::As(_) => {
                    return Err(unsupported(
                        "ALTER TABLE RENAME AS is outside the PostgreSQL profile",
                    ));
                }
            };
            if renamed == table_name {
                return Ok(SqlResult::Definition {
                    affected_objects: 0,
                });
            }
            if state.tables.contains_key(&renamed) {
                return Err(invalid(format!("table {renamed} already exists")));
            }

            definition.name = renamed.clone();
            for foreign_key in &mut definition.foreign_keys {
                if foreign_key.referenced_table == table_name {
                    foreign_key.referenced_table = renamed.clone();
                }
            }
            for check in &mut definition.check_constraints {
                check.expression = rename_check_table(&check.expression, &table_name, &renamed)?;
            }
            validate_definition(&definition)?;

            let mut referencing_definitions = Vec::new();
            for (other_name, table) in state.tables.iter() {
                if other_name == &table_name
                    || !table
                        .definition
                        .foreign_keys
                        .iter()
                        .any(|foreign_key| foreign_key.referenced_table == table_name)
                {
                    continue;
                }
                let mut other = table.definition.as_ref().clone();
                for foreign_key in &mut other.foreign_keys {
                    if foreign_key.referenced_table == table_name {
                        foreign_key.referenced_table = renamed.clone();
                    }
                }
                validate_definition(&other)?;
                referencing_definitions.push(other);
            }

            rename_table_state(state, &table_name, definition.clone(), sequence)?;
            mutations.push(RelationalMutation::RenameTable {
                old_name: table_name,
                definition,
            });
            for definition in referencing_definitions {
                let table = Arc::make_mut(
                    state
                        .tables
                        .get_mut(&definition.name)?
                        .expect("renamed table dependency exists"),
                );
                table.replace_definition(definition.clone(), sequence)?;
                mutations.push(RelationalMutation::AlterTable { definition });
            }
            return Ok(SqlResult::Definition {
                affected_objects: 1,
            });
        }
        AlterTableOperation::RenameColumn {
            old_column_name,
            new_column_name,
        } => {
            let old_name = normalize_ident(&old_column_name.value);
            let new_name = normalize_ident(&new_column_name.value);
            if old_name == new_name {
                return Ok(SqlResult::Definition {
                    affected_objects: 0,
                });
            }
            let Some(column) = definition
                .columns
                .iter_mut()
                .find(|column| column.name == old_name)
            else {
                return Err(invalid(format!("column {old_name} does not exist")));
            };
            if current
                .definition
                .columns
                .iter()
                .any(|column| column.name == new_name)
            {
                return Err(invalid(format!("column {new_name} already exists")));
            }
            column.name = new_name.clone();
            if let Some(index_id) = definition.reference_index_ids.remove(&old_name) {
                definition
                    .reference_index_ids
                    .insert(new_name.clone(), index_id);
            }
            rename_column_list(&mut definition.primary_key, &old_name, &new_name);
            for unique in &mut definition.unique_constraints {
                rename_column_list(&mut unique.columns, &old_name, &new_name);
            }
            for index in &mut definition.indexes {
                rename_column_list(&mut index.columns, &old_name, &new_name);
            }
            for foreign_key in &mut definition.foreign_keys {
                rename_column_list(&mut foreign_key.columns, &old_name, &new_name);
                if foreign_key.referenced_table == table_name {
                    rename_column_list(&mut foreign_key.referenced_columns, &old_name, &new_name);
                }
            }
            for check in &mut definition.check_constraints {
                check.expression = rename_check_column(&check.expression, &old_name, &new_name)?;
            }
            validate_definition(&definition)?;

            let mut affected = vec![definition];
            for (other_name, table) in state.tables.iter() {
                if other_name == &table_name
                    || !table.definition.foreign_keys.iter().any(|foreign_key| {
                        foreign_key.referenced_table == table_name
                            && foreign_key.referenced_columns.contains(&old_name)
                    })
                {
                    continue;
                }
                let mut other = table.definition.as_ref().clone();
                for foreign_key in &mut other.foreign_keys {
                    if foreign_key.referenced_table == table_name {
                        rename_column_list(
                            &mut foreign_key.referenced_columns,
                            &old_name,
                            &new_name,
                        );
                    }
                }
                validate_definition(&other)?;
                affected.push(other);
            }

            for definition in affected {
                let table = Arc::make_mut(
                    state
                        .tables
                        .get_mut(&definition.name)?
                        .expect("renamed table dependency exists"),
                );
                table.replace_definition(definition.clone(), sequence)?;
                mutations.push(RelationalMutation::AlterTable { definition });
            }
            return Ok(SqlResult::Definition {
                affected_objects: 1,
            });
        }
        AlterTableOperation::DropColumn {
            column_names,
            if_exists,
            drop_behavior,
            ..
        } => {
            if column_names.len() != 1 {
                return Err(unsupported(
                    "ALTER TABLE DROP COLUMN supports exactly one column with RESTRICT or CASCADE",
                ));
            }
            return execute_drop_columns(
                state,
                sequence,
                &table_name,
                vec![DropColumnSpec {
                    name: normalize_ident(&column_names[0].value),
                    if_exists,
                    cascade: matches!(drop_behavior, Some(DropBehavior::Cascade)),
                }],
                mutations,
            );
        }
        _ => {
            return Err(unsupported(
                "ALTER TABLE currently supports ADD/DROP/RENAME COLUMN, ALTER COLUMN TYPE/NULLABILITY/DEFAULT, RENAME TO/CONSTRAINT, or ADD/DROP PRIMARY KEY, UNIQUE, FOREIGN KEY, or CHECK",
            ));
        }
    }
    assign_missing_catalog_ids(state, &mut definition)?;
    bind_foreign_key_targets(state, &mut definition)?;
    validate_definition(&definition)?;
    if !rewritten_rows.is_empty() {
        // A changed row layout belongs to a new table generation. Readers of
        // the old schema retain their original root; its old-width versions
        // must not appear in a checkpoint under the new schema.
        rewrite_table_state(state, definition.clone(), sequence, &rewritten_rows)?;
        mutations.push(RelationalMutation::RewriteTable {
            definition,
            rows: rewritten_rows,
        });
    } else {
        let table = Arc::make_mut(
            state
                .tables
                .get_mut(&table_name)?
                .expect("table existence checked"),
        );
        table.replace_definition(definition.clone(), sequence)?;
        mutations.push(RelationalMutation::AlterTable { definition });
    }
    for definition in cascaded_definitions {
        validate_definition(&definition)?;
        let table = Arc::make_mut(
            state
                .tables
                .get_mut(&definition.name)?
                .expect("cascaded foreign-key table exists"),
        );
        table.replace_definition(definition.clone(), sequence)?;
        mutations.push(RelationalMutation::AlterTable { definition });
    }
    Ok(SqlResult::Definition {
        affected_objects: 1,
    })
}

#[derive(Debug)]
struct DropColumnSpec {
    name: String,
    if_exists: bool,
    cascade: bool,
}

fn execute_drop_columns(
    state: &mut RelationalState,
    sequence: u64,
    table_name: &str,
    specs: Vec<DropColumnSpec>,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<SqlResult> {
    let current = Arc::clone(
        state
            .tables
            .get(table_name)
            .expect("DROP COLUMN table existence checked"),
    );
    let original_definition = current.definition.as_ref().clone();
    let mut targets = BTreeMap::new();
    let mut target_order = Vec::new();
    for spec in specs {
        if targets.contains_key(&spec.name) {
            if spec.if_exists {
                continue;
            }
            return Err(invalid(format!(
                "column {} is specified more than once",
                spec.name
            )));
        }
        if !original_definition
            .columns
            .iter()
            .any(|column| column.name == spec.name)
        {
            if spec.if_exists {
                continue;
            }
            return Err(invalid(format!("column {} does not exist", spec.name)));
        }
        target_order.push(spec.name.clone());
        targets.insert(spec.name, spec.cascade);
    }
    if targets.is_empty() {
        return Ok(SqlResult::Definition {
            affected_objects: 0,
        });
    }
    if targets.len() == original_definition.columns.len() {
        return Err(invalid("cannot drop the last column of a table"));
    }

    let dependency_action = |columns: &[String]| {
        let mut touched = false;
        let mut cascade = false;
        for column in columns {
            if let Some(column_cascade) = targets.get(column) {
                touched = true;
                cascade |= *column_cascade;
            }
        }
        touched.then_some(cascade)
    };
    let reject_dependency = |columns: &[String]| -> Result<()> {
        if matches!(dependency_action(columns), Some(false)) {
            let column = target_order
                .iter()
                .find(|column| columns.contains(column) && !targets[*column])
                .expect("RESTRICT dependency has a target column");
            return Err(invalid(format!(
                "column {column} is used by an index or constraint"
            )));
        }
        Ok(())
    };

    let mut definition = original_definition.clone();
    reject_dependency(&definition.primary_key)?;
    if matches!(dependency_action(&definition.primary_key), Some(true)) {
        definition.primary_key.clear();
        definition.primary_key_name = None;
        definition.primary_key_index_id = None;
    }

    let mut unique_constraints = Vec::with_capacity(definition.unique_constraints.len());
    for constraint in std::mem::take(&mut definition.unique_constraints) {
        reject_dependency(&constraint.columns)?;
        if !matches!(dependency_action(&constraint.columns), Some(true)) {
            unique_constraints.push(constraint);
        }
    }
    definition.unique_constraints = unique_constraints;

    let mut indexes = Vec::with_capacity(definition.indexes.len());
    for index in std::mem::take(&mut definition.indexes) {
        reject_dependency(&index.columns)?;
        if !matches!(dependency_action(&index.columns), Some(true)) {
            indexes.push(index);
        }
    }
    definition.indexes = indexes;

    let mut foreign_keys = Vec::with_capacity(definition.foreign_keys.len());
    for foreign_key in std::mem::take(&mut definition.foreign_keys) {
        let mut dependency_columns = foreign_key.columns.clone();
        if foreign_key.referenced_table == table_name {
            dependency_columns.extend(resolved_referenced_columns(
                &foreign_key,
                &original_definition,
            )?);
        }
        reject_dependency(&dependency_columns)?;
        if !matches!(dependency_action(&dependency_columns), Some(true)) {
            foreign_keys.push(foreign_key);
        }
    }
    definition.foreign_keys = foreign_keys;

    let mut checks = Vec::with_capacity(definition.check_constraints.len());
    for constraint in std::mem::take(&mut definition.check_constraints) {
        let mut dependency_columns = Vec::new();
        for column in targets.keys() {
            if check_constraint_references_column(&constraint, column)? {
                dependency_columns.push(column.clone());
            }
        }
        reject_dependency(&dependency_columns)?;
        if !matches!(dependency_action(&dependency_columns), Some(true)) {
            checks.push(constraint);
        }
    }
    definition.check_constraints = checks;

    let mut external_dependencies = Vec::new();
    for (child_name, child) in state.tables.iter() {
        if child_name == table_name {
            continue;
        }
        let mut child_definition = child.definition.as_ref().clone();
        let mut retained = Vec::with_capacity(child_definition.foreign_keys.len());
        let mut removed = false;
        for foreign_key in child_definition.foreign_keys {
            if foreign_key.referenced_table != table_name {
                retained.push(foreign_key);
                continue;
            }
            let referenced_columns =
                resolved_referenced_columns(&foreign_key, &original_definition)?;
            reject_dependency(&referenced_columns)?;
            if matches!(dependency_action(&referenced_columns), Some(true)) {
                removed = true;
            } else {
                retained.push(foreign_key);
            }
        }
        if removed {
            child_definition.foreign_keys = retained;
            external_dependencies.push(child_definition);
        }
    }
    external_dependencies.sort_by(|left, right| left.name.cmp(&right.name));

    let mut positions = original_definition
        .columns
        .iter()
        .enumerate()
        .filter_map(|(position, column)| targets.contains_key(&column.name).then_some(position))
        .collect::<Vec<_>>();
    positions.sort_unstable_by(|left, right| right.cmp(left));
    for position in &positions {
        definition.columns.remove(*position);
    }
    definition
        .reference_index_ids
        .retain(|column, _| !targets.contains_key(column));
    validate_definition(&definition)?;
    let rewritten = visible_rows(&current, sequence)?
        .into_iter()
        .map(|(row_id, source)| {
            let mut values = source.to_vec();
            for position in &positions {
                values.remove(*position);
            }
            validate_row(&definition, &values)?;
            Ok(StoredRow { row_id, values })
        })
        .collect::<Result<Vec<_>>>()?;

    for child_definition in external_dependencies {
        validate_definition(&child_definition)?;
        Arc::make_mut(
            state
                .tables
                .get_mut(&child_definition.name)?
                .expect("DROP COLUMN dependent table exists"),
        )
        .replace_definition(child_definition.clone(), sequence)?;
        mutations.push(RelationalMutation::AlterTable {
            definition: child_definition,
        });
    }
    rewrite_table_state(state, definition.clone(), sequence, &rewritten)?;
    mutations.push(RelationalMutation::RewriteTable {
        definition,
        rows: rewritten,
    });
    Ok(SqlResult::Definition {
        affected_objects: targets.len() as u64,
    })
}

fn added_column_definition(
    table_name: &str,
    existing_check_count: usize,
    column: sqlparser::ast::ColumnDef,
) -> Result<(RelationalColumn, Vec<CheckConstraintDefinition>)> {
    let name = normalize_ident(&column.name.value);
    let data_type = relational_type(&column.data_type)?;
    let mut nullable = true;
    let mut default = None;
    let mut checks = Vec::new();
    for option in column.options {
        match option.option {
            ColumnOption::Null => nullable = true,
            ColumnOption::NotNull => nullable = false,
            ColumnOption::Default(expression) => {
                if default.is_some() {
                    return Err(invalid(format!(
                        "column {name} declares more than one default"
                    )));
                }
                default = Some(static_default_value(&expression, &data_type)?);
            }
            ColumnOption::Check(check) => {
                if check.enforced == Some(false) {
                    return Err(unsupported("NOT ENFORCED CHECK is not supported"));
                }
                checks.push(CheckConstraintDefinition {
                    name: option
                        .name
                        .or(check.name)
                        .map(|value| normalize_ident(&value.value))
                        .or_else(|| {
                            Some(format!(
                                "{}_check_{}",
                                table_name,
                                existing_check_count + checks.len() + 1
                            ))
                        }),
                    expression: check.expr.to_string(),
                });
            }
            _ => {
                return Err(unsupported(
                    "ALTER TABLE ADD COLUMN supports NULL, NOT NULL, DEFAULT, and CHECK",
                ));
            }
        }
    }
    let column = RelationalColumn {
        name,
        data_type,
        nullable,
        default,
        identity: None,
    };
    if let Some(default) = &column.default {
        validate_value(&column.data_type, default)?;
        if matches!(default, RelationalValue::Null) && !column.nullable {
            return Err(invalid(format!(
                "default for NOT NULL column {} cannot be NULL",
                column.name
            )));
        }
    }
    Ok((column, checks))
}

fn execute_create_index(
    state: &mut RelationalState,
    sequence: u64,
    create: sqlparser::ast::CreateIndex,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<SqlResult> {
    if create.concurrently
        || !create.include.is_empty()
        || create.nulls_distinct == Some(false)
        || !create.with.is_empty()
        || create.predicate.is_some()
        || !create.index_options.is_empty()
        || !create.alter_options.is_empty()
        || create
            .using
            .as_ref()
            .is_some_and(|using| !using.to_string().eq_ignore_ascii_case("btree"))
    {
        return Err(unsupported(
            "CREATE INDEX supports only non-partial BTREE column indexes",
        ));
    }
    let table_name = normalize_name(&create.table_name);
    let current = state
        .tables
        .get(&table_name)
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
    let mut definition = current.definition.as_ref().clone();
    let columns = create
        .columns
        .iter()
        .map(index_column_name)
        .collect::<Result<Vec<_>>>()?;
    if columns.is_empty() {
        return Err(invalid("CREATE INDEX requires at least one column"));
    }
    let name = create
        .name
        .as_ref()
        .map(normalize_name)
        .unwrap_or_else(|| format!("{}_{}_idx", table_name, columns.join("_")));
    if definition.indexes.iter().any(|index| index.name == name) {
        if create.if_not_exists {
            return Ok(SqlResult::Definition {
                affected_objects: 0,
            });
        }
        return Err(invalid(format!("index {name} already exists")));
    }
    if state.tables.values().any(|table| {
        table
            .definition
            .indexes
            .iter()
            .any(|index| index.name == name)
    }) {
        return Err(invalid(format!("index {name} already exists")));
    }
    definition.indexes.push(ScalarIndexDefinition {
        index_id: 0,
        name,
        columns,
        unique: create.unique,
    });
    assign_missing_catalog_ids(state, &mut definition)?;
    validate_definition(&definition)?;
    let table = Arc::make_mut(
        state
            .tables
            .get_mut(&table_name)?
            .expect("table existence checked"),
    );
    table.replace_definition(definition.clone(), sequence)?;
    mutations.push(RelationalMutation::AlterTable { definition });
    Ok(SqlResult::Definition {
        affected_objects: 1,
    })
}

fn execute_drop_index(
    state: &mut RelationalState,
    sequence: u64,
    if_exists: bool,
    names: Vec<sqlparser::ast::ObjectName>,
    cascade: bool,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<SqlResult> {
    if cascade || names.len() != 1 {
        return Err(unsupported(
            "DROP INDEX supports one index with RESTRICT behavior",
        ));
    }
    let name = normalize_name(&names[0]);
    let owner = state.tables.iter().find_map(|(table_name, table)| {
        table
            .definition
            .indexes
            .iter()
            .find(|index| index.name == name)
            .map(|index| (table_name.clone(), index.clone()))
    });
    let Some((table_name, index)) = owner else {
        if if_exists {
            return Ok(SqlResult::Definition {
                affected_objects: 0,
            });
        }
        return Err(invalid(format!("index {name} does not exist")));
    };
    if index.unique
        && state.tables.values().any(|table| {
            table.definition.foreign_keys.iter().any(|foreign_key| {
                foreign_key.referenced_table == table_name
                    && ((foreign_key.referenced_key_kind == Some(ReferencedKeyKind::UniqueIndex)
                        && foreign_key.referenced_key_name.as_deref() == Some(name.as_str()))
                        || (foreign_key.referenced_key_kind.is_none()
                            && state
                                .tables
                                .get(&table_name)
                                .and_then(|referenced| {
                                    resolved_referenced_columns(foreign_key, &referenced.definition)
                                        .ok()
                                })
                                .is_some_and(|columns| columns == index.columns)))
            })
        })
    {
        return Err(invalid(format!(
            "cannot drop index {name} because a foreign key depends on it"
        )));
    }
    let mut definition = state
        .tables
        .get(&table_name)
        .expect("index owner exists")
        .definition
        .as_ref()
        .clone();
    definition.indexes.retain(|index| index.name != name);
    assign_missing_catalog_ids(state, &mut definition)?;
    validate_definition(&definition)?;
    let table = Arc::make_mut(
        state
            .tables
            .get_mut(&table_name)?
            .expect("index owner exists"),
    );
    table.replace_definition(definition.clone(), sequence)?;
    mutations.push(RelationalMutation::AlterTable { definition });
    Ok(SqlResult::Definition {
        affected_objects: 1,
    })
}

fn execute_insert(
    state: &mut RelationalState,
    sequence: u64,
    insert: sqlparser::ast::Insert,
    parameters: &[RelationalValue],
    mutations: &mut Vec<RelationalMutation>,
) -> Result<SqlResult> {
    if insert.or.is_some()
        || insert.ignore
        || insert.overwrite
        || !insert.assignments.is_empty()
        || insert.partitioned.is_some()
        || !insert.after_columns.is_empty()
        || insert.has_table_keyword
        || insert.output.is_some()
        || insert.replace_into
        || insert.priority.is_some()
        || insert.table_alias.is_some()
        || insert.insert_alias.is_some()
        || insert.settings.is_some()
        || insert.format_clause.is_some()
        || insert.multi_table_insert_type.is_some()
        || !insert.multi_table_into_clauses.is_empty()
        || !insert.multi_table_when_clauses.is_empty()
        || insert.multi_table_else_clause.is_some()
    {
        return Err(unsupported(
            "INSERT modifier is outside the current profile",
        ));
    }
    let table_name = match insert.table {
        TableObject::TableName(name) => normalize_name(&name),
        _ => return Err(unsupported("INSERT target must be a table name")),
    };
    let on_insert = insert.on.clone();
    let returning = insert.returning.clone();
    let source = insert
        .source
        .ok_or_else(|| unsupported("INSERT requires VALUES"))?;
    let SetExpr::Values(values) = *source.body else {
        return Err(unsupported("INSERT ... SELECT is outside relational v1"));
    };
    let (definition, inserted, updated, affected, parent_changes) = {
        let table = state
            .tables
            .get_mut(&table_name)?
            .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
        let table = Arc::make_mut(table);
        let target_columns = if insert.columns.is_empty() {
            (0..table.definition.columns.len()).collect::<Vec<_>>()
        } else {
            insert
                .columns
                .iter()
                .map(|name| column_index(&table.definition, &normalize_name(name)))
                .collect::<Result<Vec<_>>>()?
        };
        let explicit_columns = target_columns.iter().copied().collect::<HashSet<_>>();
        let conflict_columns = on_insert
            .as_ref()
            .map(|on| conflict_target_columns(&table.definition, on))
            .transpose()?;
        if on_insert.as_ref().is_some_and(|on| {
            matches!(
                on,
                OnInsert::OnConflict(sqlparser::ast::OnConflict {
                    conflict_target: None,
                    action: OnConflictAction::DoUpdate(_),
                })
            )
        }) {
            return Err(invalid("ON CONFLICT DO UPDATE requires a conflict target"));
        }
        let mut inserted = Vec::with_capacity(values.rows.len());
        let mut updated = Vec::new();
        let mut affected = Vec::with_capacity(values.rows.len());
        let mut parent_changes = Vec::new();
        let mut statement_rows = HashSet::new();
        let mut parameter_cursor = 0;
        for expressions in values.rows {
            check_sql_cancelled()?;
            if expressions.len() != target_columns.len() {
                return Err(invalid("INSERT column/value count mismatch"));
            }
            let mut row = table
                .definition
                .columns
                .iter()
                .map(|column| column.default.clone().unwrap_or(RelationalValue::Null))
                .collect::<Vec<_>>();
            for (index, column) in table.definition.columns.iter().enumerate() {
                if column.identity.is_some() && !explicit_columns.contains(&index) {
                    row[index] = RelationalValue::Integer(
                        i64::try_from(table.next_row_id).map_err(|_| {
                            GaussError::ResourceExhausted(
                                "identity value exceeds signed 64-bit range".into(),
                            )
                        })?,
                    );
                }
            }
            for (expression, index) in expressions.iter().zip(&target_columns) {
                if is_default_value_expression(expression) {
                    if table.definition.columns[*index].identity.is_some() {
                        row[*index] = RelationalValue::Integer(
                            i64::try_from(table.next_row_id).map_err(|_| {
                                GaussError::ResourceExhausted(
                                    "identity value exceeds signed 64-bit range".into(),
                                )
                            })?,
                        );
                    }
                    continue;
                }
                if table.definition.columns[*index].identity == Some(IdentityGeneration::Always) {
                    return Err(invalid(format!(
                        "cannot insert an explicit value into GENERATED ALWAYS identity column {}",
                        table.definition.columns[*index].name
                    )));
                }
                row[*index] = expression_value(
                    expression,
                    &table.definition.columns[*index].data_type,
                    parameters,
                    &mut parameter_cursor,
                )?;
            }
            validate_row(&table.definition, &row)?;
            let conflict_row_id = conflict_columns
                .as_ref()
                .map(|columns| unique_conflict_row_id(table, columns, &row))
                .transpose()?
                .flatten();
            if let Some(row_id) = conflict_row_id {
                let Some(OnInsert::OnConflict(conflict)) = on_insert.as_ref() else {
                    unreachable!("conflict columns require ON CONFLICT");
                };
                match &conflict.action {
                    OnConflictAction::DoNothing => continue,
                    OnConflictAction::DoUpdate(update) => {
                        if !statement_rows.insert(row_id) {
                            return Err(invalid(
                                "ON CONFLICT DO UPDATE cannot affect row a second time",
                            ));
                        }
                        let old_values = table
                            .rows
                            .visible(row_id, sequence)?
                            .map(|version| version.values.to_vec())
                            .ok_or_else(|| invalid("conflicting row is not visible"))?;
                        if !upsert_predicate_matches(
                            update.selection.as_ref(),
                            &table.definition,
                            &old_values,
                            &row,
                            parameters,
                        )? {
                            continue;
                        }
                        let mut new_values = old_values.clone();
                        let mut assignment_columns = HashSet::new();
                        for assignment in &update.assignments {
                            let name = match &assignment.target {
                                AssignmentTarget::ColumnName(name) => normalize_name(name),
                                AssignmentTarget::Tuple(_) => {
                                    return Err(unsupported(
                                        "ON CONFLICT tuple assignment is outside the current profile",
                                    ));
                                }
                            };
                            let index = column_index(&table.definition, &name)?;
                            if !assignment_columns.insert(index) {
                                return Err(invalid(format!(
                                    "column {name} is assigned more than once"
                                )));
                            }
                            new_values[index] = upsert_expression_value(
                                &assignment.value,
                                &table.definition.columns[index].data_type,
                                &table.definition,
                                &old_values,
                                &row,
                                parameters,
                            )?;
                        }
                        validate_row(&table.definition, &new_values)?;
                        replace_visible_row(table, row_id, sequence, new_values.clone())?;
                        let stored = StoredRow {
                            row_id,
                            values: new_values.clone(),
                        };
                        updated.push(stored.clone());
                        affected.push(stored);
                        parent_changes.push(ParentChange {
                            table: table_name.clone(),
                            old_values,
                            new_values: Some(new_values),
                        });
                        continue;
                    }
                }
            }
            let row_id = table.next_row_id;
            table.next_row_id = table.next_row_id.checked_add(1).ok_or_else(|| {
                GaussError::ResourceExhausted("relational row ID overflow".into())
            })?;
            table.rows.insert(
                row_id,
                VersionChain::single(RowVersion {
                    begin: sequence,
                    end: None,
                    values: RowValues::copy(&row)?,
                })?,
            )?;
            table.index_row(row_id, &row)?;
            statement_rows.insert(row_id);
            let stored = StoredRow {
                row_id,
                values: row,
            };
            inserted.push(stored.clone());
            affected.push(stored);
        }
        (
            table.definition.clone(),
            inserted,
            updated,
            affected,
            parent_changes,
        )
    };
    let affected_rows = affected.len() as u64;
    if !inserted.is_empty() {
        mutations.push(RelationalMutation::Insert {
            table: table_name.clone(),
            rows: inserted.clone(),
        });
    }
    if !updated.is_empty() {
        mutations.push(RelationalMutation::Update {
            table: table_name,
            rows: updated,
        });
    }
    apply_referential_actions(state, sequence, parent_changes, mutations)?;
    if let Some(returning) = returning {
        project_returning_rows(&definition, &affected, &returning)
    } else {
        Ok(SqlResult::Mutation { affected_rows })
    }
}

fn is_default_value_expression(expression: &Expr) -> bool {
    matches!(expression, Expr::Identifier(identifier) if identifier.value.eq_ignore_ascii_case("default"))
}

fn conflict_target_columns(
    definition: &TableDefinition,
    on_insert: &OnInsert,
) -> Result<Vec<Vec<String>>> {
    let OnInsert::OnConflict(conflict) = on_insert else {
        return Err(unsupported("ON DUPLICATE KEY UPDATE is not supported"));
    };
    let declared = || {
        let mut keys = definition
            .unique_constraints
            .iter()
            .map(|constraint| constraint.columns.clone())
            .collect::<Vec<_>>();
        if !definition.primary_key.is_empty() {
            keys.push(definition.primary_key.clone());
        }
        keys.extend(
            definition
                .indexes
                .iter()
                .filter(|index| index.unique)
                .map(|index| index.columns.clone()),
        );
        keys
    };
    match &conflict.conflict_target {
        None => Ok(declared()),
        Some(ConflictTarget::Columns(columns)) => {
            let columns = columns
                .iter()
                .map(|column| normalize_ident(&column.value))
                .collect::<Vec<_>>();
            declared()
                .into_iter()
                .find(|key| {
                    key.len() == columns.len() && columns.iter().all(|column| key.contains(column))
                })
                .map(|key| vec![key])
                .ok_or_else(|| invalid("ON CONFLICT target must match a primary or unique key"))
        }
        Some(ConflictTarget::OnConstraint(name)) => {
            let name = normalize_name(name);
            if !definition.primary_key.is_empty() && name == primary_key_constraint_name(definition)
            {
                return Ok(vec![definition.primary_key.clone()]);
            }
            if let Some(constraint) = definition
                .unique_constraints
                .iter()
                .find(|constraint| constraint.name.as_deref() == Some(name.as_str()))
            {
                return Ok(vec![constraint.columns.clone()]);
            }
            Err(invalid(format!("unique constraint {name} does not exist")))
        }
    }
}

fn primary_key_constraint_name(definition: &TableDefinition) -> String {
    definition
        .primary_key_name
        .clone()
        .unwrap_or_else(|| format!("{}_pkey", definition.name))
}

fn unique_constraint_name(table_name: &str, constraint: &UniqueConstraint) -> String {
    constraint
        .name
        .clone()
        .unwrap_or_else(|| format!("{}_{}_key", table_name, constraint.columns.join("_")))
}

fn foreign_key_constraint_name(table_name: &str, foreign_key: &ForeignKeyDefinition) -> String {
    foreign_key
        .name
        .clone()
        .unwrap_or_else(|| format!("{}_{}_fkey", table_name, foreign_key.columns.join("_")))
}

fn check_constraint_name(
    table_name: &str,
    position: usize,
    constraint: &CheckConstraintDefinition,
) -> String {
    constraint
        .name
        .clone()
        .unwrap_or_else(|| format!("{}_check_{}", table_name, position + 1))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenamedConstraintKind {
    PrimaryKey,
    Unique,
    ForeignKey,
    Check,
}

impl RenamedConstraintKind {
    fn referenced_key_kind(self) -> Option<ReferencedKeyKind> {
        match self {
            Self::PrimaryKey => Some(ReferencedKeyKind::PrimaryKey),
            Self::Unique => Some(ReferencedKeyKind::UniqueConstraint),
            Self::ForeignKey | Self::Check => None,
        }
    }
}

fn rename_constraint_definition(
    table_name: &str,
    definition: &mut TableDefinition,
    old_name: &str,
    new_name: &str,
) -> Result<RenamedConstraintKind> {
    let all_names = std::iter::once((
        !definition.primary_key.is_empty(),
        primary_key_constraint_name(definition),
    ))
    .chain(
        definition
            .unique_constraints
            .iter()
            .map(|constraint| (true, unique_constraint_name(table_name, constraint))),
    )
    .chain(
        definition
            .foreign_keys
            .iter()
            .map(|foreign_key| (true, foreign_key_constraint_name(table_name, foreign_key))),
    )
    .chain(
        definition
            .check_constraints
            .iter()
            .enumerate()
            .map(|(position, constraint)| {
                (
                    true,
                    check_constraint_name(table_name, position, constraint),
                )
            }),
    )
    .filter_map(|(present, name)| present.then_some(name))
    .collect::<Vec<_>>();

    if !all_names.iter().any(|name| name == old_name) {
        return Err(invalid(format!("constraint {old_name} does not exist")));
    }
    if old_name == new_name {
        return Ok(
            if !definition.primary_key.is_empty()
                && primary_key_constraint_name(definition) == old_name
            {
                RenamedConstraintKind::PrimaryKey
            } else if definition
                .unique_constraints
                .iter()
                .any(|constraint| unique_constraint_name(table_name, constraint) == old_name)
            {
                RenamedConstraintKind::Unique
            } else if definition
                .foreign_keys
                .iter()
                .any(|constraint| foreign_key_constraint_name(table_name, constraint) == old_name)
            {
                RenamedConstraintKind::ForeignKey
            } else {
                RenamedConstraintKind::Check
            },
        );
    }
    if all_names.iter().any(|name| name == new_name) {
        return Err(invalid(format!("constraint {new_name} already exists")));
    }

    if !definition.primary_key.is_empty() && primary_key_constraint_name(definition) == old_name {
        definition.primary_key_name = Some(new_name.to_string());
        return Ok(RenamedConstraintKind::PrimaryKey);
    }
    if let Some(constraint) = definition
        .unique_constraints
        .iter_mut()
        .find(|constraint| unique_constraint_name(table_name, constraint) == old_name)
    {
        constraint.name = Some(new_name.to_string());
        return Ok(RenamedConstraintKind::Unique);
    }
    if let Some(constraint) = definition
        .foreign_keys
        .iter_mut()
        .find(|constraint| foreign_key_constraint_name(table_name, constraint) == old_name)
    {
        constraint.name = Some(new_name.to_string());
        return Ok(RenamedConstraintKind::ForeignKey);
    }
    if let Some(constraint) = definition
        .check_constraints
        .iter_mut()
        .enumerate()
        .find_map(|(position, constraint)| {
            (check_constraint_name(table_name, position, constraint) == old_name)
                .then_some(constraint)
        })
    {
        constraint.name = Some(new_name.to_string());
        return Ok(RenamedConstraintKind::Check);
    }
    unreachable!("constraint existence was checked")
}

fn unique_conflict_row_id(
    table: &TableState,
    keys: &[Vec<String>],
    row: &[RelationalValue],
) -> Result<Option<u64>> {
    for columns in keys {
        let indexes = columns
            .iter()
            .map(|column| column_index(&table.definition, column))
            .collect::<Result<Vec<_>>>()?;
        let values = indexes.iter().map(|index| &row[*index]).collect::<Vec<_>>();
        if let Some(mut entries) = table.indexed_entries(columns, &values)?
            && let Some((_, row_id)) = entries.next().transpose()?
        {
            return Ok(Some(row_id));
        }
    }
    Ok(None)
}

fn upsert_expression_value(
    expression: &Expr,
    expected: &RelationalType,
    definition: &TableDefinition,
    existing: &[RelationalValue],
    excluded: &[RelationalValue],
    parameters: &[RelationalValue],
) -> Result<RelationalValue> {
    let value = match expression {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            let (source, index) = upsert_column_reference(expression, definition)?;
            match source {
                UpsertRowSource::Existing => existing[index].clone(),
                UpsertRowSource::Excluded => excluded[index].clone(),
            }
        }
        Expr::Nested(expression) => upsert_expression_value(
            expression, expected, definition, existing, excluded, parameters,
        )?,
        Expr::BinaryOp { left, op, right }
            if matches!(
                op,
                BinaryOperator::Plus
                    | BinaryOperator::Minus
                    | BinaryOperator::Multiply
                    | BinaryOperator::Divide
                    | BinaryOperator::Modulo
                    | BinaryOperator::StringConcat
            ) =>
        {
            let left = upsert_expression_value(
                left,
                definition_type_for_expression(left, definition).unwrap_or(expected),
                definition,
                existing,
                excluded,
                parameters,
            )?;
            let right = upsert_expression_value(
                right,
                definition_type_for_expression(right, definition).unwrap_or(expected),
                definition,
                existing,
                excluded,
                parameters,
            )?;
            upsert_binary_value(left, op, right)?
        }
        _ => {
            let mut cursor = 0;
            expression_value(expression, expected, parameters, &mut cursor)?
        }
    };
    validate_value(expected, &value)?;
    Ok(value)
}

#[derive(Clone, Copy)]
enum UpsertRowSource {
    Existing,
    Excluded,
}

fn upsert_column_reference(
    expression: &Expr,
    definition: &TableDefinition,
) -> Result<(UpsertRowSource, usize)> {
    let (source, name) = match expression {
        Expr::Identifier(identifier) => (
            UpsertRowSource::Existing,
            normalize_ident(&identifier.value),
        ),
        Expr::CompoundIdentifier(identifiers) if identifiers.len() == 2 => {
            let qualifier = normalize_ident(&identifiers[0].value);
            let source = if qualifier == "excluded" {
                UpsertRowSource::Excluded
            } else if qualifier == definition.name {
                UpsertRowSource::Existing
            } else {
                return Err(invalid(format!(
                    "unknown ON CONFLICT row qualifier {qualifier}"
                )));
            };
            (source, normalize_ident(&identifiers[1].value))
        }
        _ => {
            return Err(unsupported(
                "ON CONFLICT expression requires a column reference",
            ));
        }
    };
    Ok((source, column_index(definition, &name)?))
}

fn definition_type_for_expression<'a>(
    expression: &Expr,
    definition: &'a TableDefinition,
) -> Option<&'a RelationalType> {
    let (_, index) = upsert_column_reference(expression, definition).ok()?;
    Some(&definition.columns[index].data_type)
}

fn upsert_binary_value(
    left: RelationalValue,
    operator: &BinaryOperator,
    right: RelationalValue,
) -> Result<RelationalValue> {
    if matches!(left, RelationalValue::Null) || matches!(right, RelationalValue::Null) {
        return Ok(RelationalValue::Null);
    }
    match (left, operator, right) {
        (RelationalValue::Integer(left), BinaryOperator::Plus, RelationalValue::Integer(right)) => {
            left.checked_add(right)
                .map(RelationalValue::Integer)
                .ok_or_else(|| invalid("integer addition overflow"))
        }
        (
            RelationalValue::Integer(left),
            BinaryOperator::Minus,
            RelationalValue::Integer(right),
        ) => left
            .checked_sub(right)
            .map(RelationalValue::Integer)
            .ok_or_else(|| invalid("integer subtraction overflow")),
        (
            RelationalValue::Integer(left),
            BinaryOperator::Multiply,
            RelationalValue::Integer(right),
        ) => left
            .checked_mul(right)
            .map(RelationalValue::Integer)
            .ok_or_else(|| invalid("integer multiplication overflow")),
        (RelationalValue::Integer(_), BinaryOperator::Divide, RelationalValue::Integer(0))
        | (RelationalValue::Integer(_), BinaryOperator::Modulo, RelationalValue::Integer(0)) => {
            Err(invalid("division by zero"))
        }
        (
            RelationalValue::Integer(left),
            BinaryOperator::Divide,
            RelationalValue::Integer(right),
        ) => left
            .checked_div(right)
            .map(RelationalValue::Integer)
            .ok_or_else(|| invalid("integer division overflow")),
        (
            RelationalValue::Integer(left),
            BinaryOperator::Modulo,
            RelationalValue::Integer(right),
        ) => left
            .checked_rem(right)
            .map(RelationalValue::Integer)
            .ok_or_else(|| invalid("integer remainder overflow")),
        (RelationalValue::Float(left), BinaryOperator::Plus, RelationalValue::Float(right)) => {
            Ok(RelationalValue::Float(left + right))
        }
        (RelationalValue::Float(left), BinaryOperator::Minus, RelationalValue::Float(right)) => {
            Ok(RelationalValue::Float(left - right))
        }
        (RelationalValue::Float(left), BinaryOperator::Multiply, RelationalValue::Float(right)) => {
            Ok(RelationalValue::Float(left * right))
        }
        (RelationalValue::Float(_), BinaryOperator::Divide, RelationalValue::Float(0.0)) => {
            Err(invalid("division by zero"))
        }
        (RelationalValue::Float(left), BinaryOperator::Divide, RelationalValue::Float(right)) => {
            Ok(RelationalValue::Float(left / right))
        }
        (
            RelationalValue::Text(mut left),
            BinaryOperator::StringConcat,
            RelationalValue::Text(right),
        ) => {
            left.push_str(&right);
            Ok(RelationalValue::Text(left))
        }
        _ => Err(unsupported(
            "ON CONFLICT arithmetic requires matching integer, float, or text operands",
        )),
    }
}

fn upsert_predicate_matches(
    expression: Option<&Expr>,
    definition: &TableDefinition,
    existing: &[RelationalValue],
    excluded: &[RelationalValue],
    parameters: &[RelationalValue],
) -> Result<bool> {
    Ok(
        upsert_predicate_result(expression, definition, existing, excluded, parameters)?
            .unwrap_or(false),
    )
}

fn upsert_predicate_result(
    expression: Option<&Expr>,
    definition: &TableDefinition,
    existing: &[RelationalValue],
    excluded: &[RelationalValue],
    parameters: &[RelationalValue],
) -> Result<Option<bool>> {
    let Some(expression) = expression else {
        return Ok(Some(true));
    };
    match expression {
        Expr::Nested(expression) => {
            upsert_predicate_result(Some(expression), definition, existing, excluded, parameters)
        }
        Expr::UnaryOp { op, expr } if op.to_string().eq_ignore_ascii_case("not") => Ok(
            upsert_predicate_result(Some(expr), definition, existing, excluded, parameters)?
                .map(|value| !value),
        ),
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::And => Ok(sql_and(
            upsert_predicate_result(Some(left), definition, existing, excluded, parameters)?,
            upsert_predicate_result(Some(right), definition, existing, excluded, parameters)?,
        )),
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::Or => Ok(sql_or(
            upsert_predicate_result(Some(left), definition, existing, excluded, parameters)?,
            upsert_predicate_result(Some(right), definition, existing, excluded, parameters)?,
        )),
        Expr::BinaryOp { left, op, right }
            if matches!(
                op,
                BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::Lt
                    | BinaryOperator::LtEq
                    | BinaryOperator::Gt
                    | BinaryOperator::GtEq
            ) =>
        {
            let expected = definition_type_for_expression(left, definition)
                .or_else(|| definition_type_for_expression(right, definition))
                .ok_or_else(|| {
                    unsupported("ON CONFLICT WHERE comparison requires a column reference")
                })?;
            let left = upsert_expression_value(
                left, expected, definition, existing, excluded, parameters,
            )?;
            let right = upsert_expression_value(
                right, expected, definition, existing, excluded, parameters,
            )?;
            if matches!(left, RelationalValue::Null) || matches!(right, RelationalValue::Null) {
                Ok(None)
            } else {
                compare_predicate(&left, &right, op).map(Some)
            }
        }
        Expr::IsNull(expression) => {
            let expected = definition_type_for_expression(expression, definition)
                .ok_or_else(|| unsupported("IS NULL requires a column reference"))?;
            Ok(Some(matches!(
                upsert_expression_value(
                    expression, expected, definition, existing, excluded, parameters,
                )?,
                RelationalValue::Null
            )))
        }
        Expr::IsNotNull(expression) => {
            let expected = definition_type_for_expression(expression, definition)
                .ok_or_else(|| unsupported("IS NOT NULL requires a column reference"))?;
            Ok(Some(!matches!(
                upsert_expression_value(
                    expression, expected, definition, existing, excluded, parameters,
                )?,
                RelationalValue::Null
            )))
        }
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            let value = upsert_expression_value(
                expression,
                &RelationalType::Boolean,
                definition,
                existing,
                excluded,
                parameters,
            )?;
            match value {
                RelationalValue::Boolean(value) => Ok(Some(value)),
                RelationalValue::Null => Ok(None),
                _ => Err(invalid("bare ON CONFLICT predicate must be BOOLEAN")),
            }
        }
        Expr::Value(value) if matches!(&value.value, Value::Boolean(_)) => {
            Ok(Some(matches!(&value.value, Value::Boolean(true))))
        }
        _ => Err(unsupported(
            "ON CONFLICT WHERE expression is outside the current profile",
        )),
    }
}

fn project_returning_rows(
    definition: &TableDefinition,
    rows: &[StoredRow],
    returning: &[SelectItem],
) -> Result<SqlResult> {
    let columns = definition
        .columns
        .iter()
        .map(|column| QueryColumn {
            qualifier: definition.name.clone(),
            name: column.name.clone(),
            data_type: column.data_type.clone(),
        })
        .collect::<Vec<_>>();
    let projection = query_projection(&columns, returning)?;
    Ok(SqlResult::Rows {
        columns: projection.iter().map(|item| item.name.clone()).collect(),
        column_types: projection
            .iter()
            .map(|item| item.data_type.clone())
            .collect(),
        rows: rows
            .iter()
            .map(|row| {
                projection
                    .iter()
                    .map(|item| match &item.source {
                        QueryProjectionSource::Column(index) => row.values[*index].clone(),
                        QueryProjectionSource::RecordRef {
                            namespace,
                            id_column,
                        } => RelationalValue::RecordRef(chirondb_types::RecordRef {
                            namespace: namespace.clone(),
                            id: relational_id(&row.values[*id_column]),
                        }),
                        QueryProjectionSource::Scalar(value) => value.clone(),
                    })
                    .collect()
            })
            .collect(),
    })
}

fn execute_update(
    state: &mut RelationalState,
    sequence: u64,
    update: sqlparser::ast::Update,
    parameters: &[RelationalValue],
    mutations: &mut Vec<RelationalMutation>,
) -> Result<SqlResult> {
    if !update.table.joins.is_empty() || update.from.is_some() {
        return Err(unsupported(
            "UPDATE joins and FROM are outside the current profile",
        ));
    }
    let returning = update.returning.clone();
    let table_name = table_factor_name(&update.table.relation)?;
    let definition = state
        .tables
        .get(&table_name)
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?
        .definition
        .clone();
    let mut assignment_cursor = 0;
    let assignment_values = update
        .assignments
        .iter()
        .map(|assignment| {
            let name = match &assignment.target {
                AssignmentTarget::ColumnName(name) => Ok(normalize_name(name)),
                AssignmentTarget::Tuple(_) => {
                    Err(unsupported("tuple assignment is outside relational v1"))
                }
            }?;
            let index = column_index(&definition, &name)?;
            let value = expression_value(
                &assignment.value,
                &definition.columns[index].data_type,
                parameters,
                &mut assignment_cursor,
            )?;
            Ok((index, value))
        })
        .collect::<Result<Vec<_>>>()?;
    let predicate_parameter_start = assignment_cursor;
    let candidates = mutation_candidates(
        state,
        &update.table.relation,
        update.selection.as_ref(),
        parameters,
        assignment_cursor,
        sequence,
    )?;
    let mut changed = Vec::new();
    let mut parent_changes = Vec::new();
    for (row_id, old_values) in candidates {
        check_sql_cancelled()?;
        let mut cursor = predicate_parameter_start;
        if !predicate_matches(
            update.selection.as_ref(),
            &definition,
            &old_values,
            parameters,
            &mut cursor,
        )? {
            continue;
        }
        let mut values = old_values.to_vec();
        for (index, value) in &assignment_values {
            values[*index] = value.clone();
        }
        validate_row(&definition, &values)?;
        update_visible_row(state, &table_name, row_id, sequence, values.clone())?;
        changed.push(StoredRow {
            row_id,
            values: values.clone(),
        });
        parent_changes.push(ParentChange {
            table: table_name.clone(),
            old_values: old_values.to_vec(),
            new_values: Some(values),
        });
    }
    let affected_rows = changed.len() as u64;
    mutations.push(RelationalMutation::Update {
        table: table_name.clone(),
        rows: changed.clone(),
    });
    // A non-deferrable key conflict is raised by the row update itself in
    // PostgreSQL. Check the updated table before ON UPDATE actions can report
    // a competing RESTRICT violation for the same statement.
    validate_updated_unique_constraints(
        state
            .tables
            .get(&table_name)
            .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?,
        &changed,
    )?;
    apply_referential_actions(state, sequence, parent_changes, mutations)?;
    if let Some(returning) = returning {
        project_returning_rows(&definition, &changed, &returning)
    } else {
        Ok(SqlResult::Mutation { affected_rows })
    }
}

fn execute_delete(
    state: &mut RelationalState,
    sequence: u64,
    delete: sqlparser::ast::Delete,
    parameters: &[RelationalValue],
    mutations: &mut Vec<RelationalMutation>,
) -> Result<SqlResult> {
    if delete.using.is_some() || !delete.order_by.is_empty() {
        return Err(unsupported(
            "DELETE USING and ORDER BY are outside the current profile",
        ));
    }
    let returning = delete.returning.clone();
    let from = match delete.from {
        FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from) => from,
    };
    if from.len() != 1 || !from[0].joins.is_empty() {
        return Err(unsupported("DELETE supports exactly one table"));
    }
    let table_name = table_factor_name(&from[0].relation)?;
    let definition = state
        .tables
        .get(&table_name)
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?
        .definition
        .clone();
    let candidates = mutation_candidates(
        state,
        &from[0].relation,
        delete.selection.as_ref(),
        parameters,
        0,
        sequence,
    )?;
    let mut deleted = Vec::new();
    let mut deleted_rows = Vec::new();
    let mut parent_changes = Vec::new();
    for (row_id, old_values) in candidates {
        check_sql_cancelled()?;
        let mut cursor = 0;
        if predicate_matches(
            delete.selection.as_ref(),
            &definition,
            &old_values,
            parameters,
            &mut cursor,
        )? {
            delete_visible_row(state, &table_name, row_id, sequence)?;
            deleted.push(row_id);
            deleted_rows.push(StoredRow {
                row_id,
                values: old_values.to_vec(),
            });
            parent_changes.push(ParentChange {
                table: table_name.clone(),
                old_values: old_values.to_vec(),
                new_values: None,
            });
        }
    }
    let affected_rows = deleted.len() as u64;
    mutations.push(RelationalMutation::Delete {
        table: table_name.clone(),
        row_ids: deleted,
    });
    apply_referential_actions(state, sequence, parent_changes, mutations)?;
    if let Some(returning) = returning {
        project_returning_rows(&definition, &deleted_rows, &returning)
    } else {
        Ok(SqlResult::Mutation { affected_rows })
    }
}

fn apply_referential_actions(
    state: &mut RelationalState,
    sequence: u64,
    initial_changes: Vec<ParentChange>,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<()> {
    let mut operator_bytes = 0;
    let mut queue = VecDeque::from(initial_changes);
    let mut visited = HashSet::new();
    let mut action_rows = 0_usize;

    while let Some(change) = queue.pop_front() {
        check_sql_cancelled()?;
        let parent_definition = state
            .tables
            .get(&change.table)
            .ok_or_else(|| invalid(format!("table {} does not exist", change.table)))?
            .definition
            .clone();
        let references = state
            .tables
            .iter()
            .flat_map(|(child_name, table)| {
                table
                    .definition
                    .foreign_keys
                    .iter()
                    .filter(|foreign_key| foreign_key.referenced_table == change.table)
                    .cloned()
                    .map(|foreign_key| (child_name.clone(), foreign_key))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for (child_name, foreign_key) in references {
            let referenced_columns = resolved_referenced_columns(&foreign_key, &parent_definition)?;
            let parent_indexes = referenced_columns
                .iter()
                .map(|name| column_index(&parent_definition, name))
                .collect::<Result<Vec<_>>>()?;
            let Some(old_key) = composite_key(&change.old_values, &parent_indexes) else {
                continue;
            };
            let new_key = change
                .new_values
                .as_ref()
                .and_then(|values| composite_key(values, &parent_indexes));
            if change.new_values.is_some() && new_key.as_ref() == Some(&old_key) {
                continue;
            }

            let action = if change.new_values.is_some() {
                foreign_key.on_update
            } else {
                foreign_key.on_delete
            };
            if action == ForeignKeyAction::NoAction {
                continue;
            }
            let child_definition = state
                .tables
                .get(&child_name)
                .ok_or_else(|| invalid(format!("table {child_name} does not exist")))?
                .definition
                .clone();
            let child_indexes = foreign_key
                .columns
                .iter()
                .map(|name| column_index(&child_definition, name))
                .collect::<Result<Vec<_>>>()?;
            let child_table = state
                .tables
                .get(&child_name)
                .ok_or_else(|| invalid(format!("table {child_name} does not exist")))?;
            let mut matching_rows = Vec::new();
            let lookup_values = parent_indexes
                .iter()
                .map(|index| &change.old_values[*index])
                .collect::<Vec<_>>();
            if let Some(entries) =
                child_table.indexed_entries(&foreign_key.columns, &lookup_values)?
            {
                for entry in entries {
                    let (_, row_id) = entry?;
                    if let Some(version) = child_table.rows.visible(row_id, sequence)? {
                        if action == ForeignKeyAction::Restrict {
                            return Err(invalid(format!(
                                "foreign key {} restricts the referenced row change",
                                foreign_key.name.as_deref().unwrap_or("<unnamed>")
                            )));
                        }
                        if matching_rows.len() == MAX_ROWS_PER_RESULT {
                            return Err(GaussError::ResourceExhausted(format!(
                                "disk index lookup exceeded {MAX_ROWS_PER_RESULT} candidate rows"
                            )));
                        }
                        charge_query_operator_row(&mut operator_bytes, &version.values)?;
                        matching_rows.push((row_id, version.values));
                    }
                }
            }

            if matching_rows.is_empty() {
                continue;
            }

            for (row_id, observed_values) in matching_rows {
                check_sql_cancelled()?;
                let visit_key = (
                    child_name.clone(),
                    row_id,
                    foreign_key
                        .name
                        .clone()
                        .unwrap_or_else(|| foreign_key.columns.join(",")),
                    old_key.clone(),
                );
                if visited.contains(&visit_key) {
                    continue;
                }
                charge_query_operator_bytes(
                    &mut operator_bytes,
                    std::mem::size_of_val(&visit_key)
                        .saturating_add(visit_key.0.len())
                        .saturating_add(visit_key.2.len())
                        .saturating_add(visit_key.3.len()),
                )?;
                visited.insert(visit_key);
                action_rows = action_rows.saturating_add(1);
                if action_rows > MAX_REFERENTIAL_ACTION_ROWS {
                    return Err(GaussError::ResourceExhausted(format!(
                        "foreign-key action exceeds {MAX_REFERENTIAL_ACTION_ROWS} affected rows"
                    )));
                }

                match action {
                    ForeignKeyAction::Cascade if change.new_values.is_none() => {
                        delete_visible_row(state, &child_name, row_id, sequence)?;
                        mutations.push(RelationalMutation::Delete {
                            table: child_name.clone(),
                            row_ids: vec![row_id],
                        });
                        let next = ParentChange {
                            table: child_name.clone(),
                            old_values: observed_values.to_vec(),
                            new_values: None,
                        };
                        charge_enqueued_parent_change(&mut operator_bytes, &next)?;
                        queue.push_back(next);
                    }
                    ForeignKeyAction::Cascade
                    | ForeignKeyAction::SetNull
                    | ForeignKeyAction::SetDefault => {
                        let mut values = observed_values.to_vec();
                        match action {
                            ForeignKeyAction::Cascade => {
                                let new_values = change.new_values.as_ref().ok_or_else(|| {
                                    invalid("ON DELETE CASCADE must delete referencing rows")
                                })?;
                                for (child_index, parent_index) in
                                    child_indexes.iter().zip(&parent_indexes)
                                {
                                    values[*child_index] = new_values[*parent_index].clone();
                                }
                            }
                            ForeignKeyAction::SetNull => {
                                for child_index in &child_indexes {
                                    values[*child_index] = RelationalValue::Null;
                                }
                            }
                            ForeignKeyAction::SetDefault => {
                                for child_index in &child_indexes {
                                    values[*child_index] = child_definition.columns[*child_index]
                                        .default
                                        .clone()
                                        .unwrap_or(RelationalValue::Null);
                                }
                            }
                            ForeignKeyAction::NoAction | ForeignKeyAction::Restrict => {
                                unreachable!("handled before referential action mutation")
                            }
                        }
                        validate_row(&child_definition, &values)?;
                        charge_query_operator_row(&mut operator_bytes, &values)?;
                        update_visible_row(state, &child_name, row_id, sequence, values.clone())?;
                        mutations.push(RelationalMutation::Update {
                            table: child_name.clone(),
                            rows: vec![StoredRow {
                                row_id,
                                values: values.clone(),
                            }],
                        });
                        let next = ParentChange {
                            table: child_name.clone(),
                            old_values: observed_values.to_vec(),
                            new_values: Some(values),
                        };
                        charge_enqueued_parent_change(&mut operator_bytes, &next)?;
                        queue.push_back(next);
                    }
                    ForeignKeyAction::NoAction | ForeignKeyAction::Restrict => {
                        unreachable!("handled before referential action mutation")
                    }
                }
            }
        }
    }
    Ok(())
}

fn charge_enqueued_parent_change(charged: &mut usize, change: &ParentChange) -> Result<()> {
    charge_query_operator_bytes(
        charged,
        std::mem::size_of::<ParentChange>().saturating_add(change.table.len()),
    )?;
    if let Some(values) = &change.new_values {
        charge_query_operator_row(charged, values)?;
    }
    Ok(())
}

fn allocate_catalog_id(state: &mut RelationalState) -> Result<u64> {
    let id = state.next_catalog_id;
    state.next_catalog_id = state.next_catalog_id.checked_add(1).ok_or_else(|| {
        GaussError::ResourceExhausted("relational catalog ID space exhausted".into())
    })?;
    Ok(id)
}

fn catalog_index_owners(definition: &TableDefinition) -> impl Iterator<Item = (u64, &[String])> {
    definition
        .primary_key_index_id
        .into_iter()
        .map(|id| (id, definition.primary_key.as_slice()))
        .chain(
            definition
                .unique_constraints
                .iter()
                .map(|constraint| (constraint.index_id, constraint.columns.as_slice())),
        )
        .chain(
            definition
                .indexes
                .iter()
                .map(|index| (index.index_id, index.columns.as_slice())),
        )
        .chain(
            definition
                .foreign_keys
                .iter()
                .map(|foreign_key| (foreign_key.index_id, foreign_key.columns.as_slice())),
        )
        .chain(
            definition
                .reference_index_ids
                .iter()
                .map(|(column, id)| (*id, std::slice::from_ref(column))),
        )
}

fn existing_index_id(definition: &TableDefinition, columns: &[String]) -> Option<u64> {
    catalog_index_owners(definition).find_map(|(index_id, candidate)| {
        (index_id != 0 && candidate == columns).then_some(index_id)
    })
}

fn assign_missing_catalog_ids(
    state: &mut RelationalState,
    definition: &mut TableDefinition,
) -> Result<()> {
    if definition.table_id == 0 {
        definition.table_id = allocate_catalog_id(state)?;
    }
    if !definition.primary_key.is_empty() && definition.primary_key_index_id.is_none() {
        definition.primary_key_index_id = Some(
            existing_index_id(definition, &definition.primary_key)
                .map(Ok)
                .unwrap_or_else(|| allocate_catalog_id(state))?,
        );
    }
    for position in 0..definition.unique_constraints.len() {
        if definition.unique_constraints[position].index_id == 0 {
            let columns = definition.unique_constraints[position].columns.clone();
            definition.unique_constraints[position].index_id =
                existing_index_id(definition, &columns)
                    .map(Ok)
                    .unwrap_or_else(|| allocate_catalog_id(state))?;
        }
    }
    for position in 0..definition.indexes.len() {
        if definition.indexes[position].index_id == 0 {
            let columns = definition.indexes[position].columns.clone();
            definition.indexes[position].index_id = existing_index_id(definition, &columns)
                .map(Ok)
                .unwrap_or_else(|| allocate_catalog_id(state))?;
        }
    }
    for position in 0..definition.foreign_keys.len() {
        if definition.foreign_keys[position].index_id == 0 {
            let columns = definition.foreign_keys[position].columns.clone();
            definition.foreign_keys[position].index_id = existing_index_id(definition, &columns)
                .map(Ok)
                .unwrap_or_else(|| allocate_catalog_id(state))?;
        }
    }
    let reference_columns = definition
        .columns
        .iter()
        .filter(|column| {
            definition.tenant_id.is_some()
                && matches!(column.data_type, RelationalType::RecordRef { .. })
        })
        .map(|column| column.name.clone())
        .collect::<BTreeSet<_>>();
    definition
        .reference_index_ids
        .retain(|column, _| reference_columns.contains(column));
    for column in reference_columns {
        if !definition.reference_index_ids.contains_key(&column) {
            let id = existing_index_id(definition, std::slice::from_ref(&column))
                .map(Ok)
                .unwrap_or_else(|| allocate_catalog_id(state))?;
            definition.reference_index_ids.insert(column, id);
        }
    }
    Ok(())
}

fn catalog_id_frontier(definition: &TableDefinition) -> u64 {
    catalog_index_owners(definition)
        .map(|(index_id, _)| index_id)
        .chain(std::iter::once(definition.table_id))
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn composite_key(values: &[RelationalValue], indexes: &[usize]) -> Option<Vec<u8>> {
    if indexes
        .iter()
        .any(|index| matches!(values[*index], RelationalValue::Null))
    {
        return None;
    }
    let mut encoded = Vec::new();
    for index in indexes {
        let part = encode_equality_value(&values[*index]);
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(&part);
    }
    Some(encoded)
}

fn delete_visible_row(
    state: &mut RelationalState,
    table_name: &str,
    row_id: u64,
    sequence: u64,
) -> Result<()> {
    let table = state
        .tables
        .get_mut(table_name)?
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
    let table = Arc::make_mut(table);
    end_visible_row(table, row_id, sequence)
}

fn update_visible_row(
    state: &mut RelationalState,
    table_name: &str,
    row_id: u64,
    sequence: u64,
    values: Vec<RelationalValue>,
) -> Result<()> {
    let table = state
        .tables
        .get_mut(table_name)?
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
    let table = Arc::make_mut(table);
    replace_visible_row(table, row_id, sequence, values)
}

fn end_visible_row(table: &mut TableState, row_id: u64, sequence: u64) -> Result<()> {
    let mut versions = table
        .rows
        .get(&row_id)?
        .ok_or_else(|| invalid(format!("row {row_id} does not exist")))?
        .into_owned()?;
    let position = versions
        .iter()
        .rposition(|version| {
            version.begin <= sequence && version.end.is_none_or(|end| sequence < end)
        })
        .ok_or_else(|| invalid(format!("row {row_id} is not visible")))?;
    table.unindex_row(row_id, &versions[position].values)?;
    if versions[position].begin == sequence {
        versions.remove(position);
    } else {
        versions[position].end = Some(sequence);
    }
    table.rows.insert(row_id, versions)?;
    Ok(())
}

fn replace_visible_row(
    table: &mut TableState,
    row_id: u64,
    sequence: u64,
    values: Vec<RelationalValue>,
) -> Result<()> {
    let mut versions = table
        .rows
        .get(&row_id)?
        .ok_or_else(|| invalid(format!("row {row_id} does not exist")))?
        .into_owned()?;
    let position = versions
        .iter()
        .rposition(|version| {
            version.begin <= sequence && version.end.is_none_or(|end| sequence < end)
        })
        .ok_or_else(|| invalid(format!("row {row_id} is not visible")))?;
    table.unindex_row(row_id, &versions[position].values)?;
    if versions[position].begin == sequence {
        versions[position].values = RowValues::copy(&values)?;
    } else {
        versions[position].end = Some(sequence);
        versions.push(RowVersion {
            begin: sequence,
            end: None,
            values: RowValues::copy(&values)?,
        })?;
    }
    table.rows.insert(row_id, versions)?;
    table.index_row(row_id, &values)?;
    Ok(())
}

fn execute_query(
    state: &RelationalState,
    snapshot: u64,
    query: &Query,
    parameters: &[RelationalValue],
) -> Result<SqlResult> {
    let cte_state = query
        .with
        .as_ref()
        .map(|with| materialize_ctes(state, snapshot, with, parameters))
        .transpose()?;
    let state = cte_state.as_ref().unwrap_or(state);
    if query.fetch.is_some() || !query.locks.is_empty() {
        return Err(unsupported("FETCH and row locks are outside relational v1"));
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Err(unsupported("set operations are outside relational v1"));
    };
    if select.from.len() != 1 {
        return Err(unsupported("SELECT requires exactly one FROM source"));
    }
    if select.top.is_some()
        || select.into.is_some()
        || select.prewhere.is_some()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
    {
        return Err(unsupported(
            "dialect-specific SELECT clauses are not yet implemented",
        ));
    }
    let distinct = match select.distinct.as_ref() {
        None | Some(Distinct::All) => false,
        Some(Distinct::Distinct) => true,
        Some(Distinct::On(_)) => {
            return Err(unsupported("DISTINCT ON is outside relational v1"));
        }
    };
    let indexed_probe = if select.from[0].joins.is_empty() {
        indexed_selection_probe(
            state,
            snapshot,
            &select.from[0].relation,
            select.selection.as_ref(),
            parameters,
            0,
        )?
    } else {
        None
    };
    let aggregate = query_uses_aggregation(select)?;
    if query.with.is_none()
        && select.from[0].joins.is_empty()
        && !distinct
        && !aggregate
        && let Some(result) =
            execute_ordered_primary_range(state, snapshot, query, select, parameters)?
    {
        return Ok(result);
    }
    if query.with.is_none()
        && select.from[0].joins.is_empty()
        && !distinct
        && !aggregate
        && let Some(result) = execute_topk_query(
            state,
            snapshot,
            query,
            select,
            parameters,
            indexed_probe.as_ref(),
        )?
    {
        return Ok(result);
    }
    if query.with.is_none()
        && select.from[0].joins.is_empty()
        && query.order_by.is_none()
        && !distinct
    {
        if aggregate
            && let Some(result) = execute_streaming_count(
                state,
                snapshot,
                query,
                select,
                parameters,
                indexed_probe.as_ref(),
            )?
        {
            return Ok(result);
        }
        if !aggregate {
            return execute_streaming_query(
                state,
                snapshot,
                query,
                select,
                parameters,
                indexed_probe.as_ref(),
            );
        }
    }
    let mut relation = query_relation_with_row_ids(
        state,
        snapshot,
        &select.from[0].relation,
        indexed_probe.as_ref(),
    )?;
    for join in &select.from[0].joins {
        relation = apply_join(state, snapshot, relation, join)?;
    }
    let mut selected = Vec::<(usize, RowValues)>::new();
    for (row_id, row) in relation.rows.into_iter().enumerate() {
        check_sql_cancelled()?;
        let mut cursor = 0;
        if query_predicate_matches(
            state,
            snapshot,
            select.selection.as_ref(),
            &relation.columns,
            &row,
            parameters,
            &mut cursor,
        )? {
            selected.push((row_id, row));
        }
    }
    if query_uses_aggregation(select)? {
        return execute_aggregate_query(&relation.columns, &selected, select, query, parameters);
    }
    let projection = query_projection_with_subqueries(
        state,
        snapshot,
        &relation.columns,
        &select.projection,
        parameters,
    )?;
    if distinct {
        validate_distinct_order_by(&projection, query.order_by.as_ref(), &relation.columns)?;
    }
    if let Some(order_by) = &query.order_by {
        if order_by.interpolate.is_some() {
            return Err(unsupported("ORDER BY INTERPOLATE is outside relational v1"));
        }
        let OrderByKind::Expressions(expressions) = &order_by.kind else {
            return Err(unsupported("ORDER BY ALL is outside relational v1"));
        };
        let ordering = expressions
            .iter()
            .map(|expression| {
                if expression.with_fill.is_some() {
                    return Err(unsupported("ORDER BY WITH FILL is outside relational v1"));
                }
                let key = query_order_key(&relation.columns, &projection, &expression.expr)?;
                Ok(QueryOrderSpec {
                    index: key.source_index,
                    ascending: expression.options.asc.unwrap_or(true),
                    nulls_first: expression.options.nulls_first,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        selected.sort_by(|left, right| {
            compare_query_order(&left.1, left.0, &right.1, right.0, &ordering)
        });
    }
    let (limit, offset) = match &query.limit_clause {
        None => (None, 0),
        Some(LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        }) if limit_by.is_empty() => {
            let requested = limit
                .as_ref()
                .map(|limit| {
                    usize::try_from(integer_literal(limit)?).map_err(|_| {
                        GaussError::ResourceExhausted("LIMIT exceeds platform size".into())
                    })
                })
                .transpose()?;
            if requested.is_some_and(|requested| requested > MAX_ROWS_PER_RESULT) {
                return Err(GaussError::ResourceExhausted(format!(
                    "LIMIT exceeds maximum result rows {MAX_ROWS_PER_RESULT}"
                )));
            }
            let offset = offset
                .as_ref()
                .map(|offset| {
                    usize::try_from(integer_literal(&offset.value)?).map_err(|_| {
                        GaussError::ResourceExhausted("OFFSET exceeds platform size".into())
                    })
                })
                .transpose()?
                .unwrap_or(0);
            (requested, offset)
        }
        _ => {
            return Err(unsupported(
                "dialect-specific LIMIT is outside relational v1",
            ));
        }
    };
    if is_count_star(&select.projection) {
        let rows = if limit == Some(0) || offset > 0 {
            Vec::new()
        } else {
            vec![vec![RelationalValue::Integer(selected.len() as i64)]]
        };
        return Ok(SqlResult::Rows {
            columns: vec!["count".to_string()],
            column_types: vec![RelationalType::BigInt],
            rows,
        });
    }
    if !distinct && selected.len().saturating_sub(offset) > MAX_ROWS_PER_RESULT && limit.is_none() {
        return Err(GaussError::ResourceExhausted(format!(
            "query produced more than {MAX_ROWS_PER_RESULT} rows; add a smaller LIMIT"
        )));
    }
    let unbounded = limit.is_none();
    let limit = limit.unwrap_or(MAX_ROWS_PER_RESULT);
    let columns = projection.iter().map(|item| item.name.clone()).collect();
    let column_types = projection
        .iter()
        .map(|item| item.data_type.clone())
        .collect();
    let mut rows = selected
        .into_iter()
        .map(|(_, values)| {
            projection
                .iter()
                .map(|item| match &item.source {
                    QueryProjectionSource::Column(index) => values[*index].clone(),
                    QueryProjectionSource::RecordRef {
                        namespace,
                        id_column,
                    } => {
                        if matches!(values[*id_column], RelationalValue::Null) {
                            RelationalValue::Null
                        } else {
                            RelationalValue::RecordRef(chirondb_types::RecordRef {
                                namespace: namespace.clone(),
                                id: relational_id(&values[*id_column]),
                            })
                        }
                    }
                    QueryProjectionSource::Scalar(value) => value.clone(),
                })
                .collect()
        })
        .collect::<Vec<Vec<RelationalValue>>>();
    if distinct {
        deduplicate_rows(&mut rows);
    }
    if rows.len().saturating_sub(offset) > MAX_ROWS_PER_RESULT && unbounded {
        return Err(GaussError::ResourceExhausted(format!(
            "query produced more than {MAX_ROWS_PER_RESULT} rows; add a smaller LIMIT"
        )));
    }
    let rows = rows.into_iter().skip(offset).take(limit).collect();
    Ok(SqlResult::Rows {
        columns,
        column_types,
        rows,
    })
}

fn query_source_rows<'a>(
    table: &'a TableState,
    snapshot: u64,
    probe: Option<&IndexedSelectionProbe>,
) -> Result<Box<dyn Iterator<Item = Result<RowValues>> + 'a>> {
    match probe {
        Some(IndexedSelectionProbe { key: None, .. }) => Ok(Box::new(std::iter::empty())),
        Some(IndexedSelectionProbe {
            columns,
            key: Some(key),
        }) => {
            let index = table
                .indexes
                .get(columns)
                .ok_or_else(|| invalid("missing scalar index"))?;
            let entries = index.entries(&table.index_segments, snapshot, Some(key))?;
            Ok(Box::new(entries.filter_map(move |entry| match entry {
                Ok((_, id)) => match table.rows.visible(id, snapshot) {
                    Ok(Some(version)) => Some(Ok(version.values)),
                    Ok(None) => None,
                    Err(error) => Some(Err(error)),
                },
                Err(error) => Some(Err(error)),
            })))
        }
        None => Ok(Box::new(
            table
                .rows
                .visible_rows(snapshot)
                .map(|row| row.map(|(_, values)| values)),
        )),
    }
}

fn compare_query_order(
    left: &[RelationalValue],
    left_position: usize,
    right: &[RelationalValue],
    right_position: usize,
    ordering: &[QueryOrderSpec],
) -> Ordering {
    for spec in ordering {
        let Some(index) = spec.index else {
            continue;
        };
        let left_value = &left[index];
        let right_value = &right[index];
        let nulls_first = spec.nulls_first.unwrap_or(!spec.ascending);
        let comparison = match (
            matches!(left_value, RelationalValue::Null),
            matches!(right_value, RelationalValue::Null),
        ) {
            (true, true) => Ordering::Equal,
            (true, false) => {
                if nulls_first {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (false, true) => {
                if nulls_first {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (false, false) => {
                let comparison = compare_values(left_value, right_value).unwrap_or(Ordering::Equal);
                if spec.ascending {
                    comparison
                } else {
                    comparison.reverse()
                }
            }
        };
        if comparison != Ordering::Equal {
            return comparison;
        }
    }
    left_position.cmp(&right_position)
}

/// A keyset page on a single integer primary key can stop after LIMIT rows.
/// The scalar index supplies logical key order even when physical row IDs or
/// mutation overlays are out of order; other ORDER BY shapes use the bounded
/// general top-k operator.
fn execute_ordered_primary_range(
    state: &RelationalState,
    snapshot: u64,
    query: &Query,
    select: &sqlparser::ast::Select,
    parameters: &[RelationalValue],
) -> Result<Option<SqlResult>> {
    let Some(order_by) = query.order_by.as_ref() else {
        return Ok(None);
    };
    let (Some(limit), 0) = aggregate_limit_offset(&query.limit_clause)? else {
        return Ok(None);
    };
    if limit == 0 || limit > MAX_ROWS_PER_RESULT || order_by.interpolate.is_some() {
        return Ok(None);
    }
    let OrderByKind::Expressions(expressions) = &order_by.kind else {
        return Ok(None);
    };
    let [order] = expressions.as_slice() else {
        return Ok(None);
    };
    if order.options.asc == Some(false) || order.with_fill.is_some() {
        return Ok(None);
    }
    let (table, columns) = query_source(state, &select.from[0].relation)?;
    let [primary] = table.definition.primary_key.as_slice() else {
        return Ok(None);
    };
    let primary_index = column_index(&table.definition, primary)?;
    if !matches!(
        table.definition.columns[primary_index].data_type,
        RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt
    ) {
        return Ok(None);
    }
    let index = table
        .indexes
        .get(std::slice::from_ref(primary))
        .ok_or_else(|| invalid("missing primary-key scalar index"))?;
    let lower = match select.selection.as_ref() {
        None => None,
        Some(Expr::BinaryOp { left, op, right })
            if matches!(op, BinaryOperator::Gt | BinaryOperator::GtEq)
                && expression_column_name(left).ok().as_ref() == Some(primary)
                && matches!(right.as_ref(), Expr::Value(_)) =>
        {
            let mut parameter_cursor = 0;
            let value = expression_value(
                right,
                &table.definition.columns[primary_index].data_type,
                parameters,
                &mut parameter_cursor,
            )?;
            if matches!(value, RelationalValue::Null) {
                return Ok(None);
            }
            Some((
                index
                    .key(&[&value])?
                    .ok_or_else(|| invalid("primary-key range bound is null"))?,
                *op == BinaryOperator::Gt,
            ))
        }
        Some(_) => return Ok(None),
    };
    let projection = query_projection_with_subqueries(
        state,
        snapshot,
        &columns,
        &select.projection,
        parameters,
    )?;
    if query_order_key(&columns, &projection, &order.expr)?.source_index != Some(primary_index) {
        return Ok(None);
    }
    match &order.expr {
        Expr::Identifier(identifier) => {
            let name = normalize_ident(&identifier.value);
            if projection.iter().any(|item| {
                item.name == name
                    && !matches!(
                        &item.source,
                        QueryProjectionSource::Column(index) if *index == primary_index
                    )
            }) {
                return Ok(None);
            }
        }
        Expr::CompoundIdentifier(_) => {}
        _ => return Ok(None),
    }
    let mut rows = Vec::new();
    let mut serialized_bytes = 0;
    let mut ordered_rows = table.rows.ordered_reader();
    let entries = match &lower {
        Some((key, _)) => index.entries_from(&table.index_segments, snapshot, key)?,
        None => index.entries(&table.index_segments, snapshot, None)?,
    };
    for entry in entries {
        check_sql_cancelled()?;
        let (key, row_id) = entry?;
        if lower
            .as_ref()
            .is_some_and(|(bound, strict)| *strict && &key == bound)
        {
            continue;
        }
        let Some(version) = ordered_rows.visible(row_id, snapshot)? else {
            continue;
        };
        if index.key(&[&version.values[primary_index]])?.as_deref() != Some(key.as_slice()) {
            continue;
        }
        let mut cursor = 0;
        if !query_predicate_matches(
            state,
            snapshot,
            select.selection.as_ref(),
            &columns,
            &version.values,
            parameters,
            &mut cursor,
        )? {
            continue;
        }
        let projected = project_query_row(&version.values, &projection);
        charge_result_row(&mut serialized_bytes, &projected)?;
        rows.push(projected);
        if rows.len() == limit {
            break;
        }
    }
    Ok(Some(SqlResult::Rows {
        columns: projection.iter().map(|item| item.name.clone()).collect(),
        column_types: projection
            .iter()
            .map(|item| item.data_type.clone())
            .collect(),
        rows,
    }))
}

/// A LIMIT with ORDER BY retains at most OFFSET+LIMIT source rows. The heap
/// holds the worst retained row at its root, so the scan never loads the
/// remainder of a large table into an operator buffer.
fn execute_topk_query(
    state: &RelationalState,
    snapshot: u64,
    query: &Query,
    select: &sqlparser::ast::Select,
    parameters: &[RelationalValue],
    row_ids: Option<&IndexedSelectionProbe>,
) -> Result<Option<SqlResult>> {
    let Some(order_by) = query.order_by.as_ref() else {
        return Ok(None);
    };
    let (Some(limit), offset) = aggregate_limit_offset(&query.limit_clause)? else {
        return Ok(None);
    };
    let Some(window) = offset
        .checked_add(limit)
        .filter(|window| *window <= MAX_ROWS_PER_RESULT)
    else {
        return Ok(None);
    };
    let (table, columns) = query_source(state, &select.from[0].relation)?;
    let projection = query_projection_with_subqueries(
        state,
        snapshot,
        &columns,
        &select.projection,
        parameters,
    )?;
    if order_by.interpolate.is_some() {
        return Err(unsupported("ORDER BY INTERPOLATE is outside relational v1"));
    }
    let OrderByKind::Expressions(expressions) = &order_by.kind else {
        return Err(unsupported("ORDER BY ALL is outside relational v1"));
    };
    let ordering = expressions
        .iter()
        .map(|expression| {
            if expression.with_fill.is_some() {
                return Err(unsupported("ORDER BY WITH FILL is outside relational v1"));
            }
            Ok(QueryOrderSpec {
                index: query_order_key(&columns, &projection, &expression.expr)?.source_index,
                ascending: expression.options.asc.unwrap_or(true),
                nulls_first: expression.options.nulls_first,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if limit == 0 {
        for row in query_source_rows(table, snapshot, row_ids)? {
            check_sql_cancelled()?;
            let row = row?;
            let mut cursor = 0;
            query_predicate_matches(
                state,
                snapshot,
                select.selection.as_ref(),
                &columns,
                &row,
                parameters,
                &mut cursor,
            )?;
        }
        return Ok(Some(SqlResult::Rows {
            columns: projection.iter().map(|item| item.name.clone()).collect(),
            column_types: projection
                .iter()
                .map(|item| item.data_type.clone())
                .collect(),
            rows: Vec::new(),
        }));
    }
    let mut heap = BinaryHeap::<RankedQueryRow<'_>>::new();
    let mut spills = None;
    let mut charged = 0_usize;
    for (position, row) in query_source_rows(table, snapshot, row_ids)?.enumerate() {
        check_sql_cancelled()?;
        let row = row?;
        let mut cursor = 0;
        if !query_predicate_matches(
            state,
            snapshot,
            select.selection.as_ref(),
            &columns,
            &row,
            parameters,
            &mut cursor,
        )? {
            continue;
        }
        if heap.len() == window
            && compare_query_order(
                &row,
                position,
                &heap.peek().expect("full heap has a root").values,
                heap.peek().expect("full heap has a root").source_position,
                &ordering,
            ) != Ordering::Less
        {
            continue;
        }
        let charge = query_operator_row_charge(&row)?;
        let replacing = heap
            .peek()
            .filter(|_| heap.len() == window)
            .map_or(0, |row| row.charge);
        let budget = query_operator_budget();
        if charged.saturating_sub(replacing).saturating_add(charge) > budget {
            if !crate::encryption::encryption_enabled() || charge > budget {
                return Err(GaussError::ResourceExhausted(format!(
                    "SQL operator memory budget exceeds {budget} bytes"
                )));
            }
            let spill = match &mut spills {
                Some(spill) => spill,
                None => spills.insert(query_spill::QuerySpill::new(&state.directory, budget)?),
            };
            spill.push_run(heap.into_sorted_vec())?;
            heap = BinaryHeap::new();
            charged = 0;
        }
        if heap.len() == window {
            heap.pop();
            charged = charged.saturating_sub(replacing);
        }
        charged = charged.saturating_add(charge);
        heap.push(RankedQueryRow {
            source_position: position,
            values: row,
            charge,
            ordering: &ordering,
        });
    }
    let output_columns = projection.iter().map(|item| item.name.clone()).collect();
    let column_types = projection
        .iter()
        .map(|item| item.data_type.clone())
        .collect();
    let mut rows = Vec::new();
    let mut serialized_bytes = 0;
    if let Some(spill) = spills {
        let sorted = heap.into_sorted_vec();
        spill.for_each_window(sorted, &ordering, offset, limit, |row| {
            let projected = project_query_row(row, &projection);
            charge_result_row(&mut serialized_bytes, &projected)?;
            rows.push(projected);
            Ok(())
        })?;
    } else {
        for row in heap.into_sorted_vec().into_iter().skip(offset).take(limit) {
            let projected = project_query_row(&row.values, &projection);
            charge_result_row(&mut serialized_bytes, &projected)?;
            rows.push(projected);
        }
    }
    Ok(Some(SqlResult::Rows {
        columns: output_columns,
        column_types,
        rows,
    }))
}

fn project_query_row(
    values: &[RelationalValue],
    projection: &[QueryProjection],
) -> Vec<RelationalValue> {
    projection
        .iter()
        .map(|item| match &item.source {
            QueryProjectionSource::Column(index) => values[*index].clone(),
            QueryProjectionSource::RecordRef {
                namespace,
                id_column,
            } => {
                if matches!(values[*id_column], RelationalValue::Null) {
                    RelationalValue::Null
                } else {
                    RelationalValue::RecordRef(chirondb_types::RecordRef {
                        namespace: namespace.clone(),
                        id: relational_id(&values[*id_column]),
                    })
                }
            }
            QueryProjectionSource::Scalar(value) => value.clone(),
        })
        .collect()
}

fn charge_result_row(charged: &mut usize, row: &[RelationalValue]) -> Result<()> {
    let mut counter = BoundedCounter {
        written: 0,
        limit: MAX_RESULT_BYTES.saturating_sub(*charged),
    };
    serde_json::to_writer(&mut counter, row).map_err(|error| {
        GaussError::ResourceExhausted(format!(
            "SQL result exceeds {MAX_RESULT_BYTES} bytes: {error}"
        ))
    })?;
    *charged = charged.saturating_add(counter.written).saturating_add(1);
    if *charged > MAX_RESULT_BYTES {
        return Err(GaussError::ResourceExhausted(format!(
            "SQL result exceeds {MAX_RESULT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn execute_streaming_count(
    state: &RelationalState,
    snapshot: u64,
    query: &Query,
    select: &sqlparser::ast::Select,
    parameters: &[RelationalValue],
    row_ids: Option<&IndexedSelectionProbe>,
) -> Result<Option<SqlResult>> {
    let GroupByExpr::Expressions(groups, modifiers) = &select.group_by else {
        return Ok(None);
    };
    if !groups.is_empty() || !modifiers.is_empty() || select.having.is_some() {
        return Ok(None);
    }
    let [item] = select.projection.as_slice() else {
        return Ok(None);
    };
    let expression = match item {
        SelectItem::UnnamedExpr(expression) => expression,
        SelectItem::ExprWithAlias { expr, .. } => expr,
        _ => return Ok(None),
    };
    if !matches!(expression, Expr::Function(function) if function.name.to_string().eq_ignore_ascii_case("count"))
    {
        return Ok(None);
    }
    let (table, columns) = query_source(state, &select.from[0].relation)?;
    let projection = aggregate_projection(&columns, &select.projection, &[])?;
    let [count] = projection.as_slice() else {
        return Ok(None);
    };
    let count_index = match count.source {
        AggregateSource::CountStar => None,
        AggregateSource::Count(index) if !count.distinct => Some(index),
        _ => return Ok(None),
    };
    let (limit, offset) = aggregate_limit_offset(&query.limit_clause)?;
    let mut matched = 0_i64;
    for row in query_source_rows(table, snapshot, row_ids)? {
        check_sql_cancelled()?;
        let row = row?;
        let mut cursor = 0;
        if query_predicate_matches(
            state,
            snapshot,
            select.selection.as_ref(),
            &columns,
            &row,
            parameters,
            &mut cursor,
        )? && count_index.is_none_or(|index| !matches!(row[index], RelationalValue::Null))
        {
            matched = matched.checked_add(1).ok_or_else(sql_overloaded)?;
        }
    }
    let rows = if limit == Some(0) || offset > 0 {
        Vec::new()
    } else {
        vec![vec![RelationalValue::Integer(matched)]]
    };
    Ok(Some(SqlResult::Rows {
        columns: vec![count.name.clone()],
        column_types: vec![count.data_type.clone()],
        rows,
    }))
}

/// Ordinary scans retain only the result window. In particular, a selective
/// LIMIT must not hydrate the whole table merely to return its first rows.
fn execute_streaming_query(
    state: &RelationalState,
    snapshot: u64,
    query: &Query,
    select: &sqlparser::ast::Select,
    parameters: &[RelationalValue],
    row_ids: Option<&IndexedSelectionProbe>,
) -> Result<SqlResult> {
    let (table, columns) = query_source(state, &select.from[0].relation)?;
    let projection = query_projection_with_subqueries(
        state,
        snapshot,
        &columns,
        &select.projection,
        parameters,
    )?;
    let (limit, offset) = aggregate_limit_offset(&query.limit_clause)?;
    let output_columns = projection.iter().map(|item| item.name.clone()).collect();
    let column_types = projection
        .iter()
        .map(|item| item.data_type.clone())
        .collect();
    let mut rows = Vec::new();
    let mut matched = 0_usize;
    let mut serialized_bytes = 0_usize;
    for row in query_source_rows(table, snapshot, row_ids)? {
        check_sql_cancelled()?;
        let row = row?;
        let mut cursor = 0;
        if !query_predicate_matches(
            state,
            snapshot,
            select.selection.as_ref(),
            &columns,
            &row,
            parameters,
            &mut cursor,
        )? {
            continue;
        }
        if limit == Some(0) {
            continue;
        }
        if matched < offset {
            matched = matched.saturating_add(1);
            continue;
        }
        if rows.len() == MAX_ROWS_PER_RESULT {
            return Err(GaussError::ResourceExhausted(format!(
                "query produced more than {MAX_ROWS_PER_RESULT} rows; add a smaller LIMIT"
            )));
        }
        let projected = project_query_row(&row, &projection);
        charge_result_row(&mut serialized_bytes, &projected)?;
        rows.push(projected);
        if limit.is_some_and(|limit| rows.len() >= limit) {
            break;
        }
    }
    Ok(SqlResult::Rows {
        columns: output_columns,
        column_types,
        rows,
    })
}

fn validate_distinct_order_by(
    projection: &[QueryProjection],
    order_by: Option<&sqlparser::ast::OrderBy>,
    source_columns: &[QueryColumn],
) -> Result<()> {
    let Some(order_by) = order_by else {
        return Ok(());
    };
    let OrderByKind::Expressions(expressions) = &order_by.kind else {
        return Err(unsupported("ORDER BY ALL is outside relational v1"));
    };
    for expression in expressions {
        let key = query_order_key(source_columns, projection, &expression.expr)?;
        if !key.projected
            && !projection.iter().any(|item| {
                matches!(item.source, QueryProjectionSource::Column(index) if Some(index) == key.source_index)
            })
        {
            return Err(invalid(
                "for SELECT DISTINCT, ORDER BY expressions must appear in select list",
            ));
        }
    }
    Ok(())
}

fn order_by_ordinal(expression: &Expr, output_len: usize) -> Result<Option<usize>> {
    let Expr::Value(value) = expression else {
        return Ok(None);
    };
    let Value::Number(_, _) = &value.value else {
        return Ok(None);
    };
    let ordinal = integer_literal(expression)?;
    if ordinal == 0 || ordinal > output_len as u64 {
        return Err(invalid(format!(
            "ORDER BY position {ordinal} is not in select list"
        )));
    }
    Ok(Some(ordinal as usize - 1))
}

fn query_order_key(
    columns: &[QueryColumn],
    projection: &[QueryProjection],
    expression: &Expr,
) -> Result<QueryOrderKey> {
    if let Some(index) = order_by_ordinal(expression, projection.len())? {
        return Ok(QueryOrderKey {
            source_index: projection_source_index(&projection[index]),
            projected: true,
        });
    }
    if let Expr::Identifier(identifier) = expression {
        let name = normalize_ident(&identifier.value);
        let matches = projection
            .iter()
            .filter(|item| item.name == name)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [item] => {
                return Ok(QueryOrderKey {
                    source_index: projection_source_index(item),
                    projected: true,
                });
            }
            [] => {}
            _ => return Err(invalid(format!("ambiguous ORDER BY output {expression}"))),
        }
    }
    Ok(QueryOrderKey {
        source_index: Some(query_column_index(columns, expression)?),
        projected: false,
    })
}

fn projection_source_index(projection: &QueryProjection) -> Option<usize> {
    match &projection.source {
        QueryProjectionSource::Column(index) => Some(*index),
        QueryProjectionSource::RecordRef { id_column, .. } => Some(*id_column),
        QueryProjectionSource::Scalar(_) => None,
    }
}

fn deduplicate_rows(rows: &mut Vec<Vec<RelationalValue>>) {
    let mut seen = HashSet::with_capacity(rows.len());
    rows.retain(|row| seen.insert(distinct_row_key(row)));
}

fn distinct_row_key(row: &[RelationalValue]) -> String {
    let mut key = String::new();
    for value in row {
        let part = value_key(value);
        key.push_str(&part.len().to_string());
        key.push(':');
        key.push_str(&part);
    }
    key
}

fn materialize_ctes(
    state: &RelationalState,
    snapshot: u64,
    with: &sqlparser::ast::With,
    parameters: &[RelationalValue],
) -> Result<RelationalState> {
    if with.recursive {
        return Err(unsupported("recursive CTE is outside relational v1"));
    }
    let mut scoped = state.clone();
    for cte in &with.cte_tables {
        if cte.from.is_some() {
            return Err(unsupported("CTE FROM is outside relational v1"));
        }
        if cte.alias.at.is_some() {
            return Err(unsupported("CTE AT alias is outside relational v1"));
        }
        if cte
            .alias
            .columns
            .iter()
            .any(|column| column.data_type.is_some())
        {
            return Err(unsupported(
                "typed CTE column aliases are outside relational v1",
            ));
        }
        let SqlResult::Rows {
            columns,
            column_types,
            rows,
        } = execute_query(&scoped, snapshot, &cte.query, parameters)?
        else {
            return Err(unsupported("CTE body must be a read-only SELECT"));
        };
        let column_names = if cte.alias.columns.is_empty() {
            columns
                .iter()
                .map(|column| normalize_ident(column))
                .collect::<Vec<_>>()
        } else {
            if cte.alias.columns.len() != columns.len() {
                return Err(invalid(format!(
                    "CTE {} declares {} columns but query returns {}",
                    cte.alias.name,
                    cte.alias.columns.len(),
                    columns.len()
                )));
            }
            cte.alias
                .columns
                .iter()
                .map(|column| normalize_ident(&column.name.value))
                .collect::<Vec<_>>()
        };
        let mut unique = HashSet::with_capacity(column_names.len());
        if column_names.iter().any(|column| !unique.insert(column)) {
            return Err(invalid(format!(
                "CTE {} has duplicate output column names",
                cte.alias.name
            )));
        }
        let table_name = normalize_ident(&cte.alias.name.value);
        let table_id = allocate_catalog_id(&mut scoped)?;
        let definition = TableDefinition {
            table_id,
            security_incarnation: None,
            creator_principal_id: None,
            tenant_id: None,
            managed_by_ml: false,
            name: table_name.clone(),
            columns: column_names
                .into_iter()
                .zip(column_types)
                .map(|(name, data_type)| RelationalColumn {
                    name,
                    data_type,
                    nullable: true,
                    default: None,
                    identity: None,
                })
                .collect(),
            primary_key: Vec::new(),
            primary_key_name: None,
            primary_key_index_id: None,
            unique_constraints: Vec::new(),
            check_constraints: Vec::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            reference_index_ids: BTreeMap::new(),
        };
        let mut table = TableState::empty(definition, Arc::clone(&scoped.directory))?;
        for values in rows {
            if values.len() != table.definition.columns.len() {
                return Err(invalid(format!(
                    "CTE {table_name} row width does not match its output columns"
                )));
            }
            let row_id = table.next_row_id;
            table.next_row_id = table
                .next_row_id
                .checked_add(1)
                .ok_or_else(|| GaussError::ResourceExhausted("CTE row ID overflow".into()))?;
            table.rows.insert(
                row_id,
                VersionChain::single(RowVersion {
                    begin: snapshot,
                    end: None,
                    values: RowValues::adopt(values)?,
                })?,
            )?;
        }
        scoped.tables.insert(&table_name, Arc::new(table))?;
    }
    Ok(scoped)
}

fn query_uses_aggregation(select: &sqlparser::ast::Select) -> Result<bool> {
    let grouped = match &select.group_by {
        GroupByExpr::Expressions(expressions, modifiers) => {
            if !modifiers.is_empty() {
                return Err(unsupported(
                    "GROUP BY modifiers are outside the current profile",
                ));
            }
            !expressions.is_empty()
        }
        GroupByExpr::All(_) => {
            return Err(unsupported("GROUP BY ALL is outside the current profile"));
        }
    };
    Ok(grouped
        || select.having.is_some()
        || select.projection.iter().any(|item| {
            let expression = match item {
                SelectItem::UnnamedExpr(expression) => Some(expression),
                SelectItem::ExprWithAlias { expr, .. } => Some(expr),
                _ => None,
            };
            expression.is_some_and(is_aggregate_expression)
        }))
}

fn is_aggregate_expression(expression: &Expr) -> bool {
    matches!(expression, Expr::Function(function) if matches!(
        function.name.to_string().to_ascii_lowercase().as_str(),
        "count" | "sum" | "avg" | "min" | "max"
    ))
}

fn execute_aggregate_query(
    columns: &[QueryColumn],
    selected: &[(usize, RowValues)],
    select: &sqlparser::ast::Select,
    query: &Query,
    parameters: &[RelationalValue],
) -> Result<SqlResult> {
    let distinct = match select.distinct.as_ref() {
        None | Some(Distinct::All) => false,
        Some(Distinct::Distinct) => true,
        Some(Distinct::On(_)) => {
            return Err(unsupported("DISTINCT ON is outside relational v1"));
        }
    };
    let group_expressions = match &select.group_by {
        GroupByExpr::Expressions(expressions, modifiers) if modifiers.is_empty() => expressions,
        GroupByExpr::Expressions(_, _) => {
            return Err(unsupported(
                "GROUP BY modifiers are outside the current profile",
            ));
        }
        GroupByExpr::All(_) => {
            return Err(unsupported("GROUP BY ALL is outside the current profile"));
        }
    };
    let group_columns = group_expressions
        .iter()
        .map(|expression| query_column_index(columns, expression))
        .collect::<Result<Vec<_>>>()?;
    let projection = aggregate_projection(columns, &select.projection, &group_columns)?;

    let mut groups = BTreeMap::<String, Vec<&Vec<RelationalValue>>>::new();
    if group_columns.is_empty() {
        groups.insert(
            String::new(),
            selected.iter().map(|(_, row)| &**row).collect(),
        );
    } else {
        for (_, row) in selected {
            check_sql_cancelled()?;
            let mut key = String::new();
            for index in &group_columns {
                let part = value_key(&row[*index]);
                key.push_str(&part.len().to_string());
                key.push(':');
                key.push_str(&part);
            }
            groups.entry(key).or_default().push(row);
        }
    }

    let mut rows = Vec::with_capacity(groups.len());
    for group in groups.values() {
        check_sql_cancelled()?;
        let row = projection
            .iter()
            .map(|item| aggregate_value(item, group))
            .collect::<Result<Vec<_>>>()?;
        if aggregate_having_matches(select.having.as_ref(), &projection, &row, parameters)? {
            rows.push(row);
        }
    }
    if distinct {
        deduplicate_rows(&mut rows);
    }

    if let Some(order_by) = &query.order_by {
        if order_by.interpolate.is_some() {
            return Err(unsupported("ORDER BY INTERPOLATE is outside relational v1"));
        }
        let OrderByKind::Expressions(expressions) = &order_by.kind else {
            return Err(unsupported("ORDER BY ALL is outside relational v1"));
        };
        let ordering = expressions
            .iter()
            .map(|expression| {
                if expression.with_fill.is_some() {
                    return Err(unsupported("ORDER BY WITH FILL is outside relational v1"));
                }
                Ok((
                    aggregate_order_output_index(&projection, &expression.expr)?,
                    expression.options.asc.unwrap_or(true),
                    expression.options.nulls_first,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        rows.sort_by(|left, right| {
            for (index, ascending, explicit_nulls_first) in &ordering {
                let left_value = &left[*index];
                let right_value = &right[*index];
                let nulls_first = explicit_nulls_first.unwrap_or(!*ascending);
                let comparison = match (
                    matches!(left_value, RelationalValue::Null),
                    matches!(right_value, RelationalValue::Null),
                ) {
                    (true, true) => Ordering::Equal,
                    (true, false) => {
                        if nulls_first {
                            Ordering::Less
                        } else {
                            Ordering::Greater
                        }
                    }
                    (false, true) => {
                        if nulls_first {
                            Ordering::Greater
                        } else {
                            Ordering::Less
                        }
                    }
                    (false, false) => {
                        let comparison =
                            compare_values(left_value, right_value).unwrap_or(Ordering::Equal);
                        if *ascending {
                            comparison
                        } else {
                            comparison.reverse()
                        }
                    }
                };
                if comparison != Ordering::Equal {
                    return comparison;
                }
            }
            Ordering::Equal
        });
    }

    let (limit, offset) = aggregate_limit_offset(&query.limit_clause)?;
    if rows.len().saturating_sub(offset) > MAX_ROWS_PER_RESULT && limit.is_none() {
        return Err(GaussError::ResourceExhausted(format!(
            "query produced more than {MAX_ROWS_PER_RESULT} groups; add a smaller LIMIT"
        )));
    }
    let rows = rows
        .into_iter()
        .skip(offset)
        .take(limit.unwrap_or(MAX_ROWS_PER_RESULT))
        .collect();
    Ok(SqlResult::Rows {
        columns: projection.iter().map(|item| item.name.clone()).collect(),
        column_types: projection
            .iter()
            .map(|item| item.data_type.clone())
            .collect(),
        rows,
    })
}

fn aggregate_projection(
    columns: &[QueryColumn],
    items: &[SelectItem],
    group_columns: &[usize],
) -> Result<Vec<AggregateProjection>> {
    let mut projection = Vec::with_capacity(items.len());
    for item in items {
        let (expression, alias) = match item {
            SelectItem::UnnamedExpr(expression) => (expression, None),
            SelectItem::ExprWithAlias { expr, alias } => {
                (expr, Some(normalize_ident(&alias.value)))
            }
            _ => {
                return Err(unsupported(
                    "aggregate projection requires grouped columns or aggregate functions",
                ));
            }
        };
        if is_aggregate_expression(expression) {
            projection.push(parse_aggregate_projection(columns, expression, alias)?);
            continue;
        }
        let index = query_column_index(columns, expression)?;
        if !group_columns.contains(&index) {
            return Err(invalid(format!(
                "column {expression} must appear in GROUP BY or be used in an aggregate function"
            )));
        }
        projection.push(AggregateProjection {
            source: AggregateSource::GroupColumn(index),
            distinct: false,
            name: alias.unwrap_or_else(|| columns[index].name.clone()),
            expression_key: canonical_expression(expression),
            data_type: columns[index].data_type.clone(),
        });
    }
    Ok(projection)
}

fn parse_aggregate_projection(
    columns: &[QueryColumn],
    expression: &Expr,
    alias: Option<String>,
) -> Result<AggregateProjection> {
    let Expr::Function(function) = expression else {
        unreachable!("caller checked aggregate function");
    };
    if function.uses_odbc_syntax
        || !matches!(function.parameters, FunctionArguments::None)
        || function.filter.is_some()
        || function.null_treatment.is_some()
        || function.over.is_some()
        || !function.within_group.is_empty()
    {
        return Err(unsupported(
            "aggregate parameters, FILTER, null treatment, window and WITHIN GROUP are outside the current profile",
        ));
    }
    let name = function.name.to_string().to_ascii_lowercase();
    let FunctionArguments::List(arguments) = &function.args else {
        return Err(invalid(format!("{name} requires an argument")));
    };
    if !arguments.clauses.is_empty() {
        return Err(unsupported(
            "ordered aggregate arguments are outside the current profile",
        ));
    }
    let distinct = match arguments.duplicate_treatment {
        None | Some(DuplicateTreatment::All) => false,
        Some(DuplicateTreatment::Distinct) => true,
    };
    let (source, data_type) = if name == "count"
        && matches!(
            arguments.args.as_slice(),
            [FunctionArg::Unnamed(FunctionArgExpr::Wildcard)]
        ) {
        if distinct {
            return Err(invalid("COUNT(DISTINCT *) is not supported; name a column"));
        }
        (AggregateSource::CountStar, RelationalType::BigInt)
    } else {
        let [FunctionArg::Unnamed(FunctionArgExpr::Expr(argument))] = arguments.args.as_slice()
        else {
            return Err(invalid(format!(
                "{name} requires exactly one column argument"
            )));
        };
        let index = query_column_index(columns, argument)?;
        let input_type = &columns[index].data_type;
        let source = match name.as_str() {
            "count" => AggregateSource::Count(index),
            "sum" => {
                if !matches!(
                    input_type,
                    RelationalType::SmallInt
                        | RelationalType::Integer
                        | RelationalType::BigInt
                        | RelationalType::Real
                        | RelationalType::Float
                ) {
                    return Err(invalid("SUM requires an integer or floating-point column"));
                }
                AggregateSource::Sum(index)
            }
            "avg" => {
                if !matches!(
                    input_type,
                    RelationalType::SmallInt
                        | RelationalType::Integer
                        | RelationalType::BigInt
                        | RelationalType::Real
                        | RelationalType::Float
                ) {
                    return Err(invalid("AVG requires an integer or floating-point column"));
                }
                AggregateSource::Avg(index)
            }
            "min" => AggregateSource::Min(index),
            "max" => AggregateSource::Max(index),
            _ => {
                return Err(unsupported(format!(
                    "aggregate function {name} is not supported"
                )));
            }
        };
        let output_type = match source {
            AggregateSource::Count(_) => RelationalType::BigInt,
            AggregateSource::Sum(_) => match input_type {
                RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt => {
                    RelationalType::BigInt
                }
                _ => RelationalType::Float,
            },
            AggregateSource::Avg(_) => RelationalType::Float,
            AggregateSource::Min(_) | AggregateSource::Max(_) => input_type.clone(),
            _ => unreachable!("handled separately"),
        };
        (source, output_type)
    };
    Ok(AggregateProjection {
        source,
        distinct,
        name: alias.unwrap_or_else(|| name.clone()),
        expression_key: canonical_expression(expression),
        data_type,
    })
}

fn aggregate_value(
    projection: &AggregateProjection,
    rows: &[&Vec<RelationalValue>],
) -> Result<RelationalValue> {
    let distinct_rows;
    let rows = if projection.distinct {
        let index = match projection.source {
            AggregateSource::Count(index)
            | AggregateSource::Sum(index)
            | AggregateSource::Avg(index)
            | AggregateSource::Min(index)
            | AggregateSource::Max(index) => index,
            AggregateSource::GroupColumn(_) | AggregateSource::CountStar => {
                return Err(invalid("DISTINCT requires a column aggregate argument"));
            }
        };
        let mut seen = HashSet::new();
        distinct_rows = rows
            .iter()
            .copied()
            .filter(|row| seen.insert(value_key(&row[index])))
            .take(MAX_ROWS_PER_RESULT + 1)
            .collect::<Vec<_>>();
        if distinct_rows.len() > MAX_ROWS_PER_RESULT {
            return Err(GaussError::ResourceExhausted(format!(
                "aggregate DISTINCT exceeded {MAX_ROWS_PER_RESULT} values"
            )));
        }
        distinct_rows.as_slice()
    } else {
        rows
    };
    match projection.source {
        AggregateSource::GroupColumn(index) => rows
            .first()
            .map(|row| row[index].clone())
            .ok_or_else(|| invalid("empty group cannot project a grouped column")),
        AggregateSource::CountStar => Ok(RelationalValue::Integer(rows.len() as i64)),
        AggregateSource::Count(index) => Ok(RelationalValue::Integer(
            rows.iter()
                .filter(|row| !matches!(row[index], RelationalValue::Null))
                .count() as i64,
        )),
        AggregateSource::Sum(index) => aggregate_sum(rows, index),
        AggregateSource::Avg(index) => aggregate_avg(rows, index),
        AggregateSource::Min(index) => aggregate_extreme(rows, index, true),
        AggregateSource::Max(index) => aggregate_extreme(rows, index, false),
    }
}

fn aggregate_sum(rows: &[&Vec<RelationalValue>], index: usize) -> Result<RelationalValue> {
    let mut integer = 0_i64;
    let mut floating = 0_f64;
    let mut kind = None;
    for value in rows.iter().map(|row| &row[index]) {
        match value {
            RelationalValue::Null => {}
            RelationalValue::Integer(value) => {
                if kind == Some(false) {
                    return Err(invalid("SUM input types changed within a column"));
                }
                kind = Some(true);
                integer = integer
                    .checked_add(*value)
                    .ok_or_else(|| invalid("SUM integer overflow"))?;
            }
            RelationalValue::Float(value) => {
                if kind == Some(true) {
                    return Err(invalid("SUM input types changed within a column"));
                }
                kind = Some(false);
                floating += value;
                if !floating.is_finite() {
                    return Err(invalid("SUM floating-point overflow"));
                }
            }
            _ => return Err(invalid("SUM requires numeric values")),
        }
    }
    Ok(match kind {
        Some(true) => RelationalValue::Integer(integer),
        Some(false) => RelationalValue::Float(floating),
        None => RelationalValue::Null,
    })
}

fn aggregate_avg(rows: &[&Vec<RelationalValue>], index: usize) -> Result<RelationalValue> {
    let mut sum = 0_f64;
    let mut count = 0_u64;
    for value in rows.iter().map(|row| &row[index]) {
        match value {
            RelationalValue::Null => {}
            RelationalValue::Integer(value) => {
                sum += *value as f64;
                count += 1;
            }
            RelationalValue::Float(value) => {
                sum += value;
                count += 1;
            }
            _ => return Err(invalid("AVG requires numeric values")),
        }
        if !sum.is_finite() {
            return Err(invalid("AVG floating-point overflow"));
        }
    }
    if count == 0 {
        Ok(RelationalValue::Null)
    } else {
        Ok(RelationalValue::Float(sum / count as f64))
    }
}

fn aggregate_extreme(
    rows: &[&Vec<RelationalValue>],
    index: usize,
    minimum: bool,
) -> Result<RelationalValue> {
    let mut selected = None::<RelationalValue>;
    for value in rows.iter().map(|row| &row[index]) {
        if matches!(value, RelationalValue::Null) {
            continue;
        }
        if let Some(current) = &selected {
            let ordering = compare_values(value, current)
                .ok_or_else(|| invalid("MIN/MAX values are not comparable"))?;
            if (minimum && ordering == Ordering::Less)
                || (!minimum && ordering == Ordering::Greater)
            {
                selected = Some(value.clone());
            }
        } else {
            selected = Some(value.clone());
        }
    }
    Ok(selected.unwrap_or(RelationalValue::Null))
}

fn aggregate_having_matches(
    expression: Option<&Expr>,
    projection: &[AggregateProjection],
    row: &[RelationalValue],
    parameters: &[RelationalValue],
) -> Result<bool> {
    let Some(expression) = expression else {
        return Ok(true);
    };
    match expression {
        Expr::Nested(expression) => {
            aggregate_having_matches(Some(expression), projection, row, parameters)
        }
        Expr::UnaryOp { op, expr } if op.to_string().eq_ignore_ascii_case("not") => Ok(
            !aggregate_having_matches(Some(expr), projection, row, parameters)?,
        ),
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::And => Ok(
            aggregate_having_matches(Some(left), projection, row, parameters)?
                && aggregate_having_matches(Some(right), projection, row, parameters)?,
        ),
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::Or => Ok(
            aggregate_having_matches(Some(left), projection, row, parameters)?
                || aggregate_having_matches(Some(right), projection, row, parameters)?,
        ),
        Expr::BinaryOp { left, op, right } => {
            let left_index = aggregate_output_index(projection, left).ok();
            let right_index = aggregate_output_index(projection, right).ok();
            let (left_value, right_value) = match (left_index, right_index) {
                (Some(left), Some(right)) => (row[left].clone(), row[right].clone()),
                (Some(left), None) => {
                    let mut cursor = 0;
                    (
                        row[left].clone(),
                        expression_value(
                            right,
                            &projection[left].data_type,
                            parameters,
                            &mut cursor,
                        )?,
                    )
                }
                (None, Some(right)) => {
                    let mut cursor = 0;
                    (
                        expression_value(
                            left,
                            &projection[right].data_type,
                            parameters,
                            &mut cursor,
                        )?,
                        row[right].clone(),
                    )
                }
                (None, None) => {
                    return Err(unsupported(
                        "HAVING must reference a projected group or aggregate expression",
                    ));
                }
            };
            compare_predicate(&left_value, &right_value, op)
        }
        Expr::IsNull(expression) => Ok(matches!(
            row[aggregate_output_index(projection, expression)?],
            RelationalValue::Null
        )),
        Expr::IsNotNull(expression) => Ok(!matches!(
            row[aggregate_output_index(projection, expression)?],
            RelationalValue::Null
        )),
        _ => Err(unsupported(
            "HAVING expression is outside the current aggregate profile",
        )),
    }
}

fn aggregate_output_index(projection: &[AggregateProjection], expression: &Expr) -> Result<usize> {
    let key = canonical_expression(expression);
    let matches = projection
        .iter()
        .enumerate()
        .filter(|(_, item)| item.name == key || item.expression_key == key)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => Err(invalid(format!("unknown aggregate output {expression}"))),
        _ => Err(invalid(format!("ambiguous aggregate output {expression}"))),
    }
}

fn aggregate_order_output_index(
    projection: &[AggregateProjection],
    expression: &Expr,
) -> Result<usize> {
    if let Some(index) = order_by_ordinal(expression, projection.len())? {
        return Ok(index);
    }
    aggregate_output_index(projection, expression)
}

fn canonical_expression(expression: &Expr) -> String {
    expression.to_string().to_ascii_lowercase()
}

fn aggregate_limit_offset(limit_clause: &Option<LimitClause>) -> Result<(Option<usize>, usize)> {
    match limit_clause {
        None => Ok((None, 0)),
        Some(LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        }) if limit_by.is_empty() => {
            let limit = limit
                .as_ref()
                .map(|limit| {
                    usize::try_from(integer_literal(limit)?).map_err(|_| {
                        GaussError::ResourceExhausted("LIMIT exceeds platform size".into())
                    })
                })
                .transpose()?;
            if limit.is_some_and(|limit| limit > MAX_ROWS_PER_RESULT) {
                return Err(GaussError::ResourceExhausted(format!(
                    "LIMIT exceeds maximum result rows {MAX_ROWS_PER_RESULT}"
                )));
            }
            let offset = offset
                .as_ref()
                .map(|offset| {
                    usize::try_from(integer_literal(&offset.value)?).map_err(|_| {
                        GaussError::ResourceExhausted("OFFSET exceeds platform size".into())
                    })
                })
                .transpose()?
                .unwrap_or(0);
            Ok((limit, offset))
        }
        _ => Err(unsupported(
            "dialect-specific LIMIT is outside relational v1",
        )),
    }
}

fn query_relation(
    state: &RelationalState,
    snapshot: u64,
    factor: &TableFactor,
) -> Result<QueryRelation> {
    query_relation_with_row_ids(state, snapshot, factor, None)
}

fn query_relation_with_row_ids(
    state: &RelationalState,
    snapshot: u64,
    factor: &TableFactor,
    row_ids: Option<&IndexedSelectionProbe>,
) -> Result<QueryRelation> {
    let (table, columns) = query_source(state, factor)?;
    let mut rows = Vec::new();
    let mut charged = 0;
    for row in query_source_rows(table, snapshot, row_ids)? {
        check_sql_cancelled()?;
        let row = row?;
        charge_query_operator_row(&mut charged, &row)?;
        rows.push(row);
    }
    Ok(QueryRelation { columns, rows })
}

fn charge_query_operator_row(charged: &mut usize, row: &[RelationalValue]) -> Result<()> {
    charge_query_operator_bytes(charged, query_operator_row_charge(row)?)
}

fn charge_query_operator_bytes(charged: &mut usize, bytes: usize) -> Result<()> {
    let budget = query_operator_budget();
    *charged = charged.saturating_add(bytes);
    if *charged > budget {
        return Err(GaussError::ResourceExhausted(format!(
            "SQL operator memory budget exceeds {budget} bytes"
        )));
    }
    Ok(())
}

fn query_operator_budget() -> usize {
    (crate::resource_profile::current().sql_request_working_set_bytes / 8)
        .try_into()
        .unwrap_or(usize::MAX)
}

fn query_operator_row_charge(row: &[RelationalValue]) -> Result<usize> {
    let budget = query_operator_budget();
    let mut counter = BoundedCounter {
        written: 0,
        limit: budget,
    };
    serde_json::to_writer(&mut counter, row).map_err(|error| {
        GaussError::ResourceExhausted(format!(
            "SQL operator memory budget exceeds {budget} bytes: {error}"
        ))
    })?;
    let fixed = std::mem::size_of_val(row);
    let heap = row.iter().fold(0_u64, |bytes, value| {
        bytes.saturating_add(memory::value_heap_bytes(value))
    });
    Ok(counter
        .written
        .saturating_add(fixed)
        .saturating_add(usize::try_from(heap).unwrap_or(usize::MAX))
        .saturating_add(64))
}

fn query_source<'a>(
    state: &'a RelationalState,
    factor: &TableFactor,
) -> Result<(&'a TableState, Vec<QueryColumn>)> {
    let TableFactor::Table {
        name, alias, args, ..
    } = factor
    else {
        return Err(unsupported("table expression is outside relational v1"));
    };
    if args.is_some() {
        return Err(unsupported("table functions are outside relational v1"));
    }
    if alias
        .as_ref()
        .is_some_and(|alias| !alias.columns.is_empty() || alias.at.is_some())
    {
        return Err(unsupported(
            "column aliases on table sources are outside relational v1",
        ));
    }
    let table_name = normalize_name(name);
    let qualifier = alias
        .as_ref()
        .map(|alias| normalize_ident(&alias.name.value))
        .unwrap_or_else(|| table_name.clone());
    let table = state
        .tables
        .get(&table_name)
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
    Ok((
        table,
        table
            .definition
            .columns
            .iter()
            .map(|column| QueryColumn {
                qualifier: qualifier.clone(),
                name: column.name.clone(),
                data_type: column.data_type.clone(),
            })
            .collect(),
    ))
}

fn mutation_candidates(
    state: &RelationalState,
    factor: &TableFactor,
    selection: Option<&Expr>,
    parameters: &[RelationalValue],
    parameter_cursor: usize,
    snapshot: u64,
) -> Result<Vec<(u64, RowValues)>> {
    let table_name = table_factor_name(factor)?;
    let table = state
        .tables
        .get(&table_name)
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
    let probe = indexed_selection_probe(
        state,
        snapshot,
        factor,
        selection,
        parameters,
        parameter_cursor,
    )?;
    let mut candidates = Vec::new();
    let mut charged = 0;
    let Some(probe) = probe else {
        for row in table.rows.visible_rows(snapshot) {
            check_sql_cancelled()?;
            let (row_id, values) = row?;
            charge_query_operator_row(&mut charged, &values)?;
            candidates.push((row_id, values));
        }
        return Ok(candidates);
    };
    let Some(key) = probe.key else {
        return Ok(Vec::new());
    };
    let index = table
        .indexes
        .get(&probe.columns)
        .ok_or_else(|| invalid("missing scalar index"))?;
    for entry in index.entries(&table.index_segments, snapshot, Some(&key))? {
        check_sql_cancelled()?;
        let (_, row_id) = entry?;
        if let Some(version) = table.rows.visible(row_id, snapshot)? {
            charge_query_operator_row(&mut charged, &version.values)?;
            candidates.push((row_id, version.values));
        }
    }
    Ok(candidates)
}

fn indexed_selection_probe(
    state: &RelationalState,
    _snapshot: u64,
    factor: &TableFactor,
    selection: Option<&Expr>,
    parameters: &[RelationalValue],
    parameter_cursor: usize,
) -> Result<Option<IndexedSelectionProbe>> {
    let Some(Expr::BinaryOp { left, op, right }) = selection else {
        return Ok(None);
    };
    if *op != BinaryOperator::Eq {
        return Ok(None);
    }
    let table_name = table_factor_name(factor)?;
    let table = state
        .tables
        .get(&table_name)
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
    let (column_expression, value_expression) = if expression_column_name(left).is_ok() {
        (&**left, &**right)
    } else if expression_column_name(right).is_ok() {
        (&**right, &**left)
    } else {
        return Ok(None);
    };
    if expression_column_name(value_expression).is_ok() {
        return Ok(None);
    }
    let column = expression_column_name(column_expression)?;
    let columns = vec![column.clone()];
    if !table.indexes.contains_key(&columns) {
        return Ok(None);
    }
    let index = column_index(&table.definition, &column)?;
    let mut parameter_cursor = parameter_cursor;
    let value = expression_value(
        value_expression,
        &table.definition.columns[index].data_type,
        parameters,
        &mut parameter_cursor,
    )?;
    let key = table
        .indexes
        .get(&columns)
        .expect("indexed selection checked membership")
        .key(&[&value])?;
    Ok(Some(IndexedSelectionProbe { columns, key }))
}

fn apply_join(
    state: &RelationalState,
    snapshot: u64,
    left: QueryRelation,
    join: &sqlparser::ast::Join,
) -> Result<QueryRelation> {
    let right = query_relation(state, snapshot, &join.relation)?;
    let (constraint, preserve_left) = match &join.join_operator {
        JoinOperator::Join(constraint) | JoinOperator::Inner(constraint) => (constraint, false),
        JoinOperator::Left(constraint) | JoinOperator::LeftOuter(constraint) => (constraint, true),
        _ => return Err(unsupported("only INNER and LEFT JOIN are supported")),
    };
    let JoinConstraint::On(expression) = constraint else {
        return Err(unsupported("JOIN requires an ON equijoin condition"));
    };
    let mut columns = left.columns.clone();
    columns.extend(right.columns.clone());
    let Expr::BinaryOp {
        left: join_left,
        op: BinaryOperator::Eq,
        right: join_right,
    } = expression
    else {
        return Err(unsupported(
            "JOIN ON requires equality between a left and right column",
        ));
    };
    let left_index = query_column_index(&columns, join_left)?;
    let right_index = query_column_index(&columns, join_right)?;
    let left_width = left.columns.len();
    if (left_index < left_width) == (right_index < left_width) {
        return Err(unsupported(
            "JOIN ON must compare one column from each relation",
        ));
    }
    if columns[left_index].data_type != columns[right_index].data_type {
        return Err(invalid("JOIN columns must have the same type"));
    }
    let (left_key_index, right_key_index) = if left_index < left_width {
        (left_index, right_index - left_width)
    } else {
        (right_index, left_index - left_width)
    };
    let mut right_by_key = HashMap::<String, Vec<&Vec<RelationalValue>>>::new();
    for row in &right.rows {
        check_sql_cancelled()?;
        if !matches!(row[right_key_index], RelationalValue::Null) {
            right_by_key
                .entry(value_key(&row[right_key_index]))
                .or_default()
                .push(row);
        }
    }
    let right_nulls = vec![RelationalValue::Null; right.columns.len()];
    let mut rows = Vec::new();
    let mut charged = 0;
    for left_row in left.rows {
        check_sql_cancelled()?;
        let matches = if matches!(left_row[left_key_index], RelationalValue::Null) {
            None
        } else {
            right_by_key.get(&value_key(&left_row[left_key_index]))
        };
        let matched = matches.is_some_and(|matches| !matches.is_empty());
        for right_row in matches.into_iter().flatten() {
            let combined = RowValues::concat(&left_row, right_row)?;
            charge_query_operator_row(&mut charged, &combined)?;
            rows.push(combined);
            if rows.len() > MAX_ROWS_PER_RESULT {
                return Err(GaussError::ResourceExhausted(format!(
                    "join produced more than {MAX_ROWS_PER_RESULT} rows; add selective predicates"
                )));
            }
        }
        if preserve_left && !matched {
            let combined = RowValues::concat(&left_row, &right_nulls)?;
            charge_query_operator_row(&mut charged, &combined)?;
            rows.push(combined);
            if rows.len() > MAX_ROWS_PER_RESULT {
                return Err(GaussError::ResourceExhausted(format!(
                    "join produced more than {MAX_ROWS_PER_RESULT} rows; add selective predicates"
                )));
            }
        }
    }
    Ok(QueryRelation { columns, rows })
}

fn query_column_index(columns: &[QueryColumn], expression: &Expr) -> Result<usize> {
    let (qualifier, name) = match expression {
        Expr::Identifier(identifier) => (None, normalize_ident(&identifier.value)),
        Expr::CompoundIdentifier(identifiers) if identifiers.len() == 2 => (
            Some(normalize_ident(&identifiers[0].value)),
            normalize_ident(&identifiers[1].value),
        ),
        _ => return Err(unsupported("expected a column reference")),
    };
    let matches = columns
        .iter()
        .enumerate()
        .filter(|(_, column)| {
            column.name == name
                && qualifier
                    .as_ref()
                    .is_none_or(|qualifier| &column.qualifier == qualifier)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => Err(invalid(format!("unknown column {expression}"))),
        _ => Err(invalid(format!("ambiguous column {expression}"))),
    }
}

fn query_predicate_matches(
    state: &RelationalState,
    snapshot: u64,
    expression: Option<&Expr>,
    columns: &[QueryColumn],
    row: &[RelationalValue],
    parameters: &[RelationalValue],
    cursor: &mut usize,
) -> Result<bool> {
    Ok(query_predicate_result(
        state, expression, snapshot, columns, row, parameters, cursor,
    )?
    .unwrap_or(false))
}

fn sql_and(left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match (left, right) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}

fn sql_or(left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match (left, right) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

fn query_predicate_result(
    state: &RelationalState,
    expression: Option<&Expr>,
    snapshot: u64,
    columns: &[QueryColumn],
    row: &[RelationalValue],
    parameters: &[RelationalValue],
    cursor: &mut usize,
) -> Result<Option<bool>> {
    let Some(expression) = expression else {
        return Ok(Some(true));
    };
    match expression {
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::And => Ok(sql_and(
            query_predicate_result(
                state,
                Some(left),
                snapshot,
                columns,
                row,
                parameters,
                cursor,
            )?,
            query_predicate_result(
                state,
                Some(right),
                snapshot,
                columns,
                row,
                parameters,
                cursor,
            )?,
        )),
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::Or => Ok(sql_or(
            query_predicate_result(
                state,
                Some(left),
                snapshot,
                columns,
                row,
                parameters,
                cursor,
            )?,
            query_predicate_result(
                state,
                Some(right),
                snapshot,
                columns,
                row,
                parameters,
                cursor,
            )?,
        )),
        Expr::UnaryOp { op, expr } if op.to_string().eq_ignore_ascii_case("not") => {
            Ok(query_predicate_result(
                state,
                Some(expr),
                snapshot,
                columns,
                row,
                parameters,
                cursor,
            )?
            .map(|value| !value))
        }
        Expr::Exists { subquery, negated } => {
            let SqlResult::Rows { rows, .. } =
                execute_query(state, snapshot, subquery, parameters)?
            else {
                return Err(unsupported("EXISTS requires a read-only subquery"));
            };
            Ok(Some(if *negated {
                rows.is_empty()
            } else {
                !rows.is_empty()
            }))
        }
        Expr::InSubquery {
            expr,
            subquery,
            negated,
        } => {
            let index = query_column_index(columns, expr)?;
            let SqlResult::Rows {
                column_types, rows, ..
            } = execute_query(state, snapshot, subquery, parameters)?
            else {
                return Err(unsupported("IN requires a read-only subquery"));
            };
            if column_types.len() != 1 || rows.iter().any(|candidate| candidate.len() != 1) {
                return Err(invalid("IN subquery must return exactly one column"));
            }
            if column_types[0] != columns[index].data_type {
                return Err(invalid(
                    "IN subquery column type does not match left operand",
                ));
            }
            let values = rows
                .into_iter()
                .map(|mut candidate| candidate.remove(0))
                .collect::<Vec<_>>();
            Ok(in_list_predicate(&row[index], &values, *negated))
        }
        Expr::InList {
            expr,
            list,
            negated,
        } => {
            let index = query_column_index(columns, expr)?;
            let values = list
                .iter()
                .map(|value| expression_value(value, &columns[index].data_type, parameters, cursor))
                .collect::<Result<Vec<_>>>()?;
            Ok(in_list_predicate(&row[index], &values, *negated))
        }
        Expr::Between {
            expr,
            negated,
            low,
            high,
        } => {
            let index = query_column_index(columns, expr)?;
            let low = expression_value(low, &columns[index].data_type, parameters, cursor)?;
            let high = expression_value(high, &columns[index].data_type, parameters, cursor)?;
            Ok(between_predicate(&row[index], &low, &high, *negated))
        }
        Expr::BinaryOp { left, op, right } => {
            let left_column = query_column_index(columns, left).ok();
            let right_column = query_column_index(columns, right).ok();
            let (left_value, right_value) = match (left_column, right_column) {
                (Some(left), Some(right)) => (&row[left], row[right].clone()),
                (Some(left), None) => (
                    &row[left],
                    expression_value(right, &columns[left].data_type, parameters, cursor)?,
                ),
                (None, Some(right)) => {
                    let value =
                        expression_value(left, &columns[right].data_type, parameters, cursor)?;
                    return if matches!(value, RelationalValue::Null)
                        || matches!(row[right], RelationalValue::Null)
                    {
                        Ok(None)
                    } else {
                        compare_predicate(&value, &row[right], op).map(Some)
                    };
                }
                (None, None) => {
                    return Err(unsupported("predicate must compare at least one column"));
                }
            };
            if matches!(left_value, RelationalValue::Null)
                || matches!(right_value, RelationalValue::Null)
            {
                Ok(None)
            } else {
                compare_predicate(left_value, &right_value, op).map(Some)
            }
        }
        Expr::IsNull(expression) => Ok(Some(matches!(
            row[query_column_index(columns, expression)?],
            RelationalValue::Null
        ))),
        Expr::IsNotNull(expression) => Ok(Some(!matches!(
            row[query_column_index(columns, expression)?],
            RelationalValue::Null
        ))),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            let index = query_column_index(columns, expression)?;
            match &row[index] {
                RelationalValue::Boolean(value) => Ok(Some(*value)),
                RelationalValue::Null => Ok(None),
                _ => Err(invalid("bare predicate column must be BOOLEAN")),
            }
        }
        Expr::Nested(expression) => query_predicate_result(
            state,
            Some(expression),
            snapshot,
            columns,
            row,
            parameters,
            cursor,
        ),
        _ => Err(unsupported("predicate expression is outside relational v1")),
    }
}

fn compare_predicate(
    left: &RelationalValue,
    right: &RelationalValue,
    operator: &BinaryOperator,
) -> Result<bool> {
    let ordering = compare_values(left, right);
    Ok(match operator {
        BinaryOperator::Eq => ordering == Some(Ordering::Equal),
        BinaryOperator::NotEq => matches!(ordering, Some(Ordering::Less | Ordering::Greater)),
        BinaryOperator::Lt => ordering == Some(Ordering::Less),
        BinaryOperator::LtEq => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
        BinaryOperator::Gt => ordering == Some(Ordering::Greater),
        BinaryOperator::GtEq => matches!(ordering, Some(Ordering::Greater | Ordering::Equal)),
        _ => return Err(unsupported("predicate operator is outside relational v1")),
    })
}

fn in_list_predicate(
    value: &RelationalValue,
    list: &[RelationalValue],
    negated: bool,
) -> Option<bool> {
    if matches!(value, RelationalValue::Null) {
        return None;
    }
    let mut saw_null = false;
    for candidate in list {
        if matches!(candidate, RelationalValue::Null) {
            saw_null = true;
        } else if compare_values(value, candidate) == Some(Ordering::Equal) {
            return Some(!negated);
        }
    }
    if saw_null { None } else { Some(negated) }
}

fn between_predicate(
    value: &RelationalValue,
    low: &RelationalValue,
    high: &RelationalValue,
    negated: bool,
) -> Option<bool> {
    let at_least_low = matches!(
        compare_values(value, low),
        Some(Ordering::Equal | Ordering::Greater)
    );
    let at_most_high = matches!(
        compare_values(value, high),
        Some(Ordering::Equal | Ordering::Less)
    );
    if matches!(value, RelationalValue::Null)
        || matches!(low, RelationalValue::Null)
        || matches!(high, RelationalValue::Null)
    {
        None
    } else {
        Some(if negated {
            !(at_least_low && at_most_high)
        } else {
            at_least_low && at_most_high
        })
    }
}

fn query_projection(
    columns: &[QueryColumn],
    projection: &[SelectItem],
) -> Result<Vec<QueryProjection>> {
    let mut output = Vec::new();
    for item in projection {
        match item {
            SelectItem::Wildcard(_) => output.extend(columns.iter().enumerate().map(
                |(index, column)| QueryProjection {
                    source: QueryProjectionSource::Column(index),
                    name: column.name.clone(),
                    data_type: column.data_type.clone(),
                },
            )),
            SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::ObjectName(name), _) => {
                let qualifier = normalize_name(name);
                let start = output.len();
                output.extend(
                    columns
                        .iter()
                        .enumerate()
                        .filter(|(_, column)| column.qualifier == qualifier)
                        .map(|(index, column)| QueryProjection {
                            source: QueryProjectionSource::Column(index),
                            name: column.name.clone(),
                            data_type: column.data_type.clone(),
                        }),
                );
                if output.len() == start {
                    return Err(invalid(format!("unknown table or alias {qualifier}")));
                }
            }
            SelectItem::UnnamedExpr(expression) => {
                output.push(projection_expression(columns, expression, None)?);
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                output.push(projection_expression(
                    columns,
                    expr,
                    Some(normalize_ident(&alias.value)),
                )?);
            }
            _ => {
                return Err(unsupported(
                    "projection expression is outside relational v1",
                ));
            }
        }
    }
    Ok(output)
}

fn query_projection_with_subqueries(
    state: &RelationalState,
    snapshot: u64,
    columns: &[QueryColumn],
    projection: &[SelectItem],
    parameters: &[RelationalValue],
) -> Result<Vec<QueryProjection>> {
    let mut output = Vec::new();
    for item in projection {
        let (expression, alias) = match item {
            SelectItem::UnnamedExpr(expression) => (expression, None),
            SelectItem::ExprWithAlias { expr, alias } => {
                (expr, Some(normalize_ident(&alias.value)))
            }
            _ => {
                output.extend(query_projection(columns, std::slice::from_ref(item))?);
                continue;
            }
        };
        let Expr::Subquery(subquery) = expression else {
            output.push(projection_expression(columns, expression, alias)?);
            continue;
        };
        let SqlResult::Rows {
            column_types,
            mut rows,
            ..
        } = execute_query(state, snapshot, subquery, parameters)?
        else {
            return Err(unsupported("scalar subquery must be read-only"));
        };
        if column_types.len() != 1 || rows.iter().any(|row| row.len() != 1) {
            return Err(invalid("scalar subquery must return exactly one column"));
        }
        if rows.len() > 1 {
            return Err(invalid("scalar subquery returned more than one row"));
        }
        let value = rows
            .pop()
            .map(|mut row| row.remove(0))
            .unwrap_or(RelationalValue::Null);
        output.push(QueryProjection {
            source: QueryProjectionSource::Scalar(value),
            name: alias.unwrap_or_else(|| "subquery".to_string()),
            data_type: column_types[0].clone(),
        });
    }
    Ok(output)
}

fn projection_expression(
    columns: &[QueryColumn],
    expression: &Expr,
    alias: Option<String>,
) -> Result<QueryProjection> {
    if let Some((namespace, id_column)) = record_ref_projection(columns, expression)? {
        return Ok(QueryProjection {
            source: QueryProjectionSource::RecordRef {
                namespace: namespace.clone(),
                id_column,
            },
            name: alias.unwrap_or_else(|| "record_ref".to_string()),
            data_type: RelationalType::RecordRef { namespace },
        });
    }
    let index = query_column_index(columns, expression)?;
    Ok(QueryProjection {
        source: QueryProjectionSource::Column(index),
        name: alias.unwrap_or_else(|| columns[index].name.clone()),
        data_type: columns[index].data_type.clone(),
    })
}

fn record_ref_projection(
    columns: &[QueryColumn],
    expression: &Expr,
) -> Result<Option<(String, usize)>> {
    let Expr::Function(function) = expression else {
        return Ok(None);
    };
    if !function.name.to_string().eq_ignore_ascii_case("record_ref") {
        return Ok(None);
    }
    let FunctionArguments::List(arguments) = &function.args else {
        return Err(invalid("RECORD_REF requires namespace and id arguments"));
    };
    if arguments.args.len() != 2 || !arguments.clauses.is_empty() {
        return Err(invalid("RECORD_REF requires namespace and id arguments"));
    }
    let expression_arg = |index: usize| match &arguments.args[index] {
        FunctionArg::Unnamed(FunctionArgExpr::Expr(expression)) => Ok(expression),
        _ => Err(invalid(
            "RECORD_REF arguments must be positional expressions",
        )),
    };
    let namespace = match expression_arg(0)? {
        Expr::Value(value) => match &value.value {
            Value::SingleQuotedString(value) if !value.is_empty() => value.to_ascii_lowercase(),
            _ => return Err(invalid("RECORD_REF namespace must be a non-empty string")),
        },
        _ => return Err(invalid("RECORD_REF namespace must be a string literal")),
    };
    let id_column = query_column_index(columns, expression_arg(1)?)?;
    match columns[id_column].data_type {
        RelationalType::Text | RelationalType::Uuid | RelationalType::Integer => {}
        _ => {
            return Err(invalid(
                "RECORD_REF id must come from text, UUID, or integer",
            ));
        }
    }
    Ok(Some((namespace, id_column)))
}

fn relational_id(value: &RelationalValue) -> String {
    match value {
        RelationalValue::Text(value) => value.clone(),
        RelationalValue::Uuid(value) => value.to_string(),
        RelationalValue::Integer(value) => value.to_string(),
        _ => String::new(),
    }
}

fn table_definition(create: sqlparser::ast::CreateTable) -> Result<TableDefinition> {
    if create.or_replace || create.temporary || create.external || create.query.is_some() {
        return Err(unsupported(
            "CREATE TABLE modifiers and AS SELECT are outside relational v1",
        ));
    }
    let table_name = normalize_name(&create.name);
    let mut columns = Vec::with_capacity(create.columns.len());
    let mut primary_key = Vec::new();
    let mut primary_key_name = None;
    let mut unique_constraints = Vec::new();
    let mut check_constraints = Vec::new();
    let mut foreign_keys = Vec::new();
    for column in create.columns {
        let name = normalize_ident(&column.name.value);
        let data_type = relational_type(&column.data_type)?;
        let mut nullable = true;
        let mut default = None;
        let mut identity = None;
        for option in column.options {
            match option.option {
                ColumnOption::Null => nullable = true,
                ColumnOption::NotNull => nullable = false,
                ColumnOption::Default(expression) => {
                    if default.is_some() {
                        return Err(invalid(format!(
                            "column {name} declares more than one default"
                        )));
                    }
                    default = Some(static_default_value(&expression, &data_type)?);
                }
                ColumnOption::PrimaryKey(key) => {
                    if key.index_name.is_some()
                        || key.index_type.is_some()
                        || !key.index_options.is_empty()
                        || key.characteristics.is_some()
                    {
                        return Err(unsupported(
                            "PRIMARY KEY supports immediate constraints without index options",
                        ));
                    }
                    if !primary_key.is_empty() {
                        return Err(invalid("table has more than one primary key"));
                    }
                    primary_key_name = option.name.map(|value| normalize_ident(&value.value));
                    nullable = false;
                    primary_key.push(name.clone());
                }
                ColumnOption::Unique(unique) => {
                    if unique.index_name.is_some()
                        || unique.index_type.is_some()
                        || !unique.index_options.is_empty()
                        || unique.characteristics.is_some()
                        || unique.nulls_distinct != sqlparser::ast::NullsDistinctOption::None
                    {
                        return Err(unsupported(
                            "UNIQUE supports immediate NULLS DISTINCT constraints without index options",
                        ));
                    }
                    unique_constraints.push(UniqueConstraint {
                        index_id: 0,
                        name: option
                            .name
                            .map(|value| normalize_ident(&value.value))
                            .or_else(|| Some(format!("{table_name}_{name}_key"))),
                        columns: vec![name.clone()],
                    });
                }
                ColumnOption::ForeignKey(foreign_key) => {
                    foreign_keys.push(foreign_key_definition(
                        option.name.map(|value| normalize_ident(&value.value)),
                        vec![name.clone()],
                        foreign_key,
                    )?);
                }
                ColumnOption::Check(check) => {
                    if check.enforced == Some(false) {
                        return Err(unsupported("NOT ENFORCED CHECK is not supported"));
                    }
                    check_constraints.push(CheckConstraintDefinition {
                        name: option
                            .name
                            .or(check.name)
                            .map(|value| normalize_ident(&value.value)),
                        expression: check.expr.to_string(),
                    });
                }
                ColumnOption::Generated {
                    generated_as,
                    sequence_options,
                    generation_expr,
                    generation_expr_mode,
                    ..
                } if generation_expr.is_none()
                    && generation_expr_mode.is_none()
                    && sequence_options.as_ref().is_none_or(Vec::is_empty) =>
                {
                    if identity.is_some() || default.is_some() {
                        return Err(invalid(format!(
                            "column {name} cannot combine identity generation with another default"
                        )));
                    }
                    if !matches!(
                        data_type,
                        RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt
                    ) {
                        return Err(invalid("identity columns require an integer type"));
                    }
                    identity = Some(match generated_as {
                        GeneratedAs::Always => IdentityGeneration::Always,
                        GeneratedAs::ByDefault => IdentityGeneration::ByDefault,
                        GeneratedAs::ExpStored => {
                            return Err(unsupported(
                                "stored generated expressions are outside the current profile",
                            ));
                        }
                    });
                    nullable = false;
                }
                _ => return Err(unsupported("column option is outside relational v1")),
            }
        }
        columns.push(RelationalColumn {
            name,
            data_type,
            nullable,
            default,
            identity,
        });
    }
    for constraint in create.constraints {
        match constraint {
            TableConstraint::PrimaryKey(key) => {
                if key.index_name.is_some()
                    || key.index_type.is_some()
                    || !key.index_options.is_empty()
                    || key.characteristics.is_some()
                {
                    return Err(unsupported(
                        "PRIMARY KEY supports immediate constraints without index options",
                    ));
                }
                if !primary_key.is_empty() {
                    return Err(invalid("table has more than one primary key"));
                }
                primary_key_name = key.name.map(|value| normalize_ident(&value.value));
                primary_key = key
                    .columns
                    .iter()
                    .map(index_column_name)
                    .collect::<Result<_>>()?;
            }
            TableConstraint::Unique(unique) => {
                if unique.index_name.is_some()
                    || unique.index_type.is_some()
                    || !unique.index_options.is_empty()
                    || unique.characteristics.is_some()
                    || unique.nulls_distinct != sqlparser::ast::NullsDistinctOption::None
                {
                    return Err(unsupported(
                        "UNIQUE supports immediate NULLS DISTINCT constraints without index options",
                    ));
                }
                let columns = unique
                    .columns
                    .iter()
                    .map(index_column_name)
                    .collect::<Result<Vec<_>>>()?;
                let name = unique
                    .name
                    .map(|value| normalize_ident(&value.value))
                    .unwrap_or_else(|| format!("{}_{}_key", table_name, columns.join("_")));
                unique_constraints.push(UniqueConstraint {
                    index_id: 0,
                    name: Some(name),
                    columns,
                });
            }
            TableConstraint::ForeignKey(foreign_key) => {
                let name = foreign_key
                    .name
                    .as_ref()
                    .map(|value| normalize_ident(&value.value));
                let local_columns = foreign_key
                    .columns
                    .iter()
                    .map(|value| normalize_ident(&value.value))
                    .collect();
                foreign_keys.push(foreign_key_definition(name, local_columns, foreign_key)?);
            }
            TableConstraint::Check(check) => {
                if check.enforced == Some(false) {
                    return Err(unsupported("NOT ENFORCED CHECK is not supported"));
                }
                check_constraints.push(CheckConstraintDefinition {
                    name: check.name.map(|value| normalize_ident(&value.value)),
                    expression: check.expr.to_string(),
                });
            }
            _ => return Err(unsupported("table constraint is outside relational v1")),
        }
    }
    if columns.is_empty() {
        return Err(invalid("table must contain at least one column"));
    }
    let mut seen = BTreeSet::new();
    for column in &columns {
        if !seen.insert(column.name.clone()) {
            return Err(invalid(format!("duplicate column {}", column.name)));
        }
    }
    for name in &primary_key {
        let index = columns
            .iter()
            .position(|column| &column.name == name)
            .ok_or_else(|| invalid(format!("unknown primary-key column {name}")))?;
        columns[index].nullable = false;
    }
    if !primary_key.is_empty() && primary_key_name.is_none() {
        primary_key_name = Some(format!("{table_name}_pkey"));
    }
    let definition = TableDefinition {
        table_id: 0,
        security_incarnation: None,
        creator_principal_id: None,
        tenant_id: None,
        managed_by_ml: false,
        name: table_name,
        columns,
        primary_key,
        primary_key_name,
        primary_key_index_id: None,
        unique_constraints,
        check_constraints,
        foreign_keys,
        indexes: Vec::new(),
        reference_index_ids: BTreeMap::new(),
    };
    Ok(definition)
}

fn foreign_key_definition(
    option_name: Option<String>,
    columns: Vec<String>,
    foreign_key: ForeignKeyConstraint,
) -> Result<ForeignKeyDefinition> {
    let match_kind = match foreign_key.match_kind {
        None | Some(ConstraintReferenceMatchKind::Simple) => ForeignKeyMatch::Simple,
        Some(ConstraintReferenceMatchKind::Full) => ForeignKeyMatch::Full,
        Some(ConstraintReferenceMatchKind::Partial) => {
            return Err(unsupported("foreign-key MATCH PARTIAL is not supported"));
        }
    };
    let on_delete = foreign_key_action(foreign_key.on_delete);
    let on_update = foreign_key_action(foreign_key.on_update);
    let ConstraintCharacteristics {
        deferrable,
        initially,
        enforced,
    } = foreign_key.characteristics.unwrap_or_default();
    if enforced == Some(false) {
        return Err(unsupported("NOT ENFORCED foreign keys are not supported"));
    }
    let deferrable = deferrable.unwrap_or(false);
    let initially_deferred = matches!(initially, Some(DeferrableInitial::Deferred));
    if initially_deferred && !deferrable {
        return Err(invalid(
            "INITIALLY DEFERRED requires a DEFERRABLE foreign key",
        ));
    }
    Ok(ForeignKeyDefinition {
        index_id: 0,
        name: option_name.or_else(|| {
            foreign_key
                .name
                .as_ref()
                .map(|value| normalize_ident(&value.value))
        }),
        columns,
        referenced_table: normalize_name(&foreign_key.foreign_table),
        referenced_columns: foreign_key
            .referred_columns
            .iter()
            .map(|value| normalize_ident(&value.value))
            .collect(),
        referenced_key_kind: None,
        referenced_key_name: None,
        match_kind,
        on_delete,
        on_update,
        deferrable,
        initially_deferred,
    })
}

fn foreign_key_action(action: Option<ReferentialAction>) -> ForeignKeyAction {
    match action.unwrap_or(ReferentialAction::NoAction) {
        ReferentialAction::NoAction => ForeignKeyAction::NoAction,
        ReferentialAction::Restrict => ForeignKeyAction::Restrict,
        ReferentialAction::Cascade => ForeignKeyAction::Cascade,
        ReferentialAction::SetNull => ForeignKeyAction::SetNull,
        ReferentialAction::SetDefault => ForeignKeyAction::SetDefault,
    }
}

fn static_default_value(expression: &Expr, data_type: &RelationalType) -> Result<RelationalValue> {
    let mut cursor = 0;
    let value = expression_value(expression, data_type, &[], &mut cursor).map_err(|_| {
        unsupported("column defaults must be typed static literals in this release")
    })?;
    validate_value(data_type, &value)?;
    Ok(value)
}

fn relational_type(data_type: &DataType) -> Result<RelationalType> {
    if let DataType::Custom(name, modifiers) = data_type
        && name.to_string().eq_ignore_ascii_case("record_ref")
    {
        if modifiers.len() != 1 || modifiers[0].trim().is_empty() {
            return Err(invalid("RECORD_REF requires exactly one namespace"));
        }
        return Ok(RelationalType::RecordRef {
            namespace: modifiers[0].to_ascii_lowercase(),
        });
    }
    let text = data_type.to_string().to_ascii_lowercase();
    if text == "boolean" || text == "bool" {
        return Ok(RelationalType::Boolean);
    }
    if text == "smallint" || text == "int2" {
        return Ok(RelationalType::SmallInt);
    }
    if text == "integer" || text == "int" || text == "int4" {
        return Ok(RelationalType::Integer);
    }
    if text == "bigint" || text == "int8" {
        return Ok(RelationalType::BigInt);
    }
    if text == "real" || text == "float4" {
        return Ok(RelationalType::Real);
    }
    if ["float", "float8", "double", "double precision"]
        .iter()
        .any(|candidate| text.starts_with(candidate))
    {
        return Ok(RelationalType::Float);
    }
    if text.starts_with("decimal") || text.starts_with("numeric") {
        let (precision, scale) = parse_precision_scale(&text)?;
        return Ok(RelationalType::Decimal { precision, scale });
    }
    if text == "uuid" {
        return Ok(RelationalType::Uuid);
    }
    if text == "bytea" {
        return Ok(RelationalType::Bytea);
    }
    if text == "date" {
        return Ok(RelationalType::Date);
    }
    if text.contains("timestamp") {
        return Ok(RelationalType::TimestampUtc);
    }
    if text == "jsonb" {
        return Ok(RelationalType::Jsonb);
    }
    if text == "text" {
        return Ok(RelationalType::Text);
    }
    if text.starts_with("varchar") || text.starts_with("character varying") {
        let length = parse_single_type_length(&text, "varchar")
            .or_else(|_| parse_single_type_length(&text, "character varying"))?;
        return Ok(RelationalType::Varchar { length });
    }
    if let Some(inner) = text
        .strip_prefix("vector(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let dimension = inner
            .parse::<usize>()
            .map_err(|_| invalid("invalid vector dimension"))?;
        if dimension == 0 || dimension > 65_536 {
            return Err(invalid("vector dimension must be between 1 and 65536"));
        }
        return Ok(RelationalType::Vector { dimension });
    }
    Err(unsupported(format!(
        "unsupported relational type {data_type}"
    )))
}

fn parse_single_type_length(value: &str, type_name: &str) -> Result<usize> {
    let arguments = value
        .strip_prefix(type_name)
        .map(str::trim)
        .and_then(|value| value.strip_prefix('('))
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| invalid(format!("{type_name} requires a positive length")))?;
    let length = arguments
        .trim()
        .parse::<usize>()
        .map_err(|_| invalid(format!("invalid {type_name} length")))?;
    if length == 0 || length > 10_485_760 {
        return Err(invalid(format!(
            "{type_name} length must be between 1 and 10485760"
        )));
    }
    Ok(length)
}

fn parse_precision_scale(value: &str) -> Result<(u8, u8)> {
    let Some(arguments) = value
        .split_once('(')
        .map(|(_, rest)| rest.trim_end_matches(')'))
    else {
        return Ok((38, 9));
    };
    let mut parts = arguments.split(',').map(str::trim);
    let precision = parts
        .next()
        .ok_or_else(|| invalid("decimal precision is required"))?
        .parse::<u8>()
        .map_err(|_| invalid("invalid decimal precision"))?;
    let scale = parts
        .next()
        .unwrap_or("0")
        .parse::<u8>()
        .map_err(|_| invalid("invalid decimal scale"))?;
    if precision == 0 || precision > 38 || scale > precision || parts.next().is_some() {
        return Err(invalid(
            "decimal requires 1 <= precision <= 38 and scale <= precision",
        ));
    }
    Ok((precision, scale))
}

fn expression_value(
    expression: &Expr,
    expected: &RelationalType,
    parameters: &[RelationalValue],
    _parameter_cursor: &mut usize,
) -> Result<RelationalValue> {
    let value = match expression {
        Expr::Value(value) => match &value.value {
            Value::Null => RelationalValue::Null,
            Value::Boolean(value) => RelationalValue::Boolean(*value),
            Value::Number(value, _) => numeric_value(value, expected)?,
            Value::SingleQuotedString(value) => string_value(value, expected)?,
            Value::Placeholder(placeholder) => {
                let index = if let Some(number) = placeholder.strip_prefix('$') {
                    number
                        .parse::<usize>()
                        .ok()
                        .and_then(|number| number.checked_sub(1))
                        .ok_or_else(|| invalid(format!("invalid placeholder {placeholder}")))?
                } else {
                    return Err(invalid(format!(
                        "unsupported placeholder {placeholder}; use $1 through $n"
                    )));
                };
                let value = parameters
                    .get(index)
                    .cloned()
                    .ok_or_else(|| invalid(format!("missing parameter for {placeholder}")))?;
                coerce_parameter(value, expected)?
            }
            _ => return Err(unsupported("literal is outside relational v1")),
        },
        Expr::Function(function)
            if function.name.to_string().eq_ignore_ascii_case("record_ref") =>
        {
            let RelationalType::RecordRef {
                namespace: expected,
            } = expected
            else {
                return Err(invalid(
                    "RECORD_REF can only be assigned to a RECORD_REF column",
                ));
            };
            let FunctionArguments::List(arguments) = &function.args else {
                return Err(invalid("RECORD_REF requires namespace and id arguments"));
            };
            if arguments.args.len() != 2 || !arguments.clauses.is_empty() {
                return Err(invalid("RECORD_REF requires namespace and id arguments"));
            }
            let positional = |index: usize| match &arguments.args[index] {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(expression)) => Ok(expression),
                _ => Err(invalid(
                    "RECORD_REF arguments must be positional expressions",
                )),
            };
            let namespace = match positional(0)? {
                Expr::Value(value) => match &value.value {
                    Value::SingleQuotedString(value) => value.to_ascii_lowercase(),
                    _ => return Err(invalid("RECORD_REF namespace must be a string literal")),
                },
                _ => return Err(invalid("RECORD_REF namespace must be a string literal")),
            };
            if &namespace != expected {
                return Err(invalid(format!(
                    "RECORD_REF namespace {namespace} does not match column namespace {expected}"
                )));
            }
            let id = match positional(1)? {
                Expr::Value(value) => match &value.value {
                    Value::SingleQuotedString(value) => value.clone(),
                    Value::Number(value, _) => value.clone(),
                    Value::Placeholder(placeholder) => {
                        let index = placeholder
                            .strip_prefix('$')
                            .and_then(|value| value.parse::<usize>().ok())
                            .and_then(|value| value.checked_sub(1))
                            .ok_or_else(|| invalid(format!("invalid placeholder {placeholder}")))?;
                        match parameters.get(index) {
                            Some(RelationalValue::Text(value)) => value.clone(),
                            Some(RelationalValue::Uuid(value)) => value.to_string(),
                            Some(RelationalValue::Integer(value)) => value.to_string(),
                            _ => {
                                return Err(invalid(
                                    "RECORD_REF id parameter must be text, UUID, or integer",
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(invalid(
                            "RECORD_REF id must be text, number, or a parameter",
                        ));
                    }
                },
                _ => return Err(invalid("RECORD_REF id must be a literal or parameter")),
            };
            if id.is_empty() {
                return Err(invalid("RECORD_REF id cannot be empty"));
            }
            RelationalValue::RecordRef(chirondb_types::RecordRef { namespace, id })
        }
        Expr::UnaryOp { op, expr } if op.to_string() == "-" => {
            match expression_value(expr, expected, parameters, _parameter_cursor)? {
                RelationalValue::Integer(value) => RelationalValue::Integer(-value),
                RelationalValue::Float(value) => RelationalValue::Float(-value),
                RelationalValue::Decimal(value) => RelationalValue::Decimal(format!("-{value}")),
                _ => return Err(invalid("unary minus requires a numeric value")),
            }
        }
        Expr::Cast {
            kind,
            expr,
            data_type,
            array,
            format,
        } => {
            if !matches!(kind, CastKind::Cast | CastKind::DoubleColon) || *array || format.is_some()
            {
                return Err(unsupported(
                    "only CAST(expr AS type) and expr::type are supported",
                ));
            }
            let target = relational_type(data_type)?;
            let value = expression_value(expr, &target, parameters, _parameter_cursor)?;
            if !cast_storage_compatible(&target, expected) {
                return Err(unsupported(format!(
                    "cast from {target:?} cannot be assigned to {expected:?}"
                )));
            }
            value
        }
        _ => {
            return Err(unsupported(
                "expression is outside the scalar relational v1 subset",
            ));
        }
    };
    validate_value(expected, &value)?;
    Ok(value)
}

fn cast_storage_compatible(source: &RelationalType, target: &RelationalType) -> bool {
    source == target
        || (matches!(
            source,
            RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt
        ) && matches!(
            target,
            RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt
        ))
        || (matches!(source, RelationalType::Real | RelationalType::Float)
            && matches!(target, RelationalType::Real | RelationalType::Float))
        || (matches!(
            source,
            RelationalType::Text | RelationalType::Varchar { .. }
        ) && matches!(
            target,
            RelationalType::Text | RelationalType::Varchar { .. }
        ))
}

fn coerce_parameter(value: RelationalValue, expected: &RelationalType) -> Result<RelationalValue> {
    if matches!(value, RelationalValue::Null) {
        return Ok(value);
    }
    if validate_value(expected, &value).is_ok() {
        return Ok(value);
    }
    let RelationalValue::Text(text) = value else {
        return Err(invalid(format!(
            "parameter value does not match type {expected:?}"
        )));
    };
    let value = match expected {
        RelationalType::Boolean => match text.to_ascii_lowercase().as_str() {
            "true" | "t" | "1" => RelationalValue::Boolean(true),
            "false" | "f" | "0" => RelationalValue::Boolean(false),
            _ => return Err(invalid("boolean parameter must be true or false")),
        },
        RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt => text
            .parse::<i64>()
            .map(RelationalValue::Integer)
            .map_err(|_| invalid("integer parameter is invalid"))?,
        RelationalType::Real | RelationalType::Float => text
            .parse::<f64>()
            .map(RelationalValue::Float)
            .map_err(|_| invalid("floating-point parameter is invalid"))?,
        RelationalType::Decimal { .. } => RelationalValue::Decimal(text),
        RelationalType::Text | RelationalType::Varchar { .. } => RelationalValue::Text(text),
        RelationalType::Bytea => RelationalValue::Bytes(parse_bytea(&text)?),
        RelationalType::Date => RelationalValue::Date(text),
        RelationalType::TimestampUtc => RelationalValue::TimestampUtc(text),
        RelationalType::Uuid => uuid::Uuid::parse_str(&text)
            .map(RelationalValue::Uuid)
            .map_err(|_| invalid("UUID parameter is invalid"))?,
        RelationalType::Jsonb => serde_json::from_str(&text)
            .map(RelationalValue::Json)
            .map_err(|_| invalid("JSONB parameter is invalid"))?,
        RelationalType::Vector { .. } => serde_json::from_str::<Vec<f32>>(&text)
            .map(RelationalValue::Vector)
            .map_err(|_| invalid("vector parameter is invalid"))?,
        RelationalType::RecordRef { .. } => {
            return Err(invalid(
                "RECORD_REF parameters require the typed record_ref representation",
            ));
        }
    };
    validate_value(expected, &value)?;
    Ok(value)
}

fn numeric_value(value: &str, expected: &RelationalType) -> Result<RelationalValue> {
    match expected {
        RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt => value
            .parse::<i64>()
            .map(RelationalValue::Integer)
            .map_err(|_| invalid(format!("{value} is not a valid integer"))),
        RelationalType::Real | RelationalType::Float => value
            .parse::<f64>()
            .map(RelationalValue::Float)
            .map_err(|_| invalid(format!("{value} is not a valid float"))),
        RelationalType::Decimal { .. } => Ok(RelationalValue::Decimal(value.to_string())),
        _ => Err(invalid(format!(
            "numeric literal is not valid for {expected:?}"
        ))),
    }
}

fn string_value(value: &str, expected: &RelationalType) -> Result<RelationalValue> {
    match expected {
        RelationalType::Text | RelationalType::Varchar { .. } => {
            Ok(RelationalValue::Text(value.to_string()))
        }
        RelationalType::Bytea => Ok(RelationalValue::Bytes(parse_bytea(value)?)),
        RelationalType::Date => Ok(RelationalValue::Date(value.to_string())),
        RelationalType::Decimal { .. } => Ok(RelationalValue::Decimal(value.to_string())),
        RelationalType::TimestampUtc => Ok(RelationalValue::TimestampUtc(value.to_string())),
        RelationalType::Uuid => uuid::Uuid::parse_str(value)
            .map(RelationalValue::Uuid)
            .map_err(|_| invalid(format!("{value} is not a valid UUID"))),
        RelationalType::Jsonb => serde_json::from_str(value)
            .map(RelationalValue::Json)
            .map_err(|_| invalid("JSONB string must be valid JSON")),
        RelationalType::Vector { .. } => {
            let vector = serde_json::from_str::<Vec<f32>>(value)
                .map_err(|_| invalid("vector string must be a JSON numeric array"))?;
            Ok(RelationalValue::Vector(vector))
        }
        _ => Err(invalid(format!(
            "string literal is not valid for {expected:?}"
        ))),
    }
}

fn parse_bytea(value: &str) -> Result<Vec<u8>> {
    let hex = value
        .strip_prefix("\\x")
        .ok_or_else(|| invalid("BYTEA text input must use PostgreSQL hex format \\x..."))?;
    if hex.len() % 2 != 0 {
        return Err(invalid("BYTEA hex input must contain complete bytes"));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex input is UTF-8");
            u8::from_str_radix(pair, 16).map_err(|_| invalid("BYTEA contains invalid hex"))
        })
        .collect()
}

fn predicate_matches(
    expression: Option<&Expr>,
    definition: &TableDefinition,
    row: &[RelationalValue],
    parameters: &[RelationalValue],
    cursor: &mut usize,
) -> Result<bool> {
    Ok(predicate_result(expression, definition, row, parameters, cursor)?.unwrap_or(false))
}

fn predicate_result(
    expression: Option<&Expr>,
    definition: &TableDefinition,
    row: &[RelationalValue],
    parameters: &[RelationalValue],
    cursor: &mut usize,
) -> Result<Option<bool>> {
    let Some(expression) = expression else {
        return Ok(Some(true));
    };
    match expression {
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::And => Ok(sql_and(
            predicate_result(Some(left), definition, row, parameters, cursor)?,
            predicate_result(Some(right), definition, row, parameters, cursor)?,
        )),
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::Or => Ok(sql_or(
            predicate_result(Some(left), definition, row, parameters, cursor)?,
            predicate_result(Some(right), definition, row, parameters, cursor)?,
        )),
        Expr::UnaryOp { op, expr } if op.to_string().eq_ignore_ascii_case("not") => Ok(
            predicate_result(Some(expr), definition, row, parameters, cursor)?.map(|value| !value),
        ),
        Expr::InList {
            expr,
            list,
            negated,
        } => {
            let index = column_index(definition, &expression_column_name(expr)?)?;
            let values = list
                .iter()
                .map(|value| {
                    expression_value(
                        value,
                        &definition.columns[index].data_type,
                        parameters,
                        cursor,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(in_list_predicate(&row[index], &values, *negated))
        }
        Expr::Between {
            expr,
            negated,
            low,
            high,
        } => {
            let index = column_index(definition, &expression_column_name(expr)?)?;
            let low = expression_value(
                low,
                &definition.columns[index].data_type,
                parameters,
                cursor,
            )?;
            let high = expression_value(
                high,
                &definition.columns[index].data_type,
                parameters,
                cursor,
            )?;
            Ok(between_predicate(&row[index], &low, &high, *negated))
        }
        Expr::BinaryOp { left, op, right } => {
            let (column_expression, value_expression, reverse) = match (&**left, &**right) {
                (Expr::Identifier(_), _) | (Expr::CompoundIdentifier(_), _) => {
                    (&**left, &**right, false)
                }
                (_, Expr::Identifier(_)) | (_, Expr::CompoundIdentifier(_)) => {
                    (&**right, &**left, true)
                }
                _ => {
                    return Err(unsupported(
                        "predicate must compare a column and scalar value",
                    ));
                }
            };
            let name = expression_column_name(column_expression)?;
            let index = column_index(definition, &name)?;
            let expected = &definition.columns[index].data_type;
            let value = expression_value(value_expression, expected, parameters, cursor)?;
            let ordering = compare_values(&row[index], &value);
            let op = if reverse {
                reverse_operator(op)
            } else {
                op.clone()
            };
            if ordering.is_none() {
                Ok(None)
            } else {
                compare_predicate(&row[index], &value, &op).map(Some)
            }
        }
        Expr::IsNull(expression) => {
            let index = column_index(definition, &expression_column_name(expression)?)?;
            Ok(Some(matches!(row[index], RelationalValue::Null)))
        }
        Expr::IsNotNull(expression) => {
            let index = column_index(definition, &expression_column_name(expression)?)?;
            Ok(Some(!matches!(row[index], RelationalValue::Null)))
        }
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            let index = column_index(definition, &expression_column_name(expression)?)?;
            match &row[index] {
                RelationalValue::Boolean(value) => Ok(Some(*value)),
                RelationalValue::Null => Ok(None),
                _ => Err(invalid("bare predicate column must be BOOLEAN")),
            }
        }
        Expr::Nested(expression) => {
            predicate_result(Some(expression), definition, row, parameters, cursor)
        }
        _ => Err(unsupported("predicate expression is outside relational v1")),
    }
}

fn reverse_operator(operator: &BinaryOperator) -> BinaryOperator {
    match operator {
        BinaryOperator::Lt => BinaryOperator::Gt,
        BinaryOperator::LtEq => BinaryOperator::GtEq,
        BinaryOperator::Gt => BinaryOperator::Lt,
        BinaryOperator::GtEq => BinaryOperator::LtEq,
        other => other.clone(),
    }
}

fn compare_values(left: &RelationalValue, right: &RelationalValue) -> Option<Ordering> {
    match (left, right) {
        (RelationalValue::Null, _) | (_, RelationalValue::Null) => None,
        (RelationalValue::Boolean(left), RelationalValue::Boolean(right)) => {
            left.partial_cmp(right)
        }
        (RelationalValue::Integer(left), RelationalValue::Integer(right)) => {
            left.partial_cmp(right)
        }
        (RelationalValue::Float(left), RelationalValue::Float(right)) => left.partial_cmp(right),
        (RelationalValue::Decimal(left), RelationalValue::Decimal(right)) => {
            compare_decimal(left, right)
        }
        (RelationalValue::Text(left), RelationalValue::Text(right)) => left.partial_cmp(right),
        (RelationalValue::Bytes(left), RelationalValue::Bytes(right)) => left.partial_cmp(right),
        (RelationalValue::Date(left), RelationalValue::Date(right)) => {
            chrono::NaiveDate::parse_from_str(left, "%Y-%m-%d")
                .ok()?
                .partial_cmp(&chrono::NaiveDate::parse_from_str(right, "%Y-%m-%d").ok()?)
        }
        (RelationalValue::TimestampUtc(left), RelationalValue::TimestampUtc(right)) => {
            chrono::DateTime::parse_from_rfc3339(left)
                .ok()?
                .partial_cmp(&chrono::DateTime::parse_from_rfc3339(right).ok()?)
        }
        (RelationalValue::Uuid(left), RelationalValue::Uuid(right)) => left.partial_cmp(right),
        (RelationalValue::Json(left), RelationalValue::Json(right)) => serde_json::to_string(left)
            .ok()?
            .partial_cmp(&serde_json::to_string(right).ok()?),
        (RelationalValue::RecordRef(left), RelationalValue::RecordRef(right)) => {
            left.partial_cmp(right)
        }
        _ => None,
    }
}

fn validate_definition(definition: &TableDefinition) -> Result<()> {
    if definition.creator_principal_id.as_ref().is_some_and(|id| {
        definition.security_incarnation.is_none() || (id.is_empty() || id.len() > 128)
    }) {
        return Err(invalid("invalid protected table creator"));
    }
    if definition
        .security_incarnation
        .is_some_and(|id| id.is_nil())
        || (definition.security_incarnation.is_some() && definition.tenant_id.is_none())
    {
        return Err(invalid("invalid protected table incarnation"));
    }
    if definition.table_id == 0 {
        return Err(invalid(
            "table catalog ID must be assigned before publication",
        ));
    }
    if definition.primary_key.is_empty() != definition.primary_key_index_id.is_none()
        || definition.primary_key_index_id == Some(0)
        || (definition.primary_key.is_empty() && definition.primary_key_name.is_some())
    {
        return Err(invalid(
            "primary-key catalog index identity does not match its columns",
        ));
    }
    if (definition.tenant_id.is_none() && !definition.reference_index_ids.is_empty())
        || definition.reference_index_ids.iter().any(|(name, id)| {
            *id == 0
                || !definition.columns.iter().any(|column| {
                    column.name == *name
                        && matches!(column.data_type, RelationalType::RecordRef { .. })
                })
                || catalog_index_owners(definition).any(|(other_id, columns)| {
                    columns == std::slice::from_ref(name) && other_id != *id
                })
        })
    {
        return Err(invalid(
            "protected reference index identity does not match its column",
        ));
    }
    let columns = definition
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect::<HashSet<_>>();
    let constraint_columns = definition
        .unique_constraints
        .iter()
        .map(|constraint| &constraint.columns)
        .chain((!definition.primary_key.is_empty()).then_some(&definition.primary_key))
        .chain(definition.indexes.iter().map(|index| &index.columns));
    for names in constraint_columns {
        if names.is_empty() || names.iter().any(|name| !columns.contains(name.as_str())) {
            return Err(invalid(
                "constraint references an unknown or empty column list",
            ));
        }
    }
    let mut index_names = HashSet::new();
    for index in &definition.indexes {
        if index.index_id == 0 || index.name.is_empty() || !index_names.insert(index.name.as_str())
        {
            return Err(invalid("scalar index names must be non-empty and unique"));
        }
    }
    if definition
        .unique_constraints
        .iter()
        .any(|constraint| constraint.index_id == 0)
        || definition
            .foreign_keys
            .iter()
            .any(|foreign_key| foreign_key.index_id == 0)
    {
        return Err(invalid(
            "constraint support indexes require stable catalog identities",
        ));
    }
    let mut physical_columns = HashMap::<u64, Vec<String>>::new();
    for (index_id, columns) in catalog_index_owners(definition) {
        if index_id == 0 {
            return Err(invalid("physical index ID zero is reserved"));
        }
        if let Some(existing) = physical_columns.insert(index_id, columns.to_vec())
            && existing != columns
        {
            return Err(invalid(format!(
                "physical index ID {index_id} has conflicting column ownership"
            )));
        }
    }
    let mut constraint_names = HashSet::new();
    for name in definition
        .primary_key_name
        .iter()
        .map(String::as_str)
        .chain(
            definition
                .unique_constraints
                .iter()
                .filter_map(|constraint| constraint.name.as_deref()),
        )
        .chain(
            definition
                .foreign_keys
                .iter()
                .filter_map(|constraint| constraint.name.as_deref()),
        )
        .chain(
            definition
                .check_constraints
                .iter()
                .filter_map(|constraint| constraint.name.as_deref()),
        )
    {
        if name.is_empty() || !constraint_names.insert(name) {
            return Err(invalid(
                "constraint names must be non-empty and unique within a table",
            ));
        }
    }
    let null_row = vec![RelationalValue::Null; definition.columns.len()];
    for constraint in &definition.check_constraints {
        if constraint.expression.trim().is_empty() {
            return Err(invalid("CHECK constraint expression must be non-empty"));
        }
        let expression = parse_check_expression(&constraint.expression)?;
        check_constraint_result(&expression, definition, &null_row)?;
    }
    for foreign_key in &definition.foreign_keys {
        if foreign_key.columns.is_empty()
            || (!foreign_key.referenced_columns.is_empty()
                && foreign_key.columns.len() != foreign_key.referenced_columns.len())
            || foreign_key
                .columns
                .iter()
                .any(|name| !columns.contains(name.as_str()))
        {
            return Err(invalid("invalid foreign-key column list"));
        }
        if foreign_key
            .referenced_key_name
            .as_ref()
            .is_some_and(String::is_empty)
        {
            return Err(invalid("foreign-key referenced key name cannot be empty"));
        }
        if foreign_key.referenced_key_kind.is_some() != foreign_key.referenced_key_name.is_some() {
            return Err(invalid(
                "foreign-key referenced key kind and name must be persisted together",
            ));
        }
        if foreign_key.initially_deferred && !foreign_key.deferrable {
            return Err(invalid(
                "INITIALLY DEFERRED requires a DEFERRABLE foreign key",
            ));
        }
    }
    for column in &definition.columns {
        if column.identity.is_some()
            && (!matches!(
                column.data_type,
                RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt
            ) || column.nullable
                || column.default.is_some())
        {
            return Err(invalid(format!(
                "identity column {} must be a NOT NULL integer without a static default",
                column.name
            )));
        }
        if let Some(default) = &column.default {
            validate_value(&column.data_type, default)?;
            if matches!(default, RelationalValue::Null) && !column.nullable {
                return Err(invalid(format!(
                    "default for NOT NULL column {} cannot be NULL",
                    column.name
                )));
            }
        }
    }
    Ok(())
}

fn resolved_referenced_columns(
    foreign_key: &ForeignKeyDefinition,
    referenced: &TableDefinition,
) -> Result<Vec<String>> {
    let columns = if foreign_key.referenced_columns.is_empty() {
        referenced.primary_key.clone()
    } else {
        foreign_key.referenced_columns.clone()
    };
    if columns.is_empty() || columns.len() != foreign_key.columns.len() {
        return Err(invalid(format!(
            "foreign key {} does not match the referenced primary-key cardinality",
            foreign_key.name.as_deref().unwrap_or("<unnamed>")
        )));
    }
    Ok(columns)
}

fn bind_foreign_key_targets(
    state: &RelationalState,
    definition: &mut TableDefinition,
) -> Result<()> {
    for position in 0..definition.foreign_keys.len() {
        if definition.foreign_keys[position]
            .referenced_key_name
            .is_some()
        {
            continue;
        }
        let foreign_key = definition.foreign_keys[position].clone();
        let referenced = if foreign_key.referenced_table == definition.name {
            &*definition
        } else {
            state
                .tables
                .get(&foreign_key.referenced_table)
                .ok_or_else(|| {
                    invalid(format!(
                        "foreign key references missing table {}",
                        foreign_key.referenced_table
                    ))
                })?
                .definition
                .as_ref()
        };
        if referenced.tenant_id != definition.tenant_id {
            return Err(SecurityError::NotFound.into());
        }
        let columns = resolved_referenced_columns(&foreign_key, referenced)?;
        let (key_kind, key_name) =
            referenced_key_for_columns(referenced, &columns).ok_or_else(|| {
                invalid(format!(
                    "foreign key {} must reference a primary or unique key",
                    foreign_key.name.as_deref().unwrap_or("<unnamed>")
                ))
            })?;
        definition.foreign_keys[position].referenced_key_kind = Some(key_kind);
        definition.foreign_keys[position].referenced_key_name = Some(key_name);
    }
    Ok(())
}

fn referenced_key_for_columns(
    definition: &TableDefinition,
    columns: &[String],
) -> Option<(ReferencedKeyKind, String)> {
    if definition.primary_key == columns {
        return Some((
            ReferencedKeyKind::PrimaryKey,
            primary_key_constraint_name(definition),
        ));
    }
    if let Some(constraint) = definition
        .unique_constraints
        .iter()
        .find(|constraint| constraint.columns == columns)
    {
        return Some((
            ReferencedKeyKind::UniqueConstraint,
            unique_constraint_name(&definition.name, constraint),
        ));
    }
    definition
        .indexes
        .iter()
        .find(|index| index.unique && index.columns == columns)
        .map(|index| (ReferencedKeyKind::UniqueIndex, index.name.clone()))
}

fn referenced_key_matches(
    definition: &TableDefinition,
    columns: &[String],
    key_kind: Option<ReferencedKeyKind>,
    key_name: Option<&str>,
) -> bool {
    match (key_kind, key_name) {
        (Some(ReferencedKeyKind::PrimaryKey), Some(key_name)) => {
            definition.primary_key == columns && primary_key_constraint_name(definition) == key_name
        }
        (Some(ReferencedKeyKind::UniqueConstraint), Some(key_name)) => {
            definition.unique_constraints.iter().any(|constraint| {
                constraint.columns == columns
                    && unique_constraint_name(&definition.name, constraint) == key_name
            })
        }
        (Some(ReferencedKeyKind::UniqueIndex), Some(key_name)) => definition
            .indexes
            .iter()
            .any(|index| index.unique && index.columns == columns && index.name == key_name),
        (None, key_name) => {
            (definition.primary_key == columns
                && key_name.is_none_or(|name| primary_key_constraint_name(definition) == name))
                || definition.unique_constraints.iter().any(|constraint| {
                    constraint.columns == columns
                        && key_name.is_none_or(|name| {
                            unique_constraint_name(&definition.name, constraint) == name
                        })
                })
                || definition.indexes.iter().any(|index| {
                    index.unique
                        && index.columns == columns
                        && key_name.is_none_or(|name| index.name == name)
                })
        }
        (Some(_), None) => false,
    }
}

fn reject_referenced_key_drop(
    state: &RelationalState,
    referenced_table: &str,
    dropped_columns: &[String],
    dropped_kind: ReferencedKeyKind,
    constraint_name: &str,
) -> Result<()> {
    let referenced_definition = &state
        .tables
        .get(referenced_table)
        .expect("referenced table exists during ALTER TABLE")
        .definition;
    for (child_table, table) in state.tables.iter() {
        for foreign_key in &table.definition.foreign_keys {
            if foreign_key_depends_on_referenced_key(
                foreign_key,
                referenced_definition,
                referenced_table,
                dropped_columns,
                dropped_kind,
                constraint_name,
            )? {
                return Err(invalid(format!(
                    "cannot drop constraint {constraint_name} because foreign key {} on table {child_table} depends on it",
                    foreign_key.name.as_deref().unwrap_or("<unnamed>")
                )));
            }
        }
    }
    Ok(())
}

fn cascade_referenced_key_drop(
    state: &RelationalState,
    referenced_table: &str,
    current_definition: &mut TableDefinition,
    dropped_columns: &[String],
    dropped_kind: ReferencedKeyKind,
    constraint_name: &str,
) -> Result<Vec<TableDefinition>> {
    let referenced_definition = &state
        .tables
        .get(referenced_table)
        .expect("referenced table exists during ALTER TABLE")
        .definition;
    let mut child_tables = state.tables.keys().cloned().collect::<Vec<_>>();
    child_tables.sort();
    let mut cascaded = Vec::new();
    for child_table in child_tables {
        let mut definition = if child_table == referenced_table {
            current_definition.clone()
        } else {
            state
                .tables
                .get(&child_table)
                .expect("child table exists during ALTER TABLE")
                .definition
                .as_ref()
                .clone()
        };
        let mut retained = Vec::with_capacity(definition.foreign_keys.len());
        let mut removed = false;
        for foreign_key in definition.foreign_keys {
            if foreign_key_depends_on_referenced_key(
                &foreign_key,
                referenced_definition,
                referenced_table,
                dropped_columns,
                dropped_kind,
                constraint_name,
            )? {
                removed = true;
            } else {
                retained.push(foreign_key);
            }
        }
        if !removed {
            continue;
        }
        definition.foreign_keys = retained;
        if child_table == referenced_table {
            *current_definition = definition;
        } else {
            cascaded.push(definition);
        }
    }
    Ok(cascaded)
}

fn foreign_key_depends_on_referenced_key(
    foreign_key: &ForeignKeyDefinition,
    referenced_definition: &TableDefinition,
    referenced_table: &str,
    dropped_columns: &[String],
    dropped_kind: ReferencedKeyKind,
    constraint_name: &str,
) -> Result<bool> {
    if foreign_key.referenced_table != referenced_table {
        return Ok(false);
    }
    if let Some(referenced_key_kind) = foreign_key.referenced_key_kind {
        if referenced_key_kind != dropped_kind
            || foreign_key.referenced_key_name.as_deref() != Some(constraint_name)
        {
            return Ok(false);
        }
    } else if let Some(referenced_key_name) = foreign_key.referenced_key_name.as_deref()
        && referenced_key_name != constraint_name
    {
        return Ok(false);
    }
    Ok(resolved_referenced_columns(foreign_key, referenced_definition)? == dropped_columns)
}

/// A DML batch can only invalidate constraints on written rows or on keys
/// removed from a referenced table. Consult their scalar indexes instead of
/// rereading every row and every index run on each commit and WAL replay.
fn validate_mutations(
    state: &RelationalState,
    before: &RelationalState,
    snapshot: u64,
    mutations: &[RelationalMutation],
    include_deferred: bool,
    constraint_modes: &ConstraintModes,
) -> Result<()> {
    // Removing tables cannot invalidate row, unique, or check constraints in
    // surviving tables. A RESTRICT drop has no dependent foreign keys; verify
    // that invariant again when applying an authenticated journal batch. This
    // avoids rereading every surviving row during a large table retirement.
    if pure_drop_preserves_validity(state, before, mutations) {
        return Ok(());
    }
    if mutations.iter().any(|mutation| {
        !matches!(
            mutation,
            RelationalMutation::Insert { .. }
                | RelationalMutation::Update { .. }
                | RelationalMutation::Delete { .. }
        )
    }) {
        return validate_database(state, snapshot, include_deferred, constraint_modes);
    }

    let mut written = BTreeMap::<String, BTreeSet<u64>>::new();
    let mut removed_parent_keys = BTreeMap::<String, BTreeSet<u64>>::new();
    for mutation in mutations {
        match mutation {
            RelationalMutation::Insert { table, rows } => {
                written
                    .entry(table.clone())
                    .or_default()
                    .extend(rows.iter().map(|row| row.row_id));
            }
            RelationalMutation::Update { table, rows } => {
                written
                    .entry(table.clone())
                    .or_default()
                    .extend(rows.iter().map(|row| row.row_id));
                removed_parent_keys
                    .entry(table.clone())
                    .or_default()
                    .extend(rows.iter().map(|row| row.row_id));
            }
            RelationalMutation::Delete { table, row_ids } => {
                removed_parent_keys
                    .entry(table.clone())
                    .or_default()
                    .extend(row_ids);
            }
            _ => unreachable!("schema changes use whole-database validation"),
        }
    }

    for (table_name, row_ids) in written {
        let table = state
            .tables
            .get(&table_name)
            .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
        let primary_indexes = table
            .definition
            .primary_key
            .iter()
            .map(|name| column_index(&table.definition, name))
            .collect::<Result<Vec<_>>>()?;
        let check_expressions = table
            .definition
            .check_constraints
            .iter()
            .map(|constraint| parse_check_expression(&constraint.expression))
            .collect::<Result<Vec<_>>>()?;
        let mut current_rows = Vec::with_capacity(row_ids.len());
        for row_id in row_ids {
            check_sql_cancelled()?;
            let Some(version) = table.rows.visible(row_id, snapshot)? else {
                continue;
            };
            let row = version.values;
            validate_row(&table.definition, &row)?;
            if primary_indexes
                .iter()
                .any(|index| matches!(row[*index], RelationalValue::Null))
            {
                return Err(invalid("primary-key columns cannot be NULL"));
            }
            for (constraint, expression) in table
                .definition
                .check_constraints
                .iter()
                .zip(&check_expressions)
            {
                if check_constraint_result(expression, &table.definition, &row)? == Some(false) {
                    return Err(invalid(format!(
                        "check constraint {} violated",
                        constraint.name.as_deref().unwrap_or("<unnamed>")
                    )));
                }
            }
            for foreign_key in &table.definition.foreign_keys {
                if !include_deferred && constraint_modes.is_deferred(foreign_key) {
                    continue;
                }
                let local_indexes = foreign_key
                    .columns
                    .iter()
                    .map(|name| column_index(&table.definition, name))
                    .collect::<Result<Vec<_>>>()?;
                let null_count = local_indexes
                    .iter()
                    .filter(|index| matches!(row[**index], RelationalValue::Null))
                    .count();
                if null_count > 0 {
                    if foreign_key.match_kind == ForeignKeyMatch::Full
                        && null_count != local_indexes.len()
                    {
                        return Err(invalid(format!(
                            "foreign key {} violates MATCH FULL null semantics",
                            foreign_key.name.as_deref().unwrap_or("<unnamed>")
                        )));
                    }
                    continue;
                }
                let parent = state
                    .tables
                    .get(&foreign_key.referenced_table)
                    .ok_or_else(|| invalid("foreign key references a missing table"))?;
                let referenced_columns =
                    resolved_referenced_columns(foreign_key, &parent.definition)?;
                let parent_index = parent.indexes.get(&referenced_columns).ok_or_else(|| {
                    invalid(format!(
                        "missing scalar index for referenced key {}",
                        referenced_columns.join(",")
                    ))
                })?;
                let values = local_indexes
                    .iter()
                    .map(|index| &row[*index])
                    .collect::<Vec<_>>();
                if parent_index
                    .lookup(&parent.index_segments, parent.index_snapshot, &values)?
                    .is_empty()
                {
                    return Err(invalid(format!(
                        "foreign key {} violated",
                        foreign_key.name.as_deref().unwrap_or("<unnamed>")
                    )));
                }
            }
            current_rows.push(StoredRow {
                row_id,
                values: row.to_vec(),
            });
        }
        validate_updated_unique_constraints(table, &current_rows)?;
    }

    for (parent_name, row_ids) in removed_parent_keys {
        let Some(before_parent) = before.tables.get(&parent_name) else {
            continue;
        };
        let parent = state
            .tables
            .get(&parent_name)
            .ok_or_else(|| invalid(format!("table {parent_name} does not exist")))?;
        for row_id in row_ids {
            check_sql_cancelled()?;
            let Some(old) = before_parent.rows.visible(row_id, snapshot)? else {
                continue;
            };
            for child in state.tables.values() {
                for foreign_key in &child.definition.foreign_keys {
                    if foreign_key.referenced_table != parent_name
                        || (!include_deferred && constraint_modes.is_deferred(foreign_key))
                    {
                        continue;
                    }
                    let referenced_columns =
                        resolved_referenced_columns(foreign_key, &parent.definition)?;
                    let parent_indexes = referenced_columns
                        .iter()
                        .map(|name| column_index(&parent.definition, name))
                        .collect::<Result<Vec<_>>>()?;
                    let old_values = parent_indexes
                        .iter()
                        .map(|index| &old.values[*index])
                        .collect::<Vec<_>>();
                    if old_values
                        .iter()
                        .any(|value| matches!(value, RelationalValue::Null))
                    {
                        continue;
                    }
                    let parent_index = parent
                        .indexes
                        .get(&referenced_columns)
                        .ok_or_else(|| invalid("missing scalar index for referenced key"))?;
                    if !parent_index
                        .lookup(&parent.index_segments, parent.index_snapshot, &old_values)?
                        .is_empty()
                    {
                        continue;
                    }
                    if let Some(mut children) =
                        child.indexed_entries(&foreign_key.columns, &old_values)?
                        && children.next().transpose()?.is_some()
                    {
                        return Err(invalid(format!(
                            "foreign key {} violated",
                            foreign_key.name.as_deref().unwrap_or("<unnamed>")
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

fn pure_drop_preserves_validity(
    state: &RelationalState,
    before: &RelationalState,
    mutations: &[RelationalMutation],
) -> bool {
    let dropped = mutations
        .iter()
        .map(|mutation| match mutation {
            RelationalMutation::DropTable { name } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Option<BTreeSet<_>>>();
    let Some(dropped) = dropped else {
        return false;
    };
    if dropped.is_empty()
        || dropped.len() != mutations.len()
        || before.tables.len() != state.tables.len() + dropped.len()
        || !dropped
            .iter()
            .all(|name| before.tables.contains_key(name) && !state.tables.contains_key(name))
    {
        return false;
    }
    state.tables.iter().all(|(name, table)| {
        before
            .tables
            .get(name)
            .is_some_and(|prior| Arc::ptr_eq(prior, table))
            && table
                .definition
                .foreign_keys
                .iter()
                .all(|foreign_key| !dropped.contains(foreign_key.referenced_table.as_str()))
    })
}

fn validate_database(
    state: &RelationalState,
    snapshot: u64,
    include_deferred: bool,
    constraint_modes: &ConstraintModes,
) -> Result<()> {
    let mut table_ids = HashSet::new();
    let mut table_incarnations = HashSet::new();
    let mut index_owners = HashMap::<u64, (u64, Vec<String>)>::new();
    for table in state.tables.values() {
        validate_definition(&table.definition)?;
        if !table_ids.insert(table.definition.table_id) {
            return Err(invalid(format!(
                "duplicate table catalog ID {}",
                table.definition.table_id
            )));
        }
        if table
            .definition
            .security_incarnation
            .is_some_and(|id| !table_incarnations.insert(id))
        {
            return Err(invalid("duplicate protected table incarnation"));
        }
        for (index_id, columns) in catalog_index_owners(&table.definition) {
            match index_owners.entry(index_id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert((table.definition.table_id, columns.to_vec()));
                }
                std::collections::hash_map::Entry::Occupied(entry)
                    if entry.get().0 != table.definition.table_id || entry.get().1 != columns =>
                {
                    return Err(invalid(format!(
                        "physical index ID {index_id} is reused by incompatible catalog objects"
                    )));
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
            }
        }
        let check_expressions = table
            .definition
            .check_constraints
            .iter()
            .map(|constraint| parse_check_expression(&constraint.expression))
            .collect::<Result<Vec<_>>>()?;
        let primary_indexes = table
            .definition
            .primary_key
            .iter()
            .map(|name| column_index(&table.definition, name))
            .collect::<Result<Vec<_>>>()?;
        for row in table.rows.visible_rows(snapshot) {
            let (_, row) = row?;
            validate_row(&table.definition, &row)?;
            if primary_indexes
                .iter()
                .any(|index| matches!(row[*index], RelationalValue::Null))
            {
                return Err(invalid("primary-key columns cannot be NULL"));
            }
            for (constraint, expression) in table
                .definition
                .check_constraints
                .iter()
                .zip(&check_expressions)
            {
                if check_constraint_result(expression, &table.definition, &row)? == Some(false) {
                    return Err(invalid(format!(
                        "check constraint {} violated",
                        constraint.name.as_deref().unwrap_or("<unnamed>")
                    )));
                }
            }
        }
        validate_unique_constraints(table)?;
        for foreign_key in &table.definition.foreign_keys {
            if !include_deferred && constraint_modes.is_deferred(foreign_key) {
                continue;
            }
            let referenced = state
                .tables
                .get(&foreign_key.referenced_table)
                .ok_or_else(|| {
                    invalid(format!(
                        "foreign key references missing table {}",
                        foreign_key.referenced_table
                    ))
                })?;
            let local_indexes = foreign_key
                .columns
                .iter()
                .map(|name| column_index(&table.definition, name))
                .collect::<Result<Vec<_>>>()?;
            let referenced_columns =
                resolved_referenced_columns(foreign_key, &referenced.definition)?;
            let remote_indexes = referenced_columns
                .iter()
                .map(|name| column_index(&referenced.definition, name))
                .collect::<Result<Vec<_>>>()?;
            if local_indexes
                .iter()
                .zip(&remote_indexes)
                .any(|(local, remote)| {
                    table.definition.columns[*local].data_type
                        != referenced.definition.columns[*remote].data_type
                })
            {
                return Err(invalid(format!(
                    "foreign key {} uses incompatible column types",
                    foreign_key.name.as_deref().unwrap_or("<unnamed>")
                )));
            }
            let referenced_is_unique = referenced_key_matches(
                &referenced.definition,
                &referenced_columns,
                foreign_key.referenced_key_kind,
                foreign_key.referenced_key_name.as_deref(),
            );
            if !referenced_is_unique {
                return Err(invalid(format!(
                    "foreign key {} must reference a primary or unique key",
                    foreign_key.name.as_deref().unwrap_or("<unnamed>")
                )));
            }
            let remote_keys = referenced.indexes.get(&referenced_columns).ok_or_else(|| {
                invalid(format!(
                    "missing scalar index for referenced key {}",
                    referenced_columns.join(",")
                ))
            })?;
            for row in table.rows.visible_rows(snapshot) {
                let (_, row) = row?;
                let null_count = local_indexes
                    .iter()
                    .filter(|index| matches!(row[**index], RelationalValue::Null))
                    .count();
                if null_count > 0 {
                    if foreign_key.match_kind == ForeignKeyMatch::Full
                        && null_count != local_indexes.len()
                    {
                        return Err(invalid(format!(
                            "foreign key {} violates MATCH FULL null semantics",
                            foreign_key.name.as_deref().unwrap_or("<unnamed>")
                        )));
                    }
                    continue;
                }
                let values = local_indexes
                    .iter()
                    .map(|index| &row[*index])
                    .collect::<Vec<_>>();
                if remote_keys
                    .lookup(
                        &referenced.index_segments,
                        referenced.index_snapshot,
                        &values,
                    )?
                    .is_empty()
                {
                    return Err(invalid(format!(
                        "foreign key {} violated",
                        foreign_key.name.as_deref().unwrap_or("<unnamed>")
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_unique_constraints(table: &TableState) -> Result<()> {
    for (constraint_columns, constraint_name) in unique_constraint_specs(&table.definition) {
        let entries = table.indexes.get(&constraint_columns).ok_or_else(|| {
            invalid(format!(
                "missing scalar index for constraint {constraint_name}"
            ))
        })?;
        if entries.has_duplicates(&table.index_segments, table.index_snapshot)? {
            return Err(invalid(format!(
                "unique constraint {} violated",
                constraint_name
            )));
        }
    }
    Ok(())
}

fn validate_updated_unique_constraints(table: &TableState, rows: &[StoredRow]) -> Result<()> {
    for (constraint_columns, constraint_name) in unique_constraint_specs(&table.definition) {
        let entries = table.indexes.get(&constraint_columns).ok_or_else(|| {
            invalid(format!(
                "missing scalar index for constraint {constraint_name}"
            ))
        })?;
        let indexes = constraint_columns
            .iter()
            .map(|name| column_index(&table.definition, name))
            .collect::<Result<Vec<_>>>()?;
        for row in rows {
            let values = indexes
                .iter()
                .map(|index| &row.values[*index])
                .collect::<Vec<_>>();
            if entries.has_duplicate_key(&table.index_segments, table.index_snapshot, &values)? {
                return Err(invalid(format!(
                    "unique constraint {} violated",
                    constraint_name
                )));
            }
        }
    }
    Ok(())
}

fn unique_constraint_specs(definition: &TableDefinition) -> Vec<(Vec<String>, String)> {
    let mut constraints = definition
        .unique_constraints
        .iter()
        .map(|constraint| {
            (
                constraint.columns.clone(),
                constraint
                    .name
                    .clone()
                    .unwrap_or_else(|| "<unnamed>".to_string()),
            )
        })
        .collect::<Vec<_>>();
    if !definition.primary_key.is_empty() {
        constraints.push((definition.primary_key.clone(), "primary_key".to_string()));
    }
    constraints.extend(
        definition
            .indexes
            .iter()
            .filter(|index| index.unique)
            .map(|index| (index.columns.clone(), index.name.clone())),
    );
    constraints
}

fn validate_row(definition: &TableDefinition, row: &[RelationalValue]) -> Result<()> {
    if row.len() != definition.columns.len() {
        return Err(invalid("row width does not match table definition"));
    }
    for (column, value) in definition.columns.iter().zip(row) {
        if matches!(value, RelationalValue::Null) {
            if !column.nullable {
                return Err(invalid(format!("column {} cannot be NULL", column.name)));
            }
        } else {
            validate_value(&column.data_type, value)?;
        }
    }
    Ok(())
}

fn parse_check_expression(expression: &str) -> Result<Expr> {
    let dialect = PostgreSqlDialect {};
    let mut statements = Parser::parse_sql(&dialect, &format!("SELECT 1 WHERE {expression}"))
        .map_err(|error| invalid(format!("invalid CHECK expression: {error}")))?;
    let Some(Statement::Query(query)) = statements.pop() else {
        return Err(invalid("invalid CHECK expression"));
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Err(invalid("invalid CHECK expression"));
    };
    select
        .selection
        .clone()
        .ok_or_else(|| invalid("CHECK expression is empty"))
}

fn check_constraint_references_column(
    constraint: &CheckConstraintDefinition,
    column_name: &str,
) -> Result<bool> {
    Ok(expression_references_column(
        &parse_check_expression(&constraint.expression)?,
        column_name,
    ))
}

fn expression_references_column(expression: &Expr, column_name: &str) -> bool {
    match expression {
        Expr::Identifier(identifier) => normalize_ident(&identifier.value) == column_name,
        Expr::CompoundIdentifier(identifiers) => identifiers
            .last()
            .is_some_and(|identifier| normalize_ident(&identifier.value) == column_name),
        Expr::BinaryOp { left, right, .. } => {
            expression_references_column(left, column_name)
                || expression_references_column(right, column_name)
        }
        Expr::InList { expr, list, .. } => {
            expression_references_column(expr, column_name)
                || list
                    .iter()
                    .any(|value| expression_references_column(value, column_name))
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            expression_references_column(expr, column_name)
                || expression_references_column(low, column_name)
                || expression_references_column(high, column_name)
        }
        Expr::IsNull(expression)
        | Expr::IsNotNull(expression)
        | Expr::Nested(expression)
        | Expr::UnaryOp {
            expr: expression, ..
        } => expression_references_column(expression, column_name),
        _ => false,
    }
}

fn rename_column_list(columns: &mut [String], old_name: &str, new_name: &str) {
    for column in columns {
        if column == old_name {
            column.clear();
            column.push_str(new_name);
        }
    }
}

fn rename_check_column(expression: &str, old_name: &str, new_name: &str) -> Result<String> {
    let mut expression = parse_check_expression(expression)?;
    rename_expression_column(&mut expression, old_name, new_name);
    Ok(expression.to_string())
}

fn rename_check_table(expression: &str, old_name: &str, new_name: &str) -> Result<String> {
    let mut expression = parse_check_expression(expression)?;
    rename_expression_table(&mut expression, old_name, new_name);
    Ok(expression.to_string())
}

fn rename_expression_column(expression: &mut Expr, old_name: &str, new_name: &str) {
    match expression {
        Expr::Identifier(identifier) => {
            if normalize_ident(&identifier.value) == old_name {
                identifier.value = new_name.to_string();
            }
        }
        Expr::CompoundIdentifier(identifiers) => {
            if let Some(identifier) = identifiers.last_mut()
                && normalize_ident(&identifier.value) == old_name
            {
                identifier.value = new_name.to_string();
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            rename_expression_column(left, old_name, new_name);
            rename_expression_column(right, old_name, new_name);
        }
        Expr::InList { expr, list, .. } => {
            rename_expression_column(expr, old_name, new_name);
            for value in list {
                rename_expression_column(value, old_name, new_name);
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            rename_expression_column(expr, old_name, new_name);
            rename_expression_column(low, old_name, new_name);
            rename_expression_column(high, old_name, new_name);
        }
        Expr::IsNull(expression)
        | Expr::IsNotNull(expression)
        | Expr::Nested(expression)
        | Expr::UnaryOp {
            expr: expression, ..
        } => rename_expression_column(expression, old_name, new_name),
        _ => {}
    }
}

fn rename_expression_table(expression: &mut Expr, old_name: &str, new_name: &str) {
    match expression {
        Expr::CompoundIdentifier(identifiers) => {
            let qualifier_count = identifiers.len().saturating_sub(1);
            for identifier in identifiers.iter_mut().take(qualifier_count) {
                if normalize_ident(&identifier.value) == old_name {
                    identifier.value = new_name.to_string();
                }
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            rename_expression_table(left, old_name, new_name);
            rename_expression_table(right, old_name, new_name);
        }
        Expr::InList { expr, list, .. } => {
            rename_expression_table(expr, old_name, new_name);
            for value in list {
                rename_expression_table(value, old_name, new_name);
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            rename_expression_table(expr, old_name, new_name);
            rename_expression_table(low, old_name, new_name);
            rename_expression_table(high, old_name, new_name);
        }
        Expr::IsNull(expression)
        | Expr::IsNotNull(expression)
        | Expr::Nested(expression)
        | Expr::UnaryOp {
            expr: expression, ..
        } => rename_expression_table(expression, old_name, new_name),
        _ => {}
    }
}

/// SQL CHECK fails only on FALSE; TRUE and UNKNOWN both pass. The Option
/// represents SQL's three-valued boolean result.
fn check_constraint_result(
    expression: &Expr,
    definition: &TableDefinition,
    row: &[RelationalValue],
) -> Result<Option<bool>> {
    match expression {
        Expr::Value(value) => match &value.value {
            Value::Boolean(value) => Ok(Some(*value)),
            Value::Null => Ok(None),
            _ => Err(unsupported("CHECK scalar must be boolean")),
        },
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::And => {
            let left = check_constraint_result(left, definition, row)?;
            let right = check_constraint_result(right, definition, row)?;
            Ok(match (left, right) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            })
        }
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::Or => {
            let left = check_constraint_result(left, definition, row)?;
            let right = check_constraint_result(right, definition, row)?;
            Ok(match (left, right) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            })
        }
        Expr::InList {
            expr,
            list,
            negated,
        } => {
            let index = column_index(definition, &expression_column_name(expr)?)?;
            let mut cursor = 0;
            let values = list
                .iter()
                .map(|value| {
                    expression_value(
                        value,
                        &definition.columns[index].data_type,
                        &[],
                        &mut cursor,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(in_list_predicate(&row[index], &values, *negated))
        }
        Expr::Between {
            expr,
            negated,
            low,
            high,
        } => {
            let index = column_index(definition, &expression_column_name(expr)?)?;
            let mut cursor = 0;
            let low =
                expression_value(low, &definition.columns[index].data_type, &[], &mut cursor)?;
            let high =
                expression_value(high, &definition.columns[index].data_type, &[], &mut cursor)?;
            Ok(between_predicate(&row[index], &low, &high, *negated))
        }
        Expr::BinaryOp { left, op, right } => {
            let left_column = expression_column_name(left)
                .ok()
                .map(|name| column_index(definition, &name))
                .transpose()?;
            let right_column = expression_column_name(right)
                .ok()
                .map(|name| column_index(definition, &name))
                .transpose()?;
            let mut cursor = 0;
            let (left_value, right_value, operator) = match (left_column, right_column) {
                (Some(left_index), Some(right_index)) => (
                    row[left_index].clone(),
                    row[right_index].clone(),
                    op.clone(),
                ),
                (Some(index), None) => (
                    row[index].clone(),
                    expression_value(
                        right,
                        &definition.columns[index].data_type,
                        &[],
                        &mut cursor,
                    )?,
                    op.clone(),
                ),
                (None, Some(index)) => (
                    row[index].clone(),
                    expression_value(left, &definition.columns[index].data_type, &[], &mut cursor)?,
                    reverse_operator(op),
                ),
                (None, None) => {
                    return Err(unsupported(
                        "CHECK comparison must reference at least one column",
                    ));
                }
            };
            if matches!(left_value, RelationalValue::Null)
                || matches!(right_value, RelationalValue::Null)
            {
                return Ok(None);
            }
            Ok(Some(compare_predicate(
                &left_value,
                &right_value,
                &operator,
            )?))
        }
        Expr::IsNull(expression) => {
            let index = column_index(definition, &expression_column_name(expression)?)?;
            Ok(Some(matches!(row[index], RelationalValue::Null)))
        }
        Expr::IsNotNull(expression) => {
            let index = column_index(definition, &expression_column_name(expression)?)?;
            Ok(Some(!matches!(row[index], RelationalValue::Null)))
        }
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            let index = column_index(definition, &expression_column_name(expression)?)?;
            match &row[index] {
                RelationalValue::Boolean(value) => Ok(Some(*value)),
                RelationalValue::Null => Ok(None),
                _ => Err(invalid("bare CHECK column must be BOOLEAN")),
            }
        }
        Expr::Nested(expression) => check_constraint_result(expression, definition, row),
        Expr::UnaryOp { op, expr } if op.to_string().eq_ignore_ascii_case("not") => {
            Ok(check_constraint_result(expr, definition, row)?.map(|value| !value))
        }
        _ => Err(unsupported("CHECK expression is outside relational v1")),
    }
}

fn validate_value(data_type: &RelationalType, value: &RelationalValue) -> Result<()> {
    if matches!(value, RelationalValue::Null) {
        return Ok(());
    }
    let valid = matches!(
        (data_type, value),
        (RelationalType::Boolean, RelationalValue::Boolean(_))
            | (RelationalType::BigInt, RelationalValue::Integer(_))
            | (RelationalType::Float, RelationalValue::Float(_))
            | (RelationalType::Text, RelationalValue::Text(_))
            | (RelationalType::Bytea, RelationalValue::Bytes(_))
            | (RelationalType::Uuid, RelationalValue::Uuid(_))
            | (RelationalType::Jsonb, RelationalValue::Json(_))
    );
    if valid {
        if let RelationalValue::Float(value) = value
            && !value.is_finite()
        {
            return Err(invalid("floating-point values must be finite"));
        }
        return Ok(());
    }
    match (data_type, value) {
        (RelationalType::SmallInt, RelationalValue::Integer(value)) => i16::try_from(*value)
            .map(|_| ())
            .map_err(|_| invalid("SMALLINT value is out of range")),
        (RelationalType::Integer, RelationalValue::Integer(value)) => i32::try_from(*value)
            .map(|_| ())
            .map_err(|_| invalid("INTEGER value is out of range")),
        (RelationalType::Real, RelationalValue::Float(value)) => {
            if value.is_finite() && (*value as f32).is_finite() {
                Ok(())
            } else {
                Err(invalid("REAL value must be finite and in range"))
            }
        }
        (RelationalType::Varchar { length }, RelationalValue::Text(value)) => {
            if value.chars().count() <= *length {
                Ok(())
            } else {
                Err(invalid(format!("VARCHAR({length}) value is too long")))
            }
        }
        (RelationalType::Date, RelationalValue::Date(value)) => {
            chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .map(|_| ())
                .map_err(|_| invalid("date must use YYYY-MM-DD"))
        }
        (RelationalType::Decimal { precision, scale }, RelationalValue::Decimal(value)) => {
            validate_decimal(value, *precision, *scale)
        }
        (RelationalType::TimestampUtc, RelationalValue::TimestampUtc(value)) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| invalid("timestamp must be valid RFC 3339"))?;
            if parsed.offset().local_minus_utc() != 0 {
                return Err(invalid("timestamp must use UTC offset Z or +00:00"));
            }
            Ok(())
        }
        (RelationalType::Vector { dimension }, RelationalValue::Vector(vector)) => {
            if vector.len() != *dimension || vector.iter().any(|value| !value.is_finite()) {
                Err(invalid(format!(
                    "vector requires {dimension} finite dimensions"
                )))
            } else {
                Ok(())
            }
        }
        (RelationalType::RecordRef { namespace }, RelationalValue::RecordRef(reference)) => {
            if reference.namespace != *namespace || reference.id.is_empty() {
                Err(invalid(format!(
                    "record reference requires namespace {namespace} and a non-empty id"
                )))
            } else {
                Ok(())
            }
        }
        _ => Err(invalid(format!("value does not match type {data_type:?}"))),
    }
}

fn analyze_parsed_statement(statement: &Statement) -> Result<SqlStatementAnalysis> {
    let declares_vector = matches!(statement, Statement::CreateTable(create) if create
        .columns
        .iter()
        .any(|column| matches!(relational_type(&column.data_type), Ok(RelationalType::Vector { .. }))));
    let indexes = match statement {
        Statement::CreateIndex(create) => create
            .name
            .as_ref()
            .map(normalize_name)
            .into_iter()
            .collect(),
        Statement::Drop {
            object_type: ObjectType::Index,
            names,
            ..
        } => names.iter().map(normalize_name).collect(),
        _ => Vec::new(),
    };
    let (class, kind, mut tables) = match statement {
        Statement::Query(query) => (
            SqlStatementClass::Read,
            SqlStatementKind::Select,
            query_base_tables(query, &HashSet::new())?,
        ),
        Statement::Explain {
            statement, analyze, ..
        } => {
            if *analyze {
                return Err(unsupported("EXPLAIN ANALYZE is outside relational v1"));
            }
            let inner = analyze_parsed_statement(statement)?;
            (
                SqlStatementClass::Read,
                SqlStatementKind::Explain,
                inner.tables,
            )
        }
        Statement::Insert(insert) => {
            let table = match &insert.table {
                TableObject::TableName(name) => normalize_name(name),
                _ => {
                    return Err(unsupported(
                        "INSERT table expression is outside relational v1",
                    ));
                }
            };
            (
                SqlStatementClass::Write,
                SqlStatementKind::Insert,
                vec![table],
            )
        }
        Statement::Update(update) => (
            SqlStatementClass::Write,
            SqlStatementKind::Update,
            vec![table_factor_name(&update.table.relation)?],
        ),
        Statement::Delete(delete) => {
            let tables = match &delete.from {
                FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => tables
                    .iter()
                    .map(|table| table_factor_name(&table.relation))
                    .collect::<Result<Vec<_>>>()?,
            };
            (SqlStatementClass::Write, SqlStatementKind::Delete, tables)
        }
        Statement::CreateTable(create) => (
            SqlStatementClass::Admin,
            SqlStatementKind::CreateTable,
            vec![normalize_name(&create.name)],
        ),
        Statement::AlterTable(alter) => {
            let mut tables = vec![normalize_name(&alter.name)];
            for operation in &alter.operations {
                if let AlterTableOperation::RenameTable { table_name } = operation {
                    let name = match table_name {
                        RenameTableNameKind::As(name) | RenameTableNameKind::To(name) => name,
                    };
                    tables.push(normalize_name(name));
                }
            }
            (
                SqlStatementClass::Admin,
                SqlStatementKind::AlterTable,
                tables,
            )
        }
        Statement::CreateIndex(create) => (
            SqlStatementClass::Admin,
            SqlStatementKind::CreateIndex,
            vec![normalize_name(&create.table_name)],
        ),
        Statement::Drop {
            object_type: ObjectType::Index,
            ..
        } => (
            SqlStatementClass::Admin,
            SqlStatementKind::DropIndex,
            Vec::new(),
        ),
        Statement::Drop {
            object_type: ObjectType::Table,
            names,
            ..
        } => (
            SqlStatementClass::Admin,
            SqlStatementKind::DropTable,
            names.iter().map(normalize_name).collect(),
        ),
        _ => {
            return Err(unsupported(
                "SQL statement is outside the native relational v1 subset",
            ));
        }
    };
    tables.sort();
    tables.dedup();
    Ok(SqlStatementAnalysis {
        class,
        kind,
        tables,
        indexes,
        declares_vector,
    })
}

fn query_base_tables(query: &Query, inherited_ctes: &HashSet<String>) -> Result<Vec<String>> {
    let mut visible_ctes = inherited_ctes.clone();
    let mut tables = Vec::new();
    if let Some(with) = &query.with {
        if with.recursive {
            return Err(unsupported("recursive CTE is outside relational v1"));
        }
        for cte in &with.cte_tables {
            tables.extend(query_base_tables(&cte.query, &visible_ctes)?);
            visible_ctes.insert(normalize_ident(&cte.alias.name.value));
        }
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Err(unsupported("set operations are outside relational v1"));
    };
    for from in &select.from {
        let name = table_factor_name(&from.relation)?;
        if !visible_ctes.contains(&name) {
            tables.push(name);
        }
        for join in &from.joins {
            let name = table_factor_name(&join.relation)?;
            if !visible_ctes.contains(&name) {
                tables.push(name);
            }
        }
    }
    for item in &select.projection {
        if let SelectItem::UnnamedExpr(expression)
        | SelectItem::ExprWithAlias {
            expr: expression, ..
        } = item
        {
            tables.extend(expression_base_tables(expression, &visible_ctes)?);
        }
    }
    if let Some(selection) = &select.selection {
        tables.extend(expression_base_tables(selection, &visible_ctes)?);
    }
    if let Some(having) = &select.having {
        tables.extend(expression_base_tables(having, &visible_ctes)?);
    }
    if let GroupByExpr::Expressions(expressions, _) = &select.group_by {
        for expression in expressions {
            tables.extend(expression_base_tables(expression, &visible_ctes)?);
        }
    }
    if let Some(order_by) = &query.order_by
        && let OrderByKind::Expressions(expressions) = &order_by.kind
    {
        for expression in expressions {
            tables.extend(expression_base_tables(&expression.expr, &visible_ctes)?);
        }
    }
    Ok(tables)
}

fn expression_base_tables(
    expression: &Expr,
    visible_ctes: &HashSet<String>,
) -> Result<Vec<String>> {
    let mut tables = Vec::new();
    match expression {
        Expr::Subquery(query)
        | Expr::Exists {
            subquery: query, ..
        } => {
            tables.extend(query_base_tables(query, visible_ctes)?);
        }
        Expr::InSubquery { expr, subquery, .. } => {
            tables.extend(expression_base_tables(expr, visible_ctes)?);
            tables.extend(query_base_tables(subquery, visible_ctes)?);
        }
        Expr::BinaryOp { left, right, .. } => {
            tables.extend(expression_base_tables(left, visible_ctes)?);
            tables.extend(expression_base_tables(right, visible_ctes)?);
        }
        Expr::UnaryOp { expr, .. }
        | Expr::Nested(expr)
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr) => {
            tables.extend(expression_base_tables(expr, visible_ctes)?);
        }
        Expr::InList { expr, list, .. } => {
            tables.extend(expression_base_tables(expr, visible_ctes)?);
            for item in list {
                tables.extend(expression_base_tables(item, visible_ctes)?);
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            tables.extend(expression_base_tables(expr, visible_ctes)?);
            tables.extend(expression_base_tables(low, visible_ctes)?);
            tables.extend(expression_base_tables(high, visible_ctes)?);
        }
        Expr::Cast { expr, .. } => {
            tables.extend(expression_base_tables(expr, visible_ctes)?);
        }
        _ => {}
    }
    Ok(tables)
}

fn validate_decimal(value: &str, precision: u8, scale: u8) -> Result<()> {
    let unsigned = value.strip_prefix(['-', '+']).unwrap_or(value);
    let mut parts = unsigned.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > scale as usize
        || whole.trim_start_matches('0').len() + fraction.len() > precision as usize
    {
        return Err(invalid(format!(
            "decimal {value} exceeds decimal({precision},{scale})"
        )));
    }
    Ok(())
}

fn decimal_parts(value: &str) -> Option<(bool, String, String)> {
    let negative = value.starts_with('-');
    let unsigned = value.strip_prefix(['-', '+']).unwrap_or(value);
    let mut split = unsigned.split('.');
    let whole = split.next()?;
    let fraction = split.next().unwrap_or_default();
    if split.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let fraction = fraction.trim_end_matches('0');
    let zero = whole == "0" && fraction.is_empty();
    Some((negative && !zero, whole.to_string(), fraction.to_string()))
}

fn compare_decimal(left: &str, right: &str) -> Option<Ordering> {
    let (left_negative, left_whole, mut left_fraction) = decimal_parts(left)?;
    let (right_negative, right_whole, mut right_fraction) = decimal_parts(right)?;
    if left_negative != right_negative {
        return Some(if left_negative {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let width = left_fraction.len().max(right_fraction.len());
    left_fraction.extend(std::iter::repeat_n('0', width - left_fraction.len()));
    right_fraction.extend(std::iter::repeat_n('0', width - right_fraction.len()));
    let magnitude = left_whole
        .len()
        .cmp(&right_whole.len())
        .then_with(|| left_whole.cmp(&right_whole))
        .then_with(|| left_fraction.cmp(&right_fraction));
    Some(if left_negative {
        magnitude.reverse()
    } else {
        magnitude
    })
}

pub(crate) fn validate_relational_prepare(
    prepare: &crate::transaction_journal::TransactionPrepare,
    batch: &RelationalBatch,
) -> Result<()> {
    replay::validate_prepare(prepare, batch)
}

pub(crate) fn relational_projection_fingerprint(batch: &RelationalBatch) -> Result<[u8; 32]> {
    replay::fingerprint(batch)
}

fn capture_relational_checkpoint(
    state: &RelationalState,
    wal_watermark: u64,
) -> Result<CapturedRelationalCheckpoint> {
    checkpoint::metadata::capture(state, wal_watermark)
}

fn checkpoint_row_references(table: &RelationalCheckpointTable) -> &[RelationalSegmentReference] {
    if table.row_segments.is_empty() {
        table.row_segment.as_slice()
    } else {
        &table.row_segments
    }
}

fn checkpoint_index_references(table: &RelationalCheckpointTable) -> &[RelationalSegmentReference] {
    if table.index_segments.is_empty() {
        table.index_segment.as_slice()
    } else {
        &table.index_segments
    }
}

fn segment_reference(file_name: String, metadata: &SegmentMetadata) -> RelationalSegmentReference {
    RelationalSegmentReference {
        file_name,
        kind: metadata.kind,
        sequence: metadata.sequence,
        record_count: metadata.record_count,
        min_key: metadata.min_key.clone(),
        max_key: metadata.max_key.clone(),
    }
}

fn row_segment_key(
    definition: &TableDefinition,
    row_id: u64,
    version: &RowVersion,
) -> Result<Vec<u8>> {
    if definition.primary_key.is_empty() {
        return encode_row_key_v1(
            definition.table_id,
            RowIdentityKey::Hidden(row_id),
            version.begin,
        );
    }
    let indexes = definition
        .primary_key
        .iter()
        .map(|name| column_index(definition, name))
        .collect::<Result<Vec<_>>>()?;
    let columns = indexes
        .iter()
        .map(|index| {
            (
                &definition.columns[*index].data_type,
                &version.values[*index],
            )
        })
        .collect::<Vec<_>>();
    encode_row_key_v1(
        definition.table_id,
        RowIdentityKey::Primary(&columns),
        version.begin,
    )
}

fn row_segment_key_admitted(
    definition: &TableDefinition,
    row_id: u64,
    version: &RowVersion,
) -> Result<segment::RecordBytes> {
    if definition.primary_key.is_empty() {
        return key_encoding::encode_row_key_v1_admitted(
            definition.table_id,
            RowIdentityKey::Hidden(row_id),
            version.begin,
        );
    }
    let mut charge = memory::Charge::storage();
    let bytes = definition
        .primary_key
        .len()
        .checked_mul(std::mem::size_of::<(&RelationalType, &RelationalValue)>())
        .and_then(|n| n.checked_add(64))
        .ok_or_else(sql_overloaded)?;
    charge.prepare(bytes as u64)?;
    let mut columns = Vec::new();
    columns
        .try_reserve_exact(definition.primary_key.len())
        .map_err(|_| sql_overloaded())?;
    for name in &definition.primary_key {
        let index = column_index(definition, name)?;
        columns.push((&definition.columns[index].data_type, &version.values[index]));
    }
    charge.prepare(
        (columns.capacity() * std::mem::size_of::<(&RelationalType, &RelationalValue)>() + 64)
            as u64,
    )?;
    let key = key_encoding::encode_row_key_v1_admitted(
        definition.table_id,
        RowIdentityKey::Primary(&columns),
        version.begin,
    )?;
    drop(columns);
    drop(charge);
    Ok(key)
}

#[cfg(test)]
fn row_segment_records(table: &TableState) -> Result<Vec<SegmentRecord>> {
    let mut records = Vec::new();
    for entry in table.rows.iter() {
        let (row_id, versions) = entry?;
        for version in versions.iter() {
            records.push(SegmentRecord {
                key: (row_segment_key(&table.definition, row_id, version)?).into(),
                value: (serde_json::to_vec(&PersistedRowVersion {
                    row_id,
                    version: version.clone(),
                })?)
                .into(),
            });
        }
    }
    records.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(records)
}

#[cfg(test)]
fn index_segment_records(table: &TableState) -> Result<Vec<SegmentRecord>> {
    let mut physical = BTreeMap::<u64, Vec<String>>::new();
    for (index_id, columns) in catalog_index_owners(&table.definition) {
        if let Some(existing) = physical.insert(index_id, columns.to_vec())
            && existing != columns
        {
            return Err(invalid(format!(
                "physical index ID {index_id} has conflicting columns"
            )));
        }
    }
    let mut records = Vec::new();
    for (index_id, columns) in physical {
        let indexes = columns
            .iter()
            .map(|name| column_index(&table.definition, name))
            .collect::<Result<Vec<_>>>()?;
        for entry in table.rows.iter() {
            let (row_id, versions) = entry?;
            for version in versions.iter() {
                if indexes
                    .iter()
                    .any(|index| matches!(version.values[*index], RelationalValue::Null))
                {
                    continue;
                }
                let values = indexes
                    .iter()
                    .map(|index| {
                        (
                            &table.definition.columns[*index].data_type,
                            &version.values[*index],
                        )
                    })
                    .collect::<Vec<_>>();
                records.push(SegmentRecord {
                    key: (encode_index_key_v1(index_id, &values, row_id, version.begin)?).into(),
                    value: (serde_json::to_vec(&PersistedIndexVersion {
                        row_id,
                        begin: version.begin,
                        end: version.end,
                    })?)
                    .into(),
                });
            }
        }
    }
    records.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(records)
}

fn validate_segment_reference(
    reference: &RelationalSegmentReference,
    metadata: &SegmentMetadata,
) -> Result<()> {
    if reference.kind != metadata.kind
        || reference.sequence != metadata.sequence
        || reference.record_count != metadata.record_count
        || reference.min_key != metadata.min_key
        || reference.max_key != metadata.max_key
    {
        return Err(relational_checkpoint_corruption(
            Path::new(&reference.file_name),
            "segment reference does not match immutable metadata",
        ));
    }
    Ok(())
}

fn checkpoint_segment_names(checkpoint: &RelationalCheckpoint) -> HashSet<String> {
    checkpoint
        .tables
        .iter()
        .flat_map(|table| {
            checkpoint_row_references(table)
                .iter()
                .chain(checkpoint_index_references(table))
        })
        .map(|reference| reference.file_name.clone())
        .collect()
}

fn recovered_index_segment_names(state: &RelationalState) -> HashSet<String> {
    state
        .tables
        .values()
        .flat_map(|table| table.index_segments.iter())
        .map(|backing| backing.file_name.clone())
        .collect()
}

fn prepare_checkpoint_backings(
    checkpoint: &RelationalCheckpoint,
    directory: &Path,
) -> Result<Vec<CheckpointTableBackings>> {
    checkpoint
        .tables
        .iter()
        .map(|table| prepare_checkpoint_table_backings(table, checkpoint.sequence, directory))
        .collect()
}

fn prepare_checkpoint_table_backings(
    table: &RelationalCheckpointTable,
    sequence: u64,
    directory: &Path,
) -> Result<CheckpointTableBackings> {
    let rows = rows::restore_rows(table, sequence, directory)?;
    let references = checkpoint_index_references(table);
    let mut projection = TableState::with_schema(
        Schema::copy(&table.definition)?,
        Arc::new(directory.to_path_buf()),
    )?;
    projection.rows = rows.clone();
    projection.next_row_id = table.next_row_id;
    let indexes = if references.is_empty() {
        projection.rebuild_indexes(sequence)?;
        projection.index_segments
    } else {
        indexes::validate_projection(&projection, directory, references, sequence)?;
        references
            .iter()
            .map(|reference| TableSegmentBacking::open(directory, reference))
            .collect::<Result<Vec<_>>>()?
    };
    Ok(CheckpointTableBackings {
        rows,
        indexes,
        scalar_indexes: projection.indexes,
    })
}

fn prepare_live_checkpoint_backings(
    persisted: &RelationalCheckpoint,
    captured: &CapturedRelationalCheckpoint,
    previous: Option<&RelationalCheckpoint>,
    directory: &Path,
) -> Result<Vec<CheckpointTableBackings>> {
    if persisted.tables.len() != captured.tables.len() {
        return Err(invalid("captured checkpoint table count changed"));
    }
    persisted
        .tables
        .iter()
        .zip(&captured.tables)
        .map(|(table, source)| {
            let old = previous.and_then(|checkpoint| {
                checkpoint
                    .tables
                    .iter()
                    .find(|entry| entry.definition.table_id == source.definition.table_id)
            });
            if &table.definition == source.definition.as_ref()
                && table.next_row_id == source.next_row_id
                && checkpoint::reuses_generation(source, old)
                && old.is_some_and(|old| {
                    checkpoint_row_references(table) == checkpoint_row_references(old)
                        && checkpoint_index_references(table) == checkpoint_index_references(old)
                })
            {
                return Ok(CheckpointTableBackings {
                    rows: source.rows.clone(),
                    indexes: source.index_segments.clone(),
                    scalar_indexes: source.indexes.clone(),
                });
            }
            if let (Some(old), Some(previous)) = (old, previous)
                && checkpoint::validate_appended_generation(
                    source,
                    table,
                    old,
                    previous.sequence,
                    directory,
                    persisted.sequence,
                )?
            {
                let rows = rows::restore_rows(table, persisted.sequence, directory)?;
                let indexes = checkpoint_index_references(table)
                    .iter()
                    .map(|reference| TableSegmentBacking::open(directory, reference))
                    .collect::<Result<Vec<_>>>()?;
                return Ok(CheckpointTableBackings {
                    rows,
                    indexes,
                    scalar_indexes: IndexCatalog::new(&source.definition)?,
                });
            }
            prepare_checkpoint_table_backings(table, persisted.sequence, directory)
        })
        .collect()
}

fn install_checkpoint_backings(
    state: &mut RelationalState,
    checkpoint: &RelationalCheckpoint,
    backings: Vec<CheckpointTableBackings>,
    permit: catalog::WritePermit,
) -> bool {
    let Some(mut tables) = state.tables.begin_prepared(permit) else {
        metrics::counter!("chirondb_relational_checkpoint_install_deferred_total").increment(1);
        return false;
    };
    for (persisted, backings) in checkpoint.tables.iter().zip(backings) {
        let Some(table) = tables.get_mut(&persisted.definition.name) else {
            continue;
        };
        if table.definition.table_id != persisted.definition.table_id {
            continue;
        }
        if table.definition.as_ref() != &persisted.definition
            || !table.rows.can_install_base(checkpoint.sequence)
        {
            continue;
        }
        let table = Arc::make_mut(table);
        table.rows.install_base(backings.rows, checkpoint.sequence);
        table.index_segments = backings.indexes;
        table.index_snapshot = checkpoint.sequence;
        // Prepared before manifest publication: installation does not fork
        // an index catalog or allocate new index descriptors under pressure.
        table.indexes = backings.scalar_indexes;
    }
    state.tables = tables.finish();
    true
}

fn cleanup_unreferenced_checkpoint_segments(
    segment_dir: &Path,
    current: &RelationalCheckpoint,
    retained_backings: &HashSet<String>,
) {
    let mut retained = checkpoint_segment_names(current);
    retained.extend(retained_backings.iter().cloned());
    let Ok(entries) = fs::read_dir(segment_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let owned = (file_name.starts_with("row-") || file_name.starts_with("index-"))
            && file_name.ends_with(".rseg");
        if owned
            && !retained.contains(&file_name)
            && let Err(error) = remove_segment_if_exists(&entry.path())
        {
            tracing::warn!(file = %file_name, error = %error, "failed to reclaim relational segment");
        }
    }
}

fn write_relational_checkpoint(path: &Path, checkpoint: &RelationalCheckpoint) -> Result<()> {
    checkpoint::encode::write(path, checkpoint)
}

fn read_relational_checkpoint(path: &Path) -> Result<Option<RelationalCheckpoint>> {
    if !path.exists() {
        return Ok(None);
    }
    let file = PersistentFile::open(path)?;
    if file.len() < RELATIONAL_CHECKPOINT_HEADER_LEN {
        return Err(relational_checkpoint_corruption(
            path,
            "checkpoint shorter than header",
        ));
    }
    let header = file.read_range_admitted(0..RELATIONAL_CHECKPOINT_HEADER_LEN)?;
    if &header[..8] != RELATIONAL_CHECKPOINT_MAGIC {
        return Err(relational_checkpoint_corruption(
            path,
            "checkpoint magic or format version is unsupported",
        ));
    }
    let payload_len = usize::try_from(u64::from_le_bytes(
        header[8..16]
            .try_into()
            .expect("relational checkpoint payload length"),
    ))
    .map_err(|_| relational_checkpoint_corruption(path, "payload length exceeds usize"))?;
    if RELATIONAL_CHECKPOINT_HEADER_LEN.checked_add(payload_len) != Some(file.len()) {
        return Err(relational_checkpoint_corruption(
            path,
            "checkpoint payload length mismatch",
        ));
    }
    let expected_crc = u32::from_le_bytes(
        header[16..20]
            .try_into()
            .expect("relational checkpoint crc"),
    );
    let actual_crc = file.crc32(RELATIONAL_CHECKPOINT_HEADER_LEN..file.len())?;
    if actual_crc != expected_crc {
        return Err(relational_checkpoint_corruption(
            path,
            "checkpoint CRC mismatch",
        ));
    }
    let checkpoint = checkpoint::decode::read(
        file.reader_at(RELATIONAL_CHECKPOINT_HEADER_LEN)?,
        payload_len,
    )?;
    if checkpoint.version != RELATIONAL_CHECKPOINT_LEGACY_VERSION
        && checkpoint.version != RELATIONAL_CHECKPOINT_RUNS_VERSION
        && checkpoint.version != RELATIONAL_CHECKPOINT_VERSION
    {
        return Err(relational_checkpoint_corruption(
            path,
            format!(
                "unsupported relational checkpoint version {}; expected {}, {} or {}",
                checkpoint.version,
                RELATIONAL_CHECKPOINT_LEGACY_VERSION,
                RELATIONAL_CHECKPOINT_RUNS_VERSION,
                RELATIONAL_CHECKPOINT_VERSION
            ),
        ));
    }
    for table in &checkpoint.tables {
        let legacy_fields_present = table.row_segment.is_some() || table.index_segment.is_some();
        let run_fields_present = !table.row_segments.is_empty() || !table.index_segments.is_empty();
        if legacy_fields_present && run_fields_present {
            return Err(relational_checkpoint_corruption(
                path,
                format!(
                    "table {} mixes legacy and multi-run segment references",
                    table.definition.name
                ),
            ));
        }
        if checkpoint.version == RELATIONAL_CHECKPOINT_LEGACY_VERSION && run_fields_present {
            return Err(relational_checkpoint_corruption(
                path,
                format!(
                    "legacy checkpoint table {} contains multi-run references",
                    table.definition.name
                ),
            ));
        }
        if checkpoint.version == RELATIONAL_CHECKPOINT_LEGACY_VERSION
            && table.row_segment.is_some() != table.index_segment.is_some()
        {
            return Err(relational_checkpoint_corruption(
                path,
                format!(
                    "legacy checkpoint table {} has an incomplete segment pair",
                    table.definition.name
                ),
            ));
        }
        if checkpoint.version >= RELATIONAL_CHECKPOINT_RUNS_VERSION
            && (legacy_fields_present
                || !table.rows.is_empty()
                || table.row_segments.is_empty()
                || table.index_segments.is_empty()
                || table.row_segments.len() > RELATIONAL_MAX_RUNS_PER_TABLE
                || table.index_segments.len() > RELATIONAL_MAX_RUNS_PER_TABLE)
        {
            return Err(relational_checkpoint_corruption(
                path,
                format!(
                    "multi-run checkpoint table {} has an invalid run shape",
                    table.definition.name
                ),
            ));
        }
    }
    Ok(Some(checkpoint))
}

fn restore_relational_checkpoint(
    checkpoint: RelationalCheckpoint,
    segment_dir: &Path,
) -> Result<(RelationalState, u64)> {
    let checkpoint_sequence = checkpoint.sequence;
    let mut state = RelationalState {
        directory: Arc::new(segment_dir.to_path_buf()),
        sequence: checkpoint_sequence,
        next_catalog_id: checkpoint.next_catalog_id,
        tables: catalog::Catalog::empty()?,
    };
    for persisted in checkpoint.tables {
        if state.tables.contains_key(&persisted.definition.name) {
            return Err(invalid(format!(
                "relational checkpoint repeats table {}",
                persisted.definition.name
            )));
        }
        let restored_rows = rows::restore_rows(&persisted, checkpoint_sequence, segment_dir)?;
        if persisted.rows.values().flatten().any(|version| {
            version.begin == 0
                || version.begin > checkpoint_sequence
                || version
                    .end
                    .is_some_and(|end| end <= version.begin || end > checkpoint_sequence)
        }) {
            return Err(invalid(format!(
                "relational checkpoint contains an invalid MVCC interval for table {}",
                persisted.definition.name
            )));
        }
        let maximum_row_id = persisted.rows.keys().next_back().copied().unwrap_or(0);
        if persisted.next_row_id <= maximum_row_id {
            return Err(invalid(format!(
                "relational checkpoint row-id frontier is stale for table {}",
                persisted.definition.name
            )));
        }
        if persisted.definition.table_id == 0
            || catalog_index_owners(&persisted.definition).any(|(index_id, _)| index_id == 0)
            || catalog_id_frontier(&persisted.definition) > checkpoint.next_catalog_id
        {
            return Err(invalid(format!(
                "relational checkpoint has invalid catalog IDs for table {}",
                persisted.definition.name
            )));
        }
        // Borrow only reference fields so the definition can move into runtime state.
        let index_references = if persisted.index_segments.is_empty() {
            persisted.index_segment.as_slice()
        } else {
            &persisted.index_segments
        };
        let mut table = TableState::empty(persisted.definition, Arc::clone(&state.directory))?;
        table.rows = restored_rows;
        table.next_row_id = persisted.next_row_id;
        if !index_references.is_empty() {
            if index_references
                .iter()
                .any(|reference| reference.sequence > checkpoint_sequence)
            {
                return Err(relational_checkpoint_corruption(
                    segment_dir,
                    "index run sequence is newer than the checkpoint",
                ));
            }
            indexes::validate_projection(
                &table,
                segment_dir,
                index_references,
                checkpoint_sequence,
            )?;
            table.index_snapshot = checkpoint_sequence;
            table.index_segments = index_references
                .iter()
                .map(|reference| TableSegmentBacking::open(segment_dir, reference))
                .collect::<Result<Vec<_>>>()?;
        } else {
            // Legacy inline checkpoints have no persisted scalar projection.
            table.rebuild_indexes(checkpoint_sequence)?;
        }
        let table = Arc::new(table);
        state.tables.insert(&table.definition.name, table.clone())?;
    }
    validate_database(
        &state,
        checkpoint_sequence,
        true,
        &ConstraintModes::default(),
    )?;
    Ok((state, checkpoint.wal_watermark))
}

fn checkpoint_segment_path(
    segment_dir: &Path,
    reference: &RelationalSegmentReference,
) -> Result<PathBuf> {
    let path = Path::new(&reference.file_name);
    if path.components().count() != 1 || reference.file_name.is_empty() {
        return Err(relational_checkpoint_corruption(
            path,
            "segment reference must be one local file name",
        ));
    }
    Ok(segment_dir.join(path))
}

fn relational_checkpoint_corruption(path: &Path, message: impl Into<String>) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.into(),
    }
}

fn rewrite_table_state(
    state: &mut RelationalState,
    definition: TableDefinition,
    sequence: u64,
    rows: &[StoredRow],
) -> Result<()> {
    rewrite_table_state_with_flush(state, definition, sequence, rows, &mut |_| Ok(()))
}

fn rewrite_table_state_with_flush(
    state: &mut RelationalState,
    definition: TableDefinition,
    sequence: u64,
    rows: &[StoredRow],
    flush: &mut impl FnMut(&mut RelationalState) -> Result<()>,
) -> Result<()> {
    validate_definition(&definition)?;
    let previous = state
        .tables
        .get(&definition.name)
        .ok_or_else(|| invalid(format!("table {} does not exist", definition.name)))?;
    let mut rewritten = TableState::empty(definition.clone(), Arc::clone(&state.directory))?;
    rewritten.rows.mark_modified(sequence);
    rewritten.next_row_id = previous.next_row_id;
    state.tables.insert(&definition.name, Arc::new(rewritten))?;
    for row in rows {
        let rewritten = Arc::make_mut(
            state
                .tables
                .get_mut(&definition.name)?
                .expect("rewrite table installed"),
        );
        if row.row_id == 0 || rewritten.rows.contains_key(&row.row_id)? {
            return Err(invalid("table rewrite contains an invalid row identity"));
        }
        validate_row(&definition, &row.values)?;
        rewritten.next_row_id =
            rewritten
                .next_row_id
                .max(row.row_id.checked_add(1).ok_or_else(|| {
                    GaussError::ResourceExhausted("relational row ID overflow".into())
                })?);
        rewritten.rows.insert(
            row.row_id,
            VersionChain::single(RowVersion {
                begin: sequence,
                end: None,
                values: RowValues::copy(&row.values)?,
            })?,
        )?;
        rewritten.index_row(row.row_id, &row.values)?;
        flush(state)?;
    }
    Ok(())
}

fn rename_table_state(
    state: &mut RelationalState,
    old_name: &str,
    definition: TableDefinition,
    sequence: u64,
) -> Result<()> {
    if old_name != definition.name && state.tables.contains_key(&definition.name) {
        return Err(invalid(format!("table {} already exists", definition.name)));
    }
    let mut table = state
        .tables
        .remove(old_name)?
        .ok_or_else(|| invalid(format!("table {old_name} does not exist")))?;
    Arc::make_mut(&mut table).replace_definition(definition.clone(), sequence)?;
    state.tables.insert(&definition.name, table)?;
    Ok(())
}

fn apply_batch(state: &mut RelationalState, batch: &RelationalBatch) -> Result<()> {
    apply_batch_with_flush(state, batch, &mut |_| Ok(()))
}

fn apply_batch_with_flush(
    state: &mut RelationalState,
    batch: &RelationalBatch,
    flush: &mut impl FnMut(&mut RelationalState) -> Result<()>,
) -> Result<()> {
    if batch.sequence <= state.sequence {
        return Ok(());
    }
    let before = state.clone();
    let mut mutations = batch.mutations.iter().peekable();
    while let Some(mutation) = mutations.next() {
        match mutation {
            RelationalMutation::CreateTable { definition } => {
                if state.tables.contains_key(&definition.name) {
                    return Err(invalid(format!("table {} already exists", definition.name)));
                }
                state.tables.insert(
                    &definition.name,
                    Arc::new(TableState::empty(
                        definition.clone(),
                        Arc::clone(&state.directory),
                    )?),
                )?;
                state.next_catalog_id = state.next_catalog_id.max(catalog_id_frontier(definition));
            }
            RelationalMutation::DropTable { name } => {
                state.tables.remove(name)?;
            }
            RelationalMutation::AlterTable { definition } => {
                // Legacy ADD COLUMN journals used ALTER followed by a complete
                // UPDATE image. Replay that pair as one schema generation so
                // chunked spill never mixes rows of different widths.
                if let Some(RelationalMutation::Update { table, rows }) = mutations.peek()
                    && table == &definition.name
                    && state.tables.get(table).is_some_and(|current| {
                        current.definition.columns.len() != definition.columns.len()
                    })
                {
                    let current = &state.tables[table];
                    let mut identities = rows.iter().map(|row| row.row_id).collect::<HashSet<_>>();
                    if identities.len() != rows.len() {
                        return Err(invalid("legacy schema rewrite repeats a row identity"));
                    }
                    for row in current.rows.visible_rows(batch.sequence) {
                        if !identities.remove(&row?.0) {
                            return Err(invalid("legacy schema rewrite omits a live row"));
                        }
                    }
                    if !identities.is_empty() {
                        return Err(invalid("legacy schema rewrite names a missing row"));
                    }
                    rewrite_table_state_with_flush(
                        state,
                        definition.clone(),
                        batch.sequence,
                        rows,
                        flush,
                    )?;
                    state.next_catalog_id =
                        state.next_catalog_id.max(catalog_id_frontier(definition));
                    mutations.next();
                    flush(state)?;
                    continue;
                }
                let table = state
                    .tables
                    .get_mut(&definition.name)?
                    .ok_or_else(|| invalid(format!("table {} does not exist", definition.name)))?;
                Arc::make_mut(table).replace_definition(definition.clone(), batch.sequence)?;
                state.next_catalog_id = state.next_catalog_id.max(catalog_id_frontier(definition));
            }
            RelationalMutation::RenameTable {
                old_name,
                definition,
            } => {
                rename_table_state(state, old_name, definition.clone(), batch.sequence)?;
                state.next_catalog_id = state.next_catalog_id.max(catalog_id_frontier(definition));
            }
            RelationalMutation::RewriteTable { definition, rows } => {
                rewrite_table_state_with_flush(
                    state,
                    definition.clone(),
                    batch.sequence,
                    rows,
                    flush,
                )?;
                state.next_catalog_id = state.next_catalog_id.max(catalog_id_frontier(definition));
            }
            RelationalMutation::Insert {
                table: table_name,
                rows,
            } => {
                for row in rows {
                    let table = state
                        .tables
                        .get_mut(table_name)?
                        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
                    let table = Arc::make_mut(table);
                    table.next_row_id = table.next_row_id.max(row.row_id.saturating_add(1));
                    let mut versions = table
                        .rows
                        .get(&row.row_id)?
                        .map(|versions| versions.into_owned())
                        .transpose()?
                        .unwrap_or_default();
                    versions.push(RowVersion {
                        begin: batch.sequence,
                        end: None,
                        values: RowValues::copy(&row.values)?,
                    })?;
                    table.rows.insert(row.row_id, versions)?;
                    table.index_row(row.row_id, &row.values)?;
                    flush(state)?;
                }
            }
            RelationalMutation::Update {
                table: table_name,
                rows,
            } => {
                for row in rows {
                    let table = state
                        .tables
                        .get_mut(table_name)?
                        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
                    let table = Arc::make_mut(table);
                    replace_visible_row(table, row.row_id, batch.sequence, row.values.clone())?;
                    flush(state)?;
                }
            }
            RelationalMutation::Delete {
                table: table_name,
                row_ids,
            } => {
                for row_id in row_ids {
                    let table = state
                        .tables
                        .get_mut(table_name)?
                        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
                    let table = Arc::make_mut(table);
                    end_visible_row(table, *row_id, batch.sequence)?;
                    flush(state)?;
                }
            }
        }
        flush(state)?;
    }
    state.sequence = batch.sequence;
    validate_mutations(
        state,
        &before,
        batch.sequence,
        &batch.mutations,
        true,
        &ConstraintModes::default(),
    )
}

fn visible_version(versions: &[RowVersion], snapshot: u64) -> Option<&RowVersion> {
    versions
        .iter()
        .rev()
        .find(|version| version.begin <= snapshot && version.end.is_none_or(|end| snapshot < end))
}

fn visible_rows(table: &TableState, snapshot: u64) -> Result<Vec<(u64, RowValues)>> {
    table.rows.visible_rows(snapshot).collect()
}

fn is_count_star(projection: &[SelectItem]) -> bool {
    projection.len() == 1 && projection[0].to_string().eq_ignore_ascii_case("count(*)")
}

fn explain_statement(state: &RelationalState, statement: &Statement) -> Result<Vec<String>> {
    let operation = match statement {
        Statement::Query(query) => {
            if query.with.is_some() {
                "relational_materialized_cte"
            } else if let SetExpr::Select(select) = query.body.as_ref()
                && query_uses_aggregation(select)?
            {
                "relational_hash_aggregate"
            } else if query_uses_scalar_index(state, query)? {
                "relational_index_lookup"
            } else {
                "relational_scan"
            }
        }
        Statement::Insert(_) => "relational_insert",
        Statement::Update(_) => "relational_update",
        Statement::Delete(_) => "relational_delete",
        Statement::CreateTable(_)
        | Statement::CreateIndex(_)
        | Statement::AlterTable(_)
        | Statement::Drop { .. } => "relational_ddl",
        _ => return Err(unsupported("statement cannot be explained")),
    };
    Ok(vec![
        format!("operator={operation}"),
        "isolation=snapshot".to_string(),
        "constraints=commit_validation".to_string(),
    ])
}

fn query_uses_scalar_index(state: &RelationalState, query: &Query) -> Result<bool> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Ok(false);
    };
    if select.from.len() != 1 || !select.from[0].joins.is_empty() {
        return Ok(false);
    }
    let Some(Expr::BinaryOp { left, op, right }) = select.selection.as_ref() else {
        return Ok(false);
    };
    if *op != BinaryOperator::Eq {
        return Ok(false);
    }
    let column = match (expression_column_name(left), expression_column_name(right)) {
        (Ok(column), Err(_)) | (Err(_), Ok(column)) => column,
        _ => return Ok(false),
    };
    let table_name = table_factor_name(&select.from[0].relation)?;
    let table = state
        .tables
        .get(&table_name)
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
    Ok(table.indexes.contains_key(&vec![column]))
}

fn is_ddl(statement: &Statement) -> bool {
    matches!(
        statement,
        Statement::CreateTable(_)
            | Statement::CreateIndex(_)
            | Statement::AlterTable(_)
            | Statement::Drop { .. }
    )
}

fn table_factor_name(factor: &TableFactor) -> Result<String> {
    match factor {
        TableFactor::Table { name, args, .. } if args.is_none() => Ok(normalize_name(name)),
        _ => Err(unsupported("table expression is outside relational v1")),
    }
}

fn expression_column_name(expression: &Expr) -> Result<String> {
    match expression {
        Expr::Identifier(identifier) => Ok(normalize_ident(&identifier.value)),
        Expr::CompoundIdentifier(identifiers) if !identifiers.is_empty() => Ok(normalize_ident(
            &identifiers.last().expect("not empty").value,
        )),
        _ => Err(unsupported("expected a column reference")),
    }
}

fn column_index(definition: &TableDefinition, name: &str) -> Result<usize> {
    definition
        .columns
        .iter()
        .position(|column| column.name == name)
        .ok_or_else(|| invalid(format!("unknown column {name}")))
}

fn index_column_name(column: &sqlparser::ast::IndexColumn) -> Result<String> {
    expression_column_name(&column.column.expr)
}

fn normalize_name(name: &sqlparser::ast::ObjectName) -> String {
    name.to_string().trim_matches('"').to_ascii_lowercase()
}

fn normalize_ident(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn integer_literal(expression: &Expr) -> Result<u64> {
    match expression {
        Expr::Value(value) => match &value.value {
            Value::Number(value, _) => value
                .parse::<u64>()
                .map_err(|_| invalid("LIMIT must be a non-negative integer")),
            _ => Err(invalid("LIMIT must be a non-negative integer")),
        },
        _ => Err(invalid("LIMIT must be a non-negative integer")),
    }
}

fn value_key(value: &RelationalValue) -> String {
    match value {
        RelationalValue::Float(value) if *value == 0.0 => "float:0".to_string(),
        RelationalValue::Float(value) => format!("float:{:016x}", value.to_bits()),
        RelationalValue::Decimal(value) => decimal_parts(value)
            .map(|(negative, whole, fraction)| {
                format!(
                    "decimal:{}{}{}",
                    if negative { "-" } else { "" },
                    whole,
                    if fraction.is_empty() {
                        String::new()
                    } else {
                        format!(".{fraction}")
                    }
                )
            })
            .unwrap_or_else(|| format!("decimal:{value}")),
        RelationalValue::Bytes(value) => {
            let mut encoded = String::from("bytea:");
            for byte in value {
                use std::fmt::Write as _;
                write!(&mut encoded, "{byte:02x}").expect("write to string");
            }
            encoded
        }
        RelationalValue::Date(value) => format!("date:{value}"),
        RelationalValue::Json(value) => serde_json::to_string(value)
            .map(|value| format!("jsonb:{value}"))
            .unwrap_or_else(|_| "jsonb:null".to_string()),
        RelationalValue::TimestampUtc(value) => chrono::DateTime::parse_from_rfc3339(value)
            .map(|value| {
                format!(
                    "timestamp:{}",
                    value
                        .to_utc()
                        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
                )
            })
            .unwrap_or_else(|_| format!("timestamp:{value}")),
        _ => serde_json::to_string(value).unwrap_or_else(|_| format!("{value:?}")),
    }
}

fn invalid(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

fn unsupported(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(format!("unsupported SQL: {}", message.into()))
}

#[cfg(test)]
pub(crate) fn with_storage_test_limit<T>(capacity: u64, operation: impl FnOnce() -> T) -> (T, u64) {
    memory::with_storage_pool(capacity, |pool| (operation(), pool.used()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{
        Classification, IdentityAuthority, PrincipalRecord, ScopeGrant, SubjectAttributes,
    };
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    #[test]
    fn nested_cancellation_keeps_request_and_shutdown_flags_and_cleans_up() {
        for cancel_outer in [true, false] {
            let request = Arc::new(AtomicBool::new(false));
            let shutdown = Arc::new(AtomicBool::new(false));
            let result = with_sql_cancellation(request.clone(), || {
                with_sql_cancellation(shutdown.clone(), || {
                    if cancel_outer { &request } else { &shutdown }
                        .store(true, AtomicOrdering::Release);
                    check_sql_cancelled()
                })
            });
            assert!(
                matches!(result, Err(GaussError::InvalidRequest(message)) if message == "query canceled")
            );
            assert!(
                check_sql_cancelled().is_ok(),
                "completed request leaked its flag"
            );
        }
    }

    fn request(sql: &str) -> SqlExecutionRequest {
        SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.to_string(),
                parameters: Vec::new(),
            }],
            idempotency_key: None,
            retry_id: None,
        }
    }

    fn audit(principal: &str) -> AuditContext {
        AuditContext {
            principal_id: principal.to_string(),
            tenant_id: Some("tenant-a".to_string()),
            transport: "test".to_string(),
            request_id: None,
        }
    }

    #[test]
    fn ordinary_insert_validates_touched_keys_without_scanning_existing_rows() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request("CREATE TABLE active (id INTEGER PRIMARY KEY, value INTEGER UNIQUE CHECK (value > 0))"))
            .unwrap();
        engine
            .execute(request("INSERT INTO unrelated VALUES (1), (2)"))
            .unwrap();
        engine.checkpoint().unwrap();

        rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
        engine
            .execute(request("INSERT INTO active VALUES (1, 7)"))
            .unwrap();
        assert_eq!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()), 0);

        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
        reopened
            .execute(request("INSERT INTO active VALUES (2, 8)"))
            .unwrap();
        assert_eq!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()), 0);
        assert!(
            reopened
                .execute(request("INSERT INTO active VALUES (3, 8)"))
                .is_err()
        );
        let mut update = request("UPDATE active SET value = $1 WHERE id = $2");
        update.statements[0].parameters =
            vec![RelationalValue::Integer(9), RelationalValue::Integer(2)];
        rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
        reopened.execute(update).unwrap();
        assert_eq!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()), 0);
        rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
        reopened
            .execute(request("DELETE FROM active WHERE id = 1"))
            .unwrap();
        assert_eq!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()), 0);
    }

    #[test]
    fn sql_idempotent_retry_returns_original_rows_without_second_mutation() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE receipts (id BIGINT PRIMARY KEY, value BIGINT)",
            ))
            .unwrap();
        let mut mutation =
            request("INSERT INTO receipts (id, value) VALUES (1, 7) RETURNING id, value");
        mutation.idempotency_key = Some("insert-receipt".into());
        mutation.retry_id = Some("first-correlation".into());
        let first = engine
            .execute_with_audit(mutation.clone(), &audit("alice"))
            .unwrap()
            .response;
        let decisions = journal.committed().unwrap();
        let durable = serde_json::to_value(
            decisions
                .last()
                .unwrap()
                .prepare
                .idempotency
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_value::<SqlExecutionResponse>(durable["response"].clone()).unwrap(),
            SqlExecutionResponse {
                transaction_id: None,
                ..first.clone()
            }
        );
        mutation.retry_id = Some("second-correlation".into());
        let retry = engine
            .execute_with_audit(mutation.clone(), &audit("alice"))
            .unwrap()
            .response;
        assert_eq!(first, retry);
        assert_eq!(journal.committed().unwrap().len(), 2); // CREATE and one INSERT.
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        let retry = engine
            .execute_with_audit(mutation.clone(), &audit("alice"))
            .unwrap()
            .response;
        assert_eq!(first, retry);
        mutation.statements[0].sql = "INSERT INTO receipts (id, value) VALUES (2, 8)".into();
        assert!(
            engine
                .execute_with_audit(mutation, &audit("alice"))
                .is_err()
        );
        let rows = engine
            .execute(request("SELECT id, value FROM receipts"))
            .unwrap()
            .response;
        assert!(matches!(&rows.results[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
        assert_eq!(journal.committed().unwrap().len(), 2);
    }

    #[test]
    fn rejected_idempotent_sql_does_not_publish_format_or_mutation() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        let before = std::fs::read(
            directory
                .path()
                .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER),
        )
        .unwrap();
        let mut invalid_request = request("INSERT INTO missing_table (id) VALUES (1)");
        invalid_request.idempotency_key = Some("rejected".into());
        assert!(engine.execute(invalid_request).is_err());
        assert_eq!(
            std::fs::read(
                directory
                    .path()
                    .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER)
            )
            .unwrap(),
            before
        );
        assert!(journal.committed().unwrap().is_empty());
    }

    #[test]
    fn zero_row_mutation_consumes_its_key_before_a_later_insert() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE counters (id BIGINT PRIMARY KEY, value BIGINT)",
            ))
            .unwrap();
        let mut mutation = request("UPDATE counters SET value = 1 WHERE id = 9");
        mutation.idempotency_key = Some("empty-update".into());
        let first = engine.execute(mutation.clone()).unwrap().response;
        assert!(first.transaction_id.is_some());
        assert_eq!(
            first.results,
            vec![SqlResult::Mutation { affected_rows: 0 }]
        );
        engine
            .execute(request("INSERT INTO counters (id, value) VALUES (9, 0)"))
            .unwrap();
        assert_eq!(engine.execute(mutation).unwrap().response, first);
        let result = engine
            .execute(request("SELECT value FROM counters WHERE id = 9"))
            .unwrap()
            .response;
        assert!(
            matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(0)]])
        );
    }

    #[test]
    fn concurrent_sql_retries_share_one_execution_even_with_unique_constraint() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE once_only (id BIGINT PRIMARY KEY)"))
            .unwrap();
        let mut mutation = request("INSERT INTO once_only (id) VALUES (1) RETURNING id");
        mutation.idempotency_key = Some("concurrent".into());
        let barrier = std::sync::Barrier::new(8);
        let responses = std::thread::scope(|scope| {
            (0..8)
                .map(|_| {
                    let (engine, barrier, mutation) = (&engine, &barrier, mutation.clone());
                    scope.spawn(move || {
                        barrier.wait();
                        engine.execute(mutation).unwrap().response
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(responses.iter().all(|response| response == &responses[0]));
        assert_eq!(journal.committed().unwrap().len(), 2);
    }

    #[test]
    fn sql_request_limits_reject_before_execution() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        let too_many = SqlExecutionRequest {
            statements: (0..=MAX_STATEMENTS_PER_REQUEST)
                .map(|_| crate::SqlStatementRequest {
                    sql: "SELECT 1".into(),
                    parameters: Vec::new(),
                })
                .collect(),
            idempotency_key: None,
            retry_id: None,
        };
        let error = engine.execute(too_many).err().expect("request must fail");
        assert!(error.to_string().contains("maximum is 32"));

        let oversized = request(&format!(
            "SELECT '{}'",
            "x".repeat(MAX_DECODED_REQUEST_BYTES)
        ));
        let error = engine.execute(oversized).err().expect("request must fail");
        assert!(error.to_string().contains("decoded SQL request exceeds"));
        assert!(engine.table_definitions().is_empty());
    }

    fn protected_identity(
        id: &str,
        tenant: &str,
        tables: &[(&str, &[SecurityAction])],
        schema: bool,
    ) -> (
        tempfile::TempDir,
        Arc<IdentityAuthority>,
        AuthenticatedIdentity,
    ) {
        let directory = tempdir().unwrap();
        let grants = tables
            .iter()
            .map(|(table, actions)| ScopeGrant {
                tenants: BTreeSet::from([tenant.to_string()]),
                collections: BTreeSet::from([(*table).to_string()]),
                actions: actions.iter().copied().collect(),
            })
            .collect();
        let key = IdentityAuthority::bootstrap(
            directory.path(),
            PrincipalRecord {
                id: id.into(),
                tenant: tenant.into(),
                enabled: true,
                attributes: SubjectAttributes {
                    department: "relational-test".into(),
                    clearance: Classification::Restricted,
                },
                grants,
                installation_actions: if schema {
                    BTreeSet::from([SecurityAction::IdentityManage, SecurityAction::Schema])
                } else {
                    BTreeSet::from([SecurityAction::IdentityManage])
                },
                delegation: Vec::new(),
            },
        )
        .unwrap();
        let authority = IdentityAuthority::open(directory.path()).unwrap().unwrap();
        let identity = authority.authenticate(&key.secret).unwrap();
        (directory, authority, identity)
    }

    #[test]
    fn protected_interactive_ddl_uses_private_catalog_for_authorization() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        let (_identity_dir, _authority, identity) = protected_identity(
            "admin",
            "acme",
            &[(
                "private_items",
                &[
                    SecurityAction::Create,
                    SecurityAction::Read,
                    SecurityAction::Update,
                    SecurityAction::Delete,
                ],
            )],
            true,
        );
        let context = AuditContext {
            principal_id: identity.principal().id.clone(),
            tenant_id: Some("acme".into()),
            transport: "test".into(),
            request_id: None,
        };
        let handle = engine
            .begin_interactive_authorized(&context)
            .unwrap()
            .handle;
        for sql in [
            "CREATE TABLE private_items (id BIGINT PRIMARY KEY, value TEXT)",
            "INSERT INTO private_items VALUES (1, 'private')",
            "UPDATE private_items SET value = 'committed' WHERE id = 1",
            "SELECT value FROM private_items WHERE id = 1",
        ] {
            let response = engine
                .execute_interactive_authorized_cancellable(
                    &handle,
                    request(sql),
                    &context,
                    Arc::new(AtomicBool::new(false)),
                    &identity,
                )
                .unwrap();
            if sql.starts_with("SELECT") {
                assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. }
                    if rows == &vec![vec![RelationalValue::Text("committed".into())]]));
            }
        }
        let committed = engine
            .commit_interactive_inner(&handle, &context, Some(&identity), None)
            .unwrap();
        assert!(committed.response.committed);
        let select = request("SELECT value FROM private_items WHERE id = 1");
        let _permit = engine.authorize_request(&identity, &select).unwrap();
        let selected = engine
            .execute_authorized_with_audit(select, &context)
            .unwrap()
            .response;
        assert!(matches!(&selected.results[0], SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Text("committed".into())]]));

        let rollback_handle = engine
            .begin_interactive_authorized(&context)
            .unwrap()
            .handle;
        for sql in [
            "SAVEPOINT before_ddl",
            "CREATE TABLE rolled_back_items (id BIGINT PRIMARY KEY)",
        ] {
            engine
                .execute_interactive_authorized_cancellable(
                    &rollback_handle,
                    request(sql),
                    &context,
                    Arc::new(AtomicBool::new(false)),
                    &identity,
                )
                .unwrap();
        }
        assert!(
            engine
                .interactive_has_table(&rollback_handle, &context, "rolled_back_items")
                .unwrap()
        );
        engine
            .execute_interactive_authorized_cancellable(
                &rollback_handle,
                request("ROLLBACK TO SAVEPOINT before_ddl"),
                &context,
                Arc::new(AtomicBool::new(false)),
                &identity,
            )
            .unwrap();
        assert!(
            !engine
                .interactive_has_table(&rollback_handle, &context, "rolled_back_items")
                .unwrap()
        );
        engine
            .commit_interactive_inner(&rollback_handle, &context, Some(&identity), None)
            .unwrap();
        assert!(
            engine
                .table_definitions()
                .iter()
                .all(|table| table.name != "rolled_back_items")
        );

        let (_denied_dir, _denied_authority, denied) = protected_identity(
            "denied",
            "acme",
            &[("denied_items", &[SecurityAction::Read])],
            true,
        );
        let denied_context = AuditContext {
            principal_id: denied.principal().id.clone(),
            tenant_id: Some("acme".into()),
            transport: "test".into(),
            request_id: None,
        };
        let denied_handle = engine
            .begin_interactive_authorized(&denied_context)
            .unwrap()
            .handle;
        engine
            .execute_interactive_authorized_cancellable(
                &denied_handle,
                request("CREATE TABLE denied_items (id BIGINT PRIMARY KEY)"),
                &denied_context,
                Arc::new(AtomicBool::new(false)),
                &denied,
            )
            .unwrap();
        assert!(matches!(
            engine.execute_interactive_authorized_cancellable(
                &denied_handle,
                request("INSERT INTO denied_items VALUES (1)"),
                &denied_context,
                Arc::new(AtomicBool::new(false)),
                &denied,
            ),
            Err(GaussError::Security(SecurityError::Forbidden))
        ));
        engine
            .rollback_interactive(&denied_handle, &denied_context)
            .unwrap();
        assert!(
            engine
                .table_definitions()
                .iter()
                .all(|table| table.name != "denied_items")
        );
    }

    #[test]
    fn protected_relational_authorization_is_tenant_scoped_and_expands_fk_actions() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        let (_identity_dir, _authority, admin) = protected_identity(
            "admin",
            "acme",
            &[
                (
                    "parents",
                    &[
                        SecurityAction::Read,
                        SecurityAction::Create,
                        SecurityAction::Update,
                        SecurityAction::Delete,
                    ],
                ),
                (
                    "children",
                    &[
                        SecurityAction::Read,
                        SecurityAction::Create,
                        SecurityAction::Update,
                        SecurityAction::Delete,
                    ],
                ),
            ],
            true,
        );
        let context = AuditContext {
            principal_id: "admin".into(),
            tenant_id: Some("acme".into()),
            transport: "protected-test".into(),
            request_id: None,
        };
        for sql in [
            "CREATE TABLE parents (id INTEGER PRIMARY KEY)",
            "CREATE TABLE children (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, CONSTRAINT children_parent_fkey FOREIGN KEY (parent_id) REFERENCES parents(id) ON DELETE CASCADE)",
            "INSERT INTO parents VALUES (1)",
            "INSERT INTO children VALUES (10, 1)",
        ] {
            let request = request(sql);
            let _permit = engine.authorize_request(&admin, &request).unwrap();
            engine
                .execute_authorized_with_audit(request, &context)
                .unwrap();
        }

        let (_limited_dir, _limited_authority, limited) = protected_identity(
            "limited",
            "acme",
            &[("parents", &[SecurityAction::Delete])],
            false,
        );
        assert!(matches!(
            engine.authorize_request(&limited, &request("DELETE FROM parents WHERE id = 1")),
            Err(GaussError::Security(SecurityError::Forbidden))
        ));

        let (_other_dir, _other_authority, other_tenant) = protected_identity(
            "other",
            "other-tenant",
            &[("parents", &[SecurityAction::Read])],
            false,
        );
        assert!(matches!(
            engine.authorize_request(&other_tenant, &request("SELECT id FROM parents")),
            Err(GaussError::Security(SecurityError::NotFound))
        ));

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let select = request("SELECT id FROM parents");
        let _permit = reopened.authorize_request(&admin, &select).unwrap();
        let response = reopened
            .execute_authorized_with_audit(select, &context)
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
    }

    #[test]
    fn typed_rows_constraints_and_recovery() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE owners (id UUID PRIMARY KEY, name TEXT NOT NULL UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE documents (id UUID PRIMARY KEY, owner_id UUID NOT NULL, title TEXT, FOREIGN KEY (owner_id) REFERENCES owners(id))",
            ))
            .unwrap();
        let owner = uuid::Uuid::new_v4();
        let document = uuid::Uuid::new_v4();
        engine
            .execute(SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "INSERT INTO owners (id, name) VALUES ($1, $2)".into(),
                    parameters: vec![
                        RelationalValue::Uuid(owner),
                        RelationalValue::Text("Ada".into()),
                    ],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        engine
            .execute(SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "INSERT INTO documents (id, owner_id, title) VALUES ($1, $2, $3)".into(),
                    parameters: vec![
                        RelationalValue::Uuid(document),
                        RelationalValue::Uuid(owner),
                        RelationalValue::Text("Native relational".into()),
                    ],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        assert!(engine.execute(request("DELETE FROM owners")).is_err());
        let response = engine
            .execute(request("SELECT id, title FROM documents"))
            .unwrap()
            .response;
        assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        let response = engine
            .execute(request("SELECT COUNT(*) FROM documents"))
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
    }

    #[test]
    fn request_rolls_back_before_commit_on_constraint_failure() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT UNIQUE)",
            ))
            .unwrap();
        let failed = engine.execute(SqlExecutionRequest {
            statements: vec![
                crate::SqlStatementRequest {
                    sql: "INSERT INTO items VALUES (1, 'same')".into(),
                    parameters: vec![],
                },
                crate::SqlStatementRequest {
                    sql: "INSERT INTO items VALUES (2, 'same')".into(),
                    parameters: vec![],
                },
            ],
            idempotency_key: None,
            retry_id: None,
        });
        assert!(failed.is_err());
        let response = engine
            .execute(request("SELECT COUNT(*) FROM items"))
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));
    }

    #[test]
    fn ordering_null_and_if_not_exists_follow_declared_semantics() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE numbers (id INTEGER PRIMARY KEY, amount DECIMAL(38, 10), observed TIMESTAMP WITH TIME ZONE)",
            ))
            .unwrap();
        let duplicate = engine
            .execute(request(
                "CREATE TABLE IF NOT EXISTS numbers (id INTEGER PRIMARY KEY)",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            duplicate.results[0],
            SqlResult::Definition {
                affected_objects: 0
            }
        ));
        engine
            .execute(request(
                "INSERT INTO numbers VALUES (1, '9007199254740993.0000000001', '2026-09-17T01:02:03Z'), (2, '9007199254740992.9999999999', '2026-09-17T01:02:03+00:00'), (3, NULL, NULL)",
            ))
            .unwrap();
        let response = engine
            .execute(request(
                "SELECT id FROM numbers WHERE amount <> '9007199254740993.0000000001' ORDER BY amount ASC NULLS LAST",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(2)]]
        ));
        let paged = engine
            .execute(request(
                "SELECT id FROM numbers ORDER BY id LIMIT 1 OFFSET 1",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &paged.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(2)]]
        ));
        assert!(
            engine
                .execute(request(
                    "INSERT INTO numbers VALUES (4, '1.0', '2026-09-17T08:02:03+07:00')",
                ))
                .is_err()
        );
    }

    #[test]
    fn streaming_select_bounds_output_and_preserves_pagination_after_reopen() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE stream (id INTEGER PRIMARY KEY, note TEXT)",
            ))
            .unwrap();
        let note = "x".repeat(32 * 1024);
        for chunk in 0..17 {
            let values = (chunk * 16..chunk * 16 + 16)
                .map(|id| format!("({id}, '{note}')"))
                .collect::<Vec<_>>()
                .join(", ");
            engine
                .execute(request(&format!("INSERT INTO stream VALUES {values}")))
                .unwrap();
        }
        engine
            .execute(request("UPDATE stream SET note = NULL WHERE id = 271"))
            .unwrap();
        assert!(
            matches!(&engine.execute(request("SELECT COUNT(*) AS total FROM stream")).unwrap().response.results[0],
            SqlResult::Rows { columns, rows, .. }
                if columns == &vec!["total".to_string()] && rows == &vec![vec![RelationalValue::Integer(272)]])
        );
        assert!(
            matches!(&engine.execute(request("SELECT COUNT(note) FROM stream WHERE id >= 270")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1)]])
        );
        let page = engine
            .execute(request("SELECT id FROM stream LIMIT 2 OFFSET 3"))
            .unwrap()
            .response;
        assert!(matches!(&page.results[0], SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Integer(3)], vec![RelationalValue::Integer(4)]]));
        assert!(
            matches!(&engine.execute(request("SELECT id FROM stream LIMIT 0")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows.is_empty())
        );
        assert!(
            matches!(&engine.execute(request("SELECT id FROM stream WHERE id >= 270 LIMIT 1")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(270)]])
        );
        assert!(
            matches!(&engine.execute(request("SELECT id FROM stream WHERE id = 271")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(271)]])
        );
        assert!(
            matches!(&engine.execute(request("SELECT id FROM stream WHERE id = 271 ORDER BY id DESC LIMIT 1")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(271)]])
        );
        assert!(
            matches!(&engine.execute(request("SELECT id FROM stream ORDER BY id DESC LIMIT 1")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(271)]])
        );
        assert!(matches!(
            engine.execute(request("SELECT id FROM stream ORDER BY id DESC LIMIT 270")),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(matches!(
            engine.execute(request("SELECT note FROM stream")),
            Err(GaussError::ResourceExhausted(_))
        ));
        let repeated_read = SqlExecutionRequest {
            statements: (0..2)
                .map(|_| crate::SqlStatementRequest {
                    sql: "SELECT note FROM stream LIMIT 150".into(),
                    parameters: Vec::new(),
                })
                .collect(),
            idempotency_key: None,
            retry_id: None,
        };
        assert!(matches!(
            engine.execute(repeated_read),
            Err(GaussError::ResourceExhausted(_))
        ));
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        assert_eq!(
            engine
                .execute(request("SELECT id FROM stream LIMIT 2 OFFSET 3"))
                .unwrap()
                .response,
            page
        );
        assert!(
            matches!(&engine.execute(request("SELECT COUNT(*) FROM stream")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(272)]])
        );
    }

    #[test]
    fn bounded_topk_matches_materialized_order_for_nulls_ties_and_aliases() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE ranking (id INTEGER PRIMARY KEY, score INTEGER)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO ranking VALUES (1, NULL), (2, 4), (3, 4), (4, 2), (5, NULL), (6, 9)",
            ))
            .unwrap();
        for query in [
            "SELECT id, score FROM ranking ORDER BY score ASC NULLS FIRST, id DESC",
            "SELECT id, score FROM ranking ORDER BY score DESC NULLS LAST, id ASC",
            "SELECT id, score AS score_alias FROM ranking ORDER BY score_alias, id",
            "SELECT id, score FROM ranking ORDER BY 2 DESC, 1 ASC",
        ] {
            let full = engine.execute(request(query)).unwrap().response;
            let page = engine
                .execute(request(&format!("{query} LIMIT 2 OFFSET 1")))
                .unwrap()
                .response;
            let SqlResult::Rows { rows: full, .. } = &full.results[0] else {
                panic!("SELECT must produce rows");
            };
            let SqlResult::Rows { rows: page, .. } = &page.results[0] else {
                panic!("SELECT must produce rows");
            };
            assert_eq!(page, &full[1..3], "{query}");
        }
        let invalid_then_write = SqlExecutionRequest {
            statements: [
                "SELECT id FROM ranking WHERE id + 1 = 2 ORDER BY id LIMIT 0",
                "INSERT INTO ranking VALUES (7, 1)",
            ]
            .into_iter()
            .map(|sql| crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: Vec::new(),
            })
            .collect(),
            idempotency_key: None,
            retry_id: None,
        };
        assert!(engine.execute(invalid_then_write).is_err());
        assert!(
            matches!(&engine.execute(request("SELECT id FROM ranking WHERE id = 7")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows.is_empty())
        );
    }

    #[test]
    fn ordered_primary_key_pages_seek_disk_and_overlay_without_row_scans() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE pages (id BIGINT PRIMARY KEY, payload TEXT)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO pages VALUES (90, 'ninety'), (10, 'ten'), (70, 'seventy'), (30, 'thirty'), (50, 'fifty')",
            ))
            .unwrap();
        engine.checkpoint().unwrap();
        drop(engine);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "UPDATE pages SET payload = 'thirty-new' WHERE id = 30",
            ))
            .unwrap();
        engine
            .execute(request("DELETE FROM pages WHERE id = 50"))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO pages VALUES (20, 'twenty'), (60, 'sixty')",
            ))
            .unwrap();

        for (sql, expected) in [
            (
                "SELECT id, payload FROM pages ORDER BY id LIMIT 3",
                vec![(10, "ten"), (20, "twenty"), (30, "thirty-new")],
            ),
            (
                "SELECT id, payload FROM pages WHERE id > 10 ORDER BY id LIMIT 3",
                vec![(20, "twenty"), (30, "thirty-new"), (60, "sixty")],
            ),
            (
                "SELECT id, payload FROM pages WHERE id >= 30 ORDER BY id LIMIT 3",
                vec![(30, "thirty-new"), (60, "sixty"), (70, "seventy")],
            ),
            (
                "SELECT id, payload FROM pages WHERE id > 90 ORDER BY id LIMIT 3",
                vec![],
            ),
        ] {
            rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
            let response = engine.execute(request(sql)).unwrap().response;
            let SqlResult::Rows { rows, .. } = &response.results[0] else {
                panic!("ordered query must return rows");
            };
            let actual = rows
                .iter()
                .map(|row| match (&row[0], &row[1]) {
                    (RelationalValue::Integer(id), RelationalValue::Text(payload)) => {
                        (*id, payload.as_str())
                    }
                    _ => panic!("unexpected row types"),
                })
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "{sql}");
            assert_eq!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()), 0);
        }
        rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
        let response = engine
            .execute(request(
                "SELECT payload AS id FROM pages WHERE id > 10 ORDER BY id LIMIT 3",
            ))
            .unwrap()
            .response;
        assert_eq!(
            response.results[0],
            SqlResult::Rows {
                columns: vec!["id".into()],
                column_types: vec![RelationalType::Text],
                rows: ["ninety", "seventy", "sixty"]
                    .into_iter()
                    .map(|value| vec![RelationalValue::Text(value.into())])
                    .collect(),
            }
        );
        assert!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()) > 0);

        rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
        let first_alias_page = engine
            .execute(request(
                "SELECT payload AS id FROM pages ORDER BY id LIMIT 3",
            ))
            .unwrap()
            .response;
        assert_eq!(first_alias_page.results[0], response.results[0]);
        assert!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()) > 0);

        let mut parameterized = request("SELECT id FROM pages WHERE id > $1 ORDER BY id LIMIT 2");
        parameterized.statements[0].parameters = vec![RelationalValue::Integer(20)];
        rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
        let response = engine.execute(parameterized).unwrap().response;
        assert_eq!(
            response.results[0],
            SqlResult::Rows {
                columns: vec!["id".into()],
                column_types: vec![RelationalType::BigInt],
                rows: vec![
                    vec![RelationalValue::Integer(30)],
                    vec![RelationalValue::Integer(60)],
                ],
            }
        );
        assert_eq!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()), 0);

        engine.checkpoint().unwrap();
        drop(engine);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        rows::VISIBLE_ROW_SCANS.with(|scans| scans.set(0));
        let response = reopened
            .execute(request(
                "SELECT id FROM pages WHERE id > 10 ORDER BY id LIMIT 4",
            ))
            .unwrap()
            .response;
        assert_eq!(
            response.results[0],
            SqlResult::Rows {
                columns: vec!["id".into()],
                column_types: vec![RelationalType::BigInt],
                rows: [20, 30, 60, 70]
                    .into_iter()
                    .map(|id| vec![RelationalValue::Integer(id)])
                    .collect(),
            }
        );
        assert_eq!(rows::VISIBLE_ROW_SCANS.with(|scans| scans.get()), 0);
    }

    #[test]
    fn ordered_primary_page_reuses_locator_cursor_for_adjacent_rows() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE pages (id BIGINT PRIMARY KEY)"))
            .unwrap();
        let values = (1..=128)
            .map(|id| format!("({id})"))
            .collect::<Vec<_>>()
            .join(",");
        engine
            .execute(request(&format!("INSERT INTO pages VALUES {values}")))
            .unwrap();
        engine.checkpoint().unwrap();
        drop(engine);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        rows::ORDERED_SEEKS.with(|seeks| seeks.set(0));
        let response = reopened
            .execute(request("SELECT id FROM pages ORDER BY id LIMIT 128"))
            .unwrap()
            .response;
        assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. } if rows.len() == 128));
        assert_eq!(rows::ORDERED_SEEKS.with(|seeks| seeks.get()), 1);
    }

    #[test]
    fn interactive_request_rejects_excess_control_statements_before_session_changes() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE bounded_session (id INTEGER PRIMARY KEY)",
            ))
            .unwrap();
        let context = audit("session-owner");
        let transaction = engine.begin_interactive(&context).unwrap();
        let excess = SqlExecutionRequest {
            statements: (0..MAX_STATEMENTS_PER_REQUEST + 1)
                .map(|index| crate::SqlStatementRequest {
                    sql: format!("SAVEPOINT point_{index}"),
                    parameters: Vec::new(),
                })
                .collect(),
            idempotency_key: None,
            retry_id: None,
        };
        assert!(matches!(
            engine.execute_interactive(&transaction.handle, excess, &context),
            Err(GaussError::ResourceExhausted(_))
        ));
        engine
            .execute_interactive(
                &transaction.handle,
                request("INSERT INTO bounded_session VALUES (1)"),
                &context,
            )
            .unwrap();
        engine
            .commit_interactive(&transaction.handle, &context)
            .unwrap();
        assert!(
            matches!(&engine.execute(request("SELECT id FROM bounded_session")).unwrap().response.results[0],
            SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1)]])
        );
    }

    #[test]
    fn foreign_key_requires_a_type_compatible_unique_target() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parents (id INTEGER, label TEXT PRIMARY KEY)",
            ))
            .unwrap();
        assert!(engine
            .execute(request(
                "CREATE TABLE children (parent_id INTEGER, FOREIGN KEY (parent_id) REFERENCES parents(id))",
            ))
            .is_err());
        engine
            .execute(request("CREATE TABLE keyed (id INTEGER PRIMARY KEY)"))
            .unwrap();
        assert!(engine
            .execute(request(
                "CREATE TABLE wrong_type (parent_id TEXT, FOREIGN KEY (parent_id) REFERENCES keyed(id))",
            ))
            .is_err());
    }

    #[test]
    fn constraints_use_sql_value_equality_not_wire_spelling() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parents (id INTEGER PRIMARY KEY, amount DECIMAL(10, 2) UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parents VALUES (1, '1.0')"))
            .unwrap();
        assert!(
            engine
                .execute(request("INSERT INTO parents VALUES (2, '1.00')"))
                .is_err()
        );
        engine
            .execute(request(
                "CREATE TABLE children (id INTEGER PRIMARY KEY, amount DECIMAL(10, 2), FOREIGN KEY (amount) REFERENCES parents(amount))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO children VALUES (1, '1.00')"))
            .unwrap();

        engine
            .execute(request(
                "CREATE TABLE nullable_unique (id INTEGER PRIMARY KEY, value TEXT, CONSTRAINT primary_key UNIQUE (value))",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO nullable_unique VALUES (1, NULL), (2, NULL)",
            ))
            .unwrap();
    }

    #[test]
    fn inner_and_left_equijoins_use_one_snapshot() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE owners (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE documents (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, FOREIGN KEY (owner_id) REFERENCES owners(id))",
            ))
            .unwrap();
        engine
            .execute(SqlExecutionRequest {
                statements: vec![
                    crate::SqlStatementRequest {
                        sql: "INSERT INTO owners VALUES (1, 'Ada'), (2, 'Linus')".into(),
                        parameters: vec![],
                    },
                    crate::SqlStatementRequest {
                        sql: "INSERT INTO documents VALUES (10, 1, 'Architecture'), (11, NULL, 'Orphan draft')".into(),
                        parameters: vec![],
                    },
                ],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        let inner = engine
            .execute(request(
                "SELECT d.title, o.name FROM documents d INNER JOIN owners o ON d.owner_id = o.id ORDER BY d.title",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &inner.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Text("Architecture".into()),
                    RelationalValue::Text("Ada".into()),
                ]]
        ));
        let left = engine
            .execute(request(
                "SELECT d.title, o.name FROM documents d LEFT JOIN owners o ON d.owner_id = o.id ORDER BY d.title",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &left.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![
                        RelationalValue::Text("Architecture".into()),
                        RelationalValue::Text("Ada".into()),
                    ],
                    vec![
                        RelationalValue::Text("Orphan draft".into()),
                        RelationalValue::Null,
                    ],
                ]
        ));
        assert!(
            engine
                .execute(request(
                    "SELECT d.title FROM documents d INNER JOIN owners o ON d.id = d.owner_id",
                ))
                .is_err()
        );
    }

    #[test]
    fn non_recursive_ctes_materialize_in_one_snapshot_and_report_base_tables() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE cte_documents (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO cte_documents VALUES (1, 'ada', 'Storage'), (2, 'linus', 'Kernel'), (3, 'ada', 'Query')",
            ))
            .unwrap();

        let sql = "WITH owned(doc_id, title) AS (SELECT id, title FROM cte_documents WHERE owner = $1), bounded AS (SELECT doc_id, title FROM owned WHERE doc_id >= 2) SELECT doc_id, title FROM bounded ORDER BY doc_id";
        let analysis = RelationalEngine::analyze_statement(sql).unwrap();
        assert_eq!(analysis.tables, vec!["cte_documents"]);
        let response = engine
            .execute(SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: sql.into(),
                    parameters: vec![RelationalValue::Text("ada".into())],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { columns, rows, .. }
                if columns == &vec!["doc_id", "title"]
                    && rows == &vec![vec![
                        RelationalValue::Integer(3),
                        RelationalValue::Text("Query".into()),
                    ]]
        ));

        let alias_error = match engine.execute(request(
            "WITH broken(one) AS (SELECT id, title FROM cte_documents) SELECT one FROM broken",
        )) {
            Ok(_) => panic!("mismatched CTE alias count must fail"),
            Err(error) => error,
        };
        assert!(alias_error.to_string().contains("declares 1 columns"));
        let recursive_error = match engine.execute(request(
            "WITH RECURSIVE ids(id) AS (SELECT id FROM cte_documents) SELECT id FROM ids",
        )) {
            Ok(_) => panic!("recursive CTE must fail"),
            Err(error) => error,
        };
        assert!(recursive_error.to_string().contains("recursive CTE"));
    }

    #[test]
    fn uncorrelated_subqueries_use_the_same_snapshot_and_report_base_tables() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(SqlExecutionRequest {
                statements: vec![
                    crate::SqlStatementRequest {
                        sql: "CREATE TABLE sub_owners (id INTEGER PRIMARY KEY, name TEXT NOT NULL, active BOOLEAN NOT NULL)".into(),
                        parameters: vec![],
                    },
                    crate::SqlStatementRequest {
                        sql: "CREATE TABLE sub_documents (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT NOT NULL)".into(),
                        parameters: vec![],
                    },
                ],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        engine
            .execute(SqlExecutionRequest {
                statements: vec![
                    crate::SqlStatementRequest {
                        sql: "INSERT INTO sub_owners VALUES (1, 'Ada', TRUE), (2, 'Grace', FALSE)".into(),
                        parameters: vec![],
                    },
                    crate::SqlStatementRequest {
                        sql: "INSERT INTO sub_documents VALUES (10, 1, 'Storage'), (11, 2, 'Compiler'), (12, NULL, 'Draft')".into(),
                        parameters: vec![],
                    },
                ],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();

        let sql = "SELECT id, (SELECT name FROM sub_owners WHERE id = $1) AS owner_name FROM sub_documents WHERE owner_id IN (SELECT id FROM sub_owners WHERE active) AND EXISTS (SELECT id FROM sub_owners WHERE id = $1) ORDER BY id";
        let analysis = RelationalEngine::analyze_statement(sql).unwrap();
        assert_eq!(analysis.tables, vec!["sub_documents", "sub_owners"]);
        let response = engine
            .execute(SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: sql.into(),
                    parameters: vec![RelationalValue::Integer(1)],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { columns, rows, .. }
                if columns == &vec!["id", "owner_name"]
                    && rows == &vec![vec![
                        RelationalValue::Integer(10),
                        RelationalValue::Text("Ada".into()),
                    ]]
        ));

        let empty = engine
            .execute(request(
                "SELECT id, (SELECT name FROM sub_owners WHERE id = 99) AS owner_name FROM sub_documents WHERE id = 10",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &empty.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(10), RelationalValue::Null]]
        ));
        let cardinality_error = match engine.execute(request(
            "SELECT id, (SELECT name FROM sub_owners) AS owner_name FROM sub_documents WHERE id = 10",
        )) {
            Ok(_) => panic!("multi-row scalar subquery must fail"),
            Err(error) => error,
        };
        assert!(
            cardinality_error
                .to_string()
                .contains("scalar subquery returned more than one row")
        );
    }

    #[test]
    fn foreign_key_actions_are_atomic_and_recoverable() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parents (id INTEGER PRIMARY KEY, replacement INTEGER UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE cascade_children (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parents(id) ON UPDATE CASCADE ON DELETE CASCADE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE nullable_children (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parents(id) ON UPDATE CASCADE ON DELETE SET NULL)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE default_children (id INTEGER PRIMARY KEY, parent_id INTEGER DEFAULT 0 REFERENCES parents(id) ON UPDATE CASCADE ON DELETE SET DEFAULT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parents VALUES (0, 0), (1, 1)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO cascade_children VALUES (10, 1)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO nullable_children VALUES (20, 1)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO default_children VALUES (30, 1)"))
            .unwrap();

        engine
            .execute(request("UPDATE parents SET id = 2 WHERE id = 1"))
            .unwrap();
        let cascaded = engine
            .execute(request(
                "SELECT parent_id FROM cascade_children WHERE id = 10",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &cascaded.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(2)]]
        ));

        engine
            .execute(request("DELETE FROM parents WHERE id = 2"))
            .unwrap();
        let cascade_count = engine
            .execute(request("SELECT COUNT(*) FROM cascade_children"))
            .unwrap()
            .response;
        assert!(matches!(
            &cascade_count.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));
        let nullable = engine
            .execute(request(
                "SELECT parent_id FROM nullable_children WHERE id = 20",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &nullable.results[0],
            SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Null]]
        ));
        let defaulted = engine
            .execute(request(
                "SELECT parent_id FROM default_children WHERE id = 30",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &defaulted.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));

        drop(engine);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened
            .execute(request(
                "SELECT parent_id FROM default_children WHERE id = 30",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &recovered.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));
    }

    #[test]
    fn randomized_foreign_key_actions_match_independent_model_across_restarts() {
        const CHILD_TABLES: [&str; 5] = [
            "restrict_children",
            "no_action_children",
            "cascade_children",
            "nullable_children",
            "default_children",
        ];

        fn next_random(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = *state;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        }

        fn read_parent_ids(engine: &RelationalEngine) -> BTreeSet<i64> {
            let response = engine
                .execute(request("SELECT id FROM fk_parent ORDER BY id"))
                .unwrap()
                .response;
            let SqlResult::Rows { rows, .. } = &response.results[0] else {
                panic!("parent query must return rows");
            };
            rows.iter()
                .map(|row| match row.as_slice() {
                    [RelationalValue::Integer(id)] => *id,
                    _ => panic!("unexpected parent row {row:?}"),
                })
                .collect()
        }

        fn read_children(engine: &RelationalEngine, table: &str) -> BTreeMap<i64, Option<i64>> {
            let response = engine
                .execute(request(&format!(
                    "SELECT id, parent_id FROM {table} ORDER BY id"
                )))
                .unwrap()
                .response;
            let SqlResult::Rows { rows, .. } = &response.results[0] else {
                panic!("child query must return rows");
            };
            rows.iter()
                .map(|row| match row.as_slice() {
                    [
                        RelationalValue::Integer(id),
                        RelationalValue::Integer(parent),
                    ] => (*id, Some(*parent)),
                    [RelationalValue::Integer(id), RelationalValue::Null] => (*id, None),
                    _ => panic!("unexpected child row {row:?}"),
                })
                .collect()
        }

        let directory = tempdir().unwrap();
        let mut engine = {
            let journal = TransactionJournal::open(directory.path()).unwrap();
            RelationalEngine::open(directory.path(), journal).unwrap()
        };
        for statement in [
            "CREATE TABLE fk_parent (id INTEGER PRIMARY KEY)",
            "CREATE TABLE restrict_children (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES fk_parent(id) ON UPDATE RESTRICT ON DELETE RESTRICT)",
            "CREATE TABLE no_action_children (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES fk_parent(id) ON UPDATE NO ACTION ON DELETE NO ACTION)",
            "CREATE TABLE cascade_children (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES fk_parent(id) ON UPDATE CASCADE ON DELETE CASCADE)",
            "CREATE TABLE nullable_children (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES fk_parent(id) ON UPDATE SET NULL ON DELETE SET NULL)",
            "CREATE TABLE default_children (id INTEGER PRIMARY KEY, parent_id INTEGER DEFAULT 0 NOT NULL REFERENCES fk_parent(id) ON UPDATE SET DEFAULT ON DELETE SET DEFAULT)",
            "INSERT INTO fk_parent VALUES (0)",
        ] {
            engine.execute(request(statement)).unwrap();
        }

        let mut parents = BTreeSet::from([0_i64]);
        let mut children: [BTreeMap<i64, Option<i64>>; 5] =
            std::array::from_fn(|_| BTreeMap::new());
        let mut random = 0x4348_4952_4f4e_4442_u64;

        for step in 0..160 {
            let operation = next_random(&mut random) % 6;
            let mut expected_success = true;
            let sql = match operation {
                0 => {
                    let parent = 1 + (next_random(&mut random) % 9) as i64;
                    expected_success = !parents.contains(&parent);
                    if expected_success {
                        parents.insert(parent);
                    }
                    format!("INSERT INTO fk_parent VALUES ({parent})")
                }
                1 => {
                    let parent = 1 + (next_random(&mut random) % 9) as i64;
                    if parents.contains(&parent) {
                        expected_success =
                            !children[0].values().any(|value| *value == Some(parent))
                                && !children[1].values().any(|value| *value == Some(parent));
                        if expected_success {
                            parents.remove(&parent);
                            children[2].retain(|_, value| *value != Some(parent));
                            for value in children[3].values_mut() {
                                if *value == Some(parent) {
                                    *value = None;
                                }
                            }
                            for value in children[4].values_mut() {
                                if *value == Some(parent) {
                                    *value = Some(0);
                                }
                            }
                        }
                    }
                    format!("DELETE FROM fk_parent WHERE id = {parent}")
                }
                2 => {
                    let old = 1 + (next_random(&mut random) % 9) as i64;
                    let new = 1 + (next_random(&mut random) % 9) as i64;
                    if parents.contains(&old) && old != new {
                        expected_success = !parents.contains(&new)
                            && !children[0].values().any(|value| *value == Some(old))
                            && !children[1].values().any(|value| *value == Some(old));
                        if expected_success {
                            parents.remove(&old);
                            parents.insert(new);
                            for value in children[2].values_mut() {
                                if *value == Some(old) {
                                    *value = Some(new);
                                }
                            }
                            for value in children[3].values_mut() {
                                if *value == Some(old) {
                                    *value = None;
                                }
                            }
                            for value in children[4].values_mut() {
                                if *value == Some(old) {
                                    *value = Some(0);
                                }
                            }
                        }
                    }
                    format!("UPDATE fk_parent SET id = {new} WHERE id = {old}")
                }
                3 => {
                    let table_index =
                        (next_random(&mut random) % CHILD_TABLES.len() as u64) as usize;
                    let child = 1 + (next_random(&mut random) % 18) as i64;
                    let nullable = table_index != 4 && next_random(&mut random).is_multiple_of(5);
                    let parent = (!nullable).then(|| (next_random(&mut random) % 10) as i64);
                    expected_success = !children[table_index].contains_key(&child)
                        && parent.is_none_or(|parent| parents.contains(&parent));
                    if expected_success {
                        children[table_index].insert(child, parent);
                    }
                    let parent = parent.map_or_else(|| "NULL".to_string(), |id| id.to_string());
                    format!(
                        "INSERT INTO {} VALUES ({child}, {parent})",
                        CHILD_TABLES[table_index]
                    )
                }
                4 => {
                    let table_index =
                        (next_random(&mut random) % CHILD_TABLES.len() as u64) as usize;
                    let child = 1 + (next_random(&mut random) % 18) as i64;
                    let nullable = table_index != 4 && next_random(&mut random).is_multiple_of(5);
                    let parent = (!nullable).then(|| (next_random(&mut random) % 10) as i64);
                    if let Some(existing_parent) = children[table_index].get_mut(&child) {
                        expected_success = parent.is_none_or(|parent| parents.contains(&parent));
                        if expected_success {
                            *existing_parent = parent;
                        }
                    }
                    let parent = parent.map_or_else(|| "NULL".to_string(), |id| id.to_string());
                    format!(
                        "UPDATE {} SET parent_id = {parent} WHERE id = {child}",
                        CHILD_TABLES[table_index]
                    )
                }
                _ => {
                    let table_index =
                        (next_random(&mut random) % CHILD_TABLES.len() as u64) as usize;
                    let child = 1 + (next_random(&mut random) % 18) as i64;
                    children[table_index].remove(&child);
                    format!(
                        "DELETE FROM {} WHERE id = {child}",
                        CHILD_TABLES[table_index]
                    )
                }
            };

            let actual_success = engine.execute(request(&sql)).is_ok();
            assert_eq!(
                actual_success, expected_success,
                "step {step} diverged for {sql}"
            );
            assert_eq!(
                read_parent_ids(&engine),
                parents,
                "parent state at step {step}"
            );
            for (table_index, table) in CHILD_TABLES.iter().enumerate() {
                assert_eq!(
                    read_children(&engine, table),
                    children[table_index],
                    "child state for {table} at step {step}"
                );
            }

            if (step + 1) % 40 == 0 {
                engine.checkpoint().unwrap();
                drop(engine);
                let journal = TransactionJournal::open(directory.path()).unwrap();
                engine = RelationalEngine::open(directory.path(), journal).unwrap();
            }
        }
    }

    #[test]
    fn deferred_and_match_full_foreign_keys_follow_transaction_semantics() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE composite_parent (a INTEGER, b INTEGER, PRIMARY KEY (a, b))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE composite_child (id INTEGER PRIMARY KEY, a INTEGER, b INTEGER, FOREIGN KEY (a, b) REFERENCES composite_parent MATCH FULL DEFERRABLE INITIALLY DEFERRED)",
            ))
            .unwrap();

        engine
            .execute(SqlExecutionRequest {
                statements: vec![
                    crate::SqlStatementRequest {
                        sql: "INSERT INTO composite_child VALUES (1, 7, 8)".into(),
                        parameters: vec![],
                    },
                    crate::SqlStatementRequest {
                        sql: "INSERT INTO composite_parent VALUES (7, 8)".into(),
                        parameters: vec![],
                    },
                ],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        assert!(
            engine
                .execute(request("INSERT INTO composite_child VALUES (2, NULL, 8)"))
                .is_err()
        );
        engine
            .execute(request(
                "INSERT INTO composite_child VALUES (3, NULL, NULL)",
            ))
            .unwrap();

        engine
            .execute(request(
                "CREATE TABLE immediate_parent (id INTEGER PRIMARY KEY)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE immediate_child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES immediate_parent)",
            ))
            .unwrap();
        assert!(
            engine
                .execute(SqlExecutionRequest {
                    statements: vec![
                        crate::SqlStatementRequest {
                            sql: "INSERT INTO immediate_child VALUES (1, 9)".into(),
                            parameters: vec![],
                        },
                        crate::SqlStatementRequest {
                            sql: "INSERT INTO immediate_parent VALUES (9)".into(),
                            parameters: vec![],
                        },
                    ],
                    idempotency_key: None,
                    retry_id: None,
                })
                .is_err()
        );
    }

    #[test]
    fn restrict_is_immediate_even_when_constraint_is_deferred() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER, FOREIGN KEY (parent_id) REFERENCES parent ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (1, 1)"))
            .unwrap();
        assert!(
            engine
                .execute(SqlExecutionRequest {
                    statements: vec![
                        crate::SqlStatementRequest {
                            sql: "DELETE FROM parent WHERE id = 1".into(),
                            parameters: vec![],
                        },
                        crate::SqlStatementRequest {
                            sql: "DELETE FROM child WHERE id = 1".into(),
                            parameters: vec![],
                        },
                    ],
                    idempotency_key: None,
                    retry_id: None,
                })
                .is_err()
        );
    }

    #[test]
    fn set_constraints_changes_named_and_all_modes_inside_atomic_request() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER, CONSTRAINT child_parent FOREIGN KEY (parent_id) REFERENCES parent DEFERRABLE INITIALLY IMMEDIATE)",
            ))
            .unwrap();

        engine
            .execute(SqlExecutionRequest {
                statements: vec![
                    crate::SqlStatementRequest {
                        sql: "SET CONSTRAINTS child_parent DEFERRED".into(),
                        parameters: vec![],
                    },
                    crate::SqlStatementRequest {
                        sql: "INSERT INTO child VALUES (1, 10)".into(),
                        parameters: vec![],
                    },
                    crate::SqlStatementRequest {
                        sql: "INSERT INTO parent VALUES (10)".into(),
                        parameters: vec![],
                    },
                    crate::SqlStatementRequest {
                        sql: "SET CONSTRAINTS ALL IMMEDIATE".into(),
                        parameters: vec![],
                    },
                ],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();

        assert!(
            engine
                .execute(SqlExecutionRequest {
                    statements: vec![
                        crate::SqlStatementRequest {
                            sql: "SET CONSTRAINTS child_parent DEFERRED".into(),
                            parameters: vec![],
                        },
                        crate::SqlStatementRequest {
                            sql: "INSERT INTO child VALUES (2, 20)".into(),
                            parameters: vec![],
                        },
                        crate::SqlStatementRequest {
                            sql: "SET CONSTRAINTS ALL IMMEDIATE".into(),
                            parameters: vec![],
                        },
                    ],
                    idempotency_key: None,
                    retry_id: None,
                })
                .is_err()
        );
        let analysis =
            RelationalEngine::analyze_statement("SET CONSTRAINTS child_parent DEFERRED;").unwrap();
        assert_eq!(analysis.class, SqlStatementClass::Write);
        assert_eq!(analysis.kind, SqlStatementKind::SetConstraints);
    }

    #[test]
    fn constraint_indexes_track_mutations_recovery_and_point_plans() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER, CONSTRAINT child_parent FOREIGN KEY (parent_id) REFERENCES parent ON UPDATE CASCADE ON DELETE CASCADE)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1), (2)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (10, 1), (11, 1)"))
            .unwrap();

        let plan = engine
            .execute(request("EXPLAIN SELECT id FROM child WHERE id = 10"))
            .unwrap()
            .response;
        assert!(matches!(
            &plan.results[0],
            SqlResult::Explain { plan }
                if plan.iter().any(|line| line == "operator=relational_index_lookup")
        ));
        let scan = engine
            .execute(request("EXPLAIN SELECT id FROM child WHERE parent_id > 0"))
            .unwrap()
            .response;
        assert!(matches!(
            &scan.results[0],
            SqlResult::Explain { plan }
                if plan.iter().any(|line| line == "operator=relational_scan")
        ));

        engine
            .execute(request("UPDATE parent SET id = 3 WHERE id = 1"))
            .unwrap();
        let cascaded = engine
            .execute(request(
                "SELECT id FROM child WHERE parent_id = 3 ORDER BY id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &cascaded.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(10)],
                    vec![RelationalValue::Integer(11)],
                ]
        ));
        engine
            .execute(request("DELETE FROM parent WHERE id = 3"))
            .unwrap();
        let state = engine.state.read();
        let child = state.tables.get("child").unwrap();
        assert!(
            child
                .indexes
                .get(&vec!["parent_id".into()])
                .unwrap()
                .entries(&child.index_segments, child.index_snapshot, None)
                .unwrap()
                .next()
                .is_none()
        );
        drop(state);

        drop(engine);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let state = reopened.state.read();
        let parent = state.tables.get("parent").unwrap();
        let child = state.tables.get("child").unwrap();
        assert_eq!(
            parent
                .indexes
                .get(&vec!["id".into()])
                .unwrap()
                .entries(&parent.index_segments, parent.index_snapshot, None)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            1
        );
        assert!(
            child
                .indexes
                .get(&vec!["parent_id".into()])
                .unwrap()
                .entries(&child.index_segments, child.index_snapshot, None)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn interactive_commit_identity_survives_racing_retries_and_reopen() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE retry_commit (id BIGINT PRIMARY KEY)"))
            .unwrap();
        let owner = audit("commit-owner");
        let transaction = engine.begin_interactive(&owner).unwrap();
        assert_eq!(
            transaction.transaction_id.as_deref(),
            Some(transaction.handle.as_str())
        );
        let private = engine
            .execute_interactive(
                &transaction.handle,
                request("INSERT INTO retry_commit VALUES (1)"),
                &owner,
            )
            .unwrap();
        assert_eq!(private.transaction_id, transaction.transaction_id);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let replies = std::thread::scope(|scope| {
            let workers = (0..8)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let engine = Arc::clone(&engine);
                    let owner = owner.clone();
                    let handle = transaction.handle.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        engine.commit_interactive(&handle, &owner).unwrap().response
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(replies.iter().all(|reply| reply == &replies[0]));
        assert_eq!(replies[0].transaction_id, transaction.transaction_id);
        assert_eq!(journal.committed().unwrap().len(), 2);
        assert!(
            engine
                .commit_interactive(&transaction.handle, &audit("other-owner"))
                .is_err()
        );
        let mut other_tenant = owner.clone();
        other_tenant.tenant_id = Some("different-tenant".into());
        assert!(
            engine
                .commit_interactive(&transaction.handle, &other_tenant)
                .is_err()
        );
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        assert_eq!(
            engine
                .commit_interactive(&transaction.handle, &owner)
                .unwrap()
                .response,
            replies[0]
        );
        assert_eq!(journal.committed().unwrap().len(), 2);
        let rows = engine
            .execute(request("SELECT COUNT(*) FROM retry_commit"))
            .unwrap()
            .response;
        assert!(matches!(&rows.results[0], SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Integer(1)]]));
    }

    #[test]
    fn empty_read_only_and_zero_row_interactive_commits_keep_one_decision() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE empty_commit (id BIGINT PRIMARY KEY)"))
            .unwrap();
        let owner = audit("owner");
        for sql in [
            None,
            Some("SELECT COUNT(*) FROM empty_commit"),
            Some("DELETE FROM empty_commit WHERE id = 1"),
        ] {
            let transaction = engine.begin_interactive(&owner).unwrap();
            if let Some(sql) = sql {
                engine
                    .execute_interactive(&transaction.handle, request(sql), &owner)
                    .unwrap();
            }
            let first = engine
                .commit_interactive(&transaction.handle, &owner)
                .unwrap()
                .response;
            assert_eq!(first.transaction_id, transaction.transaction_id);
            assert!(first.committed);
            assert!(first.results.is_empty());
            assert_eq!(
                engine
                    .commit_interactive(&transaction.handle, &owner)
                    .unwrap()
                    .response,
                first
            );
        }
        assert_eq!(journal.committed().unwrap().len(), 4);
        let rolled_back = engine.begin_interactive(&owner).unwrap();
        engine
            .rollback_interactive(&rolled_back.handle, &owner)
            .unwrap();
        assert!(
            engine
                .commit_interactive(&rolled_back.handle, &owner)
                .is_err()
        );
        assert_eq!(journal.committed().unwrap().len(), 4);
    }

    #[test]
    fn interactive_transaction_has_private_writes_deferred_fk_and_atomic_commit() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        let context = audit("alice");
        let transaction = engine.begin_interactive(&context).unwrap();

        engine
            .execute_interactive(
                &transaction.handle,
                request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"),
                &context,
            )
            .unwrap();
        engine
            .execute_interactive(
                &transaction.handle,
                request(
                    "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER, CONSTRAINT child_parent FOREIGN KEY (parent_id) REFERENCES parent DEFERRABLE INITIALLY DEFERRED)",
                ),
                &context,
            )
            .unwrap();
        engine
            .execute_interactive(
                &transaction.handle,
                request("INSERT INTO child VALUES (1, 9)"),
                &context,
            )
            .unwrap();
        engine
            .execute_interactive(
                &transaction.handle,
                request("INSERT INTO parent VALUES (9)"),
                &context,
            )
            .unwrap();
        let private = engine
            .execute_interactive(
                &transaction.handle,
                request("SELECT parent_id FROM child WHERE id = 1"),
                &context,
            )
            .unwrap();
        assert!(!private.committed);
        assert!(matches!(
            &private.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(9)]]
        ));
        assert!(engine.execute(request("SELECT * FROM child")).is_err());

        let committed = engine
            .commit_interactive(&transaction.handle, &context)
            .unwrap();
        assert!(committed.response.committed);
        assert!(committed.response.transaction_id.is_some());
        let visible = engine
            .execute(request("SELECT parent_id FROM child WHERE id = 1"))
            .unwrap()
            .response;
        assert!(matches!(
            &visible.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(9)]]
        ));
    }

    #[test]
    fn cancellation_rejects_autocommit_before_mutation_becomes_durable() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE cancelled_writes (id INTEGER PRIMARY KEY)",
            ))
            .unwrap();

        let cancellation = Arc::new(AtomicBool::new(true));
        let error = engine
            .execute_with_audit_cancellable(
                request("INSERT INTO cancelled_writes VALUES (1)"),
                &AuditContext::embedded(),
                cancellation,
            )
            .err()
            .expect("a cancelled statement must not execute");
        assert_eq!(error.to_string(), "invalid request: query canceled");

        let visible = engine
            .execute(request("SELECT COUNT(*) FROM cancelled_writes"))
            .unwrap()
            .response;
        assert!(matches!(
            &visible.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));
    }

    #[test]
    fn cancelled_interactive_commit_keeps_session_reconcilable() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE commit_cancel (id INTEGER PRIMARY KEY)",
            ))
            .unwrap();
        let context = audit("cancel-owner");
        let transaction = engine.begin_interactive(&context).unwrap();
        engine
            .execute_interactive(
                &transaction.handle,
                request("INSERT INTO commit_cancel VALUES (1)"),
                &context,
            )
            .unwrap();

        let cancellation = Arc::new(AtomicBool::new(true));
        let error = engine
            .commit_interactive_cancellable(
                &transaction.handle,
                &context,
                Arc::clone(&cancellation),
            )
            .err()
            .expect("cancellation before commit must reject the commit");
        assert_eq!(error.to_string(), "invalid request: query canceled");
        let not_visible = engine
            .execute(request("SELECT COUNT(*) FROM commit_cancel"))
            .unwrap()
            .response;
        assert!(matches!(
            &not_visible.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));

        cancellation.store(false, AtomicOrdering::Release);
        let committed = engine
            .commit_interactive_cancellable(&transaction.handle, &context, cancellation)
            .unwrap();
        assert!(committed.response.committed);
        let visible = engine
            .execute(request("SELECT COUNT(*) FROM commit_cancel"))
            .unwrap()
            .response;
        assert!(matches!(
            &visible.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
    }

    #[test]
    fn active_snapshot_pins_bound_mvcc_garbage_collection() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO items VALUES (1, 'old')"))
            .unwrap();

        let context = audit("snapshot-owner");
        let transaction = engine.begin_interactive(&context).unwrap();
        assert_eq!(engine.snapshots.active_count(), 1);
        engine
            .execute(request("UPDATE items SET name = 'new' WHERE id = 1"))
            .unwrap();
        assert_eq!(
            engine.state.read().tables["items"]
                .rows
                .get(&1)
                .unwrap()
                .unwrap()
                .len(),
            2,
            "the version visible to an active snapshot must remain resident"
        );
        let old = engine
            .execute_interactive(
                &transaction.handle,
                request("SELECT name FROM items WHERE id = 1"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("old".into())]]
        ));
        engine
            .rollback_interactive(&transaction.handle, &context)
            .unwrap();
        assert_eq!(engine.snapshots.active_count(), 0);
        assert_eq!(
            engine.state.read().tables["items"]
                .rows
                .get(&1)
                .unwrap()
                .unwrap()
                .len(),
            1
        );

        let transaction = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request("DELETE FROM items WHERE id = 1"))
            .unwrap();
        let old = engine
            .execute_interactive(
                &transaction.handle,
                request("SELECT name FROM items WHERE id = 1"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("new".into())]]
        ));
        engine
            .rollback_interactive(&transaction.handle, &context)
            .unwrap();
        assert!(engine.state.read().tables["items"].rows.is_empty());

        engine
            .execute(request("INSERT INTO items VALUES (2, 'before commit')"))
            .unwrap();
        let transaction = engine.begin_interactive(&context).unwrap();
        engine
            .execute_interactive(
                &transaction.handle,
                request("UPDATE items SET name = 'after commit' WHERE id = 2"),
                &context,
            )
            .unwrap();
        engine
            .commit_interactive(&transaction.handle, &context)
            .unwrap();
        assert_eq!(engine.snapshots.active_count(), 0);
        assert_eq!(
            engine.state.read().tables["items"]
                .rows
                .get(&2)
                .unwrap()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn non_conflicting_row_writers_rebase_but_same_row_writers_conflict() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO items VALUES (1, 'one'), (2, 'two')"))
            .unwrap();

        let context = audit("concurrent-writer");
        let first = engine.begin_interactive(&context).unwrap();
        let second = engine.begin_interactive(&context).unwrap();
        assert_eq!(first.snapshot, second.snapshot);
        engine
            .execute_interactive(
                &first.handle,
                request("UPDATE items SET name = 'first' WHERE id = 1"),
                &context,
            )
            .unwrap();
        engine
            .execute_interactive(
                &second.handle,
                request("UPDATE items SET name = 'second' WHERE id = 2"),
                &context,
            )
            .unwrap();
        engine.commit_interactive(&first.handle, &context).unwrap();
        engine
            .commit_interactive(&second.handle, &context)
            .expect("different row write sets can rebase");

        let first = engine.begin_interactive(&context).unwrap();
        let second = engine.begin_interactive(&context).unwrap();
        engine
            .execute_interactive(
                &first.handle,
                request("UPDATE items SET name = 'winner' WHERE id = 1"),
                &context,
            )
            .unwrap();
        engine
            .execute_interactive(
                &second.handle,
                request("DELETE FROM items WHERE id = 1"),
                &context,
            )
            .unwrap();
        engine.commit_interactive(&first.handle, &context).unwrap();
        let conflict = match engine.commit_interactive(&second.handle, &context) {
            Ok(_) => panic!("same-row writer must lose first-committer-wins validation"),
            Err(error) => error,
        };
        assert!(conflict.to_string().contains("serialization conflict"));

        let rows = engine
            .execute(request("SELECT id, name FROM items ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(
            &rows.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![
                        RelationalValue::Integer(1),
                        RelationalValue::Text("winner".into()),
                    ],
                    vec![
                        RelationalValue::Integer(2),
                        RelationalValue::Text("second".into()),
                    ],
                ]
        ));

        let first = engine.begin_interactive(&context).unwrap();
        let second = engine.begin_interactive(&context).unwrap();
        engine
            .execute_interactive(
                &first.handle,
                request("INSERT INTO items VALUES (3, 'three')"),
                &context,
            )
            .unwrap();
        engine
            .execute_interactive(
                &second.handle,
                request("INSERT INTO items VALUES (4, 'four')"),
                &context,
            )
            .unwrap();
        engine.commit_interactive(&first.handle, &context).unwrap();
        engine
            .commit_interactive(&second.handle, &context)
            .expect("different-key inserts receive distinct commit-time row identities");

        let first = engine.begin_interactive(&context).unwrap();
        let second = engine.begin_interactive(&context).unwrap();
        engine
            .execute_interactive(
                &first.handle,
                request("INSERT INTO items VALUES (5, 'duplicate')"),
                &context,
            )
            .unwrap();
        engine
            .execute_interactive(
                &second.handle,
                request("INSERT INTO items VALUES (6, 'duplicate')"),
                &context,
            )
            .unwrap();
        engine.commit_interactive(&first.handle, &context).unwrap();
        let unique_conflict = match engine.commit_interactive(&second.handle, &context) {
            Ok(_) => panic!("stale insert must revalidate the latest unique index"),
            Err(error) => error,
        };
        assert!(unique_conflict.to_string().contains("unique constraint"));
    }

    #[test]
    fn interactive_transaction_is_owner_bound_and_rebases_nonconflicting_insert() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
            .unwrap();
        let alice = audit("alice");
        let bob = audit("bob");
        let transaction = engine.begin_interactive(&alice).unwrap();
        assert!(
            engine
                .execute_interactive(
                    &transaction.handle,
                    request("INSERT INTO items VALUES (1)"),
                    &bob,
                )
                .is_err()
        );
        engine
            .execute_interactive(
                &transaction.handle,
                request("INSERT INTO items VALUES (1)"),
                &alice,
            )
            .unwrap();
        engine
            .execute(request("INSERT INTO items VALUES (2)"))
            .unwrap();
        engine
            .commit_interactive(&transaction.handle, &alice)
            .expect("different primary keys can commit from one snapshot");

        let rollback = engine.begin_interactive(&alice).unwrap();
        engine
            .execute_interactive(&rollback.handle, request("SAVEPOINT before_change"), &alice)
            .unwrap();
        engine
            .execute_interactive(
                &rollback.handle,
                request("INSERT INTO items VALUES (3)"),
                &alice,
            )
            .unwrap();
        assert!(
            engine
                .execute_interactive(
                    &rollback.handle,
                    request("INSERT INTO items VALUES (3)"),
                    &alice,
                )
                .is_err()
        );
        engine
            .execute_interactive(
                &rollback.handle,
                request("ROLLBACK TO SAVEPOINT before_change"),
                &alice,
            )
            .unwrap();
        engine
            .execute_interactive(
                &rollback.handle,
                request("INSERT INTO items VALUES (4)"),
                &alice,
            )
            .unwrap();
        let rolled_back = engine
            .rollback_interactive(&rollback.handle, &alice)
            .unwrap();
        assert_eq!(rolled_back.state, SqlTransactionState::RolledBack);
        let count = engine
            .execute(request("SELECT COUNT(*) FROM items"))
            .unwrap()
            .response;
        assert!(matches!(
            &count.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(2)]]
        ));
    }

    #[test]
    fn alter_table_validates_existing_rows_and_persists_foreign_key_catalog() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (1, 9)"))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE child ADD CONSTRAINT child_parent FOREIGN KEY (parent_id) REFERENCES parent(id)",
                ))
                .is_err()
        );
        assert!(
            engine
                .table_definitions()
                .iter()
                .find(|table| table.name == "child")
                .unwrap()
                .foreign_keys
                .is_empty()
        );

        engine
            .execute(request("INSERT INTO parent VALUES (9)"))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE child ADD CONSTRAINT child_parent FOREIGN KEY (parent_id) REFERENCES parent(id) ON DELETE CASCADE",
            ))
            .unwrap();
        assert_eq!(
            engine
                .table_definitions()
                .iter()
                .find(|table| table.name == "child")
                .unwrap()
                .foreign_keys[0]
                .name
                .as_deref(),
            Some("child_parent")
        );
        engine
            .execute(request("ALTER TABLE child DROP CONSTRAINT child_parent"))
            .unwrap();
        engine
            .execute(request("DELETE FROM parent WHERE id = 9"))
            .unwrap();

        drop(engine);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let child = reopened
            .table_definitions()
            .into_iter()
            .find(|table| table.name == "child")
            .unwrap();
        assert!(child.foreign_keys.is_empty());
        assert_eq!(
            RelationalEngine::analyze_statement(
                "ALTER TABLE child ADD FOREIGN KEY (parent_id) REFERENCES parent(id)"
            )
            .unwrap()
            .kind,
            SqlStatementKind::AlterTable
        );
    }

    #[test]
    fn insert_returning_and_on_conflict_do_nothing_use_unique_indexes() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, CONSTRAINT users_email_key UNIQUE (email))",
            ))
            .unwrap();
        let inserted = engine
            .execute(request(
                "INSERT INTO users VALUES (1, 'a@example.test') RETURNING id, email",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &inserted.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Text("a@example.test".into()),
                ]]
        ));
        let ignored = engine
            .execute(request(
                "INSERT INTO users VALUES (2, 'a@example.test') ON CONFLICT ON CONSTRAINT users_email_key DO NOTHING RETURNING id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &ignored.results[0],
            SqlResult::Rows { rows, .. } if rows.is_empty()
        ));
        let count = engine
            .execute(request("SELECT COUNT(*) FROM users"))
            .unwrap()
            .response;
        assert!(matches!(
            &count.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
        let updated = engine
            .execute(request(
                "UPDATE users SET email = 'b@example.test' WHERE id = 1 RETURNING email",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &updated.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("b@example.test".into())]]
        ));
        let deleted = engine
            .execute(request("DELETE FROM users WHERE id = 1 RETURNING id"))
            .unwrap()
            .response;
        assert!(matches!(
            &deleted.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
    }

    #[test]
    fn on_conflict_do_update_supports_excluded_where_returning_fk_and_recovery() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL, visits INTEGER NOT NULL, freshness INTEGER NOT NULL, CONSTRAINT accounts_email_key UNIQUE (email))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE account_events (id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL, CONSTRAINT account_events_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON UPDATE CASCADE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO accounts VALUES (1, 'a@example.test', 'old', 1, 10)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO account_events VALUES (10, 1)"))
            .unwrap();

        let updated = engine
            .execute(request(
                "INSERT INTO accounts VALUES (1, 'a@example.test', 'new', 2, 20) ON CONFLICT ON CONSTRAINT accounts_pkey DO UPDATE SET name = excluded.name, visits = accounts.visits + excluded.visits, freshness = excluded.freshness WHERE accounts.freshness < excluded.freshness RETURNING id, name, visits, freshness",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &updated.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Text("new".into()),
                    RelationalValue::Integer(3),
                    RelationalValue::Integer(20),
                ]]
        ));

        let skipped = engine
            .execute(request(
                "INSERT INTO accounts VALUES (1, 'a@example.test', 'stale', 100, 15) ON CONFLICT (id) DO UPDATE SET name = excluded.name, visits = visits + excluded.visits, freshness = excluded.freshness WHERE freshness < excluded.freshness RETURNING id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &skipped.results[0],
            SqlResult::Rows { rows, .. } if rows.is_empty()
        ));

        let inserted = engine
            .execute(request(
                "INSERT INTO accounts VALUES (2, 'b@example.test', 'second', 1, 5) ON CONFLICT (id) DO UPDATE SET name = excluded.name RETURNING id, name",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &inserted.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(2),
                    RelationalValue::Text("second".into()),
                ]]
        ));

        let duplicate = match engine.execute(request(
            "INSERT INTO accounts VALUES (1, 'a@example.test', 'first', 1, 30), (1, 'a@example.test', 'second', 1, 40) ON CONFLICT (id) DO UPDATE SET name = excluded.name, freshness = excluded.freshness",
        )) {
            Ok(_) => panic!("duplicate upsert must fail"),
            Err(error) => error,
        };
        assert!(
            duplicate
                .to_string()
                .contains("cannot affect row a second time")
        );
        let unchanged = engine
            .execute(request(
                "SELECT name, visits, freshness FROM accounts WHERE id = 1",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &unchanged.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Text("new".into()),
                    RelationalValue::Integer(3),
                    RelationalValue::Integer(20),
                ]]
        ));

        let moved = engine
            .execute(request(
                "INSERT INTO accounts VALUES (5, 'a@example.test', 'moved', 4, 50) ON CONFLICT ON CONSTRAINT accounts_email_key DO UPDATE SET id = excluded.id, name = excluded.name, visits = visits + excluded.visits, freshness = excluded.freshness RETURNING id, visits",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &moved.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(5),
                    RelationalValue::Integer(7),
                ]]
        ));
        let cascaded = engine
            .execute(request(
                "SELECT account_id FROM account_events WHERE id = 10",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &cascaded.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(5)]]
        ));

        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened
            .execute(request(
                "SELECT id, name, visits, freshness FROM accounts ORDER BY id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &recovered.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![
                        RelationalValue::Integer(2),
                        RelationalValue::Text("second".into()),
                        RelationalValue::Integer(1),
                        RelationalValue::Integer(5),
                    ],
                    vec![
                        RelationalValue::Integer(5),
                        RelationalValue::Text("moved".into()),
                        RelationalValue::Integer(7),
                        RelationalValue::Integer(50),
                    ],
                ]
        ));

        reopened
            .execute(request(
                "CREATE TABLE composite_upsert (a INTEGER, b INTEGER, value TEXT, CONSTRAINT composite_upsert_key UNIQUE (a, b))",
            ))
            .unwrap();
        reopened
            .execute(request("INSERT INTO composite_upsert VALUES (1, 2, 'old')"))
            .unwrap();
        let inferred = reopened
            .execute(request(
                "INSERT INTO composite_upsert VALUES (1, 2, 'new') ON CONFLICT (b, a) DO UPDATE SET value = excluded.value RETURNING value",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &inferred.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("new".into())]]
        ));
        reopened
            .execute(request(
                "CREATE UNIQUE INDEX composite_upsert_value_idx ON composite_upsert (value)",
            ))
            .unwrap();
        let plain_index = match reopened.execute(request(
            "INSERT INTO composite_upsert VALUES (3, 4, 'new') ON CONFLICT ON CONSTRAINT composite_upsert_value_idx DO NOTHING",
        )) {
            Ok(_) => panic!("ON CONSTRAINT must not resolve a plain unique index"),
            Err(error) => error,
        };
        assert!(
            plain_index
                .to_string()
                .contains("unique constraint composite_upsert_value_idx does not exist")
        );
    }

    #[test]
    fn orm_scalar_types_enforce_bounds_round_trip_and_recover() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE orm_types (id INTEGER PRIMARY KEY, small_value SMALLINT, large_value BIGINT, real_value REAL, double_value DOUBLE PRECISION, limited VARCHAR(5), bytes_value BYTEA, date_value DATE, payload JSONB)",
            ))
            .unwrap();
        let inserted = engine
            .execute(request(
                "INSERT INTO orm_types VALUES (1, 32767, 9223372036854775807, 1.25, 2.5, 'abcde', '\\x00ff', '2026-09-17', '{\"answer\":42}') RETURNING small_value, large_value, real_value, double_value, limited, bytes_value, date_value, payload",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &inserted.results[0],
            SqlResult::Rows { column_types, rows, .. }
                if column_types == &vec![
                    RelationalType::SmallInt,
                    RelationalType::BigInt,
                    RelationalType::Real,
                    RelationalType::Float,
                    RelationalType::Varchar { length: 5 },
                    RelationalType::Bytea,
                    RelationalType::Date,
                    RelationalType::Jsonb,
                ] && rows == &vec![vec![
                    RelationalValue::Integer(32767),
                    RelationalValue::Integer(i64::MAX),
                    RelationalValue::Float(1.25),
                    RelationalValue::Float(2.5),
                    RelationalValue::Text("abcde".into()),
                    RelationalValue::Bytes(vec![0, 255]),
                    RelationalValue::Date("2026-09-17".into()),
                    RelationalValue::Json(serde_json::json!({"answer": 42})),
                ]]
        ));

        for (sql, expected) in [
            (
                "INSERT INTO orm_types (id, small_value) VALUES (2, 32768)",
                "SMALLINT value is out of range",
            ),
            (
                "INSERT INTO orm_types (id) VALUES (2147483648)",
                "INTEGER value is out of range",
            ),
            (
                "INSERT INTO orm_types (id, limited) VALUES (3, 'abcdef')",
                "VARCHAR(5) value is too long",
            ),
            (
                "INSERT INTO orm_types (id, bytes_value) VALUES (4, '\\x0')",
                "BYTEA hex input must contain complete bytes",
            ),
            (
                "INSERT INTO orm_types (id, date_value) VALUES (5, '2026-02-30')",
                "date must use YYYY-MM-DD",
            ),
            (
                "INSERT INTO orm_types (id, payload) VALUES (6, '{invalid')",
                "JSONB string must be valid JSON",
            ),
        ] {
            let error = match engine.execute(request(sql)) {
                Ok(_) => panic!("invalid typed value must fail: {sql}"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "unexpected error for {sql}: {error}"
            );
        }

        drop(engine);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened
            .execute(request(
                "SELECT bytes_value, date_value, payload FROM orm_types WHERE id = 1",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &recovered.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Bytes(vec![0, 255]),
                    RelationalValue::Date("2026-09-17".into()),
                    RelationalValue::Json(serde_json::json!({"answer": 42})),
                ]]
        ));
    }

    #[test]
    fn grouping_aggregates_having_order_and_empty_input_follow_sql_semantics() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE sales (id INTEGER PRIMARY KEY, region TEXT NOT NULL, amount INTEGER, score DOUBLE PRECISION)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO sales VALUES (1, 'east', 10, 1.0), (2, 'east', 20, 3.0), (3, 'east', NULL, 2.0), (4, 'west', 5, 4.0), (5, 'west', NULL, NULL)",
            ))
            .unwrap();
        let grouped = engine
            .execute(SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "SELECT region, COUNT(*) AS rows, COUNT(amount) AS valued, SUM(amount) AS total, AVG(amount) AS average, MIN(amount) AS low, MAX(amount) AS high FROM sales GROUP BY region HAVING SUM(amount) >= $1 ORDER BY total DESC LIMIT 2".into(),
                    parameters: vec![RelationalValue::Integer(10)],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap()
            .response;
        assert!(matches!(
            &grouped.results[0],
            SqlResult::Rows { columns, column_types, rows }
                if columns == &vec!["region", "rows", "valued", "total", "average", "low", "high"]
                    && column_types == &vec![
                        RelationalType::Text,
                        RelationalType::BigInt,
                        RelationalType::BigInt,
                        RelationalType::BigInt,
                        RelationalType::Float,
                        RelationalType::Integer,
                        RelationalType::Integer,
                    ]
                    && rows == &vec![vec![
                        RelationalValue::Text("east".into()),
                        RelationalValue::Integer(3),
                        RelationalValue::Integer(2),
                        RelationalValue::Integer(30),
                        RelationalValue::Float(15.0),
                        RelationalValue::Integer(10),
                        RelationalValue::Integer(20),
                    ]]
        ));

        let empty = engine
            .execute(request(
                "SELECT COUNT(*) AS rows, SUM(amount) AS total, AVG(amount) AS average, MIN(amount) AS low, MAX(amount) AS high FROM sales WHERE id > 100",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &empty.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(0),
                    RelationalValue::Null,
                    RelationalValue::Null,
                    RelationalValue::Null,
                    RelationalValue::Null,
                ]]
        ));

        let distinct_groups = engine
            .execute(request(
                "SELECT region FROM sales GROUP BY region ORDER BY region",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &distinct_groups.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Text("east".into())],
                    vec![RelationalValue::Text("west".into())],
                ]
        ));

        let invalid_group = match engine.execute(request(
            "SELECT id, region, SUM(amount) FROM sales GROUP BY region",
        )) {
            Ok(_) => panic!("ungrouped selected column must fail"),
            Err(error) => error,
        };
        assert!(
            invalid_group
                .to_string()
                .contains("must appear in GROUP BY")
        );
    }

    #[test]
    fn select_distinct_deduplicates_typed_rows_before_offset_and_limit() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE distinct_items (id INTEGER PRIMARY KEY, category TEXT, score INTEGER)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO distinct_items VALUES (1, 'a', 10), (2, 'a', 10), (3, 'b', 20), (4, NULL, 30), (5, NULL, 40)",
            ))
            .unwrap();

        let distinct = engine
            .execute(request(
                "SELECT DISTINCT category FROM distinct_items ORDER BY category NULLS LAST LIMIT 2 OFFSET 1",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &distinct.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Text("b".into())],
                    vec![RelationalValue::Null],
                ]
        ));

        let explicit_all = engine
            .execute(request(
                "SELECT ALL category FROM distinct_items WHERE category = 'a' ORDER BY category",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &explicit_all.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Text("a".into())],
                    vec![RelationalValue::Text("a".into())],
                ]
        ));

        engine
            .execute(request(
                "CREATE TABLE distinct_labels (code TEXT PRIMARY KEY, label TEXT NOT NULL)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO distinct_labels VALUES ('a', 'Alpha'), ('b', 'Beta')",
            ))
            .unwrap();
        let joined = engine
            .execute(request(
                "SELECT DISTINCT l.label FROM distinct_items i INNER JOIN distinct_labels l ON l.code = i.category ORDER BY l.label",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &joined.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Text("Alpha".into())],
                    vec![RelationalValue::Text("Beta".into())],
                ]
        ));

        let grouped = engine
            .execute(request(
                "SELECT DISTINCT COUNT(*) AS size FROM distinct_items GROUP BY category ORDER BY size",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &grouped.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1)],
                    vec![RelationalValue::Integer(2)],
                ]
        ));

        let missing_order_column = match engine.execute(request(
            "SELECT DISTINCT category FROM distinct_items ORDER BY score",
        )) {
            Ok(_) => panic!("DISTINCT must reject an ORDER BY-only source column"),
            Err(error) => error,
        };
        assert!(
            missing_order_column
                .to_string()
                .contains("ORDER BY expressions must appear in select list")
        );
        let distinct_on = match engine.execute(request(
            "SELECT DISTINCT ON (category) category FROM distinct_items ORDER BY category",
        )) {
            Ok(_) => panic!("DISTINCT ON must remain outside the v1 contract"),
            Err(error) => error,
        };
        assert!(distinct_on.to_string().contains("DISTINCT ON"));
    }

    #[test]
    fn order_by_accepts_postgresql_output_positions_and_aliases() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE ordered_items (id INTEGER PRIMARY KEY, category TEXT NOT NULL, score INTEGER NOT NULL)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO ordered_items VALUES (1, 'b', 20), (2, 'a', 10), (3, 'c', 10), (4, 'a', 10)",
            ))
            .unwrap();

        let positioned = engine
            .execute(request(
                "SELECT category AS label, score FROM ordered_items ORDER BY 2 ASC, 1 DESC",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &positioned.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Text("c".into()), RelationalValue::Integer(10)],
                    vec![RelationalValue::Text("a".into()), RelationalValue::Integer(10)],
                    vec![RelationalValue::Text("a".into()), RelationalValue::Integer(10)],
                    vec![RelationalValue::Text("b".into()), RelationalValue::Integer(20)],
                ]
        ));

        let aliased = engine
            .execute(request(
                "SELECT category AS label FROM ordered_items ORDER BY label DESC, id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &aliased.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Text("c".into())],
                    vec![RelationalValue::Text("b".into())],
                    vec![RelationalValue::Text("a".into())],
                    vec![RelationalValue::Text("a".into())],
                ]
        ));

        let distinct = engine
            .execute(request(
                "SELECT DISTINCT category AS label FROM ordered_items ORDER BY 1 DESC",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &distinct.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Text("c".into())],
                    vec![RelationalValue::Text("b".into())],
                    vec![RelationalValue::Text("a".into())],
                ]
        ));

        let grouped = engine
            .execute(request(
                "SELECT category, COUNT(*) AS size FROM ordered_items GROUP BY category ORDER BY 2 DESC, 1 ASC",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &grouped.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Text("a".into()), RelationalValue::Integer(2)],
                    vec![RelationalValue::Text("b".into()), RelationalValue::Integer(1)],
                    vec![RelationalValue::Text("c".into()), RelationalValue::Integer(1)],
                ]
        ));

        let having_literal = engine
            .execute(request(
                "SELECT category, COUNT(*) AS size FROM ordered_items GROUP BY category HAVING COUNT(*) > 1 ORDER BY 2 DESC",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &having_literal.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Text("a".into()),
                    RelationalValue::Integer(2),
                ]]
        ));

        for sql in [
            "SELECT category, score FROM ordered_items ORDER BY 0",
            "SELECT category, score FROM ordered_items ORDER BY 3",
        ] {
            let error = match engine.execute(request(sql)) {
                Ok(_) => panic!("invalid ORDER BY position must fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("is not in select list"));
        }
    }

    #[test]
    fn aggregate_distinct_deduplicates_non_null_typed_values() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE aggregate_distinct (id INTEGER PRIMARY KEY, amount INTEGER)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO aggregate_distinct VALUES (1, 10), (2, 10), (3, 20), (4, NULL)",
            ))
            .unwrap();

        let response = engine
            .execute(request(
                "SELECT COUNT(ALL amount) AS all_count, COUNT(DISTINCT amount) AS distinct_count, SUM(DISTINCT amount) AS total, AVG(DISTINCT amount) AS average, MIN(DISTINCT amount) AS low, MAX(DISTINCT amount) AS high FROM aggregate_distinct",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { column_types, rows, .. }
                if column_types == &vec![
                    RelationalType::BigInt,
                    RelationalType::BigInt,
                    RelationalType::BigInt,
                    RelationalType::Float,
                    RelationalType::Integer,
                    RelationalType::Integer,
                ] && rows == &vec![vec![
                    RelationalValue::Integer(3),
                    RelationalValue::Integer(2),
                    RelationalValue::Integer(30),
                    RelationalValue::Float(15.0),
                    RelationalValue::Integer(10),
                    RelationalValue::Integer(20),
                ]]
        ));

        let invalid =
            match engine.execute(request("SELECT COUNT(DISTINCT *) FROM aggregate_distinct")) {
                Ok(_) => panic!("COUNT(DISTINCT *) must be rejected"),
                Err(error) => error,
            };
        assert!(invalid.to_string().contains("name a column"));
    }

    #[test]
    fn in_between_not_and_boolean_predicates_preserve_three_valued_logic() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE predicate_items (id INTEGER PRIMARY KEY, category TEXT CHECK (category IN ('a', 'b')), score INTEGER CHECK (score BETWEEN 0 AND 100), active BOOLEAN)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO predicate_items VALUES (1, 'a', 10, TRUE), (2, 'a', 50, FALSE), (3, NULL, NULL, NULL), (4, 'b', 90, TRUE)",
            ))
            .unwrap();

        let selected = engine
            .execute(request(
                "SELECT id FROM predicate_items WHERE id IN (1, 3, NULL) ORDER BY id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &selected.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1)],
                    vec![RelationalValue::Integer(3)],
                ]
        ));
        let unknown_not_in = engine
            .execute(request(
                "SELECT id FROM predicate_items WHERE id NOT IN (1, NULL) ORDER BY id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &unknown_not_in.results[0],
            SqlResult::Rows { rows, .. } if rows.is_empty()
        ));

        let updated = engine
            .execute(request(
                "UPDATE predicate_items SET category = 'b' WHERE score BETWEEN 10 AND 20 AND active RETURNING id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &updated.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
        let deleted = engine
            .execute(request(
                "DELETE FROM predicate_items WHERE score NOT BETWEEN 0 AND 80 RETURNING id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &deleted.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(4)]]
        ));

        let invalid_check = match engine.execute(request(
            "INSERT INTO predicate_items VALUES (5, 'c', 101, TRUE)",
        )) {
            Ok(_) => panic!("IN/BETWEEN checks must reject invalid data"),
            Err(error) => error,
        };
        assert!(invalid_check.to_string().contains("check constraint"));
        let negated = engine
            .execute(request(
                "SELECT id FROM predicate_items WHERE NOT active ORDER BY id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &negated.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(2)]]
        ));
    }

    #[test]
    fn typed_literal_and_parameter_casts_validate_before_mutation() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE cast_items (id BIGINT PRIMARY KEY, code VARCHAR(5))",
            ))
            .unwrap();
        engine
            .execute(SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "INSERT INTO cast_items VALUES ($1::INTEGER, CAST($2 AS VARCHAR(5)))"
                        .into(),
                    parameters: vec![
                        RelationalValue::Integer(7),
                        RelationalValue::Text("seven".into()),
                    ],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        let selected = engine
            .execute(SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "SELECT id, code FROM cast_items WHERE id = CAST($1 AS BIGINT)".into(),
                    parameters: vec![RelationalValue::Text("7".into())],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap()
            .response;
        assert!(matches!(
            &selected.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(7),
                    RelationalValue::Text("seven".into()),
                ]]
        ));
        assert!(
            engine
                .execute(request(
                    "INSERT INTO cast_items VALUES (CAST(40000 AS SMALLINT), 'bad')",
                ))
                .is_err()
        );
        let count = engine
            .execute(request("SELECT COUNT(*) FROM cast_items"))
            .unwrap()
            .response;
        assert!(matches!(
            &count.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
    }

    #[test]
    fn generated_identity_defaults_return_and_recover_from_row_frontier() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE identity_items (id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT NOT NULL)",
            ))
            .unwrap();
        let generated = engine
            .execute(request(
                "INSERT INTO identity_items (name) VALUES ('one'), ('two') RETURNING id, name",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &generated.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1), RelationalValue::Text("one".into())],
                    vec![RelationalValue::Integer(2), RelationalValue::Text("two".into())],
                ]
        ));
        engine
            .execute(request(
                "INSERT INTO identity_items (id, name) VALUES (10, 'explicit')",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE always_items (id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT)",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "INSERT INTO always_items (id, name) VALUES (9, 'rejected')",
                ))
                .is_err()
        );
        engine
            .execute(request(
                "INSERT INTO always_items (name) VALUES ('generated')",
            ))
            .unwrap();
        let explicit_default = engine
            .execute(request(
                "INSERT INTO always_items (id, name) VALUES (DEFAULT, 'default keyword') RETURNING id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &explicit_default.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(2)]]
        ));
        engine
            .execute(request(
                "CREATE TABLE default_values (id INTEGER PRIMARY KEY, label TEXT DEFAULT 'fallback', note TEXT)",
            ))
            .unwrap();
        let defaults = engine
            .execute(request(
                "INSERT INTO default_values (id, label, note) VALUES (1, DEFAULT, DEFAULT) RETURNING label, note",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &defaults.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Text("fallback".into()),
                    RelationalValue::Null,
                ]]
        ));
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = engine
            .execute(request(
                "INSERT INTO identity_items (name) VALUES ('after restart') RETURNING id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &recovered.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(4)]]
        ));
    }

    #[test]
    fn create_and_drop_scalar_indexes_are_versioned_and_constraint_safe() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT NOT NULL, category TEXT)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO products VALUES (1, 'a', 'book'), (2, 'b', 'book')",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE INDEX products_category_idx ON products(category)",
            ))
            .unwrap();
        let plan = engine
            .execute(request(
                "EXPLAIN SELECT id FROM products WHERE category = 'book'",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &plan.results[0],
            SqlResult::Explain { plan }
                if plan.iter().any(|line| line == "operator=relational_index_lookup")
        ));
        engine
            .execute(request(
                "CREATE UNIQUE INDEX products_sku_key ON products(sku)",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request("INSERT INTO products VALUES (3, 'a', 'music')"))
                .is_err()
        );
        engine
            .execute(request(
                "CREATE TABLE orders (id INTEGER PRIMARY KEY, sku TEXT, CONSTRAINT orders_sku_fkey FOREIGN KEY (sku) REFERENCES products(sku))",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request("DROP INDEX products_sku_key"))
                .is_err()
        );
        engine
            .execute(request(
                "ALTER TABLE orders DROP CONSTRAINT orders_sku_fkey",
            ))
            .unwrap();
        engine
            .execute(request("DROP INDEX products_sku_key"))
            .unwrap();
        engine
            .execute(request("DROP INDEX products_category_idx"))
            .unwrap();
        let scan = engine
            .execute(request(
                "EXPLAIN SELECT id FROM products WHERE category = 'book'",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &scan.results[0],
            SqlResult::Explain { plan }
                if plan.iter().any(|line| line == "operator=relational_scan")
        ));
    }

    #[test]
    fn checkpoint_bounds_wal_replay_and_recovers_the_tail() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance BIGINT NOT NULL)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO accounts VALUES (1, 100)"))
            .unwrap();

        assert_eq!(engine.checkpoint().unwrap(), 2);
        let checkpoint = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .expect("checkpoint must be published");
        assert_eq!(checkpoint.sequence, 2);
        assert_eq!(
            Wal::retained_base_lsn(engine.wal_dir()).unwrap(),
            checkpoint.wal_watermark,
            "WAL prefix covered by the checkpoint must be reclaimed"
        );

        engine
            .execute(request("INSERT INTO accounts VALUES (2, 250)"))
            .unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let response = reopened
            .execute(request("SELECT id, balance FROM accounts ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1), RelationalValue::Integer(100)],
                    vec![RelationalValue::Integer(2), RelationalValue::Integer(250)],
                ]
        ));
    }

    #[test]
    fn checkpoint_manifest_appends_compacts_and_requires_immutable_segments() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO products VALUES (1, 'one')"))
            .unwrap();
        engine.checkpoint().unwrap();

        let first = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(first.tables.len(), 1);
        assert!(first.tables[0].rows.is_empty());
        let first_row = first.tables[0].row_segments[0].clone();
        let first_index = first.tables[0].index_segments[0].clone();
        assert_eq!(first.tables[0].row_segments.len(), 1);
        assert_eq!(first.tables[0].index_segments.len(), 1);
        assert_eq!(first_row.record_count, 1);
        assert_eq!(first_index.record_count, 2);
        let segment_dir = directory.path().join(RELATIONAL_SEGMENT_DIR);
        assert!(segment_dir.join(&first_row.file_name).exists());
        assert!(segment_dir.join(&first_index.file_name).exists());

        engine
            .execute(request("INSERT INTO products VALUES (2, 'two')"))
            .unwrap();
        engine.checkpoint().unwrap();
        let second = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(second.tables[0].row_segments.len(), 2);
        assert_eq!(second.tables[0].index_segments.len(), 2);
        assert_eq!(second.tables[0].row_segments[1].record_count, 1);
        assert_eq!(second.tables[0].index_segments[1].record_count, 2);
        assert!(segment_dir.join(&first_row.file_name).exists());
        assert!(segment_dir.join(&first_index.file_name).exists());

        for id in 3..=5 {
            engine
                .execute(request(&format!(
                    "INSERT INTO products VALUES ({id}, 'sku-{id}')"
                )))
                .unwrap();
            engine.checkpoint().unwrap();
        }
        let compacted = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert!(compacted.tables[0].row_segments.len() <= RELATIONAL_MAX_RUNS_PER_TABLE);
        assert!(compacted.tables[0].index_segments.len() <= RELATIONAL_MAX_RUNS_PER_TABLE);
        let compacted_row = compacted.tables[0].row_segments[0].clone();
        let compacted_index = compacted.tables[0].index_segments[0].clone();
        assert_eq!(
            compacted.tables[0]
                .row_segments
                .iter()
                .map(|run| run.record_count)
                .sum::<u64>(),
            5
        );
        assert_eq!(
            compacted.tables[0]
                .index_segments
                .iter()
                .map(|run| run.record_count)
                .sum::<u64>(),
            10
        );
        assert!(!segment_dir.join(&first_row.file_name).exists());
        assert!(!segment_dir.join(&first_index.file_name).exists());

        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let response = reopened
            .execute(request("SELECT id FROM products ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &(1..=5)
                    .map(|id| vec![RelationalValue::Integer(id)])
                    .collect::<Vec<_>>()
        ));
        drop(reopened);
        fs::remove_file(segment_dir.join(compacted_row.file_name)).unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        assert!(RelationalEngine::open(directory.path(), journal).is_err());
        assert!(segment_dir.join(compacted_index.file_name).exists());
    }

    #[test]
    fn checkpoint_after_deleting_all_rows_does_not_resurrect_prior_runs() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE empty_after_delete (id INTEGER PRIMARY KEY, name TEXT UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO empty_after_delete VALUES (1, 'old'), (2, 'other')",
            ))
            .unwrap();
        engine.checkpoint().unwrap();
        engine
            .execute(request("DELETE FROM empty_after_delete"))
            .unwrap();
        engine.checkpoint().unwrap();
        let manifest = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(manifest.tables[0].row_segments.len(), 1);
        assert_eq!(manifest.tables[0].index_segments.len(), 1);
        assert_eq!(manifest.tables[0].row_segments[0].record_count, 0);
        assert_eq!(manifest.tables[0].index_segments[0].record_count, 0);
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        let response = engine
            .execute(request("SELECT id FROM empty_after_delete"))
            .unwrap()
            .response;
        assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. } if rows.is_empty()));
        engine
            .execute(request("INSERT INTO empty_after_delete VALUES (1, 'old')"))
            .unwrap();
    }

    #[test]
    fn checkpoint_delta_run_uses_newest_version_of_the_same_key() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO products VALUES (1, 'old')"))
            .unwrap();
        engine.checkpoint().unwrap();

        let context = audit("snapshot-holder");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request("UPDATE products SET sku = 'new' WHERE id = 1"))
            .unwrap();
        engine.checkpoint().unwrap();
        let checkpoint = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.tables[0].row_segments.len(), 2);
        assert_eq!(checkpoint.tables[0].index_segments.len(), 2);
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let old = reopened
            .execute(request("SELECT id FROM products WHERE sku = 'old'"))
            .unwrap()
            .response;
        assert!(matches!(
            &old.results[0],
            SqlResult::Rows { rows, .. } if rows.is_empty()
        ));
        let new = reopened
            .execute(request("SELECT id FROM products WHERE sku = 'new'"))
            .unwrap()
            .response;
        assert!(matches!(
            &new.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
    }

    #[test]
    fn legacy_v2_checkpoint_recovers_and_upgrades_on_the_next_generation() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO products VALUES (1, 'legacy')"))
            .unwrap();
        engine.checkpoint().unwrap();
        let mut legacy = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        legacy.version = RELATIONAL_CHECKPOINT_LEGACY_VERSION;
        for table in &mut legacy.tables {
            table.row_segment = table.row_segments.pop();
            table.index_segment = table.index_segments.pop();
        }
        write_relational_checkpoint(&engine.checkpoint_path, &legacy).unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        let rows = reopened
            .execute(request("SELECT id FROM products WHERE sku = 'legacy'"))
            .unwrap()
            .response;
        assert!(matches!(
            &rows.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
        reopened
            .execute(request("INSERT INTO products VALUES (2, 'current')"))
            .unwrap();
        reopened.checkpoint().unwrap();
        let upgraded = read_relational_checkpoint(&reopened.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(upgraded.version, RELATIONAL_CHECKPOINT_VERSION);
        assert!(upgraded.tables[0].row_segment.is_none());
        assert!(upgraded.tables[0].index_segment.is_none());
        assert_eq!(upgraded.tables[0].row_segments.len(), 2);
        assert_eq!(upgraded.tables[0].index_segments.len(), 2);

        let mut incomplete = upgraded.try_clone().unwrap();
        incomplete.tables[0].index_segments.clear();
        write_relational_checkpoint(&reopened.checkpoint_path, &incomplete).unwrap();
        assert!(read_relational_checkpoint(&reopened.checkpoint_path).is_err());
        write_relational_checkpoint(&reopened.checkpoint_path, &upgraded).unwrap();
    }

    #[test]
    fn protected_reference_index_tracks_rows_and_survives_checkpoint_reopen() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        let execute = |sql: &str| {
            engine
                .execute_scoped_with_audit(request(sql), &audit("alice"), Some("tenant-a"), None)
                .unwrap()
        };
        execute("CREATE TABLE knowledge (id BIGINT PRIMARY KEY, chunk RECORD_REF('chunks'))");
        let (reference_id, table_id) = {
            let state = engine.state.read();
            let definition = &state.tables["knowledge"].definition;
            (definition.reference_index_ids["chunk"], definition.table_id)
        };
        assert!(reference_id > table_id);
        execute("INSERT INTO knowledge VALUES (1, RECORD_REF('chunks','point-a'))");
        execute("INSERT INTO knowledge VALUES (2, RECORD_REF('chunks','point-b'))");
        let ids = |id: &str| BTreeSet::from([id.to_string()]);
        assert!(
            engine
                .ensure_no_live_references("tenant-a", "chunks", &ids("point-a"))
                .is_err()
        );
        assert!(
            engine
                .ensure_no_live_references("tenant-a", "chunks", &ids("missing"))
                .is_ok()
        );
        execute("UPDATE knowledge SET chunk=NULL WHERE id=1");
        assert!(
            engine
                .ensure_no_live_references("tenant-a", "chunks", &ids("point-a"))
                .is_ok()
        );
        engine.checkpoint().unwrap();
        let checkpoint = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.version, RELATIONAL_CHECKPOINT_VERSION);
        assert_eq!(
            checkpoint.tables[0].definition.reference_index_ids["chunk"],
            reference_id
        );
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        assert_eq!(
            reopened.state.read().tables["knowledge"]
                .definition
                .reference_index_ids["chunk"],
            reference_id
        );
        assert!(
            reopened
                .ensure_no_live_references("tenant-a", "chunks", &ids("point-b"))
                .is_err()
        );
        reopened
            .execute_scoped_with_audit(
                request("DELETE FROM knowledge WHERE id=2"),
                &audit("alice"),
                Some("tenant-a"),
                None,
            )
            .unwrap();
        assert!(
            reopened
                .ensure_no_live_references("tenant-a", "chunks", &ids("point-b"))
                .is_ok()
        );
        reopened
            .execute_scoped_with_audit(
                request("CREATE INDEX knowledge_chunk_idx ON knowledge(chunk)"),
                &audit("alice"),
                Some("tenant-a"),
                None,
            )
            .unwrap();
        let mut invalid_definition = reopened.state.read().tables["knowledge"]
            .definition
            .as_ref()
            .clone();
        assert_eq!(invalid_definition.indexes[0].index_id, reference_id);
        invalid_definition
            .reference_index_ids
            .insert("chunk".into(), reference_id + 1);
        assert!(validate_definition(&invalid_definition).is_err());
        reopened
            .execute_scoped_with_audit(
                request("DROP INDEX knowledge_chunk_idx"),
                &audit("alice"),
                Some("tenant-a"),
                None,
            )
            .unwrap();
        reopened
            .execute_scoped_with_audit(
                request("ALTER TABLE knowledge RENAME COLUMN chunk TO source"),
                &audit("alice"),
                Some("tenant-a"),
                None,
            )
            .unwrap();
        assert_eq!(
            reopened.state.read().tables["knowledge"]
                .definition
                .reference_index_ids["source"],
            reference_id
        );
        reopened
            .execute_scoped_with_audit(
                request("ALTER TABLE knowledge DROP COLUMN source"),
                &audit("alice"),
                Some("tenant-a"),
                None,
            )
            .unwrap();
        assert!(
            reopened.state.read().tables["knowledge"]
                .definition
                .reference_index_ids
                .is_empty()
        );
    }

    #[test]
    fn legacy_protected_reference_without_index_keeps_retirement_guard() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        for sql in [
            "CREATE TABLE knowledge (id BIGINT PRIMARY KEY, chunk RECORD_REF('chunks'))",
            "INSERT INTO knowledge VALUES (1, RECORD_REF('chunks','point-a'))",
        ] {
            engine
                .execute_scoped_with_audit(request(sql), &audit("alice"), Some("tenant-a"), None)
                .unwrap();
        }
        // Legacy catalog entries predate the engine-owned projection. Model
        // one explicitly to prove that retirement still checks live rows.
        let mut state = engine.state.read().clone();
        let table = Arc::make_mut(state.tables.get_mut("knowledge").unwrap().unwrap());
        let mut definition = table.definition.as_ref().clone();
        definition.reference_index_ids.clear();
        table.definition = Schema::adopt(definition).unwrap();
        table.indexes.remove_for_test(&["chunk".into()]).unwrap();
        let ids = BTreeSet::from(["point-a".to_string()]);
        assert!(
            record_references::ensure_unreferenced(&state, "tenant-a", "chunks", &ids).is_err()
        );
        assert!(
            record_references::ensure_unreferenced(
                &state,
                "tenant-a",
                "chunks",
                &BTreeSet::from(["missing".to_string()])
            )
            .is_ok()
        );
    }

    fn legacy_reference_checkpoint(directory: &Path) {
        let journal = TransactionJournal::open(directory).unwrap();
        let engine = RelationalEngine::open(directory, Arc::clone(&journal)).unwrap();
        for (table, point) in [("first", "point-a"), ("second", "point-b")] {
            engine
                .execute_scoped_with_audit(
                    request(&format!(
                        "CREATE TABLE {table} (id BIGINT PRIMARY KEY, chunk RECORD_REF('chunks'))"
                    )),
                    &audit("alice"),
                    Some("tenant-a"),
                    None,
                )
                .unwrap();
            engine
                .execute_scoped_with_audit(
                    request(&format!(
                        "INSERT INTO {table} VALUES (1, RECORD_REF('chunks','{point}'))"
                    )),
                    &audit("alice"),
                    Some("tenant-a"),
                    None,
                )
                .unwrap();
        }
        engine
            .execute_scoped_with_audit(
                request("CREATE INDEX second_chunk_idx ON second(chunk)"),
                &audit("alice"),
                Some("tenant-a"),
                None,
            )
            .unwrap();
        downgrade_reference_checkpoint(&engine);
    }

    fn downgrade_reference_checkpoint(engine: &RelationalEngine) {
        engine.checkpoint().unwrap();
        let old = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        let mut legacy = engine.state.read().clone();
        legacy
            .tables
            .try_update_all(|previous| {
                let mut definition = previous.definition.as_ref().clone();
                definition.reference_index_ids.clear();
                let mut replacement =
                    TableState::empty(definition, Arc::clone(&previous.directory))?;
                replacement.rows = previous.rows.clone();
                replacement.next_row_id = previous.next_row_id;
                Ok(Some(Arc::new(replacement)))
            })
            .unwrap();
        let captured = capture_relational_checkpoint(&legacy, old.wal_watermark).unwrap();
        let segment_dir = engine.checkpoint_path.parent().unwrap().join("segments");
        let mut persisted =
            checkpoint::materialize_migration(&captured, Some(&old), &segment_dir).unwrap();
        persisted.version = RELATIONAL_CHECKPOINT_RUNS_VERSION;
        prepare_checkpoint_backings(&persisted, &segment_dir).unwrap();
        write_relational_checkpoint(&engine.checkpoint_path, &persisted).unwrap();
    }

    #[test]
    fn offline_reference_index_migration_backfills_both_tables_and_reopens() {
        #[cfg(feature = "fault-injection")]
        let _failpoint_env = crate::failpoint::TEST_ENV
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let directory = tempdir().unwrap();
        legacy_reference_checkpoint(directory.path());
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        let before = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(before.version, RELATIONAL_CHECKPOINT_RUNS_VERSION);
        assert!(
            before
                .tables
                .iter()
                .all(|table| table.definition.reference_index_ids.is_empty())
        );
        let ids = BTreeSet::from(["point-a".to_string()]);
        assert!(
            engine
                .ensure_no_live_references("tenant-a", "chunks", &ids)
                .is_err()
        );
        assert_eq!(engine.migrate_reference_indexes_offline().unwrap(), 2);
        let after = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(after.version, RELATIONAL_CHECKPOINT_VERSION);
        assert_eq!(after.sequence, before.sequence);
        assert!(
            after
                .tables
                .iter()
                .all(|table| table.definition.reference_index_ids.contains_key("chunk"))
        );
        let second = after
            .tables
            .iter()
            .find(|table| table.definition.name == "second")
            .unwrap();
        assert_eq!(
            second.definition.reference_index_ids["chunk"],
            second.definition.indexes[0].index_id
        );
        assert_eq!(engine.migrate_reference_indexes_offline().unwrap(), 0);
        drop(engine);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        for (table, point) in [("first", "point-a"), ("second", "point-b")] {
            let response = reopened
                .execute_scoped_with_audit(
                    request(&format!("SELECT id FROM {table} WHERE id=1")),
                    &audit("alice"),
                    Some("tenant-a"),
                    None,
                )
                .unwrap()
                .response;
            assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]));
            assert!(
                reopened
                    .ensure_no_live_references(
                        "tenant-a",
                        "chunks",
                        &BTreeSet::from([point.to_string()])
                    )
                    .is_err()
            );
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn offline_reference_index_migration_recovers_on_both_sides_of_manifest() {
        for failpoint in [
            "relational_migration.after_segments",
            "relational_migration.after_manifest",
        ] {
            let directory = tempdir().unwrap();
            legacy_reference_checkpoint(directory.path());
            let journal = TransactionJournal::open(directory.path()).unwrap();
            let engine = RelationalEngine::open(directory.path(), journal).unwrap();
            let original = std::fs::read(&engine.checkpoint_path).unwrap();
            let marker = directory.path().join("marker");
            let release = directory.path().join("release");
            {
                let _env =
                    crate::failpoint::test_env(&format!("error:{failpoint}"), &marker, &release);
                assert!(engine.migrate_reference_indexes_offline().is_err());
            }
            let changed = failpoint.ends_with("after_manifest");
            assert_eq!(
                std::fs::read(&engine.checkpoint_path).unwrap() != original,
                changed
            );
            drop(engine);
            let journal = TransactionJournal::open(directory.path()).unwrap();
            let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
            let authoritative = read_relational_checkpoint(&reopened.checkpoint_path)
                .unwrap()
                .unwrap();
            let retained = checkpoint_segment_names(&authoritative);
            for entry in
                std::fs::read_dir(reopened.checkpoint_path.parent().unwrap().join("segments"))
                    .unwrap()
            {
                let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                if (name.starts_with("row-") || name.starts_with("index-"))
                    && name.ends_with(".rseg")
                {
                    assert!(retained.contains(&name), "orphan relational run: {name}");
                }
            }
            for (table, point) in [("first", "point-a"), ("second", "point-b")] {
                let response = reopened
                    .execute_scoped_with_audit(
                        request(&format!("SELECT id FROM {table} WHERE id=1")),
                        &audit("alice"),
                        Some("tenant-a"),
                        None,
                    )
                    .unwrap()
                    .response;
                assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. }
                    if rows == &vec![vec![RelationalValue::Integer(1)]]));
                assert!(
                    reopened
                        .ensure_no_live_references(
                            "tenant-a",
                            "chunks",
                            &BTreeSet::from([point.to_string()]),
                        )
                        .is_err()
                );
            }
            for table in reopened.table_definitions() {
                assert_eq!(table.reference_index_ids.contains_key("chunk"), changed);
            }
            assert_eq!(
                reopened.migrate_reference_indexes_offline().unwrap(),
                usize::from(!changed) * 2
            );
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn offline_reference_index_migration_sigkill_child() {
        let Some(directory) = std::env::var_os("CHIRONDB_REFERENCE_MIGRATION_CHILD_ROOT") else {
            return;
        };
        let directory = Path::new(&directory);
        let journal = TransactionJournal::open(directory).unwrap();
        let engine = RelationalEngine::open(directory, journal).unwrap();
        engine.migrate_reference_indexes_offline().unwrap();
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn offline_reference_index_migration_sigkill_preserves_complete_generation() {
        use std::{
            process::{Command, Stdio},
            time::{Duration, Instant},
        };

        let _failpoint_env = crate::failpoint::TEST_ENV
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for failpoint in [
            "relational_migration.after_segments",
            "relational_migration.after_manifest",
        ] {
            let directory = tempdir().unwrap();
            legacy_reference_checkpoint(directory.path());
            let checkpoint_path = directory.path().join(RELATIONAL_CHECKPOINT_FILE);
            let before = std::fs::read(&checkpoint_path).unwrap();
            let marker = directory.path().join("paused");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "relational::tests::offline_reference_index_migration_sigkill_child",
                    "--nocapture",
                ])
                .env("CHIRONDB_REFERENCE_MIGRATION_CHILD_ROOT", directory.path())
                .env("CHIRONDB_FAILPOINT", format!("pause:{failpoint}"))
                .env("CHIRONDB_FAILPOINT_MARKER", &marker)
                .env_remove("CHIRONDB_FAILPOINT_RELEASE")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while !marker.exists() {
                if let Some(status) = child.try_wait().unwrap() {
                    let output = child.wait_with_output().unwrap();
                    panic!(
                        "migration exited before {failpoint}: {status}; {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    let output = child.wait_with_output().unwrap();
                    panic!(
                        "migration did not reach {failpoint}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            child.kill().unwrap();
            let status = child.wait().unwrap();
            assert!(!status.success());
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9));
            }
            let published = failpoint.ends_with("after_manifest");
            assert_eq!(
                std::fs::read(&checkpoint_path).unwrap() != before,
                published
            );

            let journal = TransactionJournal::open(directory.path()).unwrap();
            let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
            let authoritative = read_relational_checkpoint(&checkpoint_path)
                .unwrap()
                .unwrap();
            let retained = checkpoint_segment_names(&authoritative);
            for entry in std::fs::read_dir(directory.path().join(RELATIONAL_SEGMENT_DIR)).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                if (name.starts_with("row-") || name.starts_with("index-"))
                    && name.ends_with(".rseg")
                {
                    assert!(retained.contains(&name), "orphan relational run: {name}");
                }
            }
            for table in reopened.table_definitions() {
                assert_eq!(table.reference_index_ids.contains_key("chunk"), published);
            }
            for (table, point) in [("first", "point-a"), ("second", "point-b")] {
                let response = reopened
                    .execute_scoped_with_audit(
                        request(&format!("SELECT id FROM {table} WHERE id=1")),
                        &audit("alice"),
                        Some("tenant-a"),
                        None,
                    )
                    .unwrap()
                    .response;
                assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. }
                    if rows == &vec![vec![RelationalValue::Integer(1)]]));
                assert!(
                    reopened
                        .ensure_no_live_references(
                            "tenant-a",
                            "chunks",
                            &BTreeSet::from([point.to_string()]),
                        )
                        .is_err()
                );
            }
            assert_eq!(
                reopened.migrate_reference_indexes_offline().unwrap(),
                usize::from(!published) * 2
            );
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn offline_reference_index_migration_encrypted_child() {
        let Ok(role) = std::env::var("CHIRONDB_REFERENCE_ENCRYPTED_ROLE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("CHIRONDB_REFERENCE_ENCRYPTED_ROOT").unwrap());
        let keyring = crate::encryption::Keyring::load(root.join("keyring.json")).unwrap();
        crate::encryption::install_process_keyring(keyring, true).unwrap();
        let data = root.join("data");
        match role.as_str() {
            "setup" => {
                fs::create_dir_all(&data).unwrap();
                legacy_reference_checkpoint(&data);
                let checkpoint = read_relational_checkpoint(&data.join(RELATIONAL_CHECKPOINT_FILE))
                    .unwrap()
                    .unwrap();
                assert_eq!(checkpoint.version, RELATIONAL_CHECKPOINT_RUNS_VERSION);
            }
            "migrate" => {
                let journal = TransactionJournal::open(&data).unwrap();
                let engine = RelationalEngine::open(&data, journal).unwrap();
                engine.migrate_reference_indexes_offline().unwrap();
            }
            "verify" => {
                let published =
                    std::env::var("CHIRONDB_REFERENCE_ENCRYPTED_PUBLISHED").unwrap() == "1";
                let journal = TransactionJournal::open(&data).unwrap();
                let engine = RelationalEngine::open(&data, journal).unwrap();
                let checkpoint_path = data.join(RELATIONAL_CHECKPOINT_FILE);
                let authoritative = read_relational_checkpoint(&checkpoint_path)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    authoritative.version,
                    if published {
                        RELATIONAL_CHECKPOINT_VERSION
                    } else {
                        RELATIONAL_CHECKPOINT_RUNS_VERSION
                    }
                );
                let retained = checkpoint_segment_names(&authoritative);
                for entry in fs::read_dir(data.join(RELATIONAL_SEGMENT_DIR)).unwrap() {
                    let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                    if (name.starts_with("row-") || name.starts_with("index-"))
                        && name.ends_with(".rseg")
                    {
                        assert!(retained.contains(&name), "orphan relational run: {name}");
                    }
                }
                for table in engine.table_definitions() {
                    assert_eq!(table.reference_index_ids.contains_key("chunk"), published);
                }
                for (table, point) in [("first", "point-a"), ("second", "point-b")] {
                    let response = engine
                        .execute_scoped_with_audit(
                            request(&format!("SELECT id FROM {table} WHERE id=1")),
                            &audit("alice"),
                            Some("tenant-a"),
                            None,
                        )
                        .unwrap()
                        .response;
                    assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. }
                        if rows == &vec![vec![RelationalValue::Integer(1)]]));
                    assert!(
                        engine
                            .ensure_no_live_references(
                                "tenant-a",
                                "chunks",
                                &BTreeSet::from([point.to_string()]),
                            )
                            .is_err()
                    );
                }
                assert_eq!(
                    engine.migrate_reference_indexes_offline().unwrap(),
                    usize::from(!published) * 2
                );
                drop(engine);
                let journal = TransactionJournal::open(&data).unwrap();
                let reopened = RelationalEngine::open(&data, journal).unwrap();
                assert!(
                    reopened
                        .table_definitions()
                        .iter()
                        .all(|table| table.reference_index_ids.contains_key("chunk"))
                );
                let keyring = crate::encryption::Keyring::load(root.join("keyring.json")).unwrap();
                let report = crate::encryption::verify_tree(&keyring, &data).unwrap();
                assert!(report.encrypted_files > 0);
                assert_eq!(report.plaintext_files, 0);
            }
            other => panic!("unknown encrypted migration child role: {other}"),
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn offline_reference_index_migration_encrypted_sigkill_reopens_complete_generation() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use std::process::{Command, Stdio};

        const CHILD: &str = "relational::tests::offline_reference_index_migration_encrypted_child";
        let _failpoint_env = crate::failpoint::TEST_ENV
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for failpoint in [
            "relational_migration.after_segments",
            "relational_migration.after_manifest",
        ] {
            let directory = tempdir().unwrap();
            let root = directory.path();
            let keyring = root.join("keyring.json");
            fs::write(
                &keyring,
                serde_json::json!({
                    "version": 1,
                    "active_key_id": "migration-test",
                    "keys": [{"id": "migration-test", "key_base64": STANDARD.encode([59_u8; 32])}]
                })
                .to_string(),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let child = || {
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args(["--exact", CHILD, "--nocapture"])
                    .env("CHIRONDB_REFERENCE_ENCRYPTED_ROOT", root)
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped());
                command
            };
            let setup = child()
                .env("CHIRONDB_REFERENCE_ENCRYPTED_ROLE", "setup")
                .output()
                .unwrap();
            assert!(
                setup.status.success(),
                "{}",
                String::from_utf8_lossy(&setup.stderr)
            );
            let checkpoint_path = root.join("data").join(RELATIONAL_CHECKPOINT_FILE);
            let before = fs::read(&checkpoint_path).unwrap();
            assert!(before.starts_with(crate::encryption::MAGIC));

            let marker = root.join("paused");
            let mut migrating = child()
                .env("CHIRONDB_REFERENCE_ENCRYPTED_ROLE", "migrate")
                .env("CHIRONDB_FAILPOINT", format!("pause:{failpoint}"))
                .env("CHIRONDB_FAILPOINT_MARKER", &marker)
                .env_remove("CHIRONDB_FAILPOINT_RELEASE")
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while !marker.exists() {
                if let Some(status) = migrating.try_wait().unwrap() {
                    let output = migrating.wait_with_output().unwrap();
                    panic!(
                        "encrypted migration exited before {failpoint}: {status}; {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                if Instant::now() >= deadline {
                    migrating.kill().unwrap();
                    let output = migrating.wait_with_output().unwrap();
                    panic!(
                        "encrypted migration did not reach {failpoint}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            migrating.kill().unwrap();
            let status = migrating.wait().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9));
            }
            #[cfg(not(unix))]
            assert!(!status.success());
            let published = failpoint.ends_with("after_manifest");
            assert_eq!(fs::read(&checkpoint_path).unwrap() != before, published);
            let verified = child()
                .env("CHIRONDB_REFERENCE_ENCRYPTED_ROLE", "verify")
                .env(
                    "CHIRONDB_REFERENCE_ENCRYPTED_PUBLISHED",
                    if published { "1" } else { "0" },
                )
                .output()
                .unwrap();
            assert!(
                verified.status.success(),
                "{}",
                String::from_utf8_lossy(&verified.stderr)
            );
        }
    }

    #[test]
    fn offline_reference_index_migration_installed_child() {
        let Ok(role) = std::env::var("CHIRONDB_REFERENCE_INSTALLED_ROLE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("CHIRONDB_REFERENCE_INSTALLED_ROOT").unwrap());
        let data = root.join("data");
        let keyring_path = root.join("storage.json");
        let admin_key = root.join("admin.key");
        if role == "setup" {
            use crate::security::{
                CollectionPolicy, IngestTemplate, NewPoint, PropertyAction, PropertyRule,
                Representation, RevisionUpdate,
            };

            crate::security::onboarding::initialize(
                &data,
                "acme",
                "admin",
                &keyring_path,
                &admin_key,
                false,
            )
            .unwrap();
            let db = crate::Db::open(&data).unwrap();
            let secret = fs::read_to_string(&admin_key).unwrap();
            let authority = db.identity_authority().unwrap();
            let actor = authority.authenticate(secret.trim()).unwrap();
            db.create_protected_collection_authorized(
                &actor,
                db.catalog_revision_authorized(&actor).unwrap(),
                serde_json::from_value(serde_json::json!({
                    "name": "chunks",
                    "vector_dim": 2
                }))
                .unwrap(),
            )
            .unwrap();
            db.execute_sql_authorized(
                &actor,
                request(
                    "CREATE TABLE knowledge (id BIGINT PRIMARY KEY, chunk RECORD_REF('chunks'))",
                ),
                "migration-test",
            )
            .unwrap();
            let mut admin = actor.principal().clone();
            admin.grants.push(crate::security::ScopeGrant {
                tenants: BTreeSet::from(["acme".into()]),
                collections: BTreeSet::from(["knowledge".into()]),
                actions: BTreeSet::from([
                    crate::security::Action::Create,
                    crate::security::Action::Read,
                ]),
            });
            admin.grants.push(crate::security::ScopeGrant {
                tenants: BTreeSet::from(["acme".into()]),
                collections: BTreeSet::from(["chunks".into()]),
                actions: BTreeSet::from([
                    crate::security::Action::Create,
                    crate::security::Action::Read,
                    crate::security::Action::Delete,
                    crate::security::Action::Ingest,
                    crate::security::Action::PolicyManage,
                ]),
            });
            authority
                .put_principal(&actor, actor.revision(), admin)
                .unwrap();
            let actor = authority.authenticate(secret.trim()).unwrap();
            let manage = db
                .bind_access(
                    &actor,
                    "chunks",
                    "acme",
                    crate::security::Action::PolicyManage,
                )
                .unwrap();
            db.replace_collection_policy_authorized(
                &manage,
                RevisionUpdate {
                    expected_revision: manage.policy_revision(),
                    value: CollectionPolicy {
                        department_actions: BTreeSet::new(),
                        owner_actions: BTreeSet::from([
                            crate::security::Action::Read,
                            crate::security::Action::Delete,
                        ]),
                        templates: BTreeMap::from([(
                            "standard".into(),
                            IngestTemplate {
                                department: "Security".into(),
                                classification: Classification::Internal,
                                properties: BTreeMap::from([(
                                    "/text".into(),
                                    PropertyRule {
                                        classification: Classification::Internal,
                                        actions: BTreeSet::from([
                                            PropertyAction::Read,
                                            PropertyAction::Query,
                                            PropertyAction::Write,
                                        ]),
                                    },
                                )]),
                                representations: BTreeMap::from([(
                                    "dense".into(),
                                    Representation {
                                        source_fields: BTreeSet::from(["/text".into()]),
                                        classification: Classification::Internal,
                                    },
                                )]),
                            },
                        )]),
                    },
                },
            )
            .unwrap();
            let create = db
                .bind_access(&actor, "chunks", "acme", crate::security::Action::Create)
                .unwrap();
            let ids = db
                .create_points_authorized(
                    &create,
                    "standard",
                    vec![NewPoint {
                        vector: vec![1.0, 0.0],
                        vectors: BTreeMap::new(),
                        sparse_vector: None,
                        payload: serde_json::json!({"text": "migration reference"}),
                    }],
                    true,
                )
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            fs::write(root.join("point-id"), &ids[0]).unwrap();
            db.execute_sql_authorized(
                &actor,
                request(&format!(
                    "INSERT INTO knowledge (id, chunk) VALUES (1, RECORD_REF('chunks','{}'))",
                    ids[0]
                )),
                "migration-test",
            )
            .unwrap();
            db.flush_wals().unwrap();
            drop(db);

            let active_root = crate::storage_layout::resolve(&data).unwrap().active_root;
            let journal = TransactionJournal::open(&data).unwrap();
            let engine = RelationalEngine::open(&active_root, journal).unwrap();
            downgrade_reference_checkpoint(&engine);
            drop(engine);
            let db = crate::Db::open(&data).unwrap();
            assert!(
                db.relational_tables()
                    .iter()
                    .any(|table| table.name == "knowledge" && table.reference_index_ids.is_empty())
            );
            let actor = db
                .identity_authority()
                .unwrap()
                .authenticate(secret.trim())
                .unwrap();
            let delete = db
                .bind_access(&actor, "chunks", "acme", crate::security::Action::Delete)
                .unwrap();
            let point_id = fs::read_to_string(root.join("point-id")).unwrap();
            assert!(matches!(
                db.delete_points_authorized(&delete, &[point_id]),
                Err(crate::GaussError::Security(
                    crate::security::SecurityError::Conflict
                ))
            ));
            return;
        }

        crate::encryption::install_process_keyring(
            crate::encryption::Keyring::load(&keyring_path).unwrap(),
            true,
        )
        .unwrap();
        let mut db = crate::Db::open(&data).unwrap();
        let authority = db.identity_authority().unwrap();
        let secret = fs::read_to_string(&admin_key).unwrap();
        let actor = authority.authenticate(secret.trim()).unwrap();
        assert_eq!(actor.principal().tenant, "acme");
        match role.as_str() {
            "migrate" => {
                assert_eq!(
                    db.migrate_relational_reference_indexes_offline().unwrap(),
                    1
                );
            }
            "verify" | "verify-old" => {
                let published = role == "verify";
                assert!(
                    db.relational_tables()
                        .iter()
                        .any(|table| table.name == "knowledge"
                            && table.reference_index_ids.contains_key("chunk") == published)
                );
                let response = db
                    .execute_sql_authorized(
                        &actor,
                        request("SELECT id FROM knowledge WHERE id=1"),
                        "migration-test",
                    )
                    .unwrap();
                assert!(matches!(&response.results[0], SqlResult::Rows { rows, .. }
                    if rows == &vec![vec![RelationalValue::Integer(1)]]));
                let delete = db
                    .bind_access(&actor, "chunks", "acme", crate::security::Action::Delete)
                    .unwrap();
                let point_id = fs::read_to_string(root.join("point-id")).unwrap();
                assert!(matches!(
                    db.delete_points_authorized(&delete, &[point_id]),
                    Err(crate::GaussError::Security(
                        crate::security::SecurityError::Conflict
                    ))
                ));
                if published {
                    assert_eq!(
                        db.migrate_relational_reference_indexes_offline().unwrap(),
                        0
                    );
                }
                let keyring = crate::encryption::Keyring::load(&keyring_path).unwrap();
                let report = crate::encryption::verify_tree(&keyring, &data).unwrap();
                assert!(report.encrypted_files > 0);
                assert_eq!(report.plaintext_files, 0);
            }
            other => panic!("unknown installed migration child role: {other}"),
        }
    }

    #[test]
    fn offline_reference_index_migration_on_installed_authority() {
        use std::process::Command;

        const CHILD: &str = "relational::tests::offline_reference_index_migration_installed_child";
        #[cfg(feature = "fault-injection")]
        let _failpoint_env = crate::failpoint::TEST_ENV
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for role in ["setup", "migrate", "verify"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CHILD, "--nocapture"])
                .env("CHIRONDB_REFERENCE_INSTALLED_ROLE", role)
                .env("CHIRONDB_REFERENCE_INSTALLED_ROOT", &root)
                .env_remove("CHIRONDB_FAILPOINT")
                .env_remove("CHIRONDB_FAILPOINT_MARKER")
                .env_remove("CHIRONDB_FAILPOINT_RELEASE")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{role}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn v3_run_checkpoint_reopens_and_upgrades_to_v4() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE older (id BIGINT PRIMARY KEY, note TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO older VALUES (1, 'present')"))
            .unwrap();
        engine.checkpoint().unwrap();
        let mut previous = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        previous.version = RELATIONAL_CHECKPOINT_RUNS_VERSION;
        write_relational_checkpoint(&engine.checkpoint_path, &previous).unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let rows = reopened
            .execute(request("SELECT note FROM older WHERE id=1"))
            .unwrap()
            .response;
        assert!(matches!(&rows.results[0], SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Text("present".into())]]));
        reopened
            .execute(request("INSERT INTO older VALUES (2, 'new')"))
            .unwrap();
        reopened.checkpoint().unwrap();
        assert_eq!(
            read_relational_checkpoint(&reopened.checkpoint_path)
                .unwrap()
                .unwrap()
                .version,
            RELATIONAL_CHECKPOINT_VERSION
        );
    }

    #[test]
    fn recovered_index_queries_merge_sparse_segment_and_wal_delta() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO products VALUES (1, 'one'), (2, 'two')",
            ))
            .unwrap();
        engine.checkpoint().unwrap();
        engine
            .execute(request("INSERT INTO products VALUES (3, 'three')"))
            .unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let base = reopened
            .execute(request("SELECT id FROM products WHERE sku = 'two'"))
            .unwrap()
            .response;
        assert!(matches!(
            &base.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(2)]]
        ));
        let delta = reopened
            .execute(request("SELECT id FROM products WHERE sku = 'three'"))
            .unwrap()
            .response;
        assert!(matches!(
            &delta.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(3)]]
        ));

        let index_path = reopened
            .state
            .read()
            .tables
            .get("products")
            .unwrap()
            .index_segments
            .last()
            .unwrap()
            .path
            .clone();
        // A retained mapping, rather than a pathname, owns the generation.
        // Corrupt bytes still refuse results; unlink alone does not remove the
        // data held by a reader, but the missing file must prevent recovery.
        use std::io::{Seek, SeekFrom};
        let bytes = fs::read(&index_path).unwrap();
        let original = bytes[bytes.len() - 1];
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&index_path)
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[original ^ 1]).unwrap();
        file.sync_all().unwrap();
        assert!(
            reopened
                .execute(request("SELECT id FROM products WHERE sku = 'two'"))
                .is_err()
        );
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[original]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        fs::remove_file(&index_path).unwrap();
        let pinned = reopened
            .execute(request("SELECT id FROM products WHERE sku = 'two'"))
            .unwrap()
            .response;
        assert!(matches!(&pinned.results[0], SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Integer(2)]]));
        let full_scan = reopened
            .execute(request("SELECT id FROM products WHERE id > 0 ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(
            &full_scan.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1)],
                    vec![RelationalValue::Integer(2)],
                    vec![RelationalValue::Integer(3)],
                ]
        ));
        drop(reopened);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        assert!(
            RelationalEngine::open(directory.path(), journal).is_err(),
            "recovery must refuse a missing committed index run"
        );
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn checkpoint_failpoints_preserve_manifest_authority_and_retry_cleanup() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("failpoint-marker");
        let release = directory.path().join("failpoint-release");
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO items VALUES (1)"))
            .unwrap();
        engine.checkpoint().unwrap();
        engine
            .execute(request("INSERT INTO items VALUES (2)"))
            .unwrap();
        {
            let _env = crate::failpoint::test_env(
                "error:relational_checkpoint.after_segments",
                &marker,
                &release,
            );
            assert!(engine.checkpoint().is_err());
        }
        assert_eq!(
            read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .unwrap()
                .sequence,
            2
        );
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        let rows = engine
            .execute(request("SELECT id FROM items ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(
            &rows.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1)],
                    vec![RelationalValue::Integer(2)],
                ]
        ));
        engine.checkpoint().unwrap();
        engine
            .execute(request("INSERT INTO items VALUES (3)"))
            .unwrap();
        {
            let _env = crate::failpoint::test_env(
                "error:relational_checkpoint.after_manifest",
                &marker,
                &release,
            );
            assert!(engine.checkpoint().is_err());
        }
        assert_eq!(
            read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .unwrap()
                .sequence,
            4
        );
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        let rows = engine
            .execute(request("SELECT id FROM items ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(
            &rows.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1)],
                    vec![RelationalValue::Integer(2)],
                    vec![RelationalValue::Integer(3)],
                ]
        ));
        engine.checkpoint().unwrap();
        let manifest = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        let segment_files = fs::read_dir(directory.path().join(RELATIONAL_SEGMENT_DIR))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "rseg")
            })
            .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
            .collect::<HashSet<_>>();
        assert_eq!(
            segment_files,
            checkpoint_segment_names(&manifest),
            "retry must retain every active run and reclaim every orphan"
        );
    }

    #[test]
    fn catalog_ids_are_stable_shared_and_never_reused() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER, CONSTRAINT child_parent_fk FOREIGN KEY (parent_id) REFERENCES parent(id))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE UNIQUE INDEX parent_id_unique ON parent(id)",
            ))
            .unwrap();
        engine
            .execute(request("CREATE INDEX child_parent_idx ON child(parent_id)"))
            .unwrap();

        let definitions = engine.table_definitions();
        let parent = definitions
            .iter()
            .find(|definition| definition.name == "parent")
            .unwrap();
        let child = definitions
            .iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        let parent_primary = parent.primary_key_index_id.unwrap();
        assert_ne!(parent.table_id, 0);
        assert_eq!(parent.indexes[0].index_id, parent_primary);
        let child_foreign = child.foreign_keys[0].index_id;
        assert_ne!(child_foreign, 0);
        assert_eq!(child.indexes[0].index_id, child_foreign);
        let prior_maximum = definitions
            .iter()
            .flat_map(|definition| {
                catalog_index_owners(definition)
                    .map(|(index_id, _)| index_id)
                    .chain(std::iter::once(definition.table_id))
            })
            .max()
            .unwrap();

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened.table_definitions();
        assert_eq!(recovered, definitions);

        reopened.execute(request("DROP TABLE child")).unwrap();
        drop(reopened);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let after_drop_recovery = RelationalEngine::open(directory.path(), journal).unwrap();
        after_drop_recovery
            .execute(request("CREATE TABLE replacement (id INTEGER PRIMARY KEY)"))
            .unwrap();
        let replacement = after_drop_recovery
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "replacement")
            .unwrap();
        assert!(replacement.table_id > prior_maximum);
        assert!(replacement.primary_key_index_id.unwrap() > replacement.table_id);
    }

    #[test]
    fn parent_update_reports_unique_before_restrict_and_keeps_rows() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request("CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON UPDATE RESTRICT)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1), (2)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (10, 1)"))
            .unwrap();

        let duplicate = engine
            .execute(request("UPDATE parent SET id = 2 WHERE id = 1"))
            .err()
            .expect("duplicate parent key must fail");
        assert!(duplicate.to_string().contains("unique constraint"));
        let restricted = engine
            .execute(request("UPDATE parent SET id = 3 WHERE id = 1"))
            .err()
            .expect("referenced parent key must fail");
        assert!(restricted.to_string().contains("restricts"));
        let parent = engine
            .execute(request("SELECT id FROM parent ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(&parent.results[0], SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Integer(1)], vec![RelationalValue::Integer(2)]]));
    }

    #[test]
    fn concurrent_parent_delete_and_child_insert_cannot_both_commit() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1)"))
            .unwrap();

        let snapshot = engine.state.read().clone();
        let child_insert = prepare_execution(
            snapshot.clone(),
            request("INSERT INTO child VALUES (10, 1)"),
            true,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        let parent_delete = prepare_execution(
            snapshot,
            request("DELETE FROM parent WHERE id = 1"),
            true,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        let referenced_parent_key = child_insert
            .intents
            .iter()
            .find(|intent| intent.mode == IntentMode::Shared)
            .expect("child insert must hold a shared reference intent");
        assert!(parent_delete.intents.iter().any(|intent| {
            intent.mode == IntentMode::Exclusive && intent.key == referenced_parent_key.key
        }));
        engine
            .commit_prepared(
                parent_delete,
                &AuditContext::embedded(),
                1,
                None,
                None,
                None,
            )
            .unwrap();
        let conflict = engine
            .commit_prepared(child_insert, &AuditContext::embedded(), 1, None, None, None)
            .err()
            .expect("stale child insert must not commit after parent delete");
        assert!(
            conflict.to_string().contains("foreign key"),
            "unexpected conflict: {conflict}"
        );

        let child_count = engine
            .execute(request("SELECT COUNT(*) FROM child"))
            .unwrap()
            .response;
        assert!(matches!(
            &child_count.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));
    }

    #[test]
    fn concurrent_cascade_and_child_update_never_lose_a_write() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON UPDATE CASCADE, label TEXT NOT NULL)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (10, 1, 'original')"))
            .unwrap();

        let snapshot = engine.state.read().clone();
        let cascade = prepare_execution(
            snapshot.clone(),
            request("UPDATE parent SET id = 2 WHERE id = 1"),
            true,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        let child_update = prepare_execution(
            snapshot,
            request("UPDATE child SET label = 'concurrent' WHERE id = 10"),
            true,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        engine
            .commit_prepared(cascade, &AuditContext::embedded(), 1, None, None, None)
            .unwrap();
        let conflict = engine
            .commit_prepared(child_update, &AuditContext::embedded(), 1, None, None, None)
            .err()
            .expect("child update must conflict with a committed cascade");
        assert!(conflict.to_string().contains("serialization conflict"));

        engine
            .execute(request("UPDATE parent SET id = 1 WHERE id = 2"))
            .unwrap();
        let snapshot = engine.state.read().clone();
        let cascade = prepare_execution(
            snapshot.clone(),
            request("UPDATE parent SET id = 2 WHERE id = 1"),
            true,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        let child_update = prepare_execution(
            snapshot,
            request("UPDATE child SET label = 'winner' WHERE id = 10"),
            true,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        engine
            .commit_prepared(child_update, &AuditContext::embedded(), 1, None, None, None)
            .unwrap();
        let conflict = engine
            .commit_prepared(cascade, &AuditContext::embedded(), 1, None, None, None)
            .err()
            .expect("cascade must conflict with a committed child update");
        assert!(conflict.to_string().contains("serialization conflict"));

        let rows = engine
            .execute(request("SELECT parent_id, label FROM child WHERE id = 10"))
            .unwrap()
            .response;
        assert!(matches!(
            &rows.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Text("winner".into()),
                ]]
        ));
    }

    #[test]
    fn concurrent_unique_inserts_cannot_both_commit() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE unique_items (id INTEGER PRIMARY KEY, email TEXT UNIQUE)",
            ))
            .unwrap();

        let snapshot = engine.state.read().clone();
        let first = prepare_execution(
            snapshot.clone(),
            request("INSERT INTO unique_items VALUES (1, 'same@example.test')"),
            true,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        let second = prepare_execution(
            snapshot,
            request("INSERT INTO unique_items VALUES (2, 'same@example.test')"),
            true,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(first.intents.iter().any(|left| {
            second.intents.iter().any(|right| {
                left.mode == IntentMode::Exclusive
                    && right.mode == IntentMode::Exclusive
                    && left.key == right.key
            })
        }));
        engine
            .commit_prepared(first, &AuditContext::embedded(), 1, None, None, None)
            .unwrap();
        let conflict = engine
            .commit_prepared(second, &AuditContext::embedded(), 1, None, None, None)
            .err()
            .expect("second duplicate unique insert must fail");
        assert!(conflict.to_string().contains("unique constraint"));

        let count = engine
            .execute(request("SELECT COUNT(*) FROM unique_items"))
            .unwrap()
            .response;
        assert!(matches!(
            &count.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]]
        ));
    }

    #[test]
    fn check_constraints_use_sql_three_valued_logic_and_survive_recovery() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE inventory (id INTEGER PRIMARY KEY, quantity INTEGER CONSTRAINT quantity_nonnegative CHECK (quantity >= 0), reserved INTEGER, CONSTRAINT reserved_nonnegative CHECK (reserved IS NULL OR reserved >= 0))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO inventory VALUES (1, 5, NULL)"))
            .unwrap();
        let violation = engine
            .execute(request("INSERT INTO inventory VALUES (2, -1, 0)"))
            .err()
            .expect("negative quantity must violate CHECK");
        assert!(violation.to_string().contains("quantity_nonnegative"));
        assert!(
            engine
                .execute(request("UPDATE inventory SET reserved = -1 WHERE id = 1"))
                .is_err()
        );
        engine
            .execute(request(
                "CREATE TABLE legacy_balance (id INTEGER PRIMARY KEY, amount INTEGER)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO legacy_balance VALUES (1, -1)"))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE legacy_balance ADD CONSTRAINT amount_nonnegative CHECK (amount >= 0)",
                ))
                .is_err(),
            "ALTER ADD CHECK must validate existing rows atomically"
        );
        engine
            .execute(request("UPDATE legacy_balance SET amount = 0 WHERE id = 1"))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE legacy_balance ADD CONSTRAINT amount_nonnegative CHECK (amount >= 0)",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request("INSERT INTO legacy_balance VALUES (2, -1)"))
                .is_err()
        );
        engine
            .execute(request(
                "ALTER TABLE legacy_balance DROP CONSTRAINT amount_nonnegative",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO legacy_balance VALUES (2, -1)"))
            .unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let response = reopened
            .execute(request("SELECT quantity, reserved FROM inventory"))
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(5), RelationalValue::Null]]
        ));
    }

    #[test]
    fn add_column_rewrites_existing_rows_atomically_and_survives_recovery() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE accounts (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO accounts VALUES (1)"))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE accounts ADD COLUMN state TEXT NOT NULL DEFAULT 'ready' CHECK (state = 'ready')",
            ))
            .unwrap();

        let context = audit("alice");
        let transaction = engine.begin_interactive(&context).unwrap();
        engine
            .execute_interactive(
                &transaction.handle,
                request("INSERT INTO accounts (id) VALUES (2)"),
                &context,
            )
            .unwrap();
        engine
            .execute_interactive(
                &transaction.handle,
                request("ALTER TABLE accounts ADD COLUMN note TEXT"),
                &context,
            )
            .unwrap();
        engine
            .commit_interactive(&transaction.handle, &context)
            .unwrap();

        assert!(
            engine
                .execute(request(
                    "ALTER TABLE accounts ADD COLUMN required TEXT NOT NULL",
                ))
                .is_err(),
            "adding a required column without a default must reject existing rows"
        );
        let no_op = engine
            .execute(request(
                "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS note INTEGER",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &no_op.results[0],
            SqlResult::Definition {
                affected_objects: 0
            }
        ));

        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let response = reopened
            .execute(request("SELECT id, state, note FROM accounts ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(
            &response.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![
                        RelationalValue::Integer(1),
                        RelationalValue::Text("ready".into()),
                        RelationalValue::Null,
                    ],
                    vec![
                        RelationalValue::Integer(2),
                        RelationalValue::Text("ready".into()),
                        RelationalValue::Null,
                    ],
                ]
        ));
    }

    #[test]
    fn drop_column_rewrites_atomically_rejects_dependencies_and_survives_recovery() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE, guarded INTEGER CHECK (guarded > 0), indexed TEXT, obsolete TEXT)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE INDEX parent_indexed_idx ON parent(indexed)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_code TEXT REFERENCES parent(code))",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO parent VALUES (1, 'p-1', 7, 'lookup', 'remove-me')",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (10, 'p-1')"))
            .unwrap();

        for sql in [
            "ALTER TABLE parent DROP COLUMN id",
            "ALTER TABLE parent DROP COLUMN code",
            "ALTER TABLE parent DROP COLUMN guarded",
            "ALTER TABLE parent DROP COLUMN indexed",
            "ALTER TABLE child DROP COLUMN parent_code",
        ] {
            assert!(
                engine.execute(request(sql)).is_err(),
                "{sql} must fail closed"
            );
        }
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE parent DROP COLUMN obsolete, DROP COLUMN guarded",
                ))
                .is_err()
        );
        assert!(
            engine
                .execute(request("ALTER TABLE parent DROP COLUMN missing"))
                .is_err()
        );
        let no_op = engine
            .execute(request("ALTER TABLE parent DROP COLUMN IF EXISTS missing"))
            .unwrap()
            .response;
        assert!(matches!(
            &no_op.results[0],
            SqlResult::Definition {
                affected_objects: 0
            }
        ));

        let context = audit("snapshot-holder");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request("ALTER TABLE parent DROP COLUMN obsolete"))
            .unwrap();
        let old_view = engine
            .execute_interactive(
                &snapshot.handle,
                request("SELECT obsolete FROM parent"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old_view.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("remove-me".into())]]
        ));
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();
        assert!(
            engine
                .execute(request("SELECT obsolete FROM parent"))
                .is_err()
        );
        let current = engine
            .execute(request(
                "SELECT id, code, guarded, indexed FROM parent WHERE indexed = 'lookup'",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &current.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Text("p-1".into()),
                    RelationalValue::Integer(7),
                    RelationalValue::Text("lookup".into()),
                ]]
        ));
        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened
            .execute(request(
                "SELECT id, code, guarded, indexed FROM parent WHERE indexed = 'lookup'",
            ))
            .unwrap()
            .response;
        assert_eq!(recovered.results, current.results);
    }

    #[test]
    fn drop_column_cascade_removes_exact_dependencies_and_survives_recovery() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE other_parent (id INTEGER PRIMARY KEY)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE, guarded INTEGER CHECK (guarded > 0), indexed TEXT, manager_id INTEGER, CONSTRAINT parent_manager_fkey FOREIGN KEY (manager_id) REFERENCES parent(id))",
            ))
            .unwrap();
        engine
            .execute(request("CREATE INDEX parent_code_lookup ON parent(code)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE INDEX parent_indexed_lookup ON parent(indexed)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER, parent_code TEXT, other_id INTEGER, CONSTRAINT child_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES parent(id), CONSTRAINT child_parent_code_fkey FOREIGN KEY (parent_code) REFERENCES parent(code), CONSTRAINT child_other_fkey FOREIGN KEY (other_id) REFERENCES other_parent(id))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE second_child (id INTEGER PRIMARY KEY, parent_code TEXT REFERENCES parent(code))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO other_parent VALUES (1)"))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO parent VALUES (1, 'known', 7, 'keep', NULL)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (1, 1, 'known', 1)"))
            .unwrap();

        let context = audit("drop-column-cascade-snapshot");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request("ALTER TABLE parent DROP COLUMN code CASCADE"))
            .unwrap();
        let old_snapshot = engine
            .execute_interactive(
                &snapshot.handle,
                request("SELECT code FROM parent"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old_snapshot.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("known".into())]]
        ));
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();
        assert!(engine.execute(request("SELECT code FROM parent")).is_err());

        let definitions = engine.table_definitions();
        let parent = definitions
            .iter()
            .find(|definition| definition.name == "parent")
            .unwrap();
        assert!(parent.unique_constraints.is_empty());
        assert!(
            parent
                .indexes
                .iter()
                .all(|index| index.name != "parent_code_lookup")
        );
        assert!(
            parent
                .indexes
                .iter()
                .any(|index| index.name == "parent_indexed_lookup"),
            "an unrelated user index must remain"
        );
        let child = definitions
            .iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        assert_eq!(child.foreign_keys.len(), 2);
        assert!(
            child
                .foreign_keys
                .iter()
                .all(|foreign_key| foreign_key.name.as_deref() != Some("child_parent_code_fkey"))
        );
        assert!(
            definitions
                .iter()
                .find(|definition| definition.name == "second_child")
                .unwrap()
                .foreign_keys
                .is_empty()
        );
        engine
            .execute(request("INSERT INTO child VALUES (2, 1, 'missing', 1)"))
            .unwrap();

        engine
            .execute(request("ALTER TABLE parent DROP COLUMN guarded CASCADE"))
            .unwrap();
        assert!(
            engine
                .table_definitions()
                .iter()
                .find(|definition| definition.name == "parent")
                .unwrap()
                .check_constraints
                .is_empty(),
            "a CHECK that reads the dropped column must be removed"
        );

        engine
            .execute(request("ALTER TABLE parent DROP COLUMN id CASCADE"))
            .unwrap();
        let definitions = engine.table_definitions();
        let parent = definitions
            .iter()
            .find(|definition| definition.name == "parent")
            .unwrap();
        assert!(parent.primary_key.is_empty());
        assert!(
            parent.foreign_keys.is_empty(),
            "the self-reference is removed"
        );
        let child = definitions
            .iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        assert_eq!(child.foreign_keys.len(), 1);
        assert_eq!(
            child.foreign_keys[0].name.as_deref(),
            Some("child_other_fkey")
        );
        engine
            .execute(request("INSERT INTO child VALUES (3, 999, 'missing', 1)"))
            .unwrap();
        assert!(
            engine
                .execute(request("INSERT INTO child VALUES (4, 999, 'missing', 999)"))
                .is_err(),
            "the unrelated foreign key must remain enforced"
        );
        let missing = engine
            .execute(request(
                "ALTER TABLE parent DROP COLUMN IF EXISTS missing CASCADE",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            missing.results[0],
            SqlResult::Definition {
                affected_objects: 0
            }
        ));

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let definitions = reopened.table_definitions();
        let parent = definitions
            .iter()
            .find(|definition| definition.name == "parent")
            .unwrap();
        assert_eq!(
            parent
                .columns
                .iter()
                .map(|column| column.name.as_str())
                .collect::<Vec<_>>(),
            vec!["indexed", "manager_id"]
        );
        assert!(parent.primary_key.is_empty());
        assert!(parent.unique_constraints.is_empty());
        assert!(parent.foreign_keys.is_empty());
        assert!(parent.check_constraints.is_empty());
        let child = definitions
            .iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        assert_eq!(child.foreign_keys.len(), 1);
        assert_eq!(
            child.foreign_keys[0].name.as_deref(),
            Some("child_other_fkey")
        );
    }

    #[test]
    fn multi_drop_column_rewrites_once_and_rolls_back_the_whole_statement() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY, tenant INTEGER, code TEXT, guarded INTEGER CHECK (guarded > 0), obsolete TEXT, keep TEXT, CONSTRAINT parent_tenant_code_key UNIQUE (tenant, code))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE INDEX parent_obsolete_keep_idx ON parent(obsolete, keep)",
            ))
            .unwrap();
        engine
            .execute(request("CREATE INDEX parent_keep_idx ON parent(keep)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, tenant INTEGER, parent_code TEXT, CONSTRAINT child_parent_fkey FOREIGN KEY (tenant, parent_code) REFERENCES parent(tenant, code))",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO parent VALUES (1, 7, 'known', 9, 'remove', 'preserve')",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (1, 7, 'known')"))
            .unwrap();

        assert!(
            engine
                .execute(request(
                    "ALTER TABLE parent DROP COLUMN tenant, ADD COLUMN added INTEGER",
                ))
                .is_err(),
            "mixed multi-operation ALTER TABLE must fail before mutation"
        );
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE parent DROP COLUMN keep, DROP COLUMN id",
                ))
                .is_err(),
            "a RESTRICT dependency must roll back every column drop"
        );
        let unchanged = engine
            .execute(request(
                "SELECT id, tenant, code, guarded, obsolete, keep FROM parent",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &unchanged.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Integer(7),
                    RelationalValue::Text("known".into()),
                    RelationalValue::Integer(9),
                    RelationalValue::Text("remove".into()),
                    RelationalValue::Text("preserve".into()),
                ]]
        ));

        let context = audit("multi-drop-column-snapshot");
        let snapshot = engine.begin_interactive(&context).unwrap();
        let result = engine
            .execute(request(
                "ALTER TABLE parent DROP COLUMN obsolete CASCADE, DROP COLUMN code CASCADE, DROP COLUMN guarded CASCADE",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            result.results[0],
            SqlResult::Definition {
                affected_objects: 3
            }
        ));
        let old_view = engine
            .execute_interactive(
                &snapshot.handle,
                request("SELECT code, guarded, obsolete FROM parent"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old_view.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Text("known".into()),
                    RelationalValue::Integer(9),
                    RelationalValue::Text("remove".into()),
                ]]
        ));
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();

        let definitions = engine.table_definitions();
        let parent = definitions
            .iter()
            .find(|definition| definition.name == "parent")
            .unwrap();
        assert_eq!(
            parent
                .columns
                .iter()
                .map(|column| column.name.as_str())
                .collect::<Vec<_>>(),
            vec!["id", "tenant", "keep"]
        );
        assert!(parent.unique_constraints.is_empty());
        assert!(parent.check_constraints.is_empty());
        assert_eq!(parent.indexes.len(), 1);
        assert_eq!(parent.indexes[0].name, "parent_keep_idx");
        assert!(
            definitions
                .iter()
                .find(|definition| definition.name == "child")
                .unwrap()
                .foreign_keys
                .is_empty()
        );
        engine
            .execute(request("INSERT INTO child VALUES (2, 999, 'orphan')"))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE parent DROP COLUMN id CASCADE, DROP COLUMN tenant, DROP COLUMN keep",
                ))
                .is_err(),
            "dropping every remaining column must roll back the statement"
        );

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened
            .execute(request("SELECT id, tenant, keep FROM parent"))
            .unwrap()
            .response;
        assert!(matches!(
            &recovered.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Integer(7),
                    RelationalValue::Text("preserve".into()),
                ]]
        ));
    }

    #[test]
    fn rename_column_updates_indexes_checks_and_foreign_keys_atomically() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE, guarded INTEGER CHECK (guarded > 0), label TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("CREATE INDEX parent_label_idx ON parent(label)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_code TEXT REFERENCES parent(code) ON UPDATE CASCADE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE nodes (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES nodes(id))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1, 'p-1', 7, 'lookup')"))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (10, 'p-1')"))
            .unwrap();

        let context = audit("rename-snapshot");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request(
                "ALTER TABLE parent RENAME COLUMN code TO external_code",
            ))
            .unwrap();
        let old_view = engine
            .execute_interactive(
                &snapshot.handle,
                request("SELECT code FROM parent"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old_view.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("p-1".into())]]
        ));
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();
        assert!(engine.execute(request("SELECT code FROM parent")).is_err());

        engine
            .execute(request(
                "UPDATE parent SET external_code = 'p-2' WHERE id = 1",
            ))
            .unwrap();
        let cascaded = engine
            .execute(request("SELECT parent_code FROM child WHERE id = 10"))
            .unwrap()
            .response;
        assert!(matches!(
            &cascaded.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("p-2".into())]]
        ));

        engine
            .execute(request(
                "ALTER TABLE parent RENAME COLUMN guarded TO quantity",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request("UPDATE parent SET quantity = -1 WHERE id = 1"))
                .is_err()
        );
        engine
            .execute(request("UPDATE parent SET quantity = 8 WHERE id = 1"))
            .unwrap();
        engine
            .execute(request("ALTER TABLE parent RENAME COLUMN label TO tag"))
            .unwrap();
        let indexed = engine
            .execute(request(
                "SELECT id, external_code, quantity FROM parent WHERE tag = 'lookup'",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &indexed.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Text("p-2".into()),
                    RelationalValue::Integer(8),
                ]]
        ));

        engine
            .execute(request("ALTER TABLE nodes RENAME COLUMN id TO node_id"))
            .unwrap();
        engine
            .execute(request("INSERT INTO nodes VALUES (1, NULL), (2, 1)"))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE parent RENAME COLUMN external_code TO id",
                ))
                .is_err()
        );
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE parent RENAME COLUMN missing TO present"
                ))
                .is_err()
        );

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened
            .execute(request(
                "SELECT id, external_code, quantity FROM parent WHERE tag = 'lookup'",
            ))
            .unwrap()
            .response;
        assert_eq!(recovered.results, indexed.results);
        let nodes = reopened
            .execute(request(
                "SELECT node_id, parent_id FROM nodes ORDER BY node_id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &nodes.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1), RelationalValue::Null],
                    vec![RelationalValue::Integer(2), RelationalValue::Integer(1)],
                ]
        ));
    }

    #[test]
    fn rename_table_preserves_identity_snapshots_foreign_keys_and_recovery() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY, manager_id INTEGER REFERENCES parent(id) ON UPDATE CASCADE ON DELETE CASCADE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON UPDATE CASCADE ON DELETE CASCADE)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1, NULL), (2, 1)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (10, 1)"))
            .unwrap();
        let before = engine
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "parent")
            .unwrap();

        let context = audit("rename-table-snapshot");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request("ALTER TABLE parent RENAME TO accounts"))
            .unwrap();
        let old_view = engine
            .execute_interactive(
                &snapshot.handle,
                request("SELECT id, manager_id FROM parent ORDER BY id"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old_view.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(1), RelationalValue::Null],
                    vec![RelationalValue::Integer(2), RelationalValue::Integer(1)],
                ]
        ));
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();
        assert!(engine.execute(request("SELECT id FROM parent")).is_err());

        let after = engine
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "accounts")
            .unwrap();
        assert_eq!(after.table_id, before.table_id);
        assert_eq!(after.primary_key_index_id, before.primary_key_index_id);
        assert_eq!(after.foreign_keys[0].referenced_table, "accounts");
        let child = engine
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        assert_eq!(child.foreign_keys[0].referenced_table, "accounts");

        engine
            .execute(request("UPDATE accounts SET id = 3 WHERE id = 1"))
            .unwrap();
        let self_reference = engine
            .execute(request("SELECT manager_id FROM accounts WHERE id = 2"))
            .unwrap()
            .response;
        assert!(matches!(
            &self_reference.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(3)]]
        ));
        let external_reference = engine
            .execute(request("SELECT parent_id FROM child WHERE id = 10"))
            .unwrap()
            .response;
        assert!(matches!(
            &external_reference.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(3)]]
        ));

        engine
            .execute(request("CREATE TABLE occupied (id INTEGER PRIMARY KEY)"))
            .unwrap();
        assert!(
            engine
                .execute(request("ALTER TABLE accounts RENAME TO occupied"))
                .is_err()
        );
        let no_op = engine
            .execute(request("ALTER TABLE accounts RENAME TO accounts"))
            .unwrap()
            .response;
        assert!(matches!(
            no_op.results[0],
            SqlResult::Definition {
                affected_objects: 0
            }
        ));

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened
            .execute(request("SELECT id, manager_id FROM accounts ORDER BY id"))
            .unwrap()
            .response;
        assert!(matches!(
            &recovered.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![RelationalValue::Integer(2), RelationalValue::Integer(3)],
                    vec![RelationalValue::Integer(3), RelationalValue::Null],
                ]
        ));
        reopened
            .execute(request("DELETE FROM accounts WHERE id = 3"))
            .unwrap();
        let remaining = reopened
            .execute(request("SELECT COUNT(*) FROM accounts"))
            .unwrap()
            .response;
        assert!(matches!(
            &remaining.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));
        let child_remaining = reopened
            .execute(request("SELECT COUNT(*) FROM child"))
            .unwrap()
            .response;
        assert!(matches!(
            &child_remaining.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]]
        ));
    }

    #[test]
    fn alter_column_type_rewrites_atomically_and_rejects_unsafe_conversions() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE metrics (id INTEGER PRIMARY KEY, score INTEGER, label VARCHAR(8))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO metrics VALUES (1, 32768, 'ready')"))
            .unwrap();
        let before = engine
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "metrics")
            .unwrap();

        let context = audit("alter-type-snapshot");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request(
                "ALTER TABLE metrics ALTER COLUMN score TYPE BIGINT",
            ))
            .unwrap();
        let old_view = engine
            .execute_interactive(
                &snapshot.handle,
                request("SELECT score FROM metrics"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old_view.results[0],
            SqlResult::Rows {
                column_types,
                rows,
                ..
            } if column_types == &vec![RelationalType::Integer]
                && rows == &vec![vec![RelationalValue::Integer(32768)]]
        ));
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();

        let after = engine
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "metrics")
            .unwrap();
        assert_eq!(after.table_id, before.table_id);
        assert_eq!(after.primary_key_index_id, before.primary_key_index_id);
        assert_eq!(after.columns[1].data_type, RelationalType::BigInt);
        let current = engine
            .execute(request("SELECT score FROM metrics"))
            .unwrap()
            .response;
        assert!(matches!(
            &current.results[0],
            SqlResult::Rows {
                column_types,
                rows,
                ..
            } if column_types == &vec![RelationalType::BigInt]
                && rows == &vec![vec![RelationalValue::Integer(32768)]]
        ));

        assert!(
            engine
                .execute(request(
                    "ALTER TABLE metrics ALTER COLUMN score TYPE SMALLINT",
                ))
                .is_err(),
            "narrowing must reject a value outside the target range"
        );
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE metrics ALTER COLUMN label TYPE VARCHAR(3)",
                ))
                .is_err(),
            "varchar narrowing must reject an existing long value"
        );
        assert!(
            engine
                .execute(request("ALTER TABLE metrics ALTER COLUMN score TYPE TEXT",))
                .is_err(),
            "storage-changing conversion must fail closed"
        );
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE metrics ALTER COLUMN score TYPE INTEGER USING score::INTEGER",
                ))
                .is_err(),
            "USING is not accepted until row-expression conversion is implemented"
        );
        let no_op = engine
            .execute(request(
                "ALTER TABLE metrics ALTER COLUMN score TYPE BIGINT",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            no_op.results[0],
            SqlResult::Definition {
                affected_objects: 0
            }
        ));

        engine
            .execute(request("CREATE TABLE child (id INTEGER PRIMARY KEY, metric_id INTEGER REFERENCES metrics(id))"))
            .unwrap();
        assert!(
            engine
                .execute(request("ALTER TABLE metrics ALTER COLUMN id TYPE BIGINT",))
                .is_err(),
            "one-sided FK type changes must roll back"
        );

        engine
            .execute(request("ALTER TABLE metrics ALTER COLUMN label TYPE TEXT"))
            .unwrap();
        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened
            .execute(request("SELECT score, label FROM metrics"))
            .unwrap()
            .response;
        assert!(matches!(
            &recovered.results[0],
            SqlResult::Rows {
                column_types,
                rows,
                ..
            } if column_types == &vec![RelationalType::BigInt, RelationalType::Text]
                && rows == &vec![vec![
                    RelationalValue::Integer(32768),
                    RelationalValue::Text("ready".into()),
                ]]
        ));
    }

    #[test]
    fn alter_column_nullability_and_default_validate_snapshot_and_recover() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE settings (id INTEGER PRIMARY KEY, note TEXT, retries INTEGER DEFAULT 1, required TEXT NOT NULL)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO settings (id, note, required) VALUES (1, NULL, 'ready')",
            ))
            .unwrap();

        assert!(
            engine
                .execute(request(
                    "ALTER TABLE settings ALTER COLUMN note SET NOT NULL",
                ))
                .is_err(),
            "SET NOT NULL must validate existing rows before publication"
        );
        engine
            .execute(request("UPDATE settings SET note = 'filled' WHERE id = 1"))
            .unwrap();

        let context = audit("alter-column-snapshot");
        let old_snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request(
                "ALTER TABLE settings ALTER COLUMN note SET NOT NULL",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "INSERT INTO settings (id, note, required) VALUES (2, NULL, 'current')",
                ))
                .is_err()
        );
        engine
            .execute_interactive(
                &old_snapshot.handle,
                request("INSERT INTO settings (id, note, required) VALUES (2, NULL, 'snapshot')"),
                &context,
            )
            .unwrap();
        engine
            .rollback_interactive(&old_snapshot.handle, &context)
            .unwrap();

        assert!(
            engine
                .execute(request(
                    "ALTER TABLE settings ALTER COLUMN id DROP NOT NULL",
                ))
                .is_err(),
            "primary-key nullability cannot be weakened"
        );
        engine
            .execute(request(
                "ALTER TABLE settings ALTER COLUMN note DROP NOT NULL",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO settings (id, note, required) VALUES (2, NULL, 'nullable')",
            ))
            .unwrap();

        engine
            .execute(request(
                "ALTER TABLE settings ALTER COLUMN retries SET DEFAULT 7",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO settings (id, note, required) VALUES (3, 'defaulted', 'ready')",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE settings ALTER COLUMN required SET DEFAULT NULL",
                ))
                .is_err(),
            "NOT NULL columns cannot acquire a NULL default"
        );
        engine
            .execute(request(
                "ALTER TABLE settings ALTER COLUMN retries DROP DEFAULT",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO settings (id, note, required) VALUES (4, 'no-default', 'ready')",
            ))
            .unwrap();
        let rows = engine
            .execute(request(
                "SELECT id, note, retries FROM settings ORDER BY id",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &rows.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![
                    vec![
                        RelationalValue::Integer(1),
                        RelationalValue::Text("filled".into()),
                        RelationalValue::Integer(1),
                    ],
                    vec![
                        RelationalValue::Integer(2),
                        RelationalValue::Null,
                        RelationalValue::Integer(1),
                    ],
                    vec![
                        RelationalValue::Integer(3),
                        RelationalValue::Text("defaulted".into()),
                        RelationalValue::Integer(7),
                    ],
                    vec![
                        RelationalValue::Integer(4),
                        RelationalValue::Text("no-default".into()),
                        RelationalValue::Null,
                    ],
                ]
        ));

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let definition = reopened
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "settings")
            .unwrap();
        assert!(definition.columns[1].nullable);
        assert_eq!(definition.columns[2].default, None);
        let recovered = reopened
            .execute(request(
                "SELECT id, note, retries FROM settings ORDER BY id",
            ))
            .unwrap()
            .response;
        assert_eq!(recovered.results, rows.results);
    }

    #[test]
    fn alter_primary_and_unique_constraints_validate_dependencies_and_recover() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE accounts (tenant INTEGER, code TEXT, note TEXT)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO accounts VALUES (1, 'A', 'first'), (1, 'A', 'duplicate')",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE accounts ADD CONSTRAINT accounts_tenant_code_key UNIQUE (tenant, code)",
                ))
                .is_err(),
            "ADD UNIQUE must validate existing rows atomically"
        );
        engine
            .execute(request("DELETE FROM accounts WHERE note = 'duplicate'"))
            .unwrap();
        engine
            .execute(request(
                "CREATE INDEX accounts_lookup ON accounts (tenant, code)",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE accounts ADD CONSTRAINT accounts_tenant_code_key UNIQUE (tenant, code)",
            ))
            .unwrap();
        let accounts = engine
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "accounts")
            .unwrap();
        assert_eq!(
            accounts.unique_constraints[0].index_id, accounts.indexes[0].index_id,
            "a compatible physical index is shared by catalog ownership"
        );
        engine
            .execute(request(
                "ALTER TABLE accounts ADD CONSTRAINT accounts_tenant_code_key_2 UNIQUE (tenant, code)",
            ))
            .unwrap();

        engine
            .execute(request(
                "CREATE TABLE refs (id INTEGER PRIMARY KEY, tenant INTEGER, code TEXT, CONSTRAINT refs_account_fkey FOREIGN KEY (tenant, code) REFERENCES accounts (tenant, code))",
            ))
            .unwrap();
        let refs = engine
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "refs")
            .unwrap();
        assert_eq!(
            refs.foreign_keys[0].referenced_key_name.as_deref(),
            Some("accounts_tenant_code_key")
        );
        assert_eq!(
            refs.foreign_keys[0].referenced_key_kind,
            Some(ReferencedKeyKind::UniqueConstraint)
        );
        engine
            .execute(request(
                "ALTER TABLE accounts DROP CONSTRAINT accounts_tenant_code_key_2",
            ))
            .unwrap();
        let dependency_error = engine
            .execute(request(
                "ALTER TABLE accounts DROP CONSTRAINT accounts_tenant_code_key",
            ))
            .err()
            .expect("a referenced UNIQUE constraint cannot be dropped");
        assert!(
            dependency_error
                .to_string()
                .contains("foreign key refs_account_fkey on table refs depends on it"),
            "a referenced UNIQUE constraint must report its dependent foreign key: {dependency_error}"
        );
        engine
            .execute(request(
                "ALTER TABLE refs DROP CONSTRAINT refs_account_fkey",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE accounts DROP CONSTRAINT accounts_tenant_code_key",
            ))
            .unwrap();
        let accounts = engine
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "accounts")
            .unwrap();
        assert!(accounts.unique_constraints.is_empty());
        assert_eq!(accounts.indexes.len(), 1, "user index ownership remains");

        engine
            .execute(request(
                "CREATE TABLE durable_parent (id INTEGER, CONSTRAINT durable_parent_key UNIQUE (id))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE durable_child (id INTEGER PRIMARY KEY, parent_id INTEGER, CONSTRAINT durable_child_parent_fkey FOREIGN KEY (parent_id) REFERENCES durable_parent(id))",
            ))
            .unwrap();

        engine
            .execute(request("CREATE TABLE identities (id INTEGER, label TEXT)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO identities VALUES (NULL, 'missing')"))
            .unwrap();
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE identities ADD CONSTRAINT identities_pk PRIMARY KEY (id)",
                ))
                .is_err(),
            "ADD PRIMARY KEY must reject existing NULL values"
        );
        engine
            .execute(request(
                "UPDATE identities SET id = 1 WHERE label = 'missing'",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE identities ADD CONSTRAINT identities_pk PRIMARY KEY (id)",
            ))
            .unwrap();
        assert!(
            engine
                .execute(request("INSERT INTO identities VALUES (1, 'duplicate')"))
                .is_err()
        );
        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let identities = reopened
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "identities")
            .unwrap();
        assert_eq!(
            identities.primary_key_name.as_deref(),
            Some("identities_pk")
        );
        let durable_child = reopened
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "durable_child")
            .unwrap();
        assert_eq!(
            durable_child.foreign_keys[0].referenced_key_name.as_deref(),
            Some("durable_parent_key")
        );
        assert_eq!(
            durable_child.foreign_keys[0].referenced_key_kind,
            Some(ReferencedKeyKind::UniqueConstraint)
        );
        reopened
            .execute(request(
                "ALTER TABLE identities DROP CONSTRAINT identities_pk",
            ))
            .unwrap();
        reopened
            .execute(request("INSERT INTO identities VALUES (1, 'allowed')"))
            .unwrap();
        let count = reopened
            .execute(request("SELECT COUNT(*) AS total FROM identities"))
            .unwrap()
            .response;
        assert!(matches!(
            &count.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(2)]]
        ));
    }

    #[test]
    fn rename_constraint_updates_fk_owners_snapshots_and_recovery() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parent (id INTEGER, code TEXT, guarded INTEGER, CONSTRAINT parent_pk PRIMARY KEY (id), CONSTRAINT parent_code_key UNIQUE (code), CONSTRAINT parent_guard CHECK (guarded > 0))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER, parent_code TEXT, CONSTRAINT child_parent_fkey FOREIGN KEY (parent_id) REFERENCES parent(id), CONSTRAINT child_code_fkey FOREIGN KEY (parent_code) REFERENCES parent(code))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1, 'one', 1)"))
            .unwrap();

        let context = audit("constraint-snapshot");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request(
                "ALTER TABLE parent RENAME CONSTRAINT parent_code_key TO parent_code_uq",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE parent RENAME CONSTRAINT parent_pk TO parent_identity_pk",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE parent RENAME CONSTRAINT parent_guard TO parent_guard_positive",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE child RENAME CONSTRAINT child_parent_fkey TO child_parent_reference",
            ))
            .unwrap();

        let old_snapshot_result = engine
            .execute_interactive(
                &snapshot.handle,
                request(
                    "INSERT INTO parent VALUES (2, 'one', 1) ON CONFLICT ON CONSTRAINT parent_code_key DO NOTHING",
                ),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old_snapshot_result.results[0],
            SqlResult::Mutation { affected_rows: 0 }
        ));
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();

        assert!(
            engine
                .execute(request(
                    "INSERT INTO parent VALUES (2, 'one', 1) ON CONFLICT ON CONSTRAINT parent_code_key DO NOTHING",
                ))
                .is_err(),
            "the old constraint name must disappear from the current catalog"
        );
        let current_result = engine
            .execute(request(
                "INSERT INTO parent VALUES (2, 'one', 1) ON CONFLICT ON CONSTRAINT parent_code_uq DO NOTHING",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &current_result.results[0],
            SqlResult::Mutation { affected_rows: 0 }
        ));

        let definitions = engine.table_definitions();
        let parent = definitions
            .iter()
            .find(|definition| definition.name == "parent")
            .unwrap();
        let child = definitions
            .iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        assert_eq!(
            parent.primary_key_name.as_deref(),
            Some("parent_identity_pk")
        );
        assert_eq!(
            parent.unique_constraints[0].name.as_deref(),
            Some("parent_code_uq")
        );
        assert_eq!(
            parent.check_constraints[0].name.as_deref(),
            Some("parent_guard_positive")
        );
        assert_eq!(
            child.foreign_keys[0].name.as_deref(),
            Some("child_parent_reference")
        );
        assert_eq!(
            child.foreign_keys[0].referenced_key_name.as_deref(),
            Some("parent_identity_pk")
        );
        assert_eq!(
            child.foreign_keys[1].referenced_key_name.as_deref(),
            Some("parent_code_uq")
        );

        assert!(
            engine
                .execute(request("ALTER TABLE parent DROP CONSTRAINT parent_code_uq",))
                .is_err(),
            "renamed referenced key must retain its dependency"
        );
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE parent RENAME CONSTRAINT missing TO replacement",
                ))
                .is_err()
        );
        assert!(
            engine
                .execute(request(
                    "ALTER TABLE parent RENAME CONSTRAINT parent_code_uq TO parent_identity_pk",
                ))
                .is_err()
        );
        let no_op = engine
            .execute(request(
                "ALTER TABLE parent RENAME CONSTRAINT parent_code_uq TO parent_code_uq",
            ))
            .unwrap()
            .response;
        assert!(matches!(
            &no_op.results[0],
            SqlResult::Definition {
                affected_objects: 0
            }
        ));

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened.table_definitions();
        let recovered_parent = recovered
            .iter()
            .find(|definition| definition.name == "parent")
            .unwrap();
        let recovered_child = recovered
            .iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        assert_eq!(
            recovered_parent.primary_key_name.as_deref(),
            Some("parent_identity_pk")
        );
        assert_eq!(
            recovered_child.foreign_keys[1]
                .referenced_key_name
                .as_deref(),
            Some("parent_code_uq")
        );
    }

    #[test]
    fn drop_constraint_cascade_removes_exact_dependent_foreign_keys_atomically() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY, code TEXT, manager_code TEXT)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE UNIQUE INDEX parent_code_lookup ON parent (code)",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE parent ADD CONSTRAINT parent_code_key UNIQUE (code)",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE parent ADD CONSTRAINT parent_manager_fkey FOREIGN KEY (manager_code) REFERENCES parent(code)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child_a (id INTEGER PRIMARY KEY, parent_id INTEGER, parent_code TEXT, CONSTRAINT child_a_id_fkey FOREIGN KEY (parent_id) REFERENCES parent(id), CONSTRAINT child_a_code_fkey FOREIGN KEY (parent_code) REFERENCES parent(code))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child_b (id INTEGER PRIMARY KEY, parent_code TEXT, CONSTRAINT child_b_code_fkey FOREIGN KEY (parent_code) REFERENCES parent(code))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1, 'one', NULL)"))
            .unwrap();

        let context = audit("drop-constraint-cascade-snapshot");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request(
                "ALTER TABLE parent DROP CONSTRAINT parent_code_key CASCADE",
            ))
            .unwrap();

        assert!(
            engine
                .execute_interactive(
                    &snapshot.handle,
                    request("INSERT INTO child_b VALUES (1, 'missing')"),
                    &context,
                )
                .is_err(),
            "the old snapshot must retain the foreign key"
        );
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();

        let definitions = engine.table_definitions();
        let parent = definitions
            .iter()
            .find(|definition| definition.name == "parent")
            .unwrap();
        let child_a = definitions
            .iter()
            .find(|definition| definition.name == "child_a")
            .unwrap();
        let child_b = definitions
            .iter()
            .find(|definition| definition.name == "child_b")
            .unwrap();
        assert!(parent.unique_constraints.is_empty());
        assert_eq!(
            parent.indexes.len(),
            1,
            "independently owned user index remains"
        );
        assert!(parent.foreign_keys.is_empty(), "self-reference is cascaded");
        assert_eq!(child_a.foreign_keys.len(), 1);
        assert_eq!(
            child_a.foreign_keys[0].name.as_deref(),
            Some("child_a_id_fkey"),
            "an FK to a different key owner must remain"
        );
        assert!(child_b.foreign_keys.is_empty());

        engine
            .execute(request("INSERT INTO child_b VALUES (1, 'missing')"))
            .unwrap();
        assert!(
            engine
                .execute(request("INSERT INTO child_a VALUES (2, 999, 'missing')"))
                .is_err(),
            "the unrelated primary-key FK must still be enforced"
        );
        engine
            .execute(request("INSERT INTO child_a VALUES (2, 1, 'missing')"))
            .unwrap();

        engine
            .execute(request(
                "CREATE TABLE identity_parent (id INTEGER PRIMARY KEY)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE identity_child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES identity_parent(id))",
            ))
            .unwrap();
        engine
            .execute(request(
                "ALTER TABLE identity_parent DROP CONSTRAINT identity_parent_pkey CASCADE",
            ))
            .unwrap();
        let definitions = engine.table_definitions();
        assert!(
            definitions
                .iter()
                .find(|definition| definition.name == "identity_child")
                .unwrap()
                .foreign_keys
                .is_empty(),
            "primary-key dependencies are cascaded too"
        );

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let recovered = reopened.table_definitions();
        assert!(
            recovered
                .iter()
                .find(|definition| definition.name == "parent")
                .unwrap()
                .unique_constraints
                .is_empty()
        );
        assert!(
            recovered
                .iter()
                .find(|definition| definition.name == "child_b")
                .unwrap()
                .foreign_keys
                .is_empty()
        );
    }

    #[test]
    fn drop_table_cascade_removes_external_foreign_keys_atomically() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE other_parent (id INTEGER PRIMARY KEY)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER, parent_code TEXT, other_id INTEGER, CONSTRAINT child_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES parent(id), CONSTRAINT child_parent_code_fkey FOREIGN KEY (parent_code) REFERENCES parent(code), CONSTRAINT child_other_fkey FOREIGN KEY (other_id) REFERENCES other_parent(id))",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE INDEX child_parent_lookup ON child(parent_id)",
            ))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE second_child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1, 'known')"))
            .unwrap();
        engine
            .execute(request("INSERT INTO other_parent VALUES (1)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (1, 1, 'known', 1)"))
            .unwrap();

        let restrict = engine
            .execute(request("DROP TABLE parent"))
            .err()
            .expect("RESTRICT must reject an externally referenced table");
        assert!(
            restrict
                .to_string()
                .contains("foreign key child_parent_code_fkey on table child depends on it")
                || restrict
                    .to_string()
                    .contains("foreign key child_parent_id_fkey on table child depends on it"),
            "dependency error names a deterministic first child and FK: {restrict}"
        );

        let context = audit("drop-table-cascade-snapshot");
        let snapshot = engine.begin_interactive(&context).unwrap();
        engine
            .execute(request("DROP TABLE parent CASCADE"))
            .unwrap();

        let old_snapshot = engine
            .execute_interactive(
                &snapshot.handle,
                request("SELECT id, code FROM parent"),
                &context,
            )
            .unwrap();
        assert!(matches!(
            &old_snapshot.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Text("known".into()),
                ]]
        ));
        engine
            .rollback_interactive(&snapshot.handle, &context)
            .unwrap();
        assert!(engine.execute(request("SELECT id FROM parent")).is_err());

        let definitions = engine.table_definitions();
        let child = definitions
            .iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        assert_eq!(child.foreign_keys.len(), 1);
        assert_eq!(
            child.foreign_keys[0].name.as_deref(),
            Some("child_other_fkey")
        );
        assert!(
            child
                .indexes
                .iter()
                .any(|index| index.name == "child_parent_lookup"),
            "independently owned child index must remain"
        );
        assert!(
            definitions
                .iter()
                .find(|definition| definition.name == "second_child")
                .unwrap()
                .foreign_keys
                .is_empty()
        );

        engine
            .execute(request("INSERT INTO child VALUES (2, 999, 'missing', 1)"))
            .unwrap();
        assert!(
            engine
                .execute(request("INSERT INTO child VALUES (3, 999, 'missing', 999)"))
                .is_err(),
            "the unrelated foreign key must remain enforced"
        );
        let missing = engine
            .execute(request("DROP TABLE IF EXISTS missing CASCADE"))
            .unwrap()
            .response;
        assert!(matches!(
            missing.results[0],
            SqlResult::Definition {
                affected_objects: 0
            }
        ));

        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        assert!(
            reopened
                .table_definitions()
                .iter()
                .all(|definition| definition.name != "parent")
        );
        let recovered_child = reopened
            .table_definitions()
            .into_iter()
            .find(|definition| definition.name == "child")
            .unwrap();
        assert_eq!(recovered_child.foreign_keys.len(), 1);
        assert_eq!(
            recovered_child.foreign_keys[0].name.as_deref(),
            Some("child_other_fkey")
        );
    }

    #[test]
    fn pure_drop_only_skips_row_validation_for_unchanged_survivors() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1)"))
            .unwrap();
        engine
            .execute(request("INSERT INTO child VALUES (1, 1)"))
            .unwrap();

        let before = engine.state.read().clone();
        let mut after = before.clone();
        after.tables.remove("child").unwrap();
        let drop_child = vec![RelationalMutation::DropTable {
            name: "child".into(),
        }];
        assert!(pure_drop_preserves_validity(&after, &before, &drop_child));

        let mut changed = after.clone();
        Arc::make_mut(changed.tables.get_mut("parent").unwrap().unwrap()).next_row_id += 1;
        assert!(!pure_drop_preserves_validity(
            &changed,
            &before,
            &drop_child
        ));

        let mut dangling = before.clone();
        dangling.tables.remove("parent").unwrap();
        assert!(!pure_drop_preserves_validity(
            &dangling,
            &before,
            &[RelationalMutation::DropTable {
                name: "parent".into(),
            }]
        ));
        assert!(!pure_drop_preserves_validity(
            &after,
            &before,
            &[drop_child[0].clone(), drop_child[0].clone()]
        ));
    }

    #[test]
    fn wide_dml_candidates_and_fk_actions_reject_before_partial_mutation() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE, payload TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1)"))
            .unwrap();
        let payload = "x".repeat(query_operator_budget() / 4);
        for id in 1..=2 {
            engine
                .execute(request(&format!(
                    "INSERT INTO child VALUES ({id}, 1, '{payload}')"
                )))
                .unwrap();
        }

        for sql in [
            "UPDATE child SET payload = 'changed' WHERE id > 0",
            "DELETE FROM parent WHERE id = 1",
        ] {
            let error = match engine.execute(request(sql)) {
                Ok(_) => panic!("oversized DML unexpectedly committed: {sql}"),
                Err(error) => error,
            };
            assert!(matches!(&error, GaussError::ResourceExhausted(_)));
            assert!(error.to_string().contains("SQL operator memory budget"));
        }
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        for sql in ["SELECT COUNT(*) FROM parent", "SELECT COUNT(*) FROM child"] {
            let result = reopened.execute(request(sql)).unwrap();
            assert!(
                matches!(&result.response.results[0], SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(if sql.contains("parent") { 1 } else { 2 })]])
            );
        }
        for id in 1..=2 {
            let result = reopened
                .execute(request(&format!(
                    "SELECT payload FROM child WHERE id = {id}"
                )))
                .unwrap();
            assert!(
                matches!(&result.response.results[0], SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text(payload.clone())]])
            );
        }
    }

    #[test]
    fn cascading_child_buffers_share_one_byte_budget_and_reopen_atomically() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        for child in ["child_a", "child_b", "child_c"] {
            engine
                .execute(request(&format!(
                    "CREATE TABLE {child} (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE, payload TEXT)"
                )))
                .unwrap();
        }
        engine
            .execute(request("INSERT INTO parent VALUES (1)"))
            .unwrap();
        let payload = "x".repeat(query_operator_budget() / 5);
        for child in ["child_a", "child_b", "child_c"] {
            engine
                .execute(request(&format!(
                    "INSERT INTO {child} VALUES (1, 1, '{payload}')"
                )))
                .unwrap();
        }
        engine
            .execute(request(&format!(
                "UPDATE child_a SET payload = '{payload}' WHERE id = 1"
            )))
            .unwrap();

        let error = match engine.execute(request("DELETE FROM parent WHERE id = 1")) {
            Ok(_) => panic!("combined cascade buffers unexpectedly committed"),
            Err(error) => error,
        };
        assert!(matches!(&error, GaussError::ResourceExhausted(_)));
        assert!(error.to_string().contains("SQL operator memory budget"));
        drop(engine);
        drop(journal);

        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        for table in ["parent", "child_a", "child_b", "child_c"] {
            let result = reopened
                .execute(request(&format!("SELECT COUNT(*) FROM {table}")))
                .unwrap();
            assert!(
                matches!(&result.response.results[0], SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1)]])
            );
        }
        for child in ["child_a", "child_b", "child_c"] {
            let result = reopened
                .execute(request(&format!(
                    "SELECT payload FROM {child} WHERE id = 1"
                )))
                .unwrap();
            assert!(
                matches!(&result.response.results[0], SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text(payload.clone())]])
            );
        }
    }

    #[test]
    fn single_wide_cascade_within_budget_remains_available() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request(
                "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE, payload TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO parent VALUES (1)"))
            .unwrap();
        let payload = "x".repeat(query_operator_budget() / 4);
        engine
            .execute(request(&format!(
                "INSERT INTO child VALUES (1, 1, '{payload}')"
            )))
            .unwrap();

        let result = engine.execute(request("DELETE FROM parent WHERE id = 1"));
        assert!(
            result.is_ok(),
            "one wide cascade should fit: {:?}",
            result.err()
        );
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        for table in ["parent", "child"] {
            let result = reopened
                .execute(request(&format!("SELECT COUNT(*) FROM {table}")))
                .unwrap();
            assert!(
                matches!(&result.response.results[0], SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(0)]])
            );
        }
    }

    #[test]
    fn background_checkpoint_does_not_hold_a_durable_mutation_response() {
        let directory = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, value INTEGER)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO items VALUES (1, 1)"))
            .unwrap();
        for value in 2..=1022 {
            engine
                .execute(request(&format!(
                    "UPDATE items SET value = {value} WHERE id = 1"
                )))
                .unwrap();
        }
        assert_eq!(engine.state.read().sequence, 1023);
        engine.enable_background_checkpoints(Arc::new(()));

        let checkpoint_gate = engine.checkpoint.lock().unwrap();
        let mut mutation = request("UPDATE items SET value = 1024 WHERE id = 1");
        mutation.idempotency_key = Some("checkpoint-response".into());
        let first = engine.execute(mutation.clone()).unwrap().response;
        assert!(
            engine
                .checkpoint_worker
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
        );

        let replay = engine.execute(mutation).unwrap().response;
        assert!(first.committed);
        assert_eq!(replay.transaction_id, first.transaction_id);

        drop(checkpoint_gate);
        assert!(engine.cancel_and_drain_checkpoint(Instant::now() + Duration::from_secs(10)));
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let reopened = RelationalEngine::open(directory.path(), journal).unwrap();
        let selected = reopened
            .execute(request("SELECT value FROM items WHERE id = 1"))
            .unwrap()
            .response;
        assert!(matches!(
            &selected.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(1024)]]
        ));
    }
}

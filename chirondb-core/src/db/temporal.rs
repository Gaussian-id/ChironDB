//! Tenant-scoped temporal data owned by one collection incarnation.
use super::*;
use crate::encryption::{FileType, PersistentFile, atomic_write_persistent};
use crate::relational::wal_decode::MetadataCharge;
use crate::search::PointResolver;
use crate::security::{AccessContext, Action, SecurityError, SecurityFilter};
use crate::tenant::TenantScope;
pub use chirondb_temporal::{Point as Observation, Value as SensorValue};
use chirondb_temporal::{Segment, Series, encode_segment};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
};

pub const MAX_BATCH: usize = 1024;
pub const MAX_HISTORY: usize = 4096;
const HOT_BYTES: usize = 4 << 20;
const MAX_RUNS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalSample {
    pub asset: String,
    pub property: String,
    pub time_ns: i64,
    pub tag: u8,
    pub bits: u64,
}
impl TemporalSample {
    pub fn new(
        asset: impl Into<String>,
        property: impl Into<String>,
        time_ns: i64,
        value: SensorValue,
    ) -> Self {
        let (tag, bits) = value_bits(value);
        Self {
            asset: asset.into(),
            property: property.into(),
            time_ns,
            tag,
            bits,
        }
    }
}
fn value_bits(value: SensorValue) -> (u8, u64) {
    match value {
        SensorValue::Float(v) => (0, v.to_bits()),
        SensorValue::Boolean(v) => (2, u64::from(v)),
    }
}
fn invalid(s: &str) -> GaussError {
    GaussError::InvalidRequest(s.into())
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalBatch {
    version: u8,
    tenant: String,
    pub(crate) incarnation: Option<uuid::Uuid>,
    samples: Vec<TemporalSample>,
}
impl TemporalBatch {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != 1 || self.samples.is_empty() || self.samples.len() > MAX_BATCH {
            return Err(invalid("unsupported temporal batch version or size"));
        }

        for p in &self.samples {
            if p.asset.is_empty()
                || p.property.is_empty()
                || p.asset.len() + p.property.len() + self.tenant.len() > 4096
            {
                return Err(invalid("invalid temporal series identity"));
            }
            SensorValue::from_bits(p.tag, p.bits).map_err(|e| invalid(&e.to_string()))?;
        }
        crate::security::storage::serialized_len(self, crate::wal::MAX_WAL_RECORD_BYTES / 2)?;
        Ok(())
    }
}

/// Reconstruct activation only in verified private restore staging. An ordinary
/// open must still reject a missing/legacy fence instead of hiding corruption.
pub(in crate::db) fn prepare_restore_checkpoint(dir: &Path, entry: &WalEntry) -> Result<()> {
    let WalEntry::TemporalBatch { batch } = entry else {
        return Ok(());
    };
    batch.validate()?;
    let mut checkpoint = read_checkpoint(dir)?
        .ok_or_else(|| invalid("missing collection checkpoint in temporal restore"))?;
    if checkpoint.temporal_runs.is_none() {
        checkpoint.temporal_runs = Some(Vec::new());
        // The backup predates temporal activation. Recovered temporal records
        // start in the retained suffix; do not skip any projected suffix data.
        checkpoint.temporal_wal_lsn = Some(Wal::retained_base_lsn(&dir.join("wal"))?);
        write_checkpoint(dir, &checkpoint)?;
        durable_create_dir(&dir.join("temporal"))?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub enum TemporalAccess<'a> {
    Scoped(&'a TenantScope),
    Authorized(&'a AccessContext),
}

pub struct TemporalQuery<'a> {
    pub asset: &'a str,
    pub property: &'a str,
    pub range: Option<(i64, i64, usize)>,
    /// Predicate over asset metadata; it never replaces object/property policy.
    pub filter: Option<&'a Filter>,
}

// Seek without mapping plaintext from a protected file. PersistentFile charges
// the authenticated range and retains the immutable file identity.
struct RunCursor<'a> {
    file: &'a PersistentFile,
    pos: u64,
}
impl Read for RunCursor<'_> {
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        let start = self.pos.min(self.file.len() as u64) as usize;
        let len = dst.len().min(self.file.len() - start);
        if len == 0 {
            return Ok(0);
        }
        let bytes = self
            .file
            .read_range_admitted(start..start + len)
            .map_err(std::io::Error::other)?;
        dst[..len].copy_from_slice(&bytes);
        self.pos += len as u64;
        Ok(len)
    }
}
impl Seek for RunCursor<'_> {
    fn seek(&mut self, s: SeekFrom) -> std::io::Result<u64> {
        self.pos = match s {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => (self.file.len() as u64).checked_add_signed(n),
            SeekFrom::Current(n) => self.pos.checked_add_signed(n),
        }
        .ok_or_else(|| std::io::Error::other("invalid temporal seek"))?;
        Ok(self.pos)
    }
}

type Rows = BTreeMap<Series, BTreeMap<i64, SensorValue>>;
#[derive(Debug)]
pub(super) struct TemporalState {
    dir: PathBuf,
    enabled: bool,
    runs: Vec<(String, PersistentFile)>,
    hot: Rows,
    hot_bytes: usize,
    hot_reservations: Vec<MetadataCharge>,
}
impl TemporalState {
    pub(super) fn empty(dir: &Path) -> Self {
        Self {
            dir: dir.join("temporal"),
            enabled: false,
            runs: Vec::new(),
            hot: Rows::new(),
            hot_bytes: 0,
            hot_reservations: Vec::new(),
        }
    }
    pub(super) fn load(dir: &Path, ids: Option<Vec<String>>) -> Result<Self> {
        let mut state = Self::empty(dir);
        if let Some(ids) = ids {
            if ids.len() > MAX_RUNS {
                return Err(invalid("temporal checkpoint run limit exceeded"));
            }
            state.enabled = true;
            let mut seen = BTreeSet::new();
            for id in ids {
                if id.len() != 64
                    || !id
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                    || !seen.insert(id.clone())
                {
                    return Err(invalid("invalid temporal run reference"));
                }
                let f = PersistentFile::open(&state.dir.join(format!("{id}.ctsg")))?;
                let mut digest = Sha256::new();
                let mut reader = f.reader_at(0)?;
                let mut buf = [0u8; 8192];
                loop {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    digest.update(&buf[..n]);
                }
                if crate::encryption::hex_digest(&digest.finalize()) != id {
                    return Err(invalid("temporal checkpoint run digest mismatch"));
                }
                let mut scratch = MetadataCharge::default();
                scratch.prepare((f.len() as u64).saturating_mul(4).saturating_add(262144))?;
                Segment::open(RunCursor { file: &f, pos: 0 })?;
                state.runs.push((id, f));
            }
        }
        Ok(state)
    }
    fn flush(&mut self) -> Result<()> {
        if self.hot.is_empty() {
            return Ok(());
        }
        self.admit_new_run()?;
        let mut scratch = MetadataCharge::default();
        scratch.prepare(self.hot_bytes as u64 * 4 + 65536)?;
        let rows = self.hot.iter().flat_map(|(key, points)| {
            points
                .iter()
                .map(move |(&time, &value)| (key.clone(), Observation { time, value }))
        });
        let bytes = encode_segment(rows)?;
        let id = crate::encryption::hex_digest(&Sha256::digest(&bytes));
        let path = self.dir.join(format!("{id}.ctsg"));
        durable_create_dir(&self.dir)?;
        atomic_write_persistent(&path, FileType::Segment, &bytes)?;
        self.runs.push((id, PersistentFile::open(&path)?));
        self.hot.clear();
        self.hot_reservations.clear();
        self.hot_bytes = 0;
        Ok(())
    }
    pub(super) fn checkpoint(&mut self) -> Result<Option<Vec<String>>> {
        if !self.enabled {
            return Ok(None);
        }
        self.flush()?;
        Ok(Some(self.runs.iter().map(|(id, _)| id.clone()).collect()))
    }
    fn read(&self, key: &Series, range: Option<(i64, i64, usize)>) -> Result<Vec<Observation>> {
        let mut values = BTreeMap::new();
        let max = range.map_or(1, |r| r.2);
        let mut insert = |p: Observation| -> Result<()> {
            if let Some(previous) = values.insert(p.time, p.value)
                && value_bits(previous) != value_bits(p.value)
            {
                return Err(invalid("inconsistent temporal generations"));
            }
            if values.len() > max {
                if range.is_some() {
                    values.pop_last();
                } else {
                    values.pop_first();
                }
            }
            Ok(())
        };
        for (_, file) in &self.runs {
            let mut scratch = MetadataCharge::default();
            scratch.prepare(
                (file.len() as u64)
                    .saturating_mul(4)
                    .saturating_add((max as u64) * 256 + 262144),
            )?;
            let mut reader = Segment::open(RunCursor { file, pos: 0 })?;
            if let Some((lo, hi, n)) = range {
                for p in reader.scan_limit(key, lo, hi, n)? {
                    insert(p)?;
                }
            } else if let Some(p) = reader.latest(key)? {
                insert(p)?;
            }
        }
        if let Some(points) = self.hot.get(key) {
            if let Some((lo, hi, n)) = range {
                for (&time, &value) in points.range(lo..hi).take(n) {
                    insert(Observation { time, value })?;
                }
            } else if let Some((&time, &value)) = points.last_key_value() {
                insert(Observation { time, value })?;
            }
        }
        Ok(values
            .into_iter()
            .map(|(time, value)| Observation { time, value })
            .collect())
    }
    fn prepare(&self, batch: &TemporalBatch) -> Result<(Rows, MetadataCharge)> {
        batch.validate()?;
        let mut reservation = MetadataCharge::default();
        let cost = batch
            .samples
            .iter()
            .map(|p| (batch.tenant.len() + p.asset.len() + p.property.len() + 512) as u64 * 4)
            .sum();
        reservation.prepare(cost)?;
        let mut new = Rows::new();
        for p in &batch.samples {
            let key = Series::new(&batch.tenant, &p.asset, &p.property);
            let points = new.entry(key.clone()).or_default();
            let value = SensorValue::from_bits(p.tag, p.bits)?;
            if let Some(&prior) = points.values().next()
                && value_bits(prior).0 != p.tag
            {
                return Err(invalid("mixed types in temporal series"));
            }
            if let Some(old) = points.insert(p.time_ns, value)
                && value_bits(old) != (p.tag, p.bits)
            {
                return Err(invalid("conflicting temporal observation"));
            }
        }
        for (key, ps) in new.iter_mut() {
            if let Some(last) = self.read(key, None)?.first()
                && ps
                    .values()
                    .any(|v| value_bits(*v).0 != value_bits(last.value).0)
            {
                return Err(invalid("mixed types in temporal series"));
            }
            let mut duplicates = Vec::new();
            for (&time, &value) in ps.iter() {
                let existing = if let Some(end) = time.checked_add(1) {
                    self.read(key, Some((time, end, 1)))?
                } else {
                    self.read(key, None)?
                };
                if let Some(old) = existing.first().filter(|p| p.time == time) {
                    if value_bits(old.value) != value_bits(value) {
                        return Err(invalid("conflicting temporal observation"));
                    }
                    duplicates.push(time);
                }
            }
            for t in duplicates {
                ps.remove(&t);
            }
        }
        new.retain(|_, ps| !ps.is_empty());
        let retained = new
            .iter()
            .map(|(key, ps)| {
                key.tenant.len() + key.asset.len() + key.property.len() + 256 + ps.len() * 128
            })
            .sum::<usize>();
        reservation.reduce(retained as u64);
        Ok((new, reservation))
    }
    fn apply(&mut self, (rows, reservation): (Rows, MetadataCharge)) {
        if rows.is_empty() {
            return;
        }
        self.hot_reservations.push(reservation);
        for (key, ps) in rows {
            self.hot_bytes +=
                key.asset.len() + key.property.len() + key.tenant.len() + 256 + ps.len() * 128;
            self.hot.entry(key).or_default().extend(ps);
        }
    }
    fn admit_new_run(&self) -> Result<()> {
        if self.runs.len() >= MAX_RUNS {
            return Err(GaussError::ResourceExhausted(
                "temporal checkpoint run limit exceeded".into(),
            ));
        }
        Ok(())
    }
    fn make_room(&mut self) -> Result<()> {
        if self.hot_bytes >= HOT_BYTES {
            self.flush()?;
        }
        Ok(())
    }
    pub(super) fn replay(&mut self, batch: &TemporalBatch) -> Result<()> {
        if !self.enabled {
            return Err(invalid("missing temporal checkpoint version fence"));
        }
        self.make_room()?;
        let rows = self.prepare(batch)?;
        self.apply(rows);
        Ok(())
    }
}

impl Db {
    fn bind_temporal<'a>(
        &self,
        coll: &Collection,
        access: TemporalAccess<'a>,
        action: Action,
        enforcement: crate::tenant::TenantEnforcement,
    ) -> Result<&'a str> {
        match (access, &coll.security) {
            (TemporalAccess::Scoped(scope), None) if self.identity_authority.is_none() => {
                if enforcement.blocks() && scope.tenant_id().is_none() {
                    return Err(SecurityError::Forbidden.into());
                }
                Ok(scope.tenant_id().unwrap_or(""))
            }
            (TemporalAccess::Authorized(ctx), Some(auth))
                if ctx.action() == action && auth.accepts(ctx) =>
            {
                Ok(ctx.tenant())
            }
            _ => Err(SecurityError::Forbidden.into()),
        }
    }
    /// Append atomically and return the count of new events after durable commit.
    pub fn append_temporal_batch(
        &self,
        collection: &str,
        access: TemporalAccess<'_>,
        samples: Vec<TemporalSample>,
    ) -> Result<usize> {
        let _life = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _maintenance = self.maintenance_barrier.read();
        let enforcement = self.tenant_enforcement();
        let c = self
            .inner
            .read()
            .collections
            .get(collection)
            .cloned()
            .ok_or_else(|| GaussError::CollectionNotFound(collection.into()))?;
        let mut c = c.write();
        let tenant = self
            .bind_temporal(&c, access, Action::TemporalAppend, enforcement)?
            .to_owned();
        let (ctx, incarnation) = match access {
            TemporalAccess::Scoped(scope) => (audit_context(scope), None),
            TemporalAccess::Authorized(ctx) => (
                audit::AuditContext {
                    principal_id: ctx.principal_id().into(),
                    tenant_id: Some(ctx.tenant().into()),
                    transport: "temporal".into(),
                    request_id: None,
                },
                Some(ctx.incarnation()),
            ),
        };
        let _permit = match access {
            TemporalAccess::Authorized(ctx) => Some(ctx.publication_permit()?),
            _ => None,
        };
        if let TemporalAccess::Authorized(context) = access {
            // Validate the complete batch before storage preparation, WAL, or
            // duplicate detection. A replay must obey the current authority.
            for sample in &samples {
                context.authorize_temporal_property(&sample.asset, &sample.property)?;
            }
        }
        let op = self.audit_operation_with_context(
            "append_temporal_batch",
            Some(collection),
            ctx.clone(),
        )?;
        let batch = TemporalBatch {
            version: 1,
            tenant,
            incarnation,
            samples,
        };
        c.temporal.make_room()?;
        let rows = c.temporal.prepare(&batch)?;
        let affected = rows.0.values().map(BTreeMap::len).sum();
        if affected == 0 {
            op.success(serde_json::json!({"affected":0,"replayed":true}))?;
            return Ok(0);
        }
        c.temporal.admit_new_run()?;
        if !c.temporal.enabled {
            let dir = c
                .temporal
                .dir
                .parent()
                .expect("collection directory")
                .to_owned();
            let args = (c.wal.len()?, c.live_points(), c.last_segment_id.clone());
            let mut cp = match read_checkpoint(&dir)? {
                Some(cp) => cp,
                None => c.checkpoint(args.0, args.1, args.2)?,
            };
            cp.temporal_runs = Some(Vec::new());
            cp.temporal_wal_lsn = Some(c.wal.len()?);
            write_checkpoint(&dir, &cp)?;
            durable_create_dir(&c.temporal.dir)?;
            c.temporal.enabled = true;
        }
        let (txn, _) = self.commit_collection_transaction(
            collection,
            &mut c,
            WalEntry::TemporalBatch { batch },
            TransactionAudit::mutation(
                "append_temporal_batch",
                Some(collection),
                &ctx,
                serde_json::json!({"affected":affected}),
            ),
        )?;
        c.temporal.apply(rows);
        drop(c);
        self.project_transaction_audit(&txn);
        self.finish_committed_legacy_audit(op, serde_json::json!({"affected":affected}));
        Ok(affected)
    }
    pub fn query_temporal(
        &self,
        collection: &str,
        access: TemporalAccess<'_>,
        query: TemporalQuery<'_>,
    ) -> Result<Vec<Observation>> {
        let TemporalQuery {
            asset,
            property,
            range,
            filter,
        } = query;
        if range.is_some_and(|(lo, hi, n)| lo > hi || n == 0 || n > MAX_HISTORY) {
            return Err(invalid("invalid temporal range or limit"));
        }
        let _life = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let enforcement = self.tenant_enforcement();
        if filter.is_some() {
            match access {
                TemporalAccess::Authorized(context) => {
                    let record = context.authorize_temporal_property(asset, property)?;
                    if record.content.is_point() {
                        self.ensure_collection_cold_materialized_authorized(context)?;
                    }
                }
                TemporalAccess::Scoped(_) => {
                    self.ensure_collection_cold_materialized(collection)?;
                }
            }
        }
        let c = self
            .inner
            .read()
            .collections
            .get(collection)
            .cloned()
            .ok_or_else(|| GaussError::CollectionNotFound(collection.into()))?;
        let c = c.read();
        let tenant = self.bind_temporal(&c, access, Action::TemporalRead, enforcement)?;
        let _permit = match access {
            TemporalAccess::Authorized(ctx) => Some(ctx.publication_permit()?),
            _ => None,
        };
        match access {
            TemporalAccess::Authorized(context) => {
                let resource = context.authorize_temporal_property(asset, property)?;
                if let Some(filter) = filter {
                    let filter = SecurityFilter::compile(filter.clone())?;
                    let matches = match &resource.content {
                        crate::security::ResourceContent::Point => {
                            let point = c
                                .resolve_candidate(&resource.storage_id.to_string())?
                                .ok_or(SecurityError::NotFound)?;
                            context.matches_filter(asset, &filter, &point.payload)?
                        }
                        crate::security::ResourceContent::GraphEdge { .. } => {
                            return Err(SecurityError::NotFound.into());
                        }
                        crate::security::ResourceContent::TemporalAsset { metadata } => {
                            context.matches_filter(asset, &filter, metadata)?
                        }
                    };
                    if !matches {
                        return Ok(Vec::new());
                    }
                }
            }
            TemporalAccess::Scoped(scope) => {
                if let Some(filter) = filter {
                    let Some(point) = c.resolve_candidate(asset)? else {
                        return Ok(Vec::new());
                    };
                    if !scope.may_read_payload(enforcement, &point.payload)
                        || !filter.matches(&point.payload)
                    {
                        return Ok(Vec::new());
                    }
                }
            }
        }
        c.temporal
            .read(&Series::new(tenant, asset, property), range)
    }
    /// Earliest observations in a half-open event-time range, up to the supplied limit.
    pub fn scan_temporal(
        &self,
        collection: &str,
        access: TemporalAccess<'_>,
        asset: &str,
        property: &str,
        range: std::ops::Range<i64>,
        limit: usize,
    ) -> Result<Vec<Observation>> {
        self.query_temporal(
            collection,
            access,
            TemporalQuery {
                asset,
                property,
                range: Some((range.start, range.end, limit)),
                filter: None,
            },
        )
    }
    /// Return the observation with greatest event time in this tenant, or None.
    pub fn latest_temporal(
        &self,
        collection: &str,
        access: TemporalAccess<'_>,
        asset: &str,
        property: &str,
    ) -> Result<Option<Observation>> {
        Ok(self
            .query_temporal(
                collection,
                access,
                TemporalQuery {
                    asset,
                    property,
                    range: None,
                    filter: None,
                },
            )?
            .pop())
    }
}

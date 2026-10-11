//! Rebuildable disk index over verified audit records. The only live history is
//! a preadmitted 512-record delta; immutable cursor pins survive merges.
use super::*;
use crate::relational::{
    disk_map::{Cursor, DiskMap},
    wal_decode::{self, MetadataCharge, Owned},
};
use serde::Deserialize;

const DELTA: usize = 512;
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct Terminal {
    pub(super) operation_id: String,
    pub(super) sequence: u64,
    pub(super) digest: [u8; 32],
}
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct Intent {
    category: String,
    operation: String,
    operation_id: String,
    pub(super) sequence: u64,
    collection: Option<String>,
    context: AuditContext,
}
#[derive(Debug, Deserialize, Serialize)]
pub(super) enum Entry {
    Terminal(Terminal),
    Intent(Intent),
}
impl Entry {
    pub(super) fn key(&self) -> [u8; 41] {
        let (namespace, id, sequence) = match self {
            Self::Terminal(v) => (0, v.operation_id.as_str(), v.sequence),
            Self::Intent(v) => (1, v.operation_id.as_str(), v.sequence),
        };
        let mut key = [0; 41];
        key[..33].copy_from_slice(&prefix(namespace, id));
        key[33..].copy_from_slice(&(!sequence).to_be_bytes());
        key
    }
}
fn prefix(namespace: u8, id: &str) -> [u8; 33] {
    let mut key = [namespace; 33];
    key[1..].copy_from_slice(&Sha256::digest(id.as_bytes()));
    key
}

#[derive(Debug)]
pub(super) struct Registry {
    pub(super) disk: DiskMap,
    delta: Vec<Owned<Entry>>,
    _memory: MetadataCharge,
    #[cfg(test)]
    pub(super) recovery_decoded_records: u64,
}
impl Registry {
    pub(super) fn recover(
        root: &Path,
        journal: Option<&crate::transaction_journal::TransactionJournal>,
    ) -> Result<(Self, String, u64)> {
        let mut memory = MetadataCharge::default();
        memory.prepare((std::mem::size_of::<Owned<Entry>>() * DELTA) as u64 + 4096)?;
        let mut delta = Vec::new();
        delta
            .try_reserve_exact(DELTA)
            .map_err(|_| invalid("audit registry allocation failed"))?;
        let path = audit_log_path(root);
        let mut registry = Self {
            disk: DiskMap::new(path.parent().expect("audit parent"))?,
            delta,
            _memory: memory,
            #[cfg(test)]
            recovery_decoded_records: 0,
        };
        let authority = journal
            .map(|journal| journal.storage_projection_authority())
            .transpose()?
            .flatten();
        let cached = checkpoint::recover(&mut registry, root, journal)?;
        let mut decoded = 0_u64;
        let (hash, sequence) =
            scan_verified_from(root, None, cached.as_deref(), |value, sequence| {
                if let Some(entry) = registry.prepare(value, sequence)? {
                    if let Entry::Terminal(terminal) = &*entry {
                        validate(authority, terminal)?;
                    }
                    registry.install(entry)?;
                }
                decoded += 1;
                Ok(())
            })?;
        registry.flush()?;
        metrics::counter!("chirondb_audit_recovery_decoded_records_total").increment(decoded);
        #[cfg(test)]
        {
            registry.recovery_decoded_records = decoded;
        }
        Ok((registry, hash, sequence))
    }

    pub(super) fn prepare(&mut self, value: &Value, sequence: u64) -> Result<Option<Owned<Entry>>> {
        self.flush_if_full()?;
        let Some(id) = value.get("operation_id").and_then(Value::as_str) else {
            return Ok(None);
        };
        // Persistent registry metadata belongs to the writer's captured pool;
        // a request's transient decode/admission owner must not outlive its
        // failed operation. Both pools are the same aggregate in production.
        let mut memory = self._memory.empty_in_same_pool();
        let entry = if value.get("outcome").and_then(Value::as_str) == Some("intent") {
            let category = value["category"].as_str().unwrap_or("mutation");
            let operation = value["operation"].as_str().unwrap_or("unknown");
            let collection = value["collection"].as_str();
            let principal = value["principal_id"].as_str().unwrap_or("unknown");
            let tenant = value["tenant_id"].as_str();
            let transport = value["transport"].as_str().unwrap_or("unknown");
            let request = value["request_id"].as_str();
            let bytes = [
                category.len(),
                operation.len(),
                id.len(),
                principal.len(),
                transport.len(),
                collection.map_or(0, str::len),
                tenant.map_or(0, str::len),
                request.map_or(0, str::len),
            ]
            .into_iter()
            .try_fold(1024_u64, |total, bytes| total.checked_add(bytes as u64))
            .ok_or_else(|| invalid("audit registry metadata overflow"))?;
            memory.prepare(bytes)?;
            Entry::Intent(Intent {
                category: category.into(),
                operation: operation.into(),
                operation_id: id.into(),
                sequence,
                collection: collection.map(str::to_owned),
                context: AuditContext {
                    principal_id: principal.into(),
                    tenant_id: tenant.map(str::to_owned),
                    transport: transport.into(),
                    request_id: request.map(str::to_owned),
                },
            })
        } else {
            memory.prepare(id.len() as u64 + 1024)?;
            Entry::Terminal(Terminal {
                operation_id: id.into(),
                sequence,
                digest: binding::actual(value)?,
            })
        };
        let entry = Owned::from_parts(entry, memory.into_reservation());
        Ok(Some(entry))
    }
    fn flush_if_full(&mut self) -> Result<()> {
        if self.delta.len() == DELTA {
            self.flush()?;
        }
        Ok(())
    }
    pub(super) fn install(&mut self, entry: Owned<Entry>) -> Result<()> {
        // prepare() flushed before the durable append; installation cannot grow.
        if self.delta.len() == DELTA {
            return Err(invalid("audit registry delta is full"));
        }
        self.delta.push(entry);
        Ok(())
    }
    pub(super) fn flush(&mut self) -> Result<()> {
        self.disk.insert_batch(|batch| {
            for entry in &self.delta {
                batch.insert(&entry.key(), &**entry)?;
            }
            Ok(())
        })?;
        self.delta.clear();
        Ok(())
    }
    pub(super) fn terminal(&self, id: &str) -> Result<Option<Owned<Terminal>>> {
        for entry in self.delta.iter().rev() {
            if let Entry::Terminal(value) = &**entry
                && value.operation_id == id
            {
                return wal_decode::copy(value).map(Some);
            }
        }
        let mut cursor = self.disk.prefix_cursor(&prefix(0, id))?;
        let Some(record) = cursor.next().transpose()? else {
            return Ok(None);
        };
        record
            .decode::<Entry>()?
            .try_map(|entry| match entry {
                Entry::Terminal(value)
                    if value.operation_id == id
                        && record.key()[33..] == (!value.sequence).to_be_bytes() =>
                {
                    Ok(value)
                }
                _ => Err(invalid("audit registry terminal binding changed")),
            })
            .map(Some)
    }
    pub(super) fn orphan_cursor(&mut self) -> Result<Cursor> {
        self.flush()?;
        self.disk.prefix_cursor(&[1])
    }
}

pub(super) fn validate(
    journal: Option<&crate::transaction_journal::TransactionJournal>,
    terminal: &Terminal,
) -> Result<()> {
    if let Some(journal) = journal
        && let Ok(id) = terminal.operation_id.parse()
    {
        journal.validate_audit_projection(id, terminal.digest)?;
    }
    Ok(())
}

pub(super) fn recover_orphans(writer: &AuditWriter) -> Result<()> {
    let mut cursor = writer
        .state
        .lock()
        .map_err(|_| invalid("audit writer lock poisoned"))?
        .registry
        .orphan_cursor()?;
    let mut previous: Option<[u8; 33]> = None;
    for record in &mut cursor {
        let record = record?;
        let key: [u8; 33] = record.key()[..33]
            .try_into()
            .map_err(|_| invalid("audit registry intent key"))?;
        if previous == Some(key) {
            continue;
        }
        previous = Some(key);
        let intent = record.decode::<Entry>()?.try_map(|entry| match entry {
            Entry::Intent(value)
                if prefix(1, &value.operation_id) == key
                    && record.key()[33..] == (!value.sequence).to_be_bytes() =>
            {
                Ok(value)
            }
            _ => Err(invalid("audit registry intent binding changed")),
        })?;
        if writer
            .state
            .lock()
            .map_err(|_| invalid("audit writer lock poisoned"))?
            .registry
            .terminal(&intent.operation_id)?
            .is_some()
        {
            continue;
        }
        writer.append(
            &intent.category,
            &intent.operation,
            &intent.operation_id,
            "interrupted",
            intent.collection.as_deref(),
            &intent.context,
            Some("process_interrupted"),
            Value::Null,
            true,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_registry_uses_bounded_delta_and_releases_runs_and_admission() {
        let root = tempfile::tempdir().unwrap();
        let ids: Vec<_> = (0..2050)
            .map(|_| crate::transaction_journal::TransactionId::new())
            .collect();
        let audit = crate::transaction_journal::TransactionAudit::mutation(
            "insert",
            None,
            &AuditContext::embedded(),
            Value::Null,
        );
        crate::relational::wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
            let writer = AuditWriter::open(root.path()).unwrap();
            for id in &ids {
                writer.project_committed_transaction(*id, &audit).unwrap();
                assert!(writer.state.lock().unwrap().registry.delta.len() <= DELTA);
            }
            for id in [ids[0], ids[511], ids[512], ids[2049]] {
                assert!(writer.has_durable_transaction_projection(id).unwrap());
            }
            writer.flush_and_shutdown().unwrap();
            drop(writer);
            assert_eq!(used(), 0);
            assert_eq!(fs::read_dir(root.path().join("audit")).unwrap().count(), 1);
            let writer = AuditWriter::open(root.path()).unwrap();
            assert!(writer.state.lock().unwrap().registry.delta.is_empty());
            for id in &ids {
                writer.project_committed_transaction(*id, &audit).unwrap();
            }
            assert_eq!(writer.state.lock().unwrap().sequence, ids.len() as u64);
            drop(writer);
            assert_eq!(used(), 0);
            assert_eq!(fs::read_dir(root.path().join("audit")).unwrap().count(), 1);
        });
    }
    #[test]
    fn denied_or_cancelled_registry_does_not_append_or_leak() {
        let root = tempfile::tempdir().unwrap();
        crate::relational::wal_decode::with_test_storage_pool(1, |used| {
            assert!(AuditWriter::open(root.path()).is_err());
            assert!(!audit_log_path(root.path()).exists());
            assert_eq!(used(), 0);
        });
        crate::relational::wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
            let flag = Arc::new(AtomicBool::new(true));
            assert!(
                crate::relational::with_sql_cancellation(flag, || AuditWriter::open(root.path()))
                    .is_err()
            );
            assert!(!audit_log_path(root.path()).exists());
            assert_eq!(used(), 0);
        });
    }
}

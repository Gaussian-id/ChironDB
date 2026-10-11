//! Retained overlay admission. A snapshot shares its generation's reservation;
//! a changed root reserves a conservative complete generation before mutation.
//! This intentionally overcounts shared branches/payloads between different
//! roots. Segment metadata and sort retention use a separate shared storage pool.
//! A separate history pool accounts interactive SQL/savepoints/replay copies.
//! These pools do not substitute for parser/operator or process RSS accounting.

use std::mem::size_of;
use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicU64, Ordering},
};

use super::{GaussError, RelationalValue, Result, RowVersion};

#[cfg(test)]
mod tests;

static RETAINED_POOL: LazyLock<Arc<Pool>> =
    LazyLock::new(|| Arc::new(Pool::new(crate::resource_profile::current().sql_pool_bytes)));
// Keep maintenance headroom separate from admitted row/index overlays. With
// the existing request and overlay pools this reserves at most 2.5 SQL pools;
// the remaining profile envelope is not a claim of measured process RSS.
static STORAGE_POOL: LazyLock<Arc<Pool>> = LazyLock::new(|| {
    Arc::new(Pool::storage(
        (crate::resource_profile::current().sql_pool_bytes / 2).max(1),
    ))
});
static HISTORY_POOL: LazyLock<Arc<Pool>> = LazyLock::new(|| {
    Arc::new(Pool {
        kind: PoolKind::History,
        ..Pool::new((crate::resource_profile::current().sql_pool_bytes / 4).max(1))
    })
});

#[derive(Debug, Clone, Copy)]
enum PoolKind {
    Retained,
    Storage,
    History,
}

#[derive(Debug)]
pub(super) struct Pool {
    capacity: u64,
    used: AtomicU64,
    kind: PoolKind,
    history_metrics: parking_lot::Mutex<()>,
}

impl Pool {
    fn new(capacity: u64) -> Self {
        Self {
            capacity,
            used: AtomicU64::new(0),
            kind: PoolKind::Retained,
            history_metrics: parking_lot::Mutex::new(()),
        }
    }

    fn storage(capacity: u64) -> Self {
        Self {
            kind: PoolKind::Storage,
            ..Self::new(capacity)
        }
    }

    fn gauge(&self) -> &'static str {
        match self.kind {
            PoolKind::Storage => "chirondb_relational_storage_reserved_bytes",
            PoolKind::Retained => "chirondb_relational_retained_reserved_bytes",
            PoolKind::History => "chirondb_sql_history_reserved_bytes",
        }
    }

    fn acquire(&self, bytes: u64) -> Result<()> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(bytes).filter(|next| *next <= self.capacity)
                .ok_or_else(|| {
                    if matches!(self.kind, PoolKind::History) {
                        metrics::counter!("chirondb_sql_history_rejections_total").increment(1);
                        GaussError::ResourceExhausted("SQL transaction history memory is full; release savepoints or roll back transactions".into())
                    } else if matches!(self.kind, PoolKind::Storage) {
                        STORAGE_DECODE_FAILURE.with(|scope| {
                            if let Some(failed) = scope.borrow().as_ref() {
                                failed.set(true);
                            }
                        });
                        metrics::counter!("chirondb_relational_storage_rejections_total").increment(1);
                        GaussError::ResourceExhausted("relational storage memory is full; release readers or retry after maintenance".into())
                    } else {
                        metrics::counter!("chirondb_relational_retained_rejections_total").increment(1);
                        GaussError::ResourceExhausted("relational retained memory is full; release old transactions or retry after checkpoint".into())
                    }
                })?;
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if matches!(self.kind, PoolKind::History) {
                        self.observe_history();
                    } else {
                        metrics::gauge!(self.gauge()).set(next as f64);
                    }
                    return Ok(());
                }
                Err(actual) => used = actual,
            }
        }
    }

    fn release(&self, bytes: u64) {
        let previous = self.used.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes);
        if matches!(self.kind, PoolKind::History) {
            self.observe_history();
        } else {
            metrics::gauge!(self.gauge()).set(previous.saturating_sub(bytes) as f64);
        }
    }

    fn observe_history(&self) {
        // Serialize reading and publishing the current counter. Concurrent
        // releases must not publish an older nonzero observation after zero.
        let _observation = self.history_metrics.lock();
        metrics::gauge!(self.gauge()).set(self.used.load(Ordering::Acquire) as f64);
        metrics::gauge!("chirondb_sql_history_capacity_bytes").set(self.capacity as f64);
    }
}

#[derive(Debug)]
struct Lease {
    pool: Arc<Pool>,
    bytes: u64,
    // Arc header, lease value and conservative allocator alignment.
    root: u64,
}

pub(super) const LEASE_ROOT_BYTES: u64 = (size_of::<Lease>() + 2 * size_of::<usize>() + 32) as u64;

impl Drop for Lease {
    fn drop(&mut self) {
        self.pool.release(self.bytes + self.root);
    }
}

// serde's Error::custom erases a nested owner's ResourceExhausted variant.
// Track storage admission failure only inside an explicit synchronous decode
// scope, so a failed RowValues reservation remains a resource error at the edge.
thread_local! {
    static STORAGE_DECODE_FAILURE: std::cell::RefCell<Option<std::rc::Rc<std::cell::Cell<bool>>>> = const { std::cell::RefCell::new(None) };
}

pub(super) struct StorageDecodeScope {
    failed: std::rc::Rc<std::cell::Cell<bool>>,
    previous: Option<std::rc::Rc<std::cell::Cell<bool>>>,
}

impl StorageDecodeScope {
    pub(super) fn enter() -> Self {
        let failed = std::rc::Rc::new(std::cell::Cell::new(false));
        let previous = STORAGE_DECODE_FAILURE.with(|scope| scope.replace(Some(failed.clone())));
        Self { failed, previous }
    }

    pub(super) fn failed(&self) -> bool {
        self.failed.get()
    }
}

impl Drop for StorageDecodeScope {
    fn drop(&mut self) {
        if self.failed()
            && let Some(previous) = &self.previous
        {
            previous.set(true);
        }
        STORAGE_DECODE_FAILURE.with(|scope| *scope.borrow_mut() = self.previous.take());
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Charge {
    lease: Option<Arc<Lease>>,
    // Empty owners only clone an existing pool handle; no fresh heap controller.
    pool: Option<Arc<Pool>>,
}

impl Charge {
    pub(super) fn history() -> Self {
        Self {
            lease: None,
            pool: Some(history_pool()),
        }
    }

    pub(super) fn empty_in_same_pool(&self) -> Self {
        Self {
            lease: None,
            pool: Some(self.pool.as_ref().expect("explicit pool").clone()),
        }
    }

    pub(super) fn storage() -> Self {
        Self {
            lease: None,
            pool: Some(storage_pool()),
        }
    }

    pub(super) fn bytes(&self) -> u64 {
        self.lease.as_ref().map_or(0, |lease| lease.bytes)
    }

    /// Admit payload and the shared controller before allocating it. A clone
    /// shares both; same-size forks require a new independently admitted lease.
    pub(super) fn prepare(&mut self, bytes: u64) -> Result<()> {
        if bytes == 0 {
            self.lease = None;
            return Ok(());
        }
        if let Some(lease) = self.lease.as_mut().and_then(Arc::get_mut) {
            if bytes >= lease.bytes {
                lease.pool.acquire(bytes - lease.bytes)?;
            } else {
                lease.pool.release(lease.bytes - bytes);
            }
            lease.bytes = bytes;
            return Ok(());
        }
        let pool = self.pool.as_ref().map_or_else(current_pool, Arc::clone);
        let total = bytes
            .checked_add(LEASE_ROOT_BYTES)
            .ok_or_else(super::sql_overloaded)?;
        pool.acquire(total)?;
        self.pool = Some(Arc::clone(&pool));
        self.lease = Some(Arc::new(Lease {
            pool,
            bytes,
            root: LEASE_ROOT_BYTES,
        }));
        Ok(())
    }

    /// Release only after the corresponding allocations have been dropped.
    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        self.lease = None;
    }
}

fn current_pool() -> Arc<Pool> {
    #[cfg(test)]
    if let Some(pool) = TEST_POOL.with(|pool| pool.borrow().clone()) {
        return pool;
    }
    Arc::clone(&RETAINED_POOL)
}

fn storage_pool() -> Arc<Pool> {
    #[cfg(test)]
    if let Some(pool) = TEST_STORAGE_POOL.with(|pool| pool.borrow().clone()) {
        return pool;
    }
    Arc::clone(&STORAGE_POOL)
}

pub(super) fn storage_available_bytes() -> u64 {
    let pool = storage_pool();
    pool.capacity
        .saturating_sub(pool.used.load(Ordering::Acquire))
}

fn history_pool() -> Arc<Pool> {
    #[cfg(test)]
    if let Some(pool) = TEST_HISTORY_POOL.with(|pool| pool.borrow().clone()) {
        return pool;
    }
    Arc::clone(&HISTORY_POOL)
}

pub(super) fn initialize_history_metrics() {
    history_pool().observe_history();
    metrics::counter!("chirondb_sql_history_rejections_total").increment(0);
}

pub(super) fn flush_threshold() -> u64 {
    (current_pool().capacity / 8).max(1)
}

// imbl 7's ordered nodes contain at most sixteen keys. For the small fixed
// key/value handles used here, 1 KiB per entry plus a root allowance exceeds
// their complete tree and mutation-path storage. Payload capacities are charged
// separately. Keep this conservative bound under review when upgrading imbl.
pub(super) fn tree_bytes(entries: usize) -> u64 {
    if entries == 0 {
        0
    } else {
        4096_u64.saturating_add((entries as u64).saturating_mul(1024))
    }
}

pub(super) fn row_chain_bytes(versions: &super::VersionChain) -> u64 {
    let fixed = (versions.capacity() as u64).saturating_mul(size_of::<RowVersion>() as u64);
    versions
        .iter()
        .fold(fixed.saturating_add(64), |total, version| {
            let values_bytes = (version.values.capacity() as u64)
                .saturating_mul(size_of::<RelationalValue>() as u64);
            version
                .values
                .iter()
                .fold(total.saturating_add(values_bytes), |total, value| {
                    total.saturating_add(value_heap_bytes(value))
                })
        })
}

pub(super) fn value_heap_bytes(value: &RelationalValue) -> u64 {
    match value {
        RelationalValue::Decimal(s)
        | RelationalValue::Text(s)
        | RelationalValue::Date(s)
        | RelationalValue::TimestampUtc(s) => s.capacity() as u64,
        RelationalValue::Bytes(v) => v.capacity() as u64,
        RelationalValue::Vector(v) => (v.capacity() as u64).saturating_mul(4),
        RelationalValue::RecordRef(r) => {
            (r.namespace.capacity() as u64).saturating_add(r.id.capacity() as u64)
        }
        RelationalValue::Json(value) => json_heap_bytes(value),
        _ => 0,
    }
}

fn json_heap_bytes(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::String(s) => s.capacity() as u64,
        serde_json::Value::Array(values) => values.iter().fold(
            (values.capacity() as u64).saturating_mul(size_of::<serde_json::Value>() as u64),
            |total, value| total.saturating_add(json_heap_bytes(value)),
        ),
        serde_json::Value::Object(values) => {
            values
                .iter()
                .fold(tree_bytes(values.len()), |total, (key, value)| {
                    total
                        .saturating_add(key.capacity() as u64)
                        .saturating_add(json_heap_bytes(value))
                })
        }
        _ => 0,
    }
}

#[cfg(test)]
thread_local! { static TEST_POOL: std::cell::RefCell<Option<Arc<Pool>>> = const { std::cell::RefCell::new(None) }; }

#[cfg(test)]
thread_local! { static TEST_STORAGE_POOL: std::cell::RefCell<Option<Arc<Pool>>> = const { std::cell::RefCell::new(None) }; }

#[cfg(test)]
thread_local! { static TEST_HISTORY_POOL: std::cell::RefCell<Option<Arc<Pool>>> = const { std::cell::RefCell::new(None) }; }

#[cfg(test)]
pub(super) fn with_history_pool<T>(capacity: u64, f: impl FnOnce(Arc<Pool>) -> T) -> T {
    struct Restore(Option<Arc<Pool>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_HISTORY_POOL.with(|p| *p.borrow_mut() = self.0.take());
        }
    }
    let pool = Arc::new(Pool {
        kind: PoolKind::History,
        ..Pool::new(capacity)
    });
    let _restore = Restore(TEST_HISTORY_POOL.with(|p| p.replace(Some(pool.clone()))));
    f(pool)
}

#[cfg(test)]
pub(super) fn with_storage_pool<T>(capacity: u64, f: impl FnOnce(Arc<Pool>) -> T) -> T {
    struct Restore(Option<Arc<Pool>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_STORAGE_POOL.with(|p| *p.borrow_mut() = self.0.take());
        }
    }
    let pool = Arc::new(Pool::storage(capacity));
    let _restore = Restore(TEST_STORAGE_POOL.with(|p| p.replace(Some(Arc::clone(&pool)))));
    f(pool)
}

#[cfg(test)]
pub(super) fn with_pool<T>(capacity: u64, f: impl FnOnce(Arc<Pool>) -> T) -> T {
    struct Restore(Option<Arc<Pool>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_POOL.with(|p| *p.borrow_mut() = self.0.take());
        }
    }
    let pool = Arc::new(Pool::new(capacity));
    let _restore = Restore(TEST_POOL.with(|p| p.replace(Some(Arc::clone(&pool)))));
    f(pool)
}

#[cfg(test)]
impl Pool {
    pub(super) fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
}

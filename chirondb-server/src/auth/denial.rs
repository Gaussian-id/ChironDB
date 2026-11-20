//! Redacted, bounded authentication-failure telemetry. Labels and event fields
//! are fixed strings; no unauthenticated input is retained or used as a key.
use crate::{Db, GaussError};
use std::{
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(crate) enum Transport {
    Http,
    Grpc,
    Wire,
    Postgres,
    PostgresScram,
}
impl Transport {
    fn index(self) -> usize {
        match self {
            Self::Http => 0,
            Self::Grpc => 1,
            Self::Wire => 2,
            Self::Postgres | Self::PostgresScram => 3,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Grpc => "grpc",
            Self::Wire => "chironwire",
            Self::Postgres | Self::PostgresScram => "pgwire",
        }
    }
    fn operation(self) -> &'static str {
        match self {
            Self::Http => "http_authenticate",
            Self::Grpc => "grpc_authenticate",
            Self::Wire => "chironwire_authenticate",
            Self::Postgres => "pgwire_authenticate",
            Self::PostgresScram => "pgwire_scram",
        }
    }
}

const WINDOW: Duration = Duration::from_secs(1);
const RECORDS_PER_WINDOW: u32 = 16;
struct Budget {
    started: Instant,
    records: u32,
}
impl Budget {
    fn admit(&mut self, now: Instant) -> bool {
        if now.duration_since(self.started) >= WINDOW {
            self.started = now;
            self.records = 0;
        }
        if self.records == RECORDS_PER_WINDOW {
            return false;
        }
        self.records += 1;
        true
    }
}
static BUDGETS: LazyLock<Mutex<[Budget; 4]>> = LazyLock::new(|| {
    Mutex::new(std::array::from_fn(|_| Budget {
        started: Instant::now(),
        records: 0,
    }))
});

pub(crate) fn record(db: &Db, transport: Transport) -> Result<(), GaussError> {
    metrics::counter!("chirondb_authentication_failures_total", "transport" => transport.label())
        .increment(1);
    let admitted = BUDGETS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)[transport.index()]
    .admit(Instant::now());
    if !admitted {
        metrics::counter!("chirondb_authentication_audit_suppressed_total", "transport" => transport.label(), "reason" => "rate_limit").increment(1);
        return Ok(());
    }
    let result = db.audit_access_event(
        "authentication",
        transport.operation(),
        "failure",
        None,
        "unknown",
        None,
        transport.label(),
        None,
        Some("invalid_credential"),
    );
    if result.is_err() {
        metrics::counter!("chirondb_authentication_audit_suppressed_total", "transport" => transport.label(), "reason" => "audit_unavailable").increment(1);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn anonymous_record_budget_has_fixed_memory_and_recovers_after_the_window() {
        let start = Instant::now();
        let mut budget = Budget {
            started: start,
            records: 0,
        };
        for _ in 0..RECORDS_PER_WINDOW {
            assert!(budget.admit(start));
        }
        for _ in 0..10_000 {
            assert!(!budget.admit(start + WINDOW / 2));
        }
        assert!(budget.admit(start + WINDOW));
        assert_eq!(budget.records, 1);
        assert_eq!(
            Transport::Postgres.index(),
            Transport::PostgresScram.index()
        );
    }
}

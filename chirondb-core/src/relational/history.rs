//! Owned interactive SQL history, savepoints and admitted replay copies.
//! Parser ASTs, catalogs, result rows and operator scratch have separate lifetimes.
use std::mem::size_of;

use super::{GaussError, Result, check_sql_cancelled, memory};
use crate::{SqlExecutionRequest, SqlStatementRequest};

#[derive(Debug)]
pub(super) struct History {
    statements: Vec<SqlStatementRequest>,
    savepoints: Vec<(String, usize)>,
    limit: u64,
    // Drop owned buffers before returning their reservation.
    charge: memory::Charge,
}

fn exhausted() -> GaussError {
    metrics::counter!("chirondb_sql_history_rejections_total").increment(1);
    GaussError::ResourceExhausted(
        "SQL transaction history budget exhausted; release savepoints or roll back".into(),
    )
}

fn statement_bytes(statement: &SqlStatementRequest) -> u64 {
    statement.parameters.iter().fold(
        (statement.sql.capacity() as u64).saturating_add(
            (statement.parameters.capacity() as u64)
                .saturating_mul(size_of::<crate::RelationalValue>() as u64),
        ),
        |total, value| total.saturating_add(memory::value_heap_bytes(value)),
    )
}

impl History {
    pub(super) fn new() -> Result<Self> {
        let limit = (crate::resource_profile::current().sql_request_working_set_bytes / 4).max(1);
        if limit < 4096 {
            return Err(exhausted());
        }
        let mut charge = memory::Charge::history();
        charge.prepare(4096)?;
        Ok(Self {
            statements: Vec::new(),
            savepoints: Vec::new(),
            limit,
            charge,
        })
    }

    pub(super) fn statements(&self) -> &[SqlStatementRequest] {
        &self.statements
    }

    pub(super) fn savepoints(&self) -> &[(String, usize)] {
        &self.savepoints
    }

    pub(super) fn push_statement(&mut self, statement: SqlStatementRequest) -> Result<()> {
        if self.statements.len() >= super::MAX_STATEMENTS_PER_REQUEST {
            return Err(exhausted());
        }
        admit_growth(
            &mut self.statements,
            &mut self.charge,
            self.limit,
            statement_bytes(&statement),
        )?;
        self.statements.push(statement);
        Ok(())
    }

    pub(super) fn push_savepoint(&mut self, name: String) -> Result<()> {
        admit_growth(
            &mut self.savepoints,
            &mut self.charge,
            self.limit,
            name.capacity() as u64,
        )?;
        self.savepoints.push((name, self.statements.len()));
        Ok(())
    }

    pub(super) fn truncate_statements(&mut self, count: usize) {
        self.statements.truncate(count);
        if self.statements.is_empty() {
            self.statements = Vec::new();
        }
        self.release_unused();
    }

    pub(super) fn truncate_savepoints(&mut self, count: usize) {
        self.savepoints.truncate(count);
        if self.savepoints.is_empty() {
            self.savepoints = Vec::new();
        }
        self.release_unused();
    }

    fn release_unused(&mut self) {
        let statements = self.statements.iter().fold(
            (self.statements.capacity() as u64) * size_of::<SqlStatementRequest>() as u64,
            |total, statement| total.saturating_add(statement_bytes(statement)),
        );
        let savepoints = self.savepoints.iter().fold(
            (self.savepoints.capacity() as u64) * size_of::<(String, usize)>() as u64,
            |total, (name, _)| total.saturating_add(name.capacity() as u64),
        );
        let retained = 4096u64
            .saturating_add(statements)
            .saturating_add(savepoints);
        assert!(retained <= self.charge.bytes(), "history only shrinks here");
        self.charge
            .prepare(retained)
            .expect("exclusive charge shrinks");
    }

    /// Reserve before cloning; the caller keeps the charge until replay returns.
    pub(super) fn copy_request(
        &self,
        retry_id: Option<&str>,
    ) -> Result<(SqlExecutionRequest, memory::Charge)> {
        check_sql_cancelled()?;
        let bytes = self.statements.iter().fold(
            4096u64
                .saturating_add(retry_id.map_or(0, |s| s.len() as u64))
                .saturating_add(
                    (self.statements.len() as u64) * size_of::<SqlStatementRequest>() as u64,
                ),
            |total, statement| total.saturating_add(statement_bytes(statement)),
        );
        if bytes.saturating_add(self.charge.bytes()) > self.limit {
            return Err(exhausted());
        }
        let mut charge = self.charge.empty_in_same_pool();
        charge.prepare(bytes)?;
        Ok((
            SqlExecutionRequest {
                statements: self.statements.clone(),
                idempotency_key: None,
                retry_id: retry_id.map(str::to_owned),
            },
            charge,
        ))
    }
}

#[cfg(test)]
mod tests;

fn admit_growth<T>(
    values: &mut Vec<T>,
    charge: &mut memory::Charge,
    limit: u64,
    payload: u64,
) -> Result<()> {
    check_sql_cancelled()?;
    let capacity = if values.len() == values.capacity() {
        values
            .capacity()
            .checked_mul(2)
            .ok_or_else(exhausted)?
            .max(4)
    } else {
        values.capacity()
    };
    let before = charge.bytes();
    let bytes = ((capacity - values.capacity()) as u64)
        .saturating_mul(size_of::<T>() as u64)
        .saturating_add(payload)
        .saturating_add(before);
    if bytes > limit {
        return Err(exhausted());
    }
    charge.prepare(bytes)?;
    if let Err(error) = values.try_reserve_exact(capacity - values.len()) {
        charge.prepare(before).expect("exclusive charge shrinks");
        return Err(GaussError::ResourceExhausted(format!(
            "cannot allocate SQL transaction history: {error}"
        )));
    }
    Ok(())
}

//! Late publication of SQL data must retain the exact identity and table epochs.
use super::*;
use crate::security::{Epoch, IdentityCancellation};

#[derive(Clone, Debug, Default)]
pub struct SqlPublication(Vec<Arc<Guard>>);
#[derive(Debug)]
struct Guard {
    identity: IdentityCancellation,
    tables: Vec<(String, Option<Arc<Epoch>>)>,
    session: Option<Arc<Epoch>>,
    _memory: memory::Charge,
}
impl SqlPublication {
    pub fn publication_permits(&self) -> Result<Vec<crate::security::PublicationPermit>> {
        let mut permits = Vec::new();
        for guard in &self.0 {
            permits.push(guard.identity.publication_permit()?);
            if let Some(session) = &guard.session {
                permits.push(session.enter()?);
            }
            for (_, epoch) in &guard.tables {
                if let Some(epoch) = epoch {
                    permits.push(epoch.enter()?);
                }
            }
        }
        Ok(permits)
    }
    pub fn publish<T>(&self, publish: impl FnOnce() -> T) -> Result<T> {
        let _permits = self.publication_permits()?;
        Ok(publish())
    }
    pub(in crate::relational) fn capture(
        identity: Option<&AuthenticatedIdentity>,
        state: &RelationalState,
        authorization: Option<&SqlAuthorization>,
    ) -> Result<Self> {
        let Some(identity) = identity else {
            return Ok(Self::default());
        };
        let authorization = authorization.ok_or(SecurityError::Forbidden)?;
        let names = authorization
            .grants
            .iter()
            .map(|(name, _)| name.as_str())
            .chain(
                authorization
                    .table_grants
                    .iter()
                    .map(|grant| grant.table.as_str()),
            )
            .chain(authorization.row_policies.keys().map(String::as_str))
            .collect::<BTreeSet<_>>();
        // Retain absent names: a CREATE+INSERT batch must bind its result to
        // the new candidate epoch before publication, too.
        Self::named(identity, state, names)
    }
    pub(in crate::relational) fn management(
        identity: &AuthenticatedIdentity,
        state: &RelationalState,
        table: &str,
    ) -> Result<Self> {
        Self::named(identity, state, BTreeSet::from([table]))
    }
    fn named(
        identity: &AuthenticatedIdentity,
        state: &RelationalState,
        names: BTreeSet<&str>,
    ) -> Result<Self> {
        let mut memory = memory::Charge::storage();
        memory.prepare(
            512 + names
                .iter()
                .map(|name| name.len() as u64 + 256)
                .sum::<u64>(),
        )?;
        let mut tables = Vec::with_capacity(names.len());
        for name in names {
            let epoch = state
                .tables
                .get(name)
                .map(|table| {
                    table
                        .policy_epoch
                        .as_ref()
                        .cloned()
                        .ok_or(SecurityError::Forbidden)
                })
                .transpose()?;
            if let Some(epoch) = &epoch {
                let _permit = epoch.enter()?;
            }
            tables.push((name.into(), epoch));
        }
        let guard = Self(vec![Arc::new(Guard {
            identity: identity.cancellation(),
            tables,
            session: None,
            _memory: memory,
        })]);
        guard.publish(|| ())?;
        Ok(guard)
    }
    /// Every result in an interactive batch retains its own dependencies,
    /// including statements subsequently removed by ROLLBACK TO SAVEPOINT.
    pub(in crate::relational) fn merge(&mut self, other: Self) -> Result<()> {
        // Guard admission includes vector overhead. A batch has at most one
        // captured guard per statement plus one private-session lifetime guard.
        if self.0.len() + other.0.len() > MAX_STATEMENTS_PER_REQUEST + 1 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        self.0.extend(other.0);
        Ok(())
    }
    pub(in crate::relational) fn bind_session(
        &mut self,
        identity: &AuthenticatedIdentity,
        session: Arc<Epoch>,
    ) -> Result<()> {
        let mut memory = memory::Charge::storage();
        memory.prepare(512)?;
        self.merge(Self(vec![Arc::new(Guard {
            identity: identity.cancellation(),
            tables: vec![],
            session: Some(session),
            _memory: memory,
        })]))
    }
    /// Admit the exact candidate's guard before the durable decision. It must
    /// only leave the executor if that candidate commits under the state lock.
    /// Refreshing at an arbitrary adapter would revive already-revoked results.
    pub(in crate::relational) fn after_commit(&self, state: &RelationalState) -> Result<Self> {
        let mut guards = Vec::with_capacity(self.0.len());
        for old in &self.0 {
            let mut memory = memory::Charge::storage();
            memory.prepare(
                512 + old
                    .tables
                    .iter()
                    .map(|(name, _)| name.len() as u64 + 256)
                    .sum::<u64>(),
            )?;
            let mut tables = Vec::with_capacity(old.tables.len());
            for (name, _) in &old.tables {
                let epoch = state
                    .tables
                    .get(name)
                    .map(|table| {
                        table
                            .policy_epoch
                            .as_ref()
                            .cloned()
                            .ok_or(SecurityError::Forbidden)
                    })
                    .transpose()?;
                tables.push((name.clone(), epoch));
            }
            guards.push(Arc::new(Guard {
                identity: old.identity.clone(),
                tables,
                session: old.session.clone(),
                _memory: memory,
            }));
        }
        Ok(Self(guards))
    }
}

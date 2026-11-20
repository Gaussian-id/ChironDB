//! Native row authority control plane, shared by every transport.
use super::*;
use crate::security::SecurityError;

impl Db {
    pub fn relational_security_authorized(
        &self,
        identity: &crate::security::AuthenticatedIdentity,
        table: &str,
        after_row_id: u64,
        limit: usize,
    ) -> Result<crate::SqlResponse> {
        self.ensure_request_admission()?;
        self.ensure_current_identity(identity)?;
        let _lifecycle = self.lifecycle_gate.read();
        self.relational
            .read()
            .inspect_row_security(identity, table, after_row_id, limit)
    }

    pub fn change_relational_security_authorized(
        &self,
        identity: &crate::security::AuthenticatedIdentity,
        delta: chirondb_types::relational::RelationalSecurityDelta,
    ) -> Result<crate::SqlResponse> {
        self.ensure_request_admission()?;
        self.ensure_storage_mutations_available()?;
        self.ensure_current_identity(identity)?;
        let _lifecycle = self.lifecycle_gate.read();
        let _maintenance = self.maintenance_barrier.read();
        let authority = self
            .identity_authority
            .as_ref()
            .ok_or(SecurityError::Unavailable)?;
        let audit = audit::AuditContext {
            principal_id: identity.principal().id.clone(),
            tenant_id: Some(identity.principal().tenant.clone()),
            transport: "protected-row-security".into(),
            request_id: None,
        };
        let execution = self
            .relational
            .read()
            .change_row_security(identity, authority, delta, &audit)?;
        if let Some(error) = execution.projection_error.as_ref() {
            self.mark_durability_degraded("relational_security_projection", error);
        }
        if let Some(transaction) = execution.committed.as_ref() {
            self.project_transaction_audit(transaction);
        }
        Ok(execution.into_output())
    }
}

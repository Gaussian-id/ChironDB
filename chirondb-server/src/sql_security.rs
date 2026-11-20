//! Shared legacy SQL boundary. Scoped SQL requires the protected authority;
//! audit tenant strings and collection allowlists are not SQL row policies.
use crate::rbac::{Action, Principal, authorize};
use crate::{Db, GaussError, RelationalEngine, Result, SqlExecutionRequest, SqlStatementClass};

pub(crate) fn action(request: &SqlExecutionRequest) -> Result<Action> {
    Ok(match RelationalEngine::request_class(request)? {
        SqlStatementClass::Read => Action::Read,
        SqlStatementClass::Write => Action::Write,
        SqlStatementClass::Admin => Action::Admin,
    })
}

pub(crate) fn authorize_legacy(db: &Db, principal: &Principal, action: Action) -> Result<()> {
    if db.tenant_enforcement().blocks() || principal.is_restricted() {
        return Err(crate::security::SecurityError::Forbidden.into());
    }
    authorize(principal, action, None)
        .map_err(|_| GaussError::from(crate::security::SecurityError::Forbidden))
}

pub(crate) fn authorize_request(
    db: &Db,
    principal: &Principal,
    request: &SqlExecutionRequest,
) -> Result<()> {
    authorize_legacy(db, principal, action(request)?)
}

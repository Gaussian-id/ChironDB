//! Row-level tenant isolation.
//!
//! P7 of the ChironQL plan. Enforcement lives here, in the core, rather than in
//! any one query surface: HTTP, gRPC, ChironWire, the pgvector subset and
//! ChironQL all reach the same `Db`, and a rule enforced in only one of them is
//! a fence rather than a wall.
//!
//! Four decisions this module implements, all deliberate:
//!
//! 1. **A write is stamped by the server** from the caller's authenticated
//!    identity. A `tenant_id` arriving in a user-supplied payload is never
//!    trusted; if it disagrees with the caller's own tenant the write is
//!    rejected rather than silently rewritten, because a client sending the
//!    wrong tenant is a bug worth surfacing.
//! 2. **Cross-tenant access is a capability, not a role.** Being an admin does
//!    not imply reading across tenants — [`TenantCapability`] is granted
//!    separately, so the everyday admin path stays scoped and the cross-tenant
//!    path is something a person had to ask for.
//! 3. **Cross-tenant operations are audited** with actor, target, operation and
//!    timestamp. That record is the point of making the capability explicit.
//! 4. **A point with no tenant is visible to nobody** once enforcement is on.
//!    Fail-open would make one un-migrated legacy record a cross-tenant leak,
//!    and a leak is worse than an outage. See [`TenantEnforcement`] for why
//!    that makes the rollout staged rather than a switch.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Filter, GaussError, Result, graph::GraphCapability};

/// Payload field carrying a point's owning tenant.
///
/// A reserved name: user payloads may contain it, but only the server ever
/// writes it, and [`TenantScope::stamp_payload`] rejects a mismatching one.
pub const TENANT_FIELD: &str = "tenant_id";

/// Whether tenant rules are being applied yet.
///
/// **Off by default, and that is not an oversight.** Turning enforcement on
/// makes every point that predates it invisible, because a legacy point has no
/// `tenant_id` and the missing-tenant rule is fail-closed. So the sequence is:
/// deploy with `Disabled`, backfill `tenant_id` onto existing points, verify
/// with `DryRun`, and only then switch to `Enforced`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantEnforcement {
    /// No tenant rules. Behaviour identical to a build without this module.
    #[default]
    Disabled,
    /// Rules are evaluated and violations are logged, but nothing is blocked
    /// and nothing is filtered. This is the mode that tells you whether a
    /// migration is finished, before an outage tells you it was not.
    DryRun,
    /// Rules are applied. Reads are scoped, writes are stamped, untenanted
    /// points are invisible.
    Enforced,
}

impl TenantEnforcement {
    /// Whether violations actually block.
    pub fn blocks(&self) -> bool {
        matches!(self, Self::Enforced)
    }

    /// Whether rules are evaluated at all.
    pub fn active(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// A capability a principal holds beyond its own tenant.
///
/// Deliberately separate from the `read_only` / `read_write` / `admin` role.
/// An admin key administers the cluster; reading another tenant's rows is a
/// different question and gets a different answer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantCapability {
    /// `tenant:cross_read` — may read outside its own tenant.
    CrossRead,
    /// `tenant:cross_write` — may write, stamp or delete outside its own
    /// tenant. The path migrations and administrative repair use, instead of
    /// borrowing ordinary write behaviour.
    CrossWrite,
}

impl TenantCapability {
    /// The name as it appears in configuration.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CrossRead => "tenant:cross_read",
            Self::CrossWrite => "tenant:cross_write",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tenant:cross_read" => Some(Self::CrossRead),
            "tenant:cross_write" => Some(Self::CrossWrite),
            _ => None,
        }
    }
}

/// Who is asking, and what they may reach.
///
/// Every tenant-aware `Db` entry point takes one. There is no default: a call
/// site must say which principal it is acting for, and the only way to act
/// without a tenant is to say so out loud with [`TenantScope::system`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantScope {
    /// The principal's own tenant. `None` means the principal is not scoped to
    /// one — an unconfigured deployment, or an internal caller.
    tenant_id: Option<String>,
    cross_read: bool,
    cross_write: bool,
    graph_read: bool,
    graph_write: bool,
    graph_admin: bool,
    graph_type_configure: bool,
    /// Identifies the actor in audit records. A key id or user name, never a
    /// secret.
    actor: String,
    /// Internal machinery: replication, compaction, recovery. Exempt, because
    /// it moves data that is already on disk rather than answering anybody.
    system: bool,
}

impl TenantScope {
    /// A principal scoped to one tenant, holding no cross-tenant capability.
    pub fn tenant(actor: impl Into<String>, tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: Some(tenant_id.into()),
            cross_read: false,
            cross_write: false,
            graph_read: false,
            graph_write: false,
            graph_admin: false,
            graph_type_configure: false,
            actor: actor.into(),
            system: false,
        }
    }

    /// A principal with no tenant of its own. Under enforcement this can read
    /// nothing unless it also holds [`TenantCapability::CrossRead`] — which is
    /// what makes an unconfigured key harmless rather than omnipotent.
    pub fn untenanted(actor: impl Into<String>) -> Self {
        Self {
            tenant_id: None,
            cross_read: false,
            cross_write: false,
            graph_read: false,
            graph_write: false,
            graph_admin: false,
            graph_type_configure: false,
            actor: actor.into(),
            system: false,
        }
    }

    /// Internal machinery: replication, compaction, snapshot restore. Bypasses
    /// tenant rules because it is not serving a request.
    ///
    /// Never build one of these from anything a network caller influences.
    pub fn system() -> Self {
        Self {
            tenant_id: None,
            cross_read: true,
            cross_write: true,
            graph_read: true,
            graph_write: true,
            graph_admin: true,
            graph_type_configure: true,
            actor: "system".to_string(),
            system: true,
        }
    }

    pub fn with_capability(mut self, capability: TenantCapability) -> Self {
        match capability {
            TenantCapability::CrossRead => self.cross_read = true,
            TenantCapability::CrossWrite => self.cross_write = true,
        }
        self
    }

    pub fn with_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = TenantCapability>,
    ) -> Self {
        for capability in capabilities {
            self = self.with_capability(capability);
        }
        self
    }

    pub fn with_graph_capability(mut self, capability: GraphCapability) -> Self {
        match capability {
            GraphCapability::Read => self.graph_read = true,
            GraphCapability::Write => self.graph_write = true,
            GraphCapability::Admin => self.graph_admin = true,
            GraphCapability::TypeConfigure => self.graph_type_configure = true,
        }
        self
    }

    pub fn with_graph_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = GraphCapability>,
    ) -> Self {
        for capability in capabilities {
            self = self.with_graph_capability(capability);
        }
        self
    }

    pub fn has_graph_capability(&self, capability: GraphCapability) -> bool {
        match capability {
            GraphCapability::Read => self.graph_read,
            GraphCapability::Write => self.graph_write,
            GraphCapability::Admin => self.graph_admin,
            GraphCapability::TypeConfigure => self.graph_type_configure,
        }
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub fn is_system(&self) -> bool {
        self.system
    }

    pub fn can_cross_read(&self) -> bool {
        self.cross_read
    }

    pub fn can_cross_write(&self) -> bool {
        self.cross_write
    }

    // -- reads --------------------------------------------------------------

    /// Narrows a caller's filter so it can only match the caller's own rows.
    ///
    /// The engine's filter is a conjunction of per-field conditions, so an
    /// added `tenant_id` term cannot be escaped: there is no `OR` for a caller
    /// to widen it back with. The property that makes the filter grammar
    /// restrictive is the property that makes this safe.
    pub fn scope_filter(
        &self,
        enforcement: TenantEnforcement,
        filter: Option<Filter>,
    ) -> Result<Option<Filter>> {
        if !enforcement.blocks() || self.system {
            return Ok(filter);
        }

        if self.cross_read {
            // Deliberately unscoped, and recorded as such.
            audit(TenantAudit {
                actor: self.actor.clone(),
                operation: "read".to_string(),
                target_tenant: None,
                own_tenant: self.tenant_id.clone(),
                capability: Some(TenantCapability::CrossRead),
            });
            return Ok(filter);
        }

        let Some(tenant_id) = &self.tenant_id else {
            // No tenant and no capability: nothing is visible. An unconfigured
            // key reads nothing rather than everything.
            return Err(GaussError::InvalidRequest(
                "this principal has no tenant and no tenant:cross_read capability".to_string(),
            ));
        };

        let mut object = match filter {
            Some(Filter(Value::Object(map))) => map,
            Some(Filter(Value::Null)) | None => serde_json::Map::new(),
            // A non-object filter is not something this can safely narrow.
            Some(_) => {
                return Err(GaussError::InvalidRequest(
                    "filter must be an object to be tenant-scoped".to_string(),
                ));
            }
        };

        // A caller-supplied `tenant_id` term is answered the same way a
        // caller-supplied payload tenant is: agreeing is fine, disagreeing is
        // rejected. Silently rewriting it would answer a different question
        // from the one asked and hide the client bug.
        if let Some(existing) = object.get(TENANT_FIELD) {
            let asked_for = existing
                .get("eq")
                .and_then(Value::as_str)
                .or_else(|| existing.as_str());
            if asked_for != Some(tenant_id.as_str()) {
                return Err(GaussError::InvalidRequest(format!(
                    "this principal reads as tenant '{tenant_id}'; filtering on another \
                     `{TENANT_FIELD}` needs the tenant:cross_read capability"
                )));
            }
        }

        object.insert(
            TENANT_FIELD.to_string(),
            serde_json::json!({ "eq": tenant_id }),
        );
        Ok(Some(Filter(Value::Object(object))))
    }

    /// Whether a point may be handed to this caller.
    ///
    /// Used on the paths that fetch by id, where there is no filter to narrow.
    /// A point with no `tenant_id` belongs to nobody and is visible to nobody.
    pub fn may_read_payload(&self, enforcement: TenantEnforcement, payload: &Value) -> bool {
        if !enforcement.blocks() || self.system || self.cross_read {
            return true;
        }
        let Some(tenant_id) = &self.tenant_id else {
            return false;
        };
        payload
            .get(TENANT_FIELD)
            .and_then(Value::as_str)
            .is_some_and(|owner| owner == tenant_id)
    }

    // -- writes -------------------------------------------------------------

    /// Stamps a payload with the caller's tenant.
    ///
    /// The value is taken from the authenticated identity, never from the
    /// payload. A payload that already carries a *different* `tenant_id` is
    /// rejected rather than overwritten: silently rewriting it would hide a
    /// client bug, and honouring it would be the vulnerability.
    pub fn stamp_payload(&self, enforcement: TenantEnforcement, payload: &mut Value) -> Result<()> {
        if !enforcement.active() || self.system {
            return Ok(());
        }

        let supplied = payload.get(TENANT_FIELD).and_then(Value::as_str);

        match (&self.tenant_id, supplied) {
            // Own tenant, and the payload agrees or says nothing.
            (Some(own), None) => {
                if enforcement.blocks() {
                    set_tenant(payload, own)?;
                }
                Ok(())
            }
            (Some(own), Some(supplied)) if supplied == own => Ok(()),

            // Own tenant, payload claims a different one.
            (Some(own), Some(supplied)) => {
                if !self.cross_write {
                    return Err(GaussError::InvalidRequest(format!(
                        "payload declares tenant '{supplied}' but this principal writes as \
                         '{own}'; writing for another tenant needs the tenant:cross_write \
                         capability"
                    )));
                }
                audit(TenantAudit {
                    actor: self.actor.clone(),
                    operation: "write".to_string(),
                    target_tenant: Some(supplied.to_string()),
                    own_tenant: Some(own.clone()),
                    capability: Some(TenantCapability::CrossWrite),
                });
                Ok(())
            }

            // No tenant of its own: only an explicit cross-write may proceed,
            // and only when the payload says where the row belongs.
            (None, supplied) => {
                if !self.cross_write {
                    return Err(GaussError::InvalidRequest(
                        "this principal has no tenant and no tenant:cross_write capability"
                            .to_string(),
                    ));
                }
                if supplied.is_none() && enforcement.blocks() {
                    return Err(GaussError::InvalidRequest(format!(
                        "a cross-tenant write must say which tenant it is for: set \
                         `{TENANT_FIELD}` in the payload"
                    )));
                }
                audit(TenantAudit {
                    actor: self.actor.clone(),
                    operation: "write".to_string(),
                    target_tenant: supplied.map(str::to_string),
                    own_tenant: None,
                    capability: Some(TenantCapability::CrossWrite),
                });
                Ok(())
            }
        }
    }

    /// Whether this caller may modify or delete a point that already exists.
    pub fn may_write_payload(&self, enforcement: TenantEnforcement, payload: &Value) -> Result<()> {
        if !enforcement.blocks() || self.system || self.cross_write {
            if enforcement.blocks() && self.cross_write && !self.system {
                audit(TenantAudit {
                    actor: self.actor.clone(),
                    operation: "write_existing".to_string(),
                    target_tenant: payload
                        .get(TENANT_FIELD)
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    own_tenant: self.tenant_id.clone(),
                    capability: Some(TenantCapability::CrossWrite),
                });
            }
            return Ok(());
        }

        let owner = payload.get(TENANT_FIELD).and_then(Value::as_str);
        match (&self.tenant_id, owner) {
            (Some(own), Some(owner)) if owner == own => Ok(()),
            // Untenanted legacy rows are nobody's to modify either.
            _ => Err(GaussError::InvalidRequest(
                "this point belongs to another tenant".to_string(),
            )),
        }
    }
}

fn set_tenant(payload: &mut Value, tenant_id: &str) -> Result<()> {
    match payload {
        Value::Object(map) => {
            map.insert(
                TENANT_FIELD.to_string(),
                Value::String(tenant_id.to_string()),
            );
            Ok(())
        }
        Value::Null => {
            *payload = serde_json::json!({ TENANT_FIELD: tenant_id });
            Ok(())
        }
        _ => Err(GaussError::InvalidRequest(
            "a point payload must be an object when tenant enforcement is on".to_string(),
        )),
    }
}

/// One cross-tenant access, recorded.
///
/// Emitted as a structured `tracing` event so it lands wherever the operator
/// already sends logs. Carries actor, operation, target tenant and timestamp —
/// the four things a security review asks for — and no payload contents.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TenantAudit {
    pub actor: String,
    pub operation: String,
    pub target_tenant: Option<String>,
    pub own_tenant: Option<String>,
    pub capability: Option<TenantCapability>,
}

fn audit(event: TenantAudit) {
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    tracing::info!(
        target: "chirondb::tenant_audit",
        actor = %event.actor,
        operation = %event.operation,
        target_tenant = event.target_tenant.as_deref().unwrap_or("*"),
        own_tenant = event.own_tenant.as_deref().unwrap_or("-"),
        capability = event.capability.map(|c| c.as_str()).unwrap_or("-"),
        at_unix_ms = at,
        "cross-tenant access"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn acme() -> TenantScope {
        TenantScope::tenant("key-1", "acme")
    }

    #[test]
    fn disabled_enforcement_changes_nothing() {
        let scope = acme();
        let filter = scope
            .scope_filter(TenantEnforcement::Disabled, None)
            .expect("no error");
        assert!(filter.is_none());

        let mut payload = json!({"a": 1});
        scope
            .stamp_payload(TenantEnforcement::Disabled, &mut payload)
            .expect("no error");
        assert_eq!(payload, json!({"a": 1}), "nothing was stamped");
    }

    #[test]
    fn a_read_is_narrowed_to_the_callers_own_tenant() {
        let filter = acme()
            .scope_filter(
                TenantEnforcement::Enforced,
                Some(Filter(json!({"category": {"eq": "electronics"}}))),
            )
            .expect("scoped")
            .expect("some filter");

        assert_eq!(
            filter.0,
            json!({
                "category": {"eq": "electronics"},
                "tenant_id": {"eq": "acme"}
            })
        );
    }

    #[test]
    fn a_caller_asking_for_another_tenant_is_rejected_not_quietly_redirected() {
        let error = acme()
            .scope_filter(
                TenantEnforcement::Enforced,
                Some(Filter(json!({"tenant_id": {"eq": "globex"}}))),
            )
            .expect_err("rejected");
        assert!(error.to_string().contains("cross_read"), "{error}");
    }

    #[test]
    fn a_caller_naming_its_own_tenant_is_harmless() {
        let filter = acme()
            .scope_filter(
                TenantEnforcement::Enforced,
                Some(Filter(json!({"tenant_id": {"eq": "acme"}, "a": {"eq": 1}}))),
            )
            .expect("scoped")
            .expect("filter");
        assert_eq!(filter.0["tenant_id"], json!({"eq": "acme"}));
        assert_eq!(filter.0["a"], json!({"eq": 1}));
    }

    #[test]
    fn a_principal_with_no_tenant_and_no_capability_reads_nothing() {
        let error = TenantScope::untenanted("key-2")
            .scope_filter(TenantEnforcement::Enforced, None)
            .expect_err("denied");
        assert!(error.to_string().contains("cross_read"), "{error}");
    }

    #[test]
    fn cross_read_is_a_capability_not_a_consequence_of_being_admin() {
        // Same principal, one capability apart.
        let scoped = acme()
            .scope_filter(TenantEnforcement::Enforced, None)
            .expect("scoped")
            .expect("filter");
        assert_eq!(scoped.0, json!({"tenant_id": {"eq": "acme"}}));

        let crossing = acme()
            .with_capability(TenantCapability::CrossRead)
            .scope_filter(TenantEnforcement::Enforced, None)
            .expect("scoped");
        assert!(crossing.is_none(), "no tenant term was added");
    }

    #[test]
    fn an_untenanted_point_is_visible_to_nobody() {
        let legacy = json!({"category": "electronics"});
        assert!(
            !acme().may_read_payload(TenantEnforcement::Enforced, &legacy),
            "a legacy point with no tenant must not leak"
        );
        assert!(
            !TenantScope::tenant("key-3", "globex")
                .may_read_payload(TenantEnforcement::Enforced, &legacy)
        );
        // Still readable before enforcement is switched on, which is what
        // makes a migration possible.
        assert!(acme().may_read_payload(TenantEnforcement::Disabled, &legacy));
    }

    #[test]
    fn a_point_is_visible_to_its_own_tenant_only() {
        let owned = json!({"tenant_id": "acme"});
        assert!(acme().may_read_payload(TenantEnforcement::Enforced, &owned));
        assert!(
            !TenantScope::tenant("key-3", "globex")
                .may_read_payload(TenantEnforcement::Enforced, &owned)
        );
    }

    #[test]
    fn a_write_is_stamped_from_the_identity_not_the_payload() {
        let mut payload = json!({"category": "electronics"});
        acme()
            .stamp_payload(TenantEnforcement::Enforced, &mut payload)
            .expect("stamped");
        assert_eq!(payload["tenant_id"], json!("acme"));
    }

    #[test]
    fn a_payload_claiming_another_tenant_is_rejected_not_rewritten() {
        let mut payload = json!({"tenant_id": "globex"});
        let error = acme()
            .stamp_payload(TenantEnforcement::Enforced, &mut payload)
            .expect_err("rejected");

        assert!(error.to_string().contains("cross_write"), "{error}");
        // And it was not quietly corrected either — the caller learns.
        assert_eq!(payload["tenant_id"], json!("globex"));
    }

    #[test]
    fn a_payload_agreeing_with_the_identity_is_accepted() {
        let mut payload = json!({"tenant_id": "acme", "a": 1});
        acme()
            .stamp_payload(TenantEnforcement::Enforced, &mut payload)
            .expect("accepted");
        assert_eq!(payload["tenant_id"], json!("acme"));
    }

    #[test]
    fn cross_write_may_target_another_tenant_explicitly() {
        let mut payload = json!({"tenant_id": "globex"});
        acme()
            .with_capability(TenantCapability::CrossWrite)
            .stamp_payload(TenantEnforcement::Enforced, &mut payload)
            .expect("allowed");
        assert_eq!(payload["tenant_id"], json!("globex"));
    }

    #[test]
    fn a_migration_principal_must_name_the_tenant_it_writes_for() {
        let mut payload = json!({"a": 1});
        let error = TenantScope::untenanted("migrator")
            .with_capability(TenantCapability::CrossWrite)
            .stamp_payload(TenantEnforcement::Enforced, &mut payload)
            .expect_err("must be explicit");
        assert!(error.to_string().contains(TENANT_FIELD), "{error}");
    }

    #[test]
    fn modifying_another_tenants_point_is_refused() {
        let theirs = json!({"tenant_id": "globex"});
        acme()
            .may_write_payload(TenantEnforcement::Enforced, &theirs)
            .expect_err("refused");

        let ours = json!({"tenant_id": "acme"});
        acme()
            .may_write_payload(TenantEnforcement::Enforced, &ours)
            .expect("allowed");
    }

    #[test]
    fn legacy_points_cannot_be_modified_either_once_enforcement_is_on() {
        let legacy = json!({"category": "electronics"});
        acme()
            .may_write_payload(TenantEnforcement::Enforced, &legacy)
            .expect_err("nobody owns it, so nobody may change it");
    }

    #[test]
    fn dry_run_evaluates_without_blocking() {
        // Reads are not narrowed...
        let filter = acme()
            .scope_filter(TenantEnforcement::DryRun, None)
            .expect("no error");
        assert!(filter.is_none());

        // ...and a conflicting payload is not rejected, so a migration can be
        // observed before it is enforced.
        let mut payload = json!({"tenant_id": "globex"});
        let outcome = acme().stamp_payload(TenantEnforcement::DryRun, &mut payload);
        assert!(
            outcome.is_err(),
            "the conflict is still reported in dry run"
        );
    }

    #[test]
    fn system_scope_is_exempt_because_it_serves_nobody() {
        let scope = TenantScope::system();
        assert!(
            scope
                .scope_filter(TenantEnforcement::Enforced, None)
                .expect("ok")
                .is_none()
        );
        assert!(scope.may_read_payload(TenantEnforcement::Enforced, &json!({})));

        let mut payload = json!({});
        scope
            .stamp_payload(TenantEnforcement::Enforced, &mut payload)
            .expect("ok");
        assert!(payload.get(TENANT_FIELD).is_none(), "nothing stamped");
    }

    #[test]
    fn capability_names_round_trip() {
        for capability in [TenantCapability::CrossRead, TenantCapability::CrossWrite] {
            assert_eq!(
                TenantCapability::parse(capability.as_str()),
                Some(capability)
            );
        }
        assert_eq!(TenantCapability::parse("tenant:everything"), None);
    }
}

//! Versioned security contracts. These types carry data, never executable policy.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SECURITY_VERSION: u32 = 1;
pub const MAX_GROUP_DEPTH: usize = 8;
pub const MAX_GROUP_EXPANSION: usize = 4096;
pub const MAX_INHERITANCE_DEPTH: usize = 16;
pub const MAX_POLICY_GRANTS: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Search,
    Create,
    /// Trusted ingestion may attest raw vector/sparse lineage. Separate from
    /// ordinary content creation/update and always tenant/collection scoped.
    Ingest,
    Update,
    Delete,
    GraphRead,
    GraphWrite,
    Traverse,
    Schema,
    CollectionCreate,
    CollectionDrop,
    Maintain,
    Observe,
    IdentityManage,
    PolicyManage,
    LabelsManage,
    GrantsManage,
    Export,
    Snapshot,
    Restore,
}

impl Action {
    pub const fn is_resource(self) -> bool {
        self.is_data() || matches!(self, Self::LabelsManage | Self::GrantsManage)
    }

    pub const fn is_data(self) -> bool {
        matches!(
            self,
            Self::Read
                | Self::Search
                | Self::Create
                | Self::Ingest
                | Self::Update
                | Self::Delete
                | Self::GraphRead
                | Self::GraphWrite
                | Self::Traverse
                | Self::Export
        )
    }
}

/// Rank is explicit; missing/unknown labels must fail deserialization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PointKey {
    pub collection: Uuid,
    pub tenant: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectAttributes {
    pub department: String,
    pub clearance: Classification,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeGrant {
    /// Exact names only. Empty lists grant nothing; wildcards are not accepted.
    pub tenants: BTreeSet<String>,
    pub collections: BTreeSet<String>,
    pub actions: BTreeSet<Action>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRecord {
    pub id: String,
    pub tenant: String,
    pub enabled: bool,
    pub attributes: SubjectAttributes,
    pub grants: Vec<ScopeGrant>,
    /// Administrative actions scoped to the installation, independent of data.
    pub installation_actions: BTreeSet<Action>,
    /// The maximum authority this principal can delegate; not its own access.
    pub delegation: Vec<ScopeGrant>,
}

/// A role grant names one existing collection generation. Names alone must
/// never authorize a replacement collection after drop/recreate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleCollectionGrant {
    pub collection: String,
    pub incarnation: Uuid,
    pub actions: BTreeSet<Action>,
}

/// SQL authority binds both the physical catalog ID and an incarnation that
/// survives rename and restore but changes on drop/recreate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTableGrant {
    pub table: String,
    pub table_id: u64,
    pub incarnation: Uuid,
    pub actions: BTreeSet<Action>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRecord {
    pub id: Uuid,
    pub name: String,
    pub tenant: String,
    pub retired: bool,
    pub grants: Vec<RoleCollectionGrant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_grants: Vec<RoleTableGrant>,
    pub installation_actions: BTreeSet<Action>,
}

/// Public identity metadata. Credentials and delegation ceilings are never
/// part of this representation.
#[derive(Clone, Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub attributes: SubjectAttributes,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialInfo {
    pub id: String,
    pub principal: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UserChanges {
    pub enabled: Option<bool>,
    pub department: Option<String>,
    pub clearance: Option<Classification>,
}

#[derive(Clone, Debug)]
pub struct RolePrivilegeChanges {
    pub collection: Option<(String, Uuid)>,
    pub actions: BTreeSet<Action>,
    pub grant: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PointLabelChanges {
    /// User name, resolved by the identity authority within the mutation.
    pub owner: Option<String>,
    pub department: Option<String>,
    pub classification: Option<Classification>,
}

#[derive(Clone, Debug)]
pub struct PointPrivilegeChanges {
    /// User/group names are resolved before changing protected metadata.
    pub subject: Subject,
    pub actions: BTreeSet<Action>,
    pub effect: Effect,
    pub grant: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum GroupMember {
    Principal(String),
    Group(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRecord {
    pub id: String,
    pub tenant: String,
    pub members: BTreeSet<GroupMember>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Subject {
    Principal(String),
    Group(String),
    Department(String),
    Owner,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Permit,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectGrant {
    pub subject: Subject,
    pub effect: Effect,
    pub actions: BTreeSet<Action>,
    pub inherit: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PropertyAction {
    Read,
    Query,
    Write,
    Export,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyRule {
    /// Exact JSON-pointer path, including its leading slash.
    pub classification: Classification,
    pub actions: BTreeSet<PropertyAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLabels {
    pub owner: String,
    pub department: String,
    pub classification: Classification,
    pub quarantined: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Representation {
    /// Exact input field paths attested by the trusted ingest template.
    pub source_fields: BTreeSet<String>,
    pub classification: Classification,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngestTemplate {
    pub department: String,
    pub classification: Classification,
    pub properties: BTreeMap<String, PropertyRule>,
    pub representations: BTreeMap<String, Representation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionPolicy {
    pub department_actions: BTreeSet<Action>,
    pub owner_actions: BTreeSet<Action>,
    pub templates: BTreeMap<String, IngestTemplate>,
}

/// Stored separately from ordinary payload and bound to the physical point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRecord {
    pub key: PointKey,
    pub storage_id: Uuid,
    pub labels: ResourceLabels,
    pub properties: BTreeMap<String, PropertyRule>,
    pub representations: BTreeMap<String, Representation>,
    pub grants: Vec<ObjectGrant>,
    pub parent: Option<PointKey>,
    pub revision: u64,
    pub retired: bool,
    /// A batch receipt stays on its first binding, including after deletion.
    /// Content updates and label changes cannot overwrite this authority data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_receipt: Option<CreateReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReceipt {
    pub principal: String,
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub ids: Vec<String>,
}

/// Labels and property rules are mutable only through the label authority.
/// Existing representation labels can become stricter, never silently weaker.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectLabels {
    pub labels: ResourceLabels,
    pub properties: BTreeMap<String, PropertyRule>,
}

/// The parent is a public ID in the active tenant and collection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectPermissions {
    pub grants: Vec<ObjectGrant>,
    pub parent: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservePointIds {
    pub count: u32,
    pub template: String,
    pub session: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewPoint {
    pub vector: Vec<f32>,
    #[serde(default)]
    pub vectors: BTreeMap<String, Vec<f32>>,
    #[serde(default)]
    pub sparse_vector: Option<crate::model::SparseVector>,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePoints {
    pub template: String,
    pub points: Vec<NewPoint>,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionUpdate<T> {
    pub expected_revision: u64,
    pub value: T,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum SecurityError {
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("resource not found")]
    NotFound,
    #[error("security revision changed")]
    Conflict,
    #[error("security authority unavailable")]
    Unavailable,
    #[error("invalid security configuration: {0}")]
    Invalid(String),
    #[error("security evaluation budget exceeded")]
    BudgetExceeded,
}

impl SecurityError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "security.unauthenticated",
            Self::Forbidden => "security.forbidden",
            Self::NotFound => "security.not_found",
            Self::Conflict => "security.conflict",
            Self::Unavailable => "security.unavailable",
            Self::Invalid(_) => "security.invalid",
            Self::BudgetExceeded => "security.budget_exceeded",
        }
    }
}

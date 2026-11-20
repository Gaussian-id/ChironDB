//! Admitted, immutable security metadata travels with each MVCC row version.
use super::*;
mod administration;
mod constraints;
pub(super) use constraints::{key_domain, preflight_constraints};
mod dependencies;
mod mutation;
mod publication;
mod revocation;
mod schema_changes;
pub(super) use mutation::apply_delta;
pub use publication::SqlPublication;
pub(super) use revocation::{close_replaced_epochs, fence_deletions, renew_uncommitted_epochs};
pub(super) use schema_changes::{column_rename, reconcile_columns};
#[cfg(test)]
mod tests;
use crate::security::{ResourceContent, ResourceRecord, Subject};
pub(super) use dependencies::preflight;
use std::ops::Deref;

#[derive(Debug)]
struct Allocation {
    record: ResourceRecord,
    _charge: memory::Charge,
}

#[derive(Clone, Debug)]
pub(super) struct Metadata(Arc<Allocation>);

impl Metadata {
    pub(super) fn adopt(record: ResourceRecord) -> Result<Self> {
        // Native row inheritance and vector representation attestations are not
        // interchangeable with a table's object/column authority.
        if record.revision == 0
            || record.storage_id.is_nil()
            || record.key.collection.is_nil()
            || record
                .key
                .id
                .parse::<u64>()
                .ok()
                .is_none_or(|id| id == 0 || id.to_string() != record.key.id)
            || !policy::identifier(&record.key.tenant)
            || !policy::identifier(&record.labels.owner)
            || !policy::identifier(&record.labels.department)
            || record.grants.len() > crate::security::MAX_POLICY_GRANTS
            || record.properties.len() > crate::security::MAX_POLICY_GRANTS
            || record.content != ResourceContent::Point
            || record.parent.is_some()
            || record.create_receipt.is_some()
            || !record.representations.is_empty()
            || record.grants.iter().any(|grant| grant.inherit)
        {
            return Err(SecurityError::Invalid("invalid relational row authority".into()).into());
        }
        validate_properties(&record.properties)?;
        if record
            .grants
            .iter()
            .any(|grant| grant.actions.iter().any(|action| !row_action(*action)))
        {
            return Err(SecurityError::Invalid("invalid relational object grant".into()).into());
        }
        crate::security::storage::serialized_len(&record, 64 * 1024)?;
        let mut bytes = 2048_u64;
        for value in [
            &record.key.tenant,
            &record.key.id,
            &record.labels.owner,
            &record.labels.department,
        ] {
            bytes = bytes.saturating_add(value.capacity() as u64);
        }
        for (path, rule) in &record.properties {
            bytes = bytes
                .saturating_add(512 + path.capacity() as u64 + rule.actions.len() as u64 * 128);
        }
        bytes = bytes.saturating_add(
            (record.grants.capacity() * std::mem::size_of::<crate::security::ObjectGrant>()) as u64,
        );
        for grant in &record.grants {
            bytes = bytes.saturating_add(grant.actions.len() as u64 * 128);
            match &grant.subject {
                Subject::Principal(name) | Subject::Group(name) | Subject::Department(name) => {
                    bytes = bytes.saturating_add(name.capacity() as u64)
                }
                Subject::Owner => (),
            }
        }
        let mut charge = memory::Charge::storage();
        charge.prepare(bytes)?;
        Ok(Self(Arc::new(Allocation {
            record,
            _charge: charge,
        })))
    }

    pub(super) fn decode(raw: &serde_json::value::RawValue) -> Result<Self> {
        if raw.get().len() > 64 * 1024 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        // Reserve before serde allocates strings, B-trees or grants. Retained
        // ownership gets its own exact capacity charge before scratch releases.
        let mut scratch = memory::Charge::storage();
        scratch.prepare(raw.get().len() as u64 * 64 + 4096)?;
        Self::adopt(serde_json::from_str(raw.get())?)
    }
}
impl Deref for Metadata {
    type Target = ResourceRecord;
    fn deref(&self) -> &Self::Target {
        &self.0.record
    }
}
impl Serialize for Metadata {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.0.record.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        Self::adopt(ResourceRecord::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

use crate::security::{
    Action, CollectionPolicy, IngestTemplate, PointKey, PropertyAction, PropertyRule,
    ResourceLabels, policy,
};

fn column_path(name: &str) -> String {
    format!("/{}", name.replace('~', "~0").replace('/', "~1"))
}

pub(super) fn default_policy(
    definition: &TableDefinition,
    identity: &AuthenticatedIdentity,
) -> chirondb_types::RelationalRowPolicy {
    let attributes = &identity.principal().attributes;
    chirondb_types::RelationalRowPolicy {
        revision: 1,
        default_template: "owner".into(),
        policy: CollectionPolicy {
            department_actions: BTreeSet::new(),
            owner_actions: BTreeSet::from([
                Action::Read,
                Action::Create,
                Action::Update,
                Action::Delete,
                Action::LabelsManage,
                Action::GrantsManage,
            ]),
            templates: BTreeMap::from([(
                "owner".into(),
                IngestTemplate {
                    department: attributes.department.clone(),
                    classification: attributes.clearance,
                    properties: definition
                        .columns
                        .iter()
                        .map(|column| {
                            (
                                column_path(&column.name),
                                PropertyRule {
                                    classification: attributes.clearance,
                                    actions: BTreeSet::from([
                                        PropertyAction::Read,
                                        PropertyAction::Query,
                                        PropertyAction::Write,
                                    ]),
                                },
                            )
                        })
                        .collect(),
                    representations: BTreeMap::new(),
                },
            )]),
        },
    }
}

fn resource<'a>(
    definition: &TableDefinition,
    row_id: u64,
    version: &'a RowVersion,
) -> Result<&'a ResourceRecord> {
    let record = version.security.as_deref().ok_or(SecurityError::NotFound)?;
    if definition.tenant_id.as_deref() != Some(record.key.tenant.as_str())
        || definition.security_incarnation != Some(record.key.collection)
        || record.key.id != row_id.to_string()
    {
        return Err(SecurityError::NotFound.into());
    }
    Ok(record)
}

fn object_allowed(
    definition: &TableDefinition,
    row_id: u64,
    version: &RowVersion,
    identity: &AuthenticatedIdentity,
    action: Action,
) -> Result<bool> {
    let _permit = identity.publication_permit()?;
    if definition.tenant_id.as_deref() != Some(identity.principal().tenant.as_str()) {
        return Err(SecurityError::Forbidden.into());
    }
    let config = definition
        .row_policy
        .as_ref()
        .ok_or(SecurityError::Forbidden)?;
    let record = match resource(definition, row_id, version) {
        Ok(record) => record,
        Err(GaussError::Security(SecurityError::NotFound)) => return Ok(false),
        Err(error) => return Err(error),
    };
    match policy::authorize_resource(
        identity.principal(),
        identity.groups(),
        record,
        action,
        &config.policy,
        &BTreeMap::new(),
    ) {
        Ok(()) => Ok(true),
        Err(SecurityError::NotFound) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn readable(
    definition: &TableDefinition,
    row_id: u64,
    version: &RowVersion,
    identity: Option<&AuthenticatedIdentity>,
) -> Result<bool> {
    match identity {
        Some(identity) if definition.tenant_id.is_some() => {
            object_allowed(definition, row_id, version, identity, Action::Read)
        }
        // CTEs are ephemeral projections of already-authorized rows.
        _ if definition.row_policy.is_none() => Ok(true),
        _ => Err(SecurityError::Forbidden.into()),
    }
}

pub(super) fn visible(
    table: &TableState,
    row_id: u64,
    snapshot: u64,
    identity: Option<&AuthenticatedIdentity>,
) -> Result<Option<RowVersion>> {
    let Some(version) = table.rows.visible(row_id, snapshot)? else {
        return Ok(None);
    };
    Ok(readable(&table.definition, row_id, &version, identity)?.then_some(version))
}

pub(super) fn visible_rows<'a>(
    table: &'a TableState,
    snapshot: u64,
    identity: Option<&'a AuthenticatedIdentity>,
) -> impl Iterator<Item = Result<(u64, RowValues)>> + 'a {
    table
        .rows
        .visible_versions(snapshot)
        .filter_map(move |row| {
            let result = row.and_then(|(id, version)| {
                Ok(readable(&table.definition, id, &version, identity)?
                    .then_some((id, version.values)))
            });
            match result {
                Ok(Some(row)) => Some(Ok(row)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        })
}

pub(super) fn create(
    definition: &TableDefinition,
    row_id: u64,
    identity: Option<&AuthenticatedIdentity>,
) -> Result<Option<Metadata>> {
    let Some(identity) = identity else {
        return if definition.row_policy.is_none() {
            Ok(None)
        } else {
            Err(SecurityError::Forbidden.into())
        };
    };
    let config = definition
        .row_policy
        .as_ref()
        .ok_or(SecurityError::Forbidden)?;
    let template = config
        .policy
        .templates
        .get(&config.default_template)
        .ok_or(SecurityError::Forbidden)?;
    if identity.principal().attributes.clearance < template.classification {
        return Err(SecurityError::Forbidden.into());
    }
    let record = ResourceRecord {
        key: PointKey {
            tenant: identity.principal().tenant.clone(),
            collection: definition
                .security_incarnation
                .ok_or(SecurityError::Forbidden)?,
            id: row_id.to_string(),
        },
        storage_id: uuid::Uuid::new_v4(),
        content: ResourceContent::Point,
        labels: ResourceLabels {
            owner: identity.principal().id.clone(),
            department: template.department.clone(),
            classification: template.classification,
            quarantined: false,
        },
        properties: template.properties.clone(),
        representations: BTreeMap::new(),
        grants: vec![],
        parent: None,
        revision: config.revision,
        retired: false,
        create_receipt: None,
    };
    policy::authorize_resource(
        identity.principal(),
        identity.groups(),
        &record,
        Action::Create,
        &config.policy,
        &BTreeMap::new(),
    )
    .map_err(|_| SecurityError::Forbidden)?;
    // INSERT supplies a complete physical row, including defaults and NULLs.
    for column in &definition.columns {
        if !policy::field_allowed(
            &record,
            &identity.principal().attributes,
            &column_path(&column.name),
            PropertyAction::Write,
        ) {
            return Err(SecurityError::Forbidden.into());
        }
    }
    Ok(Some(Metadata::adopt(record)?))
}

pub(super) fn stored(
    table: &TableState,
    row_id: u64,
    snapshot: u64,
) -> Result<Option<ResourceRecord>> {
    Ok(table
        .rows
        .visible(row_id, snapshot)?
        .and_then(|row| row.security.map(|metadata| (*metadata).clone())))
}

pub(super) fn write(
    table: &TableState,
    row_id: u64,
    snapshot: u64,
    identity: Option<&AuthenticatedIdentity>,
    action: Action,
    columns: &[usize],
) -> Result<()> {
    let Some(identity) = identity else {
        return if table.definition.row_policy.is_none() {
            Ok(())
        } else {
            Err(SecurityError::Forbidden.into())
        };
    };
    let version = table
        .rows
        .visible(row_id, snapshot)?
        .ok_or(SecurityError::NotFound)?;
    if !object_allowed(&table.definition, row_id, &version, identity, Action::Read)?
        || !object_allowed(&table.definition, row_id, &version, identity, action)?
    {
        return Err(SecurityError::Forbidden.into());
    }
    let record = resource(&table.definition, row_id, &version)?;
    for index in columns {
        if !policy::field_allowed(
            record,
            &identity.principal().attributes,
            &column_path(&table.definition.columns[*index].name),
            PropertyAction::Write,
        ) {
            return Err(SecurityError::Forbidden.into());
        }
    }
    Ok(())
}

pub(super) fn returning(
    definition: &TableDefinition,
    rows: &[StoredRow],
    projection: &[QueryProjection],
    identity: Option<&AuthenticatedIdentity>,
) -> Result<()> {
    let Some(identity) = identity else {
        return if definition.row_policy.is_none() {
            Ok(())
        } else {
            Err(SecurityError::Forbidden.into())
        };
    };
    let config = definition
        .row_policy
        .as_ref()
        .ok_or(SecurityError::Forbidden)?;
    for row in rows {
        let record = row.security.as_ref().ok_or(SecurityError::Forbidden)?;
        policy::authorize_resource(
            identity.principal(),
            identity.groups(),
            record,
            Action::Read,
            &config.policy,
            &BTreeMap::new(),
        )
        .map_err(|_| SecurityError::Forbidden)?;
        for item in projection {
            let index = match &item.source {
                QueryProjectionSource::Column(index) => *index,
                QueryProjectionSource::RecordRef { id_column, .. } => *id_column,
                QueryProjectionSource::Scalar(_) => continue,
            };
            if !policy::field_allowed(
                record,
                &identity.principal().attributes,
                &column_path(&definition.columns[index].name),
                PropertyAction::Read,
            ) {
                return Err(SecurityError::Forbidden.into());
            }
        }
    }
    Ok(())
}

pub(super) fn validate_policy(definition: &TableDefinition) -> Result<()> {
    let Some(config) = &definition.row_policy else {
        return Ok(());
    };
    if config.revision == 0
        || definition
            .tenant_id
            .as_deref()
            .is_none_or(|tenant| !policy::identifier(tenant))
        || definition.security_incarnation.is_none_or(|id| id.is_nil())
        || !policy::identifier(&config.default_template)
        || !config
            .policy
            .templates
            .contains_key(&config.default_template)
        || config.policy.templates.len() > crate::security::MAX_POLICY_GRANTS
    {
        return Err(SecurityError::Invalid("invalid relational policy".into()).into());
    }
    crate::security::storage::serialized_len(config, 256 * 1024)?;
    for actions in [
        &config.policy.owner_actions,
        &config.policy.department_actions,
    ] {
        if actions.iter().any(|action| !row_action(*action)) {
            return Err(SecurityError::Invalid("invalid relational object action".into()).into());
        }
    }
    for (name, template) in &config.policy.templates {
        if !policy::identifier(name)
            || !policy::identifier(&template.department)
            || !template.representations.is_empty()
        {
            return Err(SecurityError::Invalid("invalid relational ingest template".into()).into());
        }
        validate_properties(&template.properties)?;
    }
    Ok(())
}
fn row_action(action: Action) -> bool {
    matches!(
        action,
        Action::Read
            | Action::Search
            | Action::Create
            | Action::Update
            | Action::Delete
            | Action::LabelsManage
            | Action::GrantsManage
            | Action::Export
    )
}
fn validate_properties(properties: &BTreeMap<String, PropertyRule>) -> Result<()> {
    if properties.len() > crate::security::MAX_POLICY_GRANTS {
        return Err(SecurityError::BudgetExceeded.into());
    }
    for path in properties.keys() {
        let Some(column) = path.strip_prefix('/') else {
            return Err(
                SecurityError::Invalid("column rule requires a JSON pointer".into()).into(),
            );
        };
        if column.is_empty() || path.len() > 1024 || column.contains('/') {
            return Err(
                SecurityError::Invalid("column rule must name one exact column".into()).into(),
            );
        }
        let mut bytes = column.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
                return Err(SecurityError::Invalid("invalid column pointer escape".into()).into());
            }
        }
    }
    Ok(())
}
pub(super) fn validate_binding(
    definition: &TableDefinition,
    row_id: u64,
    record: Option<&ResourceRecord>,
    allow_missing: bool,
) -> Result<()> {
    match (&definition.row_policy, record) {
        (Some(config), Some(record))
            if definition.tenant_id.as_deref() == Some(record.key.tenant.as_str())
                && definition.security_incarnation == Some(record.key.collection)
                && record.key.id == row_id.to_string()
                && record.revision <= config.revision =>
        {
            Ok(())
        }
        (_, None) if allow_missing || definition.row_policy.is_none() => Ok(()),
        _ => {
            Err(SecurityError::Invalid("row authority does not match table binding".into()).into())
        }
    }
}

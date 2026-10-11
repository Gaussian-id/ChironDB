//! Exact policy oracle. Query filters are deliberately absent from this API.
use super::*;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

type Result<T> = std::result::Result<T, SecurityError>;

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}

pub(crate) fn validate_principal(principal: &PrincipalRecord) -> Result<()> {
    if !identifier(&principal.id)
        || !identifier(&principal.tenant)
        || !identifier(&principal.attributes.department)
    {
        return Err(SecurityError::Invalid(
            "invalid principal identity or attributes".into(),
        ));
    }
    if principal.grants.len() > MAX_POLICY_GRANTS || principal.delegation.len() > MAX_POLICY_GRANTS
    {
        return Err(SecurityError::BudgetExceeded);
    }
    if principal
        .installation_actions
        .iter()
        .any(|action| action.is_data())
    {
        return Err(SecurityError::Invalid(
            "data access must name exact tenant and collection scopes".into(),
        ));
    }
    for grant in principal.grants.iter().chain(&principal.delegation) {
        if grant.tenants.is_empty()
            || grant.collections.is_empty()
            || grant.actions.is_empty()
            || grant.tenants.iter().any(|id| !identifier(id))
            || grant
                .collections
                .iter()
                .any(|id| !identifier(id) || id.contains(':'))
        {
            return Err(SecurityError::Invalid(
                "grants require nonempty exact scopes".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn scope_allows(
    principal: &PrincipalRecord,
    tenant: &str,
    collection: &str,
    action: Action,
) -> bool {
    principal.enabled
        && principal.grants.iter().any(|grant| {
            grant.tenants.contains(tenant)
                && grant.collections.contains(collection)
                && grant.actions.contains(&action)
        })
}

pub(crate) fn may_delegate(actor: &PrincipalRecord, grants: &[ScopeGrant]) -> bool {
    grants.iter().all(|grant| {
        grant.tenants.iter().all(|tenant| {
            grant.collections.iter().all(|collection| {
                grant.actions.iter().all(|action| {
                    actor.delegation.iter().any(|ceiling| {
                        ceiling.tenants.contains(tenant)
                            && ceiling.collections.contains(collection)
                            && ceiling.actions.contains(action)
                    })
                })
            })
        })
    })
}

/// The installation administrator is the identity trust root. It may mint
/// exact scopes in its own tenant even when onboarding did not know future
/// collection/table names. This grants no data access to the administrator
/// itself; a separate explicit grant remains required for reads and writes.
pub(crate) fn may_delegate_identity(actor: &AuthenticatedIdentity, grants: &[ScopeGrant]) -> bool {
    if actor.is_installation_admin() {
        return grants.iter().all(|grant| {
            grant
                .tenants
                .iter()
                .all(|tenant| tenant == &actor.principal().tenant)
                && !grant.actions.contains(&Action::IdentityManage)
        });
    }
    may_delegate(actor.principal(), grants)
}

pub(crate) fn validate_groups(
    groups: &BTreeMap<String, GroupRecord>,
    principals: &BTreeMap<String, PrincipalRecord>,
) -> Result<()> {
    fn visit<'a>(
        id: &'a str,
        tenant: &str,
        groups: &'a BTreeMap<String, GroupRecord>,
        principals: &BTreeMap<String, PrincipalRecord>,
        path: &mut BTreeSet<&'a str>,
        depth: usize,
        heights: &mut BTreeMap<&'a str, usize>,
    ) -> Result<usize> {
        if depth > MAX_GROUP_DEPTH {
            return Err(SecurityError::BudgetExceeded);
        }
        if let Some(height) = heights.get(id) {
            if depth + height - 1 > MAX_GROUP_DEPTH {
                return Err(SecurityError::BudgetExceeded);
            }
            return Ok(*height);
        }
        if !path.insert(id) {
            return Err(SecurityError::Invalid("group cycle".into()));
        }
        let group = groups
            .get(id)
            .ok_or_else(|| SecurityError::Invalid("unknown group".into()))?;
        if group.tenant != tenant || group.id != id || !identifier(id) {
            return Err(SecurityError::Invalid(
                "group identity or tenant mismatch".into(),
            ));
        }
        if group.members.len() > MAX_GROUP_EXPANSION {
            return Err(SecurityError::BudgetExceeded);
        }
        let mut height = 1;
        for member in &group.members {
            match member {
                GroupMember::Principal(id) => {
                    if principals
                        .get(id)
                        .is_none_or(|principal| principal.tenant != tenant)
                    {
                        return Err(SecurityError::Invalid(
                            "unknown or cross-tenant group member".into(),
                        ));
                    }
                }
                GroupMember::Group(id) => {
                    if groups.get(id).is_none_or(|child| child.tenant != tenant) {
                        return Err(SecurityError::Invalid(
                            "unknown or cross-tenant group member".into(),
                        ));
                    }
                    height = height
                        .max(1 + visit(id, tenant, groups, principals, path, depth + 1, heights)?);
                }
            }
        }
        path.remove(id);
        heights.insert(id, height);
        Ok(height)
    }
    let mut heights = BTreeMap::new();
    for (id, group) in groups {
        visit(
            id,
            &group.tenant,
            groups,
            principals,
            &mut BTreeSet::new(),
            1,
            &mut heights,
        )?;
    }
    Ok(())
}

pub(crate) fn expand_groups(
    principal: &PrincipalRecord,
    groups: &BTreeMap<String, GroupRecord>,
) -> Result<BTreeSet<String>> {
    let mut reverse: BTreeMap<GroupMember, Vec<&str>> = BTreeMap::new();
    for group in groups
        .values()
        .filter(|group| group.tenant == principal.tenant)
    {
        for member in &group.members {
            reverse.entry(member.clone()).or_default().push(&group.id);
        }
    }
    let mut frontier = VecDeque::from([(GroupMember::Principal(principal.id.clone()), 0usize)]);
    let mut expanded = BTreeSet::new();
    while let Some((member, depth)) = frontier.pop_front() {
        for group in reverse.get(&member).into_iter().flatten() {
            if depth >= MAX_GROUP_DEPTH {
                return Err(SecurityError::BudgetExceeded);
            }
            if expanded.insert((*group).to_string()) {
                if expanded.len() > MAX_GROUP_EXPANSION {
                    return Err(SecurityError::BudgetExceeded);
                }
                frontier.push_back((GroupMember::Group((*group).to_string()), depth + 1));
            }
        }
    }
    Ok(expanded)
}

fn subject_matches(
    subject: &Subject,
    principal: &PrincipalRecord,
    groups: &BTreeSet<String>,
    resource: &ResourceRecord,
) -> bool {
    match subject {
        Subject::Principal(id) => id == &principal.id,
        Subject::Group(id) => groups.contains(id),
        Subject::Department(id) => id == &principal.attributes.department,
        Subject::Owner => resource.labels.owner == principal.id,
    }
}

pub(crate) fn authorize_resource(
    principal: &PrincipalRecord,
    groups: &BTreeSet<String>,
    resource: &ResourceRecord,
    action: Action,
    policy: &CollectionPolicy,
    resources: &BTreeMap<PointKey, ResourceRecord>,
) -> Result<()> {
    if !principal.enabled
        || resource.retired
        || (resource.labels.quarantined
            && !(action == Action::LabelsManage
                && principal.installation_actions.contains(&action)))
        || principal.attributes.clearance < resource.labels.classification
    {
        return Err(SecurityError::NotFound);
    }
    let mut permit = (matches!(action, Action::LabelsManage | Action::GrantsManage)
        && principal.installation_actions.contains(&action))
        || (resource.labels.department == principal.attributes.department
            && policy.department_actions.contains(&action))
        || (resource.labels.owner == principal.id && policy.owner_actions.contains(&action));
    let mut current = resource;
    let mut visited = [None; MAX_INHERITANCE_DEPTH];
    let mut depth = 0;
    let mut count = 0usize;
    loop {
        if visited[..depth].contains(&Some(&current.key)) {
            return Err(SecurityError::Invalid("inheritance cycle".into()));
        }
        if depth == visited.len() {
            return Err(SecurityError::BudgetExceeded);
        }
        visited[depth] = Some(&current.key);
        depth += 1;
        count += current.grants.len();
        if count > MAX_POLICY_GRANTS {
            return Err(SecurityError::BudgetExceeded);
        }
        for grant in &current.grants {
            if (current.key == resource.key || grant.inherit)
                && grant.actions.contains(&action)
                && subject_matches(&grant.subject, principal, groups, current)
            {
                match grant.effect {
                    Effect::Deny => return Err(SecurityError::NotFound),
                    Effect::Permit => permit = true,
                }
            }
        }
        let Some(parent) = &current.parent else { break };
        if parent.tenant != resource.key.tenant || parent.collection != resource.key.collection {
            return Err(SecurityError::Invalid(
                "inheritance crosses security domain".into(),
            ));
        }
        current = resources
            .get(parent)
            .filter(|parent| !parent.retired && !parent.labels.quarantined)
            .ok_or(SecurityError::NotFound)?;
    }
    if permit {
        Ok(())
    } else {
        Err(SecurityError::NotFound)
    }
}

pub(crate) fn validate_template(template: &IngestTemplate) -> Result<()> {
    if !identifier(&template.department)
        || template.properties.len() > MAX_POLICY_GRANTS
        || template.representations.len() > MAX_POLICY_GRANTS
    {
        return Err(SecurityError::Invalid("invalid ingest template".into()));
    }
    for path in template.properties.keys() {
        if !valid_property_path(path) || reserved(path) {
            return Err(SecurityError::Invalid(
                "invalid or reserved property path".into(),
            ));
        }
        if path
            .match_indices('/')
            .skip(1)
            .any(|(index, _)| template.properties.contains_key(&path[..index]))
        {
            return Err(SecurityError::Invalid(
                "property rules cannot overlap an ancestor rule".into(),
            ));
        }
    }
    for (name, representation) in &template.representations {
        if !identifier(name) || representation.source_fields.len() > MAX_POLICY_GRANTS {
            return Err(SecurityError::Invalid("invalid representation".into()));
        }
        if representation.source_fields.is_empty() {
            return Err(SecurityError::Invalid(
                "representation requires attested sources".into(),
            ));
        }
        for path in &representation.source_fields {
            let property = template
                .properties
                .get(path)
                .ok_or_else(|| SecurityError::Invalid("unknown representation source".into()))?;
            if representation.classification < property.classification {
                return Err(SecurityError::Invalid(
                    "representation is less restricted than its source".into(),
                ));
            }
        }
    }
    Ok(())
}

fn valid_property_path(path: &str) -> bool {
    if !path.starts_with('/') || path.len() > 1024 || path.split('/').count() > 17 {
        return false;
    }
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

fn reserved(path: &str) -> bool {
    [
        "/tenant_id",
        "/owner",
        "/department",
        "/classification",
        "/acl",
        "/allowed_groups",
    ]
    .iter()
    .any(|reserved| {
        path == *reserved
            || path
                .strip_prefix(reserved)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

pub(crate) fn field_allowed(
    record: &ResourceRecord,
    attributes: &SubjectAttributes,
    path: &str,
    action: PropertyAction,
) -> bool {
    record.properties.get(path).is_some_and(|rule| {
        attributes.clearance >= rule.classification && rule.actions.contains(&action)
    })
}

fn child_path(parent: &str, key: &str) -> String {
    format!("{parent}/{}", key.replace('~', "~0").replace('/', "~1"))
}

pub(crate) fn validate_payload_write(
    record: &ResourceRecord,
    attributes: &SubjectAttributes,
    payload: &Value,
) -> Result<()> {
    fn visit(
        record: &ResourceRecord,
        attributes: &SubjectAttributes,
        path: &str,
        value: &Value,
        depth: usize,
        count: &mut usize,
    ) -> Result<()> {
        *count += 1;
        if depth > 16 || *count > MAX_POLICY_GRANTS {
            return Err(SecurityError::BudgetExceeded);
        }
        if record.properties.contains_key(path) {
            return if field_allowed(record, attributes, path, PropertyAction::Write) {
                Ok(())
            } else {
                Err(SecurityError::Forbidden)
            };
        }
        if let Value::Object(fields) = value {
            if fields.is_empty() && !path.is_empty() {
                return Err(SecurityError::Forbidden);
            }
            for (name, value) in fields {
                visit(
                    record,
                    attributes,
                    &child_path(path, name),
                    value,
                    depth + 1,
                    count,
                )?;
            }
        } else if !field_allowed(record, attributes, path, PropertyAction::Write) {
            return Err(SecurityError::Forbidden);
        }
        Ok(())
    }
    if !payload.is_object() {
        return Err(SecurityError::Invalid("payload must be an object".into()));
    }
    visit(record, attributes, "", payload, 0, &mut 0)
}

/// Replacement and merge must authorize removal as well as insertion. Merely
/// checking the submitted fields would let a writer erase a protected field.
pub(crate) fn validate_payload_change(
    record: &ResourceRecord,
    attributes: &SubjectAttributes,
    old: &Value,
    new: &Value,
) -> Result<()> {
    fn visit(
        record: &ResourceRecord,
        attributes: &SubjectAttributes,
        path: &str,
        old: Option<&Value>,
        new: Option<&Value>,
        depth: usize,
        count: &mut usize,
    ) -> Result<()> {
        *count += 1;
        if depth > 16 || *count > MAX_POLICY_GRANTS {
            return Err(SecurityError::BudgetExceeded);
        }
        if old == new {
            return Ok(());
        }
        if record.properties.contains_key(path) {
            return if field_allowed(record, attributes, path, PropertyAction::Write) {
                Ok(())
            } else {
                Err(SecurityError::Forbidden)
            };
        }
        let old_fields = old.and_then(Value::as_object);
        let new_fields = new.and_then(Value::as_object);
        if old_fields.is_some() || new_fields.is_some() {
            // Scalar/object changes require permission for the scalar and for
            // every affected descendant, including descendants being removed.
            if (old.is_some_and(|value| !value.is_object())
                || new.is_some_and(|value| !value.is_object()))
                && !field_allowed(record, attributes, path, PropertyAction::Write)
            {
                return Err(SecurityError::Forbidden);
            }
            let names: BTreeSet<_> = old_fields
                .into_iter()
                .chain(new_fields)
                .flat_map(|fields| fields.keys())
                .collect();
            if names.is_empty() && !path.is_empty() {
                return Err(SecurityError::Forbidden);
            }
            for name in names {
                visit(
                    record,
                    attributes,
                    &child_path(path, name),
                    old_fields.and_then(|fields| fields.get(name)),
                    new_fields.and_then(|fields| fields.get(name)),
                    depth + 1,
                    count,
                )?;
            }
        } else if !field_allowed(record, attributes, path, PropertyAction::Write) {
            return Err(SecurityError::Forbidden);
        }
        Ok(())
    }
    if !new.is_object() {
        return Err(SecurityError::Invalid("payload must be an object".into()));
    }
    visit(record, attributes, "", Some(old), Some(new), 0, &mut 0)
}

pub(crate) fn project_payload(
    record: &ResourceRecord,
    attributes: &SubjectAttributes,
    payload: &Value,
    action: PropertyAction,
) -> Value {
    fn project(
        record: &ResourceRecord,
        attributes: &SubjectAttributes,
        path: &str,
        value: &Value,
        action: PropertyAction,
    ) -> Option<Value> {
        if record.properties.contains_key(path) {
            return field_allowed(record, attributes, path, action).then(|| value.clone());
        }
        if let Value::Object(fields) = value {
            let out: Map<String, Value> = fields
                .iter()
                .filter_map(|(name, value)| {
                    project(record, attributes, &child_path(path, name), value, action)
                        .map(|value| (name.clone(), value))
                })
                .collect();
            (!out.is_empty() || path.is_empty()).then_some(Value::Object(out))
        } else {
            field_allowed(record, attributes, path, action).then(|| value.clone())
        }
    }
    project(record, attributes, "", payload, action).unwrap_or_else(|| Value::Object(Map::new()))
}

pub(crate) fn validate_collection_policy(config: &CollectionPolicy) -> Result<()> {
    if config.templates.len() > MAX_POLICY_GRANTS {
        return Err(SecurityError::BudgetExceeded);
    }
    for (name, template) in &config.templates {
        if !policy::identifier(name) {
            return Err(SecurityError::Invalid(
                "invalid ingest template name".into(),
            ));
        }
        policy::validate_template(template)?;
    }
    if config
        .department_actions
        .iter()
        .chain(&config.owner_actions)
        .any(|action| !action.is_data())
    {
        return Err(SecurityError::Invalid(
            "object permits cannot grant administrative actions".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_resource(
    record: &ResourceRecord,
    incarnation: uuid::Uuid,
    revision: u64,
) -> Result<()> {
    if record.key.collection != incarnation
        || !policy::identifier(&record.key.tenant)
        || record.key.id.is_empty()
        || record.key.id.len() > 1024
        || record.storage_id.is_nil()
        || !policy::identifier(&record.labels.owner)
        || !policy::identifier(&record.labels.department)
        || record.revision == 0
        || record.revision > revision
    {
        return Err(SecurityError::Invalid("invalid resource binding".into()));
    }
    if record.grants.len() > MAX_POLICY_GRANTS {
        return Err(SecurityError::BudgetExceeded);
    }
    if let Some(receipt) = &record.create_receipt {
        let ids: BTreeSet<_> = receipt.ids.iter().collect();
        if !identifier(&receipt.principal)
            || !identifier(&receipt.request_id)
            || receipt.request_digest == [0; 32]
            || receipt.ids.is_empty()
            || receipt.ids.len() > 1024
            || ids.len() != receipt.ids.len()
            || receipt.ids.first() != Some(&record.key.id)
            || receipt
                .ids
                .iter()
                .any(|id| uuid::Uuid::parse_str(id).is_err())
        {
            return Err(SecurityError::Invalid("invalid create receipt".into()));
        }
    }
    for grant in &record.grants {
        if grant.actions.is_empty() || grant.actions.iter().any(|action| !action.is_resource()) {
            return Err(SecurityError::Invalid(
                "invalid object grant actions".into(),
            ));
        }
        let valid_subject = match &grant.subject {
            Subject::Owner => true,
            Subject::Principal(id) | Subject::Group(id) | Subject::Department(id) => {
                policy::identifier(id)
            }
        };
        if !valid_subject {
            return Err(SecurityError::Invalid("invalid grant subject".into()));
        }
    }
    policy::validate_template(&IngestTemplate {
        department: record.labels.department.clone(),
        classification: record.labels.classification,
        properties: record.properties.clone(),
        representations: record.representations.clone(),
    })?;
    Ok(())
}

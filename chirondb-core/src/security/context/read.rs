//! Native reads pin authority once; callbacks never reacquire its resource lock.
use super::*;
use crate::relational::wal_decode::{MetadataCharge, Owned};
use parking_lot::RwLockReadGuard;

pub(crate) struct AuthorizedResources<'a> {
    resources: RwLockReadGuard<'a, ResourceIndex>,
    context: &'a AccessContext,
    _permit: AccessPermit,
}

/// Borrow lifetime ties the checked record to the reader's resource guard.
#[derive(Clone, Copy)]
pub(crate) struct AuthorizedRecord<'a> {
    record: &'a ResourceRecord,
    context: &'a AccessContext,
}

impl AccessContext {
    pub(crate) fn read_resources(&self) -> Result<AuthorizedResources<'_>> {
        let permit = self.publication_permit()?;
        Ok(AuthorizedResources {
            resources: self.snapshot.resources.read(),
            context: self,
            _permit: permit,
        })
    }
}

impl AuthorizedResources<'_> {
    pub(crate) fn create_receipt(&self, request: &str) -> crate::Result<Option<&CreateReceipt>> {
        self.context.publication_permit()?;
        let mut memory = MetadataCharge::default();
        let bytes = self
            .context
            .tenant()
            .len()
            .checked_add(self.context.principal_id().len())
            .and_then(|n| n.checked_add(request.len()))
            .and_then(|n| n.checked_add(512))
            .ok_or_else(|| {
                crate::GaussError::ResourceExhausted("receipt lookup memory is full".into())
            })?;
        memory.prepare(bytes as u64)?;
        let key = (
            self.context.tenant().to_owned(),
            self.context.principal_id().to_owned(),
            request.to_owned(),
        );
        let Some(record) = self.resources.create_requests.get(&key) else {
            return Ok(None);
        };
        Ok(Some(
            self.resources
                .records
                .get(record)
                .and_then(|record| record.create_receipt.as_ref())
                .ok_or(SecurityError::Unavailable)?,
        ))
    }
    fn checked<'a>(&'a self, record: &'a ResourceRecord) -> Result<AuthorizedRecord<'a>> {
        self.context.publication_permit()?;
        if record.key.tenant != self.context.tenant
            || record.key.collection != self.context.incarnation()
        {
            return Err(SecurityError::NotFound);
        }
        policy::authorize_resource(
            self.context.identity.principal(),
            self.context.identity.groups(),
            record,
            self.context.action,
            &self.context.snapshot.checkpoint.policy,
            &self.resources.records,
        )?;
        Ok(AuthorizedRecord {
            record,
            context: self.context,
        })
    }

    pub(crate) fn physical(&self, id: Uuid) -> Result<AuthorizedRecord<'_>> {
        let key = self
            .resources
            .physical
            .get(&id)
            .ok_or(SecurityError::NotFound)?;
        let record = self
            .resources
            .records
            .get(key)
            .ok_or(SecurityError::Unavailable)?;
        self.checked(record)
    }

    pub(crate) fn public(&self, id: &str) -> crate::Result<AuthorizedRecord<'_>> {
        self.context.publication_permit()?;
        // The temporary composite lookup key is admitted before copying strings.
        let mut memory = MetadataCharge::default();
        let bytes = id
            .len()
            .checked_add(self.context.tenant.len())
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| {
                crate::GaussError::ResourceExhausted("authority lookup memory is full".into())
            })?;
        memory.prepare(bytes as u64)?;
        let copy = |text: &str| -> crate::Result<String> {
            let mut value = String::new();
            value.try_reserve_exact(text.len()).map_err(|_| {
                crate::GaussError::ResourceExhausted("authority lookup memory is full".into())
            })?;
            value.push_str(text);
            Ok(value)
        };
        let key = PointKey {
            collection: self.context.incarnation(),
            tenant: copy(&self.context.tenant)?,
            id: copy(id)?,
        };
        let record = self
            .resources
            .records
            .get(&key)
            .ok_or(SecurityError::NotFound)?;
        Ok(self.checked(record)?)
    }

    pub(crate) fn for_each_authorized<'a>(
        &'a self,
        check: impl Fn() -> crate::Result<()>,
        mut visit: impl FnMut(AuthorizedRecord<'a>) -> crate::Result<()>,
    ) -> crate::Result<()> {
        check()?;
        let started = std::time::Instant::now();
        let mut count = 0usize;
        // Physical order preserves the legacy domain order without collecting it.
        for (index, key) in self.resources.physical.values().enumerate() {
            if index % 64 == 0 {
                check()?;
                self.context.publication_permit()?;
                if started.elapsed() >= std::time::Duration::from_secs(30) {
                    return Err(SecurityError::BudgetExceeded.into());
                }
            }
            let record = self
                .resources
                .records
                .get(key)
                .ok_or(SecurityError::Unavailable)?;
            match self.checked(record) {
                Ok(record) => {
                    if count >= 1_000_000 {
                        return Err(SecurityError::BudgetExceeded.into());
                    }
                    count += 1;
                    visit(record)?;
                }
                Err(SecurityError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.context.publication_permit()?;
        check()?;
        Ok(())
    }
}

impl<'record> AuthorizedRecord<'record> {
    pub(crate) fn id(&self) -> &'record str {
        &self.record.key.id
    }
    #[cfg(test)]
    pub(crate) fn storage_id(&self) -> Uuid {
        self.record.storage_id
    }
    pub(crate) fn storage_name<'a>(&self, buffer: &'a mut [u8; 36]) -> &'a str {
        self.record.storage_id.hyphenated().encode_lower(buffer)
    }
    pub(crate) fn query_field(&self, path: &str) -> Result<()> {
        self.context.publication_permit()?;
        if !matches!(self.context.action, Action::Read | Action::Search) {
            return Err(SecurityError::Forbidden);
        }
        if !policy::field_allowed(
            self.record,
            &self.context.identity.principal().attributes,
            path,
            PropertyAction::Query,
        ) {
            return Err(SecurityError::NotFound);
        }
        Ok(())
    }
    pub(crate) fn representation_visible(&self, name: &str) -> Result<bool> {
        self.context.publication_permit()?;
        if !matches!(
            self.context.action,
            Action::Read | Action::Search | Action::Export
        ) {
            return Err(SecurityError::Forbidden);
        }
        let Some(representation) = self.record.representations.get(name) else {
            return Ok(false);
        };
        Ok(
            self.context.identity.principal().attributes.clearance >= representation.classification
                && representation.source_fields.iter().all(|path| {
                    policy::field_allowed(
                        self.record,
                        &self.context.identity.principal().attributes,
                        path,
                        PropertyAction::Query,
                    )
                }),
        )
    }
    pub(crate) fn matches_filter(&self, filter: &SecurityFilter, payload: &Value) -> Result<bool> {
        self.context.publication_permit()?;
        if !matches!(
            self.context.action,
            Action::Read | Action::Search | Action::Delete | Action::GraphRead
        ) {
            return Err(SecurityError::Forbidden);
        }
        filter.matches(
            self.record,
            &self.context.identity.principal().attributes,
            payload,
        )
    }
    pub(crate) fn project(&self, payload: &Value) -> crate::Result<Owned<Value>> {
        self.context.publication_permit()?;
        if !matches!(
            self.context.action,
            Action::Read | Action::Search | Action::GraphRead
        ) {
            return Err(SecurityError::Forbidden.into());
        }
        super::super::projection::copy(
            self.record,
            &self.context.identity.principal().attributes,
            payload,
            PropertyAction::Read,
        )
    }
    pub(crate) fn project_point(
        &self,
        point: &crate::Point,
    ) -> crate::Result<super::super::point::ProjectedPoint> {
        super::super::point::copy(*self, point)
    }
}

#[cfg(test)]
mod tests;

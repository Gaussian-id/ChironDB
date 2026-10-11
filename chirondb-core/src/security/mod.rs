//! Trusted security authority and mandatory, bounded policy evaluation.
pub use chirondb_types::security::*;
mod capacity;
mod context;
pub(crate) use context::{CreateOptions, DataReferenceAuthorization};
mod filter;
pub use filter::SecurityFilter;
mod identity;
pub(crate) mod mutation;
pub(crate) mod output;
mod point;
mod policy;
mod projection;
pub(crate) use projection::Path as PropertyPath;
pub(crate) mod storage;
pub use context::{
    AccessContext, AccessPermit, AuthorizedOutput, CollectionAuthority, SecurityCheckpoint,
};
pub use identity::onboarding;
pub use identity::{
    AuthenticatedIdentity, IdentityAuthority, IdentityCancellation, IssuedCredential,
    IssuedSqlCredential, PublicationPermit, SqlVerifier,
};
pub use storage::{ProtectedBatch, ProtectedContent, SecurityDelta};
#[cfg(test)]
mod tests;

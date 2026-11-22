//! Cross-transport contract for the local tabular ML refresh scheduler.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlRefreshMode {
    #[default]
    Manual,
    Auto,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlRefreshAvailability {
    NotReady,
    Available,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlRefreshActivity {
    Idle,
    Debouncing,
    Queued,
    Running,
    RetryWait,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlRefreshFreshness {
    Fresh,
    Stale,
    InvalidSource,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlRefreshRevision {
    pub data: u64,
    pub schema: u64,
}

/// Idempotent policy assignment. Omitting the mode or adding tuning fields is invalid.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MlRefreshPolicyRequest {
    pub mode: MlRefreshMode,
}

/// Availability describes the last published generation, independently of an
/// ongoing refresh. Missing identity/revisions are unknown, never revision zero.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlRefreshStatus {
    pub view: String,
    pub mode: MlRefreshMode,
    pub availability: MlRefreshAvailability,
    pub activity: MlRefreshActivity,
    pub freshness: MlRefreshFreshness,
    pub source_table_id: Option<u64>,
    pub current_revision: Option<MlRefreshRevision>,
    pub published_revision: Option<MlRefreshRevision>,
    pub active_job_id: Option<String>,
    pub last_success_at_ms: Option<u64>,
    pub queue_age_ms: Option<u64>,
    pub retry_at_ms: Option<u64>,
    pub error_code: Option<String>,
    pub blocked_reason: Option<String>,
    pub refresh_version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_explicit_and_closed() {
        for invalid in [
            r#"{}"#,
            r#"{"mode":"AUTO"}"#,
            r#"{"mode":"auto","interval":1}"#,
        ] {
            assert!(serde_json::from_str::<MlRefreshPolicyRequest>(invalid).is_err());
        }
        let policy: MlRefreshPolicyRequest = serde_json::from_str(r#"{"mode":"auto"}"#).unwrap();
        assert_eq!(policy.mode, MlRefreshMode::Auto);
    }
}

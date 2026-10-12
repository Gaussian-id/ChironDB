//! Process-wide resource sizing for the single-node runtime.
//!
//! The profile is derived from host and cgroup limits. It intentionally has no
//! customer-facing tuning knobs: every subsystem sees the same effective CPU
//! and memory envelope and must reserve work within that envelope.

use std::sync::OnceLock;

#[cfg(target_os = "linux")]
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const MIN_OS_RESERVE_BYTES: u64 = 512 * MIB;
const MIN_SQL_POOL_BYTES: u64 = 64 * MIB;
const MAX_SQL_POOL_BYTES: u64 = 256 * MIB;
const MAX_SQL_REQUEST_BYTES: u64 = 64 * MIB;

static PROCESS_PROFILE: OnceLock<ResourceProfile> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceProfile {
    pub effective_memory_bytes: u64,
    pub os_reserve_bytes: u64,
    pub engine_budget_bytes: u64,
    pub sql_pool_bytes: u64,
    pub sql_request_working_set_bytes: u64,
    pub effective_cores: usize,
    pub query_workers: usize,
    pub background_workers: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessResourceUsage {
    pub rss_bytes: Option<u64>,
    pub pss_bytes: Option<u64>,
    pub cgroup_memory_bytes: Option<u64>,
    pub thread_count: Option<usize>,
}

impl ResourceProfile {
    pub fn detect(physical_cores: usize) -> Self {
        let host_memory = physical_memory_bytes();
        let cgroup_memory = cgroup_memory_limit();
        let effective_memory = match (host_memory, cgroup_memory) {
            (Some(host), Some(cgroup)) => host.min(cgroup),
            (Some(host), None) => host,
            (None, Some(cgroup)) => cgroup,
            // A conservative fallback keeps embedded users bounded even when
            // the platform cannot report physical memory.
            (None, None) => 2 * GIB,
        };
        let cgroup_cores = cgroup_cpu_limit();
        let effective_cores = cgroup_cores
            .map_or(physical_cores.max(1), |limit| {
                physical_cores.max(1).min(limit.max(1))
            })
            .max(1);
        Self::from_limits(effective_memory, effective_cores)
    }

    pub fn from_limits(effective_memory_bytes: u64, effective_cores: usize) -> Self {
        let effective_memory_bytes = effective_memory_bytes.max(1);
        let os_reserve_bytes = MIN_OS_RESERVE_BYTES
            .max(effective_memory_bytes / 4)
            .min(effective_memory_bytes);
        let after_reserve = effective_memory_bytes.saturating_sub(os_reserve_bytes);
        let engine_budget_bytes = (effective_memory_bytes.saturating_mul(70) / 100)
            .min(after_reserve)
            .max(1);
        let proportional_sql_pool = engine_budget_bytes / 8;
        let sql_pool_bytes = proportional_sql_pool
            .clamp(MIN_SQL_POOL_BYTES, MAX_SQL_POOL_BYTES)
            .min(engine_budget_bytes);
        let sql_request_working_set_bytes = (sql_pool_bytes / 4).clamp(1, MAX_SQL_REQUEST_BYTES);
        let effective_cores = effective_cores.max(1);

        Self {
            effective_memory_bytes,
            os_reserve_bytes,
            engine_budget_bytes,
            sql_pool_bytes,
            sql_request_working_set_bytes,
            effective_cores,
            query_workers: effective_cores,
            background_workers: effective_cores.div_ceil(2).clamp(1, 4),
        }
    }

    pub fn name(self) -> &'static str {
        if self.effective_memory_bytes <= 2 * GIB || self.effective_cores <= 2 {
            "lightweight"
        } else {
            "balanced"
        }
    }
}

/// Installs the profile before any lazy worker pool is initialized.
///
/// A second caller receives the already-installed profile, keeping embedded
/// and server users deterministic instead of resizing live pools.
pub fn install(profile: ResourceProfile) -> &'static ResourceProfile {
    let _ = PROCESS_PROFILE.set(profile);
    current()
}

pub fn current() -> &'static ResourceProfile {
    PROCESS_PROFILE.get_or_init(|| {
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        ResourceProfile::detect(cores)
    })
}

pub fn process_usage() -> ProcessResourceUsage {
    platform_process_usage()
}

#[cfg(target_os = "linux")]
fn platform_process_usage() -> ProcessResourceUsage {
    let rollup = fs::read_to_string("/proc/self/smaps_rollup").unwrap_or_default();
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    ProcessResourceUsage {
        rss_bytes: proc_kib_field(&rollup, "Rss:"),
        pss_bytes: proc_kib_field(&rollup, "Pss:"),
        cgroup_memory_bytes: cgroup_memory_usage_and_limit().map(|(used, _)| used),
        thread_count: proc_scalar_field(&status, "Threads:")
            .and_then(|value| value.try_into().ok()),
    }
}

#[cfg(target_os = "linux")]
fn proc_kib_field(contents: &str, name: &str) -> Option<u64> {
    proc_scalar_field(contents, name)?.checked_mul(1024)
}

#[cfg(target_os = "linux")]
fn proc_scalar_field(contents: &str, name: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let value = line.strip_prefix(name)?.trim_start();
        value.split_whitespace().next()?.parse().ok()
    })
}

#[cfg(target_os = "macos")]
#[allow(deprecated)] // libc exposes the stable Mach call without adding a macOS-only dependency.
fn platform_process_usage() -> ProcessResourceUsage {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info>::zeroed();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    // SAFETY: task_info writes at most `count` natural words into the correctly
    // sized Mach task structure for the current process.
    let status = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast::<libc::integer_t>(),
            &mut count,
        )
    };
    let rss_bytes = (status == libc::KERN_SUCCESS).then(|| {
        // SAFETY: a successful task_info call initialized the structure.
        unsafe { info.assume_init() }.resident_size
    });
    ProcessResourceUsage {
        rss_bytes,
        ..ProcessResourceUsage::default()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_process_usage() -> ProcessResourceUsage {
    ProcessResourceUsage::default()
}

#[cfg(unix)]
fn physical_memory_bytes() -> Option<u64> {
    // SAFETY: sysconf has no pointer arguments and is thread-safe. Negative
    // return values indicate that the queried value is unavailable.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    // SAFETY: same reasoning as above.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 || page_size <= 0 {
        return None;
    }
    u64::try_from(pages)
        .ok()?
        .checked_mul(u64::try_from(page_size).ok()?)
}

#[cfg(not(unix))]
fn physical_memory_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn cgroup_memory_limit() -> Option<u64> {
    let mut paths = cgroup_v2_paths("memory.max");
    paths.extend(cgroup_v1_paths(
        "memory",
        &["memory"],
        "memory.limit_in_bytes",
    ));
    paths
        .into_iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .filter_map(|raw| raw.trim().parse::<u64>().ok())
        .filter(|limit| *limit > 0 && *limit < (1_u64 << 60))
        .min()
}

#[cfg(target_os = "linux")]
pub(crate) fn cgroup_memory_usage_and_limit() -> Option<(u64, u64)> {
    let v2_usage = cgroup_v2_paths("memory.current");
    let v2_limits = cgroup_v2_paths("memory.max");
    if let Some(pair) = read_usage_limit_pair(v2_usage, v2_limits) {
        return Some(pair);
    }
    let v1_usage = cgroup_v1_paths("memory", &["memory"], "memory.usage_in_bytes");
    let v1_limits = cgroup_v1_paths("memory", &["memory"], "memory.limit_in_bytes");
    read_usage_limit_pair(v1_usage, v1_limits)
}

#[cfg(target_os = "linux")]
fn read_usage_limit_pair(
    usage_paths: Vec<PathBuf>,
    limit_paths: Vec<PathBuf>,
) -> Option<(u64, u64)> {
    usage_paths
        .into_iter()
        .zip(limit_paths)
        .find_map(|(usage_path, limit_path)| {
            let used = fs::read_to_string(usage_path)
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()?;
            let limit = fs::read_to_string(limit_path)
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()?;
            (limit > 0 && limit < (1_u64 << 60)).then_some((used, limit))
        })
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_limit() -> Option<u64> {
    None
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn cgroup_memory_usage_and_limit() -> Option<(u64, u64)> {
    None
}

#[cfg(target_os = "linux")]
fn cgroup_cpu_limit() -> Option<usize> {
    let quota = cgroup_v2_paths("cpu.max")
        .into_iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .find_map(|raw| parse_cpu_max(&raw))
        .or_else(|| {
            let quota_paths = cgroup_v1_paths("cpu", &["cpu", "cpu,cpuacct"], "cpu.cfs_quota_us");
            let period_paths = cgroup_v1_paths("cpu", &["cpu", "cpu,cpuacct"], "cpu.cfs_period_us");
            quota_paths
                .into_iter()
                .zip(period_paths)
                .find_map(|(quota_path, period_path)| {
                    let quota = fs::read_to_string(quota_path)
                        .ok()?
                        .trim()
                        .parse::<u64>()
                        .ok()?;
                    let period = fs::read_to_string(period_path)
                        .ok()?
                        .trim()
                        .parse::<u64>()
                        .ok()?;
                    quota_to_cores(quota, period)
                })
        });
    let mut cpuset_paths = cgroup_v2_paths("cpuset.cpus.effective");
    cpuset_paths.extend(cgroup_v1_paths("cpuset", &["cpuset"], "cpuset.cpus"));
    let cpuset = cpuset_paths
        .into_iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .filter_map(|raw| parse_cpuset(&raw))
        .min();
    match (quota, cpuset) {
        (Some(quota), Some(cpuset)) => Some(quota.min(cpuset)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg(target_os = "linux")]
fn cgroup_v2_paths(file: &str) -> Vec<PathBuf> {
    let mut paths = cgroup_member_path(None)
        .and_then(|member| safe_cgroup_join(Path::new("/sys/fs/cgroup"), &member, file))
        .into_iter()
        .collect::<Vec<_>>();
    paths.push(PathBuf::from("/sys/fs/cgroup").join(file));
    paths.dedup();
    paths
}

#[cfg(target_os = "linux")]
fn cgroup_v1_paths(controller: &str, mounts: &[&str], file: &str) -> Vec<PathBuf> {
    let member = cgroup_member_path(Some(controller));
    let mut paths = Vec::new();
    for mount in mounts {
        let base = PathBuf::from("/sys/fs/cgroup").join(mount);
        if let Some(member) = member.as_deref()
            && let Some(path) = safe_cgroup_join(&base, member, file)
        {
            paths.push(path);
        }
        paths.push(base.join(file));
    }
    paths.dedup();
    paths
}

#[cfg(target_os = "linux")]
fn cgroup_member_path(controller: Option<&str>) -> Option<String> {
    let membership = fs::read_to_string("/proc/self/cgroup").ok()?;
    parse_cgroup_member_path(&membership, controller)
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_member_path(membership: &str, controller: Option<&str>) -> Option<String> {
    membership.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let member = fields.next()?;
        let matches = match controller {
            None => controllers.is_empty(),
            Some(controller) => controllers.split(',').any(|name| name == controller),
        };
        matches.then(|| member.to_string())
    })
}

#[cfg(target_os = "linux")]
fn safe_cgroup_join(base: &Path, member: &str, file: &str) -> Option<PathBuf> {
    let mut path = base.to_path_buf();
    for component in Path::new(member).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => path.push(value),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    path.push(file);
    Some(path)
}

#[cfg(not(target_os = "linux"))]
fn cgroup_cpu_limit() -> Option<usize> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_cpu_max(raw: &str) -> Option<usize> {
    let mut fields = raw.split_whitespace();
    let quota = fields.next()?;
    if quota == "max" {
        return None;
    }
    quota_to_cores(quota.parse().ok()?, fields.next()?.parse().ok()?)
}

#[cfg(any(target_os = "linux", test))]
fn quota_to_cores(quota: u64, period: u64) -> Option<usize> {
    if quota == 0 || period == 0 {
        return None;
    }
    usize::try_from(quota.div_ceil(period))
        .ok()
        .map(|v| v.max(1))
}

#[cfg(any(target_os = "linux", test))]
fn parse_cpuset(raw: &str) -> Option<usize> {
    let mut total = 0_usize;
    for part in raw.trim().split(',').filter(|part| !part.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let start = start.parse::<usize>().ok()?;
            let end = end.parse::<usize>().ok()?;
            total = total.checked_add(end.checked_sub(start)?.checked_add(1)?)?;
        } else {
            part.parse::<usize>().ok()?;
            total = total.checked_add(1)?;
        }
    }
    (total > 0).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_gib_profile_preserves_os_and_bounds_sql() {
        let profile = ResourceProfile::from_limits(2 * GIB, 2);
        assert_eq!(profile.os_reserve_bytes, 512 * MIB);
        assert_eq!(profile.engine_budget_bytes, 1_503_238_553);
        assert_eq!(profile.sql_pool_bytes, 187_904_819);
        assert_eq!(profile.sql_request_working_set_bytes, 46_976_204);
        assert_eq!(profile.query_workers, 2);
        assert_eq!(profile.background_workers, 1);
        assert_eq!(profile.name(), "lightweight");
    }

    #[test]
    fn larger_profile_caps_sql_pool() {
        let profile = ResourceProfile::from_limits(8 * GIB, 8);
        assert_eq!(profile.os_reserve_bytes, 2 * GIB);
        assert_eq!(profile.engine_budget_bytes, 6_012_954_214);
        assert_eq!(profile.sql_pool_bytes, 256 * MIB);
        assert_eq!(profile.sql_request_working_set_bytes, 64 * MIB);
        assert_eq!(profile.background_workers, 4);
        assert_eq!(profile.name(), "balanced");
    }

    #[test]
    fn parses_cpu_and_cpuset_limits() {
        assert_eq!(parse_cpu_max("200000 100000"), Some(2));
        assert_eq!(parse_cpu_max("150000 100000"), Some(2));
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert_eq!(parse_cpuset("0-1,4,6-7"), Some(5));
        assert_eq!(parse_cpuset(""), None);
        let membership = "12:memory:/docker/example\n11:cpu,cpuacct:/docker/example\n0::/system.slice/chirondb.service\n";
        assert_eq!(
            parse_cgroup_member_path(membership, None).as_deref(),
            Some("/system.slice/chirondb.service")
        );
        assert_eq!(
            parse_cgroup_member_path(membership, Some("memory")).as_deref(),
            Some("/docker/example")
        );
        assert_eq!(
            parse_cgroup_member_path(membership, Some("cpu")).as_deref(),
            Some("/docker/example")
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn process_usage_reports_resident_memory() {
        assert!(process_usage().rss_bytes.is_some_and(|bytes| bytes > 0));
    }
}

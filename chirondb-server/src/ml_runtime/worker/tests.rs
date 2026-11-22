use super::*;
use serde_json::json;
use std::fs;
#[cfg(unix)]
use std::{path::Path, sync::Arc};
use tempfile::TempDir;

fn python() -> PathBuf {
    for executable in ["python3", "python"] {
        if let Ok(output) = Command::new(executable)
            .args(["-I", "-c", "import sys; print(sys.executable)"])
            .output()
            && output.status.success()
        {
            return PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
        }
    }
    panic!("worker lifecycle tests require a Python interpreter");
}

fn config(directory: &TempDir, script: &str) -> WorkerConfig {
    let path = directory.path().join("worker.py");
    fs::write(&path, script).unwrap();
    WorkerConfig {
        python: python(),
        script: path,
    }
}

#[test]
fn custom_worker_protocol_and_cleared_environment_are_preserved() {
    let directory = TempDir::new().unwrap();
    // A sibling import verifies that isolation applies to the embedded
    // supervisor without breaking the existing custom script import path.
    fs::write(directory.path().join("helper.py"), "VALUE = 42\n").unwrap();
    let config = config(
        &directory,
        r#"
import helper, json, os, sys
request = json.load(sys.stdin)
print(json.dumps({"ok": True, "result": {"request": request, "value": helper.VALUE, "environment": list(os.environ)}}))
"#,
    );
    let request = json!({"features":["value"],"training_rows":[{"value":1.5}],"note":"雪"});
    let result = run(&config, &request, &AtomicBool::new(false)).unwrap();
    assert_eq!(result["request"], request);
    assert_eq!(result["value"], 42);
    for key in result["environment"].as_array().unwrap() {
        // Darwin's Python/CoreFoundation startup can create this encoding
        // metadata even when Command::env_clear supplied an empty environment.
        // It is not inherited server configuration or a credential.
        #[cfg(target_os = "macos")]
        if key == "__CF_USER_TEXT_ENCODING" {
            continue;
        }
        assert!(
            matches!(
                key.as_str().unwrap(),
                "PYTHONNOUSERSITE" | "LC_CTYPE" | "SystemRoot"
            ),
            "{key}"
        );
    }
}

#[test]
fn worker_failures_have_structured_retry_classes() {
    let directory = TempDir::new().unwrap();
    for (script, kind) in [
        ("import os; os._exit(17)", WorkerFailureKind::Crashed),
        ("print('not-json')", WorkerFailureKind::InvalidResponse),
        ("print('null')", WorkerFailureKind::InvalidResponse),
        ("print('{\"ok\":true}')", WorkerFailureKind::InvalidResponse),
        (
            "print('{\"ok\":false,\"error\":\"legacy failure\"}')",
            WorkerFailureKind::Crashed,
        ),
        (
            "print('{\"ok\":false,\"error_code\":\"chironql.ml_unavailable\"}')",
            WorkerFailureKind::Unavailable,
        ),
        (
            "print('{\"ok\":false,\"error_code\":\"chironql.ml_invalid_rows\"}')",
            WorkerFailureKind::InvalidInput,
        ),
        (
            "print('{\"ok\":false,\"error_code\":\"chironql.ml_worker_resource\"}')",
            WorkerFailureKind::Resource,
        ),
    ] {
        let config = config(&directory, script);
        let error = run(&config, &json!({}), &AtomicBool::new(false)).unwrap_err();
        assert_eq!(error.kind, kind, "{script}");
        assert_eq!(
            error.is_transient(),
            matches!(
                kind,
                WorkerFailureKind::Crashed | WorkerFailureKind::Resource
            )
        );
        assert!(error.code().starts_with("chironql.ml_"));
    }
}

#[test]
fn worker_byte_limits_are_hard_failures_and_do_not_wait_for_timeout() {
    let directory = TempDir::new().unwrap();
    for stream in ["stdout", "stderr"] {
        let size = if stream == "stdout" {
            MAX_OUTPUT
        } else {
            MAX_ERROR
        } + 1;
        let config = config(
            &directory,
            &format!(
                "import sys,time\nsys.{stream}.buffer.write(b'x'*{size})\nsys.{stream}.buffer.flush()\ntime.sleep(60)\n"
            ),
        );
        let error = run_with_timeout(
            &config,
            &json!({}),
            &AtomicBool::new(false),
            Duration::from_secs(3),
        )
        .unwrap_err();
        assert_eq!(error.kind, WorkerFailureKind::OutputLimit, "{stream}");
        assert!(!error.is_transient());
    }
    let config = config(&directory, "raise Exception('must not start')");
    let error = run(
        &config,
        &json!({"large":"x".repeat(MAX_INPUT)}),
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert_eq!(error.kind, WorkerFailureKind::InvalidInput);
}

#[cfg(unix)]
const SLEEPING_WORKER: &str = r#"
import json, os, sys, time
from pathlib import Path
request = json.load(sys.stdin)
Path(request["pid_file"]).write_text(json.dumps({"worker":os.getpid(),"supervisor":os.getppid()}))
time.sleep(60)
"#;

#[cfg(unix)]
fn wait_pids(path: &Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(raw) = fs::read(path)
            && let Ok(value) = serde_json::from_slice(&raw)
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "worker did not publish its PID fixture"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn running(pid: u64) -> bool {
    #[cfg(target_os = "linux")]
    {
        // The test cannot reap an orphaned grandchild supervisor. Docker PID1
        // may retain its exited zombie; assert no running orphan separately
        // from the worker itself, which its supervisor explicitly reaps.
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let state = stat.rsplit_once(')').unwrap().1.trim_start().chars().next();
        !matches!(state, Some('Z' | 'X'))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    }
}

#[cfg(unix)]
fn assert_stopped(pids: &Value) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while pids
        .as_object()
        .unwrap()
        .values()
        .any(|pid| running(pid.as_u64().unwrap()))
    {
        assert!(
            Instant::now() < deadline,
            "owned worker/supervisor still running: {pids}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    #[cfg(target_os = "linux")]
    if let Some(worker) = pids["worker"].as_u64() {
        assert!(
            !Path::new(&format!("/proc/{worker}")).exists(),
            "worker was not reaped"
        );
    }
}

#[test]
#[cfg(unix)]
fn setup_error_reaps_supervisor_before_request_delivery() {
    let directory = TempDir::new().unwrap();
    let config = config(&directory, "raise RuntimeError('worker must not start')");
    let mut pid = 0;
    let failed_setup = (|| -> Result<()> {
        let owner = OwnedSupervisor {
            child: spawn(&config, TIMEOUT)?,
            input: None,
            liveness: None,
        };
        pid = owner.child.id();
        // Model an error during thread setup, while stdin is still held by
        // Child. The ownership guard must close it and reap before returning.
        Err(WorkerFailure::new(
            WorkerFailureKind::Resource,
            "injected setup failure",
        ))
    })();
    assert_eq!(failed_setup.unwrap_err().kind, WorkerFailureKind::Resource);
    assert_stopped(&json!({"supervisor": pid}));
    #[cfg(target_os = "linux")]
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[test]
#[cfg(unix)]
fn worker_timeout_and_shutdown_reap_the_owned_child() {
    let directory = TempDir::new().unwrap();
    let config = config(&directory, SLEEPING_WORKER);
    let pid_file = directory.path().join("timeout.json");
    let request = json!({"pid_file":pid_file});
    let error = run_with_timeout(
        &config,
        &request,
        &AtomicBool::new(false),
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(error.kind, WorkerFailureKind::Timeout);
    assert!(error.is_transient());
    assert_stopped(&wait_pids(&pid_file));

    let pid_file = directory.path().join("cancel.json");
    let request = json!({"pid_file":pid_file});
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&cancelled);
    let handle = thread::spawn(move || run(&config, &request, &worker_stop));
    let pids = wait_pids(&pid_file);
    cancelled.store(true, Ordering::Release);
    let error = handle.join().unwrap().unwrap_err();
    assert_eq!(error.kind, WorkerFailureKind::Cancelled);
    assert_stopped(&pids);
}

#[test]
#[cfg(unix)]
fn killed_parent_cleans_worker_and_partial_request_supervisor() {
    const CHILD: &str = "CHIRON_TEST_WORKER_PARENT";
    if let Some(mode) = env::var_os(CHILD) {
        let config = WorkerConfig {
            python: env::var_os("CHIRON_TEST_WORKER_PYTHON").unwrap().into(),
            script: env::var_os("CHIRON_TEST_WORKER_SCRIPT").unwrap().into(),
        };
        let pid_file: PathBuf = env::var_os("CHIRON_TEST_WORKER_PID_FILE").unwrap().into();
        if mode == "partial" || mode == "empty" {
            // Guard ordinary fixture error/panic paths too. The intentional
            // SIGKILL bypasses Drop and exercises the parent-liveness pipe.
            let mut supervisor = OwnedSupervisor {
                child: spawn(&config, TIMEOUT).unwrap(),
                input: None,
                liveness: None,
            };
            let mut pipe = supervisor.child.stdin.take().unwrap();
            if mode == "partial" {
                pipe.write_all(&(MAX_INPUT as u64).to_le_bytes()).unwrap();
                pipe.write_all(b"{").unwrap();
            }
            fs::write(
                pid_file,
                json!({"supervisor":supervisor.child.id()}).to_string(),
            )
            .unwrap();
            loop {
                thread::park();
            }
        }
        run(
            &config,
            &json!({"pid_file":pid_file}),
            &AtomicBool::new(false),
        )
        .unwrap();
        panic!("parent should have been SIGKILLed before worker completes");
    }
    let directory = TempDir::new().unwrap();
    let config = config(&directory, SLEEPING_WORKER);
    for mode in ["running", "partial", "empty"] {
        let pid_file = directory.path().join(format!("{mode}.json"));
        let parent = Command::new(env::current_exe().unwrap())
            .args(["--exact", "ml_runtime::worker::tests::killed_parent_cleans_worker_and_partial_request_supervisor", "--nocapture"])
            .env(CHILD, mode).env("CHIRON_TEST_WORKER_PYTHON", &config.python)
            .env("CHIRON_TEST_WORKER_SCRIPT", &config.script)
            .env("CHIRON_TEST_WORKER_PID_FILE", &pid_file)
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        // A failed fixture assertion must also stop the owned test parent.
        let mut parent = OwnedSupervisor {
            child: parent,
            input: None,
            liveness: None,
        };
        let pids = wait_pids(&pid_file);
        parent.child.kill().unwrap(); // Child::kill sends SIGKILL on Unix.
        let status = parent.child.wait().unwrap();
        assert!(!status.success());
        assert_stopped(&pids);
    }
}

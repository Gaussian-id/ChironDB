//! Portable lifetime ownership for one optional local ML worker.
//!
//! The embedded Python supervisor retains the worker's ordinary JSON protocol.
//! Its stdin is also a parent-liveness pipe: EOF cancels and reaps the worker,
//! including when the server is SIGKILLed before or during request delivery.
use std::{
    env,
    io::{self, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::Value;

const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_ERROR: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(300);
const CLEANUP_GRACE: Duration = Duration::from_secs(5);
const SUPERVISOR: &str = include_str!("worker_supervisor.py");

#[derive(Clone)]
pub(super) struct WorkerConfig {
    pub(super) python: PathBuf,
    pub(super) script: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkerFailureKind {
    Unavailable,
    InvalidInput,
    InvalidResponse,
    OutputLimit,
    Timeout,
    Crashed,
    Io,
    Resource,
    Cancelled,
}

#[derive(Debug)]
pub(super) struct WorkerFailure {
    pub(super) kind: WorkerFailureKind,
    pub(super) message: String,
}

impl WorkerFailure {
    fn new(kind: WorkerFailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(super) fn code(&self) -> &'static str {
        match self.kind {
            WorkerFailureKind::Unavailable => "chironql.ml_unavailable",
            WorkerFailureKind::InvalidInput => "chironql.ml_invalid_rows",
            WorkerFailureKind::InvalidResponse => "chironql.ml_worker_protocol",
            WorkerFailureKind::OutputLimit => "chironql.ml_worker_output_limit",
            WorkerFailureKind::Timeout => "chironql.ml_worker_timeout",
            WorkerFailureKind::Crashed => "chironql.ml_worker_failed",
            WorkerFailureKind::Io => "chironql.ml_worker_io",
            WorkerFailureKind::Resource => "chironql.ml_worker_resource",
            WorkerFailureKind::Cancelled => "chironql.ml_worker_interrupted",
        }
    }

    pub(super) fn is_transient(&self) -> bool {
        matches!(
            self.kind,
            WorkerFailureKind::Timeout
                | WorkerFailureKind::Crashed
                | WorkerFailureKind::Io
                | WorkerFailureKind::Resource
                | WorkerFailureKind::Cancelled
        )
    }
}

type Result<T> = std::result::Result<T, WorkerFailure>;

fn spawn(config: &WorkerConfig, timeout: Duration) -> Result<Child> {
    if !config.python.is_file() || !config.script.is_file() {
        return Err(WorkerFailure::new(
            WorkerFailureKind::Unavailable,
            "configured ML worker executable or script does not exist",
        ));
    }
    let mut command = Command::new(&config.python);
    command
        .arg("-I")
        .arg("-u")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg(&config.script)
        .arg(timeout.as_secs_f64().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PYTHONNOUSERSITE", "1");
    if let Some(system_root) = env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    command.spawn().map_err(|error| {
        let kind = match error.kind() {
            io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput => WorkerFailureKind::Unavailable,
            io::ErrorKind::OutOfMemory => WorkerFailureKind::Resource,
            _ => WorkerFailureKind::Io,
        };
        WorkerFailure::new(kind, "configured ML worker supervisor could not start")
    })
}

struct OwnedSupervisor {
    child: Child,
    input: Option<JoinHandle<io::Result<ChildStdin>>>,
    liveness: Option<ChildStdin>,
}

impl Drop for OwnedSupervisor {
    fn drop(&mut self) {
        // Also close stdin if setup failed before transferring it to a writer.
        drop(self.child.stdin.take());
        // If request delivery is still blocked, dropping its JoinHandle makes
        // the returned stdin close as soon as writing finishes. The supervisor
        // never spawns a worker before the complete request has been read.
        drop(self.input.take());
        drop(self.liveness.take());
        let deadline = Instant::now() + CLEANUP_GRACE;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return;
                }
            }
        }
    }
}

fn read_output(
    stream: impl Read + Send + 'static,
    limit: usize,
) -> Result<JoinHandle<io::Result<Vec<u8>>>> {
    thread::Builder::new()
        .spawn(move || {
            let mut output = Vec::new();
            stream.take(limit as u64 + 1).read_to_end(&mut output)?;
            Ok(output)
        })
        .map_err(|_| {
            WorkerFailure::new(
                WorkerFailureKind::Resource,
                "worker stream reader could not start",
            )
        })
}

fn join_output(handle: JoinHandle<io::Result<Vec<u8>>>) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| WorkerFailure::new(WorkerFailureKind::Io, "worker stream reader panicked"))?
        .map_err(|_| WorkerFailure::new(WorkerFailureKind::Io, "worker stream could not be read"))
}

pub(super) fn run(config: &WorkerConfig, request: &Value, cancelled: &AtomicBool) -> Result<Value> {
    run_with_timeout(config, request, cancelled, TIMEOUT)
}

fn run_with_timeout(
    config: &WorkerConfig,
    request: &Value,
    cancelled: &AtomicBool,
    timeout: Duration,
) -> Result<Value> {
    if cancelled.load(Ordering::Acquire) {
        return Err(WorkerFailure::new(
            WorkerFailureKind::Cancelled,
            "ML worker interrupted by shutdown",
        ));
    }
    let input = serde_json::to_vec(request).map_err(|_| {
        WorkerFailure::new(
            WorkerFailureKind::InvalidInput,
            "worker request could not be serialized",
        )
    })?;
    if input.len() > MAX_INPUT {
        return Err(WorkerFailure::new(
            WorkerFailureKind::InvalidInput,
            "worker request exceeds 8 MiB",
        ));
    }
    // Own/reap the process before any fallible helper-thread setup. In
    // particular, thread exhaustion must return a typed error, not leave a
    // supervisor zombie in a still-running server.
    let mut owner = OwnedSupervisor {
        child: spawn(config, timeout)?,
        input: None,
        liveness: None,
    };
    let mut stdin = owner.child.stdin.take().expect("piped supervisor stdin");
    let stdout = read_output(
        owner.child.stdout.take().expect("piped supervisor stdout"),
        MAX_OUTPUT,
    )?;
    let stderr = read_output(
        owner.child.stderr.take().expect("piped supervisor stderr"),
        MAX_ERROR,
    )?;
    owner.input = Some(
        thread::Builder::new()
            .spawn(move || {
                stdin.write_all(&(input.len() as u64).to_le_bytes())?;
                stdin.write_all(&input)?;
                Ok(stdin) // Retain the pipe until the parent consumes the result.
            })
            .map_err(|_| {
                WorkerFailure::new(
                    WorkerFailureKind::Resource,
                    "worker request writer could not start",
                )
            })?,
    );
    let started = Instant::now();
    let mut input_failed = false;
    let status = loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(WorkerFailure::new(
                WorkerFailureKind::Cancelled,
                "ML worker interrupted by shutdown",
            ));
        }
        if owner.input.as_ref().is_some_and(JoinHandle::is_finished) {
            match owner.input.take().expect("finished input writer").join() {
                Ok(Ok(pipe)) => owner.liveness = Some(pipe),
                _ => input_failed = true,
            }
        }
        match owner.child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout + CLEANUP_GRACE => {
                thread::sleep(Duration::from_millis(20))
            }
            Ok(None) => {
                return Err(WorkerFailure::new(
                    WorkerFailureKind::Timeout,
                    "ML worker exceeded its deadline",
                ));
            }
            Err(_) => {
                return Err(WorkerFailure::new(
                    WorkerFailureKind::Io,
                    "ML worker status could not be read",
                ));
            }
        }
    };
    let output = join_output(stdout)?;
    let errors = join_output(stderr)?;
    if output.len() > MAX_OUTPUT || errors.len() > MAX_ERROR {
        return Err(WorkerFailure::new(
            WorkerFailureKind::OutputLimit,
            "worker output exceeded its size limit",
        ));
    }
    let message: Value = serde_json::from_slice(&output).map_err(|_| {
        WorkerFailure::new(
            if status.success() {
                WorkerFailureKind::InvalidResponse
            } else {
                WorkerFailureKind::Crashed
            },
            "worker did not return a valid JSON response",
        )
    })?;
    if !message.is_object() || !message["ok"].is_boolean() {
        return Err(WorkerFailure::new(
            WorkerFailureKind::InvalidResponse,
            "worker returned an invalid response envelope",
        ));
    }
    if !status.success() || message["ok"] != true {
        let kind = match message["error_code"].as_str() {
            Some("chironql.ml_unavailable") => WorkerFailureKind::Unavailable,
            Some("chironql.ml_invalid_rows" | "chironql.ml_model") => {
                WorkerFailureKind::InvalidInput
            }
            Some("chironql.ml_worker_protocol") => WorkerFailureKind::InvalidResponse,
            Some("chironql.ml_worker_output_limit") => WorkerFailureKind::OutputLimit,
            Some("chironql.ml_worker_timeout") => WorkerFailureKind::Timeout,
            Some("chironql.ml_worker_io") => WorkerFailureKind::Io,
            Some("chironql.ml_worker_resource") => WorkerFailureKind::Resource,
            _ => WorkerFailureKind::Crashed,
        };
        return Err(WorkerFailure::new(
            kind,
            message["error"]
                .as_str()
                .unwrap_or("worker exited without a result")
                .chars()
                .take(2048)
                .collect::<String>(),
        ));
    }
    if input_failed || message.get("result").is_none() {
        return Err(WorkerFailure::new(
            WorkerFailureKind::InvalidResponse,
            "worker returned an incomplete response",
        ));
    }
    Ok(message["result"].clone())
}

#[cfg(test)]
mod tests;

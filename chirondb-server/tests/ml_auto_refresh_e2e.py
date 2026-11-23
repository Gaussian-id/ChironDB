#!/usr/bin/env python3
"""Real-daemon scheduler qualification with a controlled stdlib worker.

Run with --server /absolute/path/chirondb --output /new/evidence/directory.
The fixture worker is deliberately deterministic: this qualifies orchestration,
not estimator quality. No production flags, credentials or scheduler knobs are
added. Databases, logs, HTTP receipts and exact worker requests are retained.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

WORKER = r'''
import json, os, sys, time, uuid
from pathlib import Path
root = Path(__file__).resolve().parent
request = json.load(sys.stdin)
label = request["features"][0].removeprefix("x_")
control_path = root / (label + ".control.json")
control = json.loads(control_path.read_text()) if control_path.exists() else {}
run = str(uuid.uuid4())
def event(kind):
    data = {"kind":kind,"label":label,"run":run,"pid":os.getpid(),"time":time.time()}
    with (root / "events.jsonl").open("a") as stream:
        stream.write(json.dumps(data) + "\n"); stream.flush(); os.fsync(stream.fileno())
(root / (run + ".request.json")).write_text(json.dumps(request))
event("start")
if control.get("mode") in ("hold", "hold_permanent"):
    while not (root / (label + ".release")).exists(): time.sleep(.025)
if control.get("mode") == "fail_once":
    marker = root / (label + ".failed_once")
    if not marker.exists():
        marker.write_text(run)
        event("finish")
        print(json.dumps({"ok":False,"error_code":"chironql.ml_worker_resource","error":"fixture transient resource failure"}))
        sys.exit(1)
if control.get("mode") in ("permanent", "hold_permanent"):
    event("finish")
    print(json.dumps({"ok":False,"error_code":"chironql.ml_invalid_rows","error":"fixture invalid training input"}))
    sys.exit(1)
rows=request["prediction_rows"]
result={"predictions":[float(row[request["features"][0]]) for row in rows],
        "confidence":[None]*len(rows),"training_rows":len(request["training_rows"]),
        "prediction_rows":len(rows),"context_rows":len(request["training_rows"])}
event("finish")
print(json.dumps({"ok":True,"result":result}))
'''


def eventually(check, description, timeout=35):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = check()
        if last:
            return last
        time.sleep(.05)
    raise AssertionError(f"timed out: {description}; last={last!r}")


def pid_running(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True  # A zombie still exists: the supervisor must actually reap it.


class Daemon:
    def __init__(self, binary, output):
        self.binary, self.output = binary, output
        self.worker = output / "worker"
        self.worker.mkdir()
        (self.worker / "worker.py").write_text(WORKER)
        self.process = None
        self.starts = 0
        self.log = None
        self.receipts = (output / "http.jsonl").open("a")
        self.checks = []

    def start(self):
        ports = []
        sockets = [socket.socket() for _ in range(3)]
        try:
            for sock in sockets:
                sock.bind(("127.0.0.1", 0))
                ports.append(sock.getsockname()[1])
        finally:
            for sock in sockets:
                sock.close()
        self.base = f"http://127.0.0.1:{ports[0]}"
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CHIRON", "GAUSS"))}
        env.update(CHIRONDB_ML_WORKER_PYTHON=sys.executable, CHIRONDB_ML_WORKER_SCRIPT=str(self.worker / "worker.py"))
        command = [str(self.binary), "--data-dir", str(self.output / "database")]
        for name, port in zip(("http", "grpc", "wire"), ports):
            command += [f"--listen-{name}", f"127.0.0.1:{port}"]
        self.starts += 1
        self.log = (self.output / f"server-{self.starts}.log").open("w")
        self.process = subprocess.Popen(command, env=env, stdout=self.log, stderr=self.log)
        def ready():
            assert self.process.poll() is None, f"server exited; inspect server-{self.starts}.log"
            try:
                return self.request("GET", "/health")
            except (OSError, urllib.error.URLError):
                return False
        eventually(ready, "server readiness", 90)

    def stop(self, kill=False):
        if self.process and self.process.poll() is None:
            self.process.kill() if kill else self.process.terminate()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                raise AssertionError("graceful shutdown exceeded 20 seconds")
        if self.log:
            self.log.close()
            self.log = None

    def request(self, method, path, body=None, expected=200):
        payload = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=payload, method=method, headers={"Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                code, data = response.status, json.load(response)
        except urllib.error.HTTPError as error:
            code, data = error.code, json.loads(error.read())
        self.receipts.write(json.dumps({"time":time.time(),"method":method,"path":path,"body":body,"status":code,"response":data}) + "\n")
        self.receipts.flush()
        assert code == expected, (method, path, expected, code, data)
        return data

    def sql(self, text):
        result = self.request("POST", "/v1/sql", {"statements":[{"sql":text,"parameters":[]}]})
        assert result.get("committed", True), result
        return result

    def source(self, label):
        self.sql(f"CREATE TABLE source_{label} (id INTEGER PRIMARY KEY, x_{label} DOUBLE PRECISION, y DOUBLE PRECISION)")
        self.sql(f"INSERT INTO source_{label} VALUES (1, 1.0, 2.0), (2, 2.0, 4.0), (3, 3.0, NULL)")

    def submit(self, label):
        result = self.request("POST", "/v1/chironql", {"query":f"ML MATERIALIZE result_{label} FROM source_{label} TARGET y FEATURES (x_{label}) TASK REGRESSION USING DECISION_TREE;"})
        return result["rows"][0]["job_id"]

    def status(self, label):
        return self.request("GET", f"/v1/ml/views/result_{label}/refresh-status")

    def policy(self, label, mode):
        return self.request("PUT", f"/v1/ml/views/result_{label}/refresh-policy", {"mode":mode})

    def job(self, job):
        return self.request("GET", f"/v1/ml/jobs/{job}")

    def page(self, label):
        return self.request("GET", f"/v1/ml/views/result_{label}?limit=1")

    def wait_version(self, label, version, timeout=35):
        def check():
            status = self.status(label)
            assert status["refresh_version"] <= version, (label, version, status)
            return status if status["refresh_version"] == version and status["activity"] == "idle" else False
        return eventually(check, f"{label} generation {version}", timeout)

    def wait_activity(self, label, activity):
        return eventually(lambda: (status if (status := self.status(label))["activity"] == activity else False), f"{label} {activity}")

    def control(self, label, mode):
        (self.worker / f"{label}.release").unlink(missing_ok=True)
        temporary = self.worker / f"{label}.control.tmp"
        temporary.write_text(json.dumps({"mode":mode}))
        temporary.replace(self.worker / f"{label}.control.json")

    def release(self, label):
        self.control(label, "pass")
        (self.worker / f"{label}.release").touch()

    def events(self, label=None, kind="start"):
        path = self.worker / "events.jsonl"
        if not path.exists():
            return []
        events = [json.loads(line) for line in path.read_text().splitlines()]
        return [event for event in events if (label is None or event["label"] == label) and (kind is None or event["kind"] == kind)]

    def quiet(self, label, version, seconds=6.2):
        started, deadline = len(self.events(label)), time.monotonic() + seconds
        while time.monotonic() < deadline:
            assert self.status(label)["refresh_version"] == version
            assert len(self.events(label)) == started, f"unexpected {label} worker"
            time.sleep(.15)

    def passed(self, name, **evidence):
        self.checks.append({"check":name, **evidence})
        print(json.dumps(self.checks[-1]), flush=True)



def qualify_permanent_newer_revision(d):
    label = "delta"
    d.source(label)
    d.submit(label)
    d.wait_version(label, 1)
    d.policy(label, "auto")

    def observed_pending(revision):
        rows = d.sql("SELECT state FROM __chiron_ml_schedule WHERE name = 'result_delta'")["results"][0]["rows"]
        state = json.loads(rows[0][0]["value"])
        return state if state["claim"] and state["pending"] and state["desired"]["data_revision"] == revision["data"] else False

    d.control(label, "hold_permanent")
    d.sql("UPDATE source_delta SET x_delta = 4.0 WHERE id = 3")
    active = d.wait_activity(label, "running")
    eventually(lambda: len(d.events(label)) == 2, "permanent old-snapshot worker started")
    d.sql("UPDATE source_delta SET x_delta = 5.0 WHERE id = 3")
    latest = d.status(label)["current_revision"]
    pending = eventually(lambda: observed_pending(latest), "newer revision durably pending before old failure")
    d.release(label)  # Old worker retains hold_permanent; next worker sees pass.
    caught_up = d.wait_version(label, 2)
    failed = d.job(active["active_job_id"])
    assert failed["status"] == "failed" and failed["error"].startswith("chironql.ml_invalid_rows:")
    assert failed["source_revision"] != latest
    assert caught_up["published_revision"] == latest and caught_up["freshness"] == "fresh"
    assert len(d.events(label)) == 3
    request = json.loads((d.worker / (d.events(label)[-1]["run"] + ".request.json")).read_text())
    assert request["prediction_rows"][-1]["x_delta"] == 5.0

    # With no newer revision, a permanent failure must stay blocked.
    d.control(label, "permanent")
    d.sql("UPDATE source_delta SET x_delta = 6.0 WHERE id = 3")
    blocked = d.wait_activity(label, "blocked")
    assert blocked["refresh_version"] == 2 and blocked["retry_at_ms"] is None
    d.quiet(label, 2)

    # Disabling AUTO cancels even an already-observed newer pending intent.
    d.policy(label, "manual")
    d.control(label, "pass")
    d.submit(label)
    d.wait_version(label, 3)
    d.policy(label, "auto")
    d.control(label, "hold_permanent")
    d.sql("UPDATE source_delta SET x_delta = 7.0 WHERE id = 3")
    disabled = d.wait_activity(label, "running")
    eventually(lambda: len(d.events(label)) == 6, "worker running before AUTO disable")
    d.sql("UPDATE source_delta SET x_delta = 8.0 WHERE id = 3")
    newest = d.status(label)["current_revision"]
    eventually(lambda: observed_pending(newest), "pending intent before AUTO disable")
    d.policy(label, "manual")
    d.release(label)
    eventually(lambda: d.job(disabled["active_job_id"])["status"] == "failed", "disabled old attempt failed")
    d.quiet(label, 3)
    final = d.status(label)
    assert final["mode"] == "manual" and final["activity"] == "blocked" and final["freshness"] == "stale"
    assert final["availability"] == "available" and len(d.events(label)) == 6
    d.passed("permanent_old_snapshot_failure_preserves_newer_intent_and_negative_guards", pending_revision=pending["desired"], published_revision=caught_up["published_revision"])


def qualify(d):
    d.start()
    d.source("alpha")
    job = d.submit("alpha")
    initial = d.wait_version("alpha", 1)
    assert d.job(job)["source_revision"] == initial["published_revision"]
    assert initial["mode"] == "manual" and initial["freshness"] == "fresh"
    d.policy("alpha", "auto")
    d.sql("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
    d.sql("INSERT INTO unrelated VALUES (1)")
    d.sql("UPDATE source_alpha SET y = 2.0 WHERE id = 1")
    d.sql("UPDATE source_alpha SET y = 9.0 WHERE id = 99")
    d.sql("DELETE FROM source_alpha WHERE id = 99")
    d.quiet("alpha", 1)
    unchanged = d.status("alpha")
    assert unchanged["current_revision"] == initial["current_revision"]
    d.passed("no_op_and_unrelated_commits_do_not_refresh")

    d.sql("ALTER TABLE source_alpha ADD COLUMN note TEXT")
    schema = d.wait_version("alpha", 2)
    assert schema["published_revision"]["schema"] > initial["published_revision"]["schema"]
    old_page = d.page("alpha")
    assert old_page["next"] is not None
    for value in [3, 4, 5]:
        d.sql(f"UPDATE source_alpha SET x_alpha = {value}.0 WHERE id = 3")
    d.wait_activity("alpha", "debouncing")
    d.quiet("alpha", 2, seconds=2)
    d.wait_version("alpha", 3)
    d.request("GET", "/v1/ml/views/result_alpha?limit=1&cursor=" + urllib.parse.quote(old_page["next"], safe=""), expected=409)
    d.passed("schema_refresh_burst_debounce_and_stale_cursor")

    d.source("beta")
    d.control("alpha", "hold")
    d.sql("UPDATE source_alpha SET x_alpha = 6.0 WHERE id = 3")
    running = d.wait_activity("alpha", "running")
    eventually(lambda: len(d.events("alpha")) == 4, "held worker started")
    held = d.events("alpha")[-1]
    beta_job = d.submit("beta")
    queued = d.job(beta_job)
    assert queued["status"] == "queued" and queued["source_version"] is None and queued["source_revision"] is None
    assert queued["requested_revision"] is not None
    d.sql("UPDATE source_beta SET x_beta = 8.0 WHERE id = 3")
    d.sql("UPDATE source_alpha SET x_alpha = 7.0 WHERE id = 3")
    d.sql("UPDATE source_alpha SET x_alpha = 9.0 WHERE id = 3")
    d.request("DELETE", "/v1/ml/views/result_alpha", expected=409)
    d.release("alpha")
    beta = d.wait_version("beta", 1)
    alpha = d.wait_version("alpha", 5)
    assert alpha["freshness"] == "fresh" and beta["freshness"] == "fresh"
    beta_done = d.job(beta_job)
    assert beta_done["requested_revision"] == queued["requested_revision"]
    assert beta_done["source_revision"] != queued["requested_revision"]
    order = [event["label"] for event in d.events() if event["time"] >= held["time"]]
    assert order == ["alpha", "beta", "alpha"], order
    request = json.loads((d.worker / (d.events("beta")[-1]["run"] + ".request.json")).read_text())
    assert request["prediction_rows"][-1]["x_beta"] == 8.0
    d.quiet("alpha", 5)
    d.passed("shared_manual_auto_queue_snapshot_at_dispatch_and_one_followup", order=order, active_job=running["active_job_id"])

    d.sql("UPDATE source_alpha SET x_alpha = 10.0 WHERE id = 3")
    d.policy("alpha", "manual")
    d.quiet("alpha", 5)
    assert d.status("alpha")["freshness"] == "stale"
    d.control("alpha", "hold")
    d.policy("alpha", "auto")
    d.wait_activity("alpha", "running")
    eventually(lambda: len(d.events("alpha")) == 6, "disabled active worker started")
    d.policy("alpha", "manual")
    d.sql("UPDATE source_alpha SET x_alpha = 11.0 WHERE id = 3")
    d.release("alpha")
    d.wait_version("alpha", 6)
    d.quiet("alpha", 6)
    assert d.status("alpha")["freshness"] == "stale"
    d.request("DELETE", "/v1/ml/views/result_alpha")
    d.request("GET", "/v1/ml/views/result_alpha/refresh-status", expected=404)
    d.request("GET", "/v1/ml/views/result_alpha", expected=404)
    d.passed("disable_pending_and_running_then_drop_idle")

    d.policy("beta", "auto")
    d.control("beta", "fail_once")
    previous = d.page("beta")
    d.sql("UPDATE source_beta SET x_beta = 9.0 WHERE id = 3")
    failed = d.wait_activity("beta", "retry_wait")
    assert failed["availability"] == "available" and failed["freshness"] == "stale"
    assert failed["refresh_version"] == 1 and failed["retry_at_ms"] is not None
    assert d.page("beta") == previous
    d.wait_version("beta", 2)
    attempts = d.events("beta")[-2:]
    assert attempts[1]["time"] - attempts[0]["time"] >= 4.8
    d.control("beta", "permanent")
    previous = d.page("beta")
    d.sql("UPDATE source_beta SET x_beta = 10.0 WHERE id = 3")
    blocked = d.wait_activity("beta", "blocked")
    assert blocked["error_code"] == "chironql.ml_invalid_rows"
    assert blocked["refresh_version"] == 2 and d.page("beta") == previous
    d.quiet("beta", 2)
    d.control("beta", "pass")
    assert d.policy("beta", "auto")["activity"] == "blocked"
    resumed = d.submit("beta")  # Explicit retry; idempotent policy PUT does not reset failure state.
    d.wait_version("beta", 3)
    assert d.job(resumed)["status"] == "succeeded"
    d.passed("transient_backoff_permanent_block_and_preserved_generation")

    # No status poll after this commit: startup must discover the durable delta.
    d.sql("UPDATE source_beta SET x_beta = 11.0 WHERE id = 3")
    d.stop(kill=True)
    before = len(d.events("beta"))
    d.start()
    eventually(lambda: len(d.events("beta")) > before, "startup automatically discovers committed source change")
    d.wait_version("beta", 4)
    d.passed("restart_detects_committed_source_change_without_status_trigger")

    d.control("beta", "hold")
    d.sql("UPDATE source_beta SET x_beta = 12.0 WHERE id = 3")
    active = d.wait_activity("beta", "running")
    eventually(lambda: len(d.events("beta")) == before + 2, "worker to reap started")
    child = d.events("beta")[-1]
    d.source("gamma")
    gamma_job = d.submit("gamma")
    assert d.job(gamma_job)["source_version"] is None
    d.stop(kill=True)
    eventually(lambda: not pid_running(child["pid"]), "worker stops after parent SIGKILL", 10)
    d.release("beta")
    d.start()
    assert d.job(active["active_job_id"])["status"] == "failed"
    d.wait_version("gamma", 1)
    d.wait_version("beta", 5)
    assert d.job(gamma_job)["status"] == "succeeded"
    d.passed("sigkill_reaps_child_and_recovers_running_and_queued_jobs", pid=child["pid"])

    d.policy("gamma", "auto")
    previous = d.page("gamma")
    d.sql("ALTER TABLE source_gamma DROP COLUMN x_gamma")
    invalid = d.wait_activity("gamma", "blocked")
    assert invalid["freshness"] == "invalid_source" and invalid["current_revision"] is None
    assert d.page("gamma") == previous
    d.sql("DROP TABLE source_gamma")
    d.source("gamma")
    d.quiet("gamma", 1)
    assert d.status("gamma")["freshness"] == "invalid_source"
    assert d.page("gamma") == previous
    d.passed("schema_and_drop_recreate_invalid_source_preserve_old_generation")

    qualify_permanent_newer_revision(d)

    # Verify no two fixture workers overlapped, excluding the killed child's
    # missing finish event, whose death was explicitly observed before restart.
    active_runs = set()
    for event in d.events(kind=None):
        if event["run"] == child["run"]:
            continue
        if event["kind"] == "start":
            assert not active_runs, (event, active_runs)
            active_runs.add(event["run"])
        else:
            active_runs.remove(event["run"])
    assert not active_runs
    version = d.status("beta")["refresh_version"]
    d.stop()
    d.start()
    assert d.status("beta")["mode"] == "auto"
    assert d.status("beta")["refresh_version"] == version
    d.quiet("beta", version)
    d.passed("one_worker_limit_and_graceful_restart_preserve_fresh_policy")


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary, output = args.server.resolve(), args.output.resolve()
    if not binary.is_file():
        parser.error("--server must be an existing binary")
    output.mkdir(parents=True, exist_ok=False)
    daemon = Daemon(binary, output)
    started = time.time()
    result = {"kind":"controlled-worker-daemon-qualification", "server":str(binary),
              "server_sha256":file_hash(binary),
              "python":sys.version,"started_at":started,"passed":False}
    try:
        qualify(daemon)
        result["passed"] = True
    finally:
        try:
            daemon.stop()
        finally:
            daemon.receipts.close()
            result.update(checks=daemon.checks, duration_seconds=time.time()-started,
                          worker_starts=len(daemon.events()), server_starts=daemon.starts)
            (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

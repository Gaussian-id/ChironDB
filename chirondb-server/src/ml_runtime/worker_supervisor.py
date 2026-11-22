"""Embedded, stdlib-only owner of one trusted ML subprocess.

stdin is an internal length-prefixed request followed by a parent-liveness pipe.
The configured worker still receives only its original JSON request and EOF.
"""
import errno
import json
import os
import signal
import subprocess
import sys
import threading
import time

MAX_INPUT = 8 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024
MAX_ERROR = 64 * 1024


def failure(code, message):
    sys.stdout.write(json.dumps({"ok": False, "error_code": code, "error": message}))
    sys.stdout.flush()
    return 1


def main():
    script, seconds = sys.argv[1:]
    seconds = float(seconds)
    if not 0 < seconds <= 300:
        return failure("chironql.ml_worker_protocol", "invalid supervisor deadline")
    deadline = time.monotonic() + seconds
    ready = threading.Event()
    parent_gone = threading.Event()
    state = {}

    def read_exact(length):
        value = bytearray()
        while len(value) < length:
            chunk = os.read(0, min(length - len(value), 65536))
            if not chunk:
                parent_gone.set()
                return None
            value.extend(chunk)
        return value

    def read_request_and_watch_parent():
        try:
            header = read_exact(8)
            if header is None:
                return
            length = int.from_bytes(header, "little")
            if length > MAX_INPUT:
                state["input_error"] = True
                return
            request = read_exact(length)
            if request is None:
                return
            state["request"] = request
            ready.set()
            # Unbuffered os.read avoids a daemon BufferedReader lock at Python
            # shutdown. No other process inherits this descriptor.
            if not os.read(0, 1):
                parent_gone.set()
            else:
                state["input_error"] = True
                parent_gone.set()
        except MemoryError:
            state["input_resource"] = True
        except OSError:
            parent_gone.set()
        finally:
            ready.set()

    threading.Thread(target=read_request_and_watch_parent, daemon=True).start()
    while not ready.wait(0.02):
        if time.monotonic() >= deadline:
            return failure("chironql.ml_worker_timeout", "ML worker exceeded its deadline")
    if parent_gone.is_set():
        return 0
    if state.get("input_resource"):
        return failure("chironql.ml_worker_resource", "worker supervision ran out of memory")
    if state.get("input_error") or "request" not in state:
        return failure("chironql.ml_invalid_rows", "worker request exceeds 8 MiB")
    try:
        child = subprocess.Popen(
            [sys.executable, script], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, bufsize=0,
            start_new_session=(os.name == "posix"),
        )
    except OSError as error:
        code = "chironql.ml_unavailable" if error.errno in (
            errno.ENOENT, errno.EACCES, errno.ENOEXEC,
        ) else "chironql.ml_worker_io"
        return failure(code, "configured ML worker could not start")

    try:
        return supervise(child, state.pop("request"), parent_gone, deadline)
    except MemoryError:
        return failure("chironql.ml_worker_resource", "worker supervision ran out of memory")
    except (OSError, RuntimeError):
        return failure("chironql.ml_worker_io", "worker supervision failed")
    finally:
        # Also cover thread-creation/setup failures after Popen succeeds.
        if child.poll() is None:
            stop_owned(child)


def stop_owned(child):
    try:
        if os.name == "posix":
            os.killpg(child.pid, signal.SIGKILL)
        elif child.poll() is None:
            child.kill()
    except ProcessLookupError:
        pass
    child.wait()


def supervise(child, request, parent_gone, deadline):
    overflow = threading.Event()
    io_failure = threading.Event()
    resource_failure = threading.Event()
    output_done, error_done, input_done = (threading.Event() for _ in range(3))
    output, errors = bytearray(), bytearray()

    def read_bounded(stream, result, limit, done):
        try:
            while True:
                chunk = stream.read(min(65536, limit + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > limit:
                    overflow.set()
                    break
        except MemoryError:
            resource_failure.set()
        except OSError:
            io_failure.set()
        finally:
            try:
                stream.close()
            finally:
                done.set()

    def send_request(request):
        try:
            view = memoryview(request)
            while view:
                count = child.stdin.write(view)
                if not count:
                    raise OSError("worker stdin closed")
                view = view[count:]
        except MemoryError:
            resource_failure.set()
        except (BrokenPipeError, OSError):
            # A worker can reject a request and exit before consuming all input.
            # Its exit status/structured response remains authoritative.
            pass
        finally:
            try:
                child.stdin.close()
            finally:
                input_done.set()

    threads = [
        threading.Thread(target=read_bounded, args=(child.stdout, output, MAX_OUTPUT, output_done), daemon=True),
        threading.Thread(target=read_bounded, args=(child.stderr, errors, MAX_ERROR, error_done), daemon=True),
        threading.Thread(target=send_request, args=(request,), daemon=True),
    ]
    for thread in threads:
        thread.start()

    reason = None
    try:
        while True:
            if parent_gone.is_set():
                reason = "parent"
                break
            if resource_failure.is_set():
                reason = "resource"
                break
            if overflow.is_set():
                reason = "limit"
                break
            if io_failure.is_set():
                reason = "io"
                break
            if time.monotonic() >= deadline:
                reason = "timeout"
                break
            status = child.poll()
            if status is not None and output_done.is_set() and error_done.is_set() and input_done.is_set():
                break
            time.sleep(0.02)
    finally:
        if reason is not None or child.returncode is None:
            # The worker owns a fresh session. Never signal the server's group
            # or search for processes by executable name.
            stop_owned(child)
        else:
            child.wait()  # Reap only this supervisor's worker.
        for thread in threads:
            thread.join(timeout=1)

    if reason == "parent":
        return 0
    if reason == "resource":
        return failure("chironql.ml_worker_resource", "worker supervision ran out of memory")
    if reason == "limit":
        return failure("chironql.ml_worker_output_limit", "worker output exceeded its size limit")
    if reason == "timeout":
        return failure("chironql.ml_worker_timeout", "ML worker exceeded its deadline")
    if reason == "io":
        return failure("chironql.ml_worker_io", "worker stream could not be read")
    # Forward the original response without JSON wrapping or base64 expansion.
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return 0 if child.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

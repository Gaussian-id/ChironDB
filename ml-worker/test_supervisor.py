"""Fault injection for supervisor resource failures, without allocating to OOM."""
import importlib.util
import io
import json
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import Mock, patch

source = Path(__file__).resolve().parents[1] / "chirondb-server/src/ml_runtime/worker_supervisor.py"
spec = importlib.util.spec_from_file_location("chiron_test_supervisor", source)
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


class SupervisorTests(unittest.TestCase):
    def test_input_memory_failure_is_structured_before_worker_spawn(self):
        output = io.StringIO()
        with patch.object(supervisor.sys, "argv", ["supervisor", "worker.py", "300"]), patch.object(
            supervisor.sys, "stdout", output
        ), patch.object(supervisor.os, "read", side_effect=[(1).to_bytes(8, "little"), MemoryError()]), patch.object(
            supervisor.subprocess, "Popen"
        ) as spawn:
            self.assertEqual(supervisor.main(), 1)
        spawn.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["error_code"], "chironql.ml_worker_resource")

    def test_output_memory_failure_stops_and_reaps_owned_worker(self):
        child = Mock()
        child.stdout.read.side_effect = MemoryError()
        child.stderr.read.return_value = b""
        child.stdin.write.side_effect = len
        child.poll.return_value = None
        child.returncode = None
        output = io.StringIO()
        def stopped(owned):
            self.assertIs(owned, child)
            child.returncode = -9
        with patch.object(supervisor, "stop_owned", side_effect=stopped) as stop, patch.object(
            supervisor.sys, "stdout", output
        ):
            self.assertEqual(supervisor.supervise(child, b"{}", threading.Event(), time.monotonic() + 10), 1)
        stop.assert_called_once_with(child)
        self.assertEqual(json.loads(output.getvalue())["error_code"], "chironql.ml_worker_resource")


if __name__ == "__main__":
    unittest.main()

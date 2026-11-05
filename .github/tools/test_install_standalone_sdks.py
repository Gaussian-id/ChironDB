"""Check fetch credential isolation and cleanup without network access."""
from contextlib import redirect_stdout
from io import StringIO
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("install_standalone_sdks.py")

class CredentialIsolation(unittest.TestCase):
    def run_installer(self, fail_fetch=False, token=True):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            environment = {"RUNNER_TEMP": temporary}
            if token:
                environment["SDK_REPOS_READ_TOKEN"] = "dummy-test-credential"
            def run(command, **kwargs):
                env = kwargs["env"]
                calls.append((command, dict(env)))
                if command[:2] == ["git", "clone"]:
                    Path(command[-1]).mkdir()
                if command[:2] == ["git", "fetch"] and fail_fetch:
                    raise subprocess.CalledProcessError(1, command)
                if "build" in command and command[1:3] == ["-m", "build"]:
                    dist = Path(kwargs["cwd"]) / "dist"
                    dist.mkdir()
                    (dist / "chirondb_client-0.1.0b2-py3-none-any.whl").touch()
                return subprocess.CompletedProcess(command, 0)
            with patch.dict(os.environ, environment, clear=True), patch("subprocess.run", side_effect=run), redirect_stdout(StringIO()):
                if fail_fetch:
                    with self.assertRaises(subprocess.CalledProcessError):
                        runpy.run_path(str(SCRIPT))
                elif not token:
                    with self.assertRaises(SystemExit):
                        runpy.run_path(str(SCRIPT))
                else:
                    runpy.run_path(str(SCRIPT))
            self.assertFalse(list(Path(temporary).rglob("git-credential-sdk")))
        return calls

    def test_read_credential_is_only_available_to_git_and_cargo_fetch(self):
        calls = self.run_installer()
        self.assertEqual(len(calls), 14)
        for command, env in calls:
            fetch = command[0] in ("git", "cargo")
            self.assertEqual("SDK_REPOS_READ_TOKEN" in env, fetch)
            if fetch:
                self.assertEqual(env["GIT_CONFIG_VALUE_0"], "")
                self.assertEqual(env["GIT_CONFIG_COUNT"], "2")
                self.assertEqual(env["CARGO_NET_GIT_FETCH_WITH_CLI"], "true")
            else:
                self.assertFalse(any(k.startswith("GIT_CONFIG_") for k in env))
            self.assertNotIn("dummy-test-credential", " ".join(command))

    def test_fetch_failure_removes_credential_helper(self):
        self.run_installer(fail_fetch=True)

    def test_missing_token_leaves_no_helper(self):
        self.assertEqual(self.run_installer(token=False), [])

if __name__ == "__main__":
    unittest.main()

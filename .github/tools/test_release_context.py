#!/usr/bin/env python3
"""Exercise release source selection against real temporary Git history."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from release_context import resolve


class ReleaseContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.previous = Path.cwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, self.previous)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.name", "Release fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        manifest = Path("chirondb-server/Cargo.toml")
        manifest.parent.mkdir()
        manifest.write_text('[package]\nversion = "0.1.0-beta.3"\n')
        self.git("add", str(manifest))
        self.git("commit", "--quiet", "-m", "fixture")
        self.source = self.git("rev-parse", "HEAD")
        self.git("tag", "-a", "v0.1.0-beta.3", "-m", "fixture")
        self.git("commit", "--allow-empty", "--quiet", "-m", "workflow repair")
        self.workflow = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.workflow)

    def git(self, *args):
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()

    def context(self, tag="v0.1.0-beta.3", ref="refs/heads/main"):
        return resolve("workflow_dispatch", ref, self.workflow, tag, "main")

    def test_retry_pins_annotated_tag_not_workflow_commit(self):
        context = self.context()
        self.assertEqual(context["source_sha"], self.source)
        self.assertNotEqual(context["source_sha"], self.workflow)
        self.assertEqual(context["publish"], "true")
        self.assertEqual(context["version"], "0.1.0-beta.3")

    def test_empty_dispatch_remains_qualification_only(self):
        context = self.context(tag="", ref="refs/heads/candidate")
        self.assertEqual(context["publish"], "false")
        self.assertEqual(context["source_sha"], self.workflow)

    def test_push_uses_tag_source(self):
        context = resolve("push", "refs/tags/v0.1.0-beta.3", self.source, "", "main")
        self.assertEqual(context, self.context())

    def test_retry_rejects_nondefault_workflow(self):
        with self.assertRaisesRegex(ValueError, "default-branch"):
            self.context(ref="refs/heads/candidate")

    def test_retry_rejects_branch_sha_and_injection(self):
        for tag in ["main", self.source, "v0.1.0-beta.3\npublish=true", "--help"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.context(tag=tag)

    def test_missing_tag_cannot_create_a_release(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.context(tag="v0.1.0-beta.4")

    def test_version_mismatch_rejects(self):
        self.git("tag", "v0.2.0", self.source)
        with self.assertRaisesRegex(ValueError, "package version"):
            self.context(tag="v0.2.0")

    def test_unmerged_source_rejects(self):
        self.git("checkout", "--quiet", "-b", "unmerged")
        self.git("commit", "--allow-empty", "--quiet", "-m", "unmerged source")
        self.git("tag", "v0.1.0-beta.3-rc.1")
        with self.assertRaises(subprocess.CalledProcessError):
            self.context(tag="v0.1.0-beta.3-rc.1")

    def test_moved_push_tag_rejects(self):
        with self.assertRaisesRegex(ValueError, "moved"):
            resolve("push", "refs/tags/v0.1.0-beta.3", self.workflow, "", "main")

    def test_other_events_cannot_publish(self):
        with self.assertRaises(ValueError):
            resolve("pull_request", "refs/pull/1/merge", self.workflow, "", "main")


if __name__ == "__main__":
    unittest.main()

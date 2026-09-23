# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import os
import subprocess
import tempfile
import unittest

from sentari import prreview
from sentari.runner import resolve_tool


def _git(d, *a):
    subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)


@unittest.skipIf(resolve_tool("git") is None, "git not installed")
class TestChangedFiles(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        _git(self.d, "init", "-q")
        _git(self.d, "config", "user.email", "t@t")
        _git(self.d, "config", "user.name", "t")
        with open(os.path.join(self.d, "a.py"), "w") as f:
            f.write("x = 1\n")
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "base")
        self.base = subprocess.run(["git", "-C", self.d, "rev-parse", "HEAD"],
                                   capture_output=True, text=True).stdout.strip()
        # change one code file and add a non-code file
        with open(os.path.join(self.d, "a.py"), "w") as f:
            f.write("import os\nos.system('echo hi')\n")
        with open(os.path.join(self.d, "notes.txt"), "w") as f:
            f.write("not code\n")
        _git(self.d, "add", "-A")
        _git(self.d, "commit", "-qm", "change")

    def test_changed_files_only_code(self):
        files, err = prreview.changed_files(self.d, self.base, "HEAD")
        self.assertIsNone(err)
        self.assertIn("a.py", files)
        self.assertNotIn("notes.txt", files)  # non-code filtered out


class TestCommentBody(unittest.TestCase):
    def test_clean_review(self):
        r = prreview.PRReview("repo", "main", "HEAD", changed=["a.py"], findings=[])
        body = prreview.comment_body(r)
        self.assertIn("No new SAST findings", body)

    def test_findings_table_sorted(self):
        r = prreview.PRReview("repo", "main", "HEAD", changed=["a.py"], findings=[
            {"check_id": "low-rule", "severity": "low", "path": "a.py", "line": 2,
             "message": "m", "cwe": [], "owasp": []},
            {"check_id": "cmdi", "severity": "high", "path": "a.py", "line": 5,
             "message": "m", "cwe": ["CWE-78"], "owasp": []},
        ])
        body = prreview.comment_body(r)
        self.assertIn("Sentari PR security review", body)
        self.assertIn("`cmdi`", body)
        # high sorts above low
        self.assertLess(body.index("cmdi"), body.index("low-rule"))

    def test_error_review(self):
        r = prreview.PRReview("repo", "main", "HEAD", error="semgrep not installed")
        self.assertIn("could not complete", prreview.comment_body(r))


if __name__ == "__main__":
    unittest.main()

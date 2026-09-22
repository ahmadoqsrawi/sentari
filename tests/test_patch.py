import subprocess
import tempfile
import unittest
from pathlib import Path

from sentari import patch
from sentari.models import Evidence, Finding, PhaseResult, Severity

_DIFF = ('--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n def login(u, p):\n'
         '-    q = "SELECT * FROM users WHERE u=" + u\n'
         '+    q = "SELECT * FROM users WHERE u=%s"\n     return db.run(q)\n')


class _Stub:
    def __init__(self, reply):
        self.reply = reply

    def complete(self, system, user, max_tokens=1200):
        return self.reply


class TestPatch(unittest.TestCase):
    def _repo(self):
        d = tempfile.mkdtemp()
        repo = Path(d)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
        (repo / "app.py").write_text(
            'def login(u, p):\n    q = "SELECT * FROM users WHERE u=" + u\n    return db.run(q)\n')
        subprocess.run(["git", "-C", str(repo), "add", "app.py"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], check=True)
        return repo

    def _finding(self, location="app.py:2"):
        r = PhaseResult(phase="sast", started_at="t", ended_at="t")
        r.evidence.append(Evidence(id="e1", command=["semgrep"], returncode=0, stdout="",
                                   stderr="", started_at="t", ended_at="t",
                                   duration_sec=0.1, tool="semgrep"))
        r.findings.append(Finding(title="SQLi", severity=Severity.HIGH, description="concat",
                                  evidence_ids=["e1"], target="x", phase="sast",
                                  location=location, recommendation="parameterize"))
        return r

    def test_validates_good_and_bad(self):
        repo = self._repo()
        self.assertTrue(patch.validates(_DIFF, repo))
        self.assertFalse(patch.validates("not a diff", repo))

    def test_location_traversal_guard(self):
        repo = self._repo()
        f, _ = patch._location_file("../../etc/passwd:1", repo)
        self.assertIsNone(f)
        f, line = patch._location_file("app.py:2", repo)
        self.assertIsNotNone(f)
        self.assertEqual(line, 2)

    def test_propose_and_apply(self):
        repo = self._repo()
        patches = patch.propose([self._finding()], str(repo), _Stub(_DIFF))
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["file"], "app.py")
        applied, failed = patch.apply(patches, str(repo))
        self.assertEqual(applied, ["app.py"])
        self.assertEqual(failed, [])
        self.assertIn("%s", (repo / "app.py").read_text())

    def test_propose_handles_code_fences(self):
        repo = self._repo()
        patches = patch.propose([self._finding()], str(repo), _Stub("```diff\n" + _DIFF + "```"))
        self.assertEqual(len(patches), 1)

    def test_propose_skips_findings_without_source(self):
        repo = self._repo()
        patches = patch.propose([self._finding(location="https://x/y")], str(repo), _Stub(_DIFF))
        self.assertEqual(patches, [])

    def test_propose_skips_invalid_diff(self):
        repo = self._repo()
        patches = patch.propose([self._finding()], str(repo), _Stub("garbage not a diff"))
        self.assertEqual(patches, [])

    def test_combined_patch_has_headers(self):
        out = patch.combined_patch([{"finding": "SQLi", "file": "app.py", "diff": _DIFF}])
        self.assertIn("# Fix: SQLi (app.py)", out)

    def test_apply_confirm_constant(self):
        self.assertEqual(patch.APPLY_CONFIRM, "APPLY THESE PATCHES TO MY WORKING TREE")


if __name__ == "__main__":
    unittest.main()

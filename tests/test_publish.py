"""Exercise publishing leases against a real local bare remote."""

from pathlib import Path
import subprocess
import tempfile
import unittest


PUSH_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "push-with-lease.sh"


class TestPublishingLease(unittest.TestCase):
    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd, check=True,
                              capture_output=True, text=True).stdout.strip()

    def test_rewrite_succeeds_then_concurrent_code_commit_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "remote.git"
            work = root / "work"
            self.git("init", "--bare", str(remote))
            self.git("init", str(work))
            self.git("config", "user.name", "Test", cwd=work)
            self.git("config", "user.email", "test@example.com", cwd=work)
            self.git("checkout", "-b", "main", cwd=work)
            self.git("commit", "--allow-empty", "-m", "base", cwd=work)
            self.git("remote", "add", "origin", str(remote), cwd=work)
            self.git("push", "origin", "HEAD:main", cwd=work)
            expected = self.git("rev-parse", "HEAD", cwd=work)
            self.git("commit", "--amend", "--allow-empty", "-m", "new data", cwd=work)
            subprocess.run(["bash", str(PUSH_SCRIPT), "origin", "main", expected],
                           cwd=work, check=True, capture_output=True)
            expected = self.git("rev-parse", "HEAD", cwd=work)
            self.git("commit", "--allow-empty", "-m", "concurrent code", cwd=work)
            concurrent = self.git("rev-parse", "HEAD", cwd=work)
            self.git("push", "origin", "HEAD:main", cwd=work)
            self.git("checkout", "--detach", expected, cwd=work)
            self.git("commit", "--amend", "--allow-empty", "-m", "stale build", cwd=work)
            result = subprocess.run(["bash", str(PUSH_SCRIPT), "origin", "main", expected],
                                    cwd=work, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            actual = self.git("--git-dir", str(remote), "rev-parse", "refs/heads/main")
            self.assertEqual(actual, concurrent)

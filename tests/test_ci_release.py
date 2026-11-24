from copy import deepcopy
from io import BytesIO
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import zipfile

from support import VaultTest
from healdan.core import Blocked, atomic, canonical, decode, digest, git, run
from scripts import audit_publication, ci_evidence as ci

ROOT = Path(__file__).resolve().parent.parent


class EvidenceFixture:
    run_id = 40
    attempt = 2
    head = "5" * 40
    workflow_id = 80
    wheel = "healdan-1.0.0.dev1-py3-none-any.whl"
    wheel_body = b"synthetic wheel bytes already verified by the installed-build test"
    index = {"all": ["tests.fixture.Core.test_one"], "macos": ["tests.fixture.Native.test_probe"]}

    def __init__(self):
        self.build = SimpleNamespace(manifest={"wheel": self.wheel},
                                     identity={"version": "1.0.0.dev1", "sha256": digest(self.wheel_body)})
        self.path = f"{ci.REPO}/actions/runs/{self.run_id}"
        self.attempt_path = f"{self.path}/attempts/{self.attempt}"
        self.run = {"id": self.run_id, "run_attempt": self.attempt, "workflow_id": self.workflow_id,
                    "name": ci.WORKFLOW, "path": ci.WORKFLOW_PATH, "status": "completed", "conclusion": "success",
                    "head_sha": self.head, "head_branch": "main", "event": "push",
                    "repository": {"id": ci.REPOSITORY_ID, "full_name": ci.REPOSITORY},
                    "head_repository": {"id": ci.REPOSITORY_ID}, "html_url": "https://example.invalid/run"}
        required = {**ci.SETUP_STEPS, **{"test-" + profile: ci.PROFILE_STEPS for profile in ci.PROFILES}}
        self.jobs = [{"name": name, "run_id": self.run_id, "run_attempt": self.attempt, "head_sha": self.head,
                      "status": "completed", "conclusion": "success",
                      "steps": [{"name": step, "status": "completed", "conclusion": "success"} for step in sorted(steps)]}
                     for name, steps in required.items()]
        self.artifacts = {}
        self.archives = {}
        self.add(ci.wheel_name(self.attempt), 19, self.wheel, self.wheel_body)
        self.results = {}
        for number, (profile, system) in enumerate(ci.PROFILES.items(), 20):
            tools = ["python", "git", "ssh", "ssh-keygen", "age", "age-keygen"]
            if profile == "macos":
                tools.extend(("node", "srt"))
            row = {"format": ci.RESULT_FORMAT, "profile": profile, "repository": ci.REPOSITORY,
                   "workflow": ci.WORKFLOW, "run_id": self.run_id, "attempt": self.attempt, "commit": self.head,
                   "wheel": self.wheel, "wheel_artifact_id": 19, "build": self.build.identity, "platform": system,
                   "tools": {name: "synthetic version" for name in tools}, "discovery_errors": [],
                   "tests": [{"id": test, "outcome": "passed"} for test in sorted(ci.expected_tests(profile, self.index))]}
            self.results[profile] = (number, row)
            self.result(profile, row)

    def add(self, name, id_, filename, data):
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(filename, data)
        body = stream.getvalue()
        self.archives[id_] = body
        self.artifacts[name] = {"id": id_, "name": name, "expired": False, "size_in_bytes": len(body),
                                "digest": "sha256:" + digest(body),
                                "workflow_run": {"id": self.run_id, "head_sha": self.head,
                                                 "repository_id": ci.REPOSITORY_ID, "head_repository_id": ci.REPOSITORY_ID}}

    def result(self, profile, value):
        name = ci.results_name(profile, self.attempt)
        self.add(name, self.results[profile][0], "results.json", canonical(value))

    def get(self, path):
        data = {
            f"{ci.REPO}/actions/workflows/ci.yml": {"id": self.workflow_id, "path": ci.WORKFLOW_PATH,
                                                  "state": "active", "name": ci.WORKFLOW},
            self.path: self.run,
            self.attempt_path: self.run,
            self.attempt_path + "/jobs?per_page=100": {"jobs": self.jobs, "total_count": len(self.jobs)},
            self.path + "/artifacts?per_page=100&page=1": {"artifacts": list(self.artifacts.values()),
                                                         "total_count": len(self.artifacts)},
        }
        return deepcopy(data[path])

    def raw(self, path):
        return self.archives[int(path.split("/")[-2])]

    def verify(self, attempt=None):
        return ci.verify(self, self.run_id, attempt, self.head, self.build, self.index)


class StructuredCI(unittest.TestCase):
    def test_verified_attempt_uses_the_same_wheel_on_all_profiles(self):
        fixture = EvidenceFixture()
        verified = fixture.verify(fixture.attempt)
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["profiles"].keys(), ci.PROFILES.keys())
        self.assertEqual(verified["wheel_sha256"], fixture.build.identity["sha256"])

    def test_overall_success_cannot_replace_each_required_test_outcome(self):
        for change in ("missing", "duplicate", "skipped", "failed", "error", "discovery"):
            with self.subTest(change=change):
                fixture = EvidenceFixture()
                result = deepcopy(fixture.results["linux"][1])
                if change == "missing":
                    result["tests"].pop()
                elif change == "duplicate":
                    result["tests"].append(result["tests"][0])
                elif change == "discovery":
                    result["discovery_errors"].append("Synthetic discovery error")
                else:
                    result["tests"][0]["outcome"] = change
                fixture.result("linux", result)
                with self.assertRaises(Blocked):
                    fixture.verify()

    def test_attempt_commit_profile_and_artifact_metadata_are_required(self):
        for field, unexpected in (("commit", "6" * 40), ("attempt", 1), ("profile", "windows"), ("wheel_artifact_id", 99),
                                  ("build", {"version": "1.0.0.dev1", "sha256": "6" * 64})):
            with self.subTest(field=field):
                fixture = EvidenceFixture()
                result = {**fixture.results["linux"][1], field: unexpected}
                fixture.result("linux", result)
                with self.assertRaisesRegex(Blocked, "does not match"):
                    fixture.verify()
        fixture = EvidenceFixture()
        fixture.artifacts[ci.results_name("linux", fixture.attempt)]["workflow_run"]["head_sha"] = "3" * 40
        with self.assertRaisesRegex(Blocked, "another run or commit"):
            fixture.verify()
        fixture = EvidenceFixture()
        fixture.add(ci.wheel_name(fixture.attempt), 19, fixture.wheel, b"different wheel")
        with self.assertRaisesRegex(Blocked, "wheel differs"):
            fixture.verify()
        fixture = EvidenceFixture()
        fixture.archives[19] += b"altered archive"
        with self.assertRaisesRegex(Blocked, "GitHub's digest"):
            fixture.verify()
        fixture = EvidenceFixture()
        fixture.jobs[-1]["steps"][-1]["conclusion"] = "skipped"
        with self.assertRaisesRegex(Blocked, "step did not succeed"):
            fixture.verify()
        fixture = EvidenceFixture()
        with self.assertRaisesRegex(Blocked, "current CI attempt"):
            fixture.verify(1)


class PublicationHistory(VaultTest):
    def audit(self, root=None, *args):
        return run([sys.executable, "-I", ROOT / "scripts/audit_publication.py", "--root", root or self.root, *args],
                   check=False)

    def commit_file(self, name, body):
        atomic(self.root / name, body)
        git(self.root, "add", "-f", "--", name)
        git(self.root, "commit", "-m", "Disposable history fixture")

    def test_removed_reference_and_another_path_for_same_blob_still_block_release(self):
        self.assertEqual(self.audit().returncode, 0)
        body = b"synthetic local reference"
        self.commit_file("earlier-alias.md", body)
        self.commit_file("wiki-1.4.md", body)
        git(self.root, "rm", "--", "wiki-1.4.md")
        git(self.root, "commit", "-m", "Remove disposable reference marker")
        result = self.audit()
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"Forbidden publication path: wiki-1.4.md", result.stdout)
        self.assertIn(b"Local reference content found under: earlier-alias.md", result.stdout)
        release = run([sys.executable, "-I", ROOT / "scripts/release_check.py", "--vault", self.root],
                      cwd=ROOT, check=False)
        self.assertEqual(release.returncode, 5)
        report = decode(release.stdout)
        self.assertEqual(report["commit"], self.vault.head())
        self.assertFalse(report["publication_audit"])
        self.assertFalse(report["stable_release_allowed"])
        self.assertTrue(all(not row["passed"] for row in report["trials"]))
        failures = []
        audit_publication.check("earlier-alias.md", body, failures, reference_hash=None)
        self.assertEqual(failures, [])
        audit_publication.check("earlier-alias.md", body, failures, reference_hash=digest(body))
        self.assertEqual(failures, ["Local reference content found under: earlier-alias.md"])
        linked = self.base / "history worktree"
        git(self.root, "worktree", "add", "--detach", str(linked))
        head = self.vault.head()
        atomic(self.vault.common / "info/grafts", (head + "\n").encode())
        self.assertEqual(git(self.root, "log", "--format=%H").splitlines(), [head])
        for target in (self.root, linked):
            result = self.audit(target, "--expected-commit", head)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"local grafts", result.stdout)

    def test_extra_branch_and_detached_head_are_both_audited(self):
        git(self.root, "checkout", "--detach")
        self.commit_file("synthetic.pem", b"ordinary fixture used to test path checking")
        detached = self.vault.head()
        self.assertEqual(self.audit().returncode, 1)
        git(self.root, "checkout", "main")
        self.assertEqual(self.audit().returncode, 0)
        git(self.root, "branch", "fixture-archive", detached)
        result = self.audit()
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"Forbidden publication path: synthetic.pem", result.stdout)

    def test_shallow_clone_and_missing_reachable_object_fail_closed(self):
        self.commit_file("history.md", b"synthetic historical blob")
        oid = git(self.root, "rev-parse", "HEAD:history.md")
        git(self.root, "rm", "--", "history.md")
        git(self.root, "commit", "-m", "Remove working copy of synthetic blob")
        shallow = self.base / "shallow clone"
        git(self.base, "clone", "--depth=1", self.root.as_uri(), str(shallow))
        result = self.audit(shallow)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"shallow", result.stdout)
        self.assertEqual(self.audit().returncode, 0)
        object_path = self.root / ".git/objects" / oid[:2] / oid[2:]
        object_path.chmod(0o600)
        object_path.unlink()
        result = self.audit()
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"reachable Git blob is unavailable", result.stdout)

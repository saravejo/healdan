import copy
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import sprint_gate as gate


HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
BOT = 42
QODO_APP = 43
COORDINATOR = 45
RUN = 46
PULL = 47
SCOPE = gate.Scope(PULL, HEAD, BASE, MERGE, "B01")
POLICY = gate.Policy(gate.BASE, gate.WORKFLOW, BASE)
ATTESTATION = 70
AUDIT = 71
PROOF = 72
COMMAND = "python -m unittest scripts.test_sprint_gate -v"
RESULT = "Reviewed regression passed in the checked-out SHA"


class GitHubFixture:
    def __init__(self):
        self.rows = {}
        self.objects = {}
        self.files = {}
        self.edit_history = {}
        self.deleted = []
        self.writes = []
        self.log = "2026-11-23T19:22:07.0000000Z Published sprint check run 9\n"

    def get(self, route):
        if route not in self.objects:
            raise gate.Blocked("GitHub evidence record is unavailable")
        return self.objects[route]

    def text_at(self, path, sha):
        item = self.files[sha, path]
        return json.dumps(item) if isinstance(item, list) else item

    def pages(self, route, key=None, **params):
        yield from self.rows.get(route, [])

    def edits(self, node, kind):
        yield from self.edit_history.get(node, [])

    def deleted_qodo_comments(self, pull, bot):
        yield from self.deleted

    def job_log(self, job):
        return self.log

    def request(self, route, method, payload):
        self.writes.append((route, method, payload))
        rows = self.rows.setdefault(f"{gate.REPO}/commits/{HEAD}/check-runs", [])
        if method == "POST":
            rows.append(payload | {"id": 9, "app": {"id": gate.ACTIONS_APP}})
        else:
            rows[0].update(payload)
        return rows[0], ""


def qodo_row(item_id, body, **fields):
    return {
        "id": item_id, "node_id": str(item_id), "html_url": f"{gate.WEB}/pull/{PULL}#test-{item_id}",
        "body": body, "user": {"id": BOT, "type": "Bot"}, "performed_via_github_app": {"id": QODO_APP},
        **fields,
    }


def qodo_review(head=HEAD, bugs=0, prefix=""):
    titles = ["Publication audit can load candidate code", "Later lots can run before dependencies", "Detailed contract scenarios can be skipped"]
    findings = "\n".join(f"<summary>  {number}.  {title} <code>Bug</code></summary>" for number, title in enumerate(titles[:bugs], 1))
    categories = "📜 Skill insights" if bugs else "📎 Requirement gaps"
    return (f"\n<h3>{prefix}Code Review by Qodo</h3>\n\n"
            f"<code>🐞 Bugs ({bugs})</code> <code>📘 Rule violations (0)</code> <code>{categories} (0)</code>\n\n"
            f"{findings}\n\n<!-- {gate.WEB}/commit/{head} -->\n")


class SprintGateTests(unittest.TestCase):
    def setUp(self):
        self.api = GitHubFixture()
        self.status = f"{gate.REPO}/branches/{gate.BASE}/protection"
        self.candidate = f"{gate.REPO}/pulls/{PULL}"
        self.reviews = f"{self.candidate}/reviews"
        self.issues = f"{gate.REPO}/issues/{PULL}/comments"
        self.inline = f"{self.candidate}/comments"
        self.jobs = f"{gate.REPO}/actions/runs/{RUN}/attempts/1/jobs"
        repo = {"id": gate.REPOSITORY_ID, "full_name": gate.REPOSITORY, "default_branch": "main", "private": False}
        actor = {"id": COORDINATOR}
        self.api.objects.update({
            gate.REPO: repo,
            f"{gate.REPO}/branches/main": {"protected": True, "commit": {"sha": BASE}},
            self.status: {
                "enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False}, "required_conversation_resolution": {"enabled": True},
                "required_pull_request_reviews": {"required_approving_review_count": 0},
                "required_status_checks": {"strict": True, "checks": [
                    {"context": name, "app_id": gate.ACTIONS_APP} for name in (gate.CHECK, "test", "package")
                ]},
            },
            f"{gate.REPO}/rules/branches/main": [{"type": "update", "ruleset_id": 2, "ruleset_source_type": "Repository"}],
            f"{gate.REPO}/rulesets/2": {"enforcement": "active", "bypass_actors": [
                {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "pull_request"}
            ]},
            self.candidate: {
                "number": PULL, "state": "open", "draft": False, "mergeable": True, "merge_commit_sha": MERGE,
                "base": {"repo": repo, "ref": "main", "sha": BASE},
                "head": {"repo": repo, "ref": "sprint/b01-integridade", "sha": HEAD},
            },
            f"{gate.REPO}/compare/{BASE}...{HEAD}?per_page=1": {"status": "ahead", "merge_base_commit": {"sha": BASE}},
            f"{gate.REPO}/git/commits/{MERGE}": {"sha": MERGE, "parents": [{"sha": BASE}, {"sha": HEAD}]},
            f"{gate.REPO}/git/commits/{HEAD}": {"sha": HEAD},
            f"{gate.REPO}/compare/{HEAD}...{BASE}?per_page=1": {"status": "behind", "merge_base_commit": {"sha": BASE}},
            f"{gate.REPO}/actions/workflows/sprint-b00.yml": {"id": 5, "path": gate.WORKFLOW},
            f"{gate.REPO}/actions/runs/{RUN}": {
                "id": RUN, "workflow_id": 5, "path": gate.WORKFLOW, "event": "workflow_dispatch", "head_branch": "main",
                "head_sha": BASE, "run_attempt": 1, "repository": repo, "head_repository": repo,
                "actor": actor, "triggering_actor": actor,
            },
        })
        self.api.rows.update({
            self.reviews: [qodo_row(1, "Early review finding", commit_id="d" * 40, state="COMMENTED", submitted_at="old"),
                           qodo_row(2, "Current review complete", commit_id=HEAD, state="COMMENTED", submitted_at="new")],
            self.inline: [qodo_row(3, "Inline finding", commit_id=HEAD)],
            self.issues: [qodo_row(4, "Finding in summary"), qodo_row(5, qodo_review())],
            self.jobs: [
                {"name": f"sprint-b00 {job}", "id": 8, "head_sha": BASE, "run_id": RUN,
                 "status": "completed", "conclusion": "success"}
                for job in ("test", "package", "gate")
            ],
        })
        self.api.edit_history["4"] = [{"id": "prior-summary", "diff": "Finding removed from current summary",
                                      "editor": {"databaseId": BOT}, "editedAt": "now"}]
        self.matrix = [{"id": item, "lote": "B01" if item == 1 else "B02", "aceite": "Acceptance criterion", "dependencias": [],
                        "estado": "pendente", "pr": None, "commits": [], "testes": [], "pareceres": []}
                       for item in range(1, 68) if item not in (40, 41)]
        self.proposal = copy.deepcopy(self.matrix)
        self.api.files.update({
            (BASE, gate.MATRIX): self.matrix,
            (HEAD, gate.MATRIX): self.proposal,
            (BASE, "docs/sprint-autonoma/B01.md"): '# Contract\n\n```json\n{"scenarios":{"1":{"positive":"Execute the test","negative":"Reject bad input"}}}\n```\n',
        })
        self.api.files[HEAD, "docs/sprint-autonoma/B01.md"] = self.api.files[BASE, "docs/sprint-autonoma/B01.md"]
        self.proof = [{"url": f"{gate.WEB}/pull/{PULL}#issuecomment-{PROOF}", "detail": "Executed a regression on the reviewed head."}]
        self.comment(PROOF, f"Tested {HEAD}\n{COMMAND}\n{RESULT}\n")

    def comment(self, item, body, pull=PULL):
        if isinstance(body, dict):
            body = f"```json\n{json.dumps(body)}\n```"
        row = {"id": item, "node_id": str(item), "body": body, "created_at": "2026-11-23T19:00:00Z", "updated_at": "2026-11-23T19:00:00Z",
               "user": {"id": COORDINATOR, "type": "User"}, "issue_url": f"https://api.github.com{gate.REPO}/issues/{pull}",
               "html_url": f"{gate.WEB}/pull/{pull}#issuecomment-{item}"}
        self.api.objects[f"{gate.REPO}/issues/comments/{item}"] = row
        return gate.digest({"id": item, "body": body, "updated_at": row["updated_at"]})

    def acceptance(self):
        return gate.load_acceptance(self.api, SCOPE, POLICY)

    def manifest(self, records):
        covered = {}
        for key, record in records.items():
            quotes = record.get("finding_titles") or ([] if key in {"issue:5", "review:2"} else [record["body"]])
            findings = [{"id": str(index), "quote": quote, "resolution": "fixed", "commit": HEAD,
                         "test": {"command": COMMAND, "result": RESULT, "evidence": self.proof}}
                        for index, quote in enumerate(quotes, 1)]
            covered[key] = {"sha256": gate.digest(record), "findings": findings, "no_findings": "Completion only"}
        accepted = self.acceptance()
        return {"version": 1, "repository": gate.REPOSITORY, **asdict(SCOPE), "implementers": ["implementation-session"],
                "contract_sha256": accepted.contract_sha256,
                "items": {"1": {"acceptance_sha256": gate.digest(self.matrix[0]["aceite"]), "result": "pass", "evidence": self.proof,
                                "scenarios": {name: {"sha256": gate.digest(text), "result": "pass", "evidence": self.proof}
                                              for name, text in accepted.scenarios["1"].items()}}},
                "qodo": {"completion": "issue:5", "records": covered}}

    def audit(self, manifest):
        return {"version": 1, "kind": "independent-audit", "repository": gate.REPOSITORY, **asdict(SCOPE),
                "agent": "audit-session", "result": "pass", "history_complete": True, "evidence": self.proof,
                "contract_sha256": manifest["contract_sha256"],
                "items": {key: {"sha256": gate.digest(value), "result": "pass"} for key, value in manifest["items"].items()},
                "qodo": {key: {"sha256": gate.digest(value), "findings": {
                    finding["id"]: {"approved": True, "resolution": finding["resolution"], "detail": "Verified independently."}
                    for finding in value["findings"]
                }} for key, value in manifest["qodo"]["records"].items()}}

    def verify(self, manifest, records, completions, audit=None):
        gate.verify_manifest(SCOPE, self.acceptance(), manifest, audit or self.audit(manifest), records, completions,
                             gate.Evidence(self.api, SCOPE, COORDINATOR))

    def verify_posted(self, manifest, audit):
        manifest["audit"] = {"comment": AUDIT, "sha256": self.comment(AUDIT, audit)}
        self.comment(ATTESTATION, manifest)
        args = SimpleNamespace(comment=ATTESTATION, bot_id=BOT, qodo_app_id=QODO_APP)
        return gate.verify_evidence(self.api, SCOPE, args, COORDINATOR, self.acceptance())

    def snapshot(self):
        return gate.qodo_snapshot(self.api, SCOPE, BOT, QODO_APP)

    def test_complete_evidence_passes_and_publishes_to_head(self):
        self.assertEqual(gate.pr_scope(self.api, PULL, HEAD, BASE), SCOPE)
        gate.verify_protection(self.api)
        gate.verify_run(self.api, POLICY, RUN, 1, COORDINATOR)
        job = gate.verify_jobs(self.api, POLICY, RUN, 1, include_gate=True)
        records, completions = self.snapshot()
        manifest = self.manifest(records)
        self.verify_posted(manifest, self.audit(manifest))
        self.assertEqual(gate.publish(self.api, SCOPE, "success", "Passed", RUN), 9)
        self.assertEqual(self.api.writes[0][2]["head_sha"], HEAD)
        self.assertEqual(gate.verify_published(self.api, SCOPE, "Passed", RUN, job), 9)

    def test_retry_recovers_existing_check_and_updates_a_failed_result(self):
        gate.publish(self.api, SCOPE, "failure", "Blocked", RUN)
        gate.publish(self.api, SCOPE, "failure", "Blocked", RUN)
        gate.publish(self.api, SCOPE, "success", "Passed", RUN)
        gate.publish(self.api, SCOPE, "success", "Passed", RUN)
        self.assertEqual([row[1] for row in self.api.writes], ["POST", "PATCH"])

    def test_old_sha_and_foreign_workflow_are_blocked(self):
        with self.assertRaisesRegex(gate.Blocked, "SHA has changed"):
            gate.pr_scope(self.api, PULL, "d" * 40, BASE)
        self.api.objects[f"{gate.REPO}/actions/runs/{RUN}"]["workflow_id"] = 123
        with self.assertRaisesRegex(gate.Blocked, "protected workflow"):
            gate.verify_run(self.api, POLICY, RUN, 1, COORDINATOR)

    def test_ci_job_must_actually_pass(self):
        self.api.rows[self.jobs][1]["conclusion"] = "skipped"
        with self.assertRaisesRegex(gate.Blocked, "package did not pass"):
            gate.verify_jobs(self.api, POLICY, RUN, 1)

    def test_qodo_absent_or_spoofed_is_blocked(self):
        self.api.rows[self.reviews] = []
        self.api.rows[self.inline] = []
        for row in self.api.rows[self.issues]:
            row["user"] = {"id": 12345, "login": "qodo[bot]", "type": "Bot"}
        with self.assertRaisesRegex(gate.Blocked, "No authenticated Qodo history"):
            self.snapshot()

    def test_qodo_previous_sha_cannot_prove_completion(self):
        self.api.rows[self.issues][1]["body"] = qodo_review("d" * 40)
        with self.assertRaisesRegex(gate.Blocked, "current head"):
            self.snapshot()

    def test_qodo_code_review_comment_proves_exact_sha_and_counts_findings(self):
        self.api.rows[self.reviews] = []
        self.api.rows[self.issues][1]["body"] = qodo_review(bugs=3)
        self.api.rows[self.issues].append(qodo_row(6, f"<h3>PR Summary by Qodo</h3>\n<!-- {gate.WEB}/commit/{HEAD} -->"))
        records, completions = self.snapshot()
        self.assertEqual(completions, ["issue:5"])
        manifest = self.manifest(records)
        manifest["qodo"]["completion"] = "issue:5"
        self.assertEqual(len(records["issue:5"]["finding_titles"]), 3)
        manifest["qodo"]["records"]["issue:5"]["findings"].pop()
        with self.assertRaisesRegex(gate.Blocked, "unaccounted findings"):
            self.verify(manifest, records, completions)
        for body in (qodo_review(head="d" * 40), qodo_review(prefix="Incremental ")):
            self.api.rows[self.issues][1]["body"] = body
            with self.assertRaisesRegex(gate.Blocked, "current head"):
                self.snapshot()

    def test_qodo_history_includes_previous_reviews_and_edited_summary(self):
        records, completions = self.snapshot()
        manifest = self.manifest(records)
        for missing in ("review:1", "issue:4", "issue:4/edit:prior-summary", "inline:3"):
            with self.subTest(missing=missing):
                incomplete = copy.deepcopy(manifest)
                del incomplete["qodo"]["records"][missing]
                with self.assertRaisesRegex(gate.Blocked, "every Qodo"):
                    self.verify(incomplete, records, completions)
        manifest["qodo"]["records"]["issue:4"]["findings"][0]["resolution"] = "open"
        with self.assertRaisesRegex(gate.Blocked, "source text or resolution"):
            self.verify(manifest, records, completions)

    def test_qodo_deleted_history_blocks(self):
        self.api.deleted = [{"id": "deletion-event", "createdAt": "2026-11-23T19:01:00Z"}]
        with self.assertRaisesRegex(gate.Blocked, "was deleted"):
            self.snapshot()

    def test_item_without_acceptance_is_blocked(self):
        self.proposal[1]["aceite"] = "  "
        with self.assertRaisesRegex(gate.Blocked, "missing acceptance"):
            self.acceptance()

    def test_candidate_matrix_is_checked_by_the_evaluate_command(self):
        records, _ = self.snapshot()
        manifest = self.manifest(records)
        manifest["audit"] = {"comment": AUDIT, "sha256": self.comment(AUDIT, self.audit(manifest))}
        self.comment(ATTESTATION, manifest)
        args = ["sprint_gate.py", "evaluate", "--pull", str(PULL), "--head", HEAD, "--base", BASE, "--run", str(RUN),
                "--attempt", "1", "--attestation", str(ATTESTATION)]
        env = {"GH_TOKEN": "fixture", "GITHUB_WORKFLOW_REF": f"{gate.REPOSITORY}/{gate.WORKFLOW}@refs/heads/main",
               "GITHUB_WORKFLOW_SHA": BASE, "GITHUB_SHA": BASE, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
               "SPRINT_QODO_BOT_ID": str(BOT), "SPRINT_QODO_APP_ID": str(QODO_APP), "SPRINT_COORDINATOR_ID": str(COORDINATOR),
               "SPRINT_PUBLISH": "true"}
        with patch.dict("os.environ", env), patch.object(sys, "argv", args), patch.object(gate, "GitHub", return_value=self.api):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(), 0)
            self.proposal[1]["aceite"] = ""
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assertEqual(gate.main(), 1)
            self.assertIn("missing acceptance", errors.getvalue())
        self.assertEqual([write[2]["conclusion"] for write in self.api.writes], ["success", "failure"])

    def test_candidate_cannot_change_protected_lot_acceptance_or_dependencies(self):
        for field, replacement in (("lote", "B01"), ("aceite", "Other acceptance"), ("dependencias", ["B00"])):
            with self.subTest(field=field):
                self.proposal[1][field] = replacement
                with self.assertRaisesRegex(gate.Blocked, "changes the protected lot"):
                    self.acceptance()
                self.proposal[1][field] = self.matrix[1][field]

    def test_pending_prerequisite_blocks_acceptance(self):
        self.matrix[0]["dependencias"] = self.proposal[0]["dependencias"] = ["B02"]
        with self.assertRaisesRegex(gate.Blocked, "prerequisite B02 is not fully integrated"):
            self.acceptance()

    def test_matrix_traceability_can_record_a_previously_integrated_lot(self):
        pull, previous_head, previous_merge = PULL - 1, "d" * 40, "e" * 40
        repo = self.api.objects[gate.REPO]
        previous = f"{gate.REPO}/pulls/{pull}"
        self.api.objects[previous] = {
            "number": pull, "state": "closed", "merged": True, "merged_at": "2026-11-23T18:00:00Z", "merge_commit_sha": previous_merge,
            "head": {"repo": repo, "ref": "sprint/b02-previous", "sha": previous_head}, "base": {"repo": repo, "ref": "main"},
        }
        compare = f"{gate.REPO}/compare/{previous_merge}...{BASE}?per_page=1"
        self.api.objects[compare] = {"status": "ahead", "merge_base_commit": {"sha": previous_merge}}
        self.api.rows[previous + "/commits"] = [{"sha": previous_head}]
        self.comment(PROOF + 1, "Executed the controller tests on the earlier PR", pull)
        self.comment(PROOF + 2, "Reviewed the earlier PR independently", pull)
        self.proposal[1].update(estado="concluido", pr=pull, commits=[previous_head],
                                testes=[f"{gate.WEB}/pull/{pull}#issuecomment-{PROOF + 1}"],
                                pareceres=[f"{gate.WEB}/pull/{pull}#issuecomment-{PROOF + 2}"])
        self.assertIn("1", self.acceptance().items)
        self.api.objects[previous]["head"]["ref"] = "sprint/b03-foreign"
        with self.assertRaisesRegex(gate.Blocked, "integrated PR from another lot"):
            self.acceptance()
        self.api.objects[previous]["head"]["ref"] = "sprint/b02-previous"
        self.api.objects[compare]["status"] = "diverged"
        with self.assertRaisesRegex(gate.Blocked, "outside the protected base history"):
            self.acceptance()
        with self.assertRaisesRegex(gate.Blocked, "must remain pending in B00"):
            gate.verify_candidate_matrix(self.api, gate.Scope(1, HEAD, BASE, MERGE, "B00"),
                                         gate.matrix_items(self.matrix), gate.matrix_items(self.proposal))

    def test_protected_scenarios_cannot_be_omitted(self):
        records, completions = self.snapshot()
        manifest = self.manifest(records)
        manifest["items"]["1"]["scenarios"].pop("negative")
        with self.assertRaisesRegex(gate.Blocked, "missing a scenario"):
            self.verify(manifest, records, completions)

    def test_missing_evidence_url_and_untrusted_audit_are_blocked(self):
        records, completions = self.snapshot()
        manifest = self.manifest(records)
        audit = self.audit(manifest)
        audit["evidence"] = [{"url": f"{gate.WEB}/pull/{PULL}#issuecomment-99999", "detail": "Invented result"}]
        with self.assertRaisesRegex(gate.Blocked, "record is unavailable"):
            self.verify(manifest, records, completions, audit)
        self.verify_posted(manifest, self.audit(manifest))
        row = self.api.objects[f"{gate.REPO}/issues/comments/{AUDIT}"]
        args = SimpleNamespace(comment=ATTESTATION, bot_id=BOT, qodo_app_id=QODO_APP)
        row["user"]["id"] = 99999
        with self.assertRaisesRegex(gate.Blocked, "configured coordinator"):
            gate.verify_evidence(self.api, SCOPE, args, COORDINATOR, self.acceptance())
        row["user"]["id"] = COORDINATOR
        row["updated_at"] = "edited"
        with self.assertRaisesRegex(gate.Blocked, "unedited GitHub comment"):
            gate.verify_evidence(self.api, SCOPE, args, COORDINATOR, self.acceptance())

    def test_dismissal_requires_a_real_counterexample_and_auditor_approval(self):
        records, completions = self.snapshot()
        manifest = self.manifest(records)
        finding = manifest["qodo"]["records"]["review:1"]["findings"][0]
        finding.update(resolution="dismissed-with-reason", reason="The reproduced operation preserves the ledger")
        self.verify(manifest, records, completions)
        audit = self.audit(manifest)
        audit["qodo"]["review:1"]["findings"]["1"]["approved"] = False
        with self.assertRaisesRegex(gate.Blocked, "explicit approval"):
            self.verify(manifest, records, completions, audit)
        finding["test"]["result"] = "Invented output"
        with self.assertRaisesRegex(gate.Blocked, "were not found in evidence"):
            self.verify(manifest, records, completions)

    def test_qodo_titles_and_editor_identify_real_findings(self):
        self.api.rows[self.issues][1]["body"] = qodo_review(bugs=3)
        records, completions = self.snapshot()
        manifest = self.manifest(records)
        manifest["qodo"]["records"]["issue:5"]["findings"][0]["quote"] = "Code Review"
        with self.assertRaisesRegex(gate.Blocked, "distinct finding title"):
            self.verify(manifest, records, completions)
        self.api.edit_history["5"] = [{"id": "later-edit", "diff": "-first heading\n+edited heading",
                                      "editor": {"databaseId": 99999}, "editedAt": "later"}]
        with self.assertRaisesRegex(gate.Blocked, "current head"):
            self.snapshot()
        self.api.edit_history["5"][0]["editor"]["databaseId"] = BOT
        self.assertIn("issue:5", self.snapshot()[1])

    def test_disappeared_qodo_notice_is_reconciled_with_its_durable_hash(self):
        row = qodo_row(10, "<h3>Qodo is busy working</h3>", html_url=f"{gate.WEB}/pull/{PULL}#issuecomment-10")
        fingerprint = hashlib.sha256(row["body"].encode()).hexdigest()
        anchor = 75
        self.comment(anchor, f"Captured from bot GitHub {BOT}, App {QODO_APP}.\n| 10 | Progress | {fingerprint} |")
        self.api.rows[self.issues].append(self.api.objects[f"{gate.REPO}/issues/comments/{anchor}"])
        with self.assertRaisesRegex(gate.Blocked, "previously recorded Qodo snapshot is missing"):
            gate.qodo_snapshot(self.api, SCOPE, BOT, QODO_APP, [], COORDINATOR)
        archive = {"kind": "issue", "record": row, "anchor": anchor}
        records, _ = gate.qodo_snapshot(self.api, SCOPE, BOT, QODO_APP, [archive], COORDINATOR)
        archived = f"issue:10/snapshot:{fingerprint}"
        self.assertIn(archived, records)
        self.assertEqual(records[archived]["archive"]["anchor"], anchor)
        row["body"] += "Changed bytes"
        with self.assertRaisesRegex(gate.Blocked, "durable, unedited GitHub hash"):
            gate.qodo_snapshot(self.api, SCOPE, BOT, QODO_APP, [archive], COORDINATOR)

    def test_saturated_qodo_edits_require_archived_evidence(self):
        api = gate.GitHub("fixture")
        edits = [{"id": str(index), "diff": "prior body", "deletedAt": None} for index in range(100)]
        reply = {"data": {"node": {"lastEditedAt": "present", "userContentEdits": {
            "nodes": edits, "totalCount": 100, "pageInfo": {"hasNextPage": False, "endCursor": None}
        }}}}
        with patch.object(api, "request", return_value=(reply, "")):
            with self.assertRaisesRegex(gate.Blocked, "may be truncated"):
                list(api.edits("node-id", "issue"))

    def test_retry_rebinds_a_new_test_merge_only_with_identical_pr_base_head_and_app(self):
        gate.publish(self.api, SCOPE, "success", "First result", RUN)
        refreshed = gate.Scope(PULL, HEAD, BASE, "f" * 40, "B01")
        gate.publish(self.api, refreshed, "success", "Refreshed result", RUN + 1)
        self.assertEqual([row[1] for row in self.api.writes], ["POST", "PATCH"])
        self.assertEqual(gate.sprint_check(self.api, refreshed)["id"], 9)
        conflicting_base = gate.Scope(PULL, HEAD, "e" * 40, MERGE, "B01")
        with self.assertRaisesRegex(gate.Blocked, "Unexpected sprint check issuer"):
            gate.publish(self.api, conflicting_base, "success", "Unrelated result", RUN + 2)

    def test_publication_audit_reads_candidate_without_loading_its_code(self):
        git = shutil.which("git")
        self.assertIsNotNone(git, "Git backs the publication audit")
        protected_script = Path(__file__).with_name("audit_publication.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            candidate.mkdir()
            scripts = candidate / "scripts"
            scripts.mkdir()
            (scripts / "audit_publication.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
            dist = root / "dist"
            dist.mkdir()
            wheel_path = dist / "untrusted.whl"
            with zipfile.ZipFile(wheel_path, "w") as wheel:
                wheel.writestr("pkg/README.md", "public wheel content\n")
            with tarfile.open(dist / "candidate.tar.gz", "w:gz") as source:
                data = b"source distribution\n"
                entry = tarfile.TarInfo("pkg/README.md")
                entry.size = len(data)
                source.addfile(entry, io.BytesIO(data))
            subprocess.run([git, "-C", str(candidate), "init", "-q"], check=True)
            subprocess.run([git, "-C", str(candidate), "add", "scripts/audit_publication.py"], check=True)
            command = [sys.executable, "-I", str(protected_script), "--root", str(candidate),
                       "--packages", str(dist), "--require-distributions"]
            clean = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            with zipfile.ZipFile(wheel_path, "a") as wheel:
                wheel.writestr("pkg/.env", "forbidden publication path\n")
            audited = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(audited.returncode, 1, audited.stderr)
            self.assertIn("Forbidden publication path: pkg/.env", audited.stdout)

    def test_untrusted_publisher_is_blocked(self):
        self.api.objects[self.status]["required_status_checks"]["checks"][0]["app_id"] = 123
        with self.assertRaisesRegex(gate.Blocked, "sprint and CI checks"):
            gate.verify_protection(self.api)

    def test_check_homonym_without_matching_gate_log_is_blocked(self):
        gate.publish(self.api, SCOPE, "success", "Passed", RUN)
        self.api.log = "Published sprint check run 10\n"
        with self.assertRaisesRegex(gate.Blocked, "protected job's published result"):
            gate.verify_published(self.api, SCOPE, "Passed", RUN, {"id": 8})

    def test_bootstrap_requires_pr_one_pinned_sha_and_absent_main_workflow(self):
        commit = "e" * 40
        route = f"{gate.REPO}/contents/.github/workflows?ref={BASE}"
        self.api.objects[f"{gate.REPO}/branches/{gate.BOOTSTRAP_BRANCH}"] = {"protected": True, "commit": {"sha": commit}}
        self.api.objects[route] = [{"path": gate.BOOTSTRAP_WORKFLOW}]
        with patch.dict("os.environ", {"SPRINT_BOOTSTRAP_SHA": commit}):
            with self.assertRaisesRegex(gate.Blocked, "first B00"):
                gate.policy_for(self.api, SCOPE, True)
            bootstrap = gate.Scope(1, HEAD, BASE, MERGE, "B00")
            self.assertEqual(gate.policy_for(self.api, bootstrap, True), gate.Policy(gate.BOOTSTRAP_BRANCH, gate.BOOTSTRAP_WORKFLOW, commit))
            self.api.objects[route].append({"path": gate.WORKFLOW})
            with self.assertRaisesRegex(gate.Blocked, "Bootstrap ended"):
                gate.policy_for(self.api, bootstrap, True)


if __name__ == "__main__":
    unittest.main()

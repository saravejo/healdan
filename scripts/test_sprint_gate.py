import copy
import unittest
from dataclasses import asdict
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


class GitHubFixture:
    def __init__(self):
        self.rows = {}
        self.objects = {}
        self.edit_history = {}
        self.deleted_comment = False
        self.writes = []
        self.log = "2026-11-23T19:22:07.0000000Z Published sprint check run 9\n"

    def get(self, route):
        return self.objects[route]

    def pages(self, route, key=None, **params):
        yield from self.rows.get(route, [])

    def edits(self, node, kind):
        yield from self.edit_history.get(node, [])

    def deleted_qodo_comment(self, pull, bot):
        return self.deleted_comment

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
    return (f"\n<h3>{prefix}Code Review by Qodo</h3>\n"
            f"<code>🐞 Bugs ({bugs})</code> <code>📘 Rule violations (0)</code> <code>📎 Requirement gaps (0)</code>\n\n"
            f"Review result\n\n<!-- {gate.WEB}/commit/{head} -->\n")


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
        self.api.edit_history["4"] = [{"id": "prior-summary", "diff": "Finding removed from current summary"}]
        self.matrix = [{"id": item, "lote": "B01" if item == 1 else "B02", "aceite": "Acceptance criterion"}
                       for item in range(1, 68) if item not in (40, 41)]

    def manifest(self, records):
        evidence = [{"url": f"{gate.WEB}/pull/{PULL}#issuecomment-1", "detail": "Reproduced and verified the correction on HEAD."}]
        covered = {}
        for key, record in records.items():
            findings = [] if key in {"issue:5", "review:2"} else [
                {"quote": record["body"], "resolution": "fixed", "evidence": evidence}
            ]
            covered[key] = {"sha256": gate.digest(record), "findings": findings, "no_findings": "Completion only"}
        return {"version": 1, "repository": gate.REPOSITORY, **asdict(SCOPE), "implementers": ["implementation-session"],
                "audit": {"agent": "audit-session", "result": "pass", "history_complete": True, "evidence": evidence},
                "items": {"1": {"acceptance_sha256": gate.digest(self.matrix[0]["aceite"]), "result": "pass", "evidence": evidence}},
                "qodo": {"completion": "issue:5", "records": covered}}

    def snapshot(self):
        return gate.qodo_snapshot(self.api, SCOPE, BOT, QODO_APP)

    def test_complete_evidence_passes_and_publishes_to_head(self):
        self.assertEqual(gate.pr_scope(self.api, PULL, HEAD, BASE), SCOPE)
        gate.verify_protection(self.api)
        gate.verify_run(self.api, POLICY, RUN, 1, COORDINATOR)
        job = gate.verify_jobs(self.api, POLICY, RUN, 1, include_gate=True)
        records, completions = self.snapshot()
        gate.verify_manifest(SCOPE, gate.criteria(self.matrix, "B01"), self.manifest(records), records, completions)
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
        self.api.rows[self.issues][1]["body"] = qodo_review(bugs=2)
        self.api.rows[self.issues].append(qodo_row(6, f"<h3>PR Summary by Qodo</h3>\n<!-- {gate.WEB}/commit/{HEAD} -->"))
        records, completions = self.snapshot()
        self.assertEqual(completions, ["issue:5"])
        manifest = self.manifest(records)
        manifest["qodo"]["completion"] = "issue:5"
        with self.assertRaisesRegex(gate.Blocked, "unaccounted findings"):
            gate.verify_manifest(SCOPE, gate.criteria(self.matrix, "B01"), manifest, records, completions)
        for body in (qodo_review(head="d" * 40), qodo_review(prefix="Incremental ")):
            self.api.rows[self.issues][1]["body"] = body
            with self.assertRaisesRegex(gate.Blocked, "current head"):
                self.snapshot()

    def test_qodo_history_includes_previous_reviews_and_edited_summary(self):
        records, completions = self.snapshot()
        manifest = self.manifest(records)
        criteria = gate.criteria(self.matrix, "B01")
        for missing in ("review:1", "issue:4", "issue:4/edit:prior-summary", "inline:3"):
            with self.subTest(missing=missing):
                incomplete = copy.deepcopy(manifest)
                del incomplete["qodo"]["records"][missing]
                with self.assertRaisesRegex(gate.Blocked, "every Qodo"):
                    gate.verify_manifest(SCOPE, criteria, incomplete, records, completions)
        manifest["qodo"]["records"]["issue:4"]["findings"][0]["resolution"] = "open"
        with self.assertRaisesRegex(gate.Blocked, "resolution or evidence"):
            gate.verify_manifest(SCOPE, criteria, manifest, records, completions)

    def test_qodo_deleted_history_blocks(self):
        self.api.deleted_comment = True
        with self.assertRaisesRegex(gate.Blocked, "was deleted"):
            self.snapshot()

    def test_item_without_acceptance_is_blocked(self):
        self.matrix[1]["aceite"] = "  "
        with self.assertRaisesRegex(gate.Blocked, "missing acceptance"):
            gate.criteria(self.matrix, "B01")

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

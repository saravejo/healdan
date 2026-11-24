from datetime import timedelta
from pathlib import Path
import copy
import os
import platform
import unittest
from uuid import uuid4

from support import VaultTest
from healdan import admission, backups, custody, inbox, linting, maintenance, retention, tasks
from healdan.core import Blocked, atomic, digest, git, read_json, stamp, utc
from healdan.review import csp_status, freeze_csp, inspect
from healdan.setup import initialize
from healdan.migration import purge_check


class Tasks(VaultTest):
    def test_worktree_boundaries_and_context_bytes(self):
        start = utc("2026-01-01T00:00:00Z")
        task = {"created_at": stamp(start), "state": "active"}
        for seconds, expected in ((43199, "active"), (43200, "warning"), (43201, "warning"),
                                  (86399, "warning"), (86400, "expired"), (86401, "expired")):
            self.assertEqual(tasks.age_status(task, start + timedelta(seconds=seconds)), expected)
        real = tasks.create(self.vault, "Fixture task")
        session = tasks.new_session(self.vault, real["id"], "read", "reader", "é" * 4000)
        self.assertEqual(session["context_bytes"], 8000)
        with self.assertRaises(Blocked):
            tasks.new_session(self.vault, real["id"], "read", "reader", "é" * 4000 + "x")
        with self.assertRaises(Blocked):
            tasks.create(self.vault, "Excess capacity")

    def test_session_operation_identity_and_no_clock_reset(self):
        task = tasks.create(self.vault, "Fixture task")
        operation = str(uuid4())
        first = tasks.new_session(self.vault, task["id"], "extract", "extractor", "context", operation=operation)
        again = tasks.new_session(self.vault, task["id"], "extract", "extractor", "context", operation=operation)
        second = tasks.new_session(self.vault, task["id"], "review", "reviewer", "context")
        self.assertEqual((first["id"], first["uuid"]), (again["id"], again["uuid"]))
        self.assertNotEqual(first["id"], second["id"])
        newer = tasks.new_session(self.vault, task["id"], "review rework", "reviewer", "context")
        self.assertNotEqual(second["proposal"], newer["proposal"])
        atomic(Path(second["proposal"]) / "comparison-input.json", b"previous knowledge")
        self.assertFalse((Path(newer["proposal"]) / "comparison-input.json").exists())
        self.assertEqual(tasks.get_task(self.vault, task["id"])["created_at"], task["created_at"])
        with self.assertRaises(Blocked):
            tasks.new_session(self.vault, task["id"], "new action", "extractor", "context", operation=operation)

    def test_human_wait_separate_from_worktree_and_no_failed_delivery_clock(self):
        task = tasks.create(self.vault, "Fixture task")
        with self.assertRaises(Blocked):
            tasks.present(self.vault, task["id"], "Decision needed", "")
        self.assertNotIn("presented_at", tasks.get_task(self.vault, task["id"]))
        start = utc()
        task = tasks.present(self.vault, task["id"], "Decision needed", "local presentation receipt", start)
        self.assertIn("reminder_day_3", tasks.reconcile_clock(self.vault, task, start + timedelta(days=3)))
        self.assertNotIn("reminder_day_3", tasks.reconcile_clock(self.vault, task, start + timedelta(days=3)))
        self.assertIn("reminder_day_5", tasks.reconcile_clock(self.vault, task, start + timedelta(days=5)))
        self.assertIn("closure_pending", tasks.reconcile_clock(self.vault, task, start + timedelta(days=7)))
        self.assertTrue(tasks.get_task(self.vault, task["id"])["capacity_held"])
        self.assertEqual(task["state"], "waiting")

    def test_failed_preservation_keeps_capacity_and_worktree(self):
        task = tasks.create(self.vault, "Fixture task")
        with self.assertRaises(Blocked):
            tasks.preserve_and_close(self.vault, task["id"])
        self.assertTrue(tasks.get_task(self.vault, task["id"])["capacity_held"])
        self.assertTrue(Path(task["worktree"]).is_dir())

    def test_signed_answer_stops_waiting_and_late_answer_is_rejected(self):
        task = tasks.create(self.vault, "Waiting fixture")
        start = utc()
        tasks.present(self.vault, task["id"], "Choose an action", "presentation", start)
        decision = {"answer": "Continue", "owner": "human", "reason": "Evidence checked"}
        with self.assertRaises(Blocked):
            tasks.answer(self.vault, task["id"], decision, start + timedelta(days=7))
        answered = tasks.answer(self.vault, task["id"], decision, start + timedelta(days=1))
        self.assertEqual(answered["created_at"], task["created_at"])
        self.assertNotIn("closure_pending", tasks.reconcile_clock(self.vault, answered, start + timedelta(days=8)))

    def test_explicit_reopening_preserves_session_consumption(self):
        self.age()
        task = tasks.create(self.vault, "Reopening fixture")
        session = tasks.new_session(self.vault, task["id"], "read", "reader", "fixture")
        session["usage"]["input_tokens"] = 40
        atomic(self.vault.control / "sessions" / (session["operation"] + ".json"), session)
        tasks.preserve_and_close(self.vault, task["id"])
        fresh = tasks.reopen(self.vault, task["id"], {"owner": "human", "reason": "Late answer received"})
        self.assertEqual(fresh["predecessor"], task["id"])
        self.assertEqual(fresh["prior_usage"]["input_tokens"], 40)
        self.assertNotEqual(fresh["id"], task["id"])

    def test_csp_freeze_numeric_sampling_and_defect_reset(self):
        units = {f"C-{n:04d}": str(n) for n in range(1, 131)}
        plan = freeze_csp(units, {"streak": 0}, "12" * 32)
        for n in range(1, 112):
            self.assertEqual(csp_status(plan)["pending"], [f"C-{n:04d}"])
            inspect(plan, {f"C-{n:04d}": "conform"})
        snapshot = copy.deepcopy(plan)
        self.assertEqual(csp_status(plan), csp_status(snapshot))
        status = csp_status(plan)
        if status["pending"]:
            selected = status["pending"][0]
            inspect(plan, {selected: "defect"})
            after = csp_status(plan)
            self.assertTrue(after["defect"])
            self.assertEqual(after["streak"], 0)
        numeric = freeze_csp({"C-10000": "a", "C-9999": "b"}, {"streak": 111}, "12" * 32)
        self.assertEqual(numeric["units"], ["C-9999", "C-10000"])


class InboxLint(VaultTest):
    def test_operational_exclusions_and_unknown_entry(self):
        for path in ("inbox/a.txt", "inbox/tasks/a.txt", "inbox/agent-dashboard.html", "inbox/agent-activities-today.md", "control/tasks/a.txt"):
            atomic(self.root / path, b"fixture")
        items = inbox.inventory(self.vault)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["paths"], ["inbox/a.txt"])
        self.assertIsNone(items[0]["entered_at"])
        self.assertIn("unknown_entry_time", inbox.findings(items[0]))

    def test_zero_bytes_not_spaces_and_sensitive_not_archived(self):
        atomic(self.root / "inbox/zero", b"")
        atomic(self.root / "inbox/spaces", b" \n ")
        rows = {i["size"]: i for i in inbox.inventory(self.vault)}
        for item in rows.values():
            inbox.decide(self.vault, item["sha256"], "archive", owner="human", classification="common", destination="archive")
        inbox.archive_empty(self.vault, rows[0]["sha256"])
        self.assertFalse((self.root / "inbox/zero").exists())
        with self.assertRaises(Blocked):
            inbox.archive_empty(self.vault, rows[3]["sha256"])
        atomic(self.root / "inbox/secret-zero", b"")
        inbox.inventory(self.vault)
        self.vault.config["source_classification_authorities"] = ["human"]
        atomic(self.vault.config_path, self.vault.config)
        approval = admission.sign_reclassification(self.vault, rows[0]["sha256"],
            {"classification": "sensitive", "reason": "Fixture correction after further review"})
        admission.reclassify(self.vault, approval)
        inbox.decide(self.vault, rows[0]["sha256"], "archive", owner="human", classification="sensitive", destination="restricted",
                     purpose={"purpose": "Verify incident", "necessity": "Required synthetic evidence", "owner": "human", "link": "fixture"})
        with self.assertRaises(Blocked):
            inbox.archive_empty(self.vault, rows[0]["sha256"])

    def test_rename_copy_version_and_deferral_keep_deadline(self):
        atomic(self.root / "inbox/a", b"original")
        item = inbox.inventory(self.vault)[0]
        entered = utc() - timedelta(days=10)
        inbox.decide(self.vault, item["sha256"], "defer", owner="human", classification="common",
                     entered_at=stamp(entered), entry_origin="recorded_capture", defer_until=stamp(utc() + timedelta(days=2)))
        atomic(self.root / "inbox/copy", b"original")
        atomic(self.root / "inbox/a", b"changed")
        items = inbox.inventory(self.vault)
        self.assertEqual(len(items), 2)
        self.assertTrue(all(i["entered_at"] == stamp(entered) for i in items))
        original = next(i for i in items if i["sha256"] == item["sha256"])
        self.assertIn("original_triage_overdue", inbox.findings(original))
        self.assertIn("deferral_due", inbox.findings(original, utc() + timedelta(days=3)))

    def test_lint_strict_eight_days_partial_and_task_dedup(self):
        start = utc()
        first = linting.lint(self.vault, start)
        self.assertEqual(first["status"], "complete")
        self.assertFalse(linting.stale(stamp(start), start + timedelta(days=8)))
        self.assertTrue(linting.stale(stamp(start), start + timedelta(days=8, microseconds=1)))
        before = self.vault.inputs()
        linting.lint(self.vault, start + timedelta(days=1))
        tasks_before = read_json(self.vault.control / "followups.json")
        partial = linting.lint(self.vault, start + timedelta(days=2), checks=lambda v, n: ({}, [{"category": "query", "error": "unavailable"}]))
        self.assertEqual(partial["status"], "partial")
        self.assertEqual(read_json(self.vault.control / "lint-state.json")["last_complete_lint_at"], stamp(start + timedelta(days=1)))
        self.assertEqual(self.vault.inputs(), before)
        self.assertEqual(tasks_before["query"]["id"], read_json(self.vault.control / "followups.json")["query"]["id"])


class Retention(VaultTest):
    def material(self, **changes):
        root = self.state / "custody"
        root.mkdir(parents=True, exist_ok=True)
        data = b"disposable ciphertext surrogate for deletion filesystem tests"
        target = root / "copy.age"
        atomic(target, data)
        record = {"id": "material-test", "kind": "conversation", "classification": "common", "closed_at": "2026-01-01T00:00:00Z",
                  "holds": [], "dependencies": [], "copies": [{"root": str(root), "path": target.name,
                  "sha256": digest(data), "kind": "ciphertext", "status": "present"}]}
        record.update(changes)
        custody.save_material(self.vault, record)
        return record, target

    def test_utc_deadlines_unknown_classes_and_purpose(self):
        record = {"classification": "common", "kind": "conversation", "closed_at": "2026-03-07T12:00:00-05:00"}
        self.assertEqual(custody.retention_deadline(record), utc(record["closed_at"]) + timedelta(hours=720))
        for classification in ("sensitive", "personal", "mixed", "unknown", None):
            record["classification"] = classification
            self.assertEqual(custody.retention_deadline(record), utc(record["closed_at"]) + timedelta(hours=168))
            with self.assertRaises(Blocked):
                custody.validate_purpose(record)
        self.assertIsNone(custody.retention_deadline({"classification": "common", "kind": "conversation"}))
        export = {"kind": "export", "classification": "sensitive", "captured_at": "2026-01-01T00:00:00Z"}
        self.assertEqual(custody.retention_deadline(export), utc("2026-01-08T00:00:00Z"))

    def test_plan_persisted_then_hash_rechecked(self):
        record, target = self.material()
        plan = retention.plan(self.vault, "2026-02-01T00:00:00Z")
        self.assertTrue((self.vault.control / "deletions" / (plan["id"] + ".json")).exists())
        atomic(target, b"changed after planning")
        result = retention.execute(self.vault, plan["id"], "2026-02-01T00:00:00Z")
        self.assertEqual(result["status"], "pending")
        self.assertTrue(target.exists())

    def test_deletion_recovers_after_material_receipt_before_plan_receipt(self):
        from unittest.mock import patch
        record, target = self.material()
        plan = retention.plan(self.vault, "2026-02-01T00:00:00Z")
        original = custody.save_material
        def interrupted(vault, material):
            original(vault, material)
            if material["copies"][0]["status"] == "deleted":
                raise SystemExit("Injected crash after copy receipt")
        with patch("healdan.retention.save_material", side_effect=interrupted), self.assertRaises(SystemExit):
            retention.execute(self.vault, plan["id"], "2026-02-01T00:00:00Z")
        self.assertFalse(target.exists())
        self.assertEqual(retention.execute(self.vault, plan["id"], "2026-02-01T00:00:00Z")["status"], "complete")

    def test_hold_after_plan_blocks_and_release_preserves_deadline(self):
        record, target = self.material()
        original_deadline = custody.retention_deadline(record)
        plan = retention.plan(self.vault, "2026-02-01T00:00:00Z")
        held = custody.hold(self.vault, record["id"], "Investigation", "human", ["dependency"])
        self.assertEqual(retention.execute(self.vault, plan["id"], "2026-02-01T00:00:00Z")["status"], "pending")
        with self.assertRaises(Blocked):
            custody.release_hold(self.vault, record["id"], held["id"], [])
        custody.release_hold(self.vault, record["id"], held["id"], ["dependency"])
        self.assertEqual(custody.retention_deadline(custody.materials(self.vault)[record["id"]]), original_deadline)
        self.assertEqual(retention.execute(self.vault, plan["id"], "2026-02-02T00:00:00Z")["status"], "complete")
        self.assertFalse(target.exists())

    def test_offline_copy_does_not_count_as_deleted(self):
        record, target = self.material()
        offline = self.base / "offline-drive"
        self.vault.config["storage_roots"] = [str(offline)]
        record["copies"][0]["root"] = str(offline)
        custody.save_material(self.vault, record)
        plan = retention.plan(self.vault, "2026-02-01T00:00:00Z")
        result = retention.execute(self.vault, plan["id"], "2026-02-01T00:00:00Z")
        self.assertEqual(result["status"], "pending")

    def test_native_decryptable_archive_without_resume_stays_held(self):
        record, target = self.material(decryption_verified=True, artifact_inventory={"session.jsonl": {}},
                                       session="unproven")
        record["copies"][0]["kind"] = "native"
        custody.save_material(self.vault, record)
        plan = retention.plan(self.vault, "2026-02-01T00:00:00Z")
        result = retention.execute(self.vault, plan["id"], "2026-02-01T00:00:00Z")
        self.assertEqual(result["status"], "pending")
        self.assertTrue(target.exists())
        self.assertTrue(custody.materials(self.vault)[record["id"]]["holds"])

    def test_backup_expiry_is_strict_and_holds_do_not_extend_it(self):
        record, _ = self.material(classification="sensitive")
        now = utc("2026-01-02T00:00:00Z")
        deadline = custody.retention_deadline(record)
        for expiry in (deadline, deadline + timedelta(seconds=1)):
            with self.assertRaises(Blocked):
                backups.validate_generation("short", [record], expiry, now)
        backups.validate_generation("short", [record], deadline - timedelta(seconds=1), now)
        with self.assertRaises(Blocked):
            backups.validate_generation("long", [record], deadline, now)
        generation = {"kind": "backup", "expires_at": stamp(deadline), "holds": [{"reason": "Hold"}]}
        self.assertEqual(custody.retention_deadline(generation), deadline)

    def test_maintenance_failure_prevents_backup(self):
        record, target = self.material()
        custody.hold(self.vault, record["id"], "Still needed", "human")
        result = maintenance.daily(self.vault, "2026-02-01T00:00:00Z")
        self.assertEqual(result["status"], "pending")
        self.assertIsNone(result["backup"])


class Installation(VaultTest):
    def test_zip_repeat_and_distribution_remote_only(self):
        original = b"keep me\n"
        atomic(self.root / "wiki/index.md", original)
        git(self.root, "remote", "add", "origin", "https://github.com/saravejo/healdan.git")
        git(self.root, "remote", "add", "personal", "https://github.com/example/private-wiki.git")
        head = self.vault.head()
        first = initialize(self.root, self.state)
        second = initialize(self.root, self.state)
        self.assertEqual(first["removed_distribution_remotes"], ["origin"])
        self.assertEqual(second["removed_distribution_remotes"], [])
        self.assertEqual(git(self.root, "remote"), "personal")
        self.assertEqual((self.root / "wiki/index.md").read_bytes(), original)
        self.assertEqual(self.vault.head(), head)
        self.assertFalse((self.root / "wiki-1.4.md").exists())

    def test_any_extra_worktree_blocks_purge(self):
        self.assertTrue(purge_check(self.vault)["eligible_for_review"])
        extra = self.base / "detached"
        git(self.root, "worktree", "add", "--detach", str(extra), "HEAD")
        git(self.root, "worktree", "lock", str(extra))
        self.assertFalse(purge_check(self.vault)["eligible_for_review"])

    def test_native_trials_missing_never_look_successful(self):
        self.assertEqual(len(maintenance.trial_status(self.vault)), 5)
        self.assertFalse(any(row["passed"] for row in maintenance.trial_status(self.vault)))


if __name__ == "__main__":
    unittest.main()

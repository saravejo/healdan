import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from io import BytesIO
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from support import VaultTest
from healdan import backups, cli, compatibility, custody, inbox, launcher, linting, maintenance, retention, setup, storage_policy, tasks
from healdan.core import Blocked, Vault, atomic, canonical, decode, digest, read_json, stamp, utc


class StorageLifecycle(VaultTest):
    def configure_age(self, **settings):
        self.age()
        destination = self.base / "backup"
        destination.mkdir()
        self.vault.config.update(backup_destinations=[str(destination)], backup_generation_days=2, **settings)
        atomic(self.vault.config_path, self.vault.config)
        return destination

    def change_policy(self, backup="off", retention_mode="by_class", days=None):
        retention_settings = {"mode": retention_mode}
        if retention_mode == "by_class":
            retention_settings["days"] = days or storage_policy.LEGACY_DAYS
        approval = storage_policy.policy_request(self.vault, {"backup": {"mode": backup}, "retention": retention_settings,
                                                               "reason": "Disposable approved fixture"})
        return storage_policy.apply_policy(self.vault, approval)

    def export(self, identifier, captured_at="2026-01-01T00:00:00Z", *, data=None):
        target = self.root / "inbox" / (identifier + ".txt")
        data = identifier.encode() if data is None else data
        atomic(target, data)
        record = {"id": identifier, "kind": "export", "classification": "common", "captured_at": captured_at,
                  "source_sha256": digest(data), "holds": [], "dependencies": [], "copies": [
                      {"root": str(target.parent), "path": target.name, "sha256": digest(data), "kind": "export",
                       "status": "present"}]}
        custody.save_material(self.vault, record)
        return record, target

    def capture(self, *, native=False):
        operation = None
        task = "fixture"
        if native:
            task = tasks.create(self.vault, "Native bookkeeping fixture")["id"]
            operation = tasks.new_session(self.vault, task, "review", "editor", "fixture")["operation"]
        origin = self.state / "profile"
        atomic(origin / "a.jsonl", b"first synthetic conversation file")
        atomic(origin / "nested/b.jsonl", b"second synthetic conversation file")
        identifier = custody.capture_tree(self.vault, origin, task=task, classification="common", session=operation)
        record = custody.materials(self.vault)[identifier]
        record["closed_at"] = "2026-01-01T00:00:00Z"
        custody.save_material(self.vault, record)
        return record, origin

    def native_approval(self, record, destination):
        custody.restore_capture(self.vault, record["id"], destination)
        session = tasks.get_session(self.vault, record["session"])
        receipt = {"id": "fixture-resume", "uuid": session["uuid"], "action": session["action"],
                   "recovery_material": record["id"], "resumed": True, "success": True,
                   "cumulative_usage": {"input_tokens": 38, "output_tokens": 7, "evidence_bytes": 140}}
        session["launches"].append(receipt)
        atomic(self.vault.control / "sessions" / (record["session"] + ".json"), session)
        return {"material": record["id"], "cipher_sha256": record["cipher_sha256"], "plain_sha256": record["plain_sha256"],
                "reconstruction_sha256": record["plain_sha256"], "launch_receipt": receipt["id"],
                "uuid": session["uuid"], "action": session["action"], "usage": receipt["cumulative_usage"]}

    def test_independent_backup_modes_and_legacy_daily(self):
        backup_root = self.configure_age()
        start = utc()
        legacy_round = maintenance.daily(self.vault, start)
        self.assertEqual(legacy_round["status"], "complete", legacy_round)
        legacy_id = legacy_round["backup"]
        self.assertEqual(maintenance.daily(self.vault, start + timedelta(hours=1))["backup_result"]["status"], "not_due")
        self.vault.config["backup_destinations"] = []
        atomic(self.vault.config_path, self.vault.config)
        self.change_policy()
        code, daily = self.cli("maintenance", "daily")
        self.assertEqual((code, daily["status"], daily["backup_result"]["status"]), (0, "complete", "disabled"), daily)
        self.assertEqual(self.cli("backup", "create", "--kind", "long", "--expires-at", "permanent")[0], 5)
        self.assertEqual(self.cli("backup", "verify", legacy_id)[0], 0)
        self.assertEqual(self.cli("restore", legacy_id, self.base / "legacy-recovered")[0], 0)
        diagnostics = {c["name"]: c for c in setup.doctor(self.vault)["checks"]}
        self.assertEqual(diagnostics["backup:policy"]["status"], "disabled")
        self.assertEqual(linting.lint(self.vault)["backup_policy"]["status"], "disabled")

        self.change_policy(backup="manual")
        self.assertEqual(maintenance.daily(self.vault, start)["backup_result"]["status"], "manual")
        self.assertEqual(linting.lint(self.vault)["backup_policy"]["status"], "missing")
        self.vault.config.update(backup_destinations=[str(backup_root)], backup_interval_hours="bad")
        atomic(self.vault.config_path, self.vault.config)
        self.assertEqual(self.cli("backup", "create", "--kind", "long", "--expires-at", "permanent")[0], 0)
        self.change_policy(backup="scheduled")
        self.assertEqual(linting.lint(self.vault)["backup_policy"]["status"], "invalid")
        self.assertEqual(self.cli("maintenance", "daily")[0], 5)
        self.vault.config["backup_interval_hours"] = 1
        atomic(self.vault.config_path, self.vault.config)
        due = maintenance.daily(self.vault, start + timedelta(hours=2))
        self.assertEqual(due["backup_result"]["status"], "complete", due)

    def test_permanent_policy_and_legacy_plan_with_rollback_boundary(self):
        record, path = self.export("legacy")
        plan = retention.plan(self.vault, "2026-02-01T00:00:00Z")
        capabilities = read_json(Path(compatibility.__file__).with_name("controller_formats.json"))
        old = {**capabilities, "journal": capabilities["journal"][:2]}
        compatibility.check(self.vault, old)
        request = self.base / "policy-request.json"
        approval_path = self.base / "policy-approval.json"
        atomic(request, {"backup": {"mode": "off"}, "retention": {"mode": "keep_forever"}, "reason": "Preserve history"})
        code, result = self.cli("maintenance", "policy", "sign", request, "--output", approval_path)
        self.assertEqual(code, 0, result)
        approval = read_json(approval_path)
        wrong_vault = self.signed(dict(approval["payload"], vault="other-vault"), "decision")
        with self.assertRaises(Blocked):
            storage_policy.apply_policy(self.vault, wrong_vault)
        with self.assertRaises(Blocked):
            storage_policy.apply_policy(self.vault, dict(approval, digest="0" * 64))
        code, decision = self.cli("maintenance", "policy", "apply", approval_path)
        self.assertEqual(code, 0, decision)
        self.assertEqual(decision["scope"], {"existing": [record["id"]], "future": True})
        self.assertEqual(decision["version"], 1)
        code, result = self.cli("maintenance", "execute", plan["id"])
        self.assertEqual(code, 0, result)
        self.assertEqual((result["digest"], result["entries"][0]["status"]), (plan["digest"], "preserved"))
        self.assertEqual(maintenance.daily(self.vault, "2045-01-01T00:00:00Z")["status"], "complete")
        self.assertTrue(path.exists())
        with self.assertRaisesRegex(Blocked, "healdan-storage-policy-v1"):
            compatibility.check(self.vault, old)
        compatibility.check(self.vault, capabilities)

    def test_signed_expiry_and_short_members(self):
        self.configure_age(backup_interval_hours=24)
        start = utc("2026-01-02T00:00:00Z")
        generation = backups.create(self.vault, "long", start + timedelta(days=2), now=start)
        original = custody.materials(self.vault)[generation["id"]]
        decision = storage_policy.preservation_request(self.vault, generation["id"], "Preserve specific generation")
        wrong_digest = self.signed(dict(decision["payload"], envelope_digest="0" * 64), "decision")
        with self.assertRaises(Blocked):
            storage_policy.apply_preservation(self.vault, generation["id"], wrong_digest)
        storage_policy.apply_preservation(self.vault, generation["id"], decision)
        self.assertEqual(custody.materials(self.vault)[generation["id"]], original)
        self.assertEqual(decision["payload"]["envelope_digest"], original["approval"]["digest"])
        self.assertEqual(backups.verify_backup(self.vault, generation["id"])["status"], "complete")
        record, _ = self.capture()
        deadline = custody.retention_deadline(record)
        for expiry in (deadline, "permanent"):
            with self.assertRaises(Blocked):
                backups.create(self.vault, "short", expiry, [record["id"]], now=start)
        backups.create(self.vault, "short", deadline - timedelta(seconds=1), [record["id"]], now=start)
        unknown = dict(record, closed_at=None)
        custody.save_material(self.vault, unknown)
        with self.assertRaisesRegex(Blocked, "unknown deadlines"):
            backups.create(self.vault, "short", start + timedelta(days=1), [record["id"]], now=start)
        self.change_policy(backup="manual", retention_mode="keep_forever")
        short = backups.create(self.vault, "short", "permanent", [record["id"]], now=start)
        self.assertEqual(short["approval"]["payload"]["expiry"], "permanent")
        self.assertIsNone(short["approval"]["payload"]["expires_at"])
        self.change_policy()
        retention.execute(self.vault, retention.plan(self.vault, "2040-01-01T00:00:00Z")["id"], "2040-01-01T00:00:00Z")
        self.assertEqual(custody.materials(self.vault)[generation["id"]], original)

    def test_expired_signed_generations_under_keep_forever_report_pending_authorization(self):
        destination = self.configure_age()
        start = utc("2026-01-02T00:00:00Z")
        expiry = start + timedelta(days=2)
        previous = backups.create(self.vault, "long", expiry, now=start)
        plan = retention.plan(self.vault, expiry)
        self.change_policy(backup="manual", retention_mode="keep_forever")
        current = backups.create(self.vault, "long", expiry, now=start)
        self.assertEqual(maintenance.daily(self.vault, start)["status"], "complete")
        pending = retention.execute(self.vault, plan["id"], expiry)
        self.assertEqual(pending["status"], "pending", pending)
        generation_ids = {previous["id"], current["id"]}
        before = {identifier: (destination / (identifier + ".age")).read_bytes() for identifier in generation_ids}
        result = maintenance.daily(self.vault, expiry)
        self.assertEqual({row["material"] for row in result["pending"]}, generation_ids)
        findings = linting.lint(self.vault, expiry)["findings"]
        self.assertTrue(all(f"retention:{identifier}" in findings for identifier in generation_ids))
        for identifier in generation_ids:
            decision = storage_policy.preservation_request(self.vault, identifier, "Keep this signed generation")
            storage_policy.apply_preservation(self.vault, identifier, decision)
        self.assertEqual(maintenance.daily(self.vault, expiry)["status"], "complete")
        for original in (previous, current):
            identifier = original["id"]
            self.assertEqual(custody.materials(self.vault)[identifier], original)
            self.assertEqual((destination / (identifier + ".age")).read_bytes(), before[identifier])

    def test_backup_deleted_replica_requires_intent_receipt(self):
        first = self.configure_age()
        second = self.base / "backup-secondary"
        second.mkdir()
        self.vault.config["backup_destinations"].append(str(second))
        atomic(self.vault.config_path, self.vault.config)
        start = utc("2026-01-02T00:00:00Z")
        expiry = start + timedelta(days=2)
        record = backups.create(self.vault, "long", expiry, now=start)
        identifier = record["id"]
        original = record["approval"]
        target = second / (identifier + ".age")
        cipher = target.read_bytes()
        target.unlink()
        material = custody.materials(self.vault)[identifier]
        material["copies"][1]["status"] = "deleted"
        custody.save_material(self.vault, material)
        with self.assertRaisesRegex(Blocked, "verified deletion receipt"):
            backups.inspect_backup(self.vault, material)
        self.assertIn("verified deletion receipt", linting.lint(self.vault)["findings"][f"custody:{identifier}"]["message"])

        material["copies"][1]["status"] = "present"
        custody.save_material(self.vault, material)
        atomic(target, cipher)
        offline = self.base / "first-backup-offline"
        first.rename(offline)
        plan = retention.plan(self.vault, expiry)
        self.assertEqual(retention.execute(self.vault, plan["id"], expiry)["status"], "pending")
        first = offline.rename(first)
        outcome = backups.verify_backup(self.vault, identifier)
        self.assertEqual(outcome["copies"], [{"root": str(first), "verified": True}])
        self.assertEqual(outcome["deleted_copies"][0]["copy_index"], 1)
        self.assertEqual(custody.materials(self.vault)[identifier]["approval"], original)
        self.assertFalse(target.exists())
        self.assertNotIn(f"custody:{identifier}", linting.lint(self.vault)["findings"])
        replica_receipt = outcome["deleted_copies"][0]["receipt"]
        receipt = read_json(self.vault.control / "receipts" / (replica_receipt + ".json"))
        incomplete = receipt["payload"]
        self.assertEqual(incomplete["intent"].pop("generation_digest"), original["digest"])
        replacement = self.vault.receipt("deletion-copy", incomplete, at=receipt["at"])
        plan_path = self.vault.control / "deletions" / (plan["id"] + ".json")
        before = read_json(plan_path)
        saved_plan = read_json(plan_path)
        saved_plan["entries"][1].update(intent=incomplete["intent"], receipt=replacement)
        atomic(plan_path, saved_plan)
        material = custody.materials(self.vault)[identifier]
        material["copies"][1]["deletion_receipt"] = replacement
        custody.save_material(self.vault, material)
        with self.assertRaisesRegex(Blocked, "verified deletion receipt"):
            backups.inspect_backup(self.vault, material)
        atomic(plan_path, before)
        material["copies"][1]["deletion_receipt"] = replica_receipt
        custody.save_material(self.vault, material)
        self.assertEqual(retention.execute(self.vault, plan["id"], expiry)["status"], "complete")
        self.assertNotIn(f"custody:{identifier}", linting.lint(self.vault)["findings"])

    def test_legacy_replica_deletion_verifies_plan_and_round_before_restore(self):
        first = self.configure_age()
        second = self.base / "legacy secondary"
        second.mkdir()
        self.vault.config["backup_destinations"].append(str(second))
        atomic(self.vault.config_path, self.vault.config)
        cutoff = utc()
        expiry = cutoff - timedelta(days=2)
        original = backups.create(self.vault, "long", expiry, now=expiry - timedelta(days=2))
        identifier = original["id"]
        lost = second / (identifier + ".age")
        cipher = lost.read_bytes()
        plan = retention.plan(self.vault, cutoff - timedelta(hours=2))
        path = self.vault.control / "deletions" / (plan["id"] + ".json")
        material = custody.materials(self.vault)[identifier]
        lost.unlink()
        material["copies"][1].update(status="deleted", deleted_at=stamp(cutoff))
        custody.save_material(self.vault, material)
        with self.assertRaisesRegex(Blocked, "verified deletion receipt"):
            backups.inspect_backup(self.vault, material)
        plan.update(status="pending")
        plan["entries"][0].update(status="pending", error="Copy destination is offline", at=stamp(cutoff))
        plan["entries"][1].update(status="deleted", at=stamp(cutoff))
        atomic(path, plan)
        with self.assertRaisesRegex(Blocked, "verified deletion receipt"):
            backups.inspect_backup(self.vault, material)
        offline = first.with_name("legacy primary offline")
        first.rename(offline)
        try:
            retried = retention.execute(self.vault, plan["id"], cutoff)
            self.assertEqual(retried["status"], "pending")
        finally:
            offline.rename(first)
        proof = {"kind": "deletion-round", "at": stamp(cutoff),
                 "payload": {"plan": plan["id"], "digest": plan["digest"], "status": "pending"}}
        receipt = digest(proof)
        self.assertEqual(read_json(self.vault.control / "receipts" / (receipt + ".json")), proof)
        self.assertEqual(retention.plan_digest(plan), plan["digest"])
        history = {p: p.read_bytes() for p in (path, self.vault.control / "materials.json",
                                                self.vault.control / "receipts" / (receipt + ".json"))}
        outcome = backups.verify_backup(self.vault, identifier)
        self.assertEqual(outcome["copies"], [{"root": str(first), "verified": True}])
        self.assertEqual(outcome["deleted_copies"], [{"root": str(second), "copy_index": 1, "receipt": receipt, "proof": "legacy-round"}])
        destination = self.base / "legacy recovery"
        self.assertEqual(self.cli("restore", identifier, destination)[0], 0)
        self.assertEqual((destination / "wiki/claims.jsonl").read_bytes(), b"")
        self.assertEqual({p: p.read_bytes() for p in history}, history)
        plan["entries"][1]["at"] = stamp(cutoff + timedelta(seconds=1))
        atomic(path, plan)
        with self.assertRaisesRegex(Blocked, "verified deletion receipt"):
            backups.inspect_backup(self.vault, material)
        atomic(path, history[path])
        atomic(lost, cipher)
        with self.assertRaisesRegex(Blocked, "verified deletion receipt"):
            backups.inspect_backup(self.vault, material)
        self.assertEqual(lost.read_bytes(), cipher)
        self.assertEqual(custody.materials(self.vault)[identifier]["approval"], original["approval"])
        lost.unlink()
        resumed = retention.execute(self.vault, plan["id"], cutoff)
        self.assertEqual((resumed["status"], resumed["digest"]), ("complete", plan["digest"]))
        retired = backups.verify_backup(self.vault, identifier, allow_retired=True)["deleted_copies"]
        self.assertEqual((retired[0]["copy_index"], retired[1]["proof"]), (0, "legacy-round"))

    def test_interrupted_backup_retires_expired_verified_bytes_and_observes_absent_replicas(self):
        first = self.configure_age()
        second, third = (self.base / name for name in ("empty-replica", "offline-replica"))
        second.mkdir()
        third.mkdir()
        self.vault.config["backup_destinations"].extend((str(second), str(third)))
        atomic(self.vault.config_path, self.vault.config)
        self.change_policy(backup="manual")
        now = utc()
        expiry = now + timedelta(hours=2)

        def stop_at_second(path, data):
            if path.parent == second:
                raise OSError("Fixture interrupted the second replica write")
            return atomic(path, data)

        with patch("healdan.backups.atomic", side_effect=stop_at_second):
            with self.assertRaisesRegex(OSError, "second replica write"):
                backups.create(self.vault, "long", expiry, now=now)
        original, = custody.materials(self.vault).values()
        identifier = original["id"]
        target = first / (identifier + ".age")
        cipher = target.read_bytes()
        self.assertEqual([copy["status"] for copy in original["copies"]], ["present", "planned", "planned"])
        self.assertEqual(retention.plan(self.vault, now)["entries"], [])
        self.assertEqual(target.read_bytes(), cipher)

        offline = third.with_name("offline-away")
        third.rename(offline)
        plan = retention.plan(self.vault, expiry)
        atomic(target, b"divergent disposable replica")
        pending = retention.execute(self.vault, plan["id"], expiry)
        self.assertEqual(pending["status"], "pending", pending)
        self.assertTrue(any("Copy hash changed" in row["reason"] for row in pending["pending"]))
        self.assertTrue(any("offline" in row["reason"] for row in pending["pending"]))
        self.assertEqual(target.read_bytes(), b"divergent disposable replica")
        observed = custody.materials(self.vault)[identifier]["copies"][1]
        self.assertEqual(observed["status"], "absent")
        self.assertNotIn("deletion_receipt", observed)

        atomic(target, cipher)
        offline.rename(third)
        completed = retention.execute(self.vault, plan["id"], expiry)
        updated = custody.materials(self.vault)[identifier]
        self.assertEqual((completed["status"], updated["status"]), ("complete", "writing"), completed)
        self.assertEqual(updated["cipher_sha256"], original["cipher_sha256"])
        self.assertNotIn("approval", updated)
        self.assertEqual([copy["status"] for copy in updated["copies"]], ["deleted", "absent", "absent"])
        self.assertFalse(target.exists())
        for index, copy in enumerate(updated["copies"]):
            receipt = copy["deletion_receipt"] if index == 0 else copy["absence_receipt"]
            evidence = read_json(self.vault.control / "receipts" / (receipt + ".json"))
            self.assertEqual(evidence["kind"], "deletion-copy" if index == 0 else "backup-replica-absent")
        self.assertFalse(any(check["name"] == "custody:" + identifier for check in setup.doctor(self.vault)["checks"]))
        self.assertEqual(maintenance.daily(self.vault, expiry, report_custody=True)["status"], "complete")
        capabilities = read_json(Path(compatibility.__file__).with_name("controller_formats.json"))
        capabilities["journal"].remove("healdan-backup-writing-absence-v1")
        with self.assertRaisesRegex(Blocked, "healdan-backup-writing-absence-v1"):
            compatibility.check(self.vault, capabilities)
        atomic(second / target.name, b"unrelated bytes placed after observation")
        self.assertIn((identifier, "Bytes reappeared at an inactive interrupted backup replica"), custody.integrity_findings(self.vault))
        self.assertEqual(retention.execute(self.vault, plan["id"], expiry)["status"], "complete")
        self.assertEqual((second / target.name).read_bytes(), b"unrelated bytes placed after observation")

        complete = backups.create(self.vault, "long", expiry, now=now)
        unsigned = {key: value for key, value in complete.items() if key not in {"approval", "verified_at"}}
        unsigned["status"] = "writing"
        custody.save_material(self.vault, unsigned)
        plan = retention.plan(self.vault, expiry)
        result = retention.execute(self.vault, plan["id"], expiry)
        self.assertEqual(result["status"], "pending")
        self.assertTrue(all(row["reason"] == "Backup generation already has a completion receipt" for row in result["pending"]))
        self.assertTrue(all((Path(copy["root"]) / copy["path"]).is_file() for copy in complete["copies"]))
        custody.save_material(self.vault, complete)
        self.assertEqual(backups.verify_backup(self.vault, complete["id"])["status"], "complete")

    def test_task_capacity_waits_for_custody_with_backup_off(self):
        keys = self.age()
        self.change_policy(retention_mode="keep_forever")
        task = tasks.create(self.vault, "Permanent task fixture")
        draft = Path(task["worktree"]) / "draft.txt"
        atomic(draft, b"retained work")
        with patch("healdan.custody.encrypt", side_effect=Blocked("fixture capture failure")):
            with self.assertRaises(Blocked):
                tasks.preserve_and_close(self.vault, task["id"])
        self.assertTrue(tasks.get_task(self.vault, task["id"])["capacity_held"])
        self.assertTrue(draft.exists())
        with patch("healdan.tasks.record_worktree_removal", side_effect=SystemExit("interrupted after Git removal")), self.assertRaises(SystemExit):
            tasks.preserve_and_close(self.vault, task["id"])
        interrupted = tasks.get_task(self.vault, task["id"])
        self.assertTrue(interrupted["capacity_held"])
        self.assertFalse(draft.exists())
        closed = tasks.preserve_and_close(self.vault, task["id"])
        self.assertEqual(closed["preservation"], interrupted["preservation"])
        material = custody.materials(self.vault)[closed["preservation"]]
        plain = custody.decrypt(self.vault, custody.capture_copy(self.vault, material), keys[1])
        self.assertTrue(any(name.endswith("draft.txt") for name in decode(plain)["files"]))
        self.assertFalse(closed["capacity_held"])
        self.assertFalse(draft.exists())

    def test_task_close_reconciles_prior_verified_snapshot_after_draft_changes(self):
        keys = self.age()
        self.change_policy()
        task = tasks.create(self.vault, "Resumed worktree closure")
        draft = Path(task["worktree"]) / "draft.txt"
        atomic(draft, b"earlier verified draft")
        preserved = self.state / "tasks" / task["id"] / "outside-worktree.txt"
        atomic(preserved, b"keep this checkpoint outside the removed worktree")
        git = tasks.git

        def interrupt(root, *args, **kwargs):
            if args[:2] == ("worktree", "remove"):
                raise SystemExit("interrupted before Git removes the worktree")
            return git(root, *args, **kwargs)

        with patch("healdan.tasks.git", side_effect=interrupt), self.assertRaises(SystemExit):
            tasks.preserve_and_close(self.vault, task["id"])
        interrupted = tasks.get_task(self.vault, task["id"])
        previous = interrupted["preservation"]
        self.assertTrue(interrupted["capacity_held"] and draft.is_file())
        with self.assertRaisesRegex(Blocked, "removal has not been confirmed by Git"):
            tasks.record_worktree_removal(self.vault, interrupted, draft.parent, previous)
        atomic(draft, b"new draft saved before retry")
        closed = tasks.preserve_and_close(Vault(self.root, self.state), task["id"])
        self.assertNotEqual(previous, closed["preservation"])
        self.assertFalse(draft.exists() or closed["capacity_held"])
        receipts = set()
        for identifier, expected in ((previous, b"earlier verified draft"), (closed["preservation"], b"new draft saved before retry")):
            row = custody.materials(self.vault)[identifier]
            files = decode(custody.decrypt(self.vault, custody.capture_copy(self.vault, row), keys[1]))["files"]
            slot = next(copy for copy in row["copies"] if copy["path"].endswith("/draft.txt"))
            self.assertEqual(base64.b64decode(files[slot["path"]]["body"]), expected)
            self.assertEqual(slot["status"], "moved")
            self.assertEqual(next(copy for copy in row["copies"] if copy["path"] == preserved.name)["status"], "present")
            receipt = read_json(self.vault.control / "receipts" / (slot["move_receipt"] + ".json"))
            self.assertEqual(receipt["payload"]["material"], identifier)
            self.assertEqual(receipt["payload"]["cipher_sha256"], row["cipher_sha256"])
            receipts.add(slot["move_receipt"])
        self.assertEqual(len(receipts), 2)
        result = maintenance.daily(self.vault, utc(closed["closed_at"]) + timedelta(days=15))
        self.assertEqual(result["status"], "complete", result)

    def test_task_close_rechecks_worktree_after_verifying_captures(self):
        self.age()
        self.change_policy()
        task = tasks.create(self.vault, "Worktree changes during verification")
        draft = Path(task["worktree"]) / "draft.txt"
        atomic(draft, b"initial draft")
        verify = tasks.verify_preserved_checkpoints

        def edit_after_verification(vault, record, copies):
            checked = verify(vault, record, copies)
            atomic(draft, b"draft changed during verification")
            return checked

        with patch("healdan.tasks.verify_preserved_checkpoints", side_effect=edit_after_verification):
            with self.assertRaisesRegex(Blocked, "Worktree changed after its verified capture"):
                tasks.preserve_and_close(self.vault, task["id"])
        self.assertEqual(draft.read_bytes(), b"draft changed during verification")
        self.assertTrue(tasks.get_task(self.vault, task["id"])["capacity_held"])
        self.assertFalse(tasks.preserve_and_close(self.vault, task["id"])["capacity_held"])

    def test_worktree_preservation_rejects_incomplete_inventory_until_access_returns(self):
        self.age()
        self.change_policy()
        scandir = os.scandir
        read_bytes = Path.read_bytes
        for expire in (False, True):
            with self.subTest(flow="expiry" if expire else "closure"):
                task = tasks.create(self.vault, "Incomplete worktree inventory")
                worktree = Path(task["worktree"])
                draft = worktree / "notes" / "draft.txt"
                data = b"local draft with unpublished bytes"
                atomic(draft, data)

                def operate():
                    if expire:
                        return tasks.reconcile_expired(self.vault, task["id"], now=utc(task["created_at"]) + timedelta(days=2))
                    return tasks.preserve_and_close(self.vault, task["id"])

                for unavailable_scan in (None, 1, 2):
                    seen = []

                    def scan(path):
                        if path in (draft.parent, str(draft.parent)):
                            seen.append(path)
                            if unavailable_scan is None or len(seen) == unavailable_scan:
                                raise PermissionError("Fixture temporarily unavailable ordinary directory")
                        return scandir(path)

                    with patch("os.scandir", side_effect=scan):
                        with self.assertRaisesRegex(Blocked, "Cannot enumerate preservation directory.*notes"):
                            operate()
                    self.assertEqual(len(seen), unavailable_scan or 1)
                    self.assertEqual(draft.read_bytes(), data)
                    self.assertTrue(tasks.get_task(self.vault, task["id"])["capacity_held"])
                    self.assertIn(worktree, self.vault.repository.worktree_roots())

                def read(path):
                    if path == draft:
                        raise PermissionError("Fixture temporarily unavailable regular file")
                    return read_bytes(path)

                with patch.object(Path, "read_bytes", read):
                    with self.assertRaisesRegex(Blocked, "Cannot read preservation path.*draft.txt"):
                        operate()
                self.assertEqual(draft.read_bytes(), data)
                self.assertTrue(tasks.get_task(self.vault, task["id"])["capacity_held"])
                result = operate()
                self.assertEqual(result["capacity_held"], expire)
                self.assertFalse(worktree.exists())
                identifier = result["expiry_preservation" if expire else "preservation"]
                record = custody.materials(self.vault)[identifier]
                _, plain = custody.verified_capture(self.vault, record)
                member = draft.relative_to(worktree.parent).as_posix()
                self.assertEqual(base64.b64decode(decode(plain)["files"][member]["body"]), data)

    def test_expired_worktree_reconciles_captures_before_and_after_process_supervision(self):
        keys = self.age()
        self.change_policy()
        task = tasks.create(self.vault, "Expired worktree with supervised process")
        task["processes"] = [{"session": "synthetic supervised process"}]
        atomic(tasks.task_path(self.vault, task["id"]), task)
        draft = Path(task["worktree"]) / "draft.txt"
        atomic(draft, b"draft before supervisor")
        prior = []

        def supervisor(vault, current):
            captures = [row for row in custody.materials(vault).values() if row.get("task") == current["id"]]
            self.assertEqual(len(captures), 1)
            prior.append(captures[0]["id"])
            self.assertTrue(custody.capture_copy(vault, captures[0]))
            atomic(draft, b"last draft flushed by supervisor")
            current["processes"] = []
            atomic(tasks.task_path(vault, current["id"]), current)

        with patch("healdan.tasks.reconcile_processes", side_effect=supervisor) as checked:
            expired = tasks.reconcile_expired(self.vault, task["id"], now=utc(task["created_at"]) + timedelta(days=2))
        checked.assert_called_once()
        self.assertTrue(expired["worktree_removed"] and expired["capacity_held"])
        self.assertFalse(draft.exists())
        self.assertNotEqual(prior[0], expired["expiry_preservation"])
        for identifier, expected in ((prior[0], b"draft before supervisor"),
                                     (expired["expiry_preservation"], b"last draft flushed by supervisor")):
            row = custody.materials(self.vault)[identifier]
            files = decode(custody.decrypt(self.vault, custody.capture_copy(self.vault, row), keys[1]))["files"]
            slot = next(copy for copy in row["copies"] if copy["path"].endswith("/draft.txt"))
            self.assertEqual(base64.b64decode(files[slot["path"]]["body"]), expected)
            self.assertEqual(slot["status"], "moved")
            self.assertIsNotNone(slot.get("move_receipt"))

    def test_material_proof_applies_before_any_native_or_cipher_deletion(self):
        self.age()
        self.change_policy()
        record, origin = self.capture(native=True)
        identifier = record["id"]
        cipher = self.state / "custody" / (identifier + ".age")
        now = "2026-02-10T00:00:00Z"
        plan = retention.plan(self.vault, now)
        self.assertEqual(plan["entries"][0]["copy"]["kind"], "ciphertext")
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "pending")
        self.assertTrue(cipher.exists() and (origin / "a.jsonl").exists())
        proof = self.native_approval(record, self.state / "profile-restored")
        material = custody.materials(self.vault)[identifier]
        material["native_recovery"] = self.signed(dict(proof, material="different-material"), "recovery")
        custody.save_material(self.vault, material)
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "pending")
        self.assertTrue(cipher.exists() and (origin / "a.jsonl").exists())
        material = custody.materials(self.vault)[identifier]
        session_file = self.vault.control / "sessions" / (record["session"] + ".json")
        session = read_json(session_file)
        for invalid_usage in (None, {"input_tokens": True, "output_tokens": 0, "evidence_bytes": 0}):
            if invalid_usage is None:
                session["launches"][0].pop("cumulative_usage", None)
            else:
                session["launches"][0]["cumulative_usage"] = invalid_usage
            atomic(session_file, session)
            invalid = dict(proof, usage=invalid_usage) if invalid_usage is not None else {k: v for k, v in proof.items() if k != "usage"}
            material["native_recovery"] = self.signed(invalid, "recovery")
            custody.save_material(self.vault, material)
            result = retention.execute(self.vault, plan["id"], now)
            self.assertEqual(result["status"], "pending", result)
            self.assertTrue(all("cumulative usage" in row["reason"] for row in result["pending"]))
            self.assertTrue(cipher.exists() and (origin / "a.jsonl").exists())
        zeros = {"input_tokens": 0, "output_tokens": 0, "evidence_bytes": 0}
        session["launches"][0]["cumulative_usage"] = zeros
        atomic(session_file, session)
        material["native_recovery"] = self.signed(dict(proof, usage=zeros), "recovery")
        custody.save_material(self.vault, material)
        result = maintenance.daily(self.vault, now)
        self.assertEqual(result["status"], "complete", result)
        self.assertFalse(cipher.exists() or (origin / "a.jsonl").exists())
        copies = custody.materials(self.vault)[identifier]["copies"]
        self.assertTrue(all(c["status"] == "deleted" and c.get("deletion_receipt") for c in copies))

    def test_human_hold_cannot_impersonate_automatic_recovery_hold(self):
        self.change_policy()
        row, target = self.export("human-request")
        code, hold = self.cli("maintenance", "hold", row["id"], "--owner", "controller", "--reason", "Native recovery unproven")
        self.assertEqual(code, 0, hold)
        code, result = self.cli("maintenance", "daily")
        self.assertEqual(code, 5, result)
        self.assertTrue(target.exists())
        legacy = custody.materials(self.vault)[row["id"]]
        del legacy["holds"][0]["origin"]
        custody.save_material(self.vault, legacy)
        self.assertEqual(self.cli("maintenance", "daily")[0], 5)
        self.assertTrue(target.exists())
        custody.release_hold(self.vault, row["id"], hold["id"], [])
        self.assertEqual(self.cli("maintenance", "daily")[0], 0)
        self.assertFalse(target.exists())

    def test_known_rename_duplicate_and_equal_hash_ambiguity(self):
        self.change_policy()
        material, original = self.export("export-a")
        moved, copied, untracked = (self.root / "inbox" / name for name in ("moved", "copied", "untracked"))
        original.rename(moved)
        atomic(copied, moved.read_bytes())
        inbox.inventory(self.vault)
        atomic(untracked, moved.read_bytes())
        now = "2026-01-09T00:00:00Z"
        plan = retention.plan(self.vault, now)
        self.assertEqual(len(plan["entries"]), 2, plan)
        latest = custody.materials(self.vault)[material["id"]]
        self.assertEqual(latest["captured_at"], material["captured_at"])
        self.assertEqual(latest["copies"][0]["status"], "moved")
        atomic(copied, b"changed inbox bytes")
        result = retention.execute(self.vault, plan["id"], now)
        self.assertEqual(result["status"], "pending")
        self.assertTrue(untracked.exists())
        self.assertFalse(moved.exists())
        self.assertEqual(copied.read_bytes(), b"changed inbox bytes")

        first, first_path = self.export("empty-a", data=b"")
        second, second_path = self.export("empty-b", data=b"")
        unknown = self.root / "inbox/unattributed-empty"
        first_path.rename(unknown)
        inbox.inventory(self.vault)
        plan = retention.plan(self.vault, now)
        result = retention.execute(self.vault, plan["id"], now)
        self.assertTrue(any(row["material"] == first["id"] for row in result["pending"]))
        self.assertEqual(len(custody.materials(self.vault)[first["id"]]["copies"]), 1)
        self.assertEqual(len(custody.materials(self.vault)[second["id"]]["copies"]), 1)
        self.assertTrue(unknown.exists())
        self.assertFalse(second_path.exists())

    def test_deletion_intent_recovers_unlink_and_detects_offline_or_unexplained_absence(self):
        self.change_policy()
        now = "2026-02-01T00:00:00Z"
        row, target = self.export("durable")
        plan = retention.plan(self.vault, now)
        unlink = Path.unlink

        def interrupted(path, *args, **kwargs):
            result = unlink(path, *args, **kwargs)
            if path == target:
                raise SystemExit("interrupted after physical unlink")
            return result

        with patch.object(Path, "unlink", interrupted), self.assertRaises(SystemExit):
            retention.execute(self.vault, plan["id"], now)
        journal = read_json(self.vault.control / "deletions" / (plan["id"] + ".json"))
        self.assertEqual(journal["entries"][0]["status"], "deleting")
        self.assertEqual(journal["entries"][0]["intent"]["plan_digest"], plan["digest"])
        result = retention.execute(self.vault, plan["id"], now)
        receipt = result["entries"][0]["receipt"]
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["entries"][0]["receipt"], receipt)

        _, missing = self.export("unexplained")
        _, offline = self.export("offline")
        external = self.base / "drive now offline"
        self.vault.config["storage_roots"] = [str(external)]
        offline_record = custody.materials(self.vault)["offline"]
        offline_record["copies"][0]["root"] = str(external)
        custody.save_material(self.vault, offline_record)
        plan = retention.plan(self.vault, now)
        missing.unlink()
        result = retention.execute(self.vault, plan["id"], now)
        reasons = {p["material"]: p["reason"] for p in result["pending"]}
        self.assertIn("verified deletion intent", reasons["unexplained"])
        self.assertIn("offline", reasons["offline"])
        self.assertTrue(offline.exists())

    def test_checkpoint_deletion_waits_for_verified_capture_and_reconciles_cipher(self):
        self.age()
        self.change_policy()
        material, origin = self.capture()
        identifier = material["id"]
        cipher = self.state / "custody" / (identifier + ".age")
        clear = [origin / name for name in ("a.jsonl", "nested/b.jsonl")]
        original = {path: path.read_bytes() for path in [*clear, cipher]}
        without_cipher = {**material, "copies": [{**material["copies"][0], "status": "deleted"}, *material["copies"][1:]]}
        with patch("healdan.custody.materials", return_value={identifier: without_cipher}):
            self.assertIn((identifier, "Native copies or checkpoints have lost their verified capture"),
                          custody.integrity_findings(self.vault))
        _, independent = self.export("independent-expiry")
        now = "2026-02-10T00:00:00Z"
        plan = retention.plan(self.vault, now)
        with patch("healdan.retention.verified_capture", side_effect=Blocked("Fixture capture temporarily unavailable", 5)):
            result = retention.execute(self.vault, plan["id"], now)
        self.assertEqual(result["status"], "pending", result)
        self.assertEqual({item["material"] for item in result["pending"]}, {identifier})
        self.assertTrue(any("temporarily unavailable" in item["reason"] for item in result["pending"]))
        self.assertEqual({path: path.read_bytes() for path in [*clear, cipher]}, original)
        self.assertFalse(independent.exists())

        unlink = Path.unlink

        def interrupt_cipher(path, *args, **kwargs):
            if path == cipher:
                raise SystemExit("interrupted before the ciphertext unlink")
            return unlink(path, *args, **kwargs)

        with patch("healdan.retention.verified_capture", wraps=custody.verified_capture) as verified, \
                patch.object(Path, "unlink", interrupt_cipher), self.assertRaises(SystemExit):
            retention.execute(self.vault, plan["id"], now)
        self.assertEqual(verified.call_count, len(clear))
        self.assertFalse(any(path.exists() for path in clear))
        self.assertEqual(cipher.read_bytes(), original[cipher])
        reconciled = custody.materials(self.vault)[identifier]
        clear_proofs = [copy["deletion_receipt"] for copy in reconciled["copies"][1:]]
        self.assertTrue(all(reconciled["copies"][i]["status"] == "deleted" for i in (1, 2)))

        with patch("healdan.retention.verified_capture", side_effect=Blocked("Fixture age temporarily unavailable", 5)) as verified:
            completed = retention.execute(self.vault, plan["id"], now)
        verified.assert_not_called()
        self.assertEqual(completed["status"], "complete", completed)
        self.assertFalse(cipher.exists())
        self.assertEqual([copy["deletion_receipt"] for copy in custody.materials(self.vault)[identifier]["copies"][1:]], clear_proofs)

    def test_shared_checkpoints_protect_both_captures_and_reconcile_every_slot(self):
        self.age()
        self.change_policy()
        original, origin = self.capture()
        duplicate = custody.capture_tree(self.vault, origin, task=original["task"], classification="common")
        other = custody.materials(self.vault)[duplicate]
        other["closed_at"] = original["closed_at"]
        custody.save_material(self.vault, other)
        hold = custody.hold(self.vault, duplicate, "Hold this captured checkpoint", "human")
        now = "2026-02-10T00:00:00Z"
        plan = retention.plan(self.vault, now)
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "pending")
        ciphers = [self.state / "custody" / (identifier + ".age") for identifier in (original["id"], duplicate)]
        self.assertTrue(all(path.is_file() for path in (*ciphers, origin / "a.jsonl", origin / "nested/b.jsonl")))
        custody.release_hold(self.vault, duplicate, hold["id"], [])

        save = retention.save_material

        def interrupted(vault, material):
            save(vault, material)
            if material["copies"][1]["status"] == "deleted":
                raise SystemExit("interrupted after the first grouped custody update")

        with patch("healdan.retention.save_material", side_effect=interrupted), self.assertRaises(SystemExit):
            retention.execute(self.vault, plan["id"], now)
        target = origin / "a.jsonl"
        self.assertFalse(target.exists())
        self.assertEqual(retention.pending_deletion_paths(self.vault)[target], {plan["id"]})
        capabilities = read_json(Path(compatibility.__file__).with_name("controller_formats.json"))
        old = {**capabilities, "journal": [name for name in capabilities["journal"] if name != "healdan-shared-deletion-v1"]}
        with self.assertRaisesRegex(Blocked, "healdan-shared-deletion-v1"):
            compatibility.check(self.vault, old)

        # Reuse the pathname without adding a slot to the already completed physical effect.
        atomic(target, b"first synthetic conversation file")
        newest = custody.capture_tree(self.vault, origin, task=original["task"], classification="common")
        newest_before = custody.materials(self.vault)[newest]
        result = retention.execute(self.vault, plan["id"], now)
        self.assertEqual(result["status"], "pending", result)
        saved = custody.materials(self.vault)
        self.assertEqual(saved[newest], newest_before)
        self.assertEqual(target.read_bytes(), b"first synthetic conversation file")
        receipts = {saved[identifier]["copies"][1]["deletion_receipt"] for identifier in (original["id"], duplicate)}
        self.assertEqual(len(receipts), 2)
        self.assertTrue(all(read_json(self.vault.control / "receipts" / (r + ".json"))["payload"]["intent"]["generations"]
                            for r in receipts))
        self.assertNotIn(target, retention.pending_deletion_paths(self.vault))
        for identifier in (original["id"], duplicate):
            self.assertEqual(saved[identifier]["copies"][1]["status"], "deleted")
        self.assertTrue(all(path.is_file() for path in ciphers))

        # The isolated new capture has its own later expiration, and blocks deletion until then.
        newest_before["closed_at"] = "2026-03-01T00:00:00Z"
        custody.save_material(self.vault, newest_before)
        final = maintenance.daily(self.vault, "2026-04-15T00:00:00Z")
        self.assertEqual(final["status"], "complete", final)
        self.assertFalse(any(path.exists() for path in (*ciphers, target, origin / "nested/b.jsonl")))

    def test_pending_shared_unlink_expands_intent_after_expiry_and_hold_release(self):
        self.age()
        self.change_policy()
        original, origin = self.capture()
        duplicate = custody.capture_tree(self.vault, origin, task=original["task"], classification="common")
        material = custody.materials(self.vault)[duplicate]
        material["closed_at"] = original["closed_at"]
        custody.save_material(self.vault, material)
        now = "2026-02-10T00:00:00Z"
        plan = retention.plan(self.vault, now)
        target = origin / "a.jsonl"
        unlink = Path.unlink

        def before_effect(path, *args, **kwargs):
            if path == target:
                raise SystemExit("interrupted before grouped unlink")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", before_effect), self.assertRaises(SystemExit):
            retention.execute(self.vault, plan["id"], now)
        plan_path = self.vault.control / "deletions" / (plan["id"] + ".json")
        prior = next(entry["intent"] for entry in read_json(plan_path)["entries"] if entry["status"] == "deleting")
        newest = custody.capture_tree(self.vault, origin, task=original["task"], classification="common")
        material = custody.materials(self.vault)[newest]
        material["closed_at"] = "2026-02-20T00:00:00Z"
        custody.save_material(self.vault, material)
        result = retention.execute(self.vault, plan["id"], now)
        self.assertEqual(result["status"], "pending", result)
        self.assertTrue(any("Retention has not expired" in item["reason"] for item in result["pending"]))
        hold = custody.hold(self.vault, newest, "Review newer capture", "human")
        _, unrelated = self.export("independent-while-held")
        restart = Vault(self.root, self.state)
        later = "2026-04-11T00:00:00Z"
        pending = maintenance.daily(restart, later)
        self.assertTrue(any("Active hold" in item["reason"] for item in pending["pending"]))
        self.assertFalse(unrelated.exists())
        self.assertEqual(target.read_bytes(), b"first synthetic conversation file")
        self.assertEqual(next(entry["intent"] for entry in read_json(plan_path)["entries"] if entry["status"] == "deleting"), prior)
        custody.release_hold(restart, newest, hold["id"], [])

        def after_effect(path, *args, **kwargs):
            outcome = unlink(path, *args, **kwargs)
            if path == target:
                raise SystemExit("interrupted after unlink with extended intent")
            return outcome

        with patch.object(Path, "unlink", after_effect), self.assertRaises(SystemExit):
            maintenance.daily(restart, later)
        self.assertFalse(target.exists())
        entry = next(entry for entry in read_json(plan_path)["entries"] if entry["status"] == "deleting")
        current = entry["intent"]
        self.assertEqual(entry["intent_history"], [prior])
        self.assertEqual(current["supersedes"], digest(prior))
        ids = {original["id"], duplicate, newest}
        self.assertEqual({slot["material"] for slot in current["generations"]}, ids)
        completed = maintenance.daily(Vault(self.root, self.state), later)
        self.assertEqual(completed["status"], "complete", completed)
        receipts = set()
        for identifier in ids:
            row = custody.materials(self.vault)[identifier]
            self.assertTrue(all(copy["status"] == "deleted" and copy["deletion_receipt"] for copy in row["copies"]))
            for copy in row["copies"]:
                receipt = read_json(self.vault.control / "receipts" / (copy["deletion_receipt"] + ".json"))
                self.assertEqual(receipt["payload"]["material"], identifier)
                receipts.add(copy["deletion_receipt"])
                if copy["path"] == target.name:
                    self.assertEqual(receipt["payload"]["intent"], current)
        self.assertEqual(len(receipts), 9)

    def test_single_slot_intent_requires_original_revision_before_expansion(self):
        self.age()
        self.change_policy()
        record, origin = self.capture()
        target = origin / "a.jsonl"
        data = target.read_bytes()
        now = "2026-02-10T00:00:00Z"
        plan = retention.plan(self.vault, now)
        unlink = Path.unlink

        def interrupt(path, *args, **kwargs):
            if path == target:
                raise SystemExit("interrupted before single-slot unlink")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", interrupt), self.assertRaises(SystemExit):
            retention.execute(self.vault, plan["id"], now)
        path = self.vault.control / "deletions" / (plan["id"] + ".json")
        original = path.read_bytes()
        journal = read_json(path)
        intent = next(entry["intent"] for entry in journal["entries"] if entry["status"] == "deleting")
        self.assertNotIn("generations", intent)
        del intent["file_mtime_ns"]
        atomic(path, journal)
        with patch.object(Path, "unlink", interrupt), self.assertRaises(SystemExit):
            retention.execute(self.vault, plan["id"], now)
        atomic(path, original)
        duplicate = custody.capture_tree(self.vault, origin, task=record["task"], classification="common")
        newest = custody.materials(self.vault)[duplicate]
        newest["closed_at"] = record["closed_at"]
        custody.save_material(self.vault, newest)
        del intent["file_revision"]
        atomic(path, journal)
        result = retention.execute(self.vault, plan["id"], now)
        self.assertTrue(any("Original file revision is unproven" in item["reason"] for item in result["pending"]))
        self.assertEqual(target.read_bytes(), data)
        atomic(path, original)
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        self.assertFalse(target.exists())
        self.assertEqual(custody.materials(self.vault)[duplicate]["copies"][1]["status"], "deleted")

    def test_pending_shared_unlink_preserves_a_rewritten_revision_even_with_same_hash(self):
        self.age()
        self.change_policy()
        record, origin = self.capture()
        before = custody.capture_tree(self.vault, origin, task=record["task"], classification="common")
        other = custody.materials(self.vault)[before]
        other["closed_at"] = record["closed_at"]
        custody.save_material(self.vault, other)
        target = origin / "a.jsonl"
        data = target.read_bytes()
        now = "2026-02-10T00:00:00Z"
        plan = retention.plan(self.vault, now)
        unlink = Path.unlink

        def interrupt(path, *args, **kwargs):
            if path == target:
                raise SystemExit("interrupted before grouped unlink")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", interrupt), self.assertRaises(SystemExit):
            retention.execute(self.vault, plan["id"], now)
        inode, mtime_ns = retention.file_identity(target), target.stat().st_mtime_ns
        target.write_bytes(data)
        self.assertEqual(retention.file_identity(target), inode)
        self.assertNotEqual(target.stat().st_mtime_ns, mtime_ns)
        retry = maintenance.daily(self.vault, now)
        self.assertEqual(retry["status"], "pending", retry)
        self.assertTrue(any("Copy identity changed" in item["reason"] for item in retry["pending"]))
        self.assertEqual(target.read_bytes(), data)
        for identifier in (record["id"], before):
            saved = custody.materials(self.vault)[identifier]
            self.assertEqual(saved["copies"][0]["status"], "present")
            self.assertEqual(saved["copies"][1]["status"], "present")

    def test_eligible_long_backup_runs_while_short_body_is_ineligible(self):
        destination = self.configure_age(backup_interval_hours=24)
        record, _ = self.capture()
        custody.hold(self.vault, record["id"], "Pending preservation review", "human")
        now = utc("2026-02-01T00:00:00Z")
        result = maintenance.daily(self.vault, now)
        self.assertEqual(result["status"], "pending", result)
        backup = result["backup"]
        archive = decode(custody.decrypt(self.vault, (destination / (backup + ".age")).read_bytes()))
        self.assertIn("control/custody-manifests.json", archive["files"])
        self.assertFalse(any(name.startswith("custody/") for name in archive["files"]))
        with self.assertRaises(Blocked):
            backups.create(self.vault, "short", now + timedelta(days=1), [record["id"]], now=now)
        self.assertTrue(backups.verify_backup(self.vault, backup)["copies"])

    def test_daily_discovers_new_expiry_and_reports_held_material_by_cli(self):
        self.configure_age(backup_interval_hours=24)
        now = utc()
        first, target_a = self.export("held-a", stamp(now - timedelta(days=9)))
        _, target_b = self.export("new-b", stamp(now - timedelta(days=7, hours=1)))
        hold = custody.hold(self.vault, first["id"], "Preserve during review", "human")
        prior = retention.plan(self.vault, now - timedelta(days=1))
        self.assertEqual(len(prior["entries"]), 1)
        code, result = self.cli("maintenance", "daily")
        self.assertEqual((code, result["status"]), (5, "pending"), result)
        self.assertTrue(target_a.exists())
        self.assertFalse(target_b.exists())
        self.assertEqual(result["pending"][0]["material"], first["id"])
        self.assertEqual(result["backup_result"]["status"], "complete")
        custody.release_hold(self.vault, first["id"], hold["id"], [])
        self.assertEqual(self.cli("maintenance", "daily")[0], 0)
        self.assertFalse(target_a.exists())

    def test_daily_retry_read_failure_preserves_pending_plan_and_runs_due_backup(self):
        self.configure_age(backup_interval_hours=24)
        self.change_policy(backup="scheduled")
        material, origin = self.capture()
        checkpoint = origin / "nested" / "b.jsonl"
        data = checkpoint.read_bytes()
        cipher = self.state / "custody" / (material["id"] + ".age")
        held, held_file = self.export("held-across-retry")
        hold = custody.hold(self.vault, held["id"], "Retain during human review", "human")
        now = utc("2026-02-15T00:00:00Z")
        plan = retention.plan(self.vault, now)
        path = self.vault.control / "deletions" / (plan["id"] + ".json")
        _, independent = self.export("independent-during-retry")
        read_file = Path.read_bytes
        read_plan = retention.read_json
        execute = retention.execute
        visits = []

        def delayed_file_read(target):
            if target == checkpoint:
                raise PermissionError("Fixture checkpoint read temporarily unavailable")
            return read_file(target)

        def delayed_plan_read(target, *args, **kwargs):
            if target == path:
                raise PermissionError("Fixture plan read temporarily unavailable on retry")
            return read_plan(target, *args, **kwargs)

        def execute_with_retry_failure(vault, identifier, time):
            visits.append(identifier)
            if identifier == plan["id"] and visits.count(identifier) == 2:
                with patch("healdan.retention.read_json", side_effect=delayed_plan_read):
                    return execute(vault, identifier, time)
            return execute(vault, identifier, time)

        with patch.object(Path, "read_bytes", delayed_file_read), patch("healdan.retention.execute", side_effect=execute_with_retry_failure):
            result = maintenance.daily(self.vault, now)
        self.assertEqual(visits.count(plan["id"]), 2)
        self.assertEqual(result["status"], "pending", result)
        self.assertIn({"plan": plan["id"], "phase": "retry", "reason": "Fixture plan read temporarily unavailable on retry"},
                      result["pending"])
        self.assertTrue(any(entry.get("material") == material["id"] and "checkpoint read temporarily unavailable" in entry["reason"]
                            for entry in result["pending"]))
        self.assertTrue(any(entry.get("material") == held["id"] and entry["reason"] == "Active hold prevents deletion"
                            for entry in result["pending"]))
        self.assertFalse(independent.exists())
        self.assertEqual(checkpoint.read_bytes(), data)
        self.assertTrue(cipher.is_file() and held_file.is_file())
        self.assertTrue(any("checkpoint read temporarily unavailable" in entry["reason"] for entry in read_json(path)["pending"]))
        self.assertEqual(result["backup_result"]["status"], "complete", result)
        self.assertEqual(backups.verify_backup(self.vault, result["backup"])["status"], "complete")
        custody.release_hold(self.vault, held["id"], hold["id"], [])
        retry = maintenance.daily(Vault(self.root, self.state), now + timedelta(hours=1))
        self.assertEqual(retry["status"], "complete", retry)
        self.assertFalse(checkpoint.exists() or cipher.exists() or held_file.exists())

    def test_daily_unreadable_task_preserves_dependent_capture_and_runs_independent_work(self):
        self.configure_age(backup_interval_hours=24)
        self.change_policy(backup="scheduled")
        past = utc() - timedelta(days=40)
        unavailable = tasks.create(self.vault, "Task with unavailable closure record", now=past)
        profile = self.state / "dependent-profile"
        checkpoint = profile / "checkpoint.jsonl"
        data = b"synthetic conversation"
        atomic(checkpoint, data)
        capture = custody.capture_tree(self.vault, profile, task=unavailable["id"], classification="common")
        cipher = self.state / "custody" / (capture + ".age")
        with patch("healdan.tasks.stamp", return_value=stamp(past)):
            tasks.preserve_and_close(self.vault, unavailable["id"])
        task_file = tasks.task_path(self.vault, unavailable["id"])
        task_data = task_file.read_bytes()
        independent = tasks.create(self.vault, "Independent waiting task", now=past)
        tasks.present(self.vault, independent["id"], "Proceed?", "fixture-delivery", now=past)
        _, expired_export = self.export("independent-of-task-read", stamp(past))
        read = tasks.read_json

        def delayed_read(path, *args):
            if path == task_file:
                raise PermissionError("Fixture task record temporarily unavailable")
            return read(path, *args)

        output = BytesIO()
        with patch("healdan.tasks.read_json", side_effect=delayed_read), patch("healdan.cli.sys.stdout") as stdout:
            with self.assertRaisesRegex(PermissionError, "task record temporarily unavailable"):
                tasks.create(self.vault, "Writer cannot assume free capacity")
            stdout.buffer = output
            code = cli.main(["--vault", str(self.root), "--state", str(self.state), "maintenance", "daily"])
        result = decode(output.getvalue())
        self.assertEqual((code, result["status"]), (5, "pending"), result)
        self.assertIn({"task": unavailable["id"], "reason": "Fixture task record temporarily unavailable"}, result["pending"])
        self.assertTrue(any(entry.get("material") == capture and "origin or deadline is unknown" in entry["reason"]
                            for entry in result["pending"]))
        self.assertEqual(task_file.read_bytes(), task_data)
        self.assertEqual(checkpoint.read_bytes(), data)
        self.assertTrue(cipher.is_file())
        self.assertFalse(expired_export.exists() or Path(independent["worktree"]).exists())
        self.assertEqual(tasks.get_task(self.vault, independent["id"])["state"], "cancelled")
        self.assertEqual(result["backup_result"]["status"], "complete", result)
        self.assertEqual(backups.verify_backup(self.vault, result["backup"])["status"], "complete")
        code, recovered = self.cli("maintenance", "daily")
        self.assertEqual((code, recovered["status"], recovered["backup_result"]["status"]), (0, "complete", "not_due"), recovered)
        self.assertFalse(checkpoint.exists() or cipher.exists())

    def test_daily_task_inventory_and_reconciliation_failures_are_isolated(self):
        self.configure_age(backup_interval_hours=24)
        self.change_policy(backup="scheduled")
        now = utc()
        expired = tasks.create(self.vault, "Expired disposable task", now=now - timedelta(days=2))
        worktree = Path(expired["worktree"])
        directory = self.vault.control / "tasks"
        task_file = tasks.task_path(self.vault, expired["id"])
        scandir, read = os.scandir, tasks.read_json
        reads = []

        @contextmanager
        def interrupted_scan(scan):
            def partial():
                yield next(scan)
                raise PermissionError("Fixture task inventory interrupted")
            with scan:
                yield partial()

        def scan(path):
            entries = scandir(path)
            return interrupted_scan(entries) if path in (directory, str(directory)) else entries

        def failed_clock_write(path, payload):
            if path == task_file:
                raise PermissionError("Fixture task clock write failed")
            return atomic(path, payload)

        def failed_reload(path, *args):
            if path == task_file:
                reads.append(path)
                if len(reads) == 2:
                    raise PermissionError("Fixture task reload failed")
            return read(path, *args)

        def scan_tasks(path):
            with patch("os.scandir", side_effect=scan):
                return tasks_json_paths(path)

        tasks_json_paths = tasks.json_paths
        with patch("healdan.tasks.json_paths", side_effect=scan_tasks):
            with self.assertRaisesRegex(PermissionError, "task inventory interrupted"):
                tasks.create(self.vault, "Writer cannot assume an empty inventory")
            result = maintenance.daily(self.vault, now)
        self.assertEqual(result["status"], "pending", result)
        self.assertIn({"task_inventory": "inventory", "reason": "Fixture task inventory interrupted"}, result["pending"])
        self.assertTrue(worktree.is_dir())
        self.assertEqual(backups.verify_backup(self.vault, result["backup"])["status"], "complete")
        cases = [(patch("healdan.tasks.atomic", side_effect=failed_clock_write), "Fixture task clock write failed"),
                 (patch("healdan.tasks.read_json", side_effect=failed_reload), "Fixture task reload failed")]
        for failure, reason in cases:
            with self.subTest(reason=reason), failure:
                result = maintenance.daily(self.vault, now + timedelta(hours=1))
                self.assertEqual(result["status"], "pending", result)
                self.assertIn({"task": expired["id"], "reason": reason}, result["pending"])
                self.assertEqual(result["backup_result"]["status"], "not_due", result)
                self.assertTrue(worktree.is_dir())
        resolved = maintenance.daily(self.vault, now + timedelta(hours=1))
        self.assertEqual(resolved["status"], "complete", resolved)
        self.assertFalse(worktree.exists())

    def test_daily_unreadable_plan_inventory_suspends_retention_but_runs_due_backup(self):
        self.configure_age(backup_interval_hours=24)
        self.change_policy(backup="scheduled")
        _, original = self.export("already-planned")
        now = utc("2026-02-15T00:00:00Z")
        plan = retention.plan(self.vault, now)
        path = self.vault.control / "deletions" / (plan["id"] + ".json")
        before = path.read_bytes()
        _, discovered = self.export("new-during-inventory-error")
        read = retention.read_json

        def delayed_read(target, *args, **kwargs):
            if target == path:
                raise PermissionError("Fixture plan inventory temporarily unavailable")
            return read(target, *args, **kwargs)

        with patch("healdan.retention.read_json", side_effect=delayed_read), patch("healdan.retention.execute") as execute:
            result = maintenance.daily(self.vault, now)
        execute.assert_not_called()
        self.assertEqual(result["status"], "pending", result)
        self.assertEqual(result["plans"], [])
        self.assertTrue(any(row.get("retention") == "inventory" and plan["id"] in row["reason"] and
                            "temporarily unavailable" in row["reason"] for row in result["pending"]))
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(original.is_file() and discovered.is_file())
        self.assertEqual(result["backup_result"]["status"], "complete", result)
        self.assertEqual(backups.verify_backup(self.vault, result["backup"])["status"], "complete")
        retry = maintenance.daily(Vault(self.root, self.state), now + timedelta(hours=1))
        self.assertEqual(retry["status"], "complete", retry)
        self.assertFalse(original.exists() or discovered.exists())

    def test_daily_unreadable_journal_directory_preserves_bytes_and_runs_due_backup(self):
        self.configure_age(backup_interval_hours=24)
        self.change_policy(backup="scheduled")
        material, origin = self.capture()
        cipher = self.state / "custody" / (material["id"] + ".age")
        checkpoint = origin / "nested" / "b.jsonl"
        data = checkpoint.read_bytes()
        now = utc("2026-02-15T00:00:00Z")
        retention.plan(self.vault, now)
        scandir = os.scandir
        for offset, name in enumerate(("deletions", "restorations")):
            with self.subTest(journal=name):
                directory = self.vault.control / name
                directory.mkdir(exist_ok=True)

                def unavailable(path):
                    if path in (directory, str(directory)):
                        raise PermissionError("Fixture journal directory temporarily unavailable: " + name)
                    return scandir(path)

                module = retention if name == "deletions" else custody
                original_paths = module.json_paths

                def scan_journal(path):
                    with patch("os.scandir", side_effect=unavailable):
                        return original_paths(path)

                with patch.object(module, "json_paths", side_effect=scan_journal):
                    if name == "deletions":
                        with self.assertRaisesRegex(PermissionError, "temporarily unavailable"):
                            retention.pending_deletion_paths(self.vault)
                    else:
                        with self.assertRaisesRegex(PermissionError, "temporarily unavailable"):
                            custody.pending_restoration(self.vault, material["id"])
                        checks = setup.doctor(self.vault)["checks"]
                        findings, _ = linting.collect(self.vault)
                        self.assertTrue(any(check["name"] == "custody:restorations" and not check["passed"] and
                                            "temporarily unavailable" in check["detail"] for check in checks))
                        self.assertTrue(any(row["category"] == "custody" and row["key"] == "restorations" and
                                            "temporarily unavailable" in row["message"] for row in findings.values()))
                    result = maintenance.daily(self.vault, now + timedelta(days=offset))
                self.assertEqual(result["status"], "pending", result)
                self.assertTrue(any("Fixture journal directory temporarily unavailable" in row["reason"] for row in result["pending"]))
                self.assertEqual(checkpoint.read_bytes(), data)
                self.assertTrue(cipher.is_file())
                self.assertEqual(result["backup_result"]["status"], "complete", result)
                self.assertEqual(backups.verify_backup(self.vault, result["backup"])["status"], "complete")
        done = maintenance.daily(Vault(self.root, self.state), now + timedelta(days=1, hours=1))
        self.assertEqual(done["status"], "complete", done)
        self.assertFalse(checkpoint.exists() or cipher.exists())

    def test_explicit_retention_execute_reports_unreadable_plan_and_preserves_input_errors(self):
        _, target = self.export("explicit-plan-retry", stamp(utc() - timedelta(days=8)))
        original = target.read_bytes()
        plan = retention.plan(self.vault)
        identifier = plan["id"]
        plan_path = self.vault.control / "deletions" / (identifier + ".json")
        saved = plan_path.read_bytes()
        read = Path.read_bytes

        def delayed_read(path):
            if path == plan_path:
                raise PermissionError("Fixture plan temporarily unavailable")
            return read(path)

        output = BytesIO()
        with patch.object(Path, "read_bytes", delayed_read), patch("healdan.cli.sys.stdout") as stdout:
            stdout.buffer = output
            code = cli.main(["--vault", str(self.root), "--state", str(self.state), "maintenance", "execute", identifier])
        self.assertEqual(code, 5)
        self.assertEqual(decode(output.getvalue()), {"id": identifier, "status": "pending",
                                                    "pending": [{"reason": "Fixture plan temporarily unavailable"}]})
        self.assertEqual(plan_path.read_bytes(), saved)
        self.assertEqual(target.read_bytes(), original)
        code, error = self.cli("maintenance", "execute", "../outside")
        self.assertEqual((code, error["error"]), (2, "Path must be relative and confined"))
        code, error = self.cli("maintenance", "execute", "missing-plan")
        self.assertEqual((code, error["error"]), (4, "Required regular file is missing: missing-plan.json"))
        code, recovered = self.cli("maintenance", "execute", identifier)
        self.assertEqual((code, recovered["status"]), (0, "complete"), recovered)
        self.assertFalse(target.exists())

    def test_explicit_retention_execute_recovers_missing_task_origin_in_the_same_plan(self):
        self.age()
        past = utc() - timedelta(days=40)
        task = tasks.create(self.vault, "Closed task with temporarily unavailable record", now=past)
        checkpoint = self.state / "plan-recovery" / "checkpoint.jsonl"
        atomic(checkpoint, b"ordinary conversation fixture")
        capture = custody.capture_tree(self.vault, checkpoint.parent, task=task["id"], classification="common")
        cipher = self.state / "custody" / (capture + ".age")
        original = {path: path.read_bytes() for path in (checkpoint, cipher)}
        with patch("healdan.tasks.stamp", return_value=stamp(past)):
            tasks.preserve_and_close(self.vault, task["id"])
        task_file = tasks.task_path(self.vault, task["id"])
        read = Path.read_bytes
        failed_reads = []

        def invoke(*args, unavailable):
            def delayed_read(path):
                if path == unavailable:
                    failed_reads.append(path)
                    raise PermissionError("Fixture task closure temporarily unavailable")
                return read(path)

            output = BytesIO()
            with patch.object(Path, "read_bytes", delayed_read), patch("healdan.cli.sys.stdout") as stdout:
                stdout.buffer = output
                code = cli.main(["--vault", str(self.root), "--state", str(self.state), "maintenance", *args])
            return code, decode(output.getvalue())

        code, plan = invoke("plan", unavailable=task_file)
        self.assertEqual(code, 0, plan)
        identifier = plan["id"]
        code, pending = invoke("execute", identifier, unavailable=task_file)
        self.assertEqual((code, pending["status"], pending["digest"]), (5, "pending", plan["digest"]), pending)
        self.assertTrue(any(row["material"] == capture and "origin or deadline is unknown" in row["reason"]
                            for row in pending["pending"]))
        self.assertEqual({path: path.read_bytes() for path in original}, original)
        self.assertNotIn("closed_at", custody.materials(self.vault)[capture])

        independent = tasks.create(self.vault, "Unrelated task outside the original plan")
        other = self.state / "outside-plan" / "checkpoint.jsonl"
        atomic(other, b"unrelated conversation fixture")
        custody.capture_tree(self.vault, other.parent, task=independent["id"], classification="common")
        unrelated_file = tasks.task_path(self.vault, independent["id"])
        failed_reads.clear()
        code, completed = invoke("execute", identifier, unavailable=unrelated_file)
        self.assertEqual((code, completed["id"], completed["status"], completed["digest"]),
                         (0, identifier, "complete", plan["digest"]), completed)
        self.assertFalse(checkpoint.exists() or cipher.exists())
        self.assertEqual(other.read_bytes(), b"unrelated conversation fixture")
        restored = custody.materials(self.vault)[capture]
        self.assertEqual(restored["closed_at"], stamp(past))
        entries = [entry for entry in completed["entries"] if entry["material"] == capture]
        for entry in entries:
            self.assertEqual(entry["intent"]["plan_digest"], plan["digest"])
            self.assertEqual(entry["receipt"], restored["copies"][entry["copy_index"]]["deletion_receipt"])
        self.assertEqual({retention.slot(entry) for entry in entries},
                         {retention.slot(entry) for entry in plan["entries"] if entry["material"] == capture})
        self.assertEqual(invoke("execute", identifier, unavailable=unrelated_file), (0, completed))
        self.assertEqual(failed_reads, [])

    def test_overlapping_rounds_reconcile_all_plans_and_discover_new_slots(self):
        self.change_policy()
        _, first = self.export("first")
        _, second = self.export("second")
        _, later = self.export("later", "2026-02-01T00:00:00Z")
        initial = "2026-02-04T00:00:00Z"
        plans = [retention.plan(self.vault, initial)["id"] for _ in range(2)]
        save = retention.save_material

        def interrupt(vault, record):
            save(vault, record)
            if record["id"] == "first":
                raise SystemExit("interrupted after updating custody")

        with patch("healdan.retention.save_material", side_effect=interrupt), self.assertRaises(SystemExit):
            retention.execute(self.vault, plans[0], initial)
        self.assertFalse(first.exists())
        self.assertTrue(second.exists() and later.exists())
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(maintenance.daily, Vault(self.root, self.state), "2026-02-09T00:00:00Z") for _ in range(2)]
            self.assertTrue(all(future.result()["status"] == "complete" for future in futures))
        self.assertFalse(first.exists() or second.exists() or later.exists())
        known = [read_json(self.vault.control / "deletions" / (p + ".json")) for p in plans]
        for left, right in zip(known[0]["entries"], known[1]["entries"]):
            self.assertEqual(left["receipt"], right["receipt"])

    def test_retention_execution_verifies_the_current_policy_once_per_plan(self):
        self.change_policy(backup="off")
        self.change_policy(backup="manual")
        now = utc()
        retired = [self.export(f"eligible-{index}", stamp(now - timedelta(days=10)))[1] for index in range(3)]
        first = retention.plan(self.vault, now)
        with patch("healdan.storage_policy.authorization", wraps=storage_policy.authorization) as checked:
            result = retention.execute(self.vault, first["id"], now)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(checked.call_count, 2)
        self.assertFalse(any(target.exists() for target in retired))

        protected = [self.export(f"protected-{index}", stamp(now - timedelta(days=10)))[1] for index in range(3)]
        second = retention.plan(self.vault, now)
        self.change_policy(backup="manual", retention_mode="keep_forever")
        for _ in range(2):
            with patch("healdan.storage_policy.authorization", wraps=storage_policy.authorization) as checked:
                result = retention.execute(self.vault, second["id"], now)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(checked.call_count, 3)
            self.assertTrue(all(entry["status"] == "preserved" for entry in result["entries"]))
        self.assertTrue(all(target.exists() for target in protected))

    def test_uncertain_copy_paths_preserve_shared_bytes_and_isolate_other_effects(self):
        self.change_policy()
        unsafe, first = self.export("uncertain-a", data=b"matching export")
        eligible, second = self.export("eligible-b")
        shared, third = self.export("shared-c", data=b"matching export")
        unsafe["copies"].append(dict(unsafe["copies"][0], path=third.name, unavailable=True))
        custody.save_material(self.vault, unsafe)
        now = "2026-02-01T00:00:00Z"
        physical_path = retention.copy_path

        def unresolved(vault, copy):
            if copy.get("unavailable") or copy["path"] == first.name:
                raise Blocked("Fixture could not identify custody copy", 5)
            return physical_path(vault, copy)

        plan = retention.plan(self.vault, now)
        with patch("healdan.retention.copy_path", side_effect=unresolved):
            result = retention.execute(self.vault, plan["id"], now)
        self.assertEqual({item["material"] for item in result["pending"]}, {unsafe["id"], shared["id"]})
        self.assertTrue(first.is_file() and third.is_file())
        self.assertFalse(second.exists())
        self.assertEqual(custody.materials(self.vault)[eligible["id"]]["copies"][0]["status"], "deleted")

    def test_restore_merges_current_material_and_session(self):
        self.age()
        record, origin = self.capture(native=True)
        destination = self.state / "recovery"
        decrypt = custody.decrypt
        operation = record["session"]

        def interleave(vault, cipher):
            access = Vault(self.root, self.state)
            custody.hold(access, record["id"], "Registered during decrypt", "human")
            material = custody.materials(access)[record["id"]]
            material["dependencies"].append("evidence added during decrypt")
            copy = material["copies"][1]
            (origin / copy["path"]).unlink()
            copy.update(status="deleted", deleted_at=stamp())
            custody.save_material(access, material)
            session = tasks.get_session(access, operation)
            session["state"] = "completed"
            session["usage"]["input_tokens"] = 99
            atomic(access.control / "sessions" / (operation + ".json"), session)
            return decrypt(vault, cipher)

        with patch("healdan.custody.decrypt", side_effect=interleave):
            result = custody.restore_capture(self.vault, record["id"], destination)
        material = custody.materials(self.vault)[record["id"]]
        self.assertEqual(material["copies"][1]["status"], "deleted")
        self.assertEqual(len(material["holds"]), 1)
        self.assertEqual(material["dependencies"], ["evidence added during decrypt"])
        self.assertEqual(len([copy for copy in material["copies"] if copy.get("restoration")]), 2)
        session = tasks.get_session(self.vault, operation)
        self.assertEqual((session["state"], session["usage"]["input_tokens"]), ("completed", 99))
        self.assertEqual(session["reconstruction"]["archive_sha256"], result["archive_sha256"])

    def test_restore_replays_interrupted_staging_and_publication_across_processes(self):
        self.age()
        record, origin = self.capture()
        identifier = record["id"]
        destination = self.base / "recovery"
        write = custody.write_staged_member
        with patch("healdan.custody.verified_capture", side_effect=SystemExit("interrupted before staging")), self.assertRaises(SystemExit):
            custody.restore_capture(self.vault, identifier, destination)
        journal_path = next((self.vault.control / "restorations").glob("*.json"))
        unbound = self.base / read_json(journal_path)["stage"]
        atomic(unbound / "outside-journal", b"unbound stage bytes")

        def interrupt_member(target, data):
            if target.name == "b.jsonl":
                write(target, data[:4])
                raise SystemExit("interrupted during second member")
            write(target, data)

        with patch("healdan.custody.write_staged_member", side_effect=interrupt_member), self.assertRaises(SystemExit):
            custody.restore_capture(self.vault, identifier, destination)
        journal = read_json(journal_path)
        self.assertEqual(journal["status"], "staging")
        self.assertEqual(journal["binding"]["cipher_sha256"], record["cipher_sha256"])
        self.assertEqual(journal["binding"]["plain_sha256"], record["plain_sha256"])
        self.assertEqual(set(journal["inventory"]), {"a.jsonl", "nested/b.jsonl"})
        self.assertTrue((self.base / journal["stage"] / "a.jsonl").is_file())
        self.assertNotEqual(self.base / journal["stage"], unbound)
        self.assertEqual(list(unbound.iterdir()), [unbound / "outside-journal"])
        self.assertFalse(destination.exists())
        with patch("healdan.custody.finish_reconstruction", side_effect=SystemExit("interrupted after publishing")), self.assertRaises(SystemExit):
            custody.restore_capture(self.vault, identifier, destination)
        self.assertEqual(read_json(journal_path)["status"], "publishing")
        code, result = self.cli("session", "restore", identifier, destination)
        self.assertEqual(code, 0, result)
        self.assertEqual(self.cli("session", "restore", identifier, destination), (0, result))
        self.assertEqual((destination / "nested/b.jsonl").read_bytes(), (origin / "nested/b.jsonl").read_bytes())
        receipts = [read_json(path) for path in (self.vault.control / "receipts").glob("*.json")]
        self.assertEqual(sum(rcpt["kind"] == "reconstruction" for rcpt in receipts), 1)

    def test_restore_collision_unsafe_path_and_tampered_capture_are_diagnosable(self):
        self.age()
        record, _ = self.capture()
        identifier = record["id"]
        occupied = self.base / "occupied"
        sentinel = occupied / "a.jsonl"
        atomic(sentinel, b"exclude these existing bytes")
        for target, reason in ((occupied, "collision"), (self.root / "unsafe", "external")):
            code, result = self.cli("session", "restore", identifier, target)
            self.assertEqual(code, 5, result)
            self.assertIn(reason, result["error"])
        self.assertEqual(sentinel.read_bytes(), b"exclude these existing bytes")
        cipher = self.state / "custody" / (identifier + ".age")
        atomic(cipher, b"tampered ciphertext")
        code, result = self.cli("session", "restore", identifier, self.base / "tampered")
        self.assertEqual(code, 5, result)
        self.assertIn("Ciphertext changed", result["error"])
        self.assertEqual(len(custody.materials(self.vault)[identifier]["copies"]), len(record["copies"]))
        self.assertEqual(len(list((self.vault.control / "restorations").glob("*.json"))), 3)

    def test_restore_to_existing_inventory_reuses_only_active_matching_slots(self):
        self.age()
        self.change_policy()
        record, origin = self.capture(native=True)
        identifier = record["id"]
        for relative in ("a.jsonl", "nested/b.jsonl"):
            (origin / relative).unlink()
        (origin / "nested").rmdir()
        # One slot recorded a completed removal before these bytes are published again.
        record["copies"][2].update(status="deleted", deleted_at="2026-01-21T00:00:00Z", deletion_receipt="legacy-copy-fixture")
        custody.save_material(self.vault, record)
        proof = self.native_approval(record, origin)
        saved = custody.materials(self.vault)[identifier]
        self.assertEqual(saved["copies"][1], record["copies"][1])
        self.assertEqual(saved["copies"][2], record["copies"][2])
        self.assertEqual(len(saved["copies"]), 4)
        self.assertEqual(saved["copies"][3]["path"], "nested/b.jsonl")
        self.assertIn("restoration", saved["copies"][3])
        saved["native_recovery"] = self.signed(proof, "recovery")
        custody.save_material(self.vault, saved)
        self.assertEqual(maintenance.daily(self.vault, "2026-02-10T00:00:00Z")["status"], "complete")
        self.assertFalse((origin / "a.jsonl").exists())
        self.assertFalse((origin / "nested/b.jsonl").exists())

    def test_restore_waits_for_offline_external_parent_without_losing_cipher(self):
        self.age()
        self.change_policy()
        material, _ = self.capture()
        identifier = material["id"]
        destination = self.base / "offline-parent" / "recovered"
        cipher = self.state / "custody" / (identifier + ".age")
        before = cipher.read_bytes()
        with self.assertRaisesRegex(Blocked, "parent is offline"):
            custody.restore_capture(self.vault, identifier, destination)
        result = maintenance.daily(self.vault, "2026-02-12T00:00:00Z")
        self.assertTrue(any("pending restoration" in row["reason"] for row in result["pending"]))
        self.assertEqual(cipher.read_bytes(), before)
        destination.parent.mkdir()
        code, restore = self.cli("session", "restore", identifier, destination)
        self.assertEqual(code, 0, restore)
        self.assertEqual((destination / "a.jsonl").read_bytes(), b"first synthetic conversation file")
        self.assertEqual(restore["status"], "complete")

    def test_recovery_launch_materializes_private_profile_and_keeps_the_external_restore(self):
        self.age()
        record, origin = self.capture(native=True)
        operation = record["session"]
        session_path = self.vault.control / "sessions" / (operation + ".json")
        session = tasks.get_session(self.vault, operation)
        session["launches"].append({"id": "synthetic-prior-launch"})
        atomic(session_path, session)
        external = self.base / "operator export"
        restoration = custody.restore_capture(self.vault, record["id"], external)
        copies = {path.relative_to(external): path.read_bytes() for path in external.rglob("*.jsonl")}
        receipt_path = self.vault.control / "receipts" / (restoration["receipt"] + ".json")
        external_receipt = receipt_path.read_bytes()
        profile = self.state / "recovery-profiles" / custody.restoration_id(self.vault, record["id"], external)
        authentications = []
        process_launches = []
        active_plan = None
        start_process = launcher.subprocess.Popen

        def mocked_command(args, **kwargs):
            if args[1:3] == ["auth", "status"]:
                authentications.append(Path(kwargs["env"]["CLAUDE_CONFIG_DIR"]))
                if len(authentications) > 1:
                    atomic(profile / ".credentials.json", canonical({"fixture": len(authentications)}))
                return SimpleNamespace(returncode=1 if len(authentications) == 1 else 0)
            self.assertEqual(args[0], "ps")
            return SimpleNamespace(stdout=b"synthetic fixture process identity")

        def mocked_process(args, *extra, **kwargs):
            if args[0] != str(self.base / "srt"):
                return start_process(args, *extra, **kwargs)
            process_launches.append(args)
            self.assertEqual(Path(kwargs["env"]["CLAUDE_CONFIG_DIR"]), profile)
            self.assertIn(str(profile / "settings.json"), args)
            self.assertNotIn(str(external), " ".join(args))
            def communicate(context, timeout):
                self.assertIn(b"Recovery verification only", context)
                if active_plan is not None:
                    result = retention.execute(self.vault, active_plan["id"], "2026-02-15T00:00:00Z")
                    self.assertTrue(any("in use or awaiting launch reconciliation" in row["reason"] for row in result["pending"]))
                    self.assertTrue((profile / "a.jsonl").is_file())
                kwargs["stdout"].write(canonical({"session_id": session["uuid"], "usage": {"input_tokens": 2}}))
            return SimpleNamespace(pid=421, returncode=0, communicate=communicate)

        write_member = custody.write_staged_member

        def interrupted_write(path, body):
            write_member(path, body)
            raise SystemExit("Fixture interrupted before internal profile publication")

        with patch("healdan.build.require_active"), patch("healdan.launcher._probe"), \
                patch("healdan.launcher.executable", side_effect=lambda name: str(self.base / name)), \
                patch("healdan.launcher.run", side_effect=mocked_command), \
                patch("healdan.launcher.subprocess.Popen", side_effect=mocked_process):
            with patch("healdan.custody.write_staged_member", side_effect=interrupted_write):
                with self.assertRaises(SystemExit):
                    launcher.launch(self.vault, operation, resume=True, recovery_material=record["id"])
            self.assertFalse(profile.exists() or authentications or process_launches)
            with self.assertRaises(Blocked) as auth_error:
                launcher.launch(self.vault, operation, resume=True, recovery_material=record["id"])
            self.assertIn(str(profile), str(auth_error.exception))
            self.assertTrue(profile.is_dir())
            atomic(profile / ".credentials.json", b'{"fixture":"authenticated"}')
            launch = launcher.launch(self.vault, operation, resume=True, recovery_material=record["id"])
            proof = {"material": record["id"], "cipher_sha256": record["cipher_sha256"], "plain_sha256": record["plain_sha256"],
                     "reconstruction_sha256": record["plain_sha256"], "launch_receipt": launch["id"], "uuid": session["uuid"],
                     "action": session["action"], "usage": launch["cumulative_usage"]}
            material = custody.materials(self.vault)[record["id"]]
            material["native_recovery"] = self.signed(proof, "recovery")
            custody.save_material(self.vault, material)
            active_plan = retention.plan(self.vault, "2026-02-15T00:00:00Z")
            launcher.launch(self.vault, operation, resume=True, recovery_material=record["id"])

        current = tasks.get_session(self.vault, operation)
        self.assertEqual((current["recovery_profile"], current["reconstruction"]["destination"]), (str(profile), str(external)))
        self.assertEqual(authentications, [profile] * 3)
        self.assertEqual(read_json(profile / ".credentials.json"), {"fixture": 3})
        self.assertEqual(len(process_launches), 2)
        self.assertEqual({name: (external / name).read_bytes() for name in copies}, copies)
        self.assertEqual(receipt_path.read_bytes(), external_receipt)
        self.assertEqual((profile / "a.jsonl").read_bytes(), (origin / "a.jsonl").read_bytes())
        self.assertTrue(any(copy.get("root") == str(profile) and copy["kind"] == "native"
                            for copy in custody.materials(self.vault)[record["id"]]["copies"]))

    def test_recovery_profile_accepts_a_legacy_reconstruction_receipt(self):
        self.age()
        record, _ = self.capture(native=True)
        session = tasks.get_session(self.vault, record["session"])
        original = self.state / "legacy-profile"
        _, plain = custody.verified_capture(self.vault, record)
        reconstruction = {**custody.restore_tree(decode(plain), original), "material": record["id"]}
        session.update(recovery_profile=str(original), reconstruction=reconstruction)
        atomic(self.vault.control / "sessions" / (session["operation"] + ".json"), session)
        with self.vault.locked():
            with self.assertRaisesRegex(Blocked, "receipt is missing or changed"):
                custody.recovery_profile(self.vault, session, record["id"])
        receipt = self.vault.receipt("reconstruction", reconstruction)
        with self.vault.locked():
            internal, _ = custody.recovery_profile(self.vault, session, record["id"])
        self.assertEqual(internal.parent, self.state / "recovery-profiles")
        self.assertEqual((internal / "a.jsonl").read_bytes(), (original / "a.jsonl").read_bytes())
        self.assertEqual(session["reconstruction"], reconstruction)
        self.assertEqual(read_json(self.vault.control / "receipts" / (receipt + ".json"))["payload"], reconstruction)
        capabilities = read_json(Path(compatibility.__file__).with_name("controller_formats.json"))
        capabilities["journal"].remove("healdan-recovery-profile-v1")
        with self.assertRaisesRegex(Blocked, "healdan-recovery-profile-v1"):
            compatibility.check(self.vault, capabilities)

    def test_recovery_profile_fails_closed_before_runtime_and_after_authentication(self):
        self.age()
        task = tasks.create(self.vault, "Verified profile inventory fixture")
        session = tasks.new_session(self.vault, task["id"], "review", "editor", "fixture")
        operation = session["operation"]
        origin = launcher.profile(self.vault, operation)
        transcript = origin / "conversation.jsonl"
        atomic(transcript, b'{"fixture":"archived conversation"}\n')
        session_path = self.vault.control / "sessions" / (operation + ".json")
        session["launches"].append({"id": "synthetic-prior-launch"})
        atomic(session_path, session)
        identifier = custody.capture_tree(self.vault, origin, task=task["id"], classification="common", session=operation)
        custody.restore_capture(self.vault, identifier, self.base / "operator export")
        with self.vault.locked():
            profile, journal = custody.recovery_profile(self.vault, tasks.get_session(self.vault, operation), identifier)
        atomic(profile / ".credentials.json", b'{"fixture":"authentication state"}')
        custody.check_recovery_inventory(profile, journal)
        session_before = session_path.read_bytes()
        verified_members = {name: (profile / name).read_bytes() for name in journal["inventory"]}
        measure = custody.file_digest

        for phase, member in (("before", "conversation.jsonl"), ("after", "settings.json")):
            with self.subTest(phase=phase):
                authenticated = False

                def authenticate(args, **kwargs):
                    nonlocal authenticated
                    self.assertEqual(args[1:3], ["auth", "status"])
                    authenticated = True
                    return SimpleNamespace(returncode=0)

                def measured_digest(path):
                    if path == profile / member and (phase == "before" or authenticated):
                        return "0" * 64
                    return measure(path)

                with patch("healdan.custody.file_digest", side_effect=measured_digest), \
                        patch("healdan.build.require_active"), patch("healdan.launcher._probe") as probe, \
                        patch("healdan.launcher.executable", side_effect=lambda name: str(self.base / name)), \
                        patch("healdan.launcher.run", side_effect=authenticate) as runtime, \
                        patch("healdan.launcher.subprocess") as process, patch.object(Vault, "receipt") as receipt:
                    with self.assertRaisesRegex(Blocked, "member differs.*" + member) as blocked:
                        launcher.launch(self.vault, operation, resume=True, recovery_material=identifier)
                    self.assertEqual(blocked.exception.code, 5)
                    self.assertEqual((probe.call_count, runtime.call_count), (0, 0) if phase == "before" else (1, 1))
                    process.Popen.assert_not_called()
                    receipt.assert_not_called()
                self.assertEqual(session_path.read_bytes(), session_before)
                self.assertEqual({name: (profile / name).read_bytes() for name in verified_members}, verified_members)

    def test_recovery_profile_rechecks_resumed_publication_before_runtime(self):
        self.age()
        record, origin = self.capture(native=True)
        identifier = record["id"]
        operation = record["session"]
        session_path = self.vault.control / "sessions" / (operation + ".json")
        session = tasks.get_session(self.vault, operation)
        session["launches"].append({"id": "synthetic-prior-launch"})
        atomic(session_path, session)
        external = self.base / "external restoration"
        custody.restore_capture(self.vault, identifier, external)
        source = custody.restoration_id(self.vault, identifier, external)
        profile = self.state / "recovery-profiles" / source
        internal = digest(["recovery-profile", self.vault.identity, source])
        journal_path = self.vault.control / "restorations" / (internal + ".json")
        receipts = self.vault.control / "receipts"

        with self.vault.locked(), patch("healdan.custody.finish_reconstruction", side_effect=SystemExit("fixture publication stopped")):
            with self.assertRaises(SystemExit):
                custody.recovery_profile(self.vault, tasks.get_session(self.vault, operation), identifier)
        self.assertEqual(read_json(journal_path)["status"], "publishing")
        self.assertEqual((profile / "a.jsonl").read_bytes(), (origin / "a.jsonl").read_bytes())
        session_before = session_path.read_bytes()
        receipts_before = set(receipts.glob("*.json"))

        def refuse(path, journal):
            self.assertEqual(path, profile)
            self.assertEqual(journal["status"], "complete")
            self.assertEqual(read_json(journal_path), journal)
            raise Blocked("Fixture recovery inventory verification refused", 5)

        with patch("healdan.custody.check_recovery_inventory", side_effect=refuse) as verified, \
                patch("healdan.build.require_active"), \
                patch("healdan.launcher._probe", side_effect=AssertionError("Unexpected recovery probe")) as probe, \
                patch("healdan.launcher.run", side_effect=AssertionError("Unexpected recovery authentication")) as runtime, \
                patch("healdan.launcher.subprocess") as process:
            with self.assertRaisesRegex(Blocked, "inventory verification refused") as blocked:
                launcher.launch(self.vault, operation, resume=True, recovery_material=identifier)
            self.assertEqual(blocked.exception.code, 5)
            verified.assert_called_once()
            probe.assert_not_called()
            runtime.assert_not_called()
            process.Popen.assert_not_called()
        self.assertEqual(session_path.read_bytes(), session_before)
        reconstruction_receipt, = set(receipts.glob("*.json")) - receipts_before
        self.assertEqual(read_json(reconstruction_receipt)["kind"], "reconstruction")
        with self.vault.locked():
            recovered, journal = custody.recovery_profile(self.vault, tasks.get_session(self.vault, operation), identifier)
        self.assertEqual((recovered, journal["result"]["receipt"]), (profile, reconstruction_receipt.stem))
        self.assertEqual(set(receipts.glob("*.json")), receipts_before | {reconstruction_receipt})

    def test_scheduled_daily_isolates_custody_findings_and_keeps_trial_gate(self):
        self.configure_age()
        record, _ = self.capture()
        destination = self.base / "occupied-restore"
        atomic(destination / "other.txt", b"external fixture")
        with self.assertRaisesRegex(Blocked, "collision"):
            custody.restore_capture(self.vault, record["id"], destination)
        findings = [row for row in setup.doctor(self.vault)["checks"] if row["name"].startswith("custody:")]
        self.assertEqual(len(findings), 1)
        trial = {"name": "trial:launchd", "passed": False}
        with patch("healdan.setup.doctor", return_value={"ready": False, "checks": [*findings, trial]}):
            with self.assertRaisesRegex(Blocked, "running a scheduled job"):
                maintenance.run_scheduled(self.vault, "daily", self.vault.identity)
            trial["passed"] = True
            result = maintenance.run_scheduled(self.vault, "daily", self.vault.identity)
        self.assertEqual(result["backup_result"]["status"], "complete", result)
        self.assertTrue(backups.verify_backup(self.vault, result["backup"])["copies"])
        self.assertEqual((destination / "other.txt").read_bytes(), b"external fixture")

    def test_scheduled_maintenance_reports_custody_once_without_routine_decryption(self):
        first_root = self.configure_age(backup_interval_hours=24)
        now = utc()
        old = backups.create(self.vault, "long", now + timedelta(days=2), now=now - timedelta(days=2))
        current_root = self.base / "current-backup"
        current_root.mkdir()
        self.vault.config["backup_destinations"] = [str(current_root)]
        atomic(self.vault.config_path, self.vault.config)
        self.change_policy(backup="scheduled")
        old_cipher = first_root / (old["id"] + ".age")
        record, _ = self.capture()
        record["closed_at"] = stamp(now)
        custody.save_material(self.vault, record)
        capture = self.state / "custody" / (record["id"] + ".age")

        with patch("healdan.backups.decrypt", side_effect=AssertionError("Routine backup check must not decrypt")), \
                patch("healdan.custody.decrypt", side_effect=AssertionError("Routine capture check must not decrypt")):
            self.assertEqual(custody.integrity_findings(self.vault), [])
            self.assertTrue(old_cipher.is_file() and capture.is_file())
        atomic(capture, b"corrupt disposable capture")
        first_root.rename(first_root.with_name("historical backup offline"))
        doctor = setup.doctor

        def configured(vault, *, check_custody=True):
            report = doctor(vault, check_custody=check_custody)
            checks = [row for row in report["checks"] if row["name"].startswith("custody:")]
            checks.append({"name": "trial:launchd", "passed": True})
            return {"ready": all(row["passed"] for row in checks), "checks": checks}

        def run_job(job):
            output = BytesIO()
            with patch("healdan.cli.sys.stdout") as stdout:
                stdout.buffer = output
                code = cli.main(["--vault", str(self.root), "--state", str(self.state), "--vault-id", self.vault.identity,
                                 "maintenance", "run-scheduled", job])
            return code, decode(output.getvalue())

        with patch("healdan.setup.doctor", side_effect=configured), \
                patch("healdan.custody.integrity_findings", wraps=custody.integrity_findings) as audit:
            code, daily = run_job("daily")
        self.assertEqual((code, daily["status"], daily["backup_result"]["status"]), (5, "pending", "complete"), daily)
        audit.assert_called_once()
        rows = {row["custody"]: row["reason"] for row in daily["pending"] if "custody" in row}
        self.assertIn("Ciphertext changed", rows[record["id"]])
        self.assertIn("Required regular file is missing", rows[old["id"]])
        self.assertEqual(backups.verify_backup(self.vault, daily["backup"])["status"], "complete")
        with patch("healdan.setup.doctor", side_effect=configured), \
                patch("healdan.backups.decrypt", side_effect=AssertionError("Scheduled lint must not decrypt")), \
                patch("healdan.custody.decrypt", side_effect=AssertionError("Scheduled lint must not decrypt")):
            code, lint = run_job("lint")
        self.assertEqual((code, lint["status"]), (5, "complete"), lint)
        self.assertEqual({row["key"] for row in lint["findings"].values() if row["category"] == "custody"}, set(rows))

        with patch("healdan.setup.doctor", side_effect=configured), \
                patch("healdan.linting.materials", side_effect=PermissionError("Fixture custody inventory temporarily unavailable")):
            code, lint = run_job("lint")
        self.assertEqual((code, lint.get("status")), (5, "partial"), lint)
        self.assertIn({"category": "custody", "error": "Fixture custody inventory temporarily unavailable"}, lint["errors"])
        self.assertIn("query:coverage", lint["findings"])

        with patch("healdan.maintenance.platform.system", return_value="Darwin"), \
                patch("healdan.setup.doctor", side_effect=configured), \
                patch("healdan.maintenance.schedule_definitions", return_value=[]):
            self.assertTrue(maintenance.schedule(self.vault, activate=True)["activated"])

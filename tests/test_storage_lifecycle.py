from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from support import VaultTest
from healdan import backups, compatibility, custody, inbox, linting, maintenance, retention, setup, storage_policy, tasks
from healdan.core import Blocked, Vault, atomic, decode, digest, read_json, stamp, utc


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
        closed = tasks.preserve_and_close(self.vault, task["id"])
        material = custody.materials(self.vault)[closed["preservation"]]
        plain = custody.decrypt(self.vault, custody.capture_copy(self.vault, material), keys[1])
        self.assertTrue(any(name.endswith("draft.txt") for name in decode(plain)["files"]))
        self.assertFalse(closed["capacity_held"])
        self.assertFalse(draft.exists())

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
        material["native_recovery"] = self.signed(proof, "recovery")
        custody.save_material(self.vault, material)
        result = maintenance.daily(self.vault, now)
        self.assertEqual(result["status"], "complete", result)
        self.assertFalse(cipher.exists() or (origin / "a.jsonl").exists())
        copies = custody.materials(self.vault)[identifier]["copies"]
        self.assertTrue(all(c["status"] == "deleted" and c.get("deletion_receipt") for c in copies))

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

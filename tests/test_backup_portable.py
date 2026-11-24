"""Portable backups with disposable Git, OpenSSH and age fixtures."""
from copy import deepcopy
from datetime import timedelta
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from support import VaultTest, controller_environment
from healdan import admission, backup_recovery, backup_snapshot, backups, binding, compatibility, custody, inbox, maintenance, retention, storage_policy, tasks, trials
from healdan.core import Blocked, Vault, atomic, canonical, decode, digest, git, read_json, run, stamp, utc
from healdan.setup import initialize
from healdan.signing import envelope, human_sign


class BackupPortable(VaultTest):
    def configure(self, count=1):
        self.identities = self.age()
        self.destinations = [self.base / f"replica-{index}" for index in range(count)]
        for directory in self.destinations:
            directory.mkdir()
        self.vault.config["backup_destinations"] = list(map(str, self.destinations))
        atomic(self.vault.config_path, self.vault.config)
        self.trust = {"age_identity": self.identities[1], "backup_signers": self.vault.config["backup_allowed_signers"],
                      "allowed_signers": self.signers}

    def create(self, kind="long", expiry=None, members=()):
        return backups.create(self.vault, kind, expiry or utc() + timedelta(days=2), members)

    def paths(self, record, index=0):
        return (self.destinations[index] / record["copies"][index]["manifest"],
                self.destinations[index] / record["copies"][index]["path"])

    def restore(self, record, destination=None, state=None, *, paths=None, remap=None):
        return backups.restore_portable(record["id"], destination or self.base / "recovered", *(paths or self.paths(record)),
                                       state=state or self.base / "recovered-state", remap=remap, **self.trust)

    def portable_cli(self, *args, paths, state):
        manifest, replica = paths
        result = run([sys.executable, "-m", "healdan", "--state", state, *args,
                      "--manifest", manifest, "--replica", replica, "--age-identity", self.identities[1],
                      "--backup-allowed-signers", self.trust["backup_signers"], "--allowed-signers", self.signers],
                     cwd=self.base, env=controller_environment(), check=False)
        self.assertEqual(result.stderr, b"")
        return result.returncode, decode(result.stdout)

    def commit(self, name):
        git(self.root, "add", "-A")
        return git(self.root, "commit", "-m", name)

    def tracked_modes(self):
        files = {"templates/regular.txt": (b"regular file\n", 0o644),
                 "templates/executable.sh": (b"#!/bin/sh\nexit 0\n", 0o755)}
        for name, (body, _) in files.items():
            atomic(self.root / name, body)
        git(self.root, "add", "--", *files)
        git(self.root, "update-index", "--chmod=+x", "--", "templates/executable.sh")
        git(self.root, "commit", "-m", "Tracked regular and executable fixtures")
        return files

    def assert_tracked_modes(self, root, files, mask):
        entries = {name: mode for name, mode, _, _ in backup_snapshot.tree_entries(root, "HEAD")}
        for name, (body, mode) in files.items():
            self.assertEqual((root / name).read_bytes(), body)
            self.assertEqual(entries[name], f"100{mode:o}")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), mode & ~mask)
        self.assertFalse(git(root, "status", "--porcelain", "--", *files))

    def test_1_portable_restores_regular_and_executable_git_modes(self):
        self.configure()
        files = self.tracked_modes()
        record = self.create()
        for mask in (0o022, 0o077) if os.name != "nt" else (0o022,):
            with self.subTest(mask=oct(mask)):
                root, state = self.base / f"mode-{mask}", self.base / f"mode-state-{mask}"
                previous = os.umask(mask)
                try:
                    self.restore(record, root, state)
                finally:
                    os.umask(previous)
                self.assert_tracked_modes(root, files, mask)
                if os.name != "nt":
                    for path in (root / ".git/healdan/materials.json", state / "config.json"):
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def conversation(self, name, *, classification="common", closed_at=None):
        origin = self.state / name
        atomic(origin / "conversation.jsonl", b'{"sessionId":"disposable","type":"assistant"}\n')
        purpose = {"purpose": "disposable recovery test", "necessity": "custody validation",
                   "owner": "human", "link": name}
        identifier = custody.capture_tree(self.vault, origin, task=name, classification=classification, purpose=purpose)
        record = custody.materials(self.vault)[identifier]
        if closed_at:
            record["closed_at"] = stamp(closed_at)
        custody.save_material(self.vault, record)
        return record

    def policy(self, backup="manual", *, permanent=False):
        retention_settings = {"mode": "keep_forever"} if permanent else {"mode": "by_class", "days": storage_policy.LEGACY_DAYS}
        decision = storage_policy.policy_request(self.vault, {"backup": {"mode": backup}, "retention": retention_settings,
                                                               "reason": "Disposable backup fixture"})
        storage_policy.apply_policy(self.vault, decision)
        return decision

    def test_1_controller_and_moved_replica(self):
        self.configure(2)
        self.vault.config[backup_snapshot.SOURCE_AUTHORITIES] = ["human"]
        atomic(self.vault.config_path, self.vault.config)
        source_body = b"The synthetic instrument has value 42 in the laboratory.\n"
        source_hash = digest(source_body)
        atomic(self.root / "inbox/synthetic.txt", source_body)
        inbox.inventory(self.vault)
        inbox.decide(self.vault, source_hash, "ingest", owner="human", classification="sensitive",
                     entered_at="2026-01-01T00:00:00Z", entry_origin="Backup fixture", destination="Reviewed test",
                     purpose={"purpose": "Review disposable source", "necessity": "Verify consent", "owner": "human",
                              "link": "inbox-" + source_hash})
        reclassification = admission.sign_reclassification(self.vault, source_hash, {
            "classification": "common", "reason": "Verified disposable data may enter the wiki"})
        event = admission.reclassify(self.vault, reclassification)
        claim = self.claim()
        self.knowledge([claim])
        git(self.root, "add", "--", "resources/sources", "wiki", "control/approvals")
        git(self.root, "commit", "-m", "Promote signed disposable knowledge")
        commit = git(self.root, "rev-parse", "HEAD")
        git(self.root, "branch", "historical")
        git(self.root, "tag", "-a", "fixture-tag", "-m", "Annotated fixture")
        task = tasks.create(self.vault, "Preserved task")
        session = tasks.new_session(self.vault, task["id"], "Review", "reviewer", "Disposable")
        atomic(self.vault.control / "csp.json", {"streak": 11})
        transaction = {"status": "complete", "package_id": "fixture", "base": commit,
                       "files": {}, "before": {}, "written": []}
        atomic(self.vault.control / "transaction.json", transaction)
        record = self.create()
        manifest, replica = self.paths(record, 1)
        self.destinations[0].rename(self.base / "offline-first")
        first = backups.restore(self.vault, record["id"], self.base / "by-id")
        self.assertEqual([entry["status"] for entry in first["replicas"]], ["unavailable", "verified"])

        moved = self.base / "moved"
        moved.mkdir()
        pair = manifest.rename(moved / "different-name.json"), replica.rename(moved / "different-name.age")
        (self.vault.control / "materials.json").unlink()
        self.vault.config_path.unlink()
        self.identities[0].unlink()
        approval_path = "control/approvals/packages.jsonl"
        approval = (self.root / approval_path).read_bytes()
        state = self.base / "portable-state"
        code, report = self.portable_cli("backup", "verify", record["id"], paths=pair, state=state)
        self.assertEqual((code, report["replica"]), (0, str(pair[1])), report)
        self.assertFalse(state.exists())
        destination = self.base / "portable-vault"
        code, report = self.portable_cli("restore", record["id"], destination, paths=pair, state=state)
        self.assertEqual(code, 0, report)
        restored = Vault(destination, state)
        self.assertEqual(restored.identity, self.vault.identity)
        self.assertEqual(git(destination, "rev-parse", "HEAD"), commit)
        self.assertEqual(backup_snapshot.git_identity(destination), backup_snapshot.git_identity(self.root))
        self.assertEqual((destination / approval_path).read_bytes(), approval)
        for name in ("wiki/claims.jsonl", "resources/sources/F-0001/original.txt", "resources/sources/index.jsonl"):
            self.assertEqual((destination / name).read_bytes(), (self.root / name).read_bytes())
        self.assertEqual(read_json(restored.control / "reservations.json"), read_json(self.vault.control / "reservations.json"))
        self.assertEqual(read_json(restored.control / "csp.json"), {"streak": 11})
        self.assertEqual(tasks.get_task(restored, task["id"])["id"], task["id"])
        self.assertEqual(tasks.get_session(restored, session["operation"])["uuid"], session["uuid"])
        classifier = admission.Classification(restored, admission.source_rows(restored))
        self.assertEqual(classifier.current(source_hash), ("common", event["receipt"]))

        history = restored.control / "historical"
        evidence = {
            f"historical/{record['id']}.manifest.json": pair[0].read_bytes(),
            "historical/materials.json": (history / "materials.json").read_bytes(),
            f"historical/tasks/{task['id']}.json": (history / "tasks" / (task["id"] + ".json")).read_bytes(),
            f"historical/sessions/{session['operation']}.json": (history / "sessions" / (session["operation"] + ".json")).read_bytes(),
            "historical/transaction.json": (history / "transaction.json").read_bytes(),
            f"receipts/{report['receipt']}.json": (restored.control / "receipts" / (report["receipt"] + ".json")).read_bytes(),
        }
        atomic(history / "incidental.json", {"credential": "excluded disposable fixture"})
        second_root = self.base / "second-generation-replica"
        second_root.mkdir()
        restored.config.update({key: self.vault.config[key] for key in ("age_recipients", "offline_recipients",
                                "backup_signing_key", "backup_signing_identity")})
        restored.config["backup_destinations"] = [str(second_root)]
        atomic(restored.config_path, restored.config)
        prior_versions = {name: (restored.control / name).read_bytes() for name in (
            "materials.json", f"tasks/{task['id']}.json", f"sessions/{session['operation']}.json")}
        second = backups.create(restored, "long", utc() + timedelta(days=2))
        second_pair = tuple(second_root / second["copies"][0][name] for name in ("manifest", "path"))
        second_result = self.restore(second, self.base / "second-vault", self.base / "second-state", paths=second_pair)
        twice = Vault(second_result["destination"], second_result["state"])
        for name, body in evidence.items():
            self.assertEqual((twice.control / name).read_bytes(), body, name)
        self.assertFalse((twice.control / "historical/incidental.json").exists())
        self.assertEqual((twice.control / "historical" / (second["id"] + ".manifest.json")).read_bytes(), second_pair[0].read_bytes())
        self.assertEqual(tasks.get_task(twice, task["id"])["state"], "reconciliation_required")
        self.assertEqual(tasks.get_session(twice, session["operation"])["state"], "reconciliation_required")
        self.assertFalse((twice.control / "transaction.json").exists())
        self.assertEqual(read_json(twice.control / "historical/transaction.json"), transaction)
        latest_history = twice.control / "historical/generations" / second["id"]
        for name, body in prior_versions.items():
            self.assertEqual((latest_history / name).read_bytes(), body, name)
        capabilities = read_json(Path(compatibility.__file__).with_name("controller_formats.json"))
        compatibility.check(twice, capabilities)
        capabilities["journal"].remove(backup_snapshot.RECOVERY_HISTORY)
        with self.assertRaisesRegex(Blocked, backup_snapshot.RECOVERY_HISTORY):
            compatibility.check(twice, capabilities)
        closed = tasks.reconcile_restored(twice, task["id"], confirmed=True)
        original = closed["reconciliation_history"][-1]
        self.assertEqual(original["origin"]["backup"], record["id"])
        receipt = read_json(twice.control / "receipts" / (original["receipt"] + ".json"))
        self.assertEqual(receipt["payload"]["recovery_receipt"], second_result["receipt"])
        self.assertEqual(tasks.get_session(twice, session["operation"])["state"], "reconciliation_required")

    def test_1_invalid_replica_or_manifest(self):
        self.configure(2)
        record = self.create()
        manifest_path, replica = self.paths(record)
        raw, cipher = manifest_path.read_bytes(), replica.read_bytes()
        destination, state = self.base / "preexisting", self.base / "failed-state"
        destination.mkdir()
        atomic(destination / "keep", b"preexisting")
        wrong = self.base / "wrong.agekey"
        run(["age-keygen", "-o", wrong])
        payload = record["approval"]["payload"]
        key = self.vault.config["backup_signing_key"]
        changes = [
            ("untrusted signer", envelope(payload, "backup", "human", self.key), cipher, self.identities[1], record["id"]),
            ("tampered envelope", {**record["approval"], "payload": {**payload, "inventory_sha256": "1" * 64}},
             cipher, self.identities[1], record["id"]),
            ("another generation", envelope({**payload, "id": str(uuid4())}, "backup", "backup", key),
             cipher, self.identities[1], record["id"]),
            ("wrong request ID", record["approval"], cipher, self.identities[1], str(uuid4())),
            ("wrong identity", record["approval"], cipher, wrong, record["id"]),
            ("cipher mismatch", record["approval"], b"changed", self.identities[1], record["id"]),
            ("inventory mismatch", envelope({**payload, "inventory_sha256": "1" * 64}, "backup", "backup", key),
             cipher, self.identities[1], record["id"]),
        ]
        for label, signature, body, identity, identifier in changes:
            with self.subTest(label=label):
                atomic(manifest_path, signature)
                atomic(replica, body)
                with self.assertRaises(Blocked):
                    backups.restore_portable(identifier, destination, manifest_path, replica, state=state,
                                             **{**self.trust, "age_identity": identity})
                self.assertEqual((destination / "keep").read_bytes(), b"preexisting")
                self.assertFalse(state.exists())
        atomic(manifest_path, raw)
        atomic(replica, b"invalid disposable replica")
        report = backups.verify_backup(self.vault, record["id"])
        self.assertEqual([entry["status"] for entry in report["replicas"]], ["invalid", "verified"])
        self.assertEqual(self.cli("backup", "verify", record["id"]), (5, report))
        self.assertEqual(report["status"], "pending")
        replica.unlink()
        code, report = self.cli("backup", "verify", record["id"])
        self.assertEqual(code, 4)
        self.assertEqual(report["status"], "pending")
        self.assertEqual([entry["status"] for entry in report["replicas"]], ["unavailable", "verified"])
        atomic(replica, cipher)
        receipt = self.vault.control / "receipts" / (record["copies"][0]["publication_receipt"] + ".json")
        original_receipt = receipt.read_bytes()
        atomic(receipt, {"kind": "changed first publication receipt"})
        report = backups.verify_backup(self.vault, record["id"])
        self.assertEqual([entry["status"] for entry in report["replicas"]], ["invalid", "verified"])
        self.assertIn("publication receipt changed", report["replicas"][0]["reason"])
        with self.assertRaisesRegex(Blocked, "publication receipt changed"):
            backups.signed_manifest(self.vault, record)
        result = backups.restore(self.vault, record["id"], self.base / "fallback-after-invalid-receipt")
        self.assertEqual(result["replica"], str(self.paths(record, 1)[1]))
        atomic(receipt, original_receipt)

        second_destination = self.destinations[1]
        offline = second_destination.rename(self.base / "temporarily-offline")
        after_expiry = utc(record["expires_at"]) + timedelta(seconds=1)
        plan = retention.plan(self.vault, after_expiry)
        self.assertEqual(retention.execute(self.vault, plan["id"], after_expiry)["status"], "pending")
        offline.rename(second_destination)
        current = custody.materials(self.vault)[record["id"]]
        code, report = self.cli("backup", "verify", record["id"])
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "complete")
        self.assertEqual([entry["status"] for entry in report["replicas"]], ["deleted", "verified"])
        deletion = self.vault.control / "receipts" / (current["copies"][0]["deletion_receipt"] + ".json")
        deletion.unlink()
        report = backups.verify_backup(self.vault, record["id"])
        self.assertEqual([entry["status"] for entry in report["replicas"]], ["invalid", "verified"])
        self.assertEqual(report["deleted_copies"], [])
        self.assertIn("lacks a verified deletion receipt", report["replicas"][0]["reason"])
        with self.assertRaisesRegex(Blocked, "lacks a verified deletion receipt"):
            backups.inspect_backup(self.vault, current)
        self.assertEqual(retention.execute(self.vault, plan["id"], after_expiry)["status"], "pending")
        destination = self.base / "fallback-after-invalid-deletion-proof"
        self.assertEqual(backups.restore(self.vault, record["id"], destination)["replica"], str(self.paths(record, 1)[1]))
        atomic(self.paths(record, 1)[1], b"last replica changed")
        code, error = self.cli("backup", "verify", record["id"])
        self.assertEqual(code, 5)
        self.assertIn("no verified retained replicas", error["error"])
        unavailable = self.base / "failed-without-a-verified-replica"
        with self.assertRaisesRegex(Blocked, "no verified retained replicas.+verified deletion receipt.+ciphertext mismatch"):
            backups.restore(self.vault, record["id"], unavailable)
        self.assertFalse(unavailable.exists())

    def test_1_invalid_replica_inventory_does_not_block_fallback(self):
        self.configure(2)
        record = self.create()
        identifier = record["id"]
        first, second = record["copies"]
        moved = self.base / "unauthorized-copy-root"
        moved.mkdir()
        for path in self.paths(record):
            atomic(moved / path.name, path.read_bytes())
        substituted = {**first, "root": str(moved)}
        substituted["publication_receipt"] = self.vault.receipt(
            "backup-replica-published", backups.published_copy(record, 0, substituted, first["published_at"]),
            at=first["published_at"],
        )
        for label, copy, error in (
            ("manifest-digest", {**first, "manifest_sha256": "0" * 64}, "Portable replica inventory changed"),
            ("malformed-copy", None, "Portable replica inventory changed"),
            ("other-slot", second, "duplicates a verified publication slot"),
            ("substituted-root", substituted, "signed publication plan"),
            ("unavailable-copy", {**first, "status": "unavailable"}, None),
        ):
            with self.subTest(label=label):
                damaged = {**record, "copies": [copy, second]}
                custody.save_material(self.vault, damaged)
                with patch.object(self.vault, "relocated_path", wraps=self.vault.relocated_path) as relocated:
                    report = backups.verify_backup(self.vault, identifier)
                if error:
                    self.assertNotIn(first["root"], [call.args[0] for call in relocated.call_args_list])
                    self.assertNotIn(str(moved), [call.args[0] for call in relocated.call_args_list])
                    self.assertIn(error, report["replicas"][0]["reason"])
                    strict_error = "publication receipt changed" if label == "other-slot" else error
                    with self.assertRaisesRegex(Blocked, strict_error):
                        backups.inspect_backup(self.vault, damaged, allow_retired=True)
                    with self.assertRaisesRegex(Blocked, strict_error):
                        backups.reconcile(self.vault, identifier)
                destination = self.base / label
                restored = backups.restore(self.vault, identifier, destination)
                for result in (report, restored):
                    self.assertEqual(result["replica"], str(self.paths(record, 1)[1]))
                    self.assertEqual([row["status"] for row in result["replicas"]],
                                     ["invalid" if error else "unavailable", "verified"])
                    self.assertEqual(result["pending_replicas"], result["replicas"][:1])
                self.assertEqual((destination / "wiki/claims.jsonl").read_bytes(), b"")

        custody.save_material(self.vault, {**record, "plain_sha256": "0" * 64})
        with self.assertRaisesRegex(Blocked, "Signed backup manifest changed"):
            backups.verify_backup(self.vault, identifier)
        destination = self.base / "unauthenticated-generation"
        with self.assertRaisesRegex(Blocked, "Signed backup manifest changed"):
            backups.restore(self.vault, identifier, destination)
        self.assertFalse(destination.exists())

    def test_1_signed_replica_count_guards_complete_inventory(self):
        self.configure(2)
        self.vault.config.update(backup_interval_hours=24, backup_generation_days=2)
        atomic(self.vault.config_path, self.vault.config)
        self.policy("scheduled")
        now = utc()
        expiry = now + timedelta(days=2)
        record = backups.create(self.vault, "long", expiry, now=now)
        identifier = record["id"]
        plan = retention.plan(self.vault, expiry)
        self.assertEqual([entry["copy_index"] for entry in plan["entries"]], [0, 1])
        self.assertEqual(record["approval"]["payload"].get("replica_count"), 2)

        for index, copy in enumerate(record["copies"]):
            with self.subTest(retained_slot=index):
                damaged = {**record, "copies": [copy]}
                custody.save_material(self.vault, damaged)
                with self.assertRaisesRegex(Blocked, "replica count"):
                    backups.inspect_backup(self.vault, damaged, decrypt_replicas=True)
                with self.assertRaisesRegex(Blocked, "replica count"):
                    backups.reconcile(self.vault, identifier)
                discovered = retention.plan(self.vault, expiry)
                self.assertEqual(discovered["entries"], [])
                self.assertEqual(discovered["pending"][0]["material"], identifier)
                self.assertIn("replica count", discovered["pending"][0]["reason"])
                outcome = retention.execute(self.vault, plan["id"], expiry)
                self.assertEqual(outcome["status"], "pending", outcome)
                self.assertEqual(len(outcome["pending"]), 2)
                self.assertTrue(all("replica count" in row["reason"] for row in outcome["pending"]))

                report = backups.verify_backup(self.vault, identifier)
                result = backups.restore(self.vault, identifier, self.base / f"restored-slot-{index}")
                self.assertEqual(self.cli("backup", "verify", identifier), (5, report))
                self.assertEqual(report["status"], "pending")
                self.assertEqual(result["status"], "complete")
                for checked in (report, result):
                    self.assertEqual(checked["replica"], str(self.paths(record, index)[1]))
                    self.assertEqual([(row["copy_index"], row["status"]) for row in checked["replicas"]], [(index, "verified")])
                    self.assertIn("replica count", checked["pending_replicas"][0]["reason"])
                self.assertTrue(all(path.is_file() for slot in (0, 1) for path in self.paths(record, slot)))

        reordered = {**record, "copies": list(reversed(record["copies"]))}
        custody.save_material(self.vault, reordered)
        offline = self.destinations[0].rename(self.base / "offline-reordered-slot")
        try:
            report = backups.verify_backup(self.vault, identifier)
            restored = backups.restore(self.vault, identifier, self.base / "reordered-restore")
            self.assertEqual(self.cli("backup", "verify", identifier), (5, report))
            for result in (report, restored):
                self.assertEqual(result["replica"], str(self.paths(record, 1)[1]))
                self.assertEqual([(row["copy_index"], row["status"]) for row in result["replicas"]],
                                 [(1, "verified"), (0, "unavailable")])
                self.assertTrue(any("catalog order" in row["reason"] for row in result["pending_replicas"]))
            with self.assertRaisesRegex(Blocked, "publication receipt changed"):
                backups.inspect_backup(self.vault, reordered, decrypt_replicas=True)
            with self.assertRaisesRegex(Blocked, "publication receipt changed"):
                backups.reconcile(self.vault, identifier)
        finally:
            offline.rename(self.destinations[0])
        self.assertEqual(retention.plan(self.vault, expiry)["entries"], [])
        outcome = retention.execute(self.vault, plan["id"], expiry)
        self.assertEqual(outcome["status"], "pending")
        self.assertTrue(all(path.is_file() for slot in (0, 1) for path in self.paths(record, slot)))

        first, second = record["copies"]
        repeated = {**record, "copies": [{**second, "status": "unavailable"}, first, first]}
        custody.save_material(self.vault, repeated)
        report = backups.verify_backup(self.vault, identifier)
        self.assertEqual(report["replica"], str(self.paths(record)[1]))
        self.assertEqual([row["status"] for row in report["replicas"]], ["unavailable", "verified", "invalid"])
        self.assertIn("duplicates a verified publication slot", report["replicas"][2]["reason"])

        conflicting = {**record, "copies": [{**first, "status": "unavailable"}, second, first]}
        custody.save_material(self.vault, conflicting)
        offline = self.destinations[1].rename(self.base / "offline-conflicting-slot")
        try:
            report = backups.verify_backup(self.vault, identifier)
            restored = backups.restore(self.vault, identifier, self.base / "conflicting-restore")
            for result in (report, restored):
                self.assertEqual(result["replica"], str(self.paths(record)[1]))
                self.assertEqual(len(result["copies"]), 1)
                self.assertEqual([(row["copy_index"], row["status"]) for row in result["replicas"]],
                                 [(0, "invalid"), (1, "unavailable"), (0, "verified")])
                self.assertIn("conflicting catalog entries", result["replicas"][0]["reason"])
            with self.assertRaisesRegex(Blocked, "replica count"):
                backups.inspect_backup(self.vault, conflicting, decrypt_replicas=True)
        finally:
            offline.rename(self.destinations[1])

        scheduled = maintenance.backup_round(self.vault, now + timedelta(minutes=1))
        self.assertEqual(scheduled["status"], "complete", scheduled)
        self.assertNotEqual(scheduled["id"], identifier)

    def test_1_portable_manifest_without_signed_publication_plan(self):
        self.configure(2)
        record = self.create()
        manifest_path, replica = self.paths(record, 1)
        for removed, issue in (({"replica_slots_sha256"}, "authenticated publication plan"),
                               ({"replica_slots_sha256", "replica_count"}, "authenticated replica count")):
            with self.subTest(issue=issue):
                payload = {key: value for key, value in record["approval"]["payload"].items() if key not in removed}
                approval = envelope(payload, "backup", "backup", self.vault.config["backup_signing_key"])
                original = canonical(approval) + b"\n"
                older = {key: value for key, value in record.items() if key not in removed}
                older.update(approval=approval)
                copies = []
                for index, copy in enumerate(record["copies"]):
                    atomic(self.paths(record, index)[0], original)
                    copy = {**copy, "manifest_sha256": digest(original)}
                    at = copy["published_at"]
                    proof = backups.published_copy(older, index, copy, at)
                    copy["publication_receipt"] = self.vault.receipt("backup-replica-published", proof, at=at)
                    copies.append(copy)
                older["copies"] = [copies[1], {**copies[0], "status": "unavailable"}]
                custody.save_material(self.vault, older)
                self.assertEqual(backups.verify_portable(record["id"], manifest_path, replica, **self.trust)["status"], "complete")
                report = backups.verify_backup(self.vault, record["id"])
                self.assertEqual(report["replica"], str(replica))
                self.assertEqual([(row["copy_index"], row["status"]) for row in report["replicas"]],
                                 [(1, "verified"), (0, "unavailable")])
                reasons = [row["reason"] for row in report["pending_replicas"]]
                self.assertTrue(any(issue in reason for reason in reasons))
                self.assertTrue(any("catalog order" in reason for reason in reasons))
                with self.assertRaisesRegex(Blocked, issue):
                    backups.inspect_backup(self.vault, older)
                self.assertEqual(manifest_path.read_bytes(), original)

    def test_1_conflicting_replica_claims_require_deletion_proof(self):
        self.configure(2)
        now = utc()
        record = backups.create(self.vault, "long", now - timedelta(days=1), now=now - timedelta(days=2))
        identifier = record["id"]
        first, second = record["copies"]
        replica = self.paths(record)[1]
        cipher = replica.read_bytes()
        claim = {**first, "status": "deleted", "deletion_receipt": "a" * 64}
        custody.save_material(self.vault, {**record, "copies": [claim, second, first]})
        report = backups.verify_backup(self.vault, identifier)
        self.assertEqual([row["status"] for row in report["replicas"]], ["invalid", "verified", "verified"])
        self.assertIn("deletion receipt", report["replicas"][0]["reason"])
        self.assertEqual(report["deleted_copies"], [])

        custody.save_material(self.vault, record)
        plan = retention.plan(self.vault, now)
        offline = self.destinations[1].rename(self.base / "offline-during-retention")
        try:
            result = retention.execute(self.vault, plan["id"], now)
            self.assertEqual(result["status"], "pending")
            retired = custody.materials(self.vault)[identifier]["copies"][0]
            self.assertEqual(retired["status"], "deleted")
        finally:
            offline.rename(self.destinations[1])

        # A recreated ciphertext and a stale present claim cannot reverse retirement.
        atomic(replica, cipher)
        custody.save_material(self.vault, {**record, "copies": [first, second, retired]})
        report = backups.verify_backup(self.vault, identifier)
        self.assertEqual(report["replica"], str(self.paths(record, 1)[1]))
        self.assertEqual(len(report["copies"]), 1)
        self.assertEqual([row["status"] for row in report["replicas"]], ["invalid", "verified", "deleted"])
        self.assertEqual([row["receipt"] for row in report["deleted_copies"]], [retired["deletion_receipt"]])
        dest = self.base / "retired-copy-cannot-restore"
        self.destinations[1].rename(self.base / "offline-after-retirement")
        with self.assertRaisesRegex(Blocked, "no verified retained replicas"):
            backups.restore(self.vault, identifier, dest)
        self.assertFalse(dest.exists())

    def test_1_custody_retention_and_authorized_remap(self):
        self.configure(2)
        decision = self.policy()
        old = utc() - timedelta(days=40)

        def export(name, expiry_origin):
            path = self.base / ("export-" + name)
            atomic(path, name.encode())
            record = {"id": name, "kind": "export", "classification": "common", "captured_at": stamp(expiry_origin),
                      "holds": [], "dependencies": [], "copies": [
                          {"root": str(self.state / "custody"), "path": path.name, "sha256": digest(path.read_bytes()),
                           "kind": "export", "status": "present"}]}
            atomic(self.state / "custody" / path.name, path.read_bytes())
            custody.save_material(self.vault, record)
            return record, path

        deleted, _ = export("already-deleted", old)
        plan = retention.plan(self.vault)
        self.assertEqual(retention.execute(self.vault, plan["id"])["status"], "complete")
        historical, _ = export("historically-deleted", old)
        divergent, _ = export("divergent-deletion-proof", old)
        legacy_id = str(uuid4())
        bundle = self.base / "retired-generation.bundle"
        git(self.root, "bundle", "create", str(bundle), "--all")
        files = {name: backup_snapshot.file_entry("knowledge", (self.root / name).read_bytes()) for name in self.vault.inputs()}
        files[backup_snapshot.BUNDLE] = backup_snapshot.file_entry("git", bundle.read_bytes())
        for entry in files.values():
            entry.pop("kind")
        plain = canonical({"format": "healdan-tree-v1", "files": files})
        cipher = custody.encrypt(self.vault, plain)
        replicas = [directory / (legacy_id + ".age") for directory in self.destinations]
        for replica in replicas:
            atomic(replica, cipher)
        legacy = {"id": legacy_id, "kind": "backup", "generation": "long", "created_at": stamp(old),
                  "expires_at": stamp(old + timedelta(days=1)), "members": [], "commit": self.vault.head(),
                  "plain_sha256": digest(plain), "cipher_sha256": digest(cipher), "holds": [], "dependencies": [],
                  "copies": [{"root": str(replica.parent), "path": replica.name, "kind": "ciphertext",
                              "sha256": digest(cipher), "status": "present"} for replica in replicas],
                  "status": "complete", "verified_at": stamp(old)}
        legacy["approval"] = envelope(deepcopy(legacy), "backup", "backup", self.vault.config["backup_signing_key"])
        custody.save_material(self.vault, legacy)

        # Persist the initial B04 intent after unlink, then use retention to write the original receipt format.
        now = utc()
        surviving_slot = retention.slot({"material": legacy_id, "copy_index": 1, "copy": legacy["copies"][1]})
        historical_plan = retention.plan(self.vault, now, exclude=[surviving_slot])
        self.assertEqual({entry["material"] for entry in historical_plan["entries"]},
                         {historical["id"], divergent["id"], legacy_id})
        for entry in historical_plan["entries"]:
            root = Path(entry["copy"]["root"])
            target = root / entry["copy"]["path"]
            self.assertEqual(digest(target.read_bytes()), entry["copy"]["sha256"])
            entry.update(status="deleting", intent={"slot": list(retention.slot(entry)), "path": str(target),
                         "root_identity": retention.file_identity(root), "file_identity": retention.file_identity(target),
                         "plan_digest": historical_plan["digest"], "at": stamp(now)})
            target.unlink()
        historical_path = f"deletions/{historical_plan['id']}.json"
        atomic(self.vault.control / historical_path, historical_plan)
        completed = retention.execute(self.vault, historical_plan["id"], now)
        self.assertEqual(completed["status"], "complete")
        altered = next(entry for entry in completed["entries"] if entry["material"] == divergent["id"])
        altered["intent"]["at"] = stamp(now + timedelta(seconds=1))
        self.assertEqual(retention.plan_digest(completed), completed["digest"])
        atomic(self.vault.control / historical_path, completed)

        legacy_record = custody.materials(self.vault)[legacy_id]
        receipt_id = legacy_record["copies"][0]["deletion_receipt"]
        receipt_path = self.vault.control / "receipts" / f"{receipt_id}.json"
        control_path = self.vault.control / historical_path
        history = {path: path.read_bytes() for path in (control_path, receipt_path, self.vault.control / "materials.json")}
        code, explicit = self.cli("backup", "verify", legacy_id)
        self.assertEqual(code, 0, explicit)
        strict = backups.inspect_backup(self.vault, legacy_record, decrypt_replicas=True)
        restored_legacy = backups.restore(self.vault, legacy_id, self.base / "legacy-with-retired-replica")
        for report in (explicit, strict, restored_legacy):
            self.assertEqual([row["status"] for row in report["replicas"]], ["deleted", "verified"])
            self.assertEqual(report["replica"], str(replicas[1]))
            self.assertEqual(report["deleted_copies"], [{"copy_index": 0, "root": str(replicas[0].parent), "receipt": receipt_id}])
        self.assertEqual(git(Path(restored_legacy["destination"]), "rev-parse", "HEAD"), legacy["commit"])

        bad_plan = read_json(control_path)
        legacy_entry = next(entry for entry in bad_plan["entries"] if entry["material"] == legacy_id)
        legacy_entry["intent"]["file_identity"][1] += 1
        self.assertEqual(retention.plan_digest(bad_plan), bad_plan["digest"])
        atomic(control_path, bad_plan)
        code, explicit = self.cli("backup", "verify", legacy_id)
        self.assertEqual(code, 5, explicit)
        self.assertEqual(explicit["status"], "pending")
        self.assertEqual([row["status"] for row in explicit["replicas"]], ["invalid", "verified"])
        self.assertEqual(explicit["deleted_copies"], [])
        with self.assertRaisesRegex(Blocked, "verified deletion receipt"):
            backups.inspect_backup(self.vault, legacy_record, decrypt_replicas=True)
        atomic(control_path, history[control_path])
        self.assertEqual({path: path.read_bytes() for path in history}, history)

        round_deleted, _ = export("deleted-by-round", old)
        round_divergent, _ = export("divergent-round-date", old)
        # The earliest producer persisted the completed slot's own timestamp and a single receipt for the round.
        round_plan = retention.plan(self.vault, now, exclude=[surviving_slot])
        round_material = {record["id"]: record for record in (round_deleted, round_divergent)}
        self.assertEqual({entry["material"] for entry in round_plan["entries"]}, round_material.keys())
        for entry in round_plan["entries"]:
            record = round_material[entry["material"]]
            copy = record["copies"][0]
            (Path(copy["root"]) / copy["path"]).unlink()
            copy.update(status="deleted", deleted_at=stamp(now))
            entry.update(status="deleted", at=stamp(now))
            if record["id"] == round_divergent["id"]:
                copy["deleted_at"] = stamp(now + timedelta(seconds=1))
            custody.save_material(self.vault, record)
        round_plan["status"] = "complete"
        round_path = f"deletions/{round_plan['id']}.json"
        atomic(self.vault.control / round_path, round_plan)
        round_receipt = self.vault.receipt("deletion-round", {"plan": round_plan["id"], "digest": round_plan["digest"],
                                                             "status": "complete"}, at=now + timedelta(seconds=2))
        round_receipt_path = f"receipts/{round_receipt}.json"
        original = custody.materials(self.vault)

        held, held_source = export("held", old)
        hold = custody.hold(self.vault, held["id"], "Await origin decision", "human", ["evidence"])
        held = custody.materials(self.vault)[held["id"]]
        held["dependencies"] = ["evidence"]
        custody.save_material(self.vault, held)
        old_plan = retention.plan(self.vault)
        independent, independent_source = export("independent", utc() - timedelta(days=2))
        unavailable, _ = export("unavailable", old)

        task = tasks.create(self.vault, "Retired worktree checkpoint")
        atomic(Path(task["worktree"]) / "draft.txt", b"Verified checkpoint")
        closed = tasks.preserve_and_close(self.vault, task["id"])
        preserved = custody.materials(self.vault)[closed["preservation"]]
        moved_checkpoint = next(copy for copy in preserved["copies"] if copy["path"].endswith("/draft.txt"))
        self.assertEqual(moved_checkpoint["status"], "moved")

        empty = self.root / "inbox" / "empty-for-archive.txt"
        atomic(empty, b"")
        inbox.inventory(self.vault)
        inbox.decide(self.vault, digest(b""), "archive", owner="human", classification="common", destination="archive")
        archived = {"id": "archived-empty", "kind": "export", "classification": "common", "captured_at": stamp(),
                    "holds": [], "dependencies": [],
                    "copies": [{"root": str(self.root), "path": "inbox/" + empty.name, "kind": "export",
                                "sha256": digest(b""), "status": "present"}]}
        custody.save_material(self.vault, archived)
        inbox.archive_empty(self.vault, digest(b""))
        moved_empty = custody.materials(self.vault)[archived["id"]]["copies"][0]
        self.assertEqual(moved_empty["status"], "moved")

        before_move = self.root / "inbox" / "before.txt"
        atomic(before_move, b"Tracked export renamed in the inbox")
        move_sha = digest(before_move.read_bytes())
        renamed = {"id": "renamed-export", "kind": "export", "classification": "common", "captured_at": stamp(),
                   "source_sha256": move_sha, "holds": [], "dependencies": [],
                   "copies": [{"root": str(before_move.parent), "path": before_move.name, "kind": "export",
                               "sha256": move_sha, "status": "present"}]}
        custody.save_material(self.vault, renamed)
        before_move.rename(before_move.with_name("after.txt"))
        inbox.inventory(self.vault)
        retention.plan(self.vault)
        moved_export = custody.materials(self.vault)[renamed["id"]]["copies"][0]
        self.assertEqual(moved_export["status"], "moved")

        record = self.create()
        (self.state / "custody" / unavailable["copies"][0]["path"]).unlink()
        with self.assertRaisesRegex(Blocked, "Remapped custody copy hash mismatch"):
            self.restore(record, remap={held["id"]: {"0": str(independent_source)}})
        result = self.restore(record, remap={held["id"]: {"0": str(held_source)},
                                            independent["id"]: {"0": str(independent_source)}})
        new = Vault(result["destination"], result["state"])
        current = custody.materials(new)
        self.assertEqual(storage_policy.history(new), [decision])
        self.assertEqual(current[held["id"]]["holds"], [hold])
        self.assertEqual(current[held["id"]]["dependencies"], ["evidence"])
        self.assertEqual(current[independent["id"]]["captured_at"], independent["captured_at"])
        self.assertEqual(current[deleted["id"]]["copies"][0]["status"], "deleted")
        for path in (historical_path, round_path, round_receipt_path):
            self.assertEqual((new.control / path).read_bytes(), (self.vault.control / path).read_bytes())
        for key in (historical["id"], legacy_id):
            copy = original[key]["copies"][0]
            self.assertEqual(current[key]["copies"][0], {**copy, "origin_status": "deleted"})
            relative = f"receipts/{copy['deletion_receipt']}.json"
            self.assertEqual((new.control / relative).read_bytes(), (self.vault.control / relative).read_bytes())
        self.assertEqual(current[legacy_id]["approval"], legacy["approval"])
        self.assertEqual(current[round_deleted["id"]]["copies"][0], {**round_deleted["copies"][0], "origin_status": "deleted"})
        for key in (divergent["id"], round_divergent["id"]):
            self.assertEqual(current[key]["copies"][0]["status"], "unavailable")
            self.assertTrue(any(row["material"] == key and row["copy_index"] == 0 and row["status"] == "invalid"
                                for row in result["pending_copies"]))
        self.assertEqual(current[unavailable["id"]]["copies"][0]["status"], "unavailable")
        recovered_checkpoint = next(copy for copy in current[preserved["id"]]["copies"] if copy.get("path") == moved_checkpoint["path"])
        self.assertEqual(recovered_checkpoint, {**moved_checkpoint, "origin_status": "moved"})
        self.assertEqual(current[archived["id"]]["copies"][0], {**moved_empty, "origin_status": "moved"})
        self.assertEqual(current[renamed["id"]]["copies"][0], {**moved_export, "origin_status": "moved"})
        self.assertEqual(read_json(new.control / "deletions" / (old_plan["id"] + ".json")), old_plan)
        local = current[independent["id"]]["copies"][1]
        local_path = Path(local["root"]) / local["path"]
        self.assertEqual(local_path.read_bytes(), independent_source.read_bytes())
        future = utc() + timedelta(days=40)
        due = retention.plan(new, future)
        status = retention.execute(new, due["id"], future)
        self.assertEqual(status["status"], "pending", status)
        self.assertFalse(local_path.exists())
        self.assertTrue(independent_source.exists())
        self.assertTrue((new.control / "historical/materials.json").exists())
        self.assertTrue((new.control / "receipts" / (current[deleted["id"]]["copies"][0]["deletion_receipt"] + ".json")).exists())

    def test_1_verified_archive_deletion_proofs_survive_portable_restore(self):
        self.configure()
        now = utc()
        sha = digest(b"")
        past = stamp(now - timedelta(days=40))
        for key, relative in (("archive-a", "a/shared.txt"), ("archive-b", "b/shared.txt"),
                              ("archive-unproved", "different.txt"), ("archive-round", "a/single.txt"),
                              ("archive-wrong-material", "b/single.txt"), ("archive-resumed", "resumed.txt"),
                              ("archive-intent-primary", "a/intent.txt"), ("archive-intent-sibling", "b/intent.txt")):
            atomic(self.root / "inbox" / relative, b"")
            custody.save_material(self.vault, {
                "id": key, "kind": "export", "classification": "common", "captured_at": past,
                "holds": [], "dependencies": [], "copies": [{"root": str(self.root / "inbox"), "path": relative,
                    "kind": "export", "sha256": sha, "status": "present"}],
            })
        inbox.inventory(self.vault)
        inbox.decide(self.vault, sha, "archive", owner="human", classification="common", destination="archive")
        inbox.archive_empty(self.vault, sha)
        records = custody.materials(self.vault)
        primary, sibling = records["archive-a"], records["archive-b"]
        unproved = records["archive-unproved"]
        archive = self.root / "archive" / sha / "shared.txt"
        self.assertEqual(digest(archive.read_bytes()), sha)
        exclusions = [retention.slot({"material": record["id"], "copy_index": 1, "copy": record["copies"][1]})
                      for record in records.values() if record["id"] != primary["id"]]
        plan = retention.plan(self.vault, now, exclude=exclusions)
        entry, = plan["entries"]
        self.assertEqual((entry["material"], entry["copy_index"]), (primary["id"], 1))

        # Persist the B03 state after the shared unlink and before recording the second slot.
        entry.update(status="deleting", at=stamp(now), verified_archive_generations=[
            retention.generation_locator(record, 1, record["copies"][1]) for record in (primary, sibling)
        ])
        plan["status"] = "pending"
        relative_plan = f"deletions/{plan['id']}.json"
        plan_path = self.vault.control / relative_plan
        atomic(plan_path, plan)
        archive.unlink()
        for record in (primary, unproved):
            record["copies"][1].update(status="deleted", deleted_at=stamp(now), verified_archive_sha256=sha)
            custody.save_material(self.vault, record)
        old_round = self.vault.receipt("deletion-round", {"plan": plan["id"], "digest": plan["digest"], "status": "pending"}, at=now)
        relative_round = f"receipts/{old_round}.json"
        history = (self.vault.control / "materials.json").read_bytes()
        first = self.restore(self.create(), self.base / "b03-restored", self.base / "b03-state")
        from_b03 = Vault(first["destination"], first["state"])
        self.assertEqual((from_b03.control / "historical/materials.json").read_bytes(), history)
        self.assertEqual((from_b03.control / relative_plan).read_bytes(), plan_path.read_bytes())
        self.assertEqual((from_b03.control / relative_round).read_bytes(), (self.vault.control / relative_round).read_bytes())
        with self.subTest(proof="B03 round"):
            restored = custody.materials(from_b03)
            self.assertEqual(restored[primary["id"]]["copies"][1], {**primary["copies"][1], "origin_status": "deleted"})
            self.assertEqual(restored[sibling["id"]]["copies"][1]["status"], "unavailable")
        self.assertEqual(custody.materials(from_b03)[unproved["id"]]["copies"][1]["status"], "unavailable")

        completed = retention.execute(self.vault, plan["id"], now)
        self.assertEqual(completed["status"], "complete")
        copy = custody.materials(self.vault)[sibling["id"]]["copies"][1]
        self.assertEqual(copy["status"], "deleted")
        relative_receipt = f"receipts/{copy['deletion_receipt']}.json"
        receipt_path = self.vault.control / relative_receipt
        self.assertEqual(read_json(receipt_path)["payload"], {"material": sibling["id"], "copy_index": 1,
                                                              "sha256": sha, "intent": None})
        for path in (self.vault.control / "receipts").glob("*.json"):
            receipt = read_json(path)
            if receipt["kind"] == "deletion-round" and receipt["payload"]["plan"] == plan["id"]:
                path.unlink()
        # The sibling's otherwise valid receipt cannot prove the primary material's slot.
        primary["copies"][1]["deletion_receipt"] = copy["deletion_receipt"]
        custody.save_material(self.vault, primary)

        history = (self.vault.control / "materials.json").read_bytes()
        second = self.restore(self.create(), self.base / "b04-restored", self.base / "b04-state")
        from_b04 = Vault(second["destination"], second["state"])
        self.assertEqual((from_b04.control / "historical/materials.json").read_bytes(), history)
        self.assertEqual((from_b04.control / relative_plan).read_bytes(), plan_path.read_bytes())
        self.assertEqual((from_b04.control / relative_receipt).read_bytes(), receipt_path.read_bytes())
        restored = custody.materials(from_b04)
        with self.subTest(proof="B04 resumed slot"):
            self.assertEqual(restored[sibling["id"]]["copies"][1], {**copy, "origin_status": "deleted"})
        for record in (primary, unproved):
            pending = restored[record["id"]]["copies"][1]
            self.assertEqual(pending["status"], "unavailable")
            self.assertFalse({"root", "path", "sha256"} & pending.keys())
            self.assertTrue(any(row["material"] == record["id"] and row["copy_index"] == 1 and row["status"] == "invalid"
                                for row in second["pending_copies"]))

        self.check_pre_generation_archive_proofs(now, sha)

    def check_pre_generation_archive_proofs(self, now, sha):
        inventory = custody.materials(self.vault)
        historical_files = []

        def prepare(material):
            exclusions = [retention.slot({"material": key, "copy_index": index, "copy": copy})
                          for key, record in inventory.items() if key != material
                          for index, copy in enumerate(record["copies"]) if copy["kind"] == "archive"]
            plan = retention.plan(self.vault, now, exclude=exclusions)
            entry, = plan["entries"]
            self.assertEqual((entry["material"], entry["copy_index"]), (material, 1))
            relative = f"deletions/{plan['id']}.json"
            historical_files.append(relative)
            target = Path(entry["copy"]["root"]) / entry["copy"]["path"]
            self.assertEqual(digest(target.read_bytes()), sha)
            return plan, entry, self.vault.control / relative, target

        # Completed single-slot proof from before B03 stored verified archive generations.
        plan, entry, path, target = prepare("archive-round")
        entry.update(status="deleted", at=stamp(now), verified_archive_sha256=sha)
        plan["status"] = "complete"
        atomic(path, plan)
        target.unlink()
        for key in ("archive-round", "archive-wrong-material"):
            inventory[key]["copies"][1].update(status="deleted", deleted_at=stamp(now), verified_archive_sha256=sha)
            custody.save_material(self.vault, inventory[key])
        receipt = self.vault.receipt("deletion-round", {"plan": plan["id"], "digest": plan["digest"], "status": "complete"},
                                     at=now)
        historical_files.append(f"receipts/{receipt}.json")

        # Resume the single-slot journal after unlink using the current B04 engine.
        plan, entry, path, target = prepare("archive-resumed")
        entry.update(status="deleting", verified_archive_sha256=sha)
        atomic(path, plan)
        target.unlink()
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        copy = custody.materials(self.vault)["archive-resumed"]["copies"][1]
        receipt_path = f"receipts/{copy['deletion_receipt']}.json"
        self.assertEqual(read_json(self.vault.control / receipt_path)["payload"],
                         {"material": "archive-resumed", "copy_index": 1, "sha256": sha, "intent": None})
        historical_files.append(receipt_path)

        # Early B04 persisted the primary slot and plan digest in the intent and listed archive slots in the plan entry.
        plan, entry, path, target = prepare("archive-intent-primary")
        intent = {"path": str(target), "slot": list(retention.slot(entry)),
                  "root_identity": retention.file_identity(Path(entry["copy"]["root"])),
                  "file_identity": retention.file_identity(target), "plan_digest": plan["digest"], "at": stamp(now)}
        entry.update(status="deleting", intent=intent, verified_archive_generations=[
            retention.generation_locator(inventory[key], 1, inventory[key]["copies"][1])
            for key in ("archive-intent-primary", "archive-intent-sibling")
        ])
        atomic(path, plan)
        target.unlink()
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        original = custody.materials(self.vault)
        for key in ("archive-intent-primary", "archive-intent-sibling"):
            receipt = original[key]["copies"][1]["deletion_receipt"]
            relative = f"receipts/{receipt}.json"
            self.assertEqual(read_json(self.vault.control / relative)["payload"],
                             {"material": key, "copy_index": 1, "sha256": sha, "intent": intent})
            historical_files.append(relative)

        history = (self.vault.control / "materials.json").read_bytes()
        restored = self.restore(self.create(), self.base / "early-restored", self.base / "early-state")
        new = Vault(restored["destination"], restored["state"])
        self.assertEqual((new.control / "historical/materials.json").read_bytes(), history)
        for relative in historical_files:
            self.assertEqual((new.control / relative).read_bytes(), (self.vault.control / relative).read_bytes())
        recovered = custody.materials(new)
        for key in ("archive-round", "archive-resumed", "archive-intent-primary", "archive-intent-sibling"):
            with self.subTest(proof=key):
                self.assertEqual(recovered[key]["copies"][1], {**original[key]["copies"][1], "origin_status": "deleted"})
        key = "archive-wrong-material"
        self.assertEqual(recovered[key]["copies"][1]["status"], "unavailable")
        self.assertTrue(any(row["material"] == key and row["copy_index"] == 1 and row["status"] == "invalid"
                            for row in restored["pending_copies"]))

        # A digest-valid plan with two entries for the same primary slot leaves the unnamed intent ambiguous.
        record = original["archive-intent-sibling"]
        copy = record["copies"][1]
        ambiguous = read_json(path)
        ambiguous["entries"].append(deepcopy(ambiguous["entries"][0]))
        ambiguous["digest"] = retention.plan_digest(ambiguous)
        altered_intent = {**intent, "plan_digest": ambiguous["digest"]}
        for entry in ambiguous["entries"]:
            entry["intent"] = altered_intent
        proof = {"kind": "deletion-copy", "at": copy["deleted_at"],
                 "payload": {"material": record["id"], "copy_index": 1, "sha256": sha, "intent": altered_intent}}
        identifier = digest(proof)
        records = {f"deletions/{ambiguous['id']}.json": ambiguous, f"receipts/{identifier}.json": proof}
        with self.assertRaisesRegex(Blocked, "lacks a verified deletion receipt"):
            backup_recovery.check_inactive_origin(record, 1, {**copy, "deletion_receipt": identifier}, records, [])

    def test_1_process_and_origin_paths_are_inactive(self):
        self.configure()
        task = tasks.create(self.vault, "Origin task with supervised process")
        session = tasks.new_session(self.vault, task["id"], "Capture", "editor", "Synthetic context")
        task = tasks.get_task(self.vault, task["id"])
        task["processes"] = [{"pid": os.getpid(), "session": session["operation"], "launch": "prior",
                              "started_identity": "fixture"}]
        session.update(state="running", usage={"input_tokens": 21, "output_tokens": 5, "evidence_bytes": 10},
                       launches=[{"id": "prior", "uuid": session["uuid"], "action": session["action"]}],
                       active_profile=str(self.state / "authentication"), launch_intent={"id": "in-progress"},
                       reconstruction={"material": str(uuid4()), "destination": str(self.state / "earlier-restore")})
        atomic(tasks.task_path(self.vault, task["id"]), task)
        atomic(self.vault.control / "sessions" / (session["operation"] + ".json"), session)
        atomic(self.state / "authentication/.credentials.json", b"disposable placeholder")
        atomic(self.state / "launchd/origin.plist", b"disposable placeholder")
        record = self.create()
        with patch("healdan.core.run", wraps=run) as processes:
            result = self.restore(record)
            restored = Vault(result["destination"], result["state"])
            active = tasks.get_task(restored, task["id"])
            with self.assertRaisesRegex(Blocked, "Restored task requires reconciliation"):
                tasks.reconcile_processes(restored, active)
            self.assertTrue(all(Path(call.args[0][0]).stem in {"git", "ssh-keygen", "age"} for call in processes.call_args_list))
        self.assertEqual(active["processes"], [])
        self.assertEqual(active["reconciliation"]["processes"], task["processes"])
        self.assertEqual(active["created_at"], task["created_at"])
        self.assertEqual(active["capacity_held"], task["capacity_held"])
        recovered = tasks.get_session(restored, session["operation"])
        for name in ("uuid", "action", "launches", "usage"):
            self.assertEqual(recovered[name], session[name])
        self.assertEqual(recovered["state"], "reconciliation_required")
        self.assertEqual(recovered["reconciliation"]["reconstruction"], session["reconstruction"])
        self.assertFalse(any((restored.state / name).exists() for name in ("authentication", "launchd", "tasks")))
        self.assertFalse(git(restored.root, "remote"))

        task_id = task["id"]
        with self.assertRaisesRegex(Blocked, "Writing capacity is occupied"):
            tasks.create(restored, "Second task before reconciliation")
        with self.assertRaisesRegex(Blocked, "Restored task requires reconciliation"):
            tasks.preserve_and_close(restored, task_id)
        with self.assertRaisesRegex(Blocked, "Restored task requires reconciliation"):
            tasks.reconcile_expired(restored, task_id, utc() + timedelta(days=2))
        cli = [sys.executable, "-m", "healdan", "--vault", restored.root, "--state", restored.state, "task", "reconcile-restored", task_id]
        refused = run(cli, env=controller_environment(), check=False)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("--confirm", decode(refused.stdout)["error"])
        task_history = restored.control / "historical/tasks" / (task_id + ".json")
        session_history = restored.control / "historical/sessions" / (session["operation"] + ".json")
        self.assertEqual(task_history.read_bytes(), tasks.task_path(self.vault, task_id).read_bytes())
        self.assertEqual(session_history.read_bytes(), (self.vault.control / "sessions" / session_history.name).read_bytes())
        history_bytes = task_history.read_bytes()
        atomic(task_history, {**decode(history_bytes), "closed_at": "2000-01-01T00:00:00Z"})
        with self.assertRaisesRegex(Blocked, "Restored task origin record .* differs"):
            tasks.reconcile_restored(restored, task_id, confirmed=True)
        atomic(task_history, history_bytes)

        active_path = tasks.task_path(restored, task_id)
        atomic(active_path, {**active, "processes": task["processes"]})
        with self.assertRaisesRegex(Blocked, "Local task processes"):
            tasks.reconcile_restored(restored, task_id, confirmed=True)
        atomic(active_path, active)
        local_base = restored.state / "tasks" / task_id
        atomic(local_base / "local-evidence", b"needs separate handling")
        with self.assertRaisesRegex(Blocked, "Local task workspace"):
            tasks.reconcile_restored(restored, task_id, confirmed=True)
        (local_base / "local-evidence").unlink()
        local_base.rmdir()
        original_stat = Path.stat
        with patch("healdan.tasks.os.killpg", create=True, side_effect=AssertionError("origin process signal")), \
                patch("healdan.tasks.os.kill", side_effect=AssertionError("origin process signal")), \
                patch("healdan.core.run", wraps=run) as processes, \
                patch("pathlib.Path.stat", autospec=True) as stats:
            def no_origin_access(path, *args, **kwargs):
                self.assertFalse(path.is_relative_to(self.state) or path.is_relative_to(self.root), str(path))
                return original_stat(path, *args, **kwargs)

            stats.side_effect = no_origin_access
            closed = tasks.reconcile_restored(restored, task_id, confirmed=True)
            for call in processes.call_args_list:
                args = list(map(str, call.args[0]))
                self.assertIn(Path(args[0]).stem, {"git", "ssh-keygen", "age"})
                self.assertFalse(any(str(self.state) in value or str(self.root) in value for value in args), args)
        self.assertEqual(closed["state"], "closed")
        self.assertFalse(closed["capacity_held"])
        self.assertEqual(closed["created_at"], task["created_at"])
        self.assertEqual(closed["reconciliation_history"][0]["origin"], active["reconciliation"])
        self.assertEqual(tasks.get_session(restored, session["operation"]), recovered)
        self.assertEqual(tasks.get_task(self.vault, task_id), task)
        retry = run([*cli, "--confirm"], env=controller_environment())
        self.assertEqual(decode(retry.stdout), closed)
        git(restored.root, "config", "user.name", "Recovery operator")
        git(restored.root, "config", "user.email", "recovery@example.invalid")
        fresh = tasks.create(restored, "New writer after reconciliation")
        self.assertNotEqual(fresh["id"], task_id)
        self.assertTrue(fresh["capacity_held"])
        with self.assertRaisesRegex(Blocked, "Restored task"):
            tasks.reconcile_restored(restored, fresh["id"], confirmed=True)

    def test_1_restored_task_reconciliation_verifies_custody_and_resumes(self):
        self.configure()
        task = tasks.create(self.vault, "Waiting source task with a linked capture")
        task_id = task["id"]
        waiting = tasks.present(self.vault, task_id, "Which source is authoritative?", "presentation-proof")
        purpose = {"purpose": "Disposable task preservation", "necessity": "Coverage of B04 custody",
                   "owner": "fixture", "link": task_id}
        material_id = custody.capture_tree(self.vault, Path(task["worktree"]), task=task_id,
                                           classification="unknown", purpose=purpose)
        material = custody.materials(self.vault)[material_id]
        material["dependencies"].append("pending-predecessor")
        custody.save_material(self.vault, material)
        custody.hold(self.vault, material_id, "Preserve pending evidence", "human")
        policy = self.policy()
        record = self.create()

        unavailable = self.restore(record, self.base / "missing-capture", self.base / "missing-capture-state")
        missing = Vault(unavailable["destination"], unavailable["state"])
        with self.assertRaisesRegex(Blocked, "No verified capture ciphertext"):
            tasks.reconcile_restored(missing, task_id, confirmed=True)
        self.assertTrue(tasks.get_task(missing, task_id)["capacity_held"])
        self.assertIsNone(custody.materials(missing)[material_id].get("closed_at"))

        original_copy = material["copies"][0]
        copy = self.base / "remapped-task-capture.age"
        atomic(copy, (Path(original_copy["root"]) / original_copy["path"]).read_bytes())
        result = self.restore(record, remap={material_id: {"0": str(copy)}})
        restored = Vault(result["destination"], result["state"])
        policy_bytes = storage_policy.history_path(restored).read_bytes()
        local = restored.state / "custody" / (material_id + ".age")
        cipher = local.read_bytes()
        atomic(local, b"damaged local fixture")
        with self.assertRaisesRegex(Blocked, "Ciphertext changed"):
            tasks.reconcile_restored(restored, task_id, confirmed=True)
        self.assertTrue(tasks.get_task(restored, task_id)["capacity_held"])
        atomic(local, cipher)

        def interrupt_close(path, value, **kwargs):
            if path == tasks.task_path(restored, task_id) and value["state"] == "closed":
                raise OSError("fixture interruption before closing state")
            return atomic(path, value, **kwargs)

        with patch("healdan.tasks.atomic", side_effect=interrupt_close), self.assertRaisesRegex(OSError, "fixture interruption"):
            tasks.reconcile_restored(restored, task_id, confirmed=True)
        pending = tasks.get_task(restored, task_id)
        self.assertTrue(pending["capacity_held"])
        intent = pending["restored_closure_pending"]
        receipt = {"kind": "task-restored-reconciled", **intent}
        receipt_id = digest(receipt)
        self.assertEqual(read_json(restored.control / "receipts" / (receipt_id + ".json")), receipt)
        task_file = tasks.task_path(restored, task_id)
        before = task_file.read_bytes()
        with self.assertRaisesRegex(Blocked, "task reconcile-restored"):
            tasks.reconcile_clock(restored, pending, utc(waiting["presented_at"]) + timedelta(days=8))
        self.assertEqual(task_file.read_bytes(), before)
        closed = tasks.reconcile_restored(restored, task_id, confirmed=True)
        self.assertEqual(tasks.reconcile_restored(restored, task_id, confirmed=True), closed)
        self.assertEqual(closed["presented_at"], waiting["presented_at"])
        self.assertEqual(closed["delivery_receipt"], waiting["delivery_receipt"])
        self.assertEqual(closed["reconciliation_history"][-1]["receipt"], receipt_id)
        receipts = [(path.stem, read_json(path)) for path in (restored.control / "receipts").glob("*.json")]
        closure_receipts = [(key, receipt) for key, receipt in receipts if receipt["kind"] == "task-restored-reconciled"]
        self.assertEqual(len(closure_receipts), 1)
        self.assertEqual(closure_receipts[0][0], receipt_id)
        self.assertEqual(digest(closure_receipts[0][1]), receipt_id)
        self.assertEqual(storage_policy.history(restored), [policy])
        self.assertEqual(storage_policy.history_path(restored).read_bytes(), policy_bytes)

        later = utc(closed["closed_at"]) + timedelta(days=8)
        plan = retention.plan(restored, later)
        guarded = retention.execute(restored, plan["id"], later)
        preserved = custody.materials(restored)[material_id]
        self.assertEqual(preserved["closed_at"], closed["closed_at"])
        self.assertEqual(preserved["dependencies"], ["pending-predecessor"])
        self.assertEqual(preserved["holds"], custody.materials(self.vault)[material_id]["holds"])
        self.assertEqual(preserved["copies"][0]["status"], "unavailable")
        self.assertTrue(any(row.get("material") == material_id for row in guarded["pending"]))
        self.assertEqual(local.read_bytes(), cipher)

    def test_1_daily_reports_restored_task_and_continues_independent_work(self):
        self.configure()
        now = utc()
        task = tasks.create(self.vault, "Waiting task to recover", now=now)
        task_id = task["id"]
        waiting = tasks.present(self.vault, task_id, "Which source is authoritative?", "presentation-proof", now=now)
        result = self.restore(self.create())
        restored = Vault(result["destination"], result["state"])
        destination = self.base / "new-controller-replica"
        destination.mkdir()
        restored.config.update(self.vault.config, backup_destinations=[str(destination)], backup_generation_days=2)
        atomic(restored.config_path, restored.config)
        expired = backups.create(restored, "long", now + timedelta(days=1), now=now)
        task_file = tasks.task_path(restored, task_id)
        before = task_file.read_bytes()

        result = maintenance.daily(restored, now + timedelta(days=8))
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["notices"], [])
        self.assertEqual([row["task"] for row in result["pending"] if "task" in row], [task_id])
        self.assertIn("task reconcile-restored", result["pending"][0]["reason"])
        self.assertEqual(task_file.read_bytes(), before)
        self.assertEqual(custody.materials(restored)[expired["id"]]["copies"][0]["status"], "deleted")
        self.assertEqual(result["backup_result"]["status"], "complete")
        self.assertEqual(backups.verify_backup(restored, result["backup"])["status"], "complete")
        closed = tasks.reconcile_restored(restored, task_id, confirmed=True)
        self.assertEqual(closed["state"], "closed")
        self.assertEqual(closed["closure_reason"], "restored_reconciliation")
        self.assertEqual(closed["presented_at"], waiting["presented_at"])
        self.assertFalse(closed["capacity_held"])

    def trial_evidence(self, name, *, vault=None):
        vault = self.vault if vault is None else vault
        artifact = self.base / "origin-only trial artifact.json"
        atomic(artifact, {"fixture": "historical artifact body"})
        evidence = {"platform": "Darwin", "passed": True, "procedure": "Disposable fixture",
                    "started_at": "2026-06-01T00:00:00Z", "completed_at": "2026-06-01T00:01:00Z",
                    "artifacts": [{"path": str(artifact), "sha256": digest(artifact.read_bytes())}]}
        build = SimpleNamespace(identity={"version": "fixture", "sha256": "b" * 64}, entry_point=Path(sys.executable))

        def tool(tool_name):
            result = {"path": str(self.base / tool_name), "sha256": digest(tool_name)}
            if tool_name in trials.TOOL_ARGUMENTS:
                result["version"] = {"srt": vault.policy["srt_version"], "node": "v22.12.0"}.get(tool_name, "fixture")
            return result

        with patch("healdan.trials.platform.system", return_value="Darwin"), \
             patch("healdan.trials._tool", side_effect=tool):
            measurements = trials.environment(vault, name, build=build)
        return artifact, evidence, measurements

    def test_1_native_trial_receipts_survive_as_inactive_history(self):
        self.configure()
        name = "offline-recovery"
        current = f"trials/v2/{name}.json"
        legacy = f"trials/{name}.json"
        artifact, evidence, measurements = self.trial_evidence(name)
        old = self.signed({**evidence, "name": name, "commit": "c" * 40, "versions": {"age": "fixture"}}, "trial")
        old_bytes = b"\n" + canonical(old) + b"\r\n"
        atomic(self.vault.control / legacy, old_bytes)
        extra_legacy = {}
        legacy_evidence = {**evidence, "commit": self.vault.head(), "versions": {"age": "fixture"}}
        minimal = {"name": "claude-auth", "passed": True, "commit": self.vault.head()}
        for payload, nominal in (
            ({**legacy_evidence, "name": "native-resume", "procedure": {"steps": ["Resume the disposable session"]},
              "format": "personal-evidence-v1"}, True),
            ({**legacy_evidence, "name": "native-cleanup", "procedure": " \t\n", "format": trials.TRIAL_FORMAT,
              "environment": {"vault_id": "legacy-extra-field"}}, True),
            ({**legacy_evidence, "name": "launchd", "format": trials.TRIAL_FORMAT,
              "environment": {"description": "Additional legacy audit details"}}, False),
            (minimal, True),
            ({**minimal, "name": "offline-recovery"}, False),
        ):
            signed = human_sign(self.vault, payload, "trial")
            if nominal:
                body = b"\n" + canonical(signed) + b"\r\n"
                path = f"trials/{payload['name']}.json"
                atomic(self.vault.control / path, body)
                extra_legacy[path] = body
            mirrors = [receipt for receipt in (self.vault.control / "receipts").glob("*.json")
                       if read_json(receipt).get("payload") == signed]
            self.assertEqual(len(mirrors), 1)
            extra_legacy[f"receipts/{mirrors[0].name}"] = mirrors[0].read_bytes()
        audit_only = human_sign(self.vault, {**evidence, "name": "launchd", "commit": self.vault.head(),
                                             "versions": {"age": "fixture"}, "format": trials.TRIAL_FORMAT}, "trial")
        orphan = next(path for path in (self.vault.control / "receipts").glob("*.json")
                      if read_json(path).get("payload") == audit_only)
        extra_legacy[f"receipts/{orphan.name}"] = orphan.read_bytes()
        with patch("healdan.trials.environment", return_value=measurements):
            approval = trials.attest(self.vault, name, {**evidence, "environment": measurements})
        current_bytes = b"  " + canonical(approval) + b"\r\n"
        atomic(self.vault.control / current, current_bytes)
        artifact.unlink()
        atomic(self.vault.control / "trials/v2/unrelated.json", {"secret": "INCIDENTAL_TRIAL_CONTENT"})
        atomic(self.state / "authentication/credentials.json", {"secret": "ORIGIN_ONLY_AUTHENTICATION"})

        backup = self.create()
        plain = custody.decrypt(self.vault, self.paths(backup)[1].read_bytes())
        contents = backup_snapshot.check_entries(decode(plain), backup["approval"]["payload"])
        expected = {current: current_bytes, legacy: old_bytes, **extra_legacy}
        for path, body in expected.items():
            self.assertEqual(contents[backup_snapshot.STATE + path], body)
        self.assertFalse(any(b"INCIDENTAL_TRIAL_CONTENT" in body or b"ORIGIN_ONLY_AUTHENTICATION" in body or
                             b"historical artifact body" in body for body in contents.values()))

        result = self.restore(backup)
        restored = Vault(result["destination"], result["state"])
        self.assertEqual(restored.identity, self.vault.identity)
        for path, body in expected.items():
            if path.startswith("receipts/"):
                self.assertEqual((restored.control / path).read_bytes(), body)
                continue
            self.assertFalse((restored.control / path).exists())
            self.assertEqual((restored.control / "historical" / path).read_bytes(), body)
        with patch("healdan.trials.environment", return_value=measurements) as measure:
            self.assertFalse(any(row["passed"] for row in trials.status(restored)))
            measure.assert_not_called()
        self.assertFalse((restored.state / "authentication/credentials.json").exists())
        self.assertNotIn("signing_key", restored.config)
        self.assertNotIn("native_trial_profiles", restored.config)

        destination = self.base / "new-controller-trial-replica"
        destination.mkdir()
        rotated_key = self.base / "rotated-trial-signer"
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", rotated_key])
        rotated_signer = b"rotated " + rotated_key.with_suffix(".pub").read_bytes()
        atomic(self.signers, self.signers.read_bytes() + rotated_signer)
        restored.config.update(self.vault.config, backup_destinations=[str(destination)],
                               signing_key=str(rotated_key), signing_identity="rotated")
        atomic(restored.config_path, restored.config)
        atomic(artifact, {"fixture": "historical artifact body"})
        measurements = {**measurements, "config_sha256": "d" * 64}
        with patch("healdan.trials.environment", return_value=measurements):
            fresh = trials.attest(restored, name, {**evidence, "environment": measurements})
        fresh_bytes = (restored.control / current).read_bytes()
        self.assertNotEqual(fresh, approval)
        next_backup = backups.create(restored, "long", utc() + timedelta(days=2))
        next_copy = next_backup["copies"][0]
        next_paths = (destination / next_copy["manifest"], destination / next_copy["path"])
        rotated_only = self.base / "current-allowed-signers"
        atomic(rotated_only, rotated_signer)
        with self.assertRaisesRegex(Blocked, "Invalid human SSH signature"):
            backups.verify_portable(next_backup["id"], *next_paths, **{**self.trust, "allowed_signers": rotated_only})
        result = self.restore(next_backup, self.base / "second-recovery", self.base / "second-state",
                              paths=next_paths)
        again = Vault(result["destination"], result["state"])
        for path, body in expected.items():
            folder = again.control if path.startswith("receipts/") else again.control / "historical"
            self.assertEqual((folder / path).read_bytes(), body)
        self.assertEqual((again.control / "historical/generations" / next_backup["id"] / current).read_bytes(), fresh_bytes)
        self.assertFalse(any(row["passed"] for row in trials.status(again)))

    def test_1_native_trial_case_matches_local_reader(self):
        self.configure()
        name = "offline-recovery"
        relative = f"trials/v2/{name}.json"
        path = self.vault.control / relative
        _, evidence, measured = self.trial_evidence(name)
        with patch("healdan.trials.environment", return_value=measured):
            trials.attest(self.vault, name, {**evidence, "environment": measured})
        original = b"\n" + path.read_bytes() + b"\r\n"
        atomic(path, original)
        alias = path.with_name(path.name.upper())
        case_insensitive = alias.exists()
        path.rename(path.with_name("rename.json")).rename(alias)
        with patch("healdan.trials.environment", return_value=measured):
            status = next(row for row in trials.status(self.vault) if row["name"] == name)
        self.assertEqual(status["passed"], case_insensitive)

        record = self.create()
        plain = custody.decrypt(self.vault, self.paths(record)[1].read_bytes())
        contents = backup_snapshot.check_entries(decode(plain), record["approval"]["payload"])
        self.assertNotIn(backup_snapshot.STATE + f"trials/v2/{alias.name}", contents)
        result = self.restore(record)
        recovered = Vault(result["destination"], result["state"])
        history = recovered.control / "historical" / relative
        if case_insensitive:
            self.assertEqual(contents[backup_snapshot.STATE + relative], original)
            self.assertEqual(history.read_bytes(), original)
            history.rename(history.with_name("rename.json")).rename(history.with_name(alias.name))
            self.assertEqual(backup_snapshot.control_records(recovered)["historical/" + relative], original)
        else:
            self.assertNotIn(backup_snapshot.STATE + relative, contents)
            self.assertFalse(history.exists())
        self.assertFalse((recovered.control / relative).exists())
        self.assertEqual(alias.read_bytes(), original)

    def test_1_orphan_native_trial_mirrors_keep_their_compatible_format(self):
        self.configure()
        qa = {"identity": "fixture identity", "namespace": "local label", "signature": "artifact description"}
        receipt_bytes, nominal_bytes = {}, {}
        for name in trials.TRIALS:
            _, evidence, measured = self.trial_evidence(name)
            common = {**evidence, "name": name, "commit": self.vault.head(), "qa": qa, "versions": {"age": "fixture"}}
            artifact = evidence["artifacts"][0]
            variant = {
                "claude-auth": {"environment": {**measured, "profile": {"trial": name}, "policy": {}}},
                "native-resume": {"versions": ["age"], "environment": {"vault_id": "legacy-audit-value"}},
                "native-cleanup": {"versions": "fixture", "procedure": {"steps": ["Disposable fixture"]},
                                   "artifacts": [{**artifact, "role": "recorded rehearsal"}]},
                "offline-recovery": {"artifacts": [artifact, {**artifact, "role": "second evidence entry"}]},
                "launchd": {"environment": {**measured, "schedules": []}},
            }[name]
            legacy = {**common, "environment": measured, **variant}
            older = human_sign(self.vault, {**legacy, "format": trials.TRIAL_FORMAT}, "trial")
            nominal = self.vault.control / "trials" / f"{name}.json"
            atomic(nominal, older)
            path, = [receipt for receipt in (self.vault.control / "receipts").glob("*.json")
                     if read_json(receipt).get("payload") == older]
            receipt_bytes[path.name] = path.read_bytes()
            renewed = human_sign(self.vault, {**common, "versions": {"age": "newer fixture"}}, "trial")
            atomic(nominal, renewed)
            self.assertNotEqual(read_json(nominal), older)
            nominal_bytes[f"trials/{name}.json"] = nominal.read_bytes()

            measurements = [measured]
            if name == "launchd":
                historical = deepcopy(measured)
                for row in historical["schedules"]:
                    job = row["ProgramArguments"][9]
                    row["ProgramArguments"][7:] = ["lint"] if job == "lint" else ["maintenance", "daily"]
                    row.pop("EnvironmentVariables")
                measurements.append(historical)
            for measurement in measurements:
                with patch("healdan.trials.environment", return_value=measurement):
                    measured_approval = trials.attest(self.vault, name, {**evidence, "environment": measurement})
                (self.vault.control / "trials/v2" / f"{name}.json").unlink()
                measured_mirror, = [path for path in (self.vault.control / "receipts").glob("*.json")
                                    if read_json(path).get("payload") == measured_approval]
                receipt_bytes[measured_mirror.name] = measured_mirror.read_bytes()

        record = self.create()
        plain = custody.decrypt(self.vault, self.paths(record)[1].read_bytes())
        contents = backup_snapshot.check_entries(decode(plain), record["approval"]["payload"])
        result = self.restore(record)
        recovered = Vault(result["destination"], result["state"])
        for filename, original in receipt_bytes.items():
            relative = f"receipts/{filename}"
            self.assertEqual(contents[backup_snapshot.STATE + relative], original)
            self.assertEqual((recovered.control / relative).read_bytes(), original)
        for relative, original in nominal_bytes.items():
            self.assertEqual(contents[backup_snapshot.STATE + relative], original)
            self.assertEqual((recovered.control / "historical" / relative).read_bytes(), original)
            self.assertFalse((recovered.control / relative).exists())
        self.assertFalse(any(row["passed"] for row in trials.status(recovered)))

        foreign_root, foreign_state = self.base / "foreign", self.base / "foreign-state"
        initialize(foreign_root, foreign_state)
        foreign = Vault(foreign_root, foreign_state)
        foreign.config.update(self.vault.config)
        atomic(foreign.config_path, foreign.config)
        name = "offline-recovery"
        _, evidence, measured = self.trial_evidence(name, vault=foreign)
        with patch("healdan.trials.environment", return_value=measured):
            unrelated = trials.attest(foreign, name, {**evidence, "commit": self.vault.head(), "versions": {"age": "fixture"},
                                                      "environment": measured})
        forged = {**older, "signature": "Invalid SSH fixture"}
        inventory = custody.materials(self.vault)
        files = sorted(self.destinations[0].iterdir())
        for receipt, reason in ((unrelated, "source vault"), (forged, "Invalid human SSH signature")):
            with self.subTest(reason=reason):
                proof = self.vault.receipt("trial-signature", receipt)
                try:
                    with self.assertRaisesRegex(Blocked, reason):
                        self.create()
                finally:
                    (self.vault.control / "receipts" / (proof + ".json")).unlink()
                self.assertEqual(custody.materials(self.vault), inventory)
                self.assertEqual(sorted(self.destinations[0].iterdir()), files)
        self.vault.receipt("ordinary-fixture", {"qa": qa})
        with self.assertRaisesRegex(Blocked, "Unknown signature envelope in snapshot"):
            self.create()

    def test_1_invalid_native_trial_evidence_blocks_backup_publication(self):
        self.configure()
        name = "offline-recovery"
        _, evidence, measured = self.trial_evidence(name)
        payload = {**evidence, "name": name, "format": trials.TRIAL_FORMAT, "environment": measured}
        approved = self.signed(payload, "trial")
        wrong_measurement = {**measured, "python": {"command": 0, "version": "3.12.10"}}
        legacy_extras = {"commit": self.vault.head(), "versions": {"age": "fixture"}}
        missing_tool = {tool: value for tool, value in measured["tools"].items() if tool != "age"}
        unrelated_tool = {**missing_tool, "other-tool": measured["tools"]["age"]}
        path = self.vault.control / f"trials/v2/{name}.json"
        for value, reason in (
            ({"payload": payload}, "Invalid signed trial receipt"),
            (self.signed({**payload, "name": "launchd"}, "trial"), "invalid name"),
            (self.signed({**payload, "environment": {**measured, "vault_id": str(uuid4())}}, "trial"), "source vault"),
            (self.signed({**payload, **legacy_extras, "environment": wrong_measurement}, "trial"), "measured trial environment"),
            (self.signed({**payload, "environment": {**measured, "tools": missing_tool}}, "trial"), "measured trial environment"),
            (self.signed({**payload, "environment": {**measured, "tools": unrelated_tool}}, "trial"), "measured trial environment"),
            (self.signed({**payload, "procedure": {"steps": ["Disposable"]}}, "trial"), "a procedure"),
            (self.signed({**payload, "procedure": " \t"}, "trial"), "a procedure"),
            (self.signed({**payload, "artifacts": [{"path": "/origin/fixture", "sha256": "invalid"}]}, "trial"), "artifact inventory"),
            (self.signed({**payload, **legacy_extras, "artifacts": evidence["artifacts"] * 2}, "trial"), "measured trial artifact paths"),
            (self.signed({**payload, "completed_at": "2026-01-01T00:00:00Z"}, "trial"), "Invalid trial times"),
            ({**approved, "payload": {**payload, "procedure": "Changed evidence"}}, "Signed payload was changed"),
        ):
            with self.subTest(reason=reason):
                atomic(path, value)
                with self.assertRaisesRegex(Blocked, reason):
                    self.create()
                self.assertEqual(list(self.destinations[0].iterdir()), [])
                self.assertEqual(custody.materials(self.vault), {})
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(Blocked, "Required regular file is missing"):
            self.create()
        path.rmdir()
        foreign = self.signed({**payload, "environment": {**measured, "vault_id": str(uuid4())}}, "trial")
        proof = self.vault.receipt("trial-signature", foreign)
        try:
            with self.assertRaisesRegex(Blocked, "source vault"):
                self.create()
        finally:
            (self.vault.control / "receipts" / (proof + ".json")).unlink()
        legacy = self.vault.control / "trials" / f"{name}.json"
        minimal = {"name": name, "passed": True, "commit": self.vault.head()}
        for value, reason in (
            (self.signed({**minimal, "format": "truncated"}, "trial"), "invalid timestamps"),
            ({**self.signed(minimal, "trial"), "signature": "invalid"}, "Invalid human SSH signature"),
            (self.signed({**minimal, "commit": "abc"}, "trial"), "Invalid legacy trial result or commit"),
        ):
            with self.subTest(reason=reason):
                atomic(legacy, value)
                with self.assertRaisesRegex(Blocked, reason):
                    self.create()
                self.assertEqual(list(self.destinations[0].iterdir()), [])

    def test_1_deleted_replica_proof_after_origin_rebind(self):
        self.configure()
        original_destination = self.state / "backup-inside-state"
        original_destination.mkdir()
        self.vault.config["backup_destinations"] = [str(original_destination)]
        atomic(self.vault.config_path, self.vault.config)
        now = utc()
        expired = backups.create(self.vault, "long", now - timedelta(days=1), now=now - timedelta(days=2))
        moved_state = self.state.rename(self.base / "relocated-origin-state")
        preview = binding.rebind(self.root, moved_state)
        binding.rebind(self.root, moved_state, preview["confirmation"])
        moved = Vault(self.root, moved_state)
        plan = retention.plan(moved, now)
        self.assertEqual(retention.execute(moved, plan["id"], now)["status"], "complete")
        retired = custody.materials(moved)[expired["id"]]
        receipt_id = retired["copies"][0]["deletion_receipt"]
        receipt_path = f"receipts/{receipt_id}.json"
        receipt = read_json(moved.control / receipt_path)
        self.assertEqual(Path(receipt["payload"]["intent"]["path"]).parent, moved_state / original_destination.name)
        self.assertEqual(retired["copies"][0]["root"], str(original_destination))
        self.assertEqual(len(backups.verify_replica_deletions(moved, retired)), 1)

        generation = backups.create(moved, "long", now + timedelta(days=2), now=now)
        replica = moved_state / original_destination.name
        pair = tuple(replica / generation["copies"][0][name] for name in ("manifest", "path"))
        result = self.restore(generation, paths=pair)
        restored = Vault(result["destination"], result["state"])
        restored_retired = custody.materials(restored)[expired["id"]]
        self.assertEqual(restored.binding["previous"], [])
        self.assertEqual(restored_retired["copies"][0]["status"], "deleted")
        self.assertEqual(read_json(restored.control / receipt_path), receipt)
        self.assertEqual(len(backups.verify_replica_deletions(restored, restored_retired)), 1)
        historical_binding = restored.control / "historical/generations" / generation["id"] / "binding.json"
        altered = read_json(historical_binding)
        altered["previous"].append(altered["location"])
        atomic(historical_binding, altered)
        with self.assertRaisesRegex(Blocked, "Historical storage relocation differs"):
            backups.verify_replica_deletions(restored, restored_retired)

    def test_1_legacy_envelope_with_backup_off(self):
        self.configure()
        self.policy("off")
        tracked = self.tracked_modes()
        identifier = str(uuid4())
        expiry = stamp(utc() + timedelta(days=2))
        bundle = self.base / "legacy.bundle"
        git(self.root, "bundle", "create", str(bundle), "--all")
        member = self.conversation("legacy-short", closed_at=utc())
        member_name = "custody/" + member["id"] + ".age"
        member_copy = member["copies"][0]
        member_cipher = (Path(member_copy["root"]) / member_copy["path"]).read_bytes()
        files = {name: backup_snapshot.file_entry("knowledge", (self.root / name).read_bytes()) for name in self.vault.inputs()}
        files[backup_snapshot.BUNDLE] = backup_snapshot.file_entry("git", bundle.read_bytes())
        files[backup_snapshot.MATERIALS] = backup_snapshot.file_entry("custody-manifests", canonical({
            member["id"]: {key: value for key, value in member.items() if key != "copies"}}))
        files[member_name] = backup_snapshot.file_entry("conversation", member_cipher)
        for entry in files.values():
            entry.pop("kind")
        archive = {"format": "healdan-tree-v1", "files": files}
        plain = canonical(archive)
        cipher = custody.encrypt(self.vault, plain)
        replica = self.destinations[0] / (identifier + ".age")
        atomic(replica, cipher)
        record = {"id": identifier, "kind": "backup", "generation": "short", "created_at": stamp(), "expires_at": expiry,
                  "members": [member["id"]], "commit": self.vault.head(), "plain_sha256": digest(plain), "cipher_sha256": digest(cipher),
                  "holds": [], "dependencies": [], "copies": [
                      {"root": str(replica.parent), "path": replica.name, "sha256": digest(cipher), "kind": "ciphertext", "status": "present"},
                      {"root": str(self.base / "lost"), "path": replica.name, "sha256": digest(cipher), "kind": "ciphertext", "status": "present"}],
                  "status": "complete", "verified_at": stamp()}
        record["approval"] = envelope(record.copy(), "backup", "backup", self.vault.config["backup_signing_key"])
        signed = canonical(record["approval"])
        record["copies"] = [dict(copy) for copy in record["copies"]]
        record["copies"][1]["status"] = "unavailable"
        custody.save_material(self.vault, record)
        code, report = self.cli("backup", "verify", identifier)
        self.assertEqual(code, 4, report)
        self.assertEqual(report["pending_replicas"][0]["status"], "unavailable")
        mask = 0o027
        previous = os.umask(mask)
        try:
            result = backups.restore(self.vault, identifier, self.base / "restored-legacy")
        finally:
            os.umask(previous)
        root = Path(result["destination"])
        self.assert_tracked_modes(root, tracked, mask)
        self.assertIn("Legacy backup omitted", result["pending_copies"][0])
        self.assertEqual((root / member_name).read_bytes(), member_cipher)
        if os.name != "nt":
            for path in (root / member_name, root / backup_snapshot.MATERIALS, root / ".git/healdan/restored-from.json"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        legacy_state = self.base / "legacy-adopted-state"
        adoption = binding.adopt(result["destination"], legacy_state)
        self.assertEqual(adoption["provenance"][0]["kind"], "restored-backup")
        binding.adopt(result["destination"], legacy_state, adoption["confirmation"])
        self.assertNotEqual(Vault(result["destination"], legacy_state).identity, self.vault.identity)
        self.assertEqual(canonical(custody.materials(self.vault)[identifier]["approval"]), signed)
        self.assertEqual(custody.materials(self.vault)[identifier]["expires_at"], expiry)
        with self.assertRaisesRegex(Blocked, "both a trusted manifest"):
            backups.verify_portable(identifier, None, replica, **self.trust)

        first, second = record["copies"]
        reordered = {**record, "copies": [second, first]}
        custody.save_material(self.vault, reordered)
        report = backups.verify_backup(self.vault, identifier)
        self.assertEqual([(row["copy_index"], row["status"]) for row in report["replicas"]],
                         [(1, "unavailable"), (0, "verified")])
        self.assertTrue(any("catalog order" in row["reason"] for row in report["pending_replicas"]))
        with self.assertRaisesRegex(Blocked, "Signed backup manifest changed"):
            backups.inspect_backup(self.vault, reordered)
        damaged = {**record, "copies": [first, {**second, "root": str(self.base / "unsigned-root")}]}
        custody.save_material(self.vault, damaged)
        report = backups.verify_backup(self.vault, identifier)
        self.assertEqual([entry["status"] for entry in report["replicas"]], ["verified", "invalid"])
        with self.assertRaisesRegex(Blocked, "Signed backup manifest changed"):
            backups.inspect_backup(self.vault, damaged)
        atomic(Path(second["root"]) / second["path"], cipher)
        for index, copy in enumerate((first, {**second, "status": "present"})):
            with self.subTest(retained_legacy_slot=index):
                truncated = {**record, "copies": [copy]}
                custody.save_material(self.vault, truncated)
                report = backups.verify_backup(self.vault, identifier)
                restored = backups.restore(self.vault, identifier, self.base / f"truncated-legacy-{index}")
                for checked in (report, restored):
                    self.assertEqual(checked["replica"], str(Path(copy["root"]) / copy["path"]))
                    self.assertEqual([(row["copy_index"], row["status"]) for row in checked["replicas"]], [(index, "verified")])
                    self.assertIn("replica count", checked["pending_replicas"][0]["reason"])
                with self.assertRaisesRegex(Blocked, "replica count"):
                    backups.inspect_backup(self.vault, truncated)
                with self.assertRaisesRegex(Blocked, "replica count"):
                    backups.signed_manifest(self.vault, truncated)
                self.assertEqual(custody.materials(self.vault)[identifier], truncated)

    def test_1_destination_retry_and_verified_bytes(self):
        self.configure()
        record = self.create()
        destination = self.base / "occupied"
        destination.mkdir()
        atomic(destination / "untouched", b"keep")
        with self.assertRaisesRegex(Blocked, "new or empty"):
            self.restore(record, destination)
        self.assertEqual((destination / "untouched").read_bytes(), b"keep")
        (destination / "untouched").unlink()
        _, replica = self.paths(record)
        cipher = replica.read_bytes()
        build = backup_recovery.build_portable

        def stop_build(stage, *args, **kwargs):
            atomic(stage / "unfinished", b"registered intermediate")
            raise RuntimeError("fixture reconstruction interruption")

        with patch("healdan.backup_recovery.build_portable", side_effect=stop_build), self.assertRaisesRegex(RuntimeError, "reconstruction"):
            self.restore(record, destination)
        state = self.base / "recovered-state"
        journal = read_json(state / backup_recovery.JOURNAL_FILE)
        stage = destination.parent / journal["stage"]
        self.assertTrue((stage / "unfinished").exists())
        self.assertEqual(list(destination.iterdir()), [])

        def stop_binding(path, payload):
            if path == stage / ".git/healdan/binding.json":
                raise RuntimeError("fixture binding interruption")
            return atomic(path, payload)

        with patch("healdan.binding.atomic", side_effect=stop_binding), self.assertRaisesRegex(RuntimeError, "binding"):
            self.restore(record, destination)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertTrue((state / "binding.json").exists())

        def swap_replica(*args, **kwargs):
            atomic(replica, b"replacement after verification")
            return build(*args, **kwargs)

        with patch("healdan.backup_recovery.build_portable", side_effect=swap_replica):
            result = self.restore(record, destination)
        self.assertEqual((destination / "wiki/claims.jsonl").read_bytes(), b"")
        self.assertTrue(Vault(destination, state))
        atomic(replica, cipher)
        self.assertEqual(self.restore(record, destination)["receipt"], result["receipt"])
        receipts = [read_json(path) for path in (destination / ".git/healdan/receipts").glob("*.json")]
        self.assertEqual([receipt["kind"] for receipt in receipts].count("backup-restored"), 1)

        other = self.base / "published-before-completion"
        other_state = self.base / "published-state"

        def stop_after_rename(path):
            raise RuntimeError("fixture after directory rename")

        with patch("healdan.backup_recovery.sync_directory", side_effect=stop_after_rename), \
                self.assertRaisesRegex(RuntimeError, "after directory rename"):
            self.restore(record, other, other_state)
        self.assertEqual(read_json(other_state / backup_recovery.JOURNAL_FILE)["phase"], "ready")
        if os.name != "nt":
            published = other / "wiki/claims.jsonl"
            mode = stat.S_IMODE(published.stat().st_mode)
            published.chmod(mode ^ stat.S_IXUSR)
            with self.assertRaisesRegex(Blocked, "destination changed before completion"):
                self.restore(record, other, other_state)
            published.chmod(mode)
        atomic(other / "wiki/claims.jsonl", b"changed before completion")
        with self.assertRaisesRegex(Blocked, "destination changed before completion"):
            self.restore(record, other, other_state)
        self.assertEqual((other / "wiki/claims.jsonl").read_bytes(), b"changed before completion")

        remapped = self.base / "remapped-copy"
        remapped_bytes = b"verified remapped recovery evidence"
        atomic(remapped, remapped_bytes)
        material = {"id": "remap-ready-test", "kind": "export", "classification": "common", "captured_at": stamp(),
                    "copies": [{"root": str(remapped.parent), "path": remapped.name, "sha256": digest(remapped_bytes),
                                "kind": "export", "status": "present"}],
                    "holds": [], "dependencies": []}
        custody.save_material(self.vault, material)
        with_remap = self.create()
        destination = self.base / "ready-with-remap"
        external = self.base / "ready-with-remap-state"
        mapping = {material["id"]: {"0": str(remapped)}}
        destination.mkdir()
        with patch("healdan.backup_recovery.publish", side_effect=RuntimeError("fixture before publication")), \
                self.assertRaisesRegex(RuntimeError, "before publication"):
            self.restore(with_remap, destination, external, remap=mapping)
        if os.name != "nt":
            ready = read_json(external / backup_recovery.JOURNAL_FILE)
            staged = destination.parent / ready["stage"] / "wiki/claims.jsonl"
            mode = stat.S_IMODE(staged.stat().st_mode)
            staged.chmod(mode ^ stat.S_IXUSR)
            with self.assertRaisesRegex(Blocked, "staging bytes or modes changed"):
                self.restore(with_remap, destination, external, remap=mapping)
            self.assertFalse(any(destination.iterdir()))
            staged.chmod(mode)
        staged_copy = external / "recovered-copies" / material["id"] / "0" / remapped.name
        self.assertEqual(staged_copy.read_bytes(), remapped_bytes)
        atomic(staged_copy, b"changed while ready")
        with self.assertRaisesRegex(Blocked, "External recovery state changed before publication"):
            self.restore(with_remap, destination, external, remap=mapping)
        self.assertEqual(staged_copy.read_bytes(), b"changed while ready")
        self.assertFalse(any(destination.iterdir()))
        self.assertEqual(read_json(external / backup_recovery.JOURNAL_FILE)["phase"], "ready")
        atomic(staged_copy, remapped_bytes)
        completed = self.restore(with_remap, destination, external, remap=mapping)
        atomic(staged_copy, b"normal post-recovery change")
        if os.name != "nt":
            recovered = destination / "wiki/claims.jsonl"
            recovered.chmod(stat.S_IMODE(recovered.stat().st_mode) ^ stat.S_IXUSR)
        self.assertEqual(self.restore(with_remap, destination, external, remap=mapping)["receipt"], completed["receipt"])

    def test_2_positive_snapshot_selection(self):
        self.configure()
        self.source()
        self.commit("Admit disposable source")
        name = "resources/sources/F-0001/original.txt"
        original = (self.root / name).read_bytes()
        self.conversation("retained-as-manifest")
        atomic(self.vault.control / "csp.json", b'{"streak":9}\r\n')
        atomic(self.root / name, b"staged source change")
        git(self.root, "add", name)
        atomic(self.root / "wiki/ignored.key", b"disposable ignored marker")
        atomic(self.root / "wiki/untracked.md", b"untracked")
        record = self.create()
        _, replica = self.paths(record)
        archive = decode(custody.decrypt(self.vault, replica.read_bytes(), self.identities[1]))
        files = archive["files"]
        expected = {name for name, *_ in backup_snapshot.tree_entries(self.root, record["commit"])
                    if backup_snapshot.knowledge_name(name)}
        expected.update({backup_snapshot.BUNDLE, backup_snapshot.MATERIALS, backup_snapshot.STATE + "csp.json"})
        expected.update(backup_snapshot.STATE + "receipts/" + p.name for p in (self.vault.control / "receipts").glob("*.json")
                        if read_json(p)["kind"] == "capture")
        self.assertEqual(set(files), expected)
        self.assertEqual(digest(backup_snapshot.inventory(archive)), record["inventory_sha256"])
        import base64
        for entry in files.values():
            data = base64.b64decode(entry["body"])
            self.assertEqual((len(data), digest(data)), (entry["size"], entry["sha256"]))
        self.assertEqual(base64.b64decode(files[name]["body"]), original)
        self.assertEqual(base64.b64decode(files[backup_snapshot.STATE + "csp.json"]["body"]), b'{"streak":9}\r\n')
        self.assertIn(b"retained-as-manifest", base64.b64decode(files[backup_snapshot.MATERIALS]["body"]))

    def test_2_edits_during_capture_use_only_verified_bytes(self):
        self.configure()
        original = b"binary\x00\xff\r\nsecond line\r\n"
        path = "resources/sources/F-0001/original.bin"
        atomic(self.root / path, original)
        self.rows("resources/sources/index.jsonl", [{"id": "F-0001", "path": path, "sha256": digest(original),
                  "size": len(original), "captured_at": stamp(), "provenance": "Fixture", "classification": "common"}])
        self.commit("Preserve CRLF binary source")
        check = backup_snapshot.check_snapshot
        csp = self.vault.control / "csp.json"
        atomic(csp, {"streak": 9})
        read_file = Path.read_bytes

        def unavailable_record(file):
            if file == csp:
                raise PermissionError("fixture required snapshot record unavailable")
            return read_file(file)

        with patch.object(Path, "read_bytes", unavailable_record), self.assertRaisesRegex(Blocked, "Cannot freeze required backup records"):
            self.create()
        self.assertEqual(list(self.destinations[0].iterdir()), [])

        def race(*args, **kwargs):
            verified = check(*args, **kwargs)
            atomic(self.root / path, b"working copy diverged")
            atomic(csp, {"streak": 10})
            return verified

        with patch("healdan.backup_snapshot.check_snapshot", side_effect=race), self.assertRaisesRegex(Blocked, "records changed"):
            self.create()
        self.assertEqual(list(self.destinations[0].iterdir()), [])
        self.assertEqual(custody.materials(self.vault), {})

        def edit_after_freeze(controller, plain):
            atomic(self.root / path, b"edited again")
            atomic(csp, {"streak": 11})
            return custody.encrypt(controller, plain)

        with patch("healdan.backups.encrypt", side_effect=edit_after_freeze):
            record = self.create()
        recovered = self.restore(record)
        root = Path(recovered["destination"])
        self.assertEqual((root / path).read_bytes(), original)
        self.assertEqual(read_json(root / ".git/healdan/csp.json"), {"streak": 10})

    def test_2_references_fixed_even_with_detached_head(self):
        self.configure()
        baseline = self.vault.head()
        atomic(self.root / "wiki/a.md", b"later commit")
        self.commit("Second knowledge commit")
        later = self.vault.head()
        git(self.root, "branch", "other", baseline)
        git(self.root, "tag", "original-tag", baseline)
        freeze = backup_snapshot.frozen_bundle
        for detached in (False, True):
            with self.subTest(detached=detached):
                git(self.root, "switch", "--detach", baseline) if detached else git(self.root, "switch", "main")
                expected = backup_snapshot.git_identity(self.root)

                def move_ref(vault, identity):
                    git(vault.root, "update-ref", "refs/heads/other", later)
                    if detached:
                        git(vault.root, "update-ref", "--no-deref", "HEAD", later)
                    return freeze(vault, identity)

                with patch("healdan.backup_snapshot.frozen_bundle", side_effect=move_ref):
                    record = self.create()
                result = self.restore(record, self.base / f"recovered-{detached}", self.base / f"state-{detached}")
                self.assertEqual(backup_snapshot.git_identity(result["destination"]), expected)
                git(self.root, "update-ref", "refs/heads/other", baseline)

    def test_2_history_checks_paths_even_when_blobs_match(self):
        self.configure()
        data = b"same harmless bytes at both Git paths"
        atomic(self.root / "wiki/valid.md", data)
        self.commit("Admit harmless path")
        git(self.root, "switch", "-c", "separate-branch")
        atomic(self.root / "transcripts/body.txt", data)
        self.commit("Prohibited historical path")
        git(self.root, "switch", "main")
        with self.assertRaisesRegex(Blocked, "Historical custody/secret paths"):
            self.create()
        self.assertFalse(any(self.destinations[0].iterdir()))
        git(self.root, "branch", "-D", "separate-branch")
        git(self.root, "tag", "-a", "ordinary-tag", "-m", "Ordinary annotation")
        self.assertEqual(self.create()["status"], "complete")
        old = self.vault.head()
        git(self.root, "commit", "--allow-empty", "-m", 'Disposable {"sessionId":"tag-or-commit","type":"assistant"}')
        with self.assertRaisesRegex(Blocked, "Native conversation object detected in Git commit"):
            self.create()
        git(self.root, "reset", "--mixed", old)
        git(self.root, "tag", "-a", "private-annotation", "-m", "-----BEGIN OPENSSH PRIVATE KEY-----")
        with self.assertRaisesRegex(Blocked, "Private key material detected in Git tag"):
            self.create()

    def test_2_short_eligibility_pending_and_permanent(self):
        self.configure()
        now = utc()
        eligible = self.conversation("eligible", closed_at=now)
        unknown = self.conversation("unknown-deadline")
        previous = self.create()
        damaged = {**previous, "copies": [None]}
        custody.save_material(self.vault, damaged)
        export_id = "unrelated-export"
        export_body = b"Export custody bytes"
        copies = []
        for name in ("old-export.txt", "verified-export.txt"):
            target = self.state / "custody" / name
            atomic(target, export_body)
            copies.append({"root": str(target.parent), "path": name, "kind": "export",
                           "sha256": digest(export_body), "status": "present"})
        export = {"id": export_id, "kind": "export", "classification": "common", "source_sha256": digest(export_body),
                  "captured_at": stamp(now - timedelta(days=40)), "copies": copies, "holds": [], "dependencies": []}
        custody.save_material(self.vault, export)
        pending = retention.plan(self.vault, now)
        self.assertEqual(pending["pending"][0]["material"], previous["id"])
        self.assertEqual([entry["copy_index"] for entry in pending["entries"] if entry["material"] == export_id], [0, 1])
        malformed = {**export, "copies": [{**copies[0], "path": "../unconfined.txt"},
                                         {**copies[1], "status": "unavailable"}]}
        custody.save_material(self.vault, malformed)
        malformed_plan = retention.plan(self.vault, now)
        pending_export = retention.execute(self.vault, malformed_plan["id"], now)
        self.assertEqual(pending_export["status"], "pending")
        self.assertTrue(any(row["material"] == export_id and row["copy_index"] == 0 and "relative and confined" in row["reason"]
                            for row in pending_export["pending"]))
        raw_inventory = (self.vault.control / "materials.json").read_bytes()
        deadline = now + timedelta(days=30)
        working = self.base / "unrelated-launch-directory"
        ordinary = working / "ordinary.txt"
        unrelated = b"Independent file outside the controller"
        atomic(ordinary, unrelated)
        homonym = working / "conversation.jsonl"
        os.link(ordinary, homonym)
        result = run([sys.executable, "-m", "healdan", "--vault", self.root, "--state", self.state,
                      "backup", "create", "--kind", "short", "--expires-at", stamp(deadline - timedelta(seconds=1)),
                      "--members", eligible["id"]], cwd=working, env=controller_environment(), check=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stderr, b"")
        self.assertTrue(ordinary.samefile(homonym))
        self.assertEqual(ordinary.read_bytes(), unrelated)
        record = decode(result.stdout)
        export_remap = self.base / "export-remap.txt"
        atomic(export_remap, export_body)
        with self.assertRaisesRegex(Blocked, "Unsafe backup path"):
            self.restore(record, remap={export_id: {"0": str(export_remap)}})
        new = self.restore(record, remap={export_id: {"1": str(export_remap)}})
        recovered = Vault(new["destination"], new["state"])
        self.assertEqual((recovered.control / "historical/materials.json").read_bytes(), raw_inventory)
        inventory = custody.materials(recovered)
        projected = inventory[previous["id"]]
        self.assertEqual([copy["status"] for copy in projected["copies"]], ["unavailable"])
        self.assertEqual(projected["approval"], previous["approval"])
        self.assertEqual({(row["material"], row["copy_index"]) for row in new["pending_copies"]
                          if row["status"] == "invalid"}, {(previous["id"], 0), (export_id, 0)})
        invalid, intact, local = inventory[export_id]["copies"]
        self.assertEqual(invalid["status"], "unavailable")
        self.assertFalse({"root", "path", "sha256"} & invalid.keys())
        self.assertEqual(intact["path"], copies[1]["path"])
        self.assertEqual(local["status"], "present")
        local_path = Path(local["root"]) / local["path"]
        self.assertEqual(local_path.read_bytes(), export_body)
        receipt = read_json(recovered.control / "receipts" / (local["recovery_receipt"] + ".json"))
        self.assertEqual(receipt["payload"]["origin_copy_index"], 1)
        self.assertEqual(read_json(recovered.control / "deletions" / (pending["id"] + ".json")),
                         {key: value for key, value in pending.items() if key != "pending"})
        self.assertEqual(retention.execute(recovered, pending["id"], now)["status"], "pending")
        self.assertEqual(local_path.read_bytes(), export_body)
        discovered = retention.plan(recovered, now)
        self.assertTrue(any(row["material"] == export_id and row["copy_index"] == 0 for row in discovered["pending"]))
        self.assertFalse(any(entry["material"] == export_id and entry["copy_index"] == 0 for entry in discovered["entries"]))
        self.assertTrue(all(path.is_file() for path in self.paths(previous)))
        current = inventory[eligible["id"]]
        self.assertEqual(current["closed_at"], eligible["closed_at"])
        self.assertEqual(current["plain_sha256"], eligible["plain_sha256"])
        self.assertEqual(current["cipher_sha256"], eligible["cipher_sha256"])
        self.assertEqual((recovered.state / "custody" / (eligible["id"] + ".age")).read_bytes(),
                         (self.state / "custody" / (eligible["id"] + ".age")).read_bytes())
        for expiry, member in ((deadline, eligible["id"]), (deadline + timedelta(seconds=1), eligible["id"]),
                               (deadline, unknown["id"])):
            with self.subTest(expiry=expiry, member=member), self.assertRaisesRegex(Blocked, "precede every finite"):
                self.create("short", expiry, [member])
        selected_copies = eligible["copies"].copy()
        selected_copies[0] = {**selected_copies[0], "sha256": "unproven"}
        custody.save_material(self.vault, {**eligible, "copies": selected_copies})
        with self.assertRaisesRegex(Blocked, "Invalid backed-up custody copy"):
            self.create("short", deadline - timedelta(seconds=1), [eligible["id"]])
        custody.save_material(self.vault, eligible)
        path = self.state / "custody" / (eligible["id"] + ".age")
        cipher = path.read_bytes()
        atomic(path, b"tampered")
        with self.assertRaisesRegex(Blocked, "Ciphertext changed"):
            self.create("short", now + timedelta(days=2), [eligible["id"]])
        self.assertEqual(self.create()["generation"], "long")
        atomic(path, cipher)
        self.policy(permanent=True)
        permanent = self.create("short", "permanent", [unknown["id"]])
        restored = self.restore(permanent, self.base / "permanent", self.base / "permanent-state")
        new_vault = Vault(restored["destination"], restored["state"])
        after = custody.materials(new_vault)[unknown["id"]]
        self.assertEqual(after["captured_at"], unknown["captured_at"])
        self.assertEqual(storage_policy.deadline(after, storage_policy.effective(new_vault)), ("permanent", None))

    def test_2_malformed_export_slots_preserve_history_and_known_hashes(self):
        self.configure()
        claim = self.claim()
        self.knowledge([claim])
        self.commit("Commit a disposable source")
        kept = self.state / "custody" / "export-copy.txt"
        atomic(kept, b"Independent export bytes")
        intact = {"root": str(kept.parent), "path": kept.name, "kind": "export", "status": "present",
                  "sha256": digest(kept.read_bytes())}
        misplaced = self.state / "misplaced-export.txt"
        atomic(misplaced, b"Export with a known digest and an unsafe locator")
        misplaced_sha = digest(misplaced.read_bytes())
        unsafe = {**intact, "path": "../" + misplaced.name, "sha256": misplaced_sha}
        key = "unrelated-export"
        record = {"id": key, "kind": "export", "classification": "common", "captured_at": stamp(),
                  "copies": [None, {k: v for k, v in intact.items() if k != "kind"}, intact, unsafe],
                  "holds": [], "dependencies": []}
        custody.save_material(self.vault, record)
        original = self.vault.control / "materials.json"
        raw = original.read_bytes()
        generation = self.create()
        archive = decode(custody.decrypt(self.vault, self.paths(generation)[1].read_bytes()))
        checked = backup_snapshot.check_entries(archive, generation["approval"]["payload"])
        self.assertEqual(backup_snapshot.records_from(checked)["materials.json"], raw)
        with self.assertRaisesRegex(Blocked, "Unsafe backup path"):
            self.restore(generation, remap={key: {"3": str(misplaced)}})
        restored = self.restore(generation, remap={key: {"2": str(kept)}})
        recovered = Vault(restored["destination"], restored["state"])
        self.assertEqual((recovered.control / "historical/materials.json").read_bytes(), raw)
        restored_export = custody.materials(recovered)[key]
        copies = restored_export["copies"]
        self.assertEqual([(index, copy["status"]) for index, copy in enumerate(copies)],
                         [(0, "unavailable"), (1, "unavailable"), (2, "unavailable"),
                          (3, "unavailable"), (4, "present")])
        receipt = read_json(recovered.control / "receipts" / (copies[4]["recovery_receipt"] + ".json"))
        self.assertEqual(receipt["payload"]["origin_copy_index"], 2)
        self.assertFalse({"root", "path", "sha256"} & copies[3].keys())
        self.assertIsNone(copies[3]["kind"])
        self.assertEqual(backup_snapshot.project_material_copies(restored_export), copies)
        classification = admission.Classification(recovered, admission.published_rows(recovered))
        with self.subTest(restored_hash=misplaced_sha):
            self.assertEqual(classification.current(misplaced_sha), ("common", None))
        self.assertEqual(misplaced.read_bytes(), b"Export with a known digest and an unsafe locator")

        # The same digest carries the restriction even when the copy's locator is unsafe.
        restricted_path = kept.with_name("restricted-export.txt")
        atomic(restricted_path, (self.root / "resources/sources/F-0001/original.txt").read_bytes())
        restricted = {**intact, "path": restricted_path.name, "sha256": digest(restricted_path.read_bytes())}
        for relative in (restricted_path.name, "../custody/" + restricted_path.name):
            with self.subTest(path=relative):
                custody.save_material(self.vault, {**record, "classification": "personal",
                                                  "copies": [None, {**restricted, "path": relative}]})
                with self.assertRaisesRegex(Blocked, "Conflicting source classifications"):
                    self.create()

    def test_2_malformed_origin_slot_preserves_recovered_conversation(self):
        self.configure()
        now = utc()
        closed = now - timedelta(days=40)
        retired = self.conversation("verified-checkpoint-deletion", closed_at=closed)
        retained_cipher = retention.slot({"material": retired["id"], "copy_index": 0, "copy": retired["copies"][0]})
        plan = retention.plan(self.vault, now, exclude=[retained_cipher])
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        retired_checkpoint = custody.materials(self.vault)[retired["id"]]["copies"][1]
        self.assertEqual(retired_checkpoint["status"], "deleted")
        self.assertFalse((Path(retired_checkpoint["root"]) / retired_checkpoint["path"]).exists())

        malformed = self.conversation("malformed-checkpoint", closed_at=closed)
        unproven_name = "unproven-checkpoint-deletion"
        atomic(self.state / unproven_name / "claimed-moved.txt", b"Checkpoint with no move record")
        atomic(self.state / unproven_name / "claimed-absent.txt", b"Checkpoint with no absence record")
        unproven = self.conversation(unproven_name, closed_at=closed)
        malformed_copy = {k: v for k, v in malformed["copies"][1].items() if k != "kind"}
        custody.save_material(self.vault, {**malformed, "copies": [malformed["copies"][0], malformed_copy]})
        claims = {"conversation.jsonl": "deleted", "claimed-moved.txt": "moved", "claimed-absent.txt": "absent"}
        custody.save_material(self.vault, {**unproven, "copies": [
            unproven["copies"][0], *({**copy, "status": claims[copy["path"]]} for copy in unproven["copies"][1:])]})
        independent = self.state / "custody" / "expired-export.txt"
        atomic(independent, b"Independently eligible for deletion")
        export = {"id": "independent-export", "kind": "export", "classification": "common",
                  "captured_at": stamp(now - timedelta(days=40)), "holds": [], "dependencies": [],
                  "copies": [{"root": str(independent.parent), "path": independent.name,
                              "kind": "export", "sha256": digest(independent.read_bytes()), "status": "present"}]}
        custody.save_material(self.vault, export)
        conversations = (malformed, unproven, retired)
        encrypted = {record["id"]: Path(record["copies"][0]["root"]) / record["copies"][0]["path"]
                     for record in conversations}
        ciphertext = {key: path.read_bytes() for key, path in encrypted.items()}
        restored = self.restore(self.create(), remap={**{key: {"0": str(path)} for key, path in encrypted.items()},
                                                       export["id"]: {"0": str(independent)}})
        recovered = Vault(restored["destination"], restored["state"])
        inventory = custody.materials(recovered)
        recovered_cipher = {key: recovered.state / "custody" / path.name for key, path in encrypted.items()}
        independent_copy = inventory[export["id"]]["copies"][1]
        independent_target = Path(independent_copy["root"]) / independent_copy["path"]
        for key, path in recovered_cipher.items():
            self.assertEqual(path.read_bytes(), ciphertext[key])
        self.assertTrue(independent_target.is_file())
        self.assertEqual(inventory[retired["id"]]["copies"][1], {**retired_checkpoint, "origin_status": "deleted"})

        # A plan created with an intact inventory can still refer to the same local ciphertext.
        for record in (malformed, unproven):
            projected = inventory[record["id"]]
            copies = [projected["copies"][0], *({**copy, "status": "unavailable"} for copy in record["copies"][1:]),
                      projected["copies"][-1]]
            custody.save_material(recovered, {**projected, "copies": copies})
        old_plan = retention.plan(recovered, now)
        for record in (malformed, unproven):
            key = record["id"]
            self.assertTrue(any(row["material"] == key and row["copy_index"] == len(record["copies"])
                                for row in old_plan["entries"]))
            custody.save_material(recovered, inventory[key])

        planned = retention.plan(recovered, now)
        outcome = retention.execute(recovered, old_plan["id"], now)
        for record in (malformed, unproven):
            key = record["id"]
            with self.subTest(material=record["task"]):
                self.assertTrue(recovered_cipher[key].is_file())
                self.assertEqual(recovered_cipher[key].read_bytes(), ciphertext[key])
                for index, copy in enumerate(inventory[key]["copies"][1:-1], start=1):
                    self.assertEqual(copy["status"], "unavailable")
                    self.assertFalse({"root", "path", "sha256"} & copy.keys())
                    self.assertTrue(any(row["material"] == key and row["copy_index"] == index for row in planned["pending"]))
                self.assertFalse(any(row["material"] == key for row in planned["entries"]))
                self.assertTrue(any(row["material"] == key and row["copy_index"] == len(record["copies"]) and
                                    "requires reconciliation" in row["reason"]
                                    for row in outcome["pending"]))
        self.assertFalse(recovered_cipher[retired["id"]].exists())
        self.assertFalse(independent_target.exists())
        self.assertTrue(independent.is_file())

    def test_2_paths_and_interrupted_publication(self):
        self.configure(2)
        original = self.create()
        originals = [tuple(p.read_bytes() for p in self.paths(original, index)) for index in range(2)]
        baseline = self.vault.head()
        oid = git(self.root, "rev-parse", "HEAD:wiki/index.md")
        bad_trees = (
            ([("100644", backup_snapshot.BUNDLE)], "collides with a backup record"),
            ([("100644", "wiki/Duplicate"), ("100644", "wiki/duplicate")], "paths collide"),
            ([("120000", "wiki/symlink")], "not a regular Git blob"),
        )
        for entries, error in bad_trees:
            with self.subTest(error=error):
                for mode, name in entries:
                    git(self.root, "update-index", "--add", "--cacheinfo", f"{mode},{oid},{name}")
                git(self.root, "commit", "-m", "Unsafe archival candidate")
                with self.assertRaisesRegex(Blocked, error):
                    self.create()
                git(self.root, "reset", "--mixed", baseline)

        def stop_manifest(path, body):
            if path.name.endswith(".manifest.json") and path.parent == self.destinations[1]:
                raise OSError("interrupted between age and manifest")
            return atomic(path, body)

        with patch("healdan.backups.atomic", side_effect=stop_manifest), self.assertRaisesRegex(OSError, "between age"):
            self.create()
        pending, = [record for record in custody.materials(self.vault).values() if record["status"] == "writing"]
        manifest, cipher = self.paths(pending, 1)
        self.assertTrue(cipher.is_file())
        self.assertFalse(manifest.exists())
        self.assertEqual([copy["status"] for copy in pending["copies"]], ["present", "planned"])
        written = cipher.read_bytes()
        truncated = {**pending, "copies": pending["copies"][:1]}
        custody.save_material(self.vault, truncated)
        with self.assertRaisesRegex(Blocked, "replica count"):
            backups.reconcile(self.vault, pending["id"])
        self.assertEqual(custody.materials(self.vault)[pending["id"]], truncated)
        self.assertEqual(cipher.read_bytes(), written)
        self.assertFalse(manifest.exists())
        custody.save_material(self.vault, pending)
        alternate = self.base / "alternate-backup-destination"
        alternate.mkdir()
        self.vault.config["backup_destinations"].append(str(alternate))
        atomic(self.vault.config_path, self.vault.config)
        first, second = pending["copies"]
        for root in (first["root"], str(alternate)):
            redirected = {**pending, "copies": [first, {**second, "root": root}]}
            custody.save_material(self.vault, redirected)
            with self.assertRaisesRegex(Blocked, "signed publication plan"):
                backups.reconcile(self.vault, pending["id"])
            self.assertEqual(custody.materials(self.vault)[pending["id"]], redirected)
            self.assertFalse(any(alternate.iterdir()))
            self.assertEqual(cipher.read_bytes(), written)
            self.assertFalse(manifest.exists())
        custody.save_material(self.vault, pending)
        relocate = self.vault.relocated_path

        def overlap(path):
            return Path(first["root"]) if path == second["root"] else relocate(path)

        with patch.object(self.vault, "relocated_path", side_effect=overlap), \
                patch("healdan.backups.publish_file", wraps=backups.publish_file) as write, \
                self.assertRaisesRegex(Blocked, "publication destinations overlap"):
            backups.reconcile(self.vault, pending["id"])
        write.assert_not_called()
        self.assertEqual(custody.materials(self.vault)[pending["id"]], pending)
        self.policy("off")
        with self.assertRaisesRegex(Blocked, "disabled by policy"):
            backups.reconcile(self.vault, pending["id"])
        self.assertFalse(manifest.exists())
        self.assertEqual(cipher.read_bytes(), written)
        self.assertEqual(custody.materials(self.vault)[pending["id"]], pending)
        self.assertEqual(backups.verify_backup(self.vault, original["id"])["status"], "complete")
        self.assertEqual(backups.reconcile(self.vault, original["id"])["status"], "complete")
        self.policy("manual")
        done = backups.reconcile(self.vault, pending["id"])
        self.assertEqual(done["status"], "complete")
        self.assertTrue(manifest.is_file())
        for copy in done["copies"]:
            self.assertTrue(copy["publication_receipt"])
        for index, pair in enumerate(originals):
            self.assertEqual(tuple(path.read_bytes() for path in self.paths(original, index)), pair)

        self.policy(permanent=True)
        member = self.conversation("finite-after-policy-change", closed_at=utc())
        with patch("healdan.backups.atomic", side_effect=stop_manifest), self.assertRaisesRegex(OSError, "between age"):
            self.create("short", "permanent", [member["id"]])
        short, = [item for item in custody.materials(self.vault).values() if item.get("status") == "writing"]
        short_manifest, short_cipher = self.paths(short, 1)
        sealed = short_cipher.read_bytes()
        self.policy(permanent=False)
        with self.assertRaisesRegex(Blocked, "precede every finite material deadline"):
            backups.reconcile(self.vault, short["id"])
        self.assertFalse(short_manifest.exists())
        self.assertEqual(short_cipher.read_bytes(), sealed)
        self.assertEqual(custody.materials(self.vault)[short["id"]], short)
        self.policy(permanent=True)
        changed_member = {**member, "cipher_sha256": "f" * 64}
        custody.save_material(self.vault, changed_member)
        with self.assertRaisesRegex(Blocked, "differs from its current custody ciphertext"):
            backups.reconcile(self.vault, short["id"])
        self.assertFalse(short_manifest.exists())
        custody.save_material(self.vault, member)
        finished = backups.reconcile(self.vault, short["id"])
        self.assertEqual(finished["approval"], short["publication"])
        self.assertEqual(short_cipher.read_bytes(), sealed)

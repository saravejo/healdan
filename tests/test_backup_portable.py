"""Portable backups with disposable Git, OpenSSH and age fixtures."""
from datetime import timedelta
import os
from pathlib import Path
import stat
import sys
from unittest.mock import patch
from uuid import uuid4

from support import VaultTest, controller_environment
from healdan import admission, backup_recovery, backup_snapshot, backups, binding, compatibility, custody, inbox, maintenance, retention, storage_policy, tasks
from healdan.core import Blocked, Vault, atomic, canonical, decode, digest, git, read_json, run, stamp, utc
from healdan.signing import envelope


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
        replica.unlink()
        self.assertEqual([entry["status"] for entry in backups.verify_backup(self.vault, record["id"])["replicas"]],
                         ["unavailable", "verified"])
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
        self.assertEqual([entry["status"] for entry in backups.verify_backup(self.vault, record["id"])["replicas"]],
                         ["deleted", "verified"])
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

        conflicting = {**record, "copies": [first, second, {**first, "status": "unavailable"}]}
        custody.save_material(self.vault, conflicting)
        report = backups.verify_backup(self.vault, identifier)
        self.assertEqual(report["replica"], str(self.paths(record, 1)[1]))
        self.assertEqual([row["status"] for row in report["replicas"]], ["invalid", "verified", "invalid"])
        self.assertTrue(all("conflicting catalog entries" in report["replicas"][index]["reason"] for index in (0, 2)))

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

    def test_1_custody_retention_and_authorized_remap(self):
        self.configure()
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
        held, held_source = export("held", old)
        hold = custody.hold(self.vault, held["id"], "Await origin decision", "human", ["evidence"])
        held = custody.materials(self.vault)[held["id"]]
        held["dependencies"] = ["evidence"]
        custody.save_material(self.vault, held)
        old_plan = retention.plan(self.vault)
        independent, independent_source = export("independent", utc() - timedelta(days=2))
        unavailable, _ = export("unavailable", old)
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
        self.assertEqual(current[unavailable["id"]]["copies"][0]["status"], "unavailable")
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
        self.assertEqual(backups.verify_backup(self.vault, identifier)["pending_replicas"][0]["status"], "unavailable")
        result = backups.restore(self.vault, identifier, self.base / "restored-legacy")
        self.assertIn("Legacy backup omitted", result["pending_copies"][0])
        self.assertEqual((Path(result["destination"]) / member_name).read_bytes(), member_cipher)
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

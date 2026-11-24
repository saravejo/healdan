import copy
import os
from pathlib import Path
import sys
from unittest.mock import patch
from uuid import uuid4

from support import VaultTest
import test_source_policy
import test_transactions
from healdan import integration_effects as effects, integration_git as integration, integration_journal as journals
from healdan import integration_files, originals, tasks, transactions
from healdan.core import Blocked, Vault, atomic, canonical, digest, executable, extend_jsonl, git, git_bytes, jsonl, parse_jsonl, read_json, run, stamp
from healdan.ids import reserve


class IntegrationB06(VaultTest):
    def package(self):
        _, _, record = test_transactions.Transactions.prepare_identity_fixture(self)
        transactions.approve(self.vault, record["id"])
        return read_json(transactions.package_path(self.vault, record["id"]))

    @property
    def journal(self):
        return self.vault.control / journals.JOURNAL

    def assert_once(self, record, commit):
        self.assertEqual(self.vault.head(), commit)
        rows = self.vault.rows(transactions.LEDGER)
        self.assertEqual(rows.count(record["approval"]), 1)
        receipts = [read_json(path) for path in (self.vault.control / "receipts").glob("*.json")]
        self.assertEqual([r["payload"] for r in receipts if r["kind"] == "integration"],
                         [{"commit": commit, "package": record["id"]}])
        self.assertEqual(self.cli("apply", "--recover")[0], 2)

    def interrupt_before_cas(self, record):
        with patch("healdan.integration_git.publish", side_effect=OSError("before CAS")), self.assertRaises(OSError):
            transactions.apply(self.vault, record["id"])
        return read_json(self.journal)

    def write_external(self, path, body):
        run([sys.executable, "-c", "from pathlib import Path; import sys; "
             "Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))", path, body.hex()])

    def test_exact_cli_tree_with_binary_crlf_ledger_and_modes(self):
        registry = "wiki/control/decisions.jsonl"
        ledger = self.root / transactions.LEDGER
        old_approvals = [self.signed({"claim_digests": {f"C-{i}": digest(str(i))}}, "package") for i in (121, 122)]
        historic = canonical(old_approvals[0]) + b"\r\n" + canonical(old_approvals[1])
        atomic(ledger, historic)
        attributes = self.root / ".gitattributes"
        atomic(attributes, attributes.read_bytes() + b"wiki/control/decisions.jsonl text eol=lf\n"
                                                   b"control/approvals/packages.jsonl -text\n")
        atomic(self.root / "unchanged.sh", b"true\n")
        git(self.root, "add", "--", str(ledger), ".gitattributes", "unchanged.sh")
        git(self.root, "update-index", "--chmod=+x", "--", registry, "unchanged.sh")
        if os.name != "nt":
            (self.root / registry).chmod(0o755)
            (self.root / "unchanged.sh").chmod(0o755)
        git(self.root, "commit", "-m", "Fixture base with modes and separators")
        prior = self.vault.head()
        empty = git_bytes(self.root, "mktree", data=b"").decode("ascii").strip()
        child, object_id = b"unaffected-empty", empty
        for parent in ("wiki/control", "wiki", ""):
            tree = prior + ":" + parent if parent else prior
            before = git_bytes(self.root, "ls-tree", "-z", tree).split(b"\0")[:-1]
            rows = [entry for entry in before if entry.split(b"\t", 1)[1] != child]
            rows.append(b"040000 tree " + object_id.encode("ascii") + b"\t" + child)
            object_id = git_bytes(self.root, "mktree", "-z", data=b"\0".join(rows) + b"\0").decode("ascii").strip()
            child = parent.rsplit("/", 1)[-1].encode("ascii")
        base = git(self.root, "commit-tree", object_id, "-p", prior, "-m", "Retain an untouched empty Git entry")
        git(self.root, "update-ref", "HEAD", base, prior)
        body = b"\x00\xffa\r\nb\n"
        row = test_source_policy.SourcePolicy.proposal(self, body)
        editor = self.state / "tasks" / self.source_task["id"] / "proposals/editor"
        decision, = reserve(self.vault, "D", 1, str(uuid4()))
        crlf = canonical({"id": decision}) + b"\r\n"
        atomic(editor / registry, crlf)
        package = test_source_policy.SourcePolicy.approved(self)
        record = read_json(transactions.package_path(self.vault, package))
        code, result = self.cli("apply", package)
        self.assertEqual(code, 0, result)
        commit = result["commit"]
        self.assertEqual(git(self.root, "show", "-s", "--format=%P", commit), base)
        expected = {path: journals.decode_bytes(encoded) for path, encoded in record["payload"]["files"].items()}
        expected[transactions.LEDGER] = extend_jsonl(historic, [record["approval"]])
        self.assertEqual(expected[registry], crlf)
        self.assertEqual(expected[row["path"]], body)
        before = integration.entries(self.root, base, recurse=True)
        after = integration.entries(self.root, commit, recurse=True)
        for path, raw in expected.items():
            self.assertEqual(git_bytes(self.root, "cat-file", "blob", commit + ":" + path), raw)
            self.assertEqual((self.root / path).read_bytes(), raw)
            self.assertEqual(after[path][0], before[path][0] if path in before else "100644")
        self.assertEqual({k: v for k, v in after.items() if k not in expected},
                         {k: v for k, v in before.items() if k not in expected})
        empty_path = "wiki/control/unaffected-empty"
        self.assertEqual(integration.entries(self.root, commit, scopes=[empty_path])[empty_path],
                         ("040000", "tree", empty))
        self.assertEqual(integration.index_entries(self.root, expected),
                         {k: [[after[k][0], after[k][2], 0, 0]] for k in expected})
        self.assertIsNotNone(read_json(self.vault.control / "csp.json").get("rule"))
        self.assert_once(record, commit)

    def test_same_base_destinations_and_real_ref_cas(self):
        record = self.package()
        base = record["payload"]["base"]
        journal = self.interrupt_before_cas(record)
        journal_bytes = self.journal.read_bytes()
        actual = journal["destination"]["ref"]
        other = self.base / "other worktree"
        git(self.root, "worktree", "add", "-b", "other", str(other), base)
        foreign = Vault(other, self.state)
        with self.assertRaisesRegex(Blocked, "destination differs"):
            transactions.apply(foreign, recover=True)
        git(self.root, "switch", "-c", "third")
        with self.assertRaisesRegex(Blocked, "destination differs"):
            transactions.apply(self.vault, recover=True)
        self.assertEqual(self.journal.read_bytes(), journal_bytes)
        git(self.root, "switch", actual.removeprefix("refs/heads/"))
        tree = git(self.root, "rev-parse", base + "^{tree}")
        advanced = git(self.root, "commit-tree", tree, "-p", base, "-m", "External ref fixture")
        publish = integration.publish
        for operation in ("advance", "delete", "switch", "other"):
            with self.subTest(operation=operation):
                def contend(vault, binding, old, commit, operation_id):
                    if operation == "advance":
                        git(self.root, "update-ref", actual, advanced, base)
                    elif operation == "delete":
                        git(self.root, "update-ref", "-d", actual, base)
                    elif operation == "switch":
                        git(self.root, "symbolic-ref", "HEAD", "refs/heads/third")
                    else:
                        git(self.root, "update-ref", "refs/heads/third", advanced, base)
                    return publish(vault, binding, old, commit, operation_id)

                with patch("healdan.integration_git.publish", side_effect=contend):
                    if operation == "other":
                        result = transactions.apply(self.vault, recover=True)
                        self.assertEqual(git(self.root, "rev-parse", "refs/heads/third"), advanced)
                        continue
                    with self.assertRaisesRegex(Blocked, "destination differs" if operation == "switch" else "CAS refused"):
                        transactions.apply(self.vault, recover=True)
                    self.assertEqual(git(self.root, "rev-parse", "--verify", actual, check=False),
                                     {"advance": advanced, "delete": "", "switch": base}[operation])
                    self.assertEqual(self.journal.read_bytes(), journal_bytes)
                if operation == "switch":
                    git(self.root, "symbolic-ref", "HEAD", actual)
                git(self.root, "update-ref", actual, base)
        self.assert_once(record, result["commit"])

    def test_independent_detached_heads_and_clone_cannot_recover(self):
        git(self.root, "switch", "--detach", "HEAD")
        record = self.package()
        base = record["payload"]["base"]
        journal = self.interrupt_before_cas(record)
        self.assertEqual(journal["destination"]["mode"], "detached")
        original = self.journal.read_bytes()
        detached = self.base / "second detached"
        git(self.root, "worktree", "add", "--detach", str(detached), base)
        index = integration.admin_dir(detached) / "index"
        prior = index.read_bytes()
        with self.assertRaisesRegex(Blocked, "destination differs"):
            transactions.apply(Vault(detached, self.state), recover=True)
        self.assertEqual(index.read_bytes(), prior)
        self.assertEqual(git(detached, "rev-parse", "HEAD"), base)
        clone = self.base / "sibling clone"
        git(self.root, "clone", "--local", str(self.root), str(clone))
        from healdan.binding import setup_binding
        clone_state = self.base / "clone state"
        setup_binding(clone, clone_state)
        sibling = Vault(clone, clone_state)
        atomic(sibling.control / journals.JOURNAL, original)
        with self.assertRaisesRegex(Blocked, "destination differs"):
            transactions.apply(sibling, recover=True)
        self.assertEqual((sibling.control / journals.JOURNAL).read_bytes(), original)
        self.assertEqual(self.journal.read_bytes(), original)
        result = transactions.apply(self.vault, recover=True)
        self.assert_once(record, result["commit"])

    def test_worktree_displacement_and_index_contenders_preserve_bytes(self):
        record = self.package()
        name = "wiki/control/decisions.jsonl"
        unrelated = "unrelated staged.txt"
        target = self.root / name
        external = b'{"id":"D-0123"}\n'
        rename = effects.rename_exclusive

        def edit_before_displacement(source, destination):
            if source == target:
                self.write_external(target, external)
            return rename(source, destination)

        with patch("healdan.integration_effects.rename_exclusive", side_effect=edit_before_displacement):
            with self.assertRaisesRegex(Blocked, "displaced copy.*decisions"):
                transactions.apply(self.vault, record["id"])
        pending = read_json(self.journal)
        published = pending["expected_commit"]
        copy_evidence = pending["reconciliation"][name]
        copy_path = integration.admin_dir(self.root) / "healdan-integration" / pending["operation"] / copy_evidence["name"]
        self.assertEqual(copy_path.read_bytes(), external)
        self.assertEqual(journals.decode_bytes(copy_evidence["body"]), external)
        with self.assertRaisesRegex(Blocked, "displaced copy.*decisions"):
            transactions.apply(self.vault, recover=True)
        approved = journals.decode_bytes(record["payload"]["files"][name])
        self.write_external(target, approved)
        other_path = self.root / unrelated
        self.write_external(other_path, b"Other staged content\n")
        sync = transactions.reconcile_index

        def stage_contender(*args, **kwargs):
            self.write_external(target, external)
            git(self.root, "add", "--", name, unrelated)
            self.write_external(target, approved)
            return sync(*args, **kwargs)

        with patch("healdan.transactions.reconcile_index", side_effect=stage_contender):
            with self.assertRaisesRegex(Blocked, "index differs.*decisions"):
                transactions.apply(self.vault, recover=True)
        self.assertEqual(git_bytes(self.root, "cat-file", "blob", ":" + name), external)
        unrelated_stage = git_bytes(self.root, "ls-files", "--stage", "-z", "--", unrelated)
        old_entry = pending["index_before"][name][0]
        git(self.root, "update-index", "--cacheinfo", old_entry[0], old_entry[1], name)
        result = transactions.apply(self.vault, recover=True)
        self.assertEqual(result["commit"], published)
        self.assertEqual(git_bytes(self.root, "ls-files", "--stage", "-z", "--", unrelated), unrelated_stage)
        self.assertEqual(copy_path.read_bytes(), external)
        self.assert_once(record, published)

    def test_affected_stage_after_index_record_keeps_integration_pending(self):
        record = self.package()
        name, unrelated = "wiki/control/decisions.jsonl", "unrelated staged.txt"
        target = self.root / name
        approved = journals.decode_bytes(record["payload"]["files"][name])
        external = b'{"id":"D-0123"}\n'
        csp = read_json(self.vault.control / "csp.json")
        receipts = {path.name: path.read_bytes() for path in (self.vault.control / "receipts").glob("*.json")}
        persist = journals.persist

        def stage_after_index(path, journal):
            persist(path, journal)
            if journal["phase"] == "indexed":
                self.assertEqual(target.read_bytes(), approved)
                self.write_external(target, external)
                self.write_external(self.root / unrelated, b"Unrelated stage\n")
                git(self.root, "add", "--", name, unrelated)
                self.write_external(target, approved)

        with patch("healdan.integration_journal.persist", side_effect=stage_after_index):
            with self.assertRaisesRegex(Blocked, "Integration index differs: " + name) as conflict:
                transactions.apply(self.vault, record["id"])
        self.assertEqual(conflict.exception.code, 5)
        pending = read_json(self.journal)
        self.assertEqual((pending["phase"], pending["status"]), ("indexed", "writing"))
        commit = pending["expected_commit"]
        self.assertEqual(git_bytes(self.root, "cat-file", "blob", commit + ":" + name), approved)
        self.assertEqual(git_bytes(self.root, "cat-file", "blob", ":" + name), external)
        self.assertEqual(target.read_bytes(), approved)
        self.assertEqual(read_json(self.vault.control / "csp.json"), csp)
        self.assertEqual({path.name: path.read_bytes() for path in (self.vault.control / "receipts").glob("*.json")}, receipts)
        unrelated_stage = git_bytes(self.root, "ls-files", "--stage", "-z", "--", unrelated)
        code, problem = self.cli("apply", "--recover")
        self.assertEqual(code, 5, problem)
        self.assertIn(name, problem["error"])
        mode, _, oid = integration.entries(self.root, commit, scopes=[name])[name]
        git(self.root, "update-index", "--cacheinfo", mode, oid, name)
        result = transactions.apply(self.vault, recover=True)
        self.assertEqual(result["commit"], commit)
        self.assertEqual(git_bytes(self.root, "ls-files", "--stage", "-z", "--", unrelated), unrelated_stage)
        self.assert_once(record, commit)

    def test_unrelated_stage_survives_and_git_lock_protects_terminal_effects(self):
        record = self.package()
        name, unrelated = "wiki/control/decisions.jsonl", "unrelated staged.txt"
        target = self.root / name
        approved = journals.decode_bytes(record["payload"]["files"][name])
        persist, release = journals.persist, effects.release_index_lock
        git_attempts = []
        stages = []

        def contend(path, journal):
            persist(path, journal)
            if journal["phase"] == "indexed":
                self.write_external(self.root / unrelated, b"Unrelated stage\n")
                git(self.root, "add", "--", unrelated)
                stages.append(git_bytes(self.root, "ls-files", "--stage", "-z", "--", unrelated))
            if journal["phase"] in {"admitted", "csp", "receipt"}:
                self.write_external(target, b'{"id":"D-0123"}\n')
                result = run([executable("git"), "-C", self.root, "add", "--", name], check=False)
                self.write_external(target, approved)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"index.lock", result.stderr)
                git_attempts.append(journal["phase"])

        def leave_completed_lock(lock_path, owner):
            if read_json(self.journal)["status"] != "complete":
                release(lock_path, owner)

        with patch("healdan.integration_journal.persist", side_effect=contend), \
                patch("healdan.integration_effects.release_index_lock", side_effect=leave_completed_lock):
            result = transactions.apply(self.vault, record["id"])
        self.assertEqual(git_attempts, ["admitted", "csp", "receipt", "receipt"])
        self.assertEqual(stages, [git_bytes(self.root, "ls-files", "--stage", "-z", "--", unrelated)])
        lock_path = integration.admin_dir(self.root) / "index.lock"
        self.assertTrue(lock_path.is_file())
        self.assert_once(record, result["commit"])
        self.assertFalse(lock_path.exists())
        self.assertFalse((integration.admin_dir(self.root) / "healdan-integration" /
                          read_json(self.journal)["operation"]).exists())
        atomic(lock_path, b"foreign lock")
        code, error = self.cli("apply", "--recover")
        self.assertEqual(code, 2, error)
        self.assertEqual(lock_path.read_bytes(), b"foreign lock")

    def test_unsigned_input_checked_before_cas_and_preserved_after_publication(self):
        record = self.package()
        name = "wiki/index.md"
        target = self.root / name
        approved_base = target.read_bytes()
        edit = b"Independent worktree edit\n"
        persist = journals.persist

        def edit_after_intent(path, journal):
            persist(path, journal)
            if journal["phase"] == "intent":
                self.write_external(target, edit)

        with patch("healdan.integration_journal.persist", side_effect=edit_after_intent):
            with self.assertRaisesRegex(Blocked, "unsigned input changed.*wiki/index.md") as conflict:
                transactions.apply(self.vault, record["id"])
        self.assertEqual(conflict.exception.code, 5)
        base = record["payload"]["base"]
        self.assertEqual(self.vault.head(), base)
        self.assertEqual(target.read_bytes(), edit)
        self.assertEqual(read_json(self.journal)["phase"], "intent")
        code, pending = self.cli("apply", "--recover")
        self.assertEqual(code, 5, pending)
        self.write_external(target, approved_base)
        publish = integration.publish

        def edit_after_cas(*args):
            publish(*args)
            self.write_external(target, edit)
            git(self.root, "add", "--", name)

        with patch("healdan.integration_git.publish", side_effect=edit_after_cas):
            result = transactions.apply(self.vault, recover=True)
        self.assertEqual(target.read_bytes(), edit)
        self.assertEqual(git_bytes(self.root, "cat-file", "blob", ":" + name), edit)
        self.assertEqual(git_bytes(self.root, "cat-file", "blob", result["commit"] + ":" + name),
                         git_bytes(self.root, "cat-file", "blob", base + ":" + name))
        self.assert_once(record, result["commit"])

    def test_signed_historical_original_rechecks_attributes_without_manifest_change(self):
        name = "resources/sources/F-0001/original.txt"
        body = b"Historical source bytes\r\n"
        atomic(self.root / name, body)
        self.rows(originals.REGISTRY, [{"id": "F-0001", "path": name, "sha256": digest(body), "size": len(body),
                                        "classification": "common", "captured_at": stamp(), "provenance": "Fixture"}])
        git(self.root, "add", "--", "resources/sources")
        git(self.root, "commit", "-m", "Preserve a historical original")
        task = tasks.create(self.vault, "Retain the existing source")
        atomic(self.state / "tasks" / task["id"] / "proposals/editor" / name, body)
        frozen = transactions.prepare(self.vault, task["id"])
        transactions.approve(self.vault, frozen["id"])
        record = read_json(transactions.package_path(self.vault, frozen["id"]))
        persisted_base = self.vault.head()
        attribute = integration.admin_dir(self.root) / "info/attributes"
        atomic(attribute, (name + " text eol=lf\n").encode("ascii"))
        code, blocked = self.cli("apply", frozen["id"])
        self.assertEqual(code, 5, blocked)
        self.assertIn("effective Git text", blocked["error"])
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.vault.head(), persisted_base)
        attribute.unlink()
        self.interrupt_before_cas(record)
        atomic(attribute, (name + " text eol=lf\n").encode("ascii"))
        code, blocked = self.cli("apply", "--recover")
        self.assertEqual(code, 5, blocked)
        self.assertIn("effective Git text", blocked["error"])
        self.assertEqual(self.vault.head(), persisted_base)
        self.assertEqual((self.root / name).read_bytes(), body)
        attribute.unlink()
        code, result = self.cli("apply", "--recover")
        self.assertEqual(code, 0, result)
        self.assertEqual(git_bytes(self.root, "cat-file", "blob", result["commit"] + ":" + name), body)
        self.assert_once(record, result["commit"])

    def test_confined_file_operations_refuse_non_directory_component(self):
        directory = self.root / "wiki/topics/private fixture"
        final = directory / "nested" / "verified"
        integration_files.prepare_file(final, b"Confined approved bytes", 0o644)
        self.assertEqual(integration_files.snapshot(final)[0], digest(b"Confined approved bytes"))
        moved = final.with_name("committed")
        integration_files.rename_exclusive(final, moved)
        self.assertEqual(moved.read_bytes(), b"Confined approved bytes")
        blocked = self.root / "wiki/topics/ordinary-file"
        atomic(blocked, b"Unrelated file")
        with self.assertRaisesRegex(Blocked, "directory path changed"):
            integration_files.prepare_file(blocked / "impossible", b"Proposed bytes", 0o644)
        self.assertEqual(blocked.read_bytes(), b"Unrelated file")

    def test_inert_sources_with_executable_extensions_integrate_as_regular_blobs(self):
        task = tasks.create(self.vault, "Preserve filename extension fixtures")
        editor = self.state / "tasks" / task["id"] / "proposals/editor"
        manifest, bodies = [], {}
        identifiers = reserve(self.vault, "F", 4, str(uuid4()))
        for identifier, extension in zip(identifiers, ("bat", "exe", "cmd", "com"), strict=True):
            name = f"resources/sources/{identifier}/fixture.{extension}"
            body = b"\x00Inert data-only fixture: " + extension.encode("ascii") + b"\r\n"
            bodies[name] = body
            atomic(editor / name, body)
            manifest.append({"id": identifier, "path": name, "sha256": digest(body), "size": len(body),
                             "classification": "common", "captured_at": stamp(), "provenance": "Fixture"})
        atomic(editor / originals.REGISTRY, jsonl(manifest))
        frozen = transactions.prepare(self.vault, task["id"])
        transactions.approve(self.vault, frozen["id"])
        record = read_json(transactions.package_path(self.vault, frozen["id"]))
        code, result = self.cli("apply", frozen["id"])
        self.assertEqual(code, 0, result)
        commit = result["commit"]
        entries = integration.entries(self.root, commit, scopes=bodies)
        for name, body in bodies.items():
            self.assertEqual((self.root / name).read_bytes(), body)
            self.assertEqual(git_bytes(self.root, "cat-file", "blob", commit + ":" + name), body)
            self.assertEqual(entries[name][:2], ("100644", "blob"))
        self.assert_once(record, commit)

    def test_journal_and_approval_changes_preserve_all_pending_effects(self):
        record = self.package()
        journal = self.interrupt_before_cas(record)
        path = transactions.package_path(self.vault, record["id"])
        frozen, approval = self.journal.read_bytes(), path.read_bytes()
        name = "wiki/control/decisions.jsonl"
        original_index = (integration.admin_dir(self.root) / "index").read_bytes()
        for field, change in (
            ("package_id", "b" * 64), ("base", "a" * 40), ("destination", {**journal["destination"], "ref": "refs/heads/fake"}),
            ("files", {**journal["files"], name: journals.encode(b"Injected\n")}),
            ("files", {**journal["files"], transactions.LEDGER: journals.encode(b"{}\n")}),
            ("before", {**journal["before"], name: digest(b"forged")}),
            ("written", {**journal["written"], name: "installed"}), ("format", "future"),
            ("written", {**journal["written"], name: ["installed"]}),
        ):
            with self.subTest(field=field, change=change):
                journals.persist(self.journal, {**journal, field: change})
                corrupt = self.journal.read_bytes()
                with self.assertRaises(Blocked):
                    transactions.apply(self.vault, recover=True)
                self.assertEqual(self.journal.read_bytes(), corrupt)
                self.assertEqual(self.vault.head(), journal["base"])
                self.assertEqual((integration.admin_dir(self.root) / "index").read_bytes(), original_index)
        atomic(self.journal, frozen)
        changed = copy.deepcopy(record)
        lines = changed["approval"]["signature"].splitlines(keepends=True)
        lines[1] = ("B" if lines[1][0] == "A" else "A") + lines[1][1:]
        changed["approval"]["signature"] = "".join(lines)
        atomic(path, changed)
        with self.assertRaisesRegex(Blocked, "SSH signature"):
            transactions.apply(self.vault, recover=True)
        self.assertEqual(self.journal.read_bytes(), frozen)
        atomic(path, approval)
        result = transactions.apply(self.vault, recover=True)
        self.assert_once(record, result["commit"])

    def legacy_intent(self, record, *, published, version=2):
        envelope, signed = record["approval"], record["approval"]["payload"]
        base = signed["base"]
        with self.vault.locked():
            bodies, _ = transactions.exact_files(self.vault, envelope, signed)
            files = {name: journals.encode(body) for name, body in bodies.items()}
            before = {name: signed["input_hashes"].get(name) for name in files}
            original = {"status": "writing", "package_id": record["id"], "base": base,
                        "files": files, "before": before, "written": []}
            if version == 2:
                original.update(format="healdan-transaction-v2", publication_at=stamp(), before_files={
                    name: journals.encode((self.root / name).read_bytes())
                    for name, sha in before.items() if sha is not None})
            atomic(self.journal, original)
            commit = None
            if published:
                for name, body in bodies.items():
                    atomic(self.root / name, body)
                original.update(written=list(files), admissions=[])
                atomic(self.journal, original)
                git(self.root, "add", "--", *files)
                git(self.root, "commit", "-m", f"Legacy publication\n\nHealdan-Package: {record['id']}")
                commit = self.vault.head()
                atomic(self.vault.control / "csp.json", {"streak": 0, "package": record["id"]})
            # The observer signs within the interrupted legacy operation, under its controller lock.
            source = self.journal.read_bytes()
            proof = self.signed({"format": "healdan-integration-origin-v1", "journal": digest(source),
                                 "destination": integration.destination(self.vault), "package": record["id"],
                                 "approval": digest(envelope), "base": base, "commit": commit}, "integration-origin")
            return source, proof, commit

    def legacy_crlf_preimage(self):
        name = "wiki/control/decisions.jsonl"
        path = self.root / name
        body = canonical({"id": "D-27"}) + b"\r\n"
        atomic(path, body)
        attrs = self.root / ".gitattributes"
        atomic(attrs, attrs.read_bytes() + ("\n" + name + " text eol=lf\n").encode("ascii"))
        git(self.root, "add", "--", ".gitattributes", name)
        git(self.root, "commit", "-m", "Preserve a normalized historic decision blob")
        record = self.package()
        base = record["payload"]["base"]
        self.assertEqual(git_bytes(self.root, "cat-file", "blob", base + ":" + name), body.replace(b"\r\n", b"\n"))
        self.assertEqual(path.read_bytes(), body)
        self.assertEqual(record["approval"]["payload"]["input_hashes"][name], digest(body))
        source, proof, _ = self.legacy_intent(record, published=False, version=1)
        atomic(self.state / "integration-origins" / (digest(source) + ".json"), proof)
        return record, source, path, body

    def test_legacy_v1_recovers_with_signed_crlf_preimage_in_attested_worktree(self):
        record, source, path, body = self.legacy_crlf_preimage()
        name = path.relative_to(self.root).as_posix()
        code, result = self.cli("apply", "--recover")
        self.assertEqual(code, 0, result)
        journal = read_json(self.journal)
        self.assertEqual(journals.decode_bytes(journal["legacy"]["original"]), source)
        self.assertEqual(journals.decode_bytes(journal["before_files"][name]), body)
        self.assert_once(record, result["commit"])

    def test_legacy_v1_keeps_pending_without_a_signed_preimage(self):
        record, source, path, _ = self.legacy_crlf_preimage()
        index = integration.admin_dir(self.root) / "index"
        original_index = index.read_bytes()
        ref = record["payload"]["base"]
        receipts = {receipt.name: receipt.read_bytes() for receipt in (self.vault.control / "receipts").glob("*.json")}
        for external in (b'{"id":"D-27","external":true}\r\n', None):
            with self.subTest(external=external):
                if external is None:
                    path.unlink()
                else:
                    self.write_external(path, external)
                code, result = self.cli("apply", "--recover")
                self.assertEqual(code, 4, result)
                self.assertIn("Legacy integration pre-image bytes differ", result["error"])
                self.assertEqual(self.journal.read_bytes(), source)
                self.assertEqual(self.vault.head(), ref)
                self.assertEqual(index.read_bytes(), original_index)
                self.assertEqual(path.read_bytes() if path.exists() else None, external)
                self.assertEqual({receipt.name: receipt.read_bytes()
                                  for receipt in (self.vault.control / "receipts").glob("*.json")}, receipts)

    def test_legacy_pending_requires_the_original_observation(self):
        record = self.package()
        source, proof, _ = self.legacy_intent(record, published=False)
        second = self.base / "legacy other"
        git(self.root, "worktree", "add", "-b", "legacy-other", str(second), self.vault.head())
        for vault in (self.vault, Vault(second, self.state)):
            with self.assertRaisesRegex(Blocked, "contemporaneous"):
                transactions.apply(vault, recover=True)
            self.assertEqual(self.journal.read_bytes(), source)
        proof_path = self.state / "integration-origins" / (digest(source) + ".json")
        atomic(proof_path, self.signed(dict(proof["payload"], journal=digest(b"Different journal")), "integration-origin"))
        with self.assertRaisesRegex(Blocked, "origin evidence differs"):
            transactions.apply(self.vault, recover=True)
        self.assertEqual(self.journal.read_bytes(), source)
        atomic(proof_path, proof)
        with self.assertRaisesRegex(Blocked, "destination differs"):
            transactions.apply(Vault(second, self.state), recover=True)
        self.assertEqual(self.journal.read_bytes(), source)
        result = transactions.apply(self.vault, recover=True)
        self.assertEqual(journals.decode_bytes(read_json(self.journal)["legacy"]["original"]), source)
        self.assert_once(record, result["commit"])

    def test_legacy_published_requires_exact_commit_and_accepts_owned_csp(self):
        record = self.package()
        source, proof, commit = self.legacy_intent(record, published=True)
        atomic(self.state / "integration-origins" / (digest(source) + ".json"), proof)
        state = self.vault.control / "csp.json"
        expected = state.read_bytes()
        atomic(state, {"streak": 5, "package": "external"})
        code, result = self.cli("apply", "--recover")
        self.assertEqual(code, 5, result)
        self.assertEqual(self.journal.read_bytes(), source)
        atomic(state, expected)
        result = transactions.apply(self.vault, recover=True)
        self.assertEqual(result["commit"], commit)
        self.assertEqual(journals.decode_bytes(read_json(self.journal)["legacy"]["original"]), source)
        self.assert_once(record, commit)

    def test_same_trailer_with_changed_blob_mode_path_or_parent(self):
        record = self.package()
        with patch("healdan.integration_effects.rename_exclusive", side_effect=OSError("after CAS")), \
                self.assertRaises(OSError):
            transactions.apply(self.vault, record["id"])
        journal = read_json(self.journal)
        expected, base = journal["expected_commit"], journal["base"]
        frozen = self.journal.read_bytes()
        name = "wiki/control/decisions.jsonl"
        rows = journals.decode_bytes(record["payload"]["files"][name])
        modified = jsonl([dict(row, fixture="Changed bytes with same ID") for row in parse_jsonl(rows, name)])
        for change in ("blob", "mode", "outside", "parent", "base"):
            with self.subTest(change=change):
                tree, parent = journal["tree"], base
                if change in ("blob", "mode", "outside"):
                    path = "unrelated.txt" if change == "outside" else name
                    modes = integration.overlay_modes(self.root, expected, [path])
                    if change == "mode":
                        modes[name][0] = "100755"
                    tree, _ = integration.prepare_tree(self.vault, expected, modes,
                                                       {path: modified if change == "blob" else rows})
                if change == "parent":
                    parent = expected
                alternate = base if change == "base" else git(
                    self.root, "commit-tree", tree, "-p", parent,
                    "-m", f"Other integration\n\nHealdan-Package: {record['id']}")
                git(self.root, "update-ref", "HEAD", alternate, expected)
                with self.assertRaisesRegex(Blocked, "destination ref differs"):
                    transactions.apply(self.vault, recover=True)
                self.assertEqual(self.vault.head(), alternate)
                self.assertEqual(self.journal.read_bytes(), frozen)
                git(self.root, "update-ref", "HEAD", expected, alternate)
        result = transactions.apply(self.vault, recover=True)
        self.assertEqual(result["commit"], expected)
        self.assert_once(record, expected)

    def test_concurrent_creation_removal_and_late_edit(self):
        source = test_source_policy.SourcePolicy.proposal(self, b"Approved source bytes\n")
        package = test_source_policy.SourcePolicy.approved(self)
        record = read_json(transactions.package_path(self.vault, package))
        new = self.root / source["path"]
        previous = self.root / "resources/sources/index.jsonl"
        external = b"Externally created file\n"
        rename = effects.rename_exclusive

        def create(source, target):
            if target == new:
                self.write_external(new, external)
            return rename(source, target)

        with patch("healdan.integration_effects.rename_exclusive", side_effect=create):
            with self.assertRaisesRegex(Blocked, "installing.*original"):
                transactions.apply(self.vault, package)
        commit = self.vault.head()
        self.assertEqual(new.read_bytes(), external)
        new.unlink()

        def remove(source, target):
            if source == previous:
                run([sys.executable, "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).unlink()", previous])
            return rename(source, target)

        with patch("healdan.integration_effects.rename_exclusive", side_effect=remove):
            with self.assertRaisesRegex(Blocked, "displacing.*index.jsonl"):
                transactions.apply(self.vault, recover=True)
        self.assertFalse(previous.exists())
        atomic(previous, journals.decode_bytes(read_json(self.journal)["before_files"]["resources/sources/index.jsonl"]))

        def edit_after_partial(source, target):
            rename(source, target)
            if target == previous:
                self.write_external(new, external)

        with patch("healdan.integration_effects.rename_exclusive", side_effect=edit_after_partial):
            with self.assertRaisesRegex(Blocked, "installed.*original"):
                transactions.apply(self.vault, recover=True)
        self.assertEqual(new.read_bytes(), external)
        atomic(new, git_bytes(self.root, "cat-file", "blob", commit + ":" + source["path"]))
        result = transactions.apply(self.vault, recover=True)
        self.assertEqual(result["commit"], commit)
        self.assert_once(record, commit)

    def test_interruption_between_each_effect_and_its_record(self):
        record = self.package()
        base = record["payload"]["base"]
        alternate = self.base / "recovery from another worktree"
        git(self.root, "worktree", "add", "-b", "recovery-other", str(alternate), base)
        other = Vault(alternate, self.state)
        persist, make_tree, make_commit, publish = journals.persist, integration.prepare_tree, integration.make_commit, integration.publish
        rename, replace = effects.rename_exclusive, os.replace
        receipt = Vault.receipt

        def fail(label):
            raise OSError(label)

        def interrupted(target, label, hook, *, new=False):
            with patch(target, autospec=True, side_effect=hook), self.assertRaisesRegex(OSError, label):
                transactions.apply(self.vault, record["id"] if new else None, recover=not new)
            if self.journal.exists():
                original = self.journal.read_bytes()
                with self.assertRaisesRegex(Blocked, "destination differs"):
                    transactions.apply(other, recover=True)
                self.assertEqual(self.journal.read_bytes(), original)

        interrupted("healdan.integration_journal.persist", "before intent", lambda *_: fail("before intent"), new=True)
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.vault.head(), base)

        def after_intent(*args):
            persist(*args)
            fail("after intent")

        interrupted("healdan.integration_journal.persist", "after intent", after_intent, new=True)

        def after_tree(*args):
            make_tree(*args)
            fail("after tree")

        interrupted("healdan.integration_git.prepare_tree", "after tree", after_tree)

        def after_commit(*args):
            make_commit(*args)
            fail("after commit object")

        interrupted("healdan.integration_git.make_commit", "after commit object", after_commit)
        interrupted("healdan.integration_git.publish", "before CAS", lambda *_: fail("before CAS"))
        expected = read_json(self.journal)["expected_commit"]

        def after_cas(*args):
            publish(*args)
            fail("after CAS")

        interrupted("healdan.integration_git.publish", "after CAS", after_cas)
        self.assertEqual(self.vault.head(), expected)
        self.assertEqual(read_json(self.journal)["phase"], "prepared")

        def after_rename_before(source, destination):
            rename(source, destination)
            if destination.name.endswith(".before"):
                fail("after displacement")

        interrupted("healdan.integration_effects.rename_exclusive", "after displacement", after_rename_before)

        def after_installed(source, destination):
            rename(source, destination)
            if source.name.endswith(".next"):
                fail("after install")

        interrupted("healdan.integration_effects.rename_exclusive", "after install", after_installed)

        index = integration.admin_dir(self.root) / "index"

        def after_index(source, destination):
            replace(source, destination)
            if Path(destination) == index:
                fail("after index")

        interrupted("healdan.integration_effects.os.replace", "after index", after_index)
        self.assertEqual(read_json(self.journal)["phase"], "indexing")

        def after_csp(path, body):
            atomic(path, body)
            if Path(path) == self.vault.control / "csp.json":
                fail("after CSP")

        interrupted("healdan.transactions.atomic", "after CSP", after_csp)

        def after_receipt(vault, kind, payload, *, at=None):
            identifier = receipt(vault, kind, payload, at=at)
            if kind == "integration":
                fail("after receipt")
            return identifier

        interrupted("healdan.core.Vault.receipt", "after receipt", after_receipt)
        result = transactions.apply(self.vault, recover=True)
        self.assertEqual(result["commit"], expected)
        self.assert_once(record, expected)

    def test_required_identities_before_and_after_unrecorded_publication(self):
        record = self.package()
        pending = self.interrupt_before_cas(record)
        cases = self.root / "wiki/control/query-cases.jsonl"
        original = cases.read_bytes()
        for phase in ("before", "after"):
            with self.subTest(phase=phase):
                expected = self.vault.head()
                frozen = self.journal.read_bytes()
                for rows, diagnostic in (
                    (None, "Required regular file is missing"),
                    ([{"id": "D-1"}], "Expected a Q- identity"),
                    ([{"id": "Q-1"}, {"id": "Q-0001"}], "Numeric identity collision"),
                ):
                    with self.subTest(rows=rows):
                        if rows is None:
                            cases.unlink()
                        else:
                            atomic(cases, jsonl(rows))
                        code, error = self.cli("apply", "--recover")
                        self.assertEqual(code, 4, error)
                        self.assertIn(diagnostic, error["error"])
                        self.assertEqual(self.journal.read_bytes(), frozen)
                        self.assertEqual(self.vault.head(), expected)
                        self.assertEqual(cases.read_bytes() if cases.exists() else None,
                                         None if rows is None else jsonl(rows))
                        atomic(cases, original)
                if phase == "before":
                    publish = integration.publish

                    def interrupted(*args):
                        publish(*args)
                        raise OSError("interrupted before recording CAS")

                    with patch("healdan.integration_git.publish", side_effect=interrupted), self.assertRaises(OSError):
                        transactions.apply(self.vault, recover=True)
                    self.assertEqual(self.vault.head(), pending["expected_commit"])
                    self.assertEqual(read_json(self.journal)["phase"], "prepared")
        result = transactions.apply(self.vault, recover=True)
        self.assert_once(record, result["commit"])

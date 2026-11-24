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
from healdan import transactions
from healdan.core import Blocked, Vault, atomic, canonical, digest, extend_jsonl, git, git_bytes, jsonl, parse_jsonl, read_json, run, stamp
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
        base = self.vault.head()
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

    def legacy_intent(self, record, *, published):
        envelope, signed = record["approval"], record["approval"]["payload"]
        base = signed["base"]
        with self.vault.locked():
            bodies, _ = transactions.exact_files(self.vault, envelope, signed)
            files = {name: journals.encode(body) for name, body in bodies.items()}
            before = {name: signed["input_hashes"].get(name) for name in files}
            original = {"format": "healdan-transaction-v2", "status": "writing", "package_id": record["id"], "base": base,
                        "files": files, "before": before, "written": [], "publication_at": stamp(),
                        "before_files": {name: journals.encode((self.root / name).read_bytes())
                                         for name, sha in before.items() if sha is not None}}
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

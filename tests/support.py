import base64
import copy
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from healdan.core import Vault, atomic, decode, digest, executable, git, jsonl, run
from healdan.setup import initialize
from healdan.signing import envelope


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="healdan test ")
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "vault with spaces"
        self.state = self.base / "external state"
        initialize(self.root, self.state)
        self.vault = Vault(self.root, self.state)
        git(self.root, "config", "user.name", "Test Operator")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "config", "commit.gpgsign", "false")
        git(self.root, "config", "core.autocrlf", "false")
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "Initialize disposable empty vault")
        self.key = self.base / "human-key"
        run([executable("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-f", self.key])
        self.signers = self.base / "allowed-signers"
        self.signers.write_text("human " + self.key.with_suffix(".pub").read_text(), encoding="utf-8")
        self.vault.config.update(signing_key=str(self.key), allowed_signers=str(self.signers), signing_identity="human")
        atomic(self.vault.config_path, self.vault.config)

    def tearDown(self):
        # Git marks object files read-only on Windows; temp cleanup handles them.
        self.temporary.cleanup()

    def rows(self, path, rows):
        atomic(self.root / path, jsonl(rows))

    def cli(self, *args):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent / "src"))
        result = run([sys.executable, "-m", "healdan", "--vault", self.root, "--state", self.state, *args],
                     env=env, check=False)
        self.assertEqual(result.stderr, b"")
        return result.returncode, decode(result.stdout)

    def signed(self, payload, namespace):
        return envelope(payload, namespace, "human", self.key)

    def source(self):
        data = b"The synthetic instrument has value 42 in the laboratory.\n"
        path = "resources/sources/F-0001/original.txt"
        atomic(self.root / path, data)
        self.rows("resources/sources/index.jsonl", [{"id": "F-0001", "path": path, "sha256": digest(data),
                  "size": len(data), "captured_at": "2026-01-01T00:00:00Z", "provenance": "Disposable test fixture",
                  "classification": "common"}])
        return {"id": "F-0001", "start": 0, "end": len(data), "sha256": digest(data)}

    def claim(self, identifier="C-0001", **changes):
        locator = self.source()
        result = {"id": identifier, "statement": "Synthetic instrument has value 42", "entity": "instrument",
                  "property": "value", "environment": "laboratory", "primary_topic": "measurement",
                  "state": "accepted", "value": {"type": "integer", "value": 42, "unit": None},
                  "polarity": "positive", "sources": [locator], "valid_from": None, "valid_to": None, "qualifiers": {}}
        result.update(changes)
        return result

    def knowledge(self, claims):
        self.rows("wiki/claims.jsonl", claims)
        self.rows("control/approvals/packages.jsonl", [self.signed({"claim_digests": {c["id"]: digest(c) for c in claims}}, "package")])

    def case(self, **changes):
        result = {"id": "Q-0001", "question": "What is the instrument value?", "filters": {"entity": "instrument", "property": "value"},
                  "cutoff": "2026-06-01T00:00:00Z", "temporal_policy": None, "expected_ids": ["C-0001"],
                  "expected_value": {"type": "integer", "value": 42, "unit": None}, "expected_polarity": "positive",
                  "outcome": "answer", "expected_conflicts": [], "reason": "Verified fixture byte range",
                  "decision": {"owner": "human", "at": "2026-06-01T00:00:00Z"}}
        result.update(changes)
        result["approval"] = self.signed(result.copy(), "case")
        return result

    def pages(self, claims, cap=6000):
        from healdan.pages import generated_pages
        self.rows("wiki/control/selectors.jsonl", [{"path": "wiki/topics/measurement.md", "title": "Measurement",
                  "topic": "measurement", "ids": [c["id"] for c in claims if c["state"] in {"accepted", "hypothesis", "disputed"}],
                  "purpose": "current_at_cutoff", "cutoff": "2026-06-01T00:00:00Z"}])
        atomic(self.root / "wiki/control/page-policy.json", {"cap": cap, "decision": "Human fixture naming decision"})
        for name, body in generated_pages(self.vault, proposed=[digest(c) for c in claims]).items():
            atomic(self.root / name, body)

    def age(self):
        if not shutil.which("age") or not shutil.which("age-keygen"):
            self.skipTest("Real age tools are unavailable; not recovery evidence")
        identities, recipients = [], []
        for name in ("operational", "offline"):
            key = self.base / (name + ".agekey")
            run([executable("age-keygen"), "-o", key])
            recipient = run([executable("age-keygen"), "-y", key]).stdout.decode().strip()
            identities.append(key)
            recipients.append(recipient)
        self.vault.config.update(age_identity=str(identities[0]), age_recipients=[recipients[0]], offline_recipients=[recipients[1]])
        backup_key = self.base / "backup-signing-key"
        run([executable("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-f", backup_key])
        backup_signers = self.base / "backup-allowed-signers"
        backup_signers.write_text("backup " + backup_key.with_suffix(".pub").read_text(), encoding="utf-8")
        self.vault.config.update(backup_signing_key=str(backup_key), backup_allowed_signers=str(backup_signers), backup_signing_identity="backup")
        atomic(self.vault.config_path, self.vault.config)
        return identities

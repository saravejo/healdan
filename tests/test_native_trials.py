import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from support import VaultTest
from healdan import maintenance, trials
from healdan.core import Blocked, Vault, atomic, digest, git
from healdan.setup import initialize


class NativeTrialIdentity(VaultTest):
    def setUp(self):
        super().setUp()
        self.fixture_build = SimpleNamespace(identity={"version": "same", "sha256": "a" * 64},
                                             entry_point=Path(sys.executable))
        self.versions = {"srt": self.vault.policy["srt_version"], "node": "v22.12.0"}
        self.artifact = self.base / "synthetic evidence"
        self.artifact.write_bytes(b"synthetic measured artifact")
        self.enterContext(patch("healdan.trials.platform.system", return_value="Darwin"))
        self.enterContext(patch("healdan.trials.require_active", return_value=self.fixture_build))
        self.enterContext(patch("healdan.trials._tool", side_effect=lambda name: {"path": name, "sha256": digest(name),
                                                                                "version": self.versions.get(name, "fixture")}))

    def evidence(self, name, profile=None):
        return {"platform": "Darwin", "passed": True, "commit": self.vault.head(),
                "procedure": "Disposable experiment for signature and identity validation",
                "started_at": "2026-06-01T00:00:00Z", "completed_at": "2026-06-01T00:01:00Z",
                "artifacts": [{"path": str(self.artifact), "sha256": digest(self.artifact.read_bytes())}],
                "environment": trials.environment(self.vault, name, profile), "profile": str(profile) if profile else None}

    def statuses(self, vault=None):
        return {row["name"]: row for row in maintenance.trial_status(vault or self.vault)}

    def test_knowledge_commit_does_not_expire_the_environment(self):
        maintenance.attest(self.vault, "claude-auth", self.evidence("claude-auth"))
        path = self.vault.control / "trials/v2/claude-auth.json"
        original = path.read_bytes()
        old = self.vault.fingerprint()
        atomic(self.root / "wiki/topics/knowledge.md", b"Reviewed disposable content")
        git(self.root, "add", "wiki/topics/knowledge.md")
        git(self.root, "commit", "-m", "Change only knowledge")
        self.assertNotEqual(self.vault.fingerprint(), old)
        self.assertTrue(self.statuses()["claude-auth"]["passed"])
        self.assertEqual(path.read_bytes(), original)

    def test_launchd_trial_validator_rejects_aliased_implicit_directories(self):
        custody = self.state / "custody"
        self.assertFalse(custody.exists())
        maintenance._check_trial_settings(self.vault, self.base)
        self.assertFalse(custody.exists())
        custody.mkdir()
        maintenance._check_trial_settings(self.vault, self.base)

        for relative in ("state/custody", "vault/inbox"):
            with self.subTest(directory=relative):
                workspace = self.base / relative.replace("/", "-")
                root, state = workspace / "vault", workspace / "state"
                control = root / ".git/healdan"
                control.mkdir(parents=True)
                state.mkdir()
                trial = SimpleNamespace(root=root, state=state, control=control, config={},
                                        repository=SimpleNamespace(worktree_roots=lambda: {root}))
                alias = workspace / relative
                target = workspace / "synthetic directory"
                target.mkdir()
                if os.name == "nt":
                    import _winapi
                    _winapi.CreateJunction(str(target), str(alias))
                else:
                    alias.symlink_to(target, target_is_directory=True)
                with self.assertRaisesRegex(Blocked, "Symlink path is forbidden|canonical workspace directory"):
                    maintenance._check_trial_settings(trial, workspace)
                self.assertEqual(alias.resolve(), target)
                self.assertEqual(list(target.iterdir()), [])

    def test_changes_to_build_dependency_and_config_expire_only_the_applicable_trials(self):
        backup_key = self.base / "separate backup key fixture"
        atomic(backup_key, b"synthetic key material")
        self.vault.config["backup_signing_key"] = str(backup_key)
        for name in ("claude-auth", "offline-recovery", "launchd"):
            maintenance.attest(self.vault, name, self.evidence(name))
        self.assertTrue(self.statuses()["offline-recovery"]["passed"])
        old_build = self.fixture_build.identity
        self.fixture_build.identity = {"version": old_build["version"], "sha256": "b" * 64}
        self.assertFalse(self.statuses()["offline-recovery"]["passed"])
        self.fixture_build.identity = old_build
        self.versions["node"] = "v22.13.0"
        statuses = self.statuses()
        self.assertFalse(statuses["claude-auth"]["passed"])
        self.assertTrue(statuses["offline-recovery"]["passed"])
        self.versions["node"] = "v22.12.0"
        atomic(backup_key, b"changed synthetic key material")
        statuses = self.statuses()
        self.assertTrue(statuses["claude-auth"]["passed"])
        self.assertFalse(statuses["offline-recovery"]["passed"])
        self.assertFalse(statuses["launchd"]["passed"])
        atomic(backup_key, b"synthetic key material")
        self.vault.config["backup_signing_key"] = str(backup_key.with_name("missing key fixture"))
        statuses = self.statuses()
        self.assertRegex(statuses["offline-recovery"]["reason"], "Backup signing key is unavailable")
        self.assertRegex(statuses["launchd"]["reason"], "Backup signing key is unavailable")
        self.vault.config["backup_signing_key"] = str(backup_key)
        self.vault.config["offline_recipients"] = ["new recipient"]
        statuses = self.statuses()
        self.assertTrue(statuses["claude-auth"]["passed"])
        self.assertFalse(statuses["offline-recovery"]["passed"])
        self.vault.config["offline_recipients"] = []
        self.vault.policy["schedules"]["lint"]["Hour"] = 11
        self.assertTrue(self.statuses()["offline-recovery"]["passed"])
        self.assertFalse(self.statuses()["launchd"]["passed"])
        self.artifact.write_bytes(b"changed artifact")
        self.assertRegex(self.statuses()["claude-auth"]["reason"], "artifact")

    def test_trial_envelope_is_isolated_by_vault_name_and_profile(self):
        profile = self.state / "profile A"
        other_profile = self.state / "profile B"
        atomic(profile / "settings.json", {"cleanupPeriodDays": 30})
        atomic(other_profile / "settings.json", {"cleanupPeriodDays": 30})
        receipt = maintenance.attest(self.vault, "claude-auth", self.evidence("claude-auth", profile))
        atomic(self.vault.control / "trials/v2/native-resume.json", receipt)
        self.assertFalse(self.statuses()["native-resume"]["passed"])
        self.vault.config["native_trial_profiles"] = {"claude-auth": str(other_profile)}
        self.assertRegex(self.statuses()["claude-auth"]["reason"], "different configured profile")
        del self.vault.config["native_trial_profiles"]
        atomic(profile / "settings.json", {"cleanupPeriodDays": 5})
        self.assertFalse(self.statuses()["claude-auth"]["passed"])
        atomic(profile / "settings.json", {"cleanupPeriodDays": 30})
        self.assertTrue(self.statuses()["claude-auth"]["passed"])
        sibling = self.base / "new bound vault"
        initialize(sibling, self.base / "sibling state")
        vault = Vault(sibling)
        escape = self.state / ".." / vault.state.name / "authentication"
        alias = self.state / "aliased profile"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(vault.state / "authentication"), str(alias))
        else:
            alias.symlink_to(vault.state / "authentication", target_is_directory=True)
        for candidate in (escape, alias):
            with self.assertRaises(Blocked):
                trials.environment(self.vault, "claude-auth", candidate)
            self.vault.config["native_trial_profiles"] = {"claude-auth": str(candidate)}
            with self.assertRaises(Blocked):
                trials.environment(self.vault, "claude-auth")
            del self.vault.config["native_trial_profiles"]
        vault.config.update(self.vault.config)
        other_receipt = maintenance.attest(self.vault, "offline-recovery", self.evidence("offline-recovery"))
        atomic(vault.control / "trials/v2/offline-recovery.json", other_receipt)
        self.assertRegex(self.statuses(vault)["offline-recovery"]["reason"], "vault, build, profile or environment changed")

    def test_legacy_receipt_bytes_preserved_and_personal_trials_gate_activation(self):
        old = self.vault.control / "trials/claude-auth.json"
        atomic(old, self.signed({"name": "claude-auth", "passed": True, "commit": self.vault.head()}, "trial"))
        bytes_before = old.read_bytes()
        self.assertRegex(self.statuses()["claude-auth"]["reason"], "Legacy receipt")
        maintenance.attest(self.vault, "claude-auth", self.evidence("claude-auth"))
        self.assertEqual(old.read_bytes(), bytes_before)
        self.assertEqual([row["name"] for row in self.statuses().values() if not row["passed"]], list(trials.TRIALS[1:]))
        with patch("healdan.setup.doctor", return_value={"ready": all(r["passed"] for r in self.statuses().values())}) as gate, \
                patch("healdan.linting.lint") as lint, patch("healdan.maintenance.daily") as daily:
            with self.assertRaisesRegex(Blocked, "native trials must pass"):
                maintenance.schedule(self.vault, activate=True)
            for job in ("lint", "daily"):
                with self.assertRaisesRegex(Blocked, "native trials must pass"):
                    maintenance.run_scheduled(self.vault, job, self.vault.identity)
            lint.assert_not_called()
            daily.assert_not_called()
            gate.return_value = {"ready": True}
            self.assertEqual(maintenance.run_scheduled(self.vault, "lint", self.vault.identity), lint.return_value)
            self.assertEqual(maintenance.run_scheduled(self.vault, "daily", self.vault.identity), daily.return_value)
        self.assertFalse((self.state / "launchd").exists())

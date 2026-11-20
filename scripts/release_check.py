#!/usr/bin/env python3
"""Fail closed unless this exact commit has all required native evidence."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from healdan.core import Blocked, Vault, canonical, decode, executable, git, run
from healdan.maintenance import trial_status

parser = argparse.ArgumentParser()
parser.add_argument("--vault", default=".")
parser.add_argument("--state")
parser.add_argument("--ci-run", help="Successful GitHub Actions run ID for this exact commit")
args = parser.parse_args()
vault = Vault(args.vault, args.state)
trials = trial_status(vault)
clean = not git(vault.root, "status", "--porcelain")
ci = {"verified": False, "reason": "Exact-commit macOS CI evidence is required"}
if args.ci_run:
    try:
        result = decode(run([executable("gh"), "api", "repos/saravejo/healdan/actions/runs/" + args.ci_run]).stdout)
        ci = {"verified": result.get("head_sha") == vault.head() and result.get("conclusion") == "success" and
                          result.get("name") == "Verify controller", "url": result.get("html_url")}
    except Blocked as exc:
        ci = {"verified": False, "reason": str(exc)}
audit = run([sys.executable, Path(__file__).with_name("audit_publication.py")], check=False)
result = {"commit": vault.head(), "clean": clean, "trials": trials,
          "ci": ci, "publication_audit": audit.returncode == 0,
          "stable_release_allowed": clean and ci["verified"] and audit.returncode == 0 and all(r["passed"] for r in trials)}
print(canonical(result).decode())
raise SystemExit(0 if result["stable_release_allowed"] else 5)
